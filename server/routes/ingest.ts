// ─── Ingestion & Discovery Routes ─────────────────────────────────────────────
// POST /api/ingest/csv       — Safe metadata CSV ingestion (admin/analyst only)
// GET  /api/ingest/sample-csv — Retrieves sample CSV text for 1-click demo import
// GET  /api/ingest/evaluation — Dataset detection metrics computed from labels
// POST /api/ingest/clear-csv  — Resets CSV-imported records (admin/analyst only)

import { Router } from 'express';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit, syncIncidentsFromEvents } from '../db/database.js';
import { parseAndValidateCsv } from '../discovery/csvParser.js';
import { classifyEvent, type ServiceRegistryItem } from '../discovery/classifier.js';
import { evaluateDataset, type EvaluableRow } from '../discovery/evaluator.js';
import { assessRisk, type SyntheticPersonRecord, type SyntheticDeviceRecord } from '../risk/riskEngine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const ingestRouter = Router();

const PRIVACY_DISCLAIMER =
  'AURA analyzes supplied or simulated metadata only. It does not connect to devices, scan a network, capture packets, decrypt HTTPS, or inspect prompt contents in imported traffic.';

/**
 * GET /api/ingest/sample-csv
 * Public demo helper: provides built-in sample CSV content for 1-click loading.
 */
ingestRouter.get('/sample-csv', (_req, res) => {
  const filePath = join(__dirname, '../../data/sample_network_metadata.csv');
  if (!existsSync(filePath)) {
    res.status(404).json({ error: 'Sample CSV file not found on server.' });
    return;
  }
  const content = readFileSync(filePath, 'utf-8');
  res.json({
    filename: 'sample_network_metadata.csv',
    content,
    privacyNotice: PRIVACY_DISCLAIMER,
  });
});

/**
 * GET /api/ingest/evaluation
 * Evaluates detection performance against ground-truth labels in the database.
 */
ingestRouter.get('/evaluation', (req, res) => {
  const db = req.db;
  const rows = db.prepare(`
    SELECT
      classification,
      COALESCE(service_name_fallback, 'Unknown') as provider,
      ground_truth_label,
      expected_provider
    FROM (
      SELECT
        e.classification,
        e.ground_truth_label,
        e.expected_provider,
        COALESCE(s.provider, e.expected_provider, 'Unknown') as service_name_fallback
      FROM events e
      LEFT JOIN services s ON e.service_id = s.id
    )
  `).all() as EvaluableRow[];

  const report = evaluateDataset(rows);
  res.json({
    report,
    privacyNotice: PRIVACY_DISCLAIMER,
  });
});

/**
 * POST /api/ingest/csv
 * Authenticated CSV metadata import.
 * Only demo administrators and analysts may import.
 */
ingestRouter.post(
  '/csv',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-user';

    // Extract CSV text from JSON payload or body
    const csvText = typeof req.body?.csvText === 'string' ? req.body.csvText : typeof req.body === 'string' ? req.body : null;

    if (!csvText || csvText.trim().length === 0) {
      res.status(400).json({ error: 'No CSV content provided. Send { csvText: "..." } in request body.' });
      return;
    }

    // 1. Parse and validate CSV with size and row limits + payload stripping
    const parseResult = parseAndValidateCsv(csvText);

    if (!parseResult.success) {
      res.status(400).json({
        error: parseResult.errorMessage ?? 'Failed to parse CSV.',
        ignoredColumns: parseResult.ignoredColumnsDetected,
      });
      return;
    }

    if (parseResult.importedRows.length === 0) {
      res.status(422).json({
        error: 'No valid rows found to import.',
        totalRowsFound: parseResult.totalRowsFound,
        skippedRows: parseResult.skippedRows,
        ignoredColumns: parseResult.ignoredColumnsDetected,
      });
      return;
    }

    // 2. Fetch service registry for classification
    const rawServices = db.prepare(`
      SELECT id, name, provider, domains, local_ports, service_type, approval_status
      FROM services
    `).all() as Array<{
      id: number;
      name: string;
      provider: string;
      domains: string;
      local_ports: string;
      service_type: string;
      approval_status: string;
    }>;

    const registry: ServiceRegistryItem[] = rawServices.map((s) => ({
      ...s,
      domains: JSON.parse(s.domains || '[]'),
      local_ports: JSON.parse(s.local_ports || '[]'),
    }));

    // 3. Prepare statement lookups for identity correlation and event insertion
    const getUserByEmail = db.prepare(`SELECT id, display_name, demo_email FROM synthetic_people WHERE demo_email = ? LIMIT 1`);
    const getDeviceByLabel = db.prepare(`SELECT id, label, person_id FROM synthetic_devices WHERE label = ? LIMIT 1`);
    const checkPermitted = db.prepare(`SELECT 1 FROM person_permitted_services WHERE person_id = ? AND service_id = ? LIMIT 1`);
    const getDestCount = db.prepare(`SELECT COUNT(*) as cnt FROM events WHERE destination = ?`);
    const getUserWarnings = db.prepare(`SELECT COUNT(*) as cnt FROM events WHERE person_id = ? AND risk_level IN ('high', 'critical')`);

    const insertEvent = db.prepare(`
      INSERT INTO events (
        occurred_at, source_label, source_type,
        device_id, person_id,
        device_name, user_email, src_ip, dst_ip,
        destination, port, service_id,
        classification, confidence, evidence,
        approval_status, risk_level, risk_score, action_recommendation,
        byte_count, sensitivity_label, evidence_tags,
        is_anomaly, is_authorized, ground_truth_label, expected_provider,
        risk_factors, risk_explanation, risk_confidence, authorization_status, identity_correlation
      ) VALUES (
        @occurred_at, @source_label, @source_type,
        @device_id, @person_id,
        @device_name, @user_email, @src_ip, @dst_ip,
        @destination, @port, @service_id,
        @classification, @confidence, @evidence,
        @approval_status, @risk_level, @risk_score, @action_recommendation,
        @byte_count, @sensitivity_label, @evidence_tags,
        @is_anomaly, @is_authorized, @ground_truth_label, @expected_provider,
        @risk_factors, @risk_explanation, @risk_confidence, @authorization_status, @identity_correlation
      )
    `);

    try {
      const runTransaction = db.transaction(() => {
        for (const row of parseResult.importedRows) {
          const result = classifyEvent(
            {
              destination: row.destination,
              port: row.port,
              rawHost: row.domain,
            },
            registry,
          );

          // Correlate synthetic identity from database
          const user = row.userEmail ? (getUserByEmail.get(row.userEmail) as SyntheticPersonRecord | undefined) : null;
          const device = row.device ? (getDeviceByLabel.get(row.device) as SyntheticDeviceRecord | undefined) : null;
          const isPermitted = user && result.serviceId ? Boolean(checkPermitted.get(user.id, result.serviceId)) : null;
          const destCount = (getDestCount.get(row.destination) as { cnt: number } | undefined)?.cnt ?? 0;
          const priorWarnings = user ? ((getUserWarnings.get(user.id) as { cnt: number } | undefined)?.cnt ?? 0) : 0;

          // Compute deterministic, explainable risk assessment
          const risk = assessRisk({
            destination: row.destination,
            port: row.port,
            classification: result.classification,
            classificationConfidence: result.confidence,
            sensitivityLabel: row.dataClassification,
            serviceApproval: result.approvalStatus,
            byteCount: row.bytes,
            isAnomalySignal: row.isAnomaly,
            userEmail: row.userEmail,
            deviceLabel: row.device,
            explicitAuth: row.explicitAuthorization,
            syntheticUser: user ?? null,
            syntheticDevice: device ?? null,
            isServicePermittedForUser: isPermitted,
            destinationOccurrenceCount: destCount,
            userPriorWarningsCount: priorWarnings,
          });

          const evidenceTags = risk.factors.map((f) => f.id);

          insertEvent.run({
            occurred_at: row.timestamp,
            source_label: 'CSV-import',
            source_type: 'csv_import',
            device_id: device?.id ?? null,
            person_id: user?.id ?? null,
            device_name: row.device ?? null,
            user_email: row.userEmail ?? null,
            src_ip: row.srcIp ?? null,
            dst_ip: row.dstIp ?? null,
            destination: row.destination,
            port: row.port,
            service_id: result.serviceId,
            classification: result.classification,
            confidence: result.confidence,
            evidence: result.evidence,
            approval_status: result.approvalStatus,
            risk_level: risk.severity,
            risk_score: risk.score,
            action_recommendation: risk.recommendation,
            byte_count: row.bytes,
            sensitivity_label: row.dataClassification,
            evidence_tags: JSON.stringify(evidenceTags),
            is_anomaly: row.isAnomaly ? 1 : 0,
            is_authorized: risk.identityCorrelation.authStatus === 'authorized' ? 1 : 0,
            ground_truth_label: row.groundTruthLabel ?? null,
            expected_provider: row.expectedProvider ?? null,
            risk_factors: JSON.stringify(risk.factors),
            risk_explanation: risk.explanation,
            risk_confidence: risk.confidence,
            authorization_status: risk.identityCorrelation.authStatus,
            identity_correlation: JSON.stringify(risk.identityCorrelation),
          });
        }
      });

      runTransaction();

      // Automatically create incidents from any newly imported qualifying High/Critical events
      const { createdCount: newIncidentsCount } = syncIncidentsFromEvents(db, actor);

      // Audit log
      appendAudit(db, actor, 'IMPORT_CSV_METADATA', {
        importedCount: parseResult.importedRows.length,
        skippedCount: parseResult.skippedRows.length,
        ignoredColumns: parseResult.ignoredColumnsDetected,
        newIncidentsCount,
      });

      res.json({
        success: true,
        message: `Successfully imported and classified ${parseResult.importedRows.length} metadata rows (${newIncidentsCount} new review incidents created).`,
        summary: {
          totalRowsFound: parseResult.totalRowsFound,
          importedCount: parseResult.importedRows.length,
          skippedCount: parseResult.skippedRows.length,
          ignoredColumns: parseResult.ignoredColumnsDetected,
          newIncidentsCount,
        },
        skippedRows: parseResult.skippedRows,
        privacyNotice: PRIVACY_DISCLAIMER,
      });
    } catch (err: unknown) {
      // Do not leak stack trace
      res.status(500).json({
        error: 'Database transaction failed during CSV import.',
        detail: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  },
);

/**
 * POST /api/ingest/clear-csv
 * Removes imported CSV events to reset to baseline simulation.
 */
ingestRouter.post(
  '/clear-csv',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-user';

    // Remove any incidents associated with CSV imported events
    db.prepare(`
      DELETE FROM incidents
      WHERE event_id IN (SELECT id FROM events WHERE source_type = 'csv_import')
    `).run();

    const info = db.prepare(`DELETE FROM events WHERE source_type = 'csv_import'`).run();
    appendAudit(db, actor, 'CLEAR_CSV_EVENTS', { deletedCount: info.changes });

    res.json({
      success: true,
      message: `Cleared ${info.changes} imported CSV records.`,
      deletedCount: info.changes,
    });
  },
);
