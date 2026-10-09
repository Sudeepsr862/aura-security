// ─── Risk & Intelligence Routes ────────────────────────────────────────────
// GET /api/risk/overview   — Summary metrics, severity counts, and policy weight disclosure
// GET /api/risk/events     — Filterable, paginated events with explainable factors
// GET /api/risk/events/:id — Single event drill-down with identity correlation and evidence

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { DEMO_POLICY_WEIGHTS, type RiskFactor, type IdentityCorrelation } from '../risk/riskEngine.js';

export const riskRouter = Router();

const DEMO_RISK_DISCLAIMER =
  'Scores use deterministic demo policy weights and synthetic/supplied metadata. They are transparent prototype calculations, not machine learning predictions or live network security blocks.';

/**
 * GET /api/risk/overview
 * Returns aggregated severity counts, policy weights disclosure, and source counts.
 */
riskRouter.get('/overview', requireAuth, (req, res) => {
  const db = req.db;

  const countsRow = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN source_type = 'csv_import' THEN 1 ELSE 0 END) as csv_count,
      SUM(CASE WHEN source_type = 'simulation' THEN 1 ELSE 0 END) as sim_count
    FROM events
    WHERE is_demo = 1
  `).get() as {
    total: number;
    low: number | null;
    medium: number | null;
    high: number | null;
    critical: number | null;
    csv_count: number | null;
    sim_count: number | null;
  };

  // Sensitivity distribution
  const sensRows = db.prepare(`
    SELECT sensitivity_label, COUNT(*) as count
    FROM events
    WHERE is_demo = 1
    GROUP BY sensitivity_label
  `).all() as Array<{ sensitivity_label: string; count: number }>;

  const sensitivityCounts: Record<string, number> = {
    Public: 0,
    Internal: 0,
    Confidential: 0,
    Restricted: 0,
  };
  for (const r of sensRows) {
    if (r.sensitivity_label in sensitivityCounts) {
      sensitivityCounts[r.sensitivity_label] = r.count;
    }
  }

  res.json({
    disclaimer: DEMO_RISK_DISCLAIMER,
    counts: {
      total: countsRow.total || 0,
      low: countsRow.low || 0,
      medium: countsRow.medium || 0,
      high: countsRow.high || 0,
      critical: countsRow.critical || 0,
      simulationCount: countsRow.sim_count || 0,
      csvImportCount: countsRow.csv_count || 0,
    },
    sensitivityCounts,
    policyWeights: DEMO_POLICY_WEIGHTS,
  });
});

/**
 * GET /api/risk/events
 * Returns filterable paginated events with explainable factors.
 */
riskRouter.get('/events', requireAuth, (req, res) => {
  const db = req.db;

  const limit  = Math.min(Math.max(parseInt(String(req.query.limit  ?? 25), 10), 1), 100);
  const offset = Math.max(parseInt(String(req.query.offset ?? 0),  10), 0);

  const severity = req.query.severity ? String(req.query.severity).toLowerCase().trim() : null;
  const classification = req.query.classification ? String(req.query.classification).trim() : null;
  const source = req.query.source ? String(req.query.source).toLowerCase().trim() : null;
  const search = req.query.search ? String(req.query.search).trim() : null;

  let whereClause = `WHERE e.is_demo = 1`;
  const params: unknown[] = [];

  if (severity && severity !== 'all') {
    whereClause += ` AND e.risk_level = ?`;
    params.push(severity);
  }

  if (classification && classification !== 'all') {
    whereClause += ` AND e.classification = ?`;
    params.push(classification);
  }

  if (source && source !== 'all') {
    if (source === 'csv' || source === 'csv_import') {
      whereClause += ` AND e.source_type = 'csv_import'`;
    } else if (source === 'sim' || source === 'simulation') {
      whereClause += ` AND e.source_type = 'simulation'`;
    }
  }

  if (search) {
    whereClause += ` AND (
      e.destination LIKE ? OR
      COALESCE(s.name, e.expected_provider) LIKE ? OR
      e.device_name LIKE ? OR
      e.user_email LIKE ? OR
      p.display_name LIKE ?
    )`;
    const sLike = `%${search}%`;
    params.push(sLike, sLike, sLike, sLike, sLike);
  }

  // Count total matching
  const countSql = `
    SELECT COUNT(*) as cnt
    FROM events e
    LEFT JOIN services         s ON s.id = e.service_id
    LEFT JOIN synthetic_people p ON p.id = e.person_id
    ${whereClause}
  `;
  const total = (db.prepare(countSql).get(...params) as { cnt: number }).cnt;

  // Fetch paginated rows
  const query = `
    SELECT
      e.id,
      e.occurred_at,
      e.source_label,
      e.source_type,
      e.destination,
      e.port,
      COALESCE(s.name, e.expected_provider, 'Unknown') as service_name,
      COALESCE(s.provider, e.expected_provider, 'Unknown') as provider,
      e.classification,
      e.confidence,
      e.evidence,
      e.approval_status,
      e.risk_level,
      e.risk_score,
      e.action_recommendation,
      e.byte_count,
      e.sensitivity_label,
      e.evidence_tags,
      e.device_name,
      e.user_email,
      COALESCE(p.display_name, e.user_email, 'Unlisted synthetic user') as person_name,
      COALESCE(d.label, e.device_name, 'Unmanaged device') as device_label,
      e.risk_factors,
      e.risk_explanation,
      e.risk_confidence,
      e.authorization_status,
      e.identity_correlation
    FROM events e
    LEFT JOIN services          s ON s.id = e.service_id
    LEFT JOIN synthetic_people  p ON p.id = e.person_id
    LEFT JOIN synthetic_devices d ON d.id = e.device_id
    ${whereClause}
    ORDER BY e.occurred_at DESC
    LIMIT ? OFFSET ?
  `;

  const rows = db.prepare(query).all(...params, limit, offset) as Array<{
    id: number;
    occurred_at: string;
    source_label: string;
    source_type: string;
    destination: string;
    port: number | null;
    service_name: string;
    provider: string;
    classification: string;
    confidence: number;
    evidence: string;
    approval_status: string;
    risk_level: string;
    risk_score: number;
    action_recommendation: string;
    byte_count: number;
    sensitivity_label: string;
    evidence_tags: string;
    device_name: string | null;
    user_email: string | null;
    person_name: string;
    device_label: string;
    risk_factors: string;
    risk_explanation: string | null;
    risk_confidence: string;
    authorization_status: string;
    identity_correlation: string;
  }>;

  const events = rows.map((r) => {
    let factors: RiskFactor[] = [];
    try {
      factors = JSON.parse(r.risk_factors || '[]');
    } catch {
      factors = [];
    }

    let identity: Partial<IdentityCorrelation> = {};
    try {
      identity = JSON.parse(r.identity_correlation || '{}');
    } catch {
      identity = {};
    }

    return {
      ...r,
      evidence_tags: JSON.parse(r.evidence_tags || '[]') as string[],
      risk_factors: factors,
      identity_correlation: identity,
      isSimulatedAction: r.action_recommendation.includes('simulation') || r.action_recommendation.includes('sample'),
    };
  });

  res.json({
    events,
    pagination: { total, limit, offset },
    disclaimer: DEMO_RISK_DISCLAIMER,
  });
});

/**
 * GET /api/risk/events/:id
 * Single event drill-down with identity correlation and factor breakdown.
 */
riskRouter.get('/events/:id', requireAuth, (req, res) => {
  const db = req.db;
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) {
    res.status(400).json({ error: 'Invalid event ID.' });
    return;
  }

  const query = `
    SELECT
      e.id,
      e.occurred_at,
      e.source_label,
      e.source_type,
      e.destination,
      e.port,
      COALESCE(s.name, e.expected_provider, 'Unknown') as service_name,
      COALESCE(s.provider, e.expected_provider, 'Unknown') as provider,
      e.classification,
      e.confidence,
      e.evidence,
      e.approval_status,
      e.risk_level,
      e.risk_score,
      e.action_recommendation,
      e.byte_count,
      e.sensitivity_label,
      e.evidence_tags,
      e.device_name,
      e.user_email,
      COALESCE(p.display_name, e.user_email, 'Unlisted synthetic user') as person_name,
      COALESCE(d.label, e.device_name, 'Unmanaged device') as device_label,
      e.risk_factors,
      e.risk_explanation,
      e.risk_confidence,
      e.authorization_status,
      e.identity_correlation
    FROM events e
    LEFT JOIN services          s ON s.id = e.service_id
    LEFT JOIN synthetic_people  p ON p.id = e.person_id
    LEFT JOIN synthetic_devices d ON d.id = e.device_id
    WHERE e.id = ? AND e.is_demo = 1
    LIMIT 1
  `;

  const row = db.prepare(query).get(id) as {
    id: number;
    occurred_at: string;
    source_label: string;
    source_type: string;
    destination: string;
    port: number | null;
    service_name: string;
    provider: string;
    classification: string;
    confidence: number;
    evidence: string;
    approval_status: string;
    risk_level: string;
    risk_score: number;
    action_recommendation: string;
    byte_count: number;
    sensitivity_label: string;
    evidence_tags: string;
    device_name: string | null;
    user_email: string | null;
    person_name: string;
    device_label: string;
    risk_factors: string;
    risk_explanation: string | null;
    risk_confidence: string;
    authorization_status: string;
    identity_correlation: string;
  } | undefined;

  if (!row) {
    res.status(404).json({ error: `Event with ID ${id} not found.` });
    return;
  }

  let factors: RiskFactor[] = [];
  try {
    factors = JSON.parse(row.risk_factors || '[]');
  } catch {
    factors = [];
  }

  let identity: Partial<IdentityCorrelation> = {};
  try {
    identity = JSON.parse(row.identity_correlation || '{}');
  } catch {
    identity = {};
  }

  res.json({
    event: {
      ...row,
      evidence_tags: JSON.parse(row.evidence_tags || '[]') as string[],
      risk_factors: factors,
      identity_correlation: identity,
      isSimulatedAction: row.action_recommendation.includes('simulation') || row.action_recommendation.includes('sample'),
    },
    policyWeights: DEMO_POLICY_WEIGHTS,
    disclaimer: DEMO_RISK_DISCLAIMER,
  });
});
