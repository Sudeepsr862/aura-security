// ─── Services Routes ──────────────────────────────────────────────────────────
// GET /api/services   — list all AI-service registry entries

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';

export const servicesRouter = Router();

/**
 * GET /api/services
 * Returns the full service registry. Read-only for all roles.
 */
servicesRouter.get('/', requireAuth, (req, res) => {
  const rows = req.db.prepare(
    `SELECT
       id, name, provider,
       domains, local_ports,
       service_type, approval_status,
       notes, updated_at
     FROM services
     WHERE is_demo = 1
     ORDER BY name`
  ).all() as {
    id: number; name: string; provider: string;
    domains: string; local_ports: string;
    service_type: string; approval_status: string;
    notes: string | null; updated_at: string;
  }[];

  // Parse JSON columns before sending
  const services = rows.map((r) => ({
    ...r,
    domains:     JSON.parse(r.domains)     as string[],
    local_ports: JSON.parse(r.local_ports) as number[],
  }));

  return res.json({ services, demoNote: 'Sample registry — no real network scanning performed.' });
});

/**
 * GET /api/services/inventory
 * Unified inventory view joining registry items and observed event endpoints.
 * Includes event count estimates, byte volume estimates, confidence, and source provenance.
 */
servicesRouter.get('/inventory', requireAuth, (req, res) => {
  const db = req.db;

  // 1. Observed endpoints aggregated from events
  const observedRows = db.prepare(`
    SELECT
      e.destination as endpoint,
      COALESCE(s.name, e.expected_provider, e.destination) as name,
      COALESCE(s.provider, e.expected_provider, 'Unknown') as provider,
      e.classification,
      e.approval_status,
      MIN(e.occurred_at) as first_seen,
      COUNT(e.id) as event_count,
      COALESCE(SUM(e.byte_count), 0) as estimated_bytes,
      MAX(e.confidence) as confidence,
      MAX(e.evidence) as evidence,
      GROUP_CONCAT(DISTINCT e.source_type) as raw_source_types,
      s.notes
    FROM events e
    LEFT JOIN services s ON e.service_id = s.id
    WHERE e.is_demo = 1
    GROUP BY e.destination, e.classification
  `).all() as Array<{
    endpoint: string;
    name: string;
    provider: string;
    classification: string;
    approval_status: string;
    first_seen: string;
    event_count: number;
    estimated_bytes: number;
    confidence: number;
    evidence: string;
    raw_source_types: string;
    notes: string | null;
  }>;

  // Map observed rows
  const observedEndpoints = new Set(observedRows.map((r) => r.endpoint.toLowerCase()));

  const items = observedRows.map((r, idx) => ({
    id: `obs-${idx + 1}`,
    name: r.name,
    provider: r.provider,
    endpoint: r.endpoint,
    classification: r.classification,
    approval_status: r.approval_status,
    first_seen: r.first_seen,
    event_count: r.event_count,
    estimated_bytes: r.estimated_bytes,
    confidence: r.confidence,
    evidence: r.evidence,
    source_types: r.raw_source_types ? r.raw_source_types.split(',') : ['simulation'],
    notes: r.notes,
  }));

  // 2. Add registered services that don't have events yet
  const registryRows = db.prepare(`
    SELECT id, name, provider, domains, local_ports, service_type, approval_status, notes
    FROM services
    WHERE is_demo = 1
  `).all() as Array<{
    id: number;
    name: string;
    provider: string;
    domains: string;
    local_ports: string;
    service_type: string;
    approval_status: string;
    notes: string | null;
  }>;

  for (const reg of registryRows) {
    const domains = JSON.parse(reg.domains || '[]') as string[];
    const ports = JSON.parse(reg.local_ports || '[]') as number[];
    const primaryEndpoint = domains[0] || (ports[0] ? `localhost:${ports[0]}` : reg.name);

    // If no observed event directly matches primary endpoint
    if (!observedEndpoints.has(primaryEndpoint.toLowerCase())) {
      items.push({
        id: `reg-${reg.id}`,
        name: reg.name,
        provider: reg.provider,
        endpoint: primaryEndpoint,
        classification: reg.service_type,
        approval_status: reg.approval_status,
        first_seen: 'Pending traffic',
        event_count: 0,
        estimated_bytes: 0,
        confidence: 0.95,
        evidence: `Registered service entry in policy database (${primaryEndpoint}).`,
        source_types: ['simulation'],
        notes: reg.notes,
      });
    }
  }

  // Sort by priority: Likely cloud AI, Possible local AI, Uncertain, Ordinary web
  items.sort((a, b) => {
    const rank = (c: string) => {
      if (c === 'Likely cloud AI') return 1;
      if (c === 'Possible local AI') return 2;
      if (c === 'Uncertain') return 3;
      return 4;
    };
    const rA = rank(a.classification);
    const rB = rank(b.classification);
    if (rA !== rB) return rA - rB;
    return b.event_count - a.event_count;
  });

  return res.json({
    inventory: items,
    privacyNotice:
      'AURA analyzes supplied or simulated metadata only. Counts and byte totals are estimates derived from imported records and do not represent all activity on a network.',
    demoNote: 'Sample inventory derived from stored events and registered signatures.',
  });
});

/**
 * PATCH /api/services/:id/approval
 * Update service approval status among Approved, Needs review, Unapproved, Unknown.
 * Role check: Administrator only.
 */
servicesRouter.patch(
  '/:id/approval',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-admin';
    const id = parseInt(String(req.params.id), 10);

    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid service ID.' });
    }

    const { approval_status } = req.body;
    const VALID_APPROVALS = ['Approved', 'Needs review', 'Unapproved', 'Unknown'];

    if (!approval_status || !VALID_APPROVALS.includes(approval_status)) {
      return res.status(400).json({
        error: `Invalid approval_status. Must be one of: ${VALID_APPROVALS.join(', ')}.`,
      });
    }

    const svc = db.prepare(`SELECT id, name, approval_status FROM services WHERE id = ?`).get(id) as {
      id: number;
      name: string;
      approval_status: string;
    } | undefined;

    if (!svc) {
      return res.status(404).json({ error: 'Service not found in registry.' });
    }

    db.prepare(`
      UPDATE services
      SET approval_status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(approval_status, id);

    appendAudit(db, actor, 'service.approval_update', {
      service_id: id,
      service_name: svc.name,
      new_status: approval_status,
      prev_status: svc.approval_status,
    });

    return res.json({
      success: true,
      message: `Service '${svc.name}' approval status updated to '${approval_status}'.`,
      service: {
        id,
        name: svc.name,
        approval_status,
      },
    });
  }
);

