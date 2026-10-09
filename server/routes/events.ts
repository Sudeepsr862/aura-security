// ─── Events Routes ────────────────────────────────────────────────────────────
// GET /api/events   — list demo events (read-only)

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';

export const eventsRouter = Router();

/**
 * GET /api/events?limit=N&offset=N
 * Returns paginated demo events. Read-only for all roles.
 */
eventsRouter.get('/', requireAuth, (req, res) => {
  const limit  = Math.min(Math.max(parseInt(String(req.query.limit  ?? 20), 10), 1), 100);
  const offset = Math.max(parseInt(String(req.query.offset ?? 0),  10), 0);

  const search = req.query.search ? String(req.query.search).trim() : null;
  const classification = req.query.classification ? String(req.query.classification).trim() : null;

  let query = `
    SELECT
      e.id,
      e.occurred_at,
      e.source_label,
      e.source_type,
      e.destination,
      e.port,
      COALESCE(s.name, e.expected_provider, 'Unknown') as service_name,
      e.classification,
      e.confidence,
      e.evidence,
      COALESCE(p.display_name, e.user_email, 'Unknown') as person_name,
      COALESCE(d.label, e.device_name, 'Unknown') as device_label,
      e.approval_status,
      e.risk_level,
      e.risk_score,
      e.action_recommendation,
      e.byte_count,
      e.sensitivity_label,
      e.evidence_tags,
      e.ground_truth_label,
      e.expected_provider,
      e.risk_factors,
      e.risk_explanation,
      e.risk_confidence,
      e.authorization_status,
      e.identity_correlation
    FROM events e
    LEFT JOIN services          s ON s.id = e.service_id
    LEFT JOIN synthetic_people  p ON p.id = e.person_id
    LEFT JOIN synthetic_devices d ON d.id = e.device_id
    WHERE e.is_demo = 1
  `;
  const queryParams: unknown[] = [];

  if (classification && classification !== 'All') {
    query += ` AND e.classification = ?`;
    queryParams.push(classification);
  }

  if (search) {
    query += ` AND (e.destination LIKE ? OR s.name LIKE ? OR e.device_name LIKE ? OR e.user_email LIKE ?)`;
    const sLike = `%${search}%`;
    queryParams.push(sLike, sLike, sLike, sLike);
  }

  query += ` ORDER BY e.occurred_at DESC LIMIT ? OFFSET ?`;
  queryParams.push(limit, offset);

  const rows = req.db.prepare(query).all(...queryParams) as Array<{
    id: number; occurred_at: string; source_label: string; source_type: string;
    destination: string; port: number | null;
    service_name: string; classification: string; confidence: number; evidence: string;
    person_name: string; device_label: string;
    approval_status: string; risk_level: string; risk_score: number;
    action_recommendation: string; byte_count: number;
    sensitivity_label: string; evidence_tags: string;
    ground_truth_label: string | null; expected_provider: string | null;
    risk_factors: string; risk_explanation: string | null; risk_confidence: string;
    authorization_status: string; identity_correlation: string;
  }>;

  const total = (
    req.db.prepare(`SELECT COUNT(*) as cnt FROM events WHERE is_demo = 1`).get() as { cnt: number }
  ).cnt;

  const events = rows.map((r) => {
    let factors = [];
    try { factors = JSON.parse(r.risk_factors || '[]'); } catch { factors = []; }
    let identity = {};
    try { identity = JSON.parse(r.identity_correlation || '{}'); } catch { identity = {}; }

    return {
      ...r,
      evidence_tags: JSON.parse(r.evidence_tags || '[]') as string[],
      risk_factors: factors,
      risk_confidence: r.risk_confidence || 'Medium',
      authorization_status: r.authorization_status || 'unknown',
      identity_correlation: identity,
      isSimulatedAction: (r.action_recommendation || '').includes('simulation') || (r.action_recommendation || '').includes('sample'),
    };
  });

  return res.json({
    events,
    pagination: { total, limit, offset },
    demoNote: 'Simulated metadata only — no real traffic captured.',
  });
});
