// ─── Dashboard Routes ─────────────────────────────────────────────────────────
// GET /api/dashboard/bootstrap — overview metrics + recent activity

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';

export const dashboardRouter = Router();

/**
 * GET /api/dashboard/bootstrap
 * Returns all data the Overview page needs in one request.
 * Requires a valid demo session (any role).
 */
dashboardRouter.get('/bootstrap', requireAuth, (req, res) => {
  const db = req.db;

  // ── Summary counts ──────────────────────────────────────────────────────────
  const totalEvents = (
    db.prepare(`SELECT COUNT(*) as cnt FROM events WHERE is_demo = 1`).get() as { cnt: number }
  ).cnt;

  const aiLikeEvents = (
    db.prepare(
      `SELECT COUNT(*) as cnt FROM events
       WHERE classification IN ('Likely cloud AI', 'Possible local AI') AND is_demo = 1`
    ).get() as { cnt: number }
  ).cnt;

  const servicesNeedingReview = (
    db.prepare(
      `SELECT COUNT(*) as cnt FROM services
       WHERE approval_status IN ('Needs review','Unapproved','Unknown') AND is_demo = 1`
    ).get() as { cnt: number }
  ).cnt;

  const highRiskEvents = (
    db.prepare(
      `SELECT COUNT(*) as cnt FROM events
       WHERE risk_level IN ('high','critical') AND is_demo = 1`
    ).get() as { cnt: number }
  ).cnt;

  const openIncidents = (
    db.prepare(
      `SELECT COUNT(*) as cnt FROM incidents
       WHERE status IN ('Open','Under review') AND is_demo = 1`
    ).get() as { cnt: number }
  ).cnt;

  const estimatedTotalBytes = (
    db.prepare(`SELECT COALESCE(SUM(byte_count), 0) as total FROM events WHERE is_demo = 1`).get() as { total: number }
  ).total;

  const csvImportCount = (
    db.prepare(`SELECT COUNT(*) as cnt FROM events WHERE source_type = 'csv_import' AND is_demo = 1`).get() as { cnt: number }
  ).cnt;

  // ── Recent activity (last 12 events) ────────────────────────────────────────
  const recentEvents = (
    db.prepare(
      `SELECT
         e.id,
         e.destination,
         e.port,
         COALESCE(s.name, e.expected_provider, 'Unknown Destination') as provider_name,
         e.classification,
         e.confidence,
         e.evidence,
         e.source_label,
         e.source_type,
         e.risk_level,
         e.sensitivity_label,
         e.byte_count,
         e.occurred_at
       FROM events e
       LEFT JOIN services s ON s.id = e.service_id
       WHERE e.is_demo = 1
       ORDER BY e.occurred_at DESC
       LIMIT 12`
    ).all()
  );

  return res.json({
    summary: {
      totalEvents,
      aiLikeEvents,
      servicesNeedingReview,
      highRiskEvents,
      openIncidents,
      estimatedTotalBytes,
      csvImportCount,
    },
    recentActivity: recentEvents,
    demoNote: 'All figures are synthetic/supplied demo data. No real network monitoring was conducted.',
  });
});
