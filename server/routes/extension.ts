// ─── AURA Extension & Live Guard Routes ──────────────────────────────────────
// Supports Manifest V3 Chrome Extension and Live Dashboard:
// - Editable AI service catalog (Add/remove/toggle AI sites & local models)
// - Real-time event ingestion (metadata only, zero prompt/secret retention)
// - Reviewer workflow (Expected, Investigate, Policy exception)
// - Historical reference dataset views joined on employee_id
// - Transparent site protection status tracking

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';
import { queryHistoricalLogs, queryHistoricalIncidents } from '../discovery/datasetLoader.js';

export const extensionRouter = Router();

// ══════════════════════════════════════════════════════════════════════════════
//  1. AI SERVICE CATALOG CRUD
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/extension/sites
 * List all configured AI service domains.
 */
extensionRouter.get('/sites', requireAuth, (req, res) => {
  const sites = req.db.prepare(`
    SELECT id, service_key, name, domain, category, adapter,
           is_enabled, last_active_at, status, created_at, updated_at
    FROM extension_sites
    ORDER BY category ASC, name ASC
  `).all();

  return res.json({
    sites: sites.map((s: any) => ({
      ...s,
      is_enabled: Boolean(s.is_enabled),
    })),
    totalSites: sites.length,
    activeProtectedCount: sites.filter((s: any) => Boolean(s.is_enabled) && s.status === 'protected').length,
    canEdit: ['administrator', 'analyst'].includes(req.demoUser?.role ?? ''),
  });
});

/**
 * POST /api/extension/sites
 * Add a new AI website or local-model endpoint domain.
 */
extensionRouter.post(
  '/sites',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const { name, domain, category, adapter } = req.body;
    const actor = req.demoUser?.username ?? 'admin';

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: 'Name is required (min 2 chars).' });
    }
    if (!domain || typeof domain !== 'string' || domain.trim().length < 3) {
      return res.status(400).json({ error: 'Domain is required (e.g. chat.example.com or localhost:8000).' });
    }

    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const cleanCategory = ['cloud', 'local', 'custom'].includes(category) ? category : 'custom';
    const cleanAdapter = ['generic', 'chatgpt', 'claude', 'local_webui'].includes(adapter) ? adapter : 'generic';
    const serviceKey = cleanDomain.replace(/[^a-z0-9]/g, '_');

    try {
      const stmt = req.db.prepare(`
        INSERT INTO extension_sites (service_key, name, domain, category, adapter, is_enabled, status)
        VALUES (?, ?, ?, ?, ?, 1, 'protected')
      `);
      const info = stmt.run(serviceKey, name.trim(), cleanDomain, cleanCategory, cleanAdapter);

      appendAudit(req.db, actor, 'extension.site.create', {
        site_id: Number(info.lastInsertRowid),
        name: name.trim(),
        domain: cleanDomain,
        category: cleanCategory,
      });

      return res.status(201).json({
        success: true,
        id: Number(info.lastInsertRowid),
        name: name.trim(),
        domain: cleanDomain,
        message: `AI service "${name}" (${cleanDomain}) added to protection catalog.`,
      });
    } catch (err: any) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: `Domain "${cleanDomain}" is already in the catalog.` });
      }
      return res.status(500).json({ error: err.message });
    }
  }
);

/**
 * PATCH /api/extension/sites/:id
 * Toggle enabled state or update status/active timestamp.
 */
extensionRouter.patch(
  '/sites/:id',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid site ID.' });

    const existing = req.db.prepare(`SELECT id, name FROM extension_sites WHERE id = ?`).get(id) as { id: number; name: string } | undefined;
    if (!existing) return res.status(404).json({ error: 'Site not found.' });

    const { is_enabled, status, last_active_at } = req.body;
    const updates: string[] = ['updated_at = datetime("now")'];
    const params: any[] = [];

    if (typeof is_enabled === 'boolean') {
      updates.push('is_enabled = ?');
      params.push(is_enabled ? 1 : 0);
    }
    if (status && ['protected', 'inactive', 'unsupported', 'changed'].includes(status)) {
      updates.push('status = ?');
      params.push(status);
    }
    if (last_active_at) {
      updates.push('last_active_at = ?');
      params.push(last_active_at);
    }

    params.push(id);
    req.db.prepare(`UPDATE extension_sites SET ${updates.join(', ')} WHERE id = ?`).run(...params);

    return res.json({ success: true, message: `Site "${existing.name}" updated.` });
  }
);

/**
 * DELETE /api/extension/sites/:id
 * Remove domain from extension catalog.
 */
extensionRouter.delete(
  '/sites/:id',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid site ID.' });

    const existing = req.db.prepare(`SELECT id, name, domain FROM extension_sites WHERE id = ?`).get(id) as any;
    if (!existing) return res.status(404).json({ error: 'Site not found.' });

    req.db.prepare(`DELETE FROM extension_sites WHERE id = ?`).run(id);

    appendAudit(req.db, req.demoUser?.username ?? 'admin', 'extension.site.delete', {
      site_id: id,
      name: existing.name,
      domain: existing.domain,
    });

    return res.json({ success: true, message: `Site "${existing.name}" removed from catalog.` });
  }
);

// ══════════════════════════════════════════════════════════════════════════════
//  2. LIVE EXTENSION EVENTS INGESTION & QUERY
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/extension/events
 * Ingests live interception event from the extension.
 * STRICT PRIVACY: Stores metadata only.
 */
extensionRouter.post('/events', (req, res) => {
  const b = req.body || {};
  const employee_id = b.employee_id || b.employeeId;
  const ai_service = b.ai_service || b.aiService;
  const domain = b.domain;
  const event_type = b.event_type || b.eventType;
  const file_name = b.file_name || b.fileName;
  const detected_category = b.detected_category || b.detectedCategory;
  const matched_rule = b.matched_rule || b.matchedRule;
  const action_taken = b.action_taken || b.actionTaken;
  const risk_level = b.risk_level || b.riskLevel;

  if (!ai_service || !domain || !detected_category) {
    return res.status(400).json({ error: 'ai_service, domain, and detected_category are required.' });
  }

  // Fallback defaults
  const empId = employee_id || req.demoUser?.username || 'EMP_020';
  const evType = event_type === 'file_upload' ? 'file_upload' : 'message_send';
  const act = ['blocked', 'warned', 'allowed'].includes(action_taken) ? action_taken : 'blocked';
  const risk = ['low', 'medium', 'high', 'critical'].includes(risk_level) ? risk_level : 'high';
  const rule = matched_rule || 'Baseline AI Protection Policy';

  const insert = req.db.prepare(`
    INSERT INTO extension_events (
      employee_id, ai_service, domain, event_type, file_name,
      detected_category, matched_rule, action_taken, risk_level, review_status, is_live
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', 1)
  `);

  const info = insert.run(empId, ai_service, domain, evType, file_name || null, detected_category, rule, act, risk);
  const eventId = Number(info.lastInsertRowid);

  // Update site's last active timestamp
  req.db.prepare(`
    UPDATE extension_sites
    SET last_active_at = datetime('now')
    WHERE domain = ? OR domain LIKE ?
  `).run(domain, `%${domain}%`);

  appendAudit(req.db, empId, 'extension.event.recorded', {
    event_id: eventId,
    ai_service,
    domain,
    detected_category,
    action_taken: act,
    risk_level: risk,
    // NEVER logs prompt text or secret values
  });

  return res.status(201).json({
    id: eventId,
    eventId,
    success: true,
    ai_service,
    action_taken: act,
    detected_category,
    message: 'Event metadata recorded. Raw prompt/secret discarded per privacy policy.',
  });
});

/**
 * GET /api/extension/events
 * Returns live extension events with filters.
 */
extensionRouter.get('/events', requireAuth, (req, res) => {
  const { risk, service, review, limit = 100 } = req.query;

  let sql = `
    SELECT e.*, emp.full_name as employee_name, emp.department, emp.job_role
    FROM extension_events e
    LEFT JOIN dataset_employees emp ON emp.employee_id = e.employee_id
    WHERE e.is_live = 1
  `;
  const params: any[] = [];

  if (risk && risk !== 'all') {
    sql += ` AND e.risk_level = ?`;
    params.push(risk);
  }
  if (service && service !== 'all') {
    sql += ` AND e.ai_service LIKE ?`;
    params.push(`%${service}%`);
  }
  if (review && review !== 'all') {
    sql += ` AND e.review_status = ?`;
    params.push(review);
  }

  sql += ` ORDER BY e.id DESC LIMIT ?`;
  params.push(Math.min(parseInt(String(limit), 10) || 100, 200));

  const rows = req.db.prepare(sql).all(...params);

  return res.json({
    events: rows,
    total: rows.length,
    canReview: ['administrator', 'analyst'].includes(req.demoUser?.role ?? ''),
  });
});

/**
 * PATCH /api/extension/events/:id/review
 * Reviewer marks event as Expected, Investigate, or Policy exception.
 */
extensionRouter.patch(
  '/events/:id/review',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid event ID.' });

    const reviewStatusVal = req.body.review_status || req.body.reviewStatus;
    const reviewerNoteVal = req.body.reviewer_note || req.body.reviewerNote;
    const actor = req.demoUser?.username ?? 'analyst';

    const ALLOWED_STATUSES = ['Expected', 'Investigate', 'Policy exception'];
    if (!reviewStatusVal || !ALLOWED_STATUSES.includes(reviewStatusVal)) {
      return res.status(400).json({ error: 'review_status must be Expected, Investigate, or Policy exception.' });
    }

    const existing = req.db.prepare(`SELECT id, employee_id, ai_service FROM extension_events WHERE id = ?`).get(id) as any;
    if (!existing) return res.status(404).json({ error: 'Event not found.' });

    const note = reviewerNoteVal ? String(reviewerNoteVal).trim() : null;

    req.db.prepare(`
      UPDATE extension_events
      SET review_status = ?, reviewer_note = ?, reviewed_by = ?, reviewed_at = datetime('now')
      WHERE id = ?
    `).run(reviewStatusVal, note, actor, id);

    appendAudit(req.db, actor, 'extension.event.reviewed', {
      event_id: id,
      review_status: reviewStatusVal,
      employee_id: existing.employee_id,
      ai_service: existing.ai_service,
    });

    return res.json({
      success: true,
      id,
      review_status: reviewStatusVal,
      reviewer_note: note,
      reviewed_by: actor,
      message: `Event marked as "${reviewStatusVal}".`,
    });
  }
);

// ══════════════════════════════════════════════════════════════════════════════
//  3. DASHBOARD METRICS & HISTORICAL DATASETS VIEW
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/extension/dashboard-summary
 * Summary metrics combining live extension protection and dataset status.
 */
extensionRouter.get('/dashboard-summary', requireAuth, (req, res) => {
  const sites = req.db.prepare(`SELECT id, status, is_enabled, last_active_at FROM extension_sites`).all() as any[];
  const liveEvents = req.db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN action_taken = 'warned' THEN 1 ELSE 0 END) as warned,
      SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN review_status = 'Pending' THEN 1 ELSE 0 END) as pending_review
    FROM extension_events WHERE is_live = 1
  `).get() as any;

  const datasetStats = {
    employees: (req.db.prepare(`SELECT COUNT(*) as c FROM dataset_employees`).get() as any).c,
    aiLogs: (req.db.prepare(`SELECT COUNT(*) as c FROM dataset_ai_logs`).get() as any).c,
    assets: (req.db.prepare(`SELECT COUNT(*) as c FROM dataset_assets`).get() as any).c,
    networkLogs: (req.db.prepare(`SELECT COUNT(*) as c FROM dataset_network_logs`).get() as any).c,
    incidents: (req.db.prepare(`SELECT COUNT(*) as c FROM dataset_incidents`).get() as any).c,
  };

  return res.json({
    catalog: {
      totalSites: sites.length,
      protectedSites: sites.filter(s => Boolean(s.is_enabled) && s.status === 'protected').length,
      inactiveSites: sites.filter(s => !s.is_enabled || s.status === 'inactive').length,
      unsupportedSites: sites.filter(s => s.status === 'unsupported' || s.status === 'changed').length,
    },
    liveEvents: {
      total: liveEvents.total || 0,
      blocked: liveEvents.blocked || 0,
      warned: liveEvents.warned || 0,
      critical: liveEvents.critical || 0,
      high: liveEvents.high || 0,
      pendingReview: liveEvents.pending_review || 0,
    },
    datasets: datasetStats,
  });
});

/**
 * GET /api/extension/datasets/history
 * Query historical activity logs from reference datasets (dataset b & d).
 * Clearly marked as is_live: 0.
 */
extensionRouter.get('/datasets/history', requireAuth, (req, res) => {
  const { service, risk, limit = 100 } = req.query;
  const logs = queryHistoricalLogs(req.db, Math.min(parseInt(String(limit), 10) || 100, 200), String(service || ''), String(risk || ''));

  return res.json({
    records: logs.map(l => ({
      ...l,
      is_live: 0,
      source: 'dataset_sample',
    })),
    total: logs.length,
    disclaimer: 'Historical sample data from reference CSV datasets. Kept visually separate from live extension detections.',
  });
});

/**
 * GET /api/extension/datasets/incidents
 * Query sample security incidents from reference dataset e.
 */
extensionRouter.get('/datasets/incidents', requireAuth, (req, res) => {
  const incidents = queryHistoricalIncidents(req.db, 50);

  return res.json({
    incidents: incidents.map(i => ({
      ...i,
      is_live: 0,
      source: 'dataset_sample',
    })),
    total: incidents.length,
  });
});
