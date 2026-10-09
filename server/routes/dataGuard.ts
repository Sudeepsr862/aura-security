// ─── Data Guard Routes ───────────────────────────────────────────────────────
// Phase 7: Data-sharing policies, file inspection, transfer attempts,
// proxy inspection, incoming traffic, and file content analysis.
//
// STRICT PRIVACY GUARANTEE:
// - No raw file content, passwords, API keys, tokens, or secrets persisted.
// - Detected secrets used for matching only, then discarded immediately.
// - Only metadata, categories, and redacted previews stored.

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';
import {
  inspectFileContent,
  proxyInspect,
  inspectIncoming,
  detectFileType,
  type DataSharingRule,
} from '../scanner/fileInspector.js';

export const dataGuardRouter = Router();

// ── Helper: load active data-sharing rules from DB ───────────────────────────
function loadRules(db: any): DataSharingRule[] {
  const rows = db.prepare(`
    SELECT id, rule_name, data_types, allowed_tools, blocked_tools,
           action, description, is_active
    FROM data_sharing_rules WHERE is_demo = 1
  `).all() as Array<{
    id: number;
    rule_name: string;
    data_types: string;
    allowed_tools: string;
    blocked_tools: string;
    action: 'allow' | 'warn' | 'block';
    description: string;
    is_active: number;
  }>;

  return rows.map(r => ({
    id: r.id,
    rule_name: r.rule_name,
    data_types: JSON.parse(r.data_types),
    allowed_tools: JSON.parse(r.allowed_tools),
    blocked_tools: JSON.parse(r.blocked_tools),
    action: r.action,
    description: r.description,
    is_active: Boolean(r.is_active),
  }));
}

// ══════════════════════════════════════════════════════════════════════════════
//  1. DATA-SHARING RULES CRUD
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/data-guard/rules
 * List all data-sharing policy rules. All roles may view.
 */
dataGuardRouter.get('/rules', requireAuth, (req, res) => {
  const rules = loadRules(req.db);
  const userRole = req.demoUser?.role ?? 'viewer';

  return res.json({
    rules,
    canEdit: userRole === 'administrator',
    userRole,
    demoNote: 'These are sample data-sharing policy rules for demonstration. ' +
      'In production, these would integrate with your organization\'s DLP and compliance systems.',
  });
});

/**
 * POST /api/data-guard/rules
 * Create a new data-sharing rule. Admin only.
 */
dataGuardRouter.post(
  '/rules',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const { rule_name, data_types, allowed_tools, blocked_tools, action, description } = req.body;

    if (!rule_name || typeof rule_name !== 'string' || rule_name.trim().length < 2) {
      return res.status(400).json({ error: 'rule_name is required (min 2 characters).' });
    }
    if (!Array.isArray(data_types) || data_types.length === 0) {
      return res.status(400).json({ error: 'data_types must be a non-empty array of category names.' });
    }
    if (!['allow', 'warn', 'block'].includes(action)) {
      return res.status(400).json({ error: 'action must be allow, warn, or block.' });
    }

    try {
      const stmt = req.db.prepare(`
        INSERT INTO data_sharing_rules (rule_name, data_types, allowed_tools, blocked_tools, action, description)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      const info = stmt.run(
        rule_name.trim(),
        JSON.stringify(data_types),
        JSON.stringify(allowed_tools ?? []),
        JSON.stringify(blocked_tools ?? ['*']),
        action,
        description ?? '',
      );

      appendAudit(req.db, req.demoUser?.username ?? 'system', 'data_sharing_rule.create', {
        rule_id: Number(info.lastInsertRowid),
        rule_name: rule_name.trim(),
        action,
      });

      return res.json({
        success: true,
        id: Number(info.lastInsertRowid),
        message: `Data-sharing rule "${rule_name.trim()}" created.`,
      });
    } catch (e: any) {
      if (e?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: `A rule named "${rule_name}" already exists.` });
      }
      throw e;
    }
  }
);

/**
 * PATCH /api/data-guard/rules/:id
 * Update a data-sharing rule. Admin only.
 */
dataGuardRouter.patch(
  '/rules/:id',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid rule ID.' });

    const existing = req.db.prepare(
      `SELECT id FROM data_sharing_rules WHERE id = ?`
    ).get(id);
    if (!existing) return res.status(404).json({ error: 'Rule not found.' });

    const { data_types, allowed_tools, blocked_tools, action, description, is_active } = req.body;
    const updates: string[] = [];
    const params: any[] = [];

    if (data_types !== undefined) {
      if (!Array.isArray(data_types)) return res.status(400).json({ error: 'data_types must be an array.' });
      updates.push('data_types = ?');
      params.push(JSON.stringify(data_types));
    }
    if (allowed_tools !== undefined) {
      updates.push('allowed_tools = ?');
      params.push(JSON.stringify(allowed_tools));
    }
    if (blocked_tools !== undefined) {
      updates.push('blocked_tools = ?');
      params.push(JSON.stringify(blocked_tools));
    }
    if (action !== undefined) {
      if (!['allow', 'warn', 'block'].includes(action)) {
        return res.status(400).json({ error: 'action must be allow, warn, or block.' });
      }
      updates.push('action = ?');
      params.push(action);
    }
    if (description !== undefined) {
      updates.push('description = ?');
      params.push(description);
    }
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      params.push(is_active ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update.' });
    }

    updates.push("updated_at = datetime('now')");
    params.push(id);

    req.db.prepare(
      `UPDATE data_sharing_rules SET ${updates.join(', ')} WHERE id = ?`
    ).run(...params);

    appendAudit(req.db, req.demoUser?.username ?? 'system', 'data_sharing_rule.update', {
      rule_id: id,
      updatedFields: Object.keys(req.body),
    });

    return res.json({ success: true, message: `Rule #${id} updated.` });
  }
);

/**
 * DELETE /api/data-guard/rules/:id
 * Delete a data-sharing rule. Admin only.
 */
dataGuardRouter.delete(
  '/rules/:id',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid rule ID.' });

    const existing = req.db.prepare(
      `SELECT rule_name FROM data_sharing_rules WHERE id = ?`
    ).get(id) as { rule_name: string } | undefined;
    if (!existing) return res.status(404).json({ error: 'Rule not found.' });

    req.db.prepare(`DELETE FROM data_sharing_rules WHERE id = ?`).run(id);

    appendAudit(req.db, req.demoUser?.username ?? 'system', 'data_sharing_rule.delete', {
      rule_id: id,
      rule_name: existing.rule_name,
    });

    return res.json({ success: true, message: `Rule "${existing.rule_name}" deleted.` });
  }
);

// ══════════════════════════════════════════════════════════════════════════════
//  2. OUTBOUND FILE INSPECTION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/data-guard/inspect-outbound
 * Inspect synthetic file content before transfer. Returns findings + rule matches.
 * Body: { filename, content, destination }
 *
 * PRIVACY: Content is analyzed in-memory and discarded. Only metadata is stored.
 */
dataGuardRouter.post('/inspect-outbound', requireAuth, (req, res) => {
  const { filename, content, destination } = req.body;
  const actor = req.demoUser?.username ?? 'system';

  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'filename is required.' });
  }
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content is required (synthetic file text).' });
  }
  if (content.length > 500000) {
    return res.status(400).json({ error: 'Content exceeds 500 KB limit for demo inspection.' });
  }
  if (!destination || typeof destination !== 'string') {
    return res.status(400).json({ error: 'destination is required.' });
  }

  // Load rules and run inspection
  const rules = loadRules(req.db);
  const result = inspectFileContent(filename, content, destination, rules);

  // Look up person_id from actor
  const person = req.db.prepare(
    `SELECT id FROM synthetic_people WHERE demo_email LIKE ? LIMIT 1`
  ).get(`%${actor}%`) as { id: number } | undefined;

  // Persist inspection metadata (NO raw content or secrets stored)
  const insertInspection = req.db.prepare(`
    INSERT INTO file_inspections (
      filename, file_size_bytes, file_type, destination, direction,
      detected_types, matched_rules, risk_level, action_taken,
      action_reason, limitations, inspector, actor, person_id
    ) VALUES (?, ?, ?, ?, 'outbound', ?, ?, ?, ?, ?, ?, 'local', ?, ?)
  `);

  const info = insertInspection.run(
    filename,
    result.fileSizeBytes,
    result.fileType,
    destination,
    JSON.stringify(result.detectedTypes.map(d => d.category)),
    JSON.stringify(result.matchedRules),
    result.riskLevel,
    result.actionTaken,
    result.actionReason,
    JSON.stringify(result.limitations),
    actor,
    person?.id ?? null,
  );

  const inspectionId = Number(info.lastInsertRowid);

  // Track repeated attempts if blocked or warned
  if (result.actionTaken === 'blocked' || result.actionTaken === 'warned') {
    for (const match of result.detectedTypes) {
      for (const ruleName of result.matchedRules) {
        trackAttempt(req.db, person?.id ?? null, actor, destination, match.category, ruleName);
      }
    }
    // If no specific rules matched but scanner blocked, track with generic rule
    if (result.matchedRules.length === 0 && result.detectedTypes.length > 0) {
      for (const match of result.detectedTypes) {
        trackAttempt(req.db, person?.id ?? null, actor, destination, match.category, 'scanner-default');
      }
    }
  }

  appendAudit(req.db, actor, 'file.inspect.outbound', {
    inspection_id: inspectionId,
    filename,
    destination,
    action_taken: result.actionTaken,
    risk_level: result.riskLevel,
    finding_count: result.totalFindings,
    // NO secret values logged
  });

  return res.json({
    success: true,
    inspectionId,
    result: {
      ...result,
      // Truncate redacted preview for response
      redactedPreview: result.redactedPreview.substring(0, 2000),
    },
    privacyNotice:
      'Raw file content was analyzed in-memory and discarded. ' +
      'Only detection metadata, categories, and redacted preview are stored. ' +
      'No passwords, API keys, tokens, or secrets were persisted.',
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  3. PROXY / GATEWAY INSPECTION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/data-guard/inspect-proxy
 * Simulated second-layer inspection via authorized proxy/gateway.
 * Body: { filename, content, destination, isEncrypted? }
 */
dataGuardRouter.post('/inspect-proxy', requireAuth, (req, res) => {
  const { filename, content, destination, isEncrypted } = req.body;
  const actor = req.demoUser?.username ?? 'system';

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content is required.' });
  }
  if (!destination || typeof destination !== 'string') {
    return res.status(400).json({ error: 'destination is required.' });
  }

  const encrypted = isEncrypted !== false; // Default to encrypted (HTTPS)
  const proxyResult = proxyInspect(content, destination, encrypted);

  // Also do the local inspection for the parent record
  const rules = loadRules(req.db);
  const localResult = inspectFileContent(filename ?? 'unknown.txt', content, destination, rules);

  // Store local inspection
  const info = req.db.prepare(`
    INSERT INTO file_inspections (
      filename, file_size_bytes, file_type, destination, direction,
      detected_types, matched_rules, risk_level, action_taken,
      action_reason, limitations, inspector, actor
    ) VALUES (?, ?, ?, ?, 'outbound', ?, ?, ?, ?, ?, ?, 'proxy', ?)
  `).run(
    filename ?? 'unknown.txt',
    Buffer.byteLength(content, 'utf-8'),
    detectFileType(filename ?? 'unknown.txt'),
    destination,
    JSON.stringify(localResult.detectedTypes.map(d => d.category)),
    JSON.stringify(localResult.matchedRules),
    localResult.riskLevel,
    proxyResult.actionTaken,
    localResult.actionReason,
    JSON.stringify(localResult.limitations),
    actor,
  );
  const inspectionId = Number(info.lastInsertRowid);

  // Store proxy inspection record
  req.db.prepare(`
    INSERT INTO proxy_inspections (
      inspection_id, proxy_layer, can_inspect, inspection_note,
      detected_types, action_taken, limitation
    ) VALUES (?, 'simulated-gateway', ?, ?, ?, ?, ?)
  `).run(
    inspectionId,
    proxyResult.canInspect ? 1 : 0,
    proxyResult.inspectionNote,
    JSON.stringify(proxyResult.detectedTypes.map(d => d.category)),
    proxyResult.actionTaken,
    proxyResult.limitation,
  );

  // Track repeated attempts for proxy-blocked items
  if (proxyResult.actionTaken === 'blocked' || proxyResult.actionTaken === 'warned') {
    for (const match of proxyResult.detectedTypes) {
      trackAttempt(req.db, null, actor, destination, match.category, 'proxy-policy');
    }
  }

  appendAudit(req.db, actor, 'file.inspect.proxy', {
    inspection_id: inspectionId,
    filename: filename ?? 'unknown.txt',
    destination,
    can_inspect: proxyResult.canInspect,
    proxy_action: proxyResult.actionTaken,
  });

  return res.json({
    success: true,
    inspectionId,
    localInspection: {
      ...localResult,
      redactedPreview: localResult.redactedPreview.substring(0, 2000),
    },
    proxyInspection: proxyResult,
    combinedAction: proxyResult.actionTaken === 'blocked' || localResult.actionTaken === 'blocked'
      ? 'blocked'
      : proxyResult.actionTaken === 'warned' || localResult.actionTaken === 'warned'
        ? 'warned'
        : 'allowed',
    privacyNotice:
      'Content analyzed in-memory by both local and proxy layers, then discarded. ' +
      'No secrets persisted. Proxy limitations clearly noted in the response.',
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  4. INCOMING TRAFFIC INSPECTION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/data-guard/inspect-incoming
 * Check incoming files for malware and defined risks.
 * Body: { filename, content, sourceOrigin? }
 */
dataGuardRouter.post('/inspect-incoming', requireAuth, (req, res) => {
  const { filename, content, sourceOrigin } = req.body;
  const actor = req.demoUser?.username ?? 'system';

  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'filename is required.' });
  }
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content is required.' });
  }
  if (content.length > 500000) {
    return res.status(400).json({ error: 'Content exceeds 500 KB limit for demo.' });
  }

  const result = inspectIncoming(filename, content, sourceOrigin ?? 'unknown');

  // Store incoming inspection metadata (NO raw content)
  req.db.prepare(`
    INSERT INTO incoming_inspections (
      filename, file_size_bytes, source_origin, detected_risks,
      risk_level, action_taken, action_reason, malware_indicators
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    filename,
    result.fileSizeBytes,
    result.sourceOrigin,
    JSON.stringify(result.detectedRisks),
    result.riskLevel,
    result.actionTaken,
    result.actionReason,
    JSON.stringify(result.malwareIndicators),
  );

  appendAudit(req.db, actor, 'file.inspect.incoming', {
    filename,
    source_origin: result.sourceOrigin,
    risk_level: result.riskLevel,
    action_taken: result.actionTaken,
    malware_count: result.malwareIndicators.length,
  });

  return res.json({
    success: true,
    result: {
      ...result,
      // Explicitly do NOT return raw content
    },
    privacyNotice:
      'File content was analyzed in-memory for malware signatures and discarded. ' +
      'No file content is stored. Only detection metadata and risk assessments are persisted.',
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  5. TRANSFER ATTEMPT TRACKING
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Helper: track or increment a transfer attempt.
 * Does NOT automatically label a person as malicious — only records the attempt
 * and flags for authorized review.
 */
function trackAttempt(
  db: any,
  personId: number | null,
  personEmail: string,
  destination: string,
  dataType: string,
  matchedRule: string,
): void {
  // Check for existing attempt group
  const existing = db.prepare(`
    SELECT id, attempt_count FROM transfer_attempts
    WHERE destination = ? AND data_type = ? AND matched_rule = ?
      AND (person_id = ? OR person_email = ?)
    LIMIT 1
  `).get(destination, dataType, matchedRule, personId, personEmail) as
    { id: number; attempt_count: number } | undefined;

  if (existing) {
    const newCount = existing.attempt_count + 1;
    // Flag for review after 3+ attempts
    const shouldFlag = newCount >= 3 ? 1 : 0;
    db.prepare(`
      UPDATE transfer_attempts
      SET attempt_count = ?, last_attempt_at = datetime('now'),
          flagged_for_review = CASE WHEN ? >= 3 THEN 1 ELSE flagged_for_review END
      WHERE id = ?
    `).run(newCount, newCount, existing.id);
  } else {
    db.prepare(`
      INSERT INTO transfer_attempts (
        person_id, person_email, destination, data_type,
        matched_rule, attempt_count, last_attempt_at
      ) VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
    `).run(personId, personEmail, destination, dataType, matchedRule);
  }
}

/**
 * GET /api/data-guard/attempts
 * List flagged and recent transfer attempts. Analyst+ access.
 */
dataGuardRouter.get(
  '/attempts',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const flaggedOnly = req.query.flagged === 'true';
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);

    let sql = `
      SELECT ta.*, sp.display_name as person_name
      FROM transfer_attempts ta
      LEFT JOIN synthetic_people sp ON sp.id = ta.person_id
    `;
    if (flaggedOnly) {
      sql += ` WHERE ta.flagged_for_review = 1`;
    }
    sql += ` ORDER BY ta.last_attempt_at DESC LIMIT ?`;

    const rows = req.db.prepare(sql).all(limit);

    return res.json({
      attempts: rows,
      disclaimer:
        'Repeated attempts are recorded for authorized review. ' +
        'A high attempt count does NOT automatically indicate malicious intent — ' +
        'it may reflect workflow issues, misconfigured tools, or legitimate retry patterns.',
    });
  }
);

/**
 * PATCH /api/data-guard/attempts/:id/review
 * Add a review note to a flagged attempt. Analyst+ access.
 */
dataGuardRouter.patch(
  '/attempts/:id/review',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const id = parseInt(String(req.params.id), 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid attempt ID.' });

    const { review_note } = req.body;
    if (!review_note || typeof review_note !== 'string' || review_note.trim().length < 3) {
      return res.status(400).json({ error: 'review_note is required (min 3 chars).' });
    }
    if (review_note.length > 1000) {
      return res.status(400).json({ error: 'review_note max 1000 characters.' });
    }

    const existing = req.db.prepare(`SELECT id FROM transfer_attempts WHERE id = ?`).get(id);
    if (!existing) return res.status(404).json({ error: 'Attempt not found.' });

    req.db.prepare(`
      UPDATE transfer_attempts SET review_note = ? WHERE id = ?
    `).run(review_note.trim(), id);

    appendAudit(req.db, req.demoUser?.username ?? 'system', 'transfer_attempt.review', {
      attempt_id: id,
      // No secret data in audit
    });

    return res.json({ success: true, message: 'Review note added.' });
  }
);

// ══════════════════════════════════════════════════════════════════════════════
//  6. INSPECTION HISTORY
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/data-guard/history
 * List recent file inspection records.
 */
dataGuardRouter.get('/history', requireAuth, (req, res) => {
  const direction = req.query.direction as string ?? 'all';
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);

  let whereClause = '';
  if (direction === 'outbound') whereClause = `WHERE fi.direction = 'outbound'`;
  else if (direction === 'inbound') whereClause = `WHERE fi.direction = 'inbound'`;

  const rows = req.db.prepare(`
    SELECT fi.*, sp.display_name as person_name,
           pi.can_inspect as proxy_can_inspect,
           pi.inspection_note as proxy_note,
           pi.limitation as proxy_limitation,
           pi.action_taken as proxy_action
    FROM file_inspections fi
    LEFT JOIN synthetic_people sp ON sp.id = fi.person_id
    LEFT JOIN proxy_inspections pi ON pi.inspection_id = fi.id
    ${whereClause}
    ORDER BY fi.created_at DESC LIMIT ?
  `).all(limit);

  return res.json({
    inspections: rows.map((r: any) => ({
      ...r,
      detected_types: JSON.parse(r.detected_types || '[]'),
      matched_rules: JSON.parse(r.matched_rules || '[]'),
      limitations: JSON.parse(r.limitations || '[]'),
      proxy: r.proxy_can_inspect !== null ? {
        canInspect: Boolean(r.proxy_can_inspect),
        note: r.proxy_note,
        limitation: r.proxy_limitation,
        action: r.proxy_action,
      } : null,
    })),
    privacyNotice: 'Inspection history contains metadata only — no raw file content or secrets.',
  });
});

/**
 * GET /api/data-guard/incoming-history
 * List recent incoming traffic inspections.
 */
dataGuardRouter.get('/incoming-history', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);

  const rows = req.db.prepare(`
    SELECT * FROM incoming_inspections
    ORDER BY created_at DESC LIMIT ?
  `).all(limit);

  return res.json({
    inspections: rows.map((r: any) => ({
      ...r,
      detected_risks: JSON.parse(r.detected_risks || '[]'),
      malware_indicators: JSON.parse(r.malware_indicators || '[]'),
    })),
    privacyNotice: 'Only detection metadata stored — no raw file content persisted.',
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  7. OVERVIEW / STATS
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/data-guard/overview
 * Summary stats for the Data Guard dashboard.
 */
dataGuardRouter.get('/overview', requireAuth, (req, res) => {
  const stats = {
    totalRules: (req.db.prepare(`SELECT COUNT(*) as c FROM data_sharing_rules`).get() as any).c,
    activeRules: (req.db.prepare(`SELECT COUNT(*) as c FROM data_sharing_rules WHERE is_active = 1`).get() as any).c,
    totalOutboundInspections: (req.db.prepare(`SELECT COUNT(*) as c FROM file_inspections WHERE direction = 'outbound'`).get() as any).c,
    totalIncomingInspections: (req.db.prepare(`SELECT COUNT(*) as c FROM incoming_inspections`).get() as any).c,
    blockedTransfers: (req.db.prepare(`SELECT COUNT(*) as c FROM file_inspections WHERE action_taken = 'blocked'`).get() as any).c,
    warnedTransfers: (req.db.prepare(`SELECT COUNT(*) as c FROM file_inspections WHERE action_taken = 'warned'`).get() as any).c,
    flaggedAttempts: (req.db.prepare(`SELECT COUNT(*) as c FROM transfer_attempts WHERE flagged_for_review = 1`).get() as any).c,
    totalAttempts: (req.db.prepare(`SELECT COUNT(*) as c FROM transfer_attempts`).get() as any).c,
    quarantinedIncoming: (req.db.prepare(`SELECT COUNT(*) as c FROM incoming_inspections WHERE action_taken IN ('quarantined','blocked')`).get() as any).c,
    proxyInspections: (req.db.prepare(`SELECT COUNT(*) as c FROM proxy_inspections`).get() as any).c,
  };

  return res.json({
    stats,
    demoNote: 'All counts reflect synthetic demo data. ' +
      'This prototype uses simulated file content and does not monitor real network traffic.',
  });
});
