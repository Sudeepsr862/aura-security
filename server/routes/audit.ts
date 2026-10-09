// ─── Audit Log Routes ──────────────────────────────────────────────────────────
// Read-only tamper-evident audit history log for demo governance.
// Evaluates SHA-256 hash chain validity across records.
// Guarantees zero storage of prompt text, secrets, or raw request payloads.

import { Router } from 'express';
import { createHash } from 'node:crypto';
import { requireAuth } from '../middleware/auth.js';

export const auditRouter = Router();

/**
 * GET /api/audit
 * Returns recent audit log entries and verifies tamper-evident hash chain integrity.
 */
auditRouter.get('/', requireAuth, (req, res) => {
  const db = req.db;
  const limit = Math.min(100, Math.max(10, parseInt(req.query.limit as string, 10) || 50));

  // 1. Fetch all records in chronological order to verify hash chain
  const allRows = db.prepare(`
    SELECT id, actor, action, detail, prev_hash, entry_hash, created_at
    FROM audit_log
    ORDER BY id ASC
  `).all() as Array<{
    id: number;
    actor: string;
    action: string;
    detail: string;
    prev_hash: string;
    entry_hash: string;
    created_at: string;
  }>;

  let isChainValid = true;
  let brokenAtId: number | null = null;
  let expectedPrev = '';

  for (const row of allRows) {
    if (row.prev_hash !== expectedPrev) {
      isChainValid = false;
      brokenAtId = row.id;
      break;
    }

    const content = `${row.prev_hash}|${row.actor}|${row.action}|${row.detail}|${row.created_at}`;
    const computedHash = createHash('sha256').update(content).digest('hex');

    if (computedHash !== row.entry_hash) {
      isChainValid = false;
      brokenAtId = row.id;
      break;
    }

    expectedPrev = row.entry_hash;
  }

  // 2. Fetch the most recent entries for display
  const recentRows = db.prepare(`
    SELECT id, actor, action, detail, prev_hash, entry_hash, created_at
    FROM audit_log
    ORDER BY id DESC
    LIMIT ?
  `).all(limit) as Array<{
    id: number;
    actor: string;
    action: string;
    detail: string;
    prev_hash: string;
    entry_hash: string;
    created_at: string;
  }>;

  const entries = recentRows.map((r) => {
    let parsedDetail = {};
    try {
      parsedDetail = JSON.parse(r.detail || '{}');
    } catch {
      parsedDetail = {};
    }

    return {
      id: r.id,
      actor: r.actor,
      action: r.action,
      detail: parsedDetail,
      prevHash: r.prev_hash,
      entryHash: r.entry_hash,
      createdAt: r.created_at,
    };
  });

  return res.json({
    entries,
    totalEntries: allRows.length,
    isChainValid,
    chainStatus: isChainValid
      ? 'Tamper-evident hash chain verified'
      : `Tamper-evident chain discrepancy detected at record ID ${brokenAtId}`,
    brokenAtId,
    disclaimer:
      'Audit history is maintained as an append-only, tamper-evident SHA-256 hash chain. No raw prompt text, sensitive credentials, or full payloads are recorded.',
  });
});
