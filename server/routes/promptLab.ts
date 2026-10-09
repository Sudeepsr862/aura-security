// ─── Prompt Lab Routes ────────────────────────────────────────────────────────
// GET  /api/prompt-lab/destinations — List destinations from registry + Unknown option
// POST /api/prompt-lab/scan         — In-memory scan for sensitive patterns (Admin/Analyst only)
// GET  /api/prompt-lab/history      — Metadata-only history of scans (no raw prompt/preview)

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';
import { scanPrompt } from '../scanner/scanner.js';
import { assessRisk } from '../risk/riskEngine.js';

export const promptLabRouter = Router();

const MAX_PROMPT_CHARS = 10000;
const PRIVACY_NOTICE =
  'Use synthetic examples only. AURA scans only text you enter here. Text was analyzed in-memory and not stored.';

/**
 * GET /api/prompt-lab/destinations
 * Returns available AI destinations from the registry plus an unknown option.
 */
promptLabRouter.get('/destinations', requireAuth, (req, res) => {
  const db = req.db;
  const rows = db.prepare(`
    SELECT id, name, provider, approval_status, service_type
    FROM services
    WHERE is_demo = 1
    ORDER BY name
  `).all() as Array<{
    id: number;
    name: string;
    provider: string;
    approval_status: string;
    service_type: string;
  }>;

  const destinations = rows.map((s) => ({
    id: String(s.id),
    name: `${s.name} (${s.provider})`,
    approvalStatus: s.approval_status,
    serviceType: s.service_type,
  }));

  // Add demonstration destination options
  destinations.push({
    id: 'unknown-dest',
    name: 'Unknown / Unregistered External Destination',
    approvalStatus: 'Unapproved',
    serviceType: 'Unapproved endpoint',
  });

  res.json({ destinations });
});

/**
 * POST /api/prompt-lab/scan
 * In-memory scan of synthetic prompt text.
 * Strictly restricted to administrator and analyst roles.
 * Privacy guarantee: Raw prompt is processed in-memory only and never persisted.
 */
promptLabRouter.post(
  '/scan',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-user';

    const text = typeof req.body?.text === 'string' ? req.body.text : '';
    const destination = typeof req.body?.destination === 'string' ? req.body.destination.trim() : 'Unknown destination';
    const destinationStatus = typeof req.body?.destinationStatus === 'string' ? req.body.destinationStatus : 'Unknown';

    // 1. Validate length
    if (!text || text.trim().length === 0) {
      res.status(400).json({ error: 'Please enter prompt text to analyze.' });
      return;
    }

    if (text.length > MAX_PROMPT_CHARS) {
      res.status(400).json({
        error: `Prompt text exceeds maximum scan limit of ${MAX_PROMPT_CHARS.toLocaleString()} characters (${text.length.toLocaleString()} chars provided).`,
      });
      return;
    }

    try {
      // 2. Perform in-memory scan & redaction
      const scanResult = scanPrompt(text, destination, destinationStatus);

      const categoryNames = scanResult.matches.map((m) => m.category);
      const now = new Date().toISOString();

      const isHighRiskSecret = categoryNames.some((c) => {
        const lower = c.toLowerCase();
        return lower.includes('key') || lower.includes('token') || lower.includes('password') || lower.includes('secret') || lower.includes('credential');
      });
      const isUnapprovedDest = destinationStatus === 'Unapproved' || destinationStatus === 'Unknown';

      // Compute explainable risk assessment for detected categories (in-memory, metadata only)
      const riskAssessment = assessRisk({
        destination,
        serviceApproval: destinationStatus,
        sensitivityLabel: scanResult.sensitivitySuggestion,
        promptCategories: categoryNames,
        explicitAuth: isHighRiskSecret && isUnapprovedDest ? 'denied' : null,
      });

      // 3. Persist METADATA ONLY into prompt_scans table
      // STRICT PRIVACY RULE: Never persist raw text, preview, or hash.
      db.prepare(`
        INSERT INTO prompt_scans (
          scanned_at, actor, destination, destination_status,
          categories, sensitivity_suggestion, policy_outcome, char_count
        ) VALUES (
          ?, ?, ?, ?,
          ?, ?, ?, ?
        )
      `).run(
        now,
        actor,
        destination,
        destinationStatus,
        JSON.stringify(categoryNames),
        scanResult.sensitivitySuggestion,
        scanResult.policyOutcome,
        text.length,
      );

      // 4. Audit log entry (minimal metadata only — no text, no preview)
      appendAudit(db, actor, 'PROMPT_SCAN_EXECUTED', {
        destination,
        destinationStatus,
        detectedCategories: categoryNames,
        policyOutcome: scanResult.policyOutcome,
        charCount: text.length,
      });

      // 5. Return result to the current browser session
      res.json({
        success: true,
        result: scanResult,
        riskAssessment,
        privacyNotice: PRIVACY_NOTICE,
      });
    } catch (err: unknown) {
      // Do not include prompt text in error response or server log
      res.status(500).json({
        error: 'An internal error occurred during prompt analysis.',
        detail: err instanceof Error ? err.message : 'Unknown error',
      });
    }
  },
);

/**
 * GET /api/prompt-lab/history
 * Returns recent scan metadata to prove no raw text or previews are stored.
 */
promptLabRouter.get('/history', requireAuth, (req, res) => {
  const db = req.db;
  const rows = db.prepare(`
    SELECT
      id, scanned_at, actor, destination, destination_status,
      categories, sensitivity_suggestion, policy_outcome, char_count
    FROM prompt_scans
    ORDER BY id DESC
    LIMIT 15
  `).all() as Array<{
    id: number;
    scanned_at: string;
    actor: string;
    destination: string;
    destination_status: string;
    categories: string;
    sensitivity_suggestion: string;
    policy_outcome: string;
    char_count: number;
  }>;

  const history = rows.map((r) => ({
    ...r,
    categories: JSON.parse(r.categories || '[]') as string[],
  }));

  res.json({
    history,
    privacyNotice: 'All records above are metadata only. No prompt texts or previews are stored in the database.',
  });
});
