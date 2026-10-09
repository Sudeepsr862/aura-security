// ─── Policies Routes ──────────────────────────────────────────────────────────
// Administrator-controlled demo policy settings:
// - Risk score thresholds (0-100, logically ordered)
// - Demo additive weights (0-50 bounds)
// - Transfer volume threshold (1-500 MB)
// - Severity response recommendations
//
// Strict role-based enforcement:
// - Administrators may edit settings via PATCH.
// - Analysts and Viewers have read-only access (PATCH returns HTTP 403 Forbidden).
// - Policy changes apply to future demo analyses without altering historic event scores.

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';

export const policiesRouter = Router();

export interface RiskThresholds {
  medium_threshold: number;
  high_threshold: number;
  critical_threshold: number;
}

export interface DemoWeights {
  sensitivity_restricted: number;
  sensitivity_confidential: number;
  sensitivity_internal: number;
  service_unapproved: number;
  service_under_review: number;
  auth_denied_or_mismatch: number;
  high_transfer_volume: number;
  anomaly_signal_flagged: number;
}

export interface SeverityRecommendations {
  low: string;
  medium: string;
  high: string;
  critical: string;
}

const DEFAULT_THRESHOLDS: RiskThresholds = {
  medium_threshold: 25,
  high_threshold: 50,
  critical_threshold: 75,
};

const DEFAULT_WEIGHTS: DemoWeights = {
  sensitivity_restricted: 35,
  sensitivity_confidential: 25,
  sensitivity_internal: 10,
  service_unapproved: 20,
  service_under_review: 12,
  auth_denied_or_mismatch: 20,
  high_transfer_volume: 18,
  anomaly_signal_flagged: 10,
};

const DEFAULT_RECOMMENDATIONS: SeverityRecommendations = {
  low: 'Allow or record for visibility',
  medium: 'Warn / review before sending',
  high: 'Review promptly',
  critical: 'Would block before transmission (simulation)',
};

/**
 * GET /api/policies
 * Returns demo policies, editable status based on current session role, and descriptions.
 */
policiesRouter.get('/', requireAuth, (req, res) => {
  const db = req.db;
  const userRole = req.demoUser?.role ?? 'viewer';
  const isAdmin = userRole === 'administrator';

  const rows = db.prepare(`SELECT name, description, value, updated_at FROM policies WHERE is_demo = 1`).all() as Array<{
    name: string;
    description: string;
    value: string;
    updated_at: string;
  }>;

  const policyMap = new Map<string, { value: string; description: string; updated_at: string }>();
  for (const r of rows) {
    policyMap.set(r.name, { value: r.value, description: r.description, updated_at: r.updated_at });
  }

  // Parse structured settings or fallback to defaults
  let thresholds = DEFAULT_THRESHOLDS;
  if (policyMap.has('risk_thresholds')) {
    try {
      thresholds = JSON.parse(policyMap.get('risk_thresholds')!.value);
    } catch {
      thresholds = DEFAULT_THRESHOLDS;
    }
  }

  let weights = DEFAULT_WEIGHTS;
  if (policyMap.has('demo_weights')) {
    try {
      weights = JSON.parse(policyMap.get('demo_weights')!.value);
    } catch {
      weights = DEFAULT_WEIGHTS;
    }
  }

  let volumeThresholdMb = 5;
  if (policyMap.has('volume_threshold_mb')) {
    const val = parseFloat(policyMap.get('volume_threshold_mb')!.value);
    if (!isNaN(val)) volumeThresholdMb = val;
  }

  let recommendations = DEFAULT_RECOMMENDATIONS;
  if (policyMap.has('severity_recommendations')) {
    try {
      recommendations = JSON.parse(policyMap.get('severity_recommendations')!.value);
    } catch {
      recommendations = DEFAULT_RECOMMENDATIONS;
    }
  }

  return res.json({
    thresholds,
    weights,
    volumeThresholdMb,
    recommendations,
    descriptions: {
      thresholds: 'Score cutoffs for severity assignment: Low [0, Med-1], Medium [Med, High-1], High [High, Crit-1], Critical [Crit, 100].',
      weights: 'Additive point values applied by the deterministic risk intelligence engine (clamped to 0–100 total).',
      volumeThresholdMb: 'Transfer size in MB above which an elevated transfer volume factor (+18 pts) is flagged.',
      recommendations: 'Simulated response recommendation displayed for events matching each severity bracket.',
    },
    fieldDescriptions: {
      medium_threshold: 'Risk score at or above this value triggers Medium severity (warn/review).',
      high_threshold: 'Risk score at or above this value triggers High severity (prompt review).',
      critical_threshold: 'Risk score at or above this value triggers Critical severity (simulated block recommendation).',
      sensitivity_restricted: 'Points added when data classification is marked Restricted.',
      sensitivity_confidential: 'Points added when data classification is marked Confidential.',
      sensitivity_internal: 'Points added when data classification is marked Internal.',
      service_unapproved: 'Points added when AI destination approval status is Unapproved.',
      service_under_review: 'Points added when AI destination approval status is Needs review or Unknown.',
      auth_denied_or_mismatch: 'Points added when user lacks permission or authorization is explicitly denied.',
      high_transfer_volume: 'Points added when network transfer size exceeds the configured volume threshold.',
      anomaly_signal_flagged: 'Points added when supplied network metadata contains an explicit anomaly flag.',
    },
    canEdit: isAdmin,
    userRole,
    policyNotice:
      'Policy updates take effect for future demo event processing and simulations. Historical event scores and timestamps remain untouched to preserve audit integrity.',
    demoNote: 'These are sample policy settings for local demonstration. No external systems or firewalls are modified.',
  });
});

/**
 * PATCH /api/policies
 * Update policy settings.
 * Enforces: Administrator role only. Analysts and Viewers receive HTTP 403 Forbidden.
 */
policiesRouter.patch(
  '/',
  requireAuth,
  requireRole('administrator'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-admin';

    const { thresholds, weights, volumeThresholdMb } = req.body;

    if (!thresholds && !weights && volumeThresholdMb === undefined) {
      return res.status(400).json({ error: 'No policy settings provided in request body.' });
    }

    // 1. Validate Thresholds if provided
    if (thresholds) {
      const { medium_threshold, high_threshold, critical_threshold } = thresholds;

      if (
        typeof medium_threshold !== 'number' ||
        typeof high_threshold !== 'number' ||
        typeof critical_threshold !== 'number'
      ) {
        return res.status(400).json({
          error: 'Thresholds must be numbers: medium_threshold, high_threshold, critical_threshold.',
        });
      }

      if (
        medium_threshold <= 0 ||
        medium_threshold >= high_threshold ||
        high_threshold >= critical_threshold ||
        critical_threshold > 100
      ) {
        return res.status(400).json({
          error: 'Thresholds must be logically ordered and within 1–100: 0 < Medium < High < Critical <= 100.',
        });
      }

      db.prepare(`
        INSERT INTO policies (name, description, value, updated_at)
        VALUES ('risk_thresholds', 'Configurable score cutoff thresholds', ?, datetime('now'))
        ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
      `).run(JSON.stringify({ medium_threshold, high_threshold, critical_threshold }));
    }

    // 2. Validate Weights if provided
    if (weights) {
      const requiredWeightKeys: (keyof DemoWeights)[] = [
        'sensitivity_restricted',
        'sensitivity_confidential',
        'sensitivity_internal',
        'service_unapproved',
        'service_under_review',
        'auth_denied_or_mismatch',
        'high_transfer_volume',
        'anomaly_signal_flagged',
      ];

      for (const key of requiredWeightKeys) {
        if (weights[key] !== undefined) {
          const val = weights[key];
          if (typeof val !== 'number' || isNaN(val) || val < 0 || val > 50) {
            return res.status(400).json({
              error: `Weight '${key}' must be a number between 0 and 50 points.`,
            });
          }
        }
      }

      // Merge with existing weights
      const existingRow = db.prepare(`SELECT value FROM policies WHERE name = 'demo_weights'`).get() as { value: string } | undefined;
      let mergedWeights = DEFAULT_WEIGHTS;
      if (existingRow) {
        try {
          mergedWeights = { ...mergedWeights, ...JSON.parse(existingRow.value) };
        } catch {
          // ignore
        }
      }
      mergedWeights = { ...mergedWeights, ...weights };

      db.prepare(`
        INSERT INTO policies (name, description, value, updated_at)
        VALUES ('demo_weights', 'Documented additive weights per risk factor', ?, datetime('now'))
        ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
      `).run(JSON.stringify(mergedWeights));
    }

    // 3. Validate Volume Threshold if provided
    if (volumeThresholdMb !== undefined) {
      const vol = Number(volumeThresholdMb);
      if (isNaN(vol) || vol < 1 || vol > 500) {
        return res.status(400).json({
          error: 'Transfer volume threshold must be a number between 1 and 500 MB.',
        });
      }

      db.prepare(`
        INSERT INTO policies (name, description, value, updated_at)
        VALUES ('volume_threshold_mb', 'Data transfer volume anomaly threshold in MB', ?, datetime('now'))
        ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
      `).run(String(vol));
    }

    // Audit log (actor, time, action, target - no prompt/secret data)
    appendAudit(db, actor, 'policy.update', {
      updatedFields: Object.keys(req.body),
    });

    return res.json({
      success: true,
      message: 'Demo policy configuration updated successfully.',
      policyNotice:
        'Changes take effect for future demo event processing and simulations. Historic records remain unchanged.',
    });
  }
);
