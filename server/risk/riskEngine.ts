// ─── AURA Explainable Risk Engine ──────────────────────────────────────────
// Transparent, deterministic rules engine for prototype risk assessment.
//
// DESIGN PRINCIPLES:
// 1. Transparent additive model: Each point is tied to an explicit, named factor.
// 2. Demo policy weights: Documented weights, clamped to 0–100.
// 3. No invented facts: Missing data is documented as missing context, lowering confidence.
// 4. No secret leakage: Only categories, counts, and classification labels are scored.
// 5. Simulated recommendations: "Would block" is visibly marked as (simulation).
// 6. Identity correlation: Uses synthetic directory records without connecting to real IDPs.

export type SensitivityLabel = 'Public' | 'Internal' | 'Confidential' | 'Restricted';
export type ServiceApproval = 'Approved' | 'Unapproved' | 'Needs review' | 'Unknown';
export type AuthStatus = 'authorized' | 'denied' | 'unknown' | 'mismatch';
export type RiskSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export interface RiskFactor {
  id: string;
  name: string;
  points: number;
  evidence: string;
  isMissingContext?: boolean;
}

export interface IdentityCorrelation {
  userListed: boolean;
  userName?: string;
  userEmail?: string;
  deviceKnown: boolean;
  deviceLabel?: string;
  servicePermitted: boolean | 'unknown';
  globalApproval: ServiceApproval;
  authStatus: AuthStatus;
  isExplicitAuth: boolean;
  notes: string;
}

export interface SyntheticPersonRecord {
  id: number;
  display_name: string;
  demo_email: string;
  department?: string;
  role_title?: string;
}

export interface SyntheticDeviceRecord {
  id: number;
  label: string;
  person_id: number | null;
  os_label?: string;
}

export interface RiskAssessmentInput {
  destination: string;
  port?: number | null;
  classification?: string; // 'Likely cloud AI' | 'Possible local AI' | 'Ordinary web' | 'Uncertain'
  classificationConfidence?: number;
  sensitivityLabel?: SensitivityLabel | string;
  serviceApproval?: ServiceApproval | string;
  byteCount?: number;
  isAnomalySignal?: boolean;

  // Identity inputs from event / metadata
  userEmail?: string | null;
  userName?: string | null;
  deviceLabel?: string | null;
  explicitAuth?: 'authorized' | 'denied' | null;

  // Correlated synthetic records from directory
  syntheticUser?: SyntheticPersonRecord | null;
  syntheticDevice?: SyntheticDeviceRecord | null;
  isServicePermittedForUser?: boolean | null;

  // Historical / repetition signals from stored dataset
  destinationOccurrenceCount?: number;
  userPriorWarningsCount?: number;

  // Prompt lab detected categories (if applicable, without raw text)
  promptCategories?: string[];
}

export interface RiskAssessmentResult {
  score: number; // clamped 0..100
  severity: RiskSeverity;
  factors: RiskFactor[];
  identityCorrelation: IdentityCorrelation;
  confidence: ConfidenceLevel;
  missingContext: string[];
  explanation: string;
  recommendation: string;
  isSimulatedAction: boolean;
}

// ── Documented Demo Policy Weights ──────────────────────────────────────────
export const DEMO_POLICY_WEIGHTS = {
  // Data sensitivity
  sensitivity_public: 0,
  sensitivity_internal: 10,
  sensitivity_confidential: 25,
  sensitivity_restricted: 35,

  // Service approval
  service_approved: 0,
  service_unapproved: 20,
  service_under_review_or_unknown: 12,

  // Authorization & identity
  auth_denied_or_mismatch: 20,
  auth_unknown: 8,
  auth_authorized: 0,
  unlisted_synthetic_user: 5,
  unmanaged_synthetic_device: 5,

  // Data volume & anomaly signals
  high_transfer_volume: 18, // >= 5 MB
  anomaly_signal_flagged: 10,

  // Historical patterns
  first_seen_destination: 5,
  repeated_warning_events: 8,
} as const;

export const DEMO_VOLUME_THRESHOLD_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Correlates synthetic identity, device, and service authorization.
 * Preserves explicit authorization; infers only when missing.
 */
export function correlateIdentity(input: {
  userEmail?: string | null;
  userName?: string | null;
  deviceLabel?: string | null;
  serviceApproval?: ServiceApproval | string;
  explicitAuth?: 'authorized' | 'denied' | null;
  syntheticUser?: SyntheticPersonRecord | null;
  syntheticDevice?: SyntheticDeviceRecord | null;
  isServicePermittedForUser?: boolean | null;
}): IdentityCorrelation {
  const globalApproval = (input.serviceApproval as ServiceApproval) || 'Unknown';
  const userListed = !!input.syntheticUser;
  const deviceKnown = !!input.syntheticDevice;

  const isExplicit = input.explicitAuth != null;
  let authStatus: AuthStatus = 'unknown';
  let notes = '';

  if (isExplicit) {
    // Preserve explicit authorization supplied by the event
    authStatus = input.explicitAuth === 'authorized' ? 'authorized' : 'denied';
    notes = `Supplied event explicitly marked authorization as '${authStatus}'.`;
  } else {
    // Infer authorization from available synthetic directory records
    if (!userListed && !deviceKnown) {
      authStatus = 'unknown';
      notes = 'User and device not found in synthetic directory; authorization is unknown and requires review.';
    } else if (!userListed) {
      authStatus = 'unknown';
      notes = 'User is unlisted in synthetic directory; authorization is unknown.';
    } else if (!deviceKnown) {
      authStatus = 'unknown';
      notes = 'Device is unmanaged/unlisted in synthetic directory; authorization requires review.';
    } else {
      // Both user and device are listed in synthetic directory
      if (input.isServicePermittedForUser === false) {
        authStatus = 'mismatch';
        notes = `Authorization mismatch: ${input.syntheticUser?.display_name || 'User'} is known, but destination is not on their sample permitted services list.`;
      } else if (input.isServicePermittedForUser === true) {
        authStatus = 'authorized';
        notes = `Authorized: Destination is listed on ${input.syntheticUser?.display_name}'s sample permitted services list.`;
      } else {
        authStatus = 'unknown';
        notes = 'Service permission for this user is unverified; authorization status is tentative.';
      }
    }
  }

  const servicePermitted =
    input.isServicePermittedForUser != null ? input.isServicePermittedForUser : 'unknown';

  return {
    userListed,
    userName: input.syntheticUser?.display_name || input.userName || undefined,
    userEmail: input.syntheticUser?.demo_email || input.userEmail || undefined,
    deviceKnown,
    deviceLabel: input.syntheticDevice?.label || input.deviceLabel || undefined,
    servicePermitted,
    globalApproval,
    authStatus,
    isExplicitAuth: isExplicit,
    notes,
  };
}

/**
 * Calculates deterministic, explainable risk score for an event or prompt scan.
 */
export function assessRisk(input: RiskAssessmentInput): RiskAssessmentResult {
  const factors: RiskFactor[] = [];
  const factorIds = new Set<string>();
  const missingContext: string[] = [];

  function addFactor(factor: RiskFactor) {
    if (!factorIds.has(factor.id)) {
      factorIds.add(factor.id);
      factors.push(factor);
    }
  }

  // 1. Identity & Authorization Correlation
  const identity = correlateIdentity({
    userEmail: input.userEmail,
    userName: input.userName,
    deviceLabel: input.deviceLabel,
    serviceApproval: input.serviceApproval,
    explicitAuth: input.explicitAuth,
    syntheticUser: input.syntheticUser,
    syntheticDevice: input.syntheticDevice,
    isServicePermittedForUser: input.isServicePermittedForUser,
  });

  // 2. Data Sensitivity Signal
  let sensitivity: SensitivityLabel = 'Internal';
  if (input.sensitivityLabel) {
    const s = input.sensitivityLabel.toLowerCase();
    if (s.includes('rest')) sensitivity = 'Restricted';
    else if (s.includes('conf')) sensitivity = 'Confidential';
    else if (s.includes('pub')) sensitivity = 'Public';
    else sensitivity = 'Internal';
  } else if (input.promptCategories && input.promptCategories.length > 0) {
    // Derive sensitivity from prompt lab categories if sensitivityLabel was omitted
    const catLower = input.promptCategories.map((c) => c.toLowerCase());
    if (
      catLower.some((c) => c.includes('key') || c.includes('token') || c.includes('password') || c.includes('secret') || c.includes('credential'))
    ) {
      sensitivity = 'Restricted';
    } else if (
      catLower.some((c) => c.includes('card') || c.includes('pii') || c.includes('business') || c.includes('confidential') || c.includes('payment'))
    ) {
      sensitivity = 'Confidential';
    } else {
      sensitivity = 'Internal';
    }
  } else {
    missingContext.push('Data sensitivity not labeled (defaulted to Internal)');
  }

  switch (sensitivity) {
    case 'Restricted':
      addFactor({
        id: 'sens_restricted',
        name: 'Restricted Data Sensitivity',
        points: DEMO_POLICY_WEIGHTS.sensitivity_restricted,
        evidence: 'Event metadata carries a Restricted data label (credentials, private keys, or core secrets).',
      });
      break;
    case 'Confidential':
      addFactor({
        id: 'sens_confidential',
        name: 'Confidential Data Sensitivity',
        points: DEMO_POLICY_WEIGHTS.sensitivity_confidential,
        evidence: 'Event metadata carries a Confidential data label (customer PII, payment info, financial).',
      });
      break;
    case 'Internal':
      addFactor({
        id: 'sens_internal',
        name: 'Internal Data Sensitivity',
        points: DEMO_POLICY_WEIGHTS.sensitivity_internal,
        evidence: 'Event metadata marks information as internal company documentation or communications.',
      });
      break;
    case 'Public':
      addFactor({
        id: 'sens_public',
        name: 'Public Data Sensitivity',
        points: DEMO_POLICY_WEIGHTS.sensitivity_public,
        evidence: 'Information is designated public marketing or open documentation (0 pts).',
      });
      break;
  }

  // 3. Service Approval Status Signal
  const approval = (input.serviceApproval as ServiceApproval) || 'Unknown';
  if (approval === 'Unapproved') {
    addFactor({
      id: 'svc_unapproved',
      name: 'Unapproved AI Destination',
      points: DEMO_POLICY_WEIGHTS.service_unapproved,
      evidence: `Destination '${input.destination}' is flagged as globally Unapproved in the service registry.`,
    });
  } else if (approval === 'Needs review' || approval === 'Unknown') {
    addFactor({
      id: 'svc_unreviewed',
      name: 'Service Under Review or Unknown',
      points: DEMO_POLICY_WEIGHTS.service_under_review_or_unknown,
      evidence: `Destination '${input.destination}' is not yet formally approved (status: ${approval}).`,
    });
  } else {
    addFactor({
      id: 'svc_approved',
      name: 'Approved Service Destination',
      points: DEMO_POLICY_WEIGHTS.service_approved,
      evidence: `Destination '${input.destination}' is registered as an approved corporate service.`,
    });
  }

  // 4. Authorization Status Signal
  if (identity.authStatus === 'denied' || identity.authStatus === 'mismatch') {
    addFactor({
      id: 'auth_denied',
      name: identity.authStatus === 'mismatch' ? 'Authorization Mismatch' : 'Unauthorized Action',
      points: DEMO_POLICY_WEIGHTS.auth_denied_or_mismatch,
      evidence: identity.notes,
    });
  } else if (identity.authStatus === 'unknown') {
    addFactor({
      id: 'auth_unknown',
      name: 'Unknown Authorization Context',
      points: DEMO_POLICY_WEIGHTS.auth_unknown,
      evidence: identity.notes,
      isMissingContext: true,
    });
  } else {
    addFactor({
      id: 'auth_granted',
      name: 'Authorized User & Device',
      points: DEMO_POLICY_WEIGHTS.auth_authorized,
      evidence: 'User and device are verified against synthetic directory permissions (0 pts).',
    });
  }

  // 5. Synthetic Identity Review Points (modest, separately named)
  if (!identity.userListed) {
    missingContext.push('User unlisted in synthetic directory');
    addFactor({
      id: 'id_user_unlisted',
      name: 'Unlisted Synthetic User',
      points: DEMO_POLICY_WEIGHTS.unlisted_synthetic_user,
      evidence: `User identifier '${input.userEmail || input.userName || 'unknown'}' has no match in demo employee records.`,
      isMissingContext: true,
    });
  }

  if (!identity.deviceKnown) {
    missingContext.push('Device unmanaged / unlisted in synthetic directory');
    addFactor({
      id: 'id_device_unmanaged',
      name: 'Unmanaged Synthetic Device',
      points: DEMO_POLICY_WEIGHTS.unmanaged_synthetic_device,
      evidence: `Device '${input.deviceLabel || 'unknown'}' is not registered in demo asset directory.`,
      isMissingContext: true,
    });
  }

  // 6. Transfer Volume Anomaly Signal
  const byteCount = input.byteCount || 0;
  if (byteCount >= DEMO_VOLUME_THRESHOLD_BYTES) {
    const mb = (byteCount / (1024 * 1024)).toFixed(1);
    addFactor({
      id: 'vol_high',
      name: 'High Transfer Volume',
      points: DEMO_POLICY_WEIGHTS.high_transfer_volume,
      evidence: `Transfer size of ${mb} MB exceeds documented demo threshold of 5 MB.`,
    });
  }

  // Explicit anomaly flag in metadata
  if (input.isAnomalySignal) {
    addFactor({
      id: 'anomaly_flagged',
      name: 'Supplied Anomaly Flag',
      points: DEMO_POLICY_WEIGHTS.anomaly_signal_flagged,
      evidence: 'Supplied network event metadata explicitly flagged an anomaly indicator.',
    });
  }

  // 7. Historical Signals (traceable, based only on supplied/stored dataset)
  if (input.destinationOccurrenceCount != null && input.destinationOccurrenceCount <= 1) {
    addFactor({
      id: 'hist_first_seen',
      name: 'First-Seen Destination',
      points: DEMO_POLICY_WEIGHTS.first_seen_destination,
      evidence: `Destination '${input.destination}' is observed for the first time in this demo dataset.`,
    });
  }

  if (input.userPriorWarningsCount != null && input.userPriorWarningsCount >= 3) {
    addFactor({
      id: 'hist_repeated_warnings',
      name: 'Repeated Elevated Events',
      points: DEMO_POLICY_WEIGHTS.repeated_warning_events,
      evidence: `Synthetic identity has accumulated ${input.userPriorWarningsCount} prior elevated risk events in history.`,
    });
  }

  // 8. Calculate total points and clamp to [0, 100]
  const rawScore = factors.reduce((acc, f) => acc + f.points, 0);
  const score = Math.max(0, Math.min(100, rawScore));

  // 9. Determine Severity
  let severity: RiskSeverity = 'low';
  if (score >= 75) severity = 'critical';
  else if (score >= 50) severity = 'high';
  else if (score >= 25) severity = 'medium';
  else severity = 'low';

  // 10. Determine Recommendation
  let recommendation = 'Allow or record for visibility';
  let isSimulatedAction = false;

  const isRestrictedUnapprovedDenied =
    sensitivity === 'Restricted' &&
    approval === 'Unapproved' &&
    (identity.authStatus === 'denied' || identity.authStatus === 'mismatch');

  if (severity === 'critical' || isRestrictedUnapprovedDenied) {
    recommendation = 'Would block before transmission (simulation)';
    isSimulatedAction = true;
  } else if (severity === 'high') {
    recommendation = 'Review promptly';
  } else if (severity === 'medium') {
    recommendation = 'Warn / review before sending';
  } else {
    recommendation = 'Allow or record for visibility';
  }

  // 11. Determine Confidence & Completeness
  let confidence: ConfidenceLevel = 'High';
  if (missingContext.length >= 2 || (input.classificationConfidence != null && input.classificationConfidence < 0.5)) {
    confidence = 'Low';
  } else if (missingContext.length === 1 || input.classification === 'Uncertain') {
    confidence = 'Medium';
  }

  // 12. Plain-Language Explanation
  const explanationParts: string[] = [];
  const sevCapitalized = severity.charAt(0).toUpperCase() + severity.slice(1);

  if (severity === 'critical') {
    explanationParts.push(
      `Critical risk (${score}/100): ${sensitivity.toLowerCase()} data was associated with ${approval.toLowerCase()} destination '${input.destination}'`
    );
    if (identity.authStatus === 'denied' || identity.authStatus === 'mismatch') {
      explanationParts.push(`and the action is unauthorized for the synthetic identity`);
    }
  } else if (severity === 'high') {
    explanationParts.push(
      `High risk (${score}/100): Elevated risk detected for ${sensitivity.toLowerCase()} data sent to ${approval.toLowerCase()} destination '${input.destination}'`
    );
  } else if (severity === 'medium') {
    explanationParts.push(
      `Medium risk (${score}/100): ${sensitivity.toLowerCase()} data observed with ${approval.toLowerCase()} service '${input.destination}'`
    );
  } else {
    explanationParts.push(
      `Low risk (${score}/100): Standard traffic to ${approval.toLowerCase()} service '${input.destination}' with ${sensitivity.toLowerCase()} sensitivity`
    );
  }

  if (byteCount >= DEMO_VOLUME_THRESHOLD_BYTES) {
    explanationParts.push(`with unusual transfer volume (${(byteCount / (1024 * 1024)).toFixed(1)} MB)`);
  }

  if (missingContext.length > 0) {
    explanationParts.push(`[Note: ${missingContext.join('; ')}]`);
  }

  explanationParts.push('All identities and policy weights are synthetic demo rules.');
  const explanation = explanationParts.join(', ').replace(', [Note:', '. [Note:');

  return {
    score,
    severity,
    factors,
    identityCorrelation: identity,
    confidence,
    missingContext,
    explanation,
    recommendation,
    isSimulatedAction,
  };
}
