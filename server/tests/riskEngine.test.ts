// ─── AURA Risk Engine Test Suite ──────────────────────────────────────────
import { strict as assert } from 'node:assert';
import {
  assessRisk,
  correlateIdentity,
  DEMO_POLICY_WEIGHTS,
  type RiskAssessmentInput,
} from '../risk/riskEngine.js';

function it(desc: string, fn: () => void) {
  try {
    fn();
    console.log(`  ✓ ${desc}`);
  } catch (err) {
    console.error(`  ✗ ${desc}`);
    throw err;
  }
}

console.log('\n========================================');
console.log(' running AURA Phase 5 Risk Engine Tests');
console.log('========================================\n');

// ── 1. Sensitivity Level Contributions ──────────────────────────────────────
console.log('• Testing Data Sensitivity Contributions:');

it('contributes 0 points for Public data', () => {
  const res = assessRisk({
    destination: 'github.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Public',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'sens_public');
  assert.ok(factor);
  assert.equal(factor.points, 0);
  assert.equal(res.score, 0);
  assert.equal(res.severity, 'low');
});

it('contributes 10 points for Internal data', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Internal',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'sens_internal');
  assert.ok(factor);
  assert.equal(factor.points, 10);
  assert.equal(res.score, 10);
  assert.equal(res.severity, 'low');
});

it('contributes 25 points for Confidential data', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Confidential',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'sens_confidential');
  assert.ok(factor);
  assert.equal(factor.points, 25);
  assert.equal(res.score, 25);
  assert.equal(res.severity, 'medium');
});

it('contributes 35 points for Restricted data', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Restricted',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'sens_restricted');
  assert.ok(factor);
  assert.equal(factor.points, 35);
  assert.equal(res.score, 35);
  assert.equal(res.severity, 'medium');
});

// ── 2. Service Approval Status Contributions ────────────────────────────────
console.log('\n• Testing Service Approval Contributions:');

it('contributes 0 points for Approved service', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Public',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'svc_approved');
  assert.ok(factor);
  assert.equal(factor.points, 0);
});

it('contributes 20 points for Unapproved service', () => {
  const res = assessRisk({
    destination: 'localhost:11434',
    serviceApproval: 'Unapproved',
    sensitivityLabel: 'Public',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: false,
  });
  const factor = res.factors.find((f) => f.id === 'svc_unapproved');
  assert.ok(factor);
  assert.equal(factor.points, 20);
});

it('contributes 12 points for Needs review / Unknown service', () => {
  const res = assessRisk({
    destination: 'api.anthropic.com',
    serviceApproval: 'Needs review',
    sensitivityLabel: 'Public',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factor = res.factors.find((f) => f.id === 'svc_unreviewed');
  assert.ok(factor);
  assert.equal(factor.points, 12);
});

// ── 3. Authorization & Identity Correlation ─────────────────────────────────
console.log('\n• Testing Authorization & Synthetic Identity:');

it('preserves explicit denied authorization and adds 20 points', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Public',
    explicitAuth: 'denied',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true, // even if DB record said true, explicit takes precedence!
  });
  assert.equal(res.identityCorrelation.authStatus, 'denied');
  assert.equal(res.identityCorrelation.isExplicitAuth, true);
  const authFactor = res.factors.find((f) => f.id === 'auth_denied');
  assert.ok(authFactor);
  assert.equal(authFactor.points, 20);
});

it('detects authorization mismatch when known user lacks service permission', () => {
  const res = assessRisk({
    destination: 'api.anthropic.com',
    serviceApproval: 'Needs review',
    sensitivityLabel: 'Internal',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: false, // Alex Mercer does NOT have Anthropic permission
  });
  assert.equal(res.identityCorrelation.authStatus, 'mismatch');
  const factor = res.factors.find((f) => f.id === 'auth_denied');
  assert.ok(factor);
  assert.equal(factor.name, 'Authorization Mismatch');
  assert.equal(factor.points, 20);
});

it('adds modest review points (5 pts each) for unlisted user and unmanaged device', () => {
  const res = assessRisk({
    destination: 'github.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Internal', // 10 pts
    userEmail: 'external.guest@random.com',
    deviceLabel: 'UNKNOWN-LAPTOP-999',
    syntheticUser: null,
    syntheticDevice: null,
  });
  // Unknown authorization: 8 pts
  // Unlisted user: 5 pts
  // Unmanaged device: 5 pts
  // Internal sensitivity: 10 pts
  // Total: 10 + 0 + 8 + 5 + 5 = 28 pts
  assert.equal(res.score, 28);
  assert.equal(res.factors.find((f) => f.id === 'id_user_unlisted')?.points, 5);
  assert.equal(res.factors.find((f) => f.id === 'id_device_unmanaged')?.points, 5);
  assert.equal(res.factors.find((f) => f.id === 'auth_unknown')?.points, 8);
  assert.equal(res.confidence, 'Low'); // missing multiple fields
  assert.ok(res.missingContext.includes('User unlisted in synthetic directory'));
});

// ── 4. Score Clamping & Severity Boundaries ─────────────────────────────────
console.log('\n• Testing Score Clamping & Severity Boundaries:');

it('clamps total score to maximum 100 points without overflow', () => {
  const res = assessRisk({
    destination: 'localhost:11434',
    serviceApproval: 'Unapproved', // 20
    sensitivityLabel: 'Restricted', // 35
    explicitAuth: 'denied', // 20
    userEmail: 'unknown@user.com', // 5
    deviceLabel: 'UNKNOWN-DEV', // 5
    byteCount: 15_000_000, // 18 (>5MB)
    isAnomalySignal: true, // 10
    destinationOccurrenceCount: 1, // 5
    userPriorWarningsCount: 4, // 8
  });
  // Sum = 20 + 35 + 20 + 5 + 5 + 18 + 10 + 5 + 8 = 126
  assert.equal(res.score, 100);
  assert.equal(res.severity, 'critical');
  assert.equal(res.recommendation, 'Would block before transmission (simulation)');
  assert.equal(res.isSimulatedAction, true);
});

it('verifies severity boundaries: Low (0-24), Medium (25-49), High (50-74), Critical (75-100)', () => {
  // Low (10)
  const r1 = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Internal',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  assert.equal(r1.score, 10);
  assert.equal(r1.severity, 'low');
  assert.equal(r1.recommendation, 'Allow or record for visibility');

  // Medium (35)
  const r2 = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Restricted',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  assert.equal(r2.score, 35);
  assert.equal(r2.severity, 'medium');
  assert.equal(r2.recommendation, 'Warn / review before sending');

  // High (55: Restricted 35 + Unapproved 20)
  const r3 = assessRisk({
    destination: 'perplexity.ai',
    serviceApproval: 'Unapproved',
    sensitivityLabel: 'Restricted',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  assert.equal(r3.score, 55);
  assert.equal(r3.severity, 'high');
  assert.equal(r3.recommendation, 'Review promptly');

  // Critical (75: Restricted 35 + Unapproved 20 + Denied 20)
  const r4 = assessRisk({
    destination: 'localhost:11434',
    serviceApproval: 'Unapproved',
    sensitivityLabel: 'Restricted',
    explicitAuth: 'denied',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: false,
  });
  assert.equal(r4.score, 75);
  assert.equal(r4.severity, 'critical');
  assert.equal(r4.recommendation, 'Would block before transmission (simulation)');
});

// ── 5. Duplicate Factor Deduplication ───────────────────────────────────────
console.log('\n• Testing Factor Deduplication:');

it('does not count the same factor twice', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Confidential',
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const factorIds = res.factors.map((f) => f.id);
  const uniqueIds = new Set(factorIds);
  assert.equal(factorIds.length, uniqueIds.size);
});

// ── 6. Prompt Categories Integration without Prompt Text Leakage ─────────────
console.log('\n• Testing Prompt Categories Scoring (Privacy):');

it('scores detected prompt categories accurately without leaking secrets', () => {
  const res = assessRisk({
    destination: 'unknown-service.com',
    serviceApproval: 'Unknown', // 12
    promptCategories: ['api_key', 'credentials'], // infers Restricted: 35
    explicitAuth: 'denied', // 20
  });
  // Inferred Restricted (35) + Unknown service (12) + Denied (20) + Unlisted user (5) + Unmanaged device (5) = 77
  assert.equal(res.score, 77);
  assert.equal(res.severity, 'critical');
  assert.equal(res.recommendation, 'Would block before transmission (simulation)');

  // Ensure explanation does NOT contain prompt text or raw secrets
  assert.ok(!res.explanation.includes('sk-'));
  assert.ok(!res.explanation.includes('secret'));
  assert.ok(!res.explanation.includes('password'));
  assert.match(res.explanation, /restricted data was associated with unknown destination/i);
});

// ── 7. Transfer Volume & Anomaly Signals ────────────────────────────────────
console.log('\n• Testing Transfer Volume and Anomaly Signals:');

it('adds 18 points when byteCount exceeds 5 MB threshold', () => {
  const res = assessRisk({
    destination: 'api.openai.com',
    serviceApproval: 'Approved',
    sensitivityLabel: 'Internal',
    byteCount: 6 * 1024 * 1024, // 6 MB
    syntheticUser: { id: 1, display_name: 'Alex Mercer', demo_email: 'alex@demo.aura' },
    syntheticDevice: { id: 1, label: 'DEVICE-SYN-042', person_id: 1 },
    isServicePermittedForUser: true,
  });
  const volFactor = res.factors.find((f) => f.id === 'vol_high');
  assert.ok(volFactor);
  assert.equal(volFactor.points, 18);
  assert.match(volFactor.evidence, /6\.0 MB/);
  assert.equal(res.score, 28); // 10 (internal) + 18 (volume)
});

console.log('\n========================================');
console.log(' ✅ Completed: All Risk Engine Tests Passed');
console.log('========================================\n');
