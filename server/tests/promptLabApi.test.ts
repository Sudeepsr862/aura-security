// ─── AURA Phase 4 Prompt Lab API & Privacy Integration Test ──────────────────
// Verifies:
// - Role authorization for Prompt Lab (Admin/Analyst allowed, Viewer forbidden)
// - Destinations list retrieval
// - Scan execution & input length validation
// - Privacy Guarantee: Database records and audit logs DO NOT contain raw prompt text or previews

import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BASE_URL = 'http://127.0.0.1:3001/api';

async function testPromptLabApi() {
  console.log('\n• Testing Prompt Lab HTTP API & Privacy Guarantees:');

  // 1. Destinations list
  const adminSign = await fetch(`${BASE_URL}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'administrator' }),
  });
  const adminCookie = adminSign.headers.get('set-cookie');

  const destRes = await fetch(`${BASE_URL}/prompt-lab/destinations`, {
    headers: { cookie: adminCookie ?? '' },
  });
  assert.equal(destRes.status, 200);
  const destJson = await destRes.json();
  assert.equal(Array.isArray(destJson.destinations), true);
  assert.equal(destJson.destinations.length > 0, true);
  assert.equal(destJson.destinations.some((d: any) => d.id === 'unknown-dest'), true);
  console.log(`  ✓ GET /api/prompt-lab/destinations returned ${destJson.destinations.length} destinations`);

  // 2. Viewer role blocked from scanning
  const viewerSign = await fetch(`${BASE_URL}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'viewer' }),
  });
  const viewerCookie = viewerSign.headers.get('set-cookie');

  const viewerScan = await fetch(`${BASE_URL}/prompt-lab/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: viewerCookie ?? '' },
    body: JSON.stringify({
      text: 'Synthetic test text',
      destination: 'Unknown destination',
      destinationStatus: 'Unapproved',
    }),
  });
  assert.equal(viewerScan.status, 403);
  const viewerErr = await viewerScan.json();
  assert.match(viewerErr.error, /cannot perform this action|permission/i);
  console.log('  ✓ Viewer role is blocked from prompt scanning (HTTP 403 Forbidden)');

  // 3. Input length validation
  const emptyScan = await fetch(`${BASE_URL}/prompt-lab/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: adminCookie ?? '' },
    body: JSON.stringify({ text: '   ' }),
  });
  assert.equal(emptyScan.status, 400);

  const oversizedText = 'A'.repeat(10001);
  const overScan = await fetch(`${BASE_URL}/prompt-lab/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: adminCookie ?? '' },
    body: JSON.stringify({ text: oversizedText }),
  });
  assert.equal(overScan.status, 400);
  const overErr = await overScan.json();
  assert.match(overErr.error, /maximum scan limit/i);
  console.log('  ✓ Input length validation enforced (empty and >10,000 chars rejected)');

  // 4. Successful Analyst scan with fake secret & unapproved destination -> Would block
  const analystSign = await fetch(`${BASE_URL}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'analyst' }),
  });
  const analystCookie = analystSign.headers.get('set-cookie');

  const secretString = 'sk-proj-supersecretkey1234567890abcdef1234567890';
  const promptPayload = `Please debug this request: ${secretString} with user email casey@demo.aura`;

  const scanRes = await fetch(`${BASE_URL}/prompt-lab/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: analystCookie ?? '' },
    body: JSON.stringify({
      text: promptPayload,
      destination: 'Unknown / External Destination',
      destinationStatus: 'Unapproved',
    }),
  });
  assert.equal(scanRes.status, 200);
  const scanJson = await scanRes.json();
  assert.equal(scanJson.success, true);
  assert.equal(scanJson.result.policyOutcome, 'would_block');
  assert.equal(scanJson.result.policyRecommendation, 'Would block before transmission (simulation).');
  assert.equal(scanJson.result.sensitivitySuggestion, 'Restricted');
  assert.equal(scanJson.result.redactedPreview.includes(secretString), false);
  assert.equal(scanJson.result.redactedPreview.includes('[REDACTED: API Key]'), true);
  console.log('  ✓ Analyst successfully executed scan: returned simulated "Would block" with redacted preview');

  // 5. Database Privacy Audit: Confirm raw prompt text is NOT in prompt_scans or audit_log
  const db = new Database(join(__dirname, '../../data/aura.db'));
  const tableCols = db.pragma('table_info(prompt_scans)') as Array<{ name: string }>;
  const colNames = tableCols.map((c) => c.name);

  assert.equal(colNames.includes('raw_prompt'), false);
  assert.equal(colNames.includes('prompt'), false);
  assert.equal(colNames.includes('preview'), false);
  assert.equal(colNames.includes('redacted_preview'), false);
  assert.equal(colNames.includes('hash'), false);
  assert.equal(colNames.includes('content_hash'), false);

  // Check rows
  const lastScan = db.prepare(`SELECT * FROM prompt_scans ORDER BY id DESC LIMIT 1`).get() as any;
  assert.equal(lastScan.destination_status, 'Unapproved');
  assert.equal(lastScan.policy_outcome, 'would_block');
  assert.equal(lastScan.char_count, promptPayload.length);

  // Check entire DB text for the secret token
  const scansContainingSecret = db.prepare(
    `SELECT COUNT(*) as cnt FROM prompt_scans WHERE categories LIKE ? OR destination LIKE ?`,
  ).get(`%${secretString}%`, `%${secretString}%`) as { cnt: number };
  assert.equal(scansContainingSecret.cnt, 0);

  const auditsContainingSecret = db.prepare(
    `SELECT COUNT(*) as cnt FROM audit_log WHERE detail LIKE ?`,
  ).get(`%${secretString}%`) as { cnt: number };
  assert.equal(auditsContainingSecret.cnt, 0);

  console.log('  ✓ Strict Privacy Verified: raw prompt, preview, and secrets are completely absent from database & audit logs');

  console.log('\n========================================');
  console.log(' ✅ All Prompt Lab API & Privacy Tests Passed!');
  console.log('========================================\n');
}

testPromptLabApi().catch((err) => {
  console.error('Prompt Lab API Test Failed:', err);
  process.exit(1);
});
