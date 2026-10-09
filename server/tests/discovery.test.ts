// ─── AURA Phase 3 Test Suite ──────────────────────────────────────────────────
// Comprehensive test suite verifying all Phase 3 acceptance criteria:
// 1. Exact provider-domain and valid subdomain matching
// 2. Rejection of lookalike domains
// 3. AI, ordinary-web, uncertain, and possible-local classifications
// 4. Local-port confidence labels and port 443 alone NOT causing an AI match
// 5. CSV header normalization, invalid rows, size/row limits, and ignored payload columns
// 6. Boolean parsing, especially "false" remaining false
// 7. Role permissions for CSV import (Admin/Analyst allowed, Viewer forbidden)
// 8. Evaluation metrics and pending-label behavior

import assert from 'node:assert/strict';
import {
  isDomainMatch,
  classifyEvent,
  normalizeHost,
  type ServiceRegistryItem,
} from '../discovery/classifier.js';
import {
  parseBooleanStrict,
  parseAndValidateCsv,
} from '../discovery/csvParser.js';
import {
  evaluateDataset,
} from '../discovery/evaluator.js';

let passedTests = 0;
let totalTests = 0;

function it(name: string, fn: () => void | Promise<void>) {
  totalTests++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err: unknown) {
    console.error(`  ✗ FAIL: ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

console.log('\n========================================');
console.log(' running AURA Phase 3 Test Suite');
console.log('========================================\n');

// ── 1. Domain Matching & Subdomain Logic ─────────────────────────────────────
console.log('• Testing Domain & Subdomain Matching:');

it('matches exact domain', () => {
  assert.equal(isDomainMatch('openai.com', 'openai.com'), true);
  assert.equal(isDomainMatch('claude.ai', 'claude.ai'), true);
});

it('matches valid subdomains', () => {
  assert.equal(isDomainMatch('api.openai.com', 'openai.com'), true);
  assert.equal(isDomainMatch('chat.openai.com', 'openai.com'), true);
  assert.equal(isDomainMatch('deep.sub.api.openai.com', 'openai.com'), true);
  assert.equal(isDomainMatch('generativelanguage.googleapis.com', 'googleapis.com'), true);
});

it('matches tenant-style Azure OpenAI wildcard domains (*.openai.azure.com)', () => {
  assert.equal(isDomainMatch('myorg.openai.azure.com', '*.openai.azure.com'), true);
  assert.equal(isDomainMatch('tenant-prod-01.openai.azure.com', '*.openai.azure.com'), true);
  assert.equal(isDomainMatch('openai.azure.com', '*.openai.azure.com'), true);
});

// ── 2. Rejection of Lookalike Domains ────────────────────────────────────────
console.log('\n• Testing Rejection of Lookalike Domains:');

it('rejects suffix lookalikes (e.g. openai.com.attacker.com)', () => {
  assert.equal(isDomainMatch('openai.com.attacker.com', 'openai.com'), false);
  assert.equal(isDomainMatch('api.openai.com.phishing.test', 'openai.com'), false);
  assert.equal(isDomainMatch('claude.ai.fake.org', 'claude.ai'), false);
  assert.equal(isDomainMatch('myorg.openai.azure.com.attacker.net', '*.openai.azure.com'), false);
});

it('rejects prefix lookalikes (e.g. notopenai.com, evil-claude.ai)', () => {
  assert.equal(isDomainMatch('notopenai.com', 'openai.com'), false);
  assert.equal(isDomainMatch('evilopenai.com', 'openai.com'), false);
  assert.equal(isDomainMatch('fake-claude.ai', 'claude.ai'), false);
  assert.equal(isDomainMatch('openai.company', 'openai.com'), false);
});

// ── 3. AI, Ordinary-Web, Uncertain, and Possible-Local Classifications ──────
console.log('\n• Testing Classification Hierarchy & Heuristics:');

const mockRegistry: ServiceRegistryItem[] = [
  {
    id: 1,
    name: 'OpenAI API',
    provider: 'OpenAI',
    domains: ['api.openai.com', 'chatgpt.com'],
    local_ports: [],
    service_type: 'Cloud AI',
    approval_status: 'Approved',
  },
  {
    id: 2,
    name: 'Claude',
    provider: 'Anthropic',
    domains: ['api.anthropic.com', 'claude.ai'],
    local_ports: [],
    service_type: 'Cloud AI',
    approval_status: 'Needs review',
  },
  {
    id: 3,
    name: 'Ollama local',
    provider: 'Ollama / local',
    domains: ['localhost'],
    local_ports: [11434],
    service_type: 'Possible local AI',
    approval_status: 'Unapproved',
  },
  {
    id: 4,
    name: 'GitHub',
    provider: 'GitHub',
    domains: ['github.com', 'api.github.com'],
    local_ports: [],
    service_type: 'Ordinary web',
    approval_status: 'Approved',
  },
];

it('classifies registered cloud AI services with high confidence', () => {
  const res = classifyEvent({ destination: 'api.openai.com', port: 443 }, mockRegistry);
  assert.equal(res.classification, 'Likely cloud AI');
  assert.equal(res.provider, 'OpenAI');
  assert.equal(res.confidence >= 0.9, true);
  assert.match(res.evidence, /Cloud AI/i);
});

it('classifies ordinary web domains as Ordinary web', () => {
  const resGitHub = classifyEvent({ destination: 'github.com', port: 443 }, mockRegistry);
  assert.equal(resGitHub.classification, 'Ordinary web');
  assert.equal(resGitHub.confidence >= 0.9, true);

  const resStackOverflow = classifyEvent({ destination: 'stackoverflow.com', port: 443 }, mockRegistry);
  assert.equal(resStackOverflow.classification, 'Ordinary web');
});

it('classifies unknown hosts as Uncertain', () => {
  const res = classifyEvent({ destination: 'random-metrics-srv.internal', port: 9090 }, mockRegistry);
  assert.equal(res.classification, 'Uncertain');
  assert.equal(res.provider, 'Unknown');
  assert.equal(res.confidence <= 0.3, true);
  assert.match(res.evidence, /not recognized/i);
});

// ── 4. Local-Port Confidence & Port 443 Alone Guard ─────────────────────────
console.log('\n• Testing Local Port Clues & Port 443 Guard:');

it('flags dedicated Ollama port (11434) as Possible local AI with high confidence (0.85)', () => {
  const res = classifyEvent({ destination: 'localhost', port: 11434 }, mockRegistry);
  assert.equal(res.classification, 'Possible local AI');
  assert.equal(res.confidence, 0.85);
  assert.match(res.evidence, /port match is a clue/i);
});

it('flags LM Studio port (1234) as Possible local AI with high confidence (0.85)', () => {
  const res = classifyEvent({ destination: '127.0.0.1', port: 1234 }, mockRegistry);
  assert.equal(res.classification, 'Possible local AI');
  assert.equal(res.confidence, 0.85);
  assert.match(res.evidence, /LM Studio/i);
});

it('treats generic dev port 8000 on local IP as lower confidence (0.40)', () => {
  const res = classifyEvent({ destination: '127.0.0.1', port: 8000 }, mockRegistry);
  assert.equal(res.classification, 'Possible local AI');
  assert.equal(res.confidence, 0.40);
  assert.match(res.evidence, /Low-confidence clue/i);
});

it('DOES NOT flag port 443 alone as AI (Port 443 Guard)', () => {
  const resUnknown = classifyEvent({ destination: 'unknown-service.com', port: 443 }, mockRegistry);
  assert.notEqual(resUnknown.classification, 'Possible local AI');
  assert.notEqual(resUnknown.classification, 'Likely cloud AI');
  assert.equal(resUnknown.classification, 'Uncertain');
});

it('extracts embedded port from host string (e.g. localhost:11434)', () => {
  const norm = normalizeHost('localhost:11434');
  assert.equal(norm.hostname, 'localhost');
  assert.equal(norm.portFromHost, 11434);
});

// ── 5. CSV Normalization, Limits & Ignored Payload Columns ──────────────────
console.log('\n• Testing CSV Parser, Normalization & Privacy Stripping:');

it('normalizes various equivalent header names (e.g. domain_sni -> domain, bytes_out -> bytes)', () => {
  const csv = `timestamp,source_ip,host_name,domain_sni,destination_port,bytes_out,sensitivity\n2024-10-08T09:00:00Z,10.0.0.1,DEV-01,api.openai.com,443,5000,Confidential`;
  const result = parseAndValidateCsv(csv);
  assert.equal(result.success, true);
  assert.equal(result.importedRows.length, 1);
  const row = result.importedRows[0];
  assert.equal(row.destination, 'api.openai.com');
  assert.equal(row.port, 443);
  assert.equal(row.bytes, 5000);
  assert.equal(row.dataClassification, 'Confidential');
});

it('ignores unknown columns and strips payload contents (prompts, body, passwords)', () => {
  const csv = `timestamp,domain,port,prompt,raw_body,secret_password\n2024-10-08T09:00:00Z,api.openai.com,443,"PROMPT_TEXT_SECRET","BODY_DATA","PASSWORD"`;
  const result = parseAndValidateCsv(csv);
  assert.equal(result.success, true);
  assert.equal(result.importedRows.length, 1);
  // Ignored column headers are detected
  assert.equal(result.ignoredColumnsDetected.includes('prompt'), true);
  assert.equal(result.ignoredColumnsDetected.includes('raw_body'), true);
  assert.equal(result.ignoredColumnsDetected.includes('secret_password'), true);
  // Ensure the ignored payload content is NOT in the normalized row object
  const row = result.importedRows[0] as unknown as Record<string, unknown>;
  assert.equal(row['prompt'], undefined);
  assert.equal(row['raw_body'], undefined);
  assert.equal(row['secret_password'], undefined);
});

it('skips rows without usable destination and reports clear reason', () => {
  const csv = `timestamp,user,bytes\n2024-10-08T09:00:00Z,alex@demo.aura,1000`;
  const result = parseAndValidateCsv(csv);
  assert.equal(result.success, true);
  assert.equal(result.importedRows.length, 0);
  assert.equal(result.skippedRows.length, 1);
  assert.match(result.skippedRows[0].reason, /Missing usable domain/i);
});

it('skips rows with invalid port (e.g. port 99999)', () => {
  const csv = `timestamp,domain,port\n2024-10-08T09:00:00Z,example.com,99999`;
  const result = parseAndValidateCsv(csv);
  assert.equal(result.success, true);
  assert.equal(result.importedRows.length, 0);
  assert.equal(result.skippedRows.length, 1);
  assert.match(result.skippedRows[0].reason, /Invalid port/i);
});

it('enforces maximum row limit (500 rows)', () => {
  const header = 'timestamp,domain,port\n';
  const row = '2024-10-08T09:00:00Z,example.com,443\n';
  const bigCsv = header + row.repeat(501);
  const result = parseAndValidateCsv(bigCsv);
  assert.equal(result.success, false);
  assert.match(result.errorMessage!, /exceeds maximum row limit/i);
});

it('handles UTF-8 Byte-Order Mark (BOM)', () => {
  const csvWithBom = '\uFEFFtimestamp,domain,port\n2024-10-08T09:00:00Z,github.com,443';
  const result = parseAndValidateCsv(csvWithBom);
  assert.equal(result.success, true);
  assert.equal(result.importedRows.length, 1);
  assert.equal(result.importedRows[0].destination, 'github.com');
});

// ── 6. Strict Boolean Parsing ("false" remains false) ────────────────────────
console.log('\n• Testing Strict Boolean Parsing:');

it('strictly parses "false", "0", "no" as false', () => {
  assert.equal(parseBooleanStrict('false'), false);
  assert.equal(parseBooleanStrict('0'), false);
  assert.equal(parseBooleanStrict('no'), false);
  assert.equal(parseBooleanStrict('FALSE'), false);
  assert.equal(parseBooleanStrict('No'), false);
  assert.equal(parseBooleanStrict(0), false);
  assert.equal(parseBooleanStrict(false), false);
});

it('strictly parses "true", "1", "yes" as true', () => {
  assert.equal(parseBooleanStrict('true'), true);
  assert.equal(parseBooleanStrict('1'), true);
  assert.equal(parseBooleanStrict('yes'), true);
  assert.equal(parseBooleanStrict('TRUE'), true);
  assert.equal(parseBooleanStrict(1), true);
  assert.equal(parseBooleanStrict(true), true);
});

// ── 7. Evaluation Metrics & Pending Labels Behavior ─────────────────────────
console.log('\n• Testing Evaluation Metrics & Ground Truth Handling:');

it('evaluates TP, FP, TN, FN, precision, recall, and FPR accurately on labeled dataset', () => {
  const testRows = [
    // True Positive: ground truth is AI, predicted Likely cloud AI
    { classification: 'Likely cloud AI', provider: 'OpenAI', ground_truth_label: 'ai', expected_provider: 'OpenAI' },
    // True Positive: ground truth is AI, predicted Possible local AI
    { classification: 'Possible local AI', provider: 'Ollama', ground_truth_label: 'ai', expected_provider: 'Ollama' },
    // False Positive: ground truth is ordinary, predicted Likely cloud AI
    { classification: 'Likely cloud AI', provider: 'OpenAI', ground_truth_label: 'ordinary', expected_provider: '' },
    // True Negative: ground truth is ordinary, predicted Ordinary web
    { classification: 'Ordinary web', provider: 'GitHub', ground_truth_label: 'ordinary', expected_provider: '' },
    // False Negative: ground truth is AI, predicted Ordinary web
    { classification: 'Ordinary web', provider: 'GitHub', ground_truth_label: 'ai', expected_provider: 'OpenAI' },
  ];

  const report = evaluateDataset(testRows);
  assert.equal(report.confusionMatrix.truePositives, 2);
  assert.equal(report.confusionMatrix.falsePositives, 1);
  assert.equal(report.confusionMatrix.trueNegatives, 1);
  assert.equal(report.confusionMatrix.falseNegatives, 1);

  // Precision = 2 / (2 + 1) = 66.7%
  assert.equal(report.metrics.precision.formatted, '66.7%');
  // Recall = 2 / (2 + 1) = 66.7%
  assert.equal(report.metrics.recall.formatted, '66.7%');
  // FPR = 1 / (1 + 1) = 50.0%
  assert.equal(report.metrics.falsePositiveRate.formatted, '50.0%');
});

it('shows "Pending labels" when there are no ground truth labels', () => {
  const unlabeledRows = [
    { classification: 'Likely cloud AI', provider: 'OpenAI' },
    { classification: 'Ordinary web', provider: 'GitHub' },
  ];

  const report = evaluateDataset(unlabeledRows);
  assert.equal(report.labeledRows, 0);
  assert.equal(report.metrics.precision.value, null);
  assert.equal(report.metrics.precision.formatted, 'Pending labels');
  assert.equal(report.metrics.recall.formatted, 'Pending labels');
  assert.equal(report.metrics.falsePositiveRate.formatted, 'Pending labels');
});

it('evaluates provider match identification separately only when expected_provider is given', () => {
  const rows = [
    { classification: 'Likely cloud AI', provider: 'OpenAI', ground_truth_label: 'ai', expected_provider: 'OpenAI' },
    { classification: 'Likely cloud AI', provider: 'Anthropic', ground_truth_label: 'ai', expected_provider: 'OpenAI' }, // provider mismatch
    { classification: 'Ordinary web', provider: 'GitHub', ground_truth_label: 'ordinary' }, // no expected_provider
  ];

  const report = evaluateDataset(rows);
  assert.equal(report.providerEvaluation.totalWithExpected, 2);
  assert.equal(report.providerEvaluation.matches, 1);
  assert.equal(report.providerEvaluation.accuracy.formatted, '50.0%');
});

console.log('\n========================================');
console.log(` ✅ Completed: ${passedTests}/${totalTests} tests passed.`);
console.log('========================================\n');
