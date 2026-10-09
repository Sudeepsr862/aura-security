// ─── AURA Phase 3 API Integration Test ─────────────────────────────────────────
// Verifies HTTP endpoints:
// - Role authorization for CSV import (Admin/Analyst allowed, Viewer forbidden)
// - Sample CSV retrieval
// - End-to-end CSV import and dataset evaluation endpoint

import assert from 'node:assert/strict';

const BASE_URL = 'http://127.0.0.1:3001/api';

async function testApi() {
  console.log('\n• Testing HTTP API Endpoints & Role Permissions:');

  // 1. Health check
  const healthRes = await fetch(`${BASE_URL}/health`);
  assert.equal(healthRes.status, 200);
  console.log('  ✓ GET /api/health returned 200 OK');

  // 2. Sample CSV retrieval
  const sampleRes = await fetch(`${BASE_URL}/ingest/sample-csv`);
  assert.equal(sampleRes.status, 200);
  const sampleJson = await sampleRes.json();
  assert.equal(typeof sampleJson.content, 'string');
  assert.match(sampleJson.content, /api\.openai\.com/);
  console.log('  ✓ GET /api/ingest/sample-csv provided valid sample data');

  // 3. Test Viewer Role (Forbidden from importing CSV)
  const viewerSign = await fetch(`${BASE_URL}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'viewer' }),
  });
  const viewerCookie = viewerSign.headers.get('set-cookie');

  const viewerImport = await fetch(`${BASE_URL}/ingest/csv`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      cookie: viewerCookie ?? '',
    },
    body: JSON.stringify({ csvText: sampleJson.content }),
  });
  assert.equal(viewerImport.status, 403);
  const viewerErr = await viewerImport.json();
  assert.match(viewerErr.error, /cannot perform this action|permission/i);
  console.log('  ✓ Viewer role is correctly blocked from CSV import (HTTP 403 Forbidden)');

  // 4. Test Analyst Role (Allowed to import CSV)
  const analystSign = await fetch(`${BASE_URL}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'analyst' }),
  });
  const analystCookie = analystSign.headers.get('set-cookie');

  const analystImport = await fetch(`${BASE_URL}/ingest/csv`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      cookie: analystCookie ?? '',
    },
    body: JSON.stringify({ csvText: sampleJson.content }),
  });
  assert.equal(analystImport.status, 200);
  const analystResult = await analystImport.json();
  assert.equal(analystResult.success, true);
  assert.equal(analystResult.summary.importedCount >= 10, true);
  console.log(`  ✓ Analyst role successfully imported and classified ${analystResult.summary.importedCount} rows (HTTP 200)`);

  // 5. Test Evaluation Endpoint
  const evalRes = await fetch(`${BASE_URL}/ingest/evaluation`);
  assert.equal(evalRes.status, 200);
  const evalJson = await evalRes.json();
  assert.equal(evalJson.report.totalRows > 0, true);
  assert.equal(evalJson.report.labeledRows > 0, true);
  console.log(`  ✓ GET /api/ingest/evaluation returned metrics (Precision: ${evalJson.report.metrics.precision.formatted}, Recall: ${evalJson.report.metrics.recall.formatted})`);

  // 6. Test Unified Inventory Endpoint
  const invRes = await fetch(`${BASE_URL}/services/inventory`, {
    headers: { cookie: analystCookie ?? '' },
  });
  assert.equal(invRes.status, 200);
  const invJson = await invRes.json();
  assert.equal(Array.isArray(invJson.inventory), true);
  assert.equal(invJson.inventory.length > 0, true);
  const hasCsv = invJson.inventory.some((i: any) => i.source_types.includes('csv_import'));
  const hasSim = invJson.inventory.some((i: any) => i.source_types.includes('simulation'));
  assert.equal(hasCsv, true);
  assert.equal(hasSim, true);
  console.log('  ✓ GET /api/services/inventory contains both CSV imports and simulated services with source labels');

  console.log('\n========================================');
  console.log(' ✅ All HTTP Integration Tests Passed!');
  console.log('========================================\n');
}

testApi().catch((e) => {
  console.error('API Test Failed:', e);
  process.exit(1);
});
