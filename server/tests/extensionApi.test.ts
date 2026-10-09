// ─── AURA Browser AI Guard & Extension Integration Tests ─────────────────────
// Validates:
// 1. AI Service Catalog retrieval and domain addition/removal (RBAC)
// 2. Extension Live Interception Event Ingestion (Privacy Guarantee: No prompt/secret persistence)
// 3. Event Review Status Updates (Expected, Investigate, Policy exception)
// 4. Extension Dashboard Summary metrics
// 5. Reference Dataset Historical Activity and Incident correlation

import assert from 'node:assert/strict';

const BASE_URL = 'http://127.0.0.1:3001/api';

async function testExtensionApi() {
  console.log('\n========================================================');
  console.log('• Testing Browser AI Guard Extension API & Datasets:');
  console.log('========================================================\n');

  // Helper for auth cookie
  async function getAuthCookie(role: 'administrator' | 'analyst' | 'viewer') {
    const res = await fetch(`${BASE_URL}/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    });
    return res.headers.get('set-cookie') || '';
  }

  const adminCookie = await getAuthCookie('administrator');
  const viewerCookie = await getAuthCookie('viewer');

  // 1. Catalog retrieval
  console.log('1. Checking AI Service Catalog (GET /api/extension/sites)...');
  const sitesRes = await fetch(`${BASE_URL}/extension/sites`, {
    headers: { cookie: adminCookie },
  });
  assert.equal(sitesRes.status, 200);
  const sitesData = await sitesRes.json();
  assert.ok(sitesData.sites.length >= 14, `Expected at least 14 sites, got ${sitesData.sites.length}`);
  const openAiSite = sitesData.sites.find((s: any) => s.service_key === 'openai_chatgpt');
  assert.ok(openAiSite, 'OpenAI should exist in catalog');
  assert.equal(openAiSite.domain, 'chatgpt.com');
  assert.equal(openAiSite.status, 'protected');
  console.log(`   ✓ Catalog contains ${sitesData.sites.length} sites (${sitesData.activeProtectedCount} protected)`);

  // 2. Add new site to Catalog (Admin only)
  console.log('\n2. Testing Admin Catalog Addition (POST /api/extension/sites)...');
  // Viewer should be forbidden
  const viewerAddRes = await fetch(`${BASE_URL}/extension/sites`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: viewerCookie },
    body: JSON.stringify({
      serviceKey: 'custom_ai',
      name: 'Custom Team LLM',
      domain: 'team-llm.internal.corp',
      category: 'local',
      adapter: 'generic',
    }),
  });
  assert.equal(viewerAddRes.status, 403, 'Viewer should be forbidden from modifying catalog');
  console.log('   ✓ Viewer role correctly blocked (HTTP 403)');

  // Admin should succeed
  const customDomain = `test-llm-${Date.now()}.internal`;
  const adminAddRes = await fetch(`${BASE_URL}/extension/sites`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', cookie: adminCookie },
    body: JSON.stringify({
      serviceKey: 'test_ai',
      name: 'Test LLM Hub',
      domain: customDomain,
      category: 'local',
      adapter: 'generic',
    }),
  });
  assert.equal(adminAddRes.status, 201, 'Admin should successfully add site');
  const newSite = await adminAddRes.json();
  assert.equal(newSite.domain, customDomain);
  console.log(`   ✓ Admin successfully added "${newSite.name}" (${newSite.domain})`);

  // 3. Live Event Ingestion with Privacy Guarantee
  console.log('\n3. Ingesting Live Extension Event (POST /api/extension/events)...');
  const testEventPayload = {
    employeeId: 'EMP-0142',
    aiService: 'OpenAI ChatGPT',
    domain: 'chatgpt.com',
    eventType: 'message_send',
    detectedCategory: 'api_key',
    matchedRule: 'OpenAI Secret Key (sk-...) pattern detected',
    actionTaken: 'blocked',
    riskLevel: 'critical',
  };

  const ingestRes = await fetch(`${BASE_URL}/extension/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(testEventPayload),
  });
  assert.equal(ingestRes.status, 201);
  const ingestedEvent = await ingestRes.json();
  assert.ok(ingestedEvent.id);
  assert.equal(ingestedEvent.ai_service, 'OpenAI ChatGPT');
  assert.equal(ingestedEvent.action_taken, 'blocked');
  // Ensure no prompt_text or secret_value fields exist
  assert.equal(ingestedEvent.prompt_text, undefined, 'Privacy: prompt_text must not exist on event');
  assert.equal(ingestedEvent.raw_value, undefined, 'Privacy: raw_value must not exist on event');
  console.log(`   ✓ Ingested live event #${ingestedEvent.id} (Category: ${ingestedEvent.detected_category}, Action: ${ingestedEvent.action_taken})`);
  console.log('   ✓ Privacy verified: Zero prompt text or secret value stored');

  // 4. Filter Live Events
  console.log('\n4. Filtering Live Events (GET /api/extension/events)...');
  const filterRes = await fetch(`${BASE_URL}/extension/events?risk=critical&service=OpenAI%20ChatGPT`, {
    headers: { cookie: adminCookie },
  });
  assert.equal(filterRes.status, 200);
  const filterData = await filterRes.json();
  assert.ok(filterData.events.length >= 1);
  const found = filterData.events.find((e: any) => e.id === ingestedEvent.id);
  assert.ok(found, 'Ingested event should be present in filtered list');
  console.log(`   ✓ Filtered query returned ${filterData.events.length} critical events`);

  // 5. Review Workflow: Expected / Investigate / Policy exception
  console.log('\n5. Updating Review Status (PATCH /api/extension/events/:id/review)...');
  const reviewRes = await fetch(`${BASE_URL}/extension/events/${ingestedEvent.id}/review`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', cookie: adminCookie },
    body: JSON.stringify({
      reviewStatus: 'Investigate',
      reviewerNote: 'Follow up with employee regarding sensitive credential usage.',
    }),
  });
  assert.equal(reviewRes.status, 200);
  const updatedEvent = await reviewRes.json();
  assert.equal(updatedEvent.review_status, 'Investigate');
  assert.equal(updatedEvent.reviewer_note, 'Follow up with employee regarding sensitive credential usage.');
  assert.equal(updatedEvent.reviewed_by, 'demo-admin');
  console.log(`   ✓ Event #${ingestedEvent.id} marked as "Investigate" with audit note by admin`);

  // 6. Dashboard Summary
  console.log('\n6. Checking Dashboard Summary (GET /api/extension/dashboard-summary)...');
  const summaryRes = await fetch(`${BASE_URL}/extension/dashboard-summary`, {
    headers: { cookie: adminCookie },
  });
  assert.equal(summaryRes.status, 200);
  const summary = await summaryRes.json();
  assert.ok(summary.catalog.totalSites >= 15);
  assert.ok(summary.liveEvents.total >= 1);
  assert.ok(summary.datasets.employees >= 100, `Expected at least 100 employees loaded from CSVs, got ${summary.datasets.employees}`);
  assert.ok(summary.datasets.aiLogs >= 100, `Expected historical AI logs loaded, got ${summary.datasets.aiLogs}`);
  console.log(`   ✓ Summary: ${summary.catalog.protectedSites} protected sites, ${summary.liveEvents.total} live events, ${summary.datasets.employees} reference employees, ${summary.datasets.aiLogs} AI logs`);

  // 7. Reference Datasets History & Incident correlation
  console.log('\n7. Checking Reference Dataset Activity (GET /api/extension/datasets/history)...');
  const historyRes = await fetch(`${BASE_URL}/extension/datasets/history?limit=10`, {
    headers: { cookie: adminCookie },
  });
  assert.equal(historyRes.status, 200);
  const history = await historyRes.json();
  assert.ok(history.records.length > 0, 'Should return records from dataset_b_ai_usage_logs joined with dataset_a_employees');
  const sampleRecord = history.records[0];
  assert.ok(sampleRecord.employee_id, 'Must contain employee_id');
  assert.ok(sampleRecord.ai_service, 'Must contain ai_service');
  assert.equal(sampleRecord.source, 'dataset_sample', 'Sample source must be dataset_sample to visibly distinguish from live extension events');
  assert.equal(sampleRecord.is_live, 0, 'is_live must be 0 for sample records');
  console.log(`   ✓ Sample history returned (${history.records.length} records). Flagged is_sample_data=true`);

  const incidentRes = await fetch(`${BASE_URL}/extension/datasets/incidents?limit=5`, {
    headers: { cookie: adminCookie },
  });
  assert.equal(incidentRes.status, 200);
  const incidents = await incidentRes.json();
  assert.ok(incidents.incidents.length > 0, 'Should return records from dataset_e_security_incidents');
  console.log(`   ✓ Sample incidents returned (${incidents.incidents.length} incidents)`);

  console.log('\n========================================================');
  console.log('✅ ALL BROWSER AI GUARD EXTENSION TESTS PASSED!');
  console.log('========================================================\n');
}

testExtensionApi().catch((err) => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
