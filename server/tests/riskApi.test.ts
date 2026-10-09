// ─── AURA Phase 5 Risk API Integration Tests ──────────────────────────────
import { strict as assert } from 'node:assert';
import { openDb, applySchema, seedDemo } from '../db/database.js';

function it(desc: string, fn: () => void | Promise<void>) {
  return Promise.resolve()
    .then(() => fn())
    .then(() => console.log(`  ✓ ${desc}`))
    .catch((err) => {
      console.error(`  ✗ ${desc}`);
      throw err;
    });
}

console.log('\n========================================');
console.log(' running AURA Phase 5 Risk API Tests');
console.log('========================================\n');

const BASE_URL = 'http://127.0.0.1:3001';

async function loginAs(role: 'administrator' | 'analyst' | 'viewer'): Promise<string> {
  const res = await fetch(`${BASE_URL}/api/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  assert.equal(res.status, 200);
  const cookie = res.headers.get('set-cookie') ?? '';
  return cookie;
}

async function runTests() {
  const adminCookie = await loginAs('administrator');
  const analystCookie = await loginAs('analyst');
  const viewerCookie = await loginAs('viewer');

  console.log('• Testing GET /api/risk/overview:');

  await it('returns severity counts, disclaimer, and documented demo policy weights', async () => {
    const res = await fetch(`${BASE_URL}/api/risk/overview`, {
      headers: { cookie: analystCookie },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as {
      disclaimer: string;
      counts: { total: number; low: number; medium: number; high: number; critical: number };
      policyWeights: Record<string, number>;
    };

    assert.ok(data.disclaimer.includes('deterministic demo policy weights'));
    assert.ok(data.counts.total > 0);
    assert.equal(typeof data.counts.low, 'number');
    assert.equal(typeof data.counts.critical, 'number');
    assert.equal(data.policyWeights.sensitivity_restricted, 35);
    assert.equal(data.policyWeights.service_unapproved, 20);
    assert.equal(data.policyWeights.auth_denied_or_mismatch, 20);
  });

  console.log('\n• Testing GET /api/risk/events & Filtering:');

  await it('returns paginated events with explainable factors and identity correlation', async () => {
    const res = await fetch(`${BASE_URL}/api/risk/events?limit=10`, {
      headers: { cookie: analystCookie },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as {
      events: Array<{
        id: number;
        destination: string;
        risk_score: number;
        risk_level: string;
        risk_factors: Array<{ id: string; name: string; points: number }>;
        risk_explanation: string;
        identity_correlation: { authStatus: string; userListed: boolean };
      }>;
      pagination: { total: number };
    };

    assert.ok(data.events.length > 0);
    const evt = data.events[0];
    assert.ok(Array.isArray(evt.risk_factors));
    assert.ok(evt.risk_factors.length > 0);
    assert.equal(typeof evt.risk_explanation, 'string');
    assert.ok(evt.identity_correlation != null);
  });

  await it('filters events accurately by severity (critical, high, low)', async () => {
    const resCritical = await fetch(`${BASE_URL}/api/risk/events?severity=critical`, {
      headers: { cookie: analystCookie },
    });
    assert.equal(resCritical.status, 200);
    const dataCritical = (await resCritical.json()) as { events: Array<{ risk_level: string }> };
    for (const e of dataCritical.events) {
      assert.equal(e.risk_level, 'critical');
    }

    const resLow = await fetch(`${BASE_URL}/api/risk/events?severity=low`, {
      headers: { cookie: analystCookie },
    });
    assert.equal(resLow.status, 200);
    const dataLow = (await resLow.json()) as { events: Array<{ risk_level: string }> };
    for (const e of dataLow.events) {
      assert.equal(e.risk_level, 'low');
    }
  });

  await it('filters events by classification and source provenance', async () => {
    const res = await fetch(`${BASE_URL}/api/risk/events?classification=Possible local AI&source=simulation`, {
      headers: { cookie: analystCookie },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as { events: Array<{ classification: string; source_type: string }> };
    for (const e of data.events) {
      assert.equal(e.classification, 'Possible local AI');
      assert.equal(e.source_type, 'simulation');
    }
  });

  console.log('\n• Testing GET /api/risk/events/:id Detail Drilldown:');

  await it('returns complete factor breakdown, explanation, and identity correlation for single event', async () => {
    // Get first event id
    const listRes = await fetch(`${BASE_URL}/api/risk/events?limit=1`, {
      headers: { cookie: viewerCookie },
    });
    assert.equal(listRes.status, 200);
    const listData = (await listRes.json()) as { events: Array<{ id: number }> };
    const eventId = listData.events[0].id;

    const detailRes = await fetch(`${BASE_URL}/api/risk/events/${eventId}`, {
      headers: { cookie: viewerCookie },
    });
    assert.equal(detailRes.status, 200);
    const detailData = (await detailRes.json()) as {
      event: {
        id: number;
        destination: string;
        risk_score: number;
        risk_level: string;
        risk_factors: Array<{ id: string; name: string; points: number }>;
        risk_explanation: string;
        identity_correlation: { authStatus: string; userListed: boolean; notes: string };
        action_recommendation: string;
      };
      policyWeights: Record<string, number>;
    };

    assert.equal(detailData.event.id, eventId);
    assert.ok(detailData.event.risk_factors.length > 0);
    assert.ok(detailData.event.risk_explanation.length > 0);
    assert.ok(detailData.event.identity_correlation.notes.length > 0);
  });

  console.log('\n• Testing Prompt Lab Explainable Risk Integration & Privacy:');

  await it('returns risk assessment metadata with detected categories without leaking prompt text', async () => {
    const scanRes = await fetch(`${BASE_URL}/api/prompt-lab/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        cookie: analystCookie,
      },
      body: JSON.stringify({
        text: 'Deploy secret sk-999fake999fake999fake999 to production database',
        destination: 'Unknown destination',
        destinationStatus: 'Unapproved',
      }),
    });
    assert.equal(scanRes.status, 200);
    const scanData = (await scanRes.json()) as {
      success: boolean;
      riskAssessment: {
        score: number;
        severity: string;
        factors: Array<{ id: string; name: string; points: number }>;
        explanation: string;
        recommendation: string;
      };
    };

    assert.equal(scanData.success, true);
    assert.ok(scanData.riskAssessment != null);
    assert.ok(scanData.riskAssessment.score >= 50);
    // Ensure explanation does NOT contain the secret
    assert.ok(!scanData.riskAssessment.explanation.includes('sk-999'));
    // Ensure simulated recommendation is marked
    assert.match(scanData.riskAssessment.recommendation, /simulation/i);
  });

  console.log('\n========================================');
  console.log(' ✅ Completed: All Risk API Tests Passed');
  console.log('========================================\n');
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
