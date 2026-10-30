/**
 * @fileoverview Test Suite for Supabase Integration
 * Team: Obsidian
 */

'use strict';

const assert = require('assert');
const path = require('path');
let supabaseModulePath = './supabaseClient';
try {
  require.resolve(supabaseModulePath);
} catch {
  supabaseModulePath = '../server/supabaseClient';
}
const {
  formatReportRow,
  getSupabaseConfig,
  saveScanReport,
  getScanReportById,
  getScanHistoryByHostname,
  getRecentScans,
} = require(supabaseModulePath);

async function runTests() {
  console.log('=== TEST SUITE: Supabase Integration Client ===\n');
  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      passed++;
      console.log(`  [PASS] ${name}`);
    } catch (err) {
      failed++;
      console.error(`  [FAIL] ${name}: ${err.message}`);
    }
  }

  async function asyncTest(name, fn) {
    try {
      await fn();
      passed++;
      console.log(`  [PASS] ${name}`);
    } catch (err) {
      failed++;
      console.error(`  [FAIL] ${name}: ${err.message}`);
    }
  }

  // Sample valid scan report for testing
  const sampleScan = {
    url: 'https://example.com',
    finalUrl: 'https://example.com/',
    hostname: 'example.com',
    score: {
      overall: 82,
      byCategory: { headers: 75, tls: 100, exposure: 80, privacy: 75 },
    },
    summary: { high: 0, medium: 2, low: 1 },
    results: [
      {
        rule: {
          id: 'SEC-HEADER-CSP',
          category: 'headers',
          severity: 'medium',
          explain: 'Missing Content Security Policy',
          owasp: 'A05:2021',
          check: () => true, // SHOULD BE STRIPPED
        },
        triggered: true,
      },
      {
        rule: {
          id: 'TLS-VERSION',
          category: 'tls',
          severity: 'high',
          explain: 'TLS 1.3 Active',
          owasp: 'A02:2021',
          check: () => false, // SHOULD BE STRIPPED
        },
        triggered: false,
      },
    ],
    aiExplanation: {
      available: true,
      summary: 'Site posture is generally good with minor header gaps.',
      explanations: [],
      remediation: ['Add Content-Security-Policy'],
    },
  };

  // 1. Config extraction & detection
  test('1. getSupabaseConfig detects unconfigured environment correctly', () => {
    const savedUrl = process.env.SUPABASE_URL;
    const savedKey = process.env.SUPABASE_KEY;
    const savedAnon = process.env.SUPABASE_ANON_KEY;
    const savedRole = process.env.SUPABASE_SERVICE_ROLE_KEY;

    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_KEY;
    delete process.env.SUPABASE_ANON_KEY;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;

    const cfg = getSupabaseConfig();
    assert.strictEqual(cfg.isConfigured, false);

    // Restore for subsequent tests
    if (savedUrl) process.env.SUPABASE_URL = savedUrl;
    if (savedKey) process.env.SUPABASE_KEY = savedKey;
    if (savedAnon) process.env.SUPABASE_ANON_KEY = savedAnon;
    if (savedRole) process.env.SUPABASE_SERVICE_ROLE_KEY = savedRole;
  });

  // 2. Data formatting & schema mapping
  test('2. formatReportRow maps fields and strips rule.check functions', () => {
    const row = formatReportRow(sampleScan);
    assert.strictEqual(row.url, 'https://example.com');
    assert.strictEqual(row.hostname, 'example.com');
    assert.strictEqual(row.score_overall, 82);
    assert.strictEqual(row.summary_counts.medium, 2);
    assert.strictEqual(row.findings.length, 2);
    // Crucial: rule.check must NOT be in persisted row
    assert.strictEqual(row.findings[0].rule.check, undefined, 'check function must be stripped');
    assert.strictEqual(row.findings[0].rule.id, 'SEC-HEADER-CSP');
    assert.strictEqual(row.ai_explanation.available, true);
    assert.ok(row.scanned_at);
  });

  // 3. Score bounds clamping
  test('3. formatReportRow clamps scores between 0 and 100', () => {
    const high = formatReportRow({ url: 'test.com', score: { overall: 150 } });
    assert.strictEqual(high.score_overall, 100);
    const low = formatReportRow({ url: 'test.com', score: { overall: -20 } });
    assert.strictEqual(low.score_overall, 0);
  });

  // 4. Invalid payload validation
  test('4. formatReportRow throws clean error on non-object payload', () => {
    assert.throws(() => formatReportRow(null), /must be a non-null object/);
    assert.throws(() => formatReportRow('invalid'), /must be a non-null object/);
  });

  // 5. Unconfigured environment fails safely
  await asyncTest('5. saveScanReport fails safely without throwing when unconfigured', async () => {
    const res = await saveScanReport(sampleScan, {
      url: '',
      key: '',
      isConfigured: false,
    });
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.reportId, null);
    assert.strictEqual(res.mockSaved, true);
    assert.ok(res.error.includes('SUPABASE_NOT_CONFIGURED'));
  });

  // 6. Mocked successful REST insertion
  await asyncTest('6. saveScanReport succeeds via REST API when configured', async () => {
    const fakeUuid = '123e4567-e89b-12d3-a456-426614174000';
    let requestCaptured = null;

    const mockFetch = async (url, options) => {
      requestCaptured = { url, options };
      return {
        ok: true,
        status: 201,
        json: async () => [{ id: fakeUuid, ...JSON.parse(options.body) }],
      };
    };

    const res = await saveScanReport(sampleScan, {
      url: 'https://xyzcompany.supabase.co',
      key: 'fake-secret-service-role-key-12345',
      isConfigured: true,
      preferRest: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.reportId, fakeUuid);
    assert.strictEqual(res.error, null);
    assert.ok(requestCaptured.url.includes('/rest/v1/scan_reports'));
    assert.strictEqual(requestCaptured.options.headers['apikey'], 'fake-secret-service-role-key-12345');
    assert.strictEqual(requestCaptured.options.headers['Prefer'], 'return=representation');
  });

  // 7. Mocked REST error handling (401 Unauthorized / RLS rejection)
  await asyncTest('7. saveScanReport handles HTTP 401 error safely without throwing', async () => {
    const mockFetch = async () => ({
      ok: false,
      status: 401,
      json: async () => ({ message: 'Invalid API key' }),
    });

    const res = await saveScanReport(sampleScan, {
      url: 'https://xyzcompany.supabase.co',
      key: 'invalid-key',
      isConfigured: true,
      preferRest: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, false);
    assert.strictEqual(res.reportId, null);
    assert.ok(res.error.includes('401'));
  });

  // 8. Query report by ID
  await asyncTest('8. getScanReportById queries single report by UUID', async () => {
    const fakeUuid = '123e4567-e89b-12d3-a456-426614174000';
    const mockFetch = async (url) => {
      assert.ok(url.includes(fakeUuid));
      return {
        ok: true,
        status: 200,
        json: async () => [{ id: fakeUuid, hostname: 'example.com', score_overall: 82 }],
      };
    };

    const res = await getScanReportById(fakeUuid, {
      url: 'https://xyzcompany.supabase.co',
      key: 'test-key',
      isConfigured: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.report.id, fakeUuid);
    assert.strictEqual(res.report.hostname, 'example.com');
  });

  // 9. Query scan history by hostname
  await asyncTest('9. getScanHistoryByHostname queries ordered audit history', async () => {
    const mockFetch = async (url) => {
      assert.ok(url.includes('hostname=eq.example.com'));
      assert.ok(url.includes('order=scanned_at.desc'));
      return {
        ok: true,
        status: 200,
        json: async () => [
          { id: '1', score_overall: 85, scanned_at: '2026-10-30T10:00:00Z' },
          { id: '2', score_overall: 80, scanned_at: '2026-10-29T10:00:00Z' },
        ],
      };
    };

    const res = await getScanHistoryByHostname('EXAMPLE.COM', 5, {
      url: 'https://xyzcompany.supabase.co',
      key: 'test-key',
      isConfigured: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.history.length, 2);
    assert.strictEqual(res.history[0].score_overall, 85);
  });

  // 10. Query recent public scans
  await asyncTest('10. getRecentScans queries community scan feed', async () => {
    const mockFetch = async (url) => {
      assert.ok(url.includes('order=scanned_at.desc'));
      return {
        ok: true,
        status: 200,
        json: async () => [
          { id: '1', hostname: 'github.com', score_overall: 95 },
          { id: '2', hostname: 'mozilla.org', score_overall: 92 },
        ],
      };
    };

    const res = await getRecentScans(10, {
      url: 'https://xyzcompany.supabase.co',
      key: 'test-key',
      isConfigured: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.scans.length, 2);
  });

  // 11. Network disconnection / fetch failure resilience
  await asyncTest('11. saveScanReport catches network exceptions safely without crashing', async () => {
    const mockFetch = async () => {
      throw new Error('ECONNRESET connection dropped');
    };

    const res = await saveScanReport(sampleScan, {
      url: 'https://xyzcompany.supabase.co',
      key: 'test-key',
      isConfigured: true,
      preferRest: true,
      force: true,
      fetch: mockFetch,
    });

    assert.strictEqual(res.success, false);
    assert.ok(res.error.includes('ECONNRESET'));
  });

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
