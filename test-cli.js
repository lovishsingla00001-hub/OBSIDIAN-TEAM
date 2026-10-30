/**
 * SiteCheck - Automated CLI Test Suite
 * Team: Obsidian
 * 
 * Verifies all CLI requirements:
 * 1. Missing URL argument.
 * 2. Invalid URL.
 * 3. Unsupported URL protocol.
 * 4. Successful scan.
 * 5. Report containing high-severity findings (Exit Code 1).
 * 6. Report without high-severity findings (Exit Code 0).
 * 7. PII results appearing in report as counts (phone, email, aadhaar-like).
 * 8. Fetch failure handling.
 * 9. Integration with printReport.
 */

import { validateCliUrl, runCliScan, printReport } from './cli/sitecheck.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  PASS: ${message}`);
    passed++;
  } else {
    console.error(`  FAIL: ${message}`);
    failed++;
  }
}

function assertThrows(fn, messagePattern, testName) {
  try {
    fn();
    console.error(`  FAIL: ${testName} (did not throw)`);
    failed++;
  } catch (err) {
    if (messagePattern && !err.message.includes(messagePattern)) {
      console.error(`  FAIL: ${testName} (unexpected message: "${err.message}")`);
      failed++;
    } else {
      console.log(`  PASS: ${testName}`);
      passed++;
    }
  }
}

async function assertAsyncThrows(promiseFn, messagePattern, testName) {
  try {
    await promiseFn();
    console.error(`  FAIL: ${testName} (did not throw)`);
    failed++;
  } catch (err) {
    if (messagePattern && !err.message.includes(messagePattern)) {
      console.error(`  FAIL: ${testName} (unexpected message: "${err.message}")`);
      failed++;
    } else {
      console.log(`  PASS: ${testName}`);
      passed++;
    }
  }
}

console.log('=== SiteCheck CLI Test Suite (Step 3) ===\n');

// 1. Missing URL argument
assertThrows(() => validateCliUrl(''), 'Missing URL argument', 'Test 1a: Missing empty string URL throws');
assertThrows(() => validateCliUrl(null), 'Missing URL argument', 'Test 1b: Missing null URL throws');
assertThrows(() => validateCliUrl(undefined), 'Missing URL argument', 'Test 1c: Missing undefined URL throws');

// 2. Invalid URL
assertThrows(() => validateCliUrl('   '), 'Missing URL argument', 'Test 2a: Whitespace-only URL throws');

// 3. Unsupported URL protocol
assertThrows(() => validateCliUrl('ftp://example.com'), 'Unsupported protocol', 'Test 3a: ftp protocol rejected');
assertThrows(() => validateCliUrl('file:///etc/passwd'), 'Unsupported protocol', 'Test 3b: file protocol rejected');
assertThrows(() => validateCliUrl('ssh://git@github.com'), 'Unsupported protocol', 'Test 3c: ssh protocol rejected');

// Valid URL normalization
assert(validateCliUrl('https://example.com') === 'https://example.com/', 'Test 3d: Normalizes valid https URL');
assert(validateCliUrl('http://example.com') === 'http://example.com/', 'Test 3e: Normalizes valid http URL');

// Mock data fixtures
const mockHtmlWithPII = `
  <html>
    <body>
      <p>Contact: demo@example.com</p>
      <p>Helpline: 9876543210</p>
      <p>Aadhaar: 2345 6789 0123</p>
    </body>
  </html>
`;

const mockCleanHtml = '<html><body><h1>Clean Documentation</h1></body></html>';

// 4. Successful scan with clean HTML & no high-severity findings
const cleanScanResult = await runCliScan('https://clean-site.org', {
  fetchSiteContext: async (url) => ({
    url,
    finalUrl: url,
    html: mockCleanHtml,
    headers: { 'content-type': 'text/html' }
  }),
  runRules: () => ({
    results: [
      { rule: { id: 'header-check', severity: 'low' }, triggered: false }
    ],
    score: { overall: 100 },
    summary: { high: 0, medium: 0, low: 0 }
  })
});

assert(cleanScanResult.exitCode === 0, 'Test 4a: Clean scan returns exitCode 0');
assert(Array.isArray(cleanScanResult.report.pii), 'Test 4b: Report pii property is an array');
assert(cleanScanResult.report.pii.length === 0, 'Test 4c: Clean scan pii array is empty');
assert(cleanScanResult.report.score.overall === 100, 'Test 4d: Preserves overall score 100');

// 5. Report containing high-severity findings -> Exit code 1
const highSeverityScanResult = await runCliScan('https://vulnerable-site.org', {
  fetchSiteContext: async (url) => ({
    url,
    finalUrl: url,
    html: mockCleanHtml,
    headers: {}
  }),
  runRules: () => ({
    results: [
      { rule: { id: 'SEC-EXPOSURE-ENV', severity: 'high', explain: 'Exposed env' }, triggered: true }
    ],
    score: { overall: 75 },
    summary: { high: 1, medium: 0, low: 0 }
  })
});

assert(highSeverityScanResult.exitCode === 1, 'Test 5: High severity finding returns exitCode 1');

// 6. Report containing only medium/low severity findings -> Exit code 0
const mediumSeverityScanResult = await runCliScan('https://low-risk-site.org', {
  fetchSiteContext: async (url) => ({
    url,
    finalUrl: url,
    html: mockCleanHtml,
    headers: {}
  }),
  runRules: () => ({
    results: [
      { rule: { id: 'SEC-TLS-EXPIRY', severity: 'medium', explain: 'TLS expiring' }, triggered: true },
      { rule: { id: 'SEC-HEADER-XFO', severity: 'low', explain: 'Missing XFO' }, triggered: true }
    ],
    score: { overall: 85 },
    summary: { high: 0, medium: 1, low: 1 }
  })
});

assert(mediumSeverityScanResult.exitCode === 0, 'Test 6: Medium/Low severity findings return exitCode 0');

// 7. PII results properly detected and formatted as counts
const piiScanResult = await runCliScan('https://patient-portal.org', {
  fetchSiteContext: async (url) => ({
    url,
    finalUrl: url,
    html: mockHtmlWithPII,
    headers: {}
  }),
  runRules: () => ({
    results: [],
    score: { overall: 100 },
    summary: { high: 0, medium: 0, low: 0 }
  })
});

assert(piiScanResult.report.pii.length === 3, 'Test 7a: Detects exactly 3 PII categories');
const phoneItem = piiScanResult.report.pii.find(p => p.type === 'phone');
const emailItem = piiScanResult.report.pii.find(p => p.type === 'email');
const aadhaarItem = piiScanResult.report.pii.find(p => p.type === 'aadhaar-like');

assert(phoneItem && phoneItem.count === 1, 'Test 7b: Phone count is 1');
assert(emailItem && emailItem.count === 1, 'Test 7c: Email count is 1');
assert(aadhaarItem && aadhaarItem.count === 1, 'Test 7d: Aadhaar-like count is 1');

// 8. Fetch failure handling
await assertAsyncThrows(
  () => runCliScan('https://offline-target.com', {
    fetchSiteContext: async () => {
      throw new Error('DNS resolution failed for hostname: ENOTFOUND');
    }
  }),
  'Fetch failure',
  'Test 8: Network/DNS fetch error throws operational failure'
);

// 9. Verify printReport output executes cleanly without errors
try {
  console.log('\n--- Terminal Report Visual Preview ---');
  printReport(piiScanResult.report, 'https://patient-portal.org');
  console.log('--- End Visual Preview ---\n');
  assert(true, 'Test 9: printReport formats and renders cleanly');
} catch (err) {
  assert(false, `Test 9: printReport threw: ${err.message}`);
}

console.log('========================================');
console.log(`Test Summary: ${passed} passed, ${failed} failed`);
console.log('========================================\n');

if (failed > 0) {
  process.exit(1);
}
