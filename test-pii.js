/**
 * SiteCheck - PII Scanner Unit Tests
 * Temporary test file: test-pii.js
 * 
 * Fictional test data only:
 * - Email: demo@example.com, support@example.com
 * - Phone: 9876543210
 * - Aadhaar-shaped: 2345 6789 0123
 */

import assert from 'node:assert';
import { scanForPII } from './src/core/piiScan.js';

let passed = 0;
let failed = 0;

function runTest(description, testFn) {
  try {
    testFn();
    console.log(`  PASS: ${description}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${description}`);
    console.error(`    Error: ${err.message}`);
    failed++;
  }
}

console.log('=== SiteCheck PII Scanner Test Suite ===\n');

// 1. First Test: Combined HTML with one phone, one email, and one Aadhaar-shaped pattern
runTest('Combined Test: One phone, one email, one Aadhaar-shaped pattern', () => {
  const sampleHtml = `
    <div class="user-card">
      <p>Contact: demo@example.com</p>
      <p>Phone: 9876543210</p>
      <p>ID: 2345 6789 0123</p>
    </div>
  `;
  const result = scanForPII(sampleHtml);
  const expected = [
    { type: 'phone', count: 1 },
    { type: 'email', count: 1 },
    { type: 'aadhaar-like', count: 1 }
  ];
  assert.deepStrictEqual(result, expected);
  console.log('    Output:', JSON.stringify(result, null, 2));
});

// 2. Individual Test: One phone number
runTest('One phone number', () => {
  const html = '<p>Call us at 9876543210 for support.</p>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'phone', count: 1 }
  ]);
});

// 3. Individual Test: One email
runTest('One email address', () => {
  const html = '<a href="mailto:demo@example.com">Send an email</a>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'email', count: 1 }
  ]);
});

// 4. Individual Test: One Aadhaar-shaped pattern
runTest('One Aadhaar-shaped pattern (pattern detection only)', () => {
  const html = '<span>Pattern sample: 2345 6789 0123</span>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'aadhaar-like', count: 1 }
  ]);
});

// 5. Multiple email addresses
runTest('Multiple email addresses', () => {
  const html = `
    <div>
      <p>Primary: demo@example.com</p>
      <p>Secondary: support@example.com</p>
    </div>
  `;
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'email', count: 2 }
  ]);
});

// 6. HTML containing no matches
runTest('HTML containing no matches', () => {
  const html = '<main><h1>Welcome to SiteCheck</h1><p>Clean website with no PII.</p></main>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, []);
});

// 7. Empty HTML
runTest('Empty HTML string', () => {
  const html = '';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, []);
});

// 8. Invalid inputs (safely handled with TypeError)
runTest('Invalid input: null', () => {
  assert.throws(() => scanForPII(null), TypeError);
});

runTest('Invalid input: undefined', () => {
  assert.throws(() => scanForPII(undefined), TypeError);
});

runTest('Invalid input: number', () => {
  assert.throws(() => scanForPII(12345), TypeError);
});

runTest('Invalid input: object', () => {
  assert.throws(() => scanForPII({ html: '<p>test</p>' }), TypeError);
});

runTest('Invalid input: boolean', () => {
  assert.throws(() => scanForPII(true), TypeError);
});

// 9. Edge case: International format Indian phone (+91 9876543210)
runTest('Edge Case: Phone with +91 prefix and formatting', () => {
  const html = '<p>Call +91 9876543210 or 98765 43210</p>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'phone', count: 2 }
  ]);
});

// 10. Edge case: 12-digit Aadhaar starting with 9 without matching as phone
runTest('Edge Case: Aadhaar-shaped number starting with 9 does not falsely match phone', () => {
  const html = '<p>ID: 9234 5678 9012</p>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'aadhaar-like', count: 1 }
  ]);
});

// 11. Edge case: Continuous 12-digit Aadhaar-shaped pattern
runTest('Edge Case: Continuous 12-digit Aadhaar-shaped pattern', () => {
  const html = '<p>ID: 234567890123</p>';
  const result = scanForPII(html);
  assert.deepStrictEqual(result, [
    { type: 'aadhaar-like', count: 1 }
  ]);
});

console.log(`\n========================================`);
console.log(`Test Summary: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}
