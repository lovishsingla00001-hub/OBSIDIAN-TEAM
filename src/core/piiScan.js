/**
 * SiteCheck - PII Scanner Module
 * Team: Obsidian
 * 
 * LEGAL AND ETHICAL BOUNDARIES:
 * - This scanner only inspects HTML strings already fetched upstream by teammate A's fetchSiteContext().
 * - It never implements its own network fetching or URL access functionality.
 * - Aadhaar detection is pattern detection only (12-digit Aadhaar-shaped number patterns),
 *   NOT actual identity or Aadhaar validation.
 * - Privacy protection: Matched personal information is never logged, stored, or retained.
 *   Only category names and counts are returned.
 */

// Indian mobile phone number patterns:
// 10 digits starting with 6, 7, 8, or 9, with optional +91 / 91 / 0 prefix and optional standard separators.
const PHONE_PATTERN = /(?<!\d|\+)(?:(?:\+91|91|0)[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}(?!\d)|(?<!\d|\+)(?:(?:\+91|91|0)[\s.-]?)?[6-9]\d{2}[\s.-]\d{3}[\s.-]\d{4}(?!\d)/g;

// Standard email address patterns:
const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// 12-digit Aadhaar-shaped number patterns (pattern detection only, not identity validation):
// Formatted as 4-4-4 with space/hyphen separators or 12 contiguous digits, starting with 2-9.
const AADHAAR_LIKE_PATTERN = /(?<!\d)[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}(?!\d)|(?<!\d)[2-9]\d{11}(?!\d)/g;

/**
 * Scans an HTML string for Personally Identifiable Information (PII) patterns.
 * Pure JavaScript regex-based detection with zero external dependencies.
 *
 * @param {string} html - The pre-fetched HTML string to scan.
 * @returns {Array<{ type: string, count: number }>} Array of detected categories and match counts.
 * @throws {TypeError} If the input is not a string.
 */
export function scanForPII(html) {
  if (typeof html !== 'string') {
    throw new TypeError('Invalid input: HTML must be a string');
  }

  const results = [];

  // Category 1: phone - Indian mobile phone number patterns
  const phoneMatches = html.match(PHONE_PATTERN);
  if (phoneMatches && phoneMatches.length > 0) {
    results.push({ type: 'phone', count: phoneMatches.length });
  }

  // Category 2: email - Email address patterns
  const emailMatches = html.match(EMAIL_PATTERN);
  if (emailMatches && emailMatches.length > 0) {
    results.push({ type: 'email', count: emailMatches.length });
  }

  // Category 3: aadhaar-like - 12-digit Aadhaar-shaped number patterns
  const aadhaarMatches = html.match(AADHAAR_LIKE_PATTERN);
  if (aadhaarMatches && aadhaarMatches.length > 0) {
    results.push({ type: 'aadhaar-like', count: aadhaarMatches.length });
  }

  return results;
}

export default scanForPII;
