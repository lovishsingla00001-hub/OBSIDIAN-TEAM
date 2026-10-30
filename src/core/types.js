/**
 * @fileoverview Frozen data contracts and JSDoc type definitions for SiteCheck.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * CONTRACT: FROZEN (Do not rename or reshape properties)
 */

/**
 * TLS certificate inspection details.
 * @typedef {Object} TlsInfo
 * @property {boolean} valid - Whether the TLS certificate is valid and within its active date window.
 * @property {number} daysUntilExpiry - Days remaining until certificate expiration.
 */

/**
 * Well-known path probe result.
 * @typedef {Object} PathStatus
 * @property {number} status - HTTP status code returned for the probed path.
 */

/**
 * Fixed probe targets for well-known paths.
 * @typedef {Object} WellKnownPaths
 * @property {PathStatus} "/.git/HEAD" - Probe result for exposed Git HEAD metadata.
 * @property {PathStatus} "/.env" - Probe result for exposed environment variables file.
 * @property {PathStatus} "/robots.txt" - Probe result for robots.txt configuration.
 * @property {PathStatus} "/sitemap.xml" - Probe result for sitemap.xml configuration.
 */

/**
 * Frozen SiteContext structure assembled exclusively by fetchSiteContext(url).
 *
 * @typedef {Object} SiteContext
 * @property {string} url - The initial user-supplied target URL.
 * @property {string} finalUrl - Final destination URL after following HTTP redirects.
 * @property {number} statusCode - HTTP status code returned by the homepage.
 * @property {Record<string, string>} headers - Lowercased HTTP response headers key-value map.
 * @property {string} html - Raw HTML response body of the homepage.
 * @property {boolean} usedHttps - Whether the final connection used HTTPS.
 * @property {boolean} redirectedToHttps - Whether the server redirected from HTTP to HTTPS.
 * @property {TlsInfo | null} tls - TLS certificate details, or null if connection was insecure / failed.
 * @property {WellKnownPaths} wellKnownPaths - Probe results for the fixed list of well-known paths.
 */

/**
 * Framework-specific remediation code snippets.
 * @typedef {Object} RuleFixes
 * @property {string} [express] - Remediation snippet for Express.js.
 * @property {string} [nginx] - Remediation snippet for Nginx.
 * @property {string} [django] - Remediation snippet for Django.
 * @property {string} [flask] - Remediation snippet for Flask.
 */

/**
 * Internal Rule definition with evaluation check function.
 *
 * @typedef {Object} Rule
 * @property {string} id - Unique identifier for the rule.
 * @property {string} category - Category grouping (e.g., 'headers', 'tls', 'exposure').
 * @property {string} severity - Severity level ('high', 'medium', 'low').
 * @property {(ctx: SiteContext) => boolean} check - Evaluation function; returns true if the issue is detected.
 * @property {string} explain - Plain-English explanation of the security/privacy issue.
 * @property {string} owasp - Associated OWASP category reference.
 * @property {RuleFixes} fixes - Framework-specific remediation snippets.
 * @property {boolean} [informational] - Optional flag indicating an informational finding (no score penalty).
 */

/**
 * Sanitized, client-facing Rule definition.
 * NOTE: The check() function MUST NOT appear in the final client-facing report.
 *
 * @typedef {Object} ClientRule
 * @property {string} id - Unique identifier for the rule.
 * @property {string} category - Category grouping.
 * @property {string} severity - Severity level.
 * @property {string} explain - Plain-English explanation of the issue.
 * @property {string} owasp - Associated OWASP category reference.
 * @property {RuleFixes} fixes - Framework-specific remediation snippets.
 * @property {boolean} [informational] - Optional flag indicating an informational finding (no score penalty).
 */

/**
 * Result of evaluating a rule against a SiteContext.
 *
 * @typedef {Object} RuleResult
 * @property {ClientRule} rule - The sanitized rule object (without the check() function).
 * @property {boolean} triggered - True if the rule condition was met (issue detected).
 * @property {string | null} [evaluationError] - Error message if evaluation threw an exception; null on successful evaluation.
 */

/**
 * Category score mapping (0-100 per category).
 * @typedef {Record<string, number>} CategoryScores
 */

/**
 * Overall and per-category scoring structure.
 * @typedef {Object} Score
 * @property {number} overall - Overall score between 0 and 100.
 * @property {CategoryScores} byCategory - Category scores between 0 and 100.
 */

/**
 * Count summary of triggered rules grouped by severity.
 * @typedef {Object} Summary
 * @property {number} high - Count of triggered high severity rules.
 * @property {number} medium - Count of triggered medium severity rules.
 * @property {number} low - Count of triggered low severity rules.
 */

/**
 * Complete serializable JSON output returned by runRules(ctx, rules).
 *
 * @typedef {Object} EngineReport
 * @property {RuleResult[]} results - Evaluated rule results with check() stripped.
 * @property {Score} score - Score breakdown.
 * @property {Summary} summary - Summary counts by severity.
 */

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {};
}
