/**
 * SiteCheck Security Rule Template
 *
 * This file serves as a reference and starting point for creating new security rules.
 * Open-source contributors can copy this file, rename it to <rule-id>.js, and implement
 * their check and remediation logic.
 *
 * ABSOLUTE SECURITY BOUNDARY:
 * - Rules must ONLY read information already provided in the `ctx` object.
 * - NEVER perform network calls (no fetch, axios, http/https, dns, ping, etc.).
 * - NEVER probe endpoints, send attack payloads, or attempt exploitation.
 * - If a rule requires information not present in `ctx`, document the requirement
 *   for Teammate A to add into `fetchSiteContext()`.
 *
 * RETURN VALUE FOR check(ctx):
 * - return true  => Security vulnerability/misconfiguration FOUND (triggers warning/issue).
 * - return false => Security protection is present OR insufficient evidence to claim an issue.
 * - Never report a problem based on assumptions.
 *
 * ALLOWED RULE PROPERTIES:
 * - id: String (kebab-case, unique identifier matching the filename, e.g., "csp-missing")
 * - category: "headers" | "tls" | "exposure" | "privacy" | "hygiene"
 * - severity: "high" | "medium" | "low"
 * - check: Function receiving `ctx` and returning boolean
 * - explain: Plain English, beginner-friendly explanation of why this matters
 * - owasp: Reference string (e.g., "A05:2021-Security Misconfiguration")
 * - fixes: Object with practical snippets for express, nginx, django, flask
 */

export default {
  // Unique identifier for the rule (kebab-case). Note: prefix with underscore for template.
  id: "_rule-template",

  // Category must be one of: "headers", "tls", "exposure", "privacy", "hygiene"
  category: "headers",

  // Severity must be one of: "high", "medium", "low"
  severity: "medium",

  /**
   * Evaluates the website context for the security condition.
   *
   * @param {Object} ctx - The frozen context collected for the website.
   * @param {string} ctx.url - Initial target URL provided by the user.
   * @param {string} ctx.finalUrl - Final URL reached after redirects.
   * @param {number} ctx.statusCode - HTTP response status code.
   * @param {Record<string, string>} ctx.headers - Lowercase HTTP response headers.
   * @param {string} ctx.html - Response body HTML content.
   * @param {boolean} ctx.usedHttps - Whether HTTPS was used.
   * @param {boolean} ctx.redirectedToHttps - Whether HTTP redirected to HTTPS.
   * @param {Object|null} ctx.tls - TLS certificate details (valid, daysUntilExpiry).
   * @param {Record<string, { status: number }>} ctx.wellKnownPaths - Probed status for common paths.
   *
   * @returns {boolean} true if the security flaw is present, false otherwise.
   */
  check(ctx) {
    // 1. Guard against missing or null context and headers
    if (!ctx || !ctx.headers) {
      return false;
    }

    // 2. Inspect headers or context properties safely
    // Example: const headerVal = ctx.headers["example-security-header"];
    // if (!headerVal || headerVal.trim() === "") {
    //   return true; // Problem found!
    // }

    // Always default to false when evidence is not conclusive or protection is present
    return false;
  },

  // Clear, educational explanation accessible to beginners and non-security developers
  explain:
    "Briefly explain the security mechanism, what risk is introduced when it is missing or misconfigured, and why addressing it improves application defense.",

  // Standard OWASP Top 10 or ASVS category mapping
  owasp: "A05:2021-Security Misconfiguration",

  // Practical, drop-in remediation configuration for the four major web stacks
  fixes: {
    express: `// Express.js remediation using helmet or custom middleware
const helmet = require('helmet');
app.use(helmet());`,

    nginx: `# Nginx remediation inside server or location block
add_header X-Example-Header "value" always;`,

    django: `# Django settings.py configuration
# Ensure the relevant security setting is enabled
SECURE_EXAMPLE_SETTING = True`,

    flask: `# Flask remediation using Flask-Talisman or after_request hook
@app.after_request
def set_security_headers(response):
    response.headers['X-Example-Header'] = 'value'
    return response`
  }
};

