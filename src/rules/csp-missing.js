/**
 * SiteCheck Security Rule: csp-missing
 *
 * Detects whether the Content-Security-Policy (CSP) HTTP response header is missing or empty.
 * CSP is a critical defense-in-depth header that restricts the sources from which scripts,
 * images, stylesheets, and other resources can be loaded, preventing Cross-Site Scripting (XSS)
 * and data injection attacks.
 */

export default {
  id: "csp-missing",

  category: "headers",

  severity: "medium",

  /**
   * Evaluates whether an enforced Content-Security-Policy is missing.
   *
   * Note:
   * - Content-Security-Policy-Report-Only does NOT enforce policies and should not
   *   satisfy the requirement for an enforced Content-Security-Policy header.
   * - A missing or whitespace-only header triggers the rule (returns true).
   * - Returns false if evidence is insufficient (e.g. missing context or headers).
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if Content-Security-Policy is missing/empty, false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.headers || typeof ctx.headers !== "object") {
      return false;
    }

    const csp = ctx.headers["content-security-policy"];

    // Missing, undefined, null, or empty string policy triggers the rule
    if (typeof csp !== "string" || csp.trim() === "") {
      return true;
    }

    return false;
  },

  explain:
    "Content-Security-Policy (CSP) is an HTTP header that specifies which dynamic resources are allowed to load and execute in the browser. Without an enforced Content-Security-Policy, attackers who find a cross-site scripting (XSS) vulnerability can inject and execute arbitrary malicious scripts, steal session tokens, or exfiltrate sensitive user data.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation using helmet middleware
const helmet = require('helmet');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"]
    }
  })
);`,

    nginx: `# Nginx remediation inside server {} or location {} block
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';" always;`,

    django: `# Django remediation using django-csp
# 1. Install django-csp: pip install django-csp
# 2. Add 'csp.middleware.CSPMiddleware' to MIDDLEWARE in settings.py
# 3. Configure directives in settings.py:
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FRAME_ANCESTORS = ("'self'",)`,

    flask: `# Flask remediation using Flask-Talisman or after_request hook
# Option A: With Flask-Talisman (recommended)
from flask_talisman import Talisman

csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'object-src': "'none'"
}
Talisman(app, content_security_policy=csp)

# Option B: With native after_request hook
@app.after_request
def set_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
    return response`
  }
};

