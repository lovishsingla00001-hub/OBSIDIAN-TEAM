/**
 * SiteCheck Security Rule: x-content-type-options-missing
 *
 * Detects whether the X-Content-Type-Options HTTP response header is missing or not set to 'nosniff'.
 * When this header is absent or misconfigured, web browsers may attempt to deduce ("sniff") the MIME type
 * of a response by inspecting its byte content rather than trusting the server's Content-Type header.
 * Attackers can leverage MIME sniffing to execute malicious scripts disguised as images or text files.
 */

export default {
  id: "x-content-type-options-missing",

  category: "headers",

  severity: "low",

  /**
   * Evaluates whether the X-Content-Type-Options header is missing or invalid.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if X-Content-Type-Options is missing or not 'nosniff', false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.headers || typeof ctx.headers !== "object") {
      return false;
    }

    const header = ctx.headers["x-content-type-options"];

    // Missing, non-string, or empty header triggers the rule
    if (typeof header !== "string" || header.trim() === "") {
      return true;
    }

    // Must be set to 'nosniff' (case-insensitive check)
    if (header.trim().toLowerCase() !== "nosniff") {
      return true;
    }

    return false;
  },

  explain:
    "The X-Content-Type-Options response header prevents web browsers from MIME-sniffing a response away from the declared Content-Type. Without this header set to 'nosniff', a browser might interpret a benign file (like an uploaded image or text file) as executable JavaScript, opening the door to cross-site scripting (XSS) attacks.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation using helmet or custom middleware
const helmet = require('helmet');

// Helmet includes noSniff by default
app.use(helmet.noSniff());

// Or set the header directly:
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});`,

    nginx: `# Nginx remediation inside server {} or location {} block
add_header X-Content-Type-Options "nosniff" always;`,

    django: `# Django remediation in settings.py
# Ensures X-Content-Type-Options: nosniff is sent with every response
SECURE_CONTENT_TYPE_NOSNIFF = True`,

    flask: `# Flask remediation using Flask-Talisman or after_request hook
# Option A: With Flask-Talisman (content_security_policy and nosniff enabled by default)
from flask_talisman import Talisman
Talisman(app)

# Option B: Native after_request hook
@app.after_request
def set_nosniff_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response`
  }
};

