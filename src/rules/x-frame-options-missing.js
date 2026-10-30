/**
 * SiteCheck Security Rule: x-frame-options-missing
 *
 * Detects whether the X-Frame-Options HTTP response header is missing, empty, or set to an invalid directive.
 * X-Frame-Options protects users against clickjacking (UI redressing) attacks by ensuring that the webpage
 * cannot be embedded within malicious iframes, frames, or object tags on external origins.
 */

export default {
  id: "x-frame-options-missing",

  category: "headers",

  severity: "medium",

  /**
   * Evaluates whether X-Frame-Options is missing or configured with an invalid directive.
   *
   * Valid directives:
   * - DENY: Completely prevents the page from being rendered in a frame.
   * - SAMEORIGIN: Allows framing only if the framing page is on the exact same origin.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if X-Frame-Options is missing, empty, or invalid; false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.headers || typeof ctx.headers !== "object") {
      return false;
    }

    const header = ctx.headers["x-frame-options"];

    // Missing, non-string, or empty header triggers the rule
    if (typeof header !== "string" || header.trim() === "") {
      return true;
    }

    const normalizedValue = header.trim().toUpperCase();

    // Valid standard directives are DENY and SAMEORIGIN
    if (normalizedValue === "DENY" || normalizedValue === "SAMEORIGIN") {
      return false;
    }

    // Invalid or deprecated directive (e.g., 'ALLOW', 'NONE', '1', or malformed value)
    return true;
  },

  explain:
    "The X-Frame-Options response header defends against clickjacking attacks by instructing web browsers whether a page may be rendered inside a <frame>, <iframe>, <embed>, or <object>. Without a valid directive (such as DENY or SAMEORIGIN), malicious websites can load your application in a transparent frame overlaid on top of a decoy page, tricking users into clicking buttons or executing unauthorized transactions without their knowledge.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation using helmet or custom middleware
const helmet = require('helmet');

// Option A: With helmet frameguard (DENY or SAMEORIGIN)
app.use(helmet.frameguard({ action: 'deny' }));

// Option B: Set the header directly
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});`,

    nginx: `# Nginx remediation inside server {} or location {} block
# Deny framing entirely:
add_header X-Frame-Options "DENY" always;

# Or allow framing only from the same origin:
# add_header X-Frame-Options "SAMEORIGIN" always;`,

    django: `# Django remediation in settings.py
# 1. Ensure 'django.middleware.clickjacking.XFrameOptionsMiddleware' is in MIDDLEWARE
# 2. Configure X_FRAME_OPTIONS:
X_FRAME_OPTIONS = 'DENY' # Or 'SAMEORIGIN'`,

    flask: `# Flask remediation using Flask-Talisman or after_request hook
# Option A: With Flask-Talisman
from flask_talisman import Talisman
Talisman(app, frame_options='DENY')

# Option B: Native after_request hook
@app.after_request
def set_frame_options_header(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response`
  }
};

