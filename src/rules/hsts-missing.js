/**
 * SiteCheck Security Rule: hsts-missing
 *
 * Detects whether the HTTP Strict Transport Security (HSTS) response header is missing on an HTTPS website.
 * HSTS ensures that compliant web browsers only communicate with the origin over HTTPS, preventing
 * SSL-stripping and man-in-the-middle downgrade attacks.
 *
 * IMPORTANT:
 * - Only evaluated when the website is using HTTPS.
 * - If the website has not reached HTTPS (e.g. plain HTTP), missing HSTS is NOT reported,
 *   because HSTS headers are ignored by browsers over plain HTTP and cannot protect an unencrypted connection.
 */

export default {
  id: "hsts-missing",

  category: "headers",

  severity: "medium",

  /**
   * Evaluates whether HSTS is missing on an HTTPS website.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if HSTS is missing on HTTPS, false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.headers || typeof ctx.headers !== "object") {
      return false;
    }

    // Determine if the website connection has reached HTTPS
    const isHttps =
      ctx.usedHttps === true ||
      (typeof ctx.finalUrl === "string" && ctx.finalUrl.toLowerCase().startsWith("https://")) ||
      (typeof ctx.url === "string" && ctx.url.toLowerCase().startsWith("https://"));

    // Do not report missing HSTS on websites that have not reached HTTPS
    if (!isHttps) {
      return false;
    }

    const hsts = ctx.headers["strict-transport-security"];

    // Missing, undefined, null, or empty string header triggers the rule
    if (typeof hsts !== "string" || hsts.trim() === "") {
      return true;
    }

    return false;
  },

  explain:
    "HTTP Strict Transport Security (HSTS) instructs web browsers that the website must only be accessed over secure HTTPS connections, and that any insecure HTTP attempts must be automatically upgraded client-side before sending requests over the network. Without HSTS on an HTTPS site, users can be vulnerable to SSL-stripping and man-in-the-middle downgrade attacks on public Wi-Fi or untrusted networks.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation using helmet middleware or custom header
const helmet = require('helmet');

app.use(
  helmet.hsts({
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true
  })
);

// Or via custom middleware:
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload'
    );
  }
  next();
});`,

    nginx: `# Nginx remediation inside the HTTPS server block (port 443)
server {
    listen 443 ssl http2;
    server_name example.com;

    # Enforce HSTS for 1 year including subdomains
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}`,

    django: `# Django remediation in settings.py
# Enforce HSTS across the application (requires HTTPS)
SECURE_HSTS_SECONDS = 31536000  # 1 year in seconds
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True`,

    flask: `# Flask remediation using Flask-Talisman or after_request hook
# Option A: With Flask-Talisman (recommended)
from flask_talisman import Talisman

Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True
)

# Option B: With native after_request hook
@app.after_request
def set_hsts_header(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response`
  }
};

