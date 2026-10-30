/**
 * SiteCheck Security Rule: server-header-leaks-version
 *
 * Detects whether the Server HTTP response header reveals specific software and version numbers.
 * Disclosing exact software versions (e.g. "nginx/1.18.0" or "Apache/2.4.41") assists attackers in
 * conducting automated reconnaissance and matching published Common Vulnerabilities and Exposures (CVEs)
 * to vulnerable backend services.
 *
 * IMPORTANT:
 * - A generic server banner (e.g., "nginx", "Apache", "cloudflare") that does NOT reveal a version
 *   is NOT flagged (returns false).
 * - Only flags when a concrete version identifier or revision number is detected in the header value.
 */

export default {
  id: "server-header-leaks-version",

  category: "hygiene",

  severity: "low",

  /**
   * Evaluates whether the Server response header leaks a software version.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if Server header exposes software version; false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.headers || typeof ctx.headers !== "object") {
      return false;
    }

    const server = ctx.headers["server"];

    // Missing, empty, or non-string header does not leak version information
    if (typeof server !== "string" || server.trim() === "") {
      return false;
    }

    const trimmed = server.trim();

    // Regex pattern to detect software version disclosures:
    // 1. Slash followed by a version number (e.g. "nginx/1.18.0", "Apache/2.4", "IIS/10.0")
    // 2. Explicit semantic or dotted version numbers (e.g. "2.4.41", "v2.6.4", "20.1.0")
    const VERSION_PATTERN = /(?:\/\s*v?\d+(?:\.\d+)*)|\b(?:v?\d+\.\d+(?:\.\d+)*)\b/i;

    return VERSION_PATTERN.test(trimmed);
  },

  explain:
    "The Server response header indicates the web server software handling the request. When configured to display full version details (such as 'Apache/2.4.41' or 'nginx/1.18.0'), attackers can quickly enumerate known unpatched vulnerabilities (CVEs) that specifically affect that release. Obscuring or omitting the version number prevents simple banner-grabbing reconnaissance.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation: Suppress information-disclosing headers
const helmet = require('helmet');

// Hide Express banner (X-Powered-By)
app.disable('x-powered-by');
app.use(helmet.hidePoweredBy());`,

    nginx: `# Nginx remediation: Hide the nginx version in HTTP response headers
# Add this directive inside the http {} block in /etc/nginx/nginx.conf:
http {
    server_tokens off; # Only sends 'Server: nginx' without version numbers
}`,

    django: `# Django / WSGI remediation:
# Configure your WSGI server (Gunicorn / uWSGI) or reverse proxy to omit server banners.
# In Nginx reverse proxy configuration:
proxy_hide_header Server;
add_header Server "webserver" always;`,

    flask: `# Flask remediation using an after_request hook or WSGI configuration
@app.after_request
def sanitize_server_header(response):
    # Strip or replace version disclosure in Server header
    response.headers['Server'] = 'webserver'
    return response`
  }
};

