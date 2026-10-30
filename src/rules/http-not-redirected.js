/**
 * SiteCheck Security Rule: http-not-redirected
 *
 * Detects whether unencrypted HTTP connections fail to redirect to HTTPS.
 * When a website supports HTTPS but does not automatically redirect plain HTTP traffic,
 * users who type the domain without specifying "https://" or who follow insecure links
 * remain exposed to eavesdropping, packet sniffing, and man-in-the-middle (MITM) attacks.
 *
 * IMPORTANT:
 * - Only flags when HTTPS is supported/available and HTTP fails to redirect.
 * - Does not flag if HTTPS is unavailable or if evidence is insufficient.
 */

export default {
  id: "http-not-redirected",

  category: "tls",

  severity: "medium",

  /**
   * Evaluates whether plain HTTP requests fail to redirect to HTTPS.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if HTTP fails to redirect to available HTTPS, false otherwise.
   */
  check(ctx) {
    if (!ctx || typeof ctx !== "object") {
      return false;
    }

    // If the crawler confirmed redirection to HTTPS, the security control is working
    if (ctx.redirectedToHttps === true) {
      return false;
    }

    // Determine if HTTPS is available on the target host
    const httpsAvailable =
      ctx.usedHttps === true ||
      Boolean(ctx.tls && ctx.tls.valid === true) ||
      (typeof ctx.finalUrl === "string" && ctx.finalUrl.toLowerCase().startsWith("https://"));

    // Do not flag sites where HTTPS is not available or evidence is insufficient
    if (!httpsAvailable) {
      return false;
    }

    // If redirectedToHttps is explicitly false while HTTPS is supported, problem found
    if (ctx.redirectedToHttps === false) {
      return true;
    }

    // Fallback: Check if initial request was HTTP and final response remained on HTTP
    const initialIsHttp =
      typeof ctx.url === "string" && ctx.url.toLowerCase().startsWith("http://");
    const finalIsHttp =
      typeof ctx.finalUrl === "string" && ctx.finalUrl.toLowerCase().startsWith("http://");

    if (initialIsHttp && finalIsHttp) {
      return true;
    }

    return false;
  },

  explain:
    "Websites should automatically redirect all unencrypted HTTP traffic to HTTPS using an HTTP 301 Permanent Redirect. Without this redirection, users accessing the site over plain HTTP are vulnerable to network eavesdropping, session hijacking, and man-in-the-middle attacks where attackers can tamper with website content.",

  owasp: "A02:2021-Cryptographic Failures",

  fixes: {
    express: `// Express.js remediation: Redirect all HTTP requests to HTTPS
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    return next();
  }
  return res.redirect(301, \`https://\${req.headers.host}\${req.url}\`);
});`,

    nginx: `# Nginx remediation: Redirect port 80 HTTP traffic to HTTPS
server {
    listen 80;
    server_name example.com www.example.com;

    # Permanent redirect to HTTPS
    return 301 https://$host$request_uri;
}`,

    django: `# Django remediation in settings.py
# Enforce automatic SSL redirect for all HTTP connections
SECURE_SSL_REDIRECT = True

# If running behind a reverse proxy or load balancer (Nginx, AWS ALB, Cloudflare):
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')`,

    flask: `# Flask remediation using Flask-Talisman or before_request hook
# Option A: Flask-Talisman (recommended)
from flask_talisman import Talisman
Talisman(app, force_https=True)

# Option B: Native before_request hook
from flask import request, redirect

@app.before_request
def enforce_https():
    if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)`
  }
};

