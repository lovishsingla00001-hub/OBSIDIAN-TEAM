/**
 * @fileoverview HTTP Security Headers Rules for SiteCheck.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * DOMAIN: HTTP Header Security & Information Disclosure
 */

/** @type {import('../core/types').Rule[]} */
const headerRules = [
  {
    id: 'SEC-HEADER-CSP',
    category: 'headers',
    severity: 'high',
    check: (ctx) => !ctx.headers || !ctx.headers['content-security-policy'],
    explain: 'Missing Content-Security-Policy (CSP) header allows cross-site scripting (XSS) and data injection attacks.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }));",
      nginx: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;",
      django: "CSP_DEFAULT_SRC = (\"'self'\",)",
      flask: "Talisman(app, content_security_policy=csp)",
    },
  },
  {
    id: 'SEC-HEADER-HSTS',
    category: 'headers',
    severity: 'high',
    check: (ctx) => Boolean(ctx.usedHttps && (!ctx.headers || !ctx.headers['strict-transport-security'])),
    explain: 'Missing Strict-Transport-Security (HSTS) header allows SSL-stripping and man-in-the-middle attacks.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));",
      nginx: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
      django: "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True",
      flask: "Talisman(app, force_https=True, strict_transport_security=True)",
    },
  },
  {
    id: 'SEC-HEADER-XFO',
    category: 'headers',
    severity: 'medium',
    check: (ctx) => {
      if (!ctx.headers) return true;
      const xfo = ctx.headers['x-frame-options'];
      const csp = ctx.headers['content-security-policy'];
      const hasCspFrameAncestors = typeof csp === 'string' && csp.toLowerCase().includes('frame-ancestors');
      // Trigger if X-Frame-Options is missing AND CSP does not provide frame-ancestors
      return !xfo && !hasCspFrameAncestors;
    },
    explain: 'Missing X-Frame-Options header leaves the website vulnerable to clickjacking and UI redressing attacks.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.frameguard({ action: 'deny' }));",
      nginx: 'add_header X-Frame-Options "DENY" always;',
      django: "X_FRAME_OPTIONS = 'DENY'",
      flask: "Talisman(app, frame_options='DENY')",
    },
  },
  {
    id: 'SEC-HEADER-XCTO',
    category: 'headers',
    severity: 'low',
    check: (ctx) => {
      if (!ctx.headers) return true;
      const xcto = ctx.headers['x-content-type-options'];
      return !xcto || xcto.toLowerCase().trim() !== 'nosniff';
    },
    explain: 'Missing or misconfigured X-Content-Type-Options allows MIME-type sniffing, leading to executable code injection.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: 'app.use(helmet.noSniff());',
      nginx: 'add_header X-Content-Type-Options "nosniff" always;',
      django: 'SECURE_CONTENT_TYPE_NOSNIFF = True',
      flask: 'Talisman(app, content_type_nosniff=True)',
    },
  },
  {
    id: 'SEC-HEADER-REFERRER',
    category: 'headers',
    severity: 'low',
    check: (ctx) => {
      if (!ctx.headers) return true;
      const ref = ctx.headers['referrer-policy'];
      if (!ref) return true;
      const lower = ref.toLowerCase().trim();
      // Insecure policies leak sensitive URLs or user tokens in Referer header
      return lower === 'unsafe-url' || lower === 'no-referrer-when-downgrade';
    },
    explain: 'Missing or insecure Referrer-Policy header risks leaking sensitive URL parameters to third-party domains.',
    owasp: 'A04:2021-Insecure Design',
    fixes: {
      express: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      django: "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
      flask: "Talisman(app, referrer_policy='strict-origin-when-cross-origin')",
    },
  },
  {
    id: 'SEC-HEADER-PERMISSIONS',
    category: 'headers',
    severity: 'low',
    check: (ctx) => {
      if (!ctx.headers) return true;
      return !ctx.headers['permissions-policy'] && !ctx.headers['feature-policy'];
    },
    explain: 'Missing Permissions-Policy header fails to restrict browser hardware features like camera, microphone, and geolocation.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.permittedCrossDomainPolicies());",
      nginx: 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
      django: "SECURE_PERMISSIONS_POLICY = {'geolocation': '()', 'camera': '()'}",
      flask: "Talisman(app, permissions_policy={'geolocation': '()'})",
    },
  },
  {
    id: 'SEC-DISCLOSURE-SERVER',
    category: 'headers',
    severity: 'low',
    check: (ctx) => {
      if (!ctx.headers) return false;
      // Exposing x-powered-by reveals backend runtime/framework
      if (ctx.headers['x-powered-by']) return true;
      // Exposing specific version numbers in server header (e.g. nginx/1.24.0 or Apache/2.4.41)
      const server = ctx.headers['server'];
      if (typeof server === 'string' && /\d+\.\d+/.test(server)) {
        return true;
      }
      return false;
    },
    explain: 'Server or X-Powered-By header discloses exact software versions, aiding attackers in locating targeted CVE exploits.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: 'app.disable("x-powered-by");',
      nginx: 'server_tokens off;',
      django: '# Ensure WSGI server does not emit server banners',
      flask: 'app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0 # Strip server banners in reverse proxy',
    },
  },
];

module.exports = headerRules;
