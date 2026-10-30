/**
 * @fileoverview Transport Layer Security (TLS/HTTPS) Rules for SiteCheck.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * DOMAIN: Encryption in Transit & Certificate Health
 */

/** @type {import('../core/types').Rule[]} */
const tlsRules = [
  {
    id: 'SEC-TLS-INSECURE',
    category: 'tls',
    severity: 'high',
    check: (ctx) => !ctx.usedHttps,
    explain: 'Website is served over unencrypted HTTP, allowing network eavesdropping and traffic tampering.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      express: '# Enforce HTTPS via reverse proxy or TLS termination',
      nginx: 'listen 443 ssl http2;\nssl_certificate /path/to/cert.pem;\nssl_certificate_key /path/to/key.pem;',
      django: 'SECURE_SSL_REDIRECT = True',
      flask: 'Talisman(app, force_https=True)',
    },
  },
  {
    id: 'SEC-TLS-REDIRECT',
    category: 'tls',
    severity: 'high',
    check: (ctx) => {
      // Distinguish failed redirects from unknown/unavailable evidence:
      // Only evaluate if the initial URL explicitly requested HTTP.
      const initialWasHttp = typeof ctx.url === 'string' && /^http:\/\//i.test(ctx.url.trim());
      if (!initialWasHttp) {
        return false; // Not applicable: Initial visit was already HTTPS or bare domain
      }
      // Trigger if the server failed to upgrade the connection to HTTPS
      return !ctx.redirectedToHttps || !ctx.usedHttps;
    },
    explain: 'HTTP requests are not automatically redirected to secure HTTPS, leaving initial page loads exposed.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      express: 'app.use((req, res, next) => req.secure ? next() : res.redirect(`https://${req.headers.host}${req.url}`));',
      nginx: 'server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}',
      django: 'SECURE_SSL_REDIRECT = True',
      flask: 'Talisman(app, force_https=True)',
    },
  },
  {
    id: 'SEC-TLS-VALIDITY',
    category: 'tls',
    severity: 'high',
    check: (ctx) => {
      // Handle ctx.tls === null safely
      if (!ctx.usedHttps || !ctx.tls) {
        return false;
      }
      return ctx.tls.valid === false;
    },
    explain: 'The TLS certificate is invalid, self-signed, expired, or hostname-mismatched, causing browser security warnings.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      nginx: 'certbot certonly --nginx -d example.com',
      django: '# Install trusted CA certificate chain in web server',
      flask: '# Install trusted CA certificate chain in web server',
    },
  },
  {
    id: 'SEC-TLS-EXPIRY',
    category: 'tls',
    severity: 'medium',
    check: (ctx) => {
      // Handle ctx.tls === null safely
      if (!ctx.usedHttps || !ctx.tls || !ctx.tls.valid) {
        return false;
      }
      const days = ctx.tls.daysUntilExpiry;
      return typeof days === 'number' && days <= 30 && days > 0;
    },
    explain: 'The TLS certificate will expire within 30 days. Timely renewal is required to prevent website outages.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      nginx: 'certbot renew',
      django: '# Configure automated certificate renewal (e.g. systemd timer or cron for certbot)',
      flask: '# Configure automated certificate renewal (e.g. systemd timer or cron for certbot)',
    },
  },
];

module.exports = tlsRules;
