/**
 * SiteCheck - Mock Scan Dataset (mockScanData.js)
 * Team: Obsidian
 * 
 * Illustrative demonstration dataset matching backend schema for offline preview
 * and automated verification tests.
 */

(function (window) {
  'use strict';

  const MOCK_SCAN_DATA = {
    isMock: true,
    url: 'https://example.com',
    finalUrl: 'https://example.com/',
    hostname: 'example.com',
    scannedAt: 'Fri, 30 Oct 2026 14:30:00 GMT',
    score: {
      overall: 75,
      byCategory: {
        headers: 65,
        tls: 100,
        exposure: 80,
        privacy: 75
      }
    },
    summary: {
      high: 2,
      medium: 2,
      low: 2
    },
    meta: {
      targetUrl: 'https://example.com',
      hostname: 'example.com',
      scannedAt: 'Fri, 30 Oct 2026 14:30:00 GMT',
      statusCode: 200,
      responseTimeMs: 142
    },
    tls: {
      valid: true,
      daysUntilExpiry: 90
    },
    wellKnownPaths: {
      '/.git/HEAD': { status: 404 },
      '/.env': { status: 404 },
      '/robots.txt': { status: 200 },
      '/sitemap.xml': { status: 404 }
    },
    aiExplanation: {
      available: true,
      model: 'gemma4:e4b',
      summary: 'The target website presents an exemplary TLS certificate configuration (valid with 90 days to renewal). However, 6 security hygiene gaps were discovered in HTTP response headers and endpoint information exposure that leave client sessions vulnerable to cross-site scripting, clickjacking, and mime-confusion attacks.',
      whatItMeans: 'The web server delivers content without modern defense-in-depth response headers that instruct browsers on how to strictly sandbox scripts, frame resources, and prevent protocol downgrade.',
      whyItMatters: 'Without Content-Security-Policy and HSTS, attackers can inject rogue scripts or intercept network requests. Without X-Frame-Options, adversaries can embed your site inside malicious iframes to hijack clicks.',
      howToFix: 'Implement defense-in-depth headers at the edge reverse proxy (such as Nginx) or via standard security middleware (Helmet for Express). Ensure Server version tokens are obscured from responses.',
      remediation: [
        'Deploy Content-Security-Policy (CSP) restricting script sources to self and trusted CDNs',
        'Enable Strict-Transport-Security (HSTS) with a 31536000 second max-age and includeSubDomains',
        'Add X-Content-Type-Options: nosniff to stop MIME-type confusion',
        'Configure X-Frame-Options: DENY or SAMEORIGIN to prevent framing',
        'Remove or sanitize the "Server" response banner to reduce target fingerprinting'
      ]
    },
    results: [
      // 1. Triggered: CSP (SEC-HDR-001)
      {
        rule: {
          id: 'SEC-HDR-001',
          category: 'headers',
          severity: 'high',
          explain: 'Content-Security-Policy (CSP) header is missing from the HTTP response.',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"]\n  }\n}));`,
            nginx: `add_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;`,
            django: `CSP_DEFAULT_SRC = ("'self'",)\nCSP_SCRIPT_SRC = ("'self'",)`,
            flask: `from flask_talisman import Talisman\nTalisman(app, content_security_policy={"default-src": "'self'"})`
          }
        },
        triggered: true
      },
      // 2. Triggered: HSTS (SEC-HDR-002)
      {
        rule: {
          id: 'SEC-HDR-002',
          category: 'headers',
          severity: 'high',
          explain: 'Strict-Transport-Security (HSTS) header is missing or enforces less than 6 months max-age.',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`,
            nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
            django: `SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True`,
            flask: `Talisman(app, force_https=True, strict_transport_security=True)`
          }
        },
        triggered: true
      },
      // 3. Triggered: X-Frame-Options (SEC-HDR-003)
      {
        rule: {
          id: 'SEC-HDR-003',
          category: 'headers',
          severity: 'medium',
          explain: 'X-Frame-Options header is absent, allowing framing by external sites (Clickjacking risk).',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.use(helmet.frameguard({ action: 'deny' }));`,
            nginx: `add_header X-Frame-Options "DENY" always;`,
            django: `X_FRAME_OPTIONS = 'DENY'`,
            flask: `Talisman(app, frame_options='DENY')`
          }
        },
        triggered: true
      },
      // 4. Triggered: X-Content-Type-Options (SEC-HDR-004)
      {
        rule: {
          id: 'SEC-HDR-004',
          category: 'headers',
          severity: 'medium',
          explain: 'X-Content-Type-Options: nosniff header is missing, permitting browser MIME-sniffing.',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.use(helmet.noSniff());`,
            nginx: `add_header X-Content-Type-Options "nosniff" always;`,
            django: `SECURE_CONTENT_TYPE_NOSNIFF = True`,
            flask: `Talisman(app, content_security_policy_report_only=False)`
          }
        },
        triggered: true
      },
      // 5. Triggered: Server Banner Exposure (SEC-EXP-001)
      {
        rule: {
          id: 'SEC-EXP-001',
          category: 'exposure',
          severity: 'low',
          explain: 'Server header reveals detailed software version tokens (e.g. Apache/2.4.41).',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.disable('x-powered-by');`,
            nginx: `server_tokens off;`,
            django: `# Handled at reverse proxy (e.g. Nginx server_tokens off;)`,
            flask: `# Handled at WSGI server (e.g. Gunicorn --no-send-header)`
          }
        },
        triggered: true
      },
      // 6. Triggered: Referrer Policy (SEC-PRV-001)
      {
        rule: {
          id: 'SEC-PRV-001',
          category: 'privacy',
          severity: 'low',
          explain: 'Referrer-Policy header not configured, potentially exposing internal URL query strings.',
          owasp: 'A05:2021-Security Misconfiguration',
          fixes: {
            express: `app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`,
            nginx: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
            django: `SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'`,
            flask: `Talisman(app, referrer_policy='strict-origin-when-cross-origin')`
          }
        },
        triggered: true
      },
      // 7. Passed: TLS Certificate Valid (SEC-TLS-001)
      {
        rule: {
          id: 'SEC-TLS-001',
          category: 'tls',
          severity: 'high',
          explain: 'TLS Certificate is cryptographically valid and signed by a recognized Certificate Authority.',
          owasp: 'A02:2021-Cryptographic Failures',
          fixes: {}
        },
        triggered: false
      },
      // 8. Passed: Sensitive Git Exposure (SEC-EXP-002)
      {
        rule: {
          id: 'SEC-EXP-002',
          category: 'exposure',
          severity: 'high',
          explain: 'Git repository directory (/.git/HEAD) is not publicly accessible (returns 404).',
          owasp: 'A01:2021-Broken Access Control',
          fixes: {}
        },
        triggered: false
      }
    ]
  };

  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.MOCK_SCAN_DATA = MOCK_SCAN_DATA;

})(window);
