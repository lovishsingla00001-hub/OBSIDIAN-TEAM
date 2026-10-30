/**
 * @fileoverview HTML Content & Markup Security Rules for SiteCheck.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * DOMAIN: Markup Analysis, Insecure Actions & Information Disclosure
 */

/**
 * Fast, non-backtracking checks for meaningful application debug disclosures.
 * Excludes benign developer comments like TODO, FIXME, or design notes.
 *
 * @param {string} html
 * @returns {boolean}
 */
function hasMeaningfulDebugDisclosure(html) {
  if (typeof html !== 'string' || html.length === 0) {
    return false;
  }

  // 1. Common framework debug error pages & stack traces
  if (html.includes('Traceback (most recent call last):')) {
    return true; // Python / Django / Flask
  }
  if (html.includes('Fatal error: Uncaught ') || html.includes('Stack trace:\n#0')) {
    return true; // PHP fatal errors
  }
  if (html.includes('Action Controller: Exception caught') || html.includes('ActiveRecord::RecordNotFound')) {
    return true; // Ruby on Rails
  }
  if (html.includes('DEBUG = True') && (html.includes('Django Version') || html.includes('Request Method:'))) {
    return true; // Django debug page
  }
  if (html.includes('Whitelabel Error Page') && html.includes('There was an unexpected error (type=')) {
    return true; // Spring Boot default error page
  }

  // 2. V8 / Node.js stack traces: "    at Object.<anonymous> (/app/server.js:42:15)"
  if (/\s+at (?:async\s+)?[a-zA-Z0-9_$.<>]+\s+\([^)]+:\d+:\d+\)/.test(html)) {
    return true;
  }

  // 3. Java stack traces: "    at org.springframework.web.servlet..."
  if (/\s+at [a-zA-Z0-9_$.]+\([^)]+\.java:\d+\)/.test(html)) {
    return true;
  }

  // 4. Exposed secrets/tokens in HTML comments (excluding generic placeholders or TODOs)
  // Safely find comments using bounded regex without exponential backtracking
  const comments = html.match(/<!--[\s\S]*?-->/g);
  if (comments) {
    const secretPattern = /(?:api[_-]?key|aws_secret_access_key|password|bearer\s*token|jwt_secret)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{16,}['"]?/i;
    for (const comment of comments) {
      if (secretPattern.test(comment)) {
        return true;
      }
    }
  }

  return false;
}

/** @type {import('../core/types').Rule[]} */
const htmlRules = [
  {
    id: 'SEC-HTML-INSECURE-FORM',
    category: 'html',
    severity: 'medium',
    check: (ctx) => {
      if (!ctx.html || typeof ctx.html !== 'string') {
        return false;
      }
      // Matches <form ... action="http://..." ...>
      // Safe, non-backtracking regex bounded by >
      return /<form\b[^>]*?\baction\s*=\s*["']http:\/\//i.test(ctx.html);
    },
    explain: 'HTML form submits data over unencrypted HTTP (action="http://..."), allowing attackers to intercept submitted credentials or personal data.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      express: '# Update form action attributes to use HTTPS or relative paths (e.g. action="/login")',
      nginx: '# Ensure all form endpoints enforce HTTPS redirection',
      django: '# Use relative action URLs or ensure url tags generate https:// URLs',
      flask: '# Use url_for("endpoint", _external=True, _scheme="https")',
    },
  },
  {
    id: 'SEC-HTML-DEBUG-DISCLOSURE',
    category: 'html',
    severity: 'low',
    check: (ctx) => {
      if (!ctx.html || typeof ctx.html !== 'string') {
        return false;
      }
      return hasMeaningfulDebugDisclosure(ctx.html);
    },
    explain: 'HTML response contains meaningful debug information, application stack traces, or credentials in comments.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: 'app.use((err, req, res, next) => res.status(500).send("Internal Server Error")); // Ensure NODE_ENV=production',
      nginx: 'fastcgi_param PHP_VALUE "display_errors=Off";',
      django: 'DEBUG = False # In production settings.py',
      flask: 'app.config["DEBUG"] = False # In production configuration',
    },
  },
];

module.exports = htmlRules;
