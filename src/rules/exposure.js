/**
 * @fileoverview Sensitive File & Well-Known Path Exposure Rules for SiteCheck.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * DOMAIN: Sensitive Path Exposure & Access Control
 */

/** @type {import('../core/types').Rule[]} */
const exposureRules = [
  {
    id: 'SEC-EXPOSURE-GIT',
    category: 'exposure',
    severity: 'high',
    check: (ctx) => {
      // Check status code only; zero response body is retained
      return Boolean(
        ctx.wellKnownPaths &&
        ctx.wellKnownPaths['/.git/HEAD'] &&
        ctx.wellKnownPaths['/.git/HEAD'].status === 200
      );
    },
    explain: 'Git repository metadata (/.git/HEAD) is publicly accessible, allowing attackers to download entire source code histories.',
    owasp: 'A01:2021-Broken Access Control',
    fixes: {
      express: '# Ensure .git directory is excluded from static file serving',
      nginx: 'location ~ /\\.git {\n  deny all;\n  return 404;\n}',
      django: '# Ensure web server blocks dotfile access in static root',
      flask: '# Ensure static folder does not map to repository root',
    },
  },
  {
    id: 'SEC-EXPOSURE-ENV',
    category: 'exposure',
    severity: 'high',
    check: (ctx) => {
      // Check status code only; zero response body is retained
      return Boolean(
        ctx.wellKnownPaths &&
        ctx.wellKnownPaths['/.env'] &&
        ctx.wellKnownPaths['/.env'].status === 200
      );
    },
    explain: 'Environment configuration file (/.env) is publicly accessible, exposing critical secrets, database credentials, and API keys.',
    owasp: 'A01:2021-Broken Access Control',
    fixes: {
      express: '# Store .env outside public root or block via web server',
      nginx: 'location ~ /\\.env {\n  deny all;\n  return 404;\n}',
      django: '# Keep .env outside static and media directories',
      flask: '# Keep .env outside static directory',
    },
  },
  {
    id: 'SEC-INFO-ROBOTS',
    category: 'exposure',
    severity: 'low',
    informational: true, // Informational note: does not deduct security penalties
    check: (ctx) => {
      // Triggers informational note only when robots.txt returns 404
      return Boolean(
        ctx.wellKnownPaths &&
        ctx.wellKnownPaths['/robots.txt'] &&
        ctx.wellKnownPaths['/robots.txt'].status === 404
      );
    },
    explain: 'Informational: No robots.txt file was found (status 404). This is not a security flaw, but search engine crawlers will have no domain-specific guidance.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      nginx: '# Create /robots.txt with User-agent: * and Disallow: rules for sensitive paths',
    },
  },
];

module.exports = exposureRules;
