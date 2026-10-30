/**
 * SiteCheck Security Rule: exposed-git
 *
 * Detects whether Git metadata or repository files (such as /.git/HEAD) are publicly accessible.
 * If the .git folder is exposed to the web, malicious actors can download the entire source code,
 * commit history, branch information, and potentially hardcoded secrets or environment variables.
 *
 * ABSOLUTE SECURITY BOUNDARY:
 * - Read-only inspection using solely signals supplied by ctx.wellKnownPaths.
 * - Does NOT perform active HTTP requests, cloning, or traversal.
 * - Does NOT download source code, credentials, or private repository data.
 */

export default {
  id: "exposed-git",

  category: "exposure",

  severity: "high",

  /**
   * Evaluates whether Git repository endpoints are publicly exposed.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if Git metadata endpoints are publicly accessible, false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.wellKnownPaths || typeof ctx.wellKnownPaths !== "object") {
      return false;
    }

    // Standard Git probe paths present in wellKnownPaths
    const primaryGitPaths = ["/.git/HEAD", "/.git/config", "/.git/index"];

    for (const path of primaryGitPaths) {
      const entry = ctx.wellKnownPaths[path];
      if (entry && typeof entry === "object") {
        // A 2xx status code indicates the file is publicly exposed and readable
        if (typeof entry.status === "number" && entry.status >= 200 && entry.status < 300) {
          return true;
        }
      }
    }

    // Inspect any additional path in wellKnownPaths matching Git patterns
    for (const [path, entry] of Object.entries(ctx.wellKnownPaths)) {
      if (path.startsWith("/.git/") && entry && typeof entry === "object") {
        if (typeof entry.status === "number" && entry.status >= 200 && entry.status < 300) {
          return true;
        }
      }
    }

    return false;
  },

  explain:
    "The .git directory contains your application's complete version control metadata, source code history, commit logs, and potentially sensitive credentials or internal URLs. When publicly accessible over HTTP, attackers can reconstruct the full codebase and discover hardcoded secrets.",

  owasp: "A01:2021-Broken Access Control",

  fixes: {
    express: `// Express.js remediation: Block all requests to hidden/dot files
// When using express.static, configure the 'dotfiles' option to 'deny':
const express = require('express');
const app = express();

app.use(express.static('public', {
  dotfiles: 'deny' // Returns 403 Forbidden for any requests to dotfiles like /.git
}));`,

    nginx: `# Nginx remediation: Deny access to all hidden files and folders including .git
# Place this directive inside your server {} block:
location ~ /\\. {
    deny all;
    access_log off;
    log_not_found off;
    return 404; # Or 403 Forbidden
}`,

    django: `# Django remediation:
# 1. Ensure STATICFILES_DIRS and STATIC_ROOT strictly point to compiled static assets,
#    never the project root where .git resides.
# 2. In production, configure the upstream reverse proxy (Nginx/Apache) to deny dotfiles:
#    location ~ /\\.git { deny all; }`,

    flask: `# Flask remediation:
# Block any requests attempting to reach hidden files or directories:
from flask import abort, request

@app.before_request
def block_hidden_files():
    if '/.' in request.path:
        abort(404)`
  }
};

