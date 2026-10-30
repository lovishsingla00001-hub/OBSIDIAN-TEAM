/**
 * SiteCheck Security Rule: exposed-env
 *
 * Detects whether environment configuration files (such as /.env) are publicly accessible.
 * Application developers often store sensitive secrets, API keys, database passwords, and
 * encryption salts in .env files. If these files are exposed to the web, unauthorized users
 * can download them and gain complete unauthorized access to backend systems.
 *
 * ABSOLUTE SECURITY BOUNDARY:
 * - Read-only inspection using solely signals supplied by ctx.wellKnownPaths.
 * - Does NOT perform active HTTP requests, file downloads, or credential harvesting.
 */

export default {
  id: "exposed-env",

  category: "exposure",

  severity: "high",

  /**
   * Evaluates whether .env configuration files are publicly accessible.
   *
   * @param {Object} ctx - The frozen context object.
   * @returns {boolean} true if .env files are publicly accessible, false otherwise.
   */
  check(ctx) {
    if (!ctx || !ctx.wellKnownPaths || typeof ctx.wellKnownPaths !== "object") {
      return false;
    }

    // Standard .env probe paths
    const envPaths = [
      "/.env",
      "/.env.local",
      "/.env.production",
      "/.env.development",
      "/.env.backup"
    ];

    for (const path of envPaths) {
      const entry = ctx.wellKnownPaths[path];
      if (entry && typeof entry === "object") {
        // A 2xx status code indicates the file is publicly exposed and readable
        if (typeof entry.status === "number" && entry.status >= 200 && entry.status < 300) {
          return true;
        }
      }
    }

    // Check any dynamic path in wellKnownPaths matching .env patterns
    for (const [path, entry] of Object.entries(ctx.wellKnownPaths)) {
      if (path.includes("/.env") && entry && typeof entry === "object") {
        if (typeof entry.status === "number" && entry.status >= 200 && entry.status < 300) {
          return true;
        }
      }
    }

    return false;
  },

  explain:
    "Environment files (like .env) contain private application configurations, including database credentials, third-party API secret keys, token signing keys, and administrative passwords. If a web server serves this file publicly, malicious actors can extract these secrets and compromise your entire infrastructure.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: `// Express.js remediation: Prevent serving hidden files and keep secrets out of public directories
// 1. Never place .env files inside public/ or static asset directories.
// 2. Configure express.static with dotfiles: 'deny':
const express = require('express');
const app = express();

app.use(express.static('public', {
  dotfiles: 'deny' // Returns 403 Forbidden for requests like /.env
}));`,

    nginx: `# Nginx remediation: Deny access to .env and all hidden files
# Add this rule inside your server {} configuration block:
location ~ /\\.env {
    deny all;
    access_log off;
    log_not_found off;
    return 404; # Return 404 to avoid disclosing the file's existence
}`,

    django: `# Django remediation:
# 1. Keep your .env file in the repository root or outside the project, never in STATIC_ROOT.
# 2. In production, configure your web server (Nginx/Apache) to deny dotfiles:
#    location ~ /\\.env { deny all; }`,

    flask: `# Flask remediation:
# 1. Store .env outside your static/ templates folders.
# 2. Block requests targeting dotfiles:
from flask import abort, request

@app.before_request
def block_env_files():
    if '/.env' in request.path or '/.' in request.path:
        abort(404)`
  }
};

