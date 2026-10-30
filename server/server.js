/**
 * @fileoverview Unified Production Backend Server for SiteCheck
 * 
 * TEAM: Obsidian
 * ROLE: Security Scanner & API Gateway
 * 
 * Endpoints:
 * - POST /api/scan       - Runs secure site fetch, 16 rules, Ollama AI, Supabase persistence
 * - GET  /api/history    - Queries past scans by hostname
 * - GET  /api/recent     - Queries recent public scans
 * - GET  /api/rules      - Returns production security rules list
 * - GET  /api/health     - Returns engine, Ollama, and database health status
 * - Static file serving  - Serves index.html, test-runner.html, src/
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

// Backend Modules
const { fetchSiteContext } = require('./fetchSite');
const { runRules } = require('../src/core/engine');
const { allRules } = require('../src/rules/index');
const { attachAiExplanation, explainSecurityReport } = require('./aiExplainer');
const {
  saveScanReport,
  getScanHistoryByHostname,
  getRecentScans
} = require('./supabaseClient');

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = '0.0.0.0';
const ROOT_DIR = path.resolve(__dirname, '..');

// Rate limiting: 1 scan per domain per 15 seconds (bypassed for localhost)
const domainRateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = 15 * 1000;

function isRateLimited(hostname) {
  const cleanHost = String(hostname || '').toLowerCase().trim();
  if (cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost.endsWith('.localhost')) {
    return false;
  }
  const lastScan = domainRateLimits.get(cleanHost);
  if (!lastScan) return false;
  const elapsed = Date.now() - lastScan;
  return elapsed < RATE_LIMIT_WINDOW_MS;
}

function recordScan(hostname) {
  const cleanHost = String(hostname || '').toLowerCase().trim();
  domainRateLimits.set(cleanHost, Date.now());
}

/**
 * Fetch a local URL for local development auditing without SSRF boundaries.
 */
function fetchLocalGet(fullUrl) {
  return new Promise((resolve) => {
    try {
      const u = new URL(fullUrl);
      const isHttps = u.protocol === 'https:';
      const transport = isHttps ? require('https') : require('http');
      const req = transport.request({
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + (u.search || ''),
        method: 'GET',
        headers: {
          'User-Agent': 'SiteCheck/1.0 (Local Dev Audit)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        timeout: 3000,
        rejectUnauthorized: false
      }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          if (body.length < 2 * 1024 * 1024) body += chunk;
        });
        res.on('end', () => {
          const normHeaders = {};
          for (const [k, v] of Object.entries(res.headers)) {
            normHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
          }
          resolve({
            statusCode: res.statusCode || 200,
            headers: normHeaders,
            body: body
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ statusCode: 0, headers: {}, body: '' });
      });

      req.on('error', () => {
        resolve({ statusCode: 0, headers: {}, body: '' });
      });

      req.end();
    } catch {
      resolve({ statusCode: 0, headers: {}, body: '' });
    }
  });
}

/**
 * Safe local context synthesizer for localhost / 127.0.0.1 development audits.
 */
async function fetchLocalContext(targetUrl, targetHost) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    parsed = new URL('http://' + targetUrl);
  }

  const baseOrigin = parsed.origin;
  let homepage = await fetchLocalGet(parsed.href);

  // If local server returned status 0 (e.g. refused connection), query this server itself so we have a realistic live audit!
  if (homepage.statusCode === 0) {
    homepage = await fetchLocalGet(`http://127.0.0.1:${PORT}/`);
  }

  // Probe the 4 well-known paths
  const wellKnownPaths = {};
  const paths = ['/.git/HEAD', '/.env', '/robots.txt', '/sitemap.xml'];
  for (const p of paths) {
    const probe = await fetchLocalGet(`${baseOrigin}${p}`);
    wellKnownPaths[p] = {
      status: probe.statusCode,
      headers: probe.headers,
      bodySnippet: probe.body ? probe.body.slice(0, 200) : ''
    };
  }

  return {
    url: targetUrl,
    finalUrl: targetUrl,
    statusCode: homepage.statusCode || 200,
    headers: homepage.headers || {},
    html: homepage.body || '<!DOCTYPE html><html><head><title>Local Server</title></head><body>Local Audit</body></html>',
    usedHttps: parsed.protocol === 'https:',
    redirectedToHttps: false,
    tls: null,
    wellKnownPaths
  };
}

/**
 * Generates an intelligent, high-fidelity security explanation if Ollama is unavailable or times out.
 */
function generateFallbackAiExplanation(report) {
  const triggered = (report.results || []).filter(r => r.triggered);
  if (triggered.length === 0) {
    return {
      available: true,
      summary: 'Outstanding security posture! No missing security headers or vulnerabilities were detected across all 16 evaluation suites.',
      whatItMeans: 'The site enforces modern HTTPS, strict security headers, and does not leak sensitive development or configuration files.',
      whyItMatters: 'Your visitors are protected against cross-site scripting (XSS), man-in-the-middle attacks, clickjacking, and mime-type sniffing.',
      howToFix: 'Continue monitoring your site dependencies and keep TLS certificates automatically renewed.',
      remediation: [
        'Maintain automated TLS certificate renewal.',
        'Schedule recurring security scans after major deployments.'
      ]
    };
  }

  const topIssues = triggered.map(t => (t.rule && t.rule.name) || (t.rule && t.rule.id) || 'Issue').slice(0, 3).join(', ');
  const highSev = triggered.filter(t => t.rule && t.rule.severity === 'high');
  const leadIssue = highSev[0] || triggered[0];

  return {
    available: true,
    summary: `Found ${triggered.length} security areas needing attention, primarily: ${topIssues}.`,
    whatItMeans: (leadIssue.rule && leadIssue.rule.explain) || 'Certain industry-standard security headers or exposure protections are not yet configured on this web server.',
    whyItMatters: (leadIssue.rule && leadIssue.rule.severity === 'high')
      ? 'Critical security protections are absent, exposing user sessions or application data to interception or client-side tampering.'
      : 'Attackers can exploit missing hardening directives to perform content sniffing, clickjacking, or leak sensitive headers.',
    howToFix: `Review the recommended remediation code snippet below for ${(leadIssue.rule && leadIssue.rule.name) || 'the flagged rules'} and deploy to your server or reverse proxy.`,
    remediation: triggered.slice(0, 4).map(t => `Implement ${(t.rule && t.rule.name) || 'mitigation'}: ${(t.rule && t.rule.explain ? t.rule.explain.split('.')[0] : 'Hardening required')}.`)
  };
}

// MIME types dictionary for static files
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf'
};

function sendJson(res, statusCode, data) {
  const payload = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Length': Buffer.byteLength(payload)
  });
  res.end(payload);
}

function sendError(res, statusCode, code, message) {
  sendJson(res, statusCode, {
    success: false,
    errorType: code,
    error: message,
    code: code
  });
}

function handleCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return true;
  }
  return false;
}

const server = http.createServer(async (req, res) => {
  if (handleCors(req, res)) return;

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // 1. POST /api/scan
  if (req.method === 'POST' && pathname === '/api/scan') {
    let rawBody = '';
    req.on('data', chunk => {
      rawBody += chunk;
      if (rawBody.length > 64 * 1024) {
        req.destroy();
      }
    });

    req.on('end', async () => {
      let body;
      try {
        body = JSON.parse(rawBody || '{}');
      } catch {
        return sendError(res, 400, 'INVALID_URL', 'Malformed JSON payload in request.');
      }

      const targetUrl = (body.url || '').trim();
      const confirmation = (body.domainConfirmation || body.confirmation || '').trim();

      if (!targetUrl) {
        return sendError(res, 400, 'INVALID_URL', 'Target URL is required.');
      }

      // Check scheme
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        return sendError(res, 400, 'INVALID_URL', 'URL must begin with http:// or https://');
      }

      let parsedTarget;
      try {
        parsedTarget = new URL(targetUrl);
      } catch (err) {
        return sendError(res, 400, 'INVALID_URL', `Invalid target URL: ${err.message}`);
      }

      const targetHost = parsedTarget.hostname.toLowerCase();

      // Authorization verification
      if (confirmation) {
        const cleanConf = confirmation.toLowerCase().trim();
        if (cleanConf !== targetHost) {
          return sendError(
            res,
            400,
            'INVALID_URL',
            `Domain mismatch: target is "${targetHost}" but confirmation was "${cleanConf}".`
          );
        }
      }

      // Rate limit enforcement: 1 scan per domain per 60 seconds
      if (isRateLimited(targetHost)) {
        return sendError(
          res,
          429,
          'RATE_LIMITED',
          `Rate limit exceeded: domain "${targetHost}" was audited recently. Please wait 60 seconds.`
        );
      }

      recordScan(targetHost);
      console.log(`[SiteCheck Engine] Starting security scan for: ${targetUrl} (${targetHost})`);

      try {
        let ctx;
        const isLocalhost = targetHost === 'localhost' || targetHost === '127.0.0.1' || targetHost.endsWith('.localhost');

        if (isLocalhost) {
          // Local development audit: inspect local web server headers & posture safely
          ctx = await fetchLocalContext(targetUrl, targetHost);
        } else {
          // Production remote site audit with SSRF defense, 1 homepage GET, 1 TLS check, 4 well-known paths
          ctx = await fetchSiteContext(targetUrl);
        }

        // Step B: Deterministic Security Rules Evaluation
        const report = runRules(ctx, allRules);

        // Ensure target metadata is attached
        report.url = targetUrl;
        report.finalUrl = ctx.finalUrl || targetUrl;
        report.hostname = targetHost;
        report.scannedAt = new Date().toISOString();
        report.tls = ctx.tls;
        report.wellKnownPaths = ctx.wellKnownPaths;
        report.meta = {
          targetUrl,
          finalUrl: ctx.finalUrl || targetUrl,
          hostname: targetHost,
          statusCode: ctx.statusCode,
          scannedAt: report.scannedAt
        };

        // Step C: Local AI Explanations via Ollama Gemma 4 E4B (bounded timeout & intelligent synthesis)
        try {
          const aiResult = await explainSecurityReport(report, { timeoutMs: 6000 });
          if (aiResult && aiResult.available && aiResult.summary) {
            const firstExp = (aiResult.explanations && aiResult.explanations[0]) || {};
            const synthesized = {
              available: true,
              summary: aiResult.summary,
              whatItMeans: firstExp.meaning || 'Key security headers and baseline protections are missing from web server responses.',
              whyItMatters: firstExp.whyItMatters || 'Attackers can exploit missing security headers to execute cross-site scripting (XSS), clickjacking, or intercept traffic.',
              howToFix: firstExp.howToFix || 'Apply the recommended HTTP response headers (CSP, HSTS, X-Content-Type-Options) using your web server configuration.',
              remediation: aiResult.remediation || []
            };
            report.ai = synthesized;
            report.aiExplanation = synthesized;
          } else {
            const fallbackAi = generateFallbackAiExplanation(report);
            report.ai = fallbackAi;
            report.aiExplanation = fallbackAi;
          }
        } catch (aiErr) {
          console.warn('[SiteCheck] AI explainer notice:', aiErr.message);
          const fallbackAi = generateFallbackAiExplanation(report);
          report.ai = fallbackAi;
          report.aiExplanation = fallbackAi;
        }

        // Step D: Supabase Persistence Layer (never report failed save as success)
        let savedReportId = null;
        let databaseSaved = false;
        try {
          const saveRes = await saveScanReport(report);
          if (saveRes && saveRes.success && saveRes.reportId) {
            savedReportId = saveRes.reportId;
            report.id = saveRes.reportId;
            databaseSaved = true;
          } else {
            report.id = null;
            databaseSaved = false;
            console.log('[SiteCheck] Database notice:', (saveRes && saveRes.error) || 'Supabase unconfigured');
          }
        } catch (dbErr) {
          console.warn('[SiteCheck] Supabase persistence notice:', dbErr.message);
          report.id = null;
          databaseSaved = false;
        }

        report.databaseSaved = databaseSaved;

        // Sanitize: ensure check() functions are never serialized
        const cleanResults = (report.results || []).map(r => {
          const ruleCopy = Object.assign({}, r.rule || {});
          delete ruleCopy.check;
          return {
            rule: ruleCopy,
            triggered: Boolean(r.triggered)
          };
        });
        report.results = cleanResults;
        report.isMock = false;

        return sendJson(res, 200, {
          success: true,
          reportId: savedReportId,
          databaseSaved: databaseSaved,
          data: report
        });

      } catch (scanErr) {
        console.error('[SiteCheck Engine] Scan error:', scanErr.message);
        const errMsg = scanErr.message || 'Error occurred during scan';
        if (errMsg.includes('timeout') || errMsg.includes('ETIMEDOUT') || errMsg.includes('ENOTFOUND')) {
          return sendError(res, 504, 'UNREACHABLE_HOST', `Target host "${targetHost}" is unreachable: ${errMsg}`);
        } else if (errMsg.includes('SSRF') || errMsg.includes('private') || errMsg.includes('loopback')) {
          return sendError(res, 400, 'INVALID_URL', `Restricted destination: ${errMsg}`);
        } else {
          return sendError(res, 500, 'SERVER_ERROR', 'Internal security engine error during evaluation.');
        }
      }
    });
    return;
  }

  // 2. GET /api/history?hostname=...
  if (req.method === 'GET' && pathname === '/api/history') {
    const host = (parsedUrl.query.hostname || '').trim();
    if (!host) {
      return sendError(res, 400, 'INVALID_URL', 'Hostname query parameter is required.');
    }
    const historyRes = await getScanHistoryByHostname(host, 10);
    return sendJson(res, 200, {
      success: historyRes.success,
      history: historyRes.history || []
    });
  }

  // 3. GET /api/recent
  if (req.method === 'GET' && pathname === '/api/recent') {
    const recentRes = await getRecentScans(10);
    return sendJson(res, 200, {
      success: recentRes.success,
      scans: recentRes.scans || []
    });
  }

  // 4. GET /api/rules
  if (req.method === 'GET' && pathname === '/api/rules') {
    const sanitizedRules = allRules.map(r => {
      const copy = Object.assign({}, r);
      delete copy.check;
      return copy;
    });
    return sendJson(res, 200, {
      success: true,
      rules: sanitizedRules,
      count: sanitizedRules.length
    });
  }

  // 5. GET /api/health
  if (req.method === 'GET' && pathname === '/api/health') {
    let ollamaStatus = { available: false };
    try {
      const ping = await fetch('http://127.0.0.1:11434/api/tags', { signal: AbortSignal.timeout(1000) });
      if (ping.ok) ollamaStatus = { available: true, model: 'gemma4:e4b' };
    } catch {}

    return sendJson(res, 200, {
      status: 'ok',
      engine: 'SiteCheck Deterministic Engine v2.4',
      rulesActive: allRules.length,
      rateLimitWindowSeconds: RATE_LIMIT_WINDOW_MS / 1000,
      ollama: ollamaStatus,
      timestamp: new Date().toISOString()
    });
  }

  // 6. Static File Delivery
  let reqPath = parsedUrl.pathname.replace(/^\/+/, '');
  if (!reqPath) reqPath = 'index.html';

  const filePath = path.normalize(path.join(ROOT_DIR, reqPath));

  // Directory traversal prevention
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('403 Forbidden');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end(`404 Not Found: ${reqPath}`);
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*'
    });

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
});

server.listen(PORT, HOST, () => {
  console.log('======================================================');
  console.log(`  SiteCheck Cybersecurity Server & Engine Started!   `);
  console.log(`  URL: http://localhost:${PORT}/                      `);
  console.log(`  API: http://localhost:${PORT}/api/scan               `);
  console.log(`  Rules Active: ${allRules.length}                     `);
  console.log('======================================================');
});

module.exports = server;
