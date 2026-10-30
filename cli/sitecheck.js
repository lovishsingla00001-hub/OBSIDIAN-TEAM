#!/usr/bin/env node
/**
 * SiteCheck - Command Line Interface (CLI)
 * Team: Obsidian
 * 
 * Usage:
 *   node cli/sitecheck.js <url>
 * 
 * Pipeline:
 *   1. Validate URL (HTTP/HTTPS only)
 *   2. Fetch website context via A's fetchSiteContext()
 *   3. Execute security rules via B's runRules()
 *   4. Attach PII counts via attachPIIToReport()
 *   5. Display readable terminal report
 *   6. Exit with code:
 *      - 0: Scan successful, no high-severity security findings
 *      - 1: Scan successful, at least one high-severity finding exists
 *      - 2: Operational failure (invalid input, network error, timeout)
 */

import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { attachPIIToReport } from '../src/core/integrateReport.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CommonJS loader cache
const cjsCache = new Map();

/**
 * Loads CommonJS modules reliably within Node's ES module environment
 * without requiring changes to teammate files.
 *
 * @param {string} filePath - Absolute or relative path to the CommonJS file.
 * @returns {any} Exported module content.
 */
export function loadCommonJs(filePath) {
  let resolved = path.resolve(__dirname, filePath);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
    resolved = path.join(resolved, 'index.js');
  } else if (!fs.existsSync(resolved) && fs.existsSync(resolved + '.js')) {
    resolved = resolved + '.js';
  }

  if (cjsCache.has(resolved)) {
    return cjsCache.get(resolved);
  }

  const code = fs.readFileSync(resolved, 'utf8');
  const moduleObj = { exports: {} };
  cjsCache.set(resolved, moduleObj.exports);

  function customRequire(id) {
    if (id.startsWith('.')) {
      const targetDir = path.dirname(resolved);
      let targetPath = path.resolve(targetDir, id);
      if (fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory()) {
        targetPath = path.join(targetPath, 'index.js');
      } else if (!fs.existsSync(targetPath) && fs.existsSync(targetPath + '.js')) {
        targetPath = targetPath + '.js';
      }
      return loadCommonJs(targetPath);
    }
    const nativeRequire = createRequire(resolved);
    return nativeRequire(id);
  }

  const wrapper = vm.compileFunction(
    code,
    ['exports', 'require', 'module', '__filename', '__dirname'],
    { filename: resolved }
  );

  wrapper(moduleObj.exports, customRequire, moduleObj, resolved, path.dirname(resolved));
  cjsCache.set(resolved, moduleObj.exports);
  return moduleObj.exports;
}

// Load Teammates' CommonJS Modules
const fetchSiteModule = loadCommonJs('../server/fetchSite.js');
const engineModule = loadCommonJs('../src/core/engine.js');

const fetchSiteContext = fetchSiteModule.fetchSiteContext;
const runRules = engineModule.runRules;
const defaultRules = engineModule.defaultRules || engineModule.allRules || [];

/**
 * Validates the raw user-supplied URL.
 * 
 * @param {string} rawUrl - Command line argument.
 * @returns {string} Normalized URL string.
 * @throws {Error} If URL is missing, malformed, or uses a non-HTTP/HTTPS protocol.
 */
export function validateCliUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new Error('Missing URL argument.\nUsage: node cli/sitecheck.js <url>');
  }

  const trimmed = rawUrl.trim();
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    // If user provided a bare domain like 'example.com', parse with https://
    try {
      parsed = new URL(`https://${trimmed}`);
    } catch {
      throw new Error(`Invalid URL '${trimmed}': Malformed URL format.`);
    }
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported protocol '${parsed.protocol}'. Only HTTP and HTTPS are permitted.`);
  }

  return parsed.href;
}

/**
 * Formats and prints the scan results to the terminal.
 * Never prints raw personal information.
 * 
 * @param {object} finalReport - The completed report with security & PII data.
 * @param {string} targetUrl - The target URL scanned.
 */
export function printReport(finalReport, targetUrl) {
  const divider = '='.repeat(60);
  const subDivider = '-'.repeat(60);

  console.log(`\n${divider}`);
  console.log('                 SITECHECK AUDIT REPORT');
  console.log(`${divider}`);
  console.log(`Target URL:      ${targetUrl}`);
  console.log(`Final URL:       ${finalReport.url || targetUrl}`);
  console.log(`Timestamp:       ${new Date().toISOString()}`);

  // 1. Overall Security Score & Severity Counts
  const overallScore = (finalReport.score && typeof finalReport.score.overall === 'number')
    ? finalReport.score.overall
    : 'N/A';
  const summary = finalReport.summary || { high: 0, medium: 0, low: 0 };

  console.log(`\nOverall Score:   ${overallScore} / 100`);
  console.log(`Findings Summary: [High: ${summary.high || 0}]  [Medium: ${summary.medium || 0}]  [Low: ${summary.low || 0}]`);
  console.log(subDivider);

  // 2. Security Findings Details
  console.log('SECURITY FINDINGS:');
  const findings = Array.isArray(finalReport.results) ? finalReport.results : [];
  const triggeredFindings = findings.filter(f => f.triggered);

  if (triggeredFindings.length === 0) {
    console.log('  [PASS] No security vulnerabilities detected.');
  } else {
    for (const item of triggeredFindings) {
      const rule = item.rule || {};
      const severityTag = (rule.severity || 'UNKNOWN').toUpperCase().padEnd(6);
      console.log(`  [${severityTag}] ${rule.id || 'Unknown Rule'}`);
      if (rule.explain) {
        console.log(`           Explanation: ${rule.explain}`);
      }
      if (rule.owasp) {
        console.log(`           OWASP Ref:   ${rule.owasp}`);
      }
    }
  }
  console.log(subDivider);

  // 3. Privacy & PII Findings (Counts only — Never expose raw PII)
  console.log('PII EXPOSURE AUDIT:');
  const piiCategories = Array.isArray(finalReport.pii) ? finalReport.pii : [];

  if (piiCategories.length === 0) {
    console.log('  [PASS] No exposed phone numbers, email addresses, or Aadhaar-like numbers found.');
  } else {
    for (const item of piiCategories) {
      const typeLabel = item.type === 'aadhaar-like'
        ? 'Aadhaar-like (12-digit pattern only)'
        : item.type === 'phone'
        ? 'Indian Mobile Phone Number'
        : 'Email Address';
      console.log(`  [ALERT] ${typeLabel.padEnd(36)}: ${item.count} detected`);
    }
    console.log('  Notice: Pattern detection only; no raw personal information is stored or displayed.');
  }
  console.log(`${divider}\n`);
}

/**
 * Orchestrates the full scan pipeline.
 *
 * @param {string} rawUrl - Command line URL argument.
 * @param {object} [injectedDeps] - Optional injected dependencies for unit testing.
 * @returns {Promise<{ exitCode: number, report: object }>}
 */
export async function runCliScan(rawUrl, injectedDeps = {}) {
  const fetchFn = injectedDeps.fetchSiteContext || fetchSiteContext;
  const rulesFn = injectedDeps.runRules || runRules;
  const rulesList = injectedDeps.rules || defaultRules;
  const attachFn = injectedDeps.attachPIIToReport || attachPIIToReport;

  // 1. Validate Input URL
  const validUrl = validateCliUrl(rawUrl);

  // 2. Fetch Website Context
  let ctx;
  try {
    ctx = await fetchFn(validUrl);
  } catch (err) {
    throw new Error(`Fetch failure for '${validUrl}': ${err.message}`);
  }

  if (!ctx || typeof ctx !== 'object') {
    throw new Error(`Fetch failed: Empty context received for '${validUrl}'.`);
  }

  // 3. Execute Security Rules
  const baseReport = rulesFn(ctx, rulesList);

  // 4. Attach PII Detections to Report
  const finalReport = attachFn(baseReport, ctx.html || '');
  finalReport.url = validUrl;

  // 5. Determine Exit Code
  // Contract: Exit 1 if at least one high-severity finding exists; Exit 0 otherwise.
  const hasHighSeverity = Boolean(finalReport.summary && finalReport.summary.high > 0);
  const exitCode = hasHighSeverity ? 1 : 0;

  return { exitCode, report: finalReport };
}

// Direct CLI Invocation
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const targetArg = process.argv[2];

  runCliScan(targetArg)
    .then(({ exitCode, report }) => {
      printReport(report, targetArg);
      process.exit(exitCode);
    })
    .catch((err) => {
      console.error(`\n[ERROR] Operational Failure: ${err.message}\n`);
      process.exit(2);
    });
}
