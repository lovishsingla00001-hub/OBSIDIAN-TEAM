/**
 * @fileoverview Supabase Integration Client for SiteCheck
 * 
 * TEAM: Obsidian
 * ROLE: Engine & Persistence Layer
 * 
 * Provides automated, resilient persistence for SiteCheck security reports,
 * score history, and AI explanations into Supabase PostgreSQL.
 * 
 * Works seamlessly with:
 * 1. Native @supabase/supabase-js (if installed)
 * 2. Pure Node.js built-in fetch (zero-dependency PostgREST fallback)
 */

'use strict';

// Attempt to load optional @supabase/supabase-js without hard failing
let supabaseModule = null;
try {
  supabaseModule = require('@supabase/supabase-js');
} catch {
  supabaseModule = null;
}

/**
 * Default table name for scan reports.
 */
const TABLE_NAME = 'scan_reports';

let envLoaded = false;

/**
 * Automatically loads .env file once if environment variables are not already present.
 */
function loadEnvFile() {
  if (envLoaded) return;
  envLoaded = true;
  if (process.env.SUPABASE_URL) return;
  try {
    const fs = require('fs');
    const path = require('path');
    const candidates = [
      path.resolve(process.cwd(), '.env'),
      path.resolve(__dirname, '.env'),
      path.resolve(__dirname, '..', '.env'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8');
        for (const line of content.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const eq = trimmed.indexOf('=');
          if (eq !== -1) {
            const k = trimmed.substring(0, eq).trim();
            const v = trimmed.substring(eq + 1).trim();
            if (!process.env[k]) {
              process.env[k] = v;
            }
          }
        }
        break;
      }
    }
  } catch {
    // Fail silently if fs or path fails
  }
}

// Run environment loader once when module is required
loadEnvFile();

/**
 * Extracts Supabase configuration from environment variables.
 * @returns {{ url: string, key: string, isConfigured: boolean }}
 */
function getSupabaseConfig() {
  const url = (process.env.SUPABASE_URL || '').trim();
  const key = (
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    ''
  ).trim();

  const isConfigured = Boolean(
    url &&
    url.startsWith('https://') &&
    key &&
    key.length > 10 &&
    !url.includes('your-project-id')
  );

  return { url, key, isConfigured };
}

/**
 * Formats and sanitizes a complete audit report for database insertion.
 * 
 * @param {Object} scanData
 * @param {string} scanData.url - Scanned target URL.
 * @param {string} [scanData.finalUrl] - Final resolved URL after redirects.
 * @param {string} [scanData.hostname] - Target hostname.
 * @param {Object} scanData.score - Overall and category scores.
 * @param {Object} scanData.summary - Severity counts.
 * @param {Array} scanData.results - Sanitized rule findings.
 * @param {Object} [scanData.aiExplanation] - Optional local AI explanation narrative.
 * @param {Object} [scanData.metadata] - Optional additional audit metadata.
 * @returns {Object} Database row format.
 */
function formatReportRow(scanData) {
  if (!scanData || typeof scanData !== 'object') {
    throw new Error('Invalid scanData: payload must be a non-null object');
  }

  const rawUrl = scanData.url || scanData.finalUrl || '';
  let derivedHostname = scanData.hostname || '';

  if (!derivedHostname && rawUrl) {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
      derivedHostname = parsed.hostname;
    } catch {
      derivedHostname = rawUrl;
    }
  }

  const overallScore = typeof scanData.score?.overall === 'number'
    ? Math.max(0, Math.min(100, Math.round(scanData.score.overall)))
    : 0;

  const categoryScores = (scanData.score?.byCategory && typeof scanData.score.byCategory === 'object')
    ? scanData.score.byCategory
    : {};

  const summaryCounts = (scanData.summary && typeof scanData.summary === 'object')
    ? {
        high: Number(scanData.summary.high) || 0,
        medium: Number(scanData.summary.medium) || 0,
        low: Number(scanData.summary.low) || 0,
      }
    : { high: 0, medium: 0, low: 0 };

  // Sanitize findings: ensure rule.check function is never present in persisted JSON
  const rawFindings = Array.isArray(scanData.results) ? scanData.results : [];
  const sanitizedFindings = rawFindings.map((item) => {
    if (!item || typeof item !== 'object') return item;
    const ruleCopy = Object.assign({}, item.rule || {});
    delete ruleCopy.check; // Strip check function if accidentally attached

    return {
      rule: ruleCopy,
      triggered: Boolean(item.triggered),
    };
  });

  return {
    url: String(rawUrl),
    final_url: String(scanData.finalUrl || rawUrl),
    hostname: String(derivedHostname).toLowerCase(),
    score_overall: overallScore,
    score_by_category: categoryScores,
    summary_counts: summaryCounts,
    findings: sanitizedFindings,
    ai_explanation: scanData.aiExplanation || null,
    metadata: scanData.metadata || {},
    scanned_at: new Date().toISOString(),
  };
}

/**
 * Saves a security scan report to Supabase.
 * Fails safely: if Supabase is unconfigured or unavailable, returns a clean error
 * without interrupting or crashing the scanner application.
 * 
 * @param {Object} scanData - Complete scan report data.
 * @param {Object} [overrideConfig] - Optional explicit credentials or custom fetch.
 * @returns {Promise<{ success: boolean, reportId: string | null, error: string | null, mockSaved?: boolean }>}
 */
async function saveScanReport(scanData, overrideConfig = {}) {
  const config = Object.assign({}, getSupabaseConfig(), overrideConfig);
  const fetchFn = overrideConfig.fetch || globalThis.fetch;

  // 1. Format and validate data
  let row;
  try {
    row = formatReportRow(scanData);
  } catch (err) {
    return {
      success: false,
      reportId: null,
      error: `Validation error: ${err.message}`,
    };
  }

  // 2. Fallback if Supabase credentials are not configured
  if (!config.isConfigured && !overrideConfig.force) {
    return {
      success: false,
      reportId: null,
      error: 'SUPABASE_NOT_CONFIGURED: Missing valid SUPABASE_URL or SUPABASE_KEY in environment',
      mockSaved: true,
    };
  }

  // 3. Option A: Use @supabase/supabase-js client if available
  if (supabaseModule && !overrideConfig.preferRest) {
    try {
      const client = supabaseModule.createClient(config.url, config.key, {
        auth: { persistSession: false },
      });

      const { data, error } = await client
        .from(TABLE_NAME)
        .insert([row])
        .select('id')
        .single();

      if (error) {
        return {
          success: false,
          reportId: null,
          error: error.message || 'Supabase insertion error',
        };
      }

      return {
        success: true,
        reportId: data?.id || null,
        error: null,
      };
    } catch (err) {
      return {
        success: false,
        reportId: null,
        error: `Supabase client error: ${err.message}`,
      };
    }
  }

  // 4. Option B: Built-in Native fetch REST API (Zero-dependency fallback)
  if (typeof fetchFn !== 'function') {
    return {
      success: false,
      reportId: null,
      error: 'Native fetch is unavailable in this Node.js runtime.',
    };
  }

  try {
    const endpoint = `${config.url.replace(/\/+$/, '')}/rest/v1/${TABLE_NAME}`;
    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': config.key,
        'Authorization': `Bearer ${config.key}`,
        'Prefer': 'return=representation',
      },
      body: JSON.stringify(row),
    });

    if (!response.ok) {
      let errorText = '';
      try {
        const errorJson = await response.json();
        errorText = errorJson.message || errorJson.error || JSON.stringify(errorJson);
      } catch {
        errorText = await response.text();
      }
      return {
        success: false,
        reportId: null,
        error: `Supabase REST ${response.status}: ${errorText}`,
      };
    }

    const insertedRows = await response.json();
    const createdId = Array.isArray(insertedRows) && insertedRows.length > 0
      ? insertedRows[0].id
      : null;

    return {
      success: true,
      reportId: createdId,
      error: null,
    };
  } catch (err) {
    return {
      success: false,
      reportId: null,
      error: `Network error connecting to Supabase: ${err.message}`,
    };
  }
}

/**
 * Fetches a single scan report by its UUID.
 * 
 * @param {string} id - UUID of the scan report.
 * @param {Object} [overrideConfig] - Optional config or custom fetch.
 * @returns {Promise<{ success: boolean, report: Object | null, error: string | null }>}
 */
async function getScanReportById(id, overrideConfig = {}) {
  if (!id || typeof id !== 'string') {
    return { success: false, report: null, error: 'Invalid report ID' };
  }

  const config = Object.assign({}, getSupabaseConfig(), overrideConfig);
  const fetchFn = overrideConfig.fetch || globalThis.fetch;

  if (!config.isConfigured && !overrideConfig.force) {
    return {
      success: false,
      report: null,
      error: 'SUPABASE_NOT_CONFIGURED',
    };
  }

  try {
    const endpoint = `${config.url.replace(/\/+$/, '')}/rest/v1/${TABLE_NAME}?id=eq.${encodeURIComponent(id)}&select=*`;
    const response = await fetchFn(endpoint, {
      method: 'GET',
      headers: {
        'apikey': config.key,
        'Authorization': `Bearer ${config.key}`,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      return {
        success: false,
        report: null,
        error: `Supabase query error: HTTP ${response.status}`,
      };
    }

    const rows = await response.json();
    return {
      success: true,
      report: Array.isArray(rows) && rows.length > 0 ? rows[0] : null,
      error: null,
    };
  } catch (err) {
    return {
      success: false,
      report: null,
      error: err.message,
    };
  }
}

/**
 * Retrieves past audit scans for a specific hostname to display security posture trends.
 * 
 * @param {string} hostname - Target domain (e.g., 'example.com').
 * @param {number} [limit=10] - Maximum number of records to return.
 * @param {Object} [overrideConfig] - Optional config or custom fetch.
 * @returns {Promise<{ success: boolean, history: Array, error: string | null }>}
 */
async function getScanHistoryByHostname(hostname, limit = 10, overrideConfig = {}) {
  if (!hostname || typeof hostname !== 'string') {
    return { success: false, history: [], error: 'Invalid hostname' };
  }

  const config = Object.assign({}, getSupabaseConfig(), overrideConfig);
  const fetchFn = overrideConfig.fetch || globalThis.fetch;

  if (!config.isConfigured && !overrideConfig.force) {
    return { success: false, history: [], error: 'SUPABASE_NOT_CONFIGURED' };
  }

  try {
    const cleanHost = hostname.trim().toLowerCase();
    const endpoint = `${config.url.replace(/\/+$/, '')}/rest/v1/${TABLE_NAME}?hostname=eq.${encodeURIComponent(cleanHost)}&select=id,url,hostname,score_overall,summary_counts,scanned_at&order=scanned_at.desc&limit=${limit}`;

    const response = await fetchFn(endpoint, {
      method: 'GET',
      headers: {
        'apikey': config.key,
        'Authorization': `Bearer ${config.key}`,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      return { success: false, history: [], error: `HTTP ${response.status}` };
    }

    const rows = await response.json();
    return {
      success: true,
      history: Array.isArray(rows) ? rows : [],
      error: null,
    };
  } catch (err) {
    return { success: false, history: [], error: err.message };
  }
}

/**
 * Retrieves the most recent public scans across all domains.
 * Useful for community feed / recent audits widget on the landing page.
 * 
 * @param {number} [limit=10] - Number of recent audits to fetch.
 * @param {Object} [overrideConfig] - Optional config or custom fetch.
 * @returns {Promise<{ success: boolean, scans: Array, error: string | null }>}
 */
async function getRecentScans(limit = 10, overrideConfig = {}) {
  const config = Object.assign({}, getSupabaseConfig(), overrideConfig);
  const fetchFn = overrideConfig.fetch || globalThis.fetch;

  if (!config.isConfigured && !overrideConfig.force) {
    return { success: false, scans: [], error: 'SUPABASE_NOT_CONFIGURED' };
  }

  try {
    const endpoint = `${config.url.replace(/\/+$/, '')}/rest/v1/${TABLE_NAME}?select=id,hostname,score_overall,summary_counts,scanned_at&order=scanned_at.desc&limit=${limit}`;

    const response = await fetchFn(endpoint, {
      method: 'GET',
      headers: {
        'apikey': config.key,
        'Authorization': `Bearer ${config.key}`,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      return { success: false, scans: [], error: `HTTP ${response.status}` };
    }

    const rows = await response.json();
    return {
      success: true,
      scans: Array.isArray(rows) ? rows : [],
      error: null,
    };
  } catch (err) {
    return { success: false, scans: [], error: err.message };
  }
}

module.exports = {
  TABLE_NAME,
  getSupabaseConfig,
  formatReportRow,
  saveScanReport,
  getScanReportById,
  getScanHistoryByHostname,
  getRecentScans,
};
