/**
 * @fileoverview Core rule evaluation, sanitization, and scoring engine.
 *
 * TEAM: Obsidian
 * ROLE: Engine Lead
 * DOMAIN: Security Rule Evaluation & Scoring Engine
 */

const defaultRules = require('../rules');

/**
 * Agreed severity penalty deductions per triggered rule.
 */
const SEVERITY_PENALTIES = {
  high: 25,
  medium: 10,
  low: 5,
};

/**
 * Approved standard rule categories.
 */
const VALID_CATEGORIES = Object.freeze(['headers', 'tls', 'exposure', 'html', 'general']);

/**
 * Approved severity levels.
 */
const VALID_SEVERITIES = Object.freeze(['high', 'medium', 'low']);

/**
 * Validates a single rule against the strict Rule contract.
 *
 * Contract requirements:
 * 1. Non-empty string id.
 * 2. Unique id within the rule set.
 * 3. Valid category ('headers' | 'tls' | 'exposure' | 'html' | 'general').
 * 4. Valid severity ('high' | 'medium' | 'low').
 * 5. Callable check function.
 * 6. Non-empty explain string.
 * 7. Non-empty OWASP reference string.
 * 8. Serializable fixes object with string remediation snippets.
 *
 * @param {any} rule - The rule object to validate.
 * @param {Set<string>} [seenIds] - Set of encountered rule IDs.
 * @param {Object} [options] - Optional validation flags.
 * @param {boolean} [options.allowCustomCategory=false] - Whether to allow non-standard categories.
 * @returns {{ valid: boolean, error: string | null }}
 */
function validateRule(rule, seenIds = new Set(), options = {}) {
  if (!rule || typeof rule !== 'object') {
    return { valid: false, error: 'Rule must be a non-null object' };
  }

  if (typeof rule.id !== 'string' || rule.id.trim() === '') {
    return { valid: false, error: 'Rule must have a non-empty string id' };
  }

  if (seenIds.has(rule.id)) {
    return { valid: false, error: `Duplicate rule ID '${rule.id}'` };
  }
  seenIds.add(rule.id);

  if (typeof rule.category !== 'string' || rule.category.trim() === '') {
    return { valid: false, error: `Rule '${rule.id}' must have a non-empty category` };
  }

  if (!options.allowCustomCategory && !VALID_CATEGORIES.includes(rule.category.toLowerCase())) {
    return {
      valid: false,
      error: `Rule '${rule.id}' has invalid category '${rule.category}'. Must be one of: ${VALID_CATEGORIES.join(', ')}`,
    };
  }

  if (typeof rule.severity !== 'string' || !VALID_SEVERITIES.includes(rule.severity.toLowerCase())) {
    return {
      valid: false,
      error: `Rule '${rule.id}' has invalid severity '${rule.severity}'. Must be one of: ${VALID_SEVERITIES.join(', ')}`,
    };
  }

  if (typeof rule.check !== 'function') {
    return { valid: false, error: `Rule '${rule.id}' check is not a function` };
  }

  if (typeof rule.explain !== 'string' || rule.explain.trim() === '') {
    return { valid: false, error: `Rule '${rule.id}' must have a non-empty explain string` };
  }

  if (typeof rule.owasp !== 'string' || rule.owasp.trim() === '') {
    return { valid: false, error: `Rule '${rule.id}' must have a non-empty OWASP reference` };
  }

  if (!rule.fixes || typeof rule.fixes !== 'object' || Array.isArray(rule.fixes)) {
    return { valid: false, error: `Rule '${rule.id}' fixes must be a serializable object` };
  }

  for (const [platform, fixText] of Object.entries(rule.fixes)) {
    if (typeof fixText !== 'string') {
      return { valid: false, error: `Rule '${rule.id}' fix for '${platform}' must be a string` };
    }
  }

  return { valid: true, error: null };
}

/**
 * Validates an array of rules against the strict Rule contract.
 *
 * @param {any[]} rules - Array of rules.
 * @param {Object} [options] - Validation options.
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateRules(rules, options = {}) {
  if (!Array.isArray(rules)) {
    return { valid: false, errors: ['Rules must be an array'] };
  }

  const seenIds = new Set();
  const errors = [];

  for (const rule of rules) {
    const res = validateRule(rule, seenIds, options);
    if (!res.valid && res.error) {
      errors.push(res.error);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Calculates overall and category-level scores (0–100) and severity summary counts.
 * Clamps all scores between 0 and 100.
 *
 * @param {import('./types').RuleResult[]} results - Evaluated rule results.
 * @param {string[]} allCategories - List of all categories represented in the evaluated rule set.
 * @returns {{ score: import('./types').Score, summary: import('./types').Summary }}
 */
function calculateScores(results, allCategories = []) {
  const summary = {
    high: 0,
    medium: 0,
    low: 0,
  };

  const byCategory = {};
  for (const cat of allCategories) {
    byCategory[cat] = 100;
  }

  let totalPenalty = 0;
  const categoryPenalties = {};

  for (const item of results) {
    if (item.triggered) {
      // Informational findings do not penalize security score or increment vulnerability counts
      if (item.rule && item.rule.informational) {
        continue;
      }

      const severity = (item.rule.severity || '').toLowerCase();
      const penalty = SEVERITY_PENALTIES[severity] || 0;
      totalPenalty += penalty;

      if (severity === 'high') {
        summary.high++;
      } else if (severity === 'medium') {
        summary.medium++;
      } else if (severity === 'low') {
        summary.low++;
      }

      const cat = item.rule.category || 'general';
      categoryPenalties[cat] = (categoryPenalties[cat] || 0) + penalty;
    }
  }

  // Deduct penalties per category, clamped between 0 and 100
  for (const cat of Object.keys(byCategory)) {
    const penalty = categoryPenalties[cat] || 0;
    byCategory[cat] = Math.max(0, Math.min(100, 100 - penalty));
  }

  // Include any categories present in penalties not initially seeded
  for (const cat of Object.keys(categoryPenalties)) {
    if (byCategory[cat] === undefined) {
      byCategory[cat] = Math.max(0, Math.min(100, 100 - categoryPenalties[cat]));
    }
  }

  // Overall score clamped between 0 and 100
  const overall = Math.max(0, Math.min(100, 100 - totalPenalty));

  return {
    score: {
      overall,
      byCategory,
    },
    summary,
  };
}

/**
 * Evaluates an array of rules against a SiteContext.
 *
 * Enforces:
 * 1. Rule contract validation: rejects invalid rules before execution.
 * 2. Independent evaluation of each rule with try/catch.
 * 3. Fault tolerance: one failed rule never crashes the audit.
 * 4. Complete sanitization: strips check() function and ensures functions never appear in report.
 * 5. Produces clean, serializable JSON without circular references or function values.
 * 6. Distinctly identifies:
 *    - Triggered: triggered === true, evaluationError === null
 *    - Passed (Safe): triggered === false, evaluationError === null
 *    - Evaluation Failed: triggered === false, evaluationError === string (never counted as safe)
 * 7. Informational findings trigger without score penalties.
 * 8. Clamps all scores between 0 and 100.
 *
 * @param {import('./types').SiteContext} ctx - The fetched site context.
 * @param {import('./types').Rule[]} rules - Array of security/privacy rules.
 * @param {Object} [options] - Evaluation options.
 * @param {boolean} [options.strict=false] - If true, requires strict category and metadata checks.
 * @returns {import('./types').EngineReport} Final client-facing report.
 */
function runRules(ctx, rules, options = {}) {
  if (!rules || !Array.isArray(rules)) {
    return {
      results: [],
      score: { overall: 100, byCategory: {} },
      summary: { high: 0, medium: 0, low: 0 },
    };
  }

  const results = [];
  const categoriesSet = new Set();
  const seenIds = new Set();

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') continue;

    // Rule contract pre-validation: reject invalid rules before execution
    let contractError = null;

    if (!rule.id || typeof rule.id !== 'string' || rule.id.trim() === '') {
      contractError = 'Rule must have a non-empty string id';
    } else if (seenIds.has(rule.id)) {
      contractError = `Duplicate rule ID '${rule.id}'`;
    } else {
      seenIds.add(rule.id);
    }

    if (!contractError) {
      const severity = (rule.severity || '').toLowerCase();
      if (!VALID_SEVERITIES.includes(severity)) {
        contractError = `Rule '${rule.id}' has invalid severity '${rule.severity}'. Must be one of: ${VALID_SEVERITIES.join(', ')}`;
      }
    }

    if (!contractError && typeof rule.check !== 'function') {
      contractError = `Rule '${rule.id}' check is not a function`;
    }

    // In strict mode, enforce full metadata contracts (categories, explain, owasp, fixes)
    if (!contractError && options.strict) {
      const fullRes = validateRule(rule, new Set(Array.from(seenIds).filter((id) => id !== rule.id)));
      if (!fullRes.valid) {
        contractError = fullRes.error;
      }
    }

    const category = rule.category || 'general';
    categoriesSet.add(category);

    // Sanitize rule: completely strip check() function and copy only serializable properties
    const sanitizedFixes = {};
    if (rule.fixes && typeof rule.fixes === 'object' && !Array.isArray(rule.fixes)) {
      for (const [k, v] of Object.entries(rule.fixes)) {
        if (typeof v === 'string') {
          sanitizedFixes[k] = v;
        }
      }
    }

    const sanitizedRule = {
      id: rule.id || 'unknown',
      category: rule.category || 'general',
      severity: rule.severity || 'low',
      explain: rule.explain || '',
      owasp: rule.owasp || '',
      fixes: sanitizedFixes,
      ...(rule.informational ? { informational: true } : {}),
    };

    let triggered = false;
    let evaluationError = null;

    if (contractError) {
      // Rejected before execution: do NOT call rule.check
      triggered = false;
      evaluationError = contractError;
    } else {
      try {
        triggered = Boolean(rule.check(ctx));
      } catch (err) {
        // Evaluation failed at runtime: do NOT count as triggered, do NOT count as safe
        triggered = false;
        evaluationError = err && err.message ? err.message : String(err);
      }
    }

    results.push({
      rule: sanitizedRule,
      triggered,
      evaluationError,
    });
  }

  const { score, summary } = calculateScores(results, Array.from(categoriesSet));

  return {
    results,
    score,
    summary,
  };
}

/**
 * Isolated mock SiteContext fixture for engine testing and development.
 * @type {import('./types').SiteContext}
 */
const mockSiteContext = {
  url: 'https://example.com',
  finalUrl: 'https://example.com/',
  statusCode: 200,
  headers: {
    'content-type': 'text/html; charset=utf-8',
    'server': 'nginx/1.24.0',
    'x-content-type-options': 'nosniff',
  },
  html: '<!DOCTYPE html><html><head><title>Obsidian</title></head><body><h1>Audited</h1></body></html>',
  usedHttps: true,
  redirectedToHttps: false,
  tls: {
    valid: true,
    daysUntilExpiry: 90,
  },
  wellKnownPaths: {
    '/.git/HEAD': { status: 404 },
    '/.env': { status: 404 },
    '/robots.txt': { status: 200 },
    '/sitemap.xml': { status: 200 },
  },
};

/**
 * Isolated mock Rule array fixture for engine testing and development.
 * @type {import('./types').Rule[]}
 */
const mockRules = [
  {
    id: 'SEC-HEADER-CSP',
    category: 'headers',
    severity: 'high',
    check: (ctx) => !ctx.headers['content-security-policy'],
    explain: 'Missing Content-Security-Policy header allows content injection attacks.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.contentSecurityPolicy());",
      nginx: "add_header Content-Security-Policy \"default-src 'self'\";",
    },
  },
  {
    id: 'SEC-EXPOSURE-ENV',
    category: 'exposure',
    severity: 'high',
    check: (ctx) => ctx.wellKnownPaths && ctx.wellKnownPaths['/.env'] && ctx.wellKnownPaths['/.env'].status === 200,
    explain: 'Environment configuration file is publicly accessible, leaking secrets.',
    owasp: 'A01:2021-Broken Access Control',
    fixes: {
      nginx: 'location ~ /\\.env { deny all; }',
    },
  },
  {
    id: 'SEC-TLS-EXPIRY',
    category: 'tls',
    severity: 'medium',
    check: (ctx) => !ctx.tls || !ctx.tls.valid || ctx.tls.daysUntilExpiry < 30,
    explain: 'TLS certificate is invalid or expires within 30 days.',
    owasp: 'A02:2021-Cryptographic Failures',
    fixes: {
      nginx: 'certbot renew',
    },
  },
  {
    id: 'SEC-HEADER-XFO',
    category: 'headers',
    severity: 'low',
    check: (ctx) => !ctx.headers['x-frame-options'],
    explain: 'Missing X-Frame-Options header leaves site vulnerable to clickjacking.',
    owasp: 'A05:2021-Security Misconfiguration',
    fixes: {
      express: "app.use(helmet.frameguard({ action: 'deny' }));",
      nginx: 'add_header X-Frame-Options "DENY";',
    },
  },
];

module.exports = {
  SEVERITY_PENALTIES,
  VALID_CATEGORIES,
  VALID_SEVERITIES,
  validateRule,
  validateRules,
  calculateScores,
  runRules,
  mockSiteContext,
  mockRules,
  allRules: defaultRules,
  defaultRules,
};
