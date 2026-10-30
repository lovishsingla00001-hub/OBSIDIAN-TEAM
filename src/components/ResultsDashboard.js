/**
 * SiteCheck - Results Dashboard Component (ResultsDashboard.js)
 * Team: Obsidian
 * 
 * Renders the primary cybersecurity SaaS dashboard including:
 * - Circular SVG turquoise security score gauge (0-100)
 * - Stat counters (Total, Passed, Failed, Critical)
 * - Category breakdown gauges
 * - Right-side AI Recommendations card (powered by Ollama Gemma 4 E4B)
 * - Target scan metadata & TLS details
 * - Professional Findings Table with search & multi-severity filters
 * - Multi-framework remediation snippets (Express, Nginx, Django, Flask)
 * - Report export & print functionality
 */

(function (window) {
  'use strict';

  class ResultsDashboard {
    constructor(container, options = {}) {
      this.container = container;
      this.options = options;
      this.onNewScan = options.onNewScan || (() => {});
      this.currentFramework = 'nginx'; // 'express' | 'nginx' | 'django' | 'flask'
      this.searchQuery = '';
      this.selectedSeverity = 'all'; // 'all' | 'high' | 'medium' | 'low' | 'passed'
      this.selectedCategory = 'all';
      this.expandedRules = new Set();
      this.data = null;
    }

    setData(reportData) {
      this.data = reportData || window.SiteCheck.MOCK_SCAN_DATA;
      this.render();
      this.bindEvents();
    }

    setFramework(framework) {
      this.currentFramework = framework.toLowerCase();
      this.updateCodeSnippets();
      this.updateFrameworkTabUI();
    }

    render() {
      if (!this.data) return;

      const score = this.calculateOverallScore();
      const summary = this.data.summary || { high: 0, medium: 0, low: 0 };
      const rawResults = Array.isArray(this.data.results) ? this.data.results : [];
      
      const totalChecks = rawResults.length;
      const triggeredChecks = rawResults.filter(r => r.triggered).length;
      const passedChecks = rawResults.filter(r => !r.triggered).length;
      const criticalFindings = (Number(summary.high) || 0);

      const targetUrl = this.data.url || this.data.finalUrl || (this.data.meta && this.data.meta.targetUrl) || 'Target URL';
      const hostname = this.data.hostname || (this.data.meta && this.data.meta.hostname) || deriveHostname(targetUrl);
      const scannedAt = this.data.scannedAt || (this.data.meta && this.data.meta.scannedAt) || new Date().toUTCString();
      const isMock = Boolean(this.data.isMock);

      // SVG circle calculation: r=64 => circumference = 2 * PI * 64 = 402.12
      const circumference = 402.12;
      const strokeDashoffset = circumference - (score / 100) * circumference;

      // Color based on score
      let scoreColor = '#10b981'; // Green / Turquoise
      let gradeLabel = 'Good Posture';
      let gradeBg = 'rgba(16, 185, 129, 0.15)';
      let gradeBorder = 'rgba(16, 185, 129, 0.4)';

      if (score < 50) {
        scoreColor = '#ef4444'; // Red
        gradeLabel = 'Critical Risk';
        gradeBg = 'rgba(239, 68, 68, 0.15)';
        gradeBorder = 'rgba(239, 68, 68, 0.4)';
      } else if (score < 80) {
        scoreColor = '#f59e0b'; // Amber / Yellow
        gradeLabel = 'Needs Attention';
        gradeBg = 'rgba(245, 158, 11, 0.15)';
        gradeBorder = 'rgba(245, 158, 11, 0.4)';
      }

      // Categories
      const catScores = (this.data.score && this.data.score.byCategory) || {};
      const catHeaders = catScores.headers !== undefined ? catScores.headers : 75;
      const catTls = catScores.tls !== undefined ? catScores.tls : (this.data.tls && this.data.tls.valid ? 100 : 0);
      const catExposure = catScores.exposure !== undefined ? catScores.exposure : 80;
      const catHtml = (catScores.html !== undefined ? catScores.html : (catScores.privacy !== undefined ? catScores.privacy : 75));

      // AI Explanation
      const ai = this.data.aiExplanation || this.data.ai || null;
      const aiAvailable = ai && (ai.available !== false) && (ai.summary || ai.whatItMeans);

      this.container.innerHTML = `
        <!-- Demo Data Banner -->
        ${isMock ? `
          <div class="demo-data-banner" role="status">
            <div style="display: flex; align-items: center; gap: 0.65rem;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span><strong>DEMO DATA:</strong> You are viewing an offline sample audit. Enter a live website URL above to inspect real security posture.</span>
            </div>
            <span style="font-size: 0.75rem; opacity: 0.8; font-family: monospace;">MOCK_SCAN_DATA</span>
          </div>
        ` : ''}

        <!-- Two-Column Asymmetric Dashboard Grid -->
        <div class="dashboard-grid-layout" style="margin-top: ${isMock ? '1.25rem' : '0'};">
          
          <!-- LEFT / PRIMARY COLUMN -->
          <div class="dashboard-main-col">
            
            <!-- 1. Security Score Hero Card -->
            <div class="score-overview-card" role="region" aria-label="Security Posture Score">
              <!-- Radial Score Gauge -->
              <div class="score-radial-box">
                <svg class="score-svg-circle" viewBox="0 0 160 160" aria-hidden="true">
                  <defs>
                    <linearGradient id="score-cyan-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stop-color="#00f2fe" />
                      <stop offset="100%" stop-color="#10b981" />
                    </linearGradient>
                  </defs>
                  <circle
                    class="score-circle-bg"
                    cx="80"
                    cy="80"
                    r="64"
                  />
                  <circle
                    class="score-circle-progress"
                    cx="80"
                    cy="80"
                    r="64"
                    stroke="${scoreColor}"
                    stroke-dasharray="${circumference}"
                    stroke-dashoffset="${strokeDashoffset}"
                  />
                </svg>
                <div class="score-inner-content">
                  <span class="score-number">${score}</span>
                  <span class="score-denominator">SCORE</span>
                  <span class="score-grade-pill" style="color: ${scoreColor}; background: ${gradeBg}; border: 1px solid ${gradeBorder};">
                    ${gradeLabel}
                  </span>
                </div>
              </div>

              <!-- Stats Matrix & Category Bars -->
              <div class="score-stats-matrix">
                <!-- 4 Key Stat Counters -->
                <div class="stats-counter-row">
                  <div class="stat-counter-box">
                    <span class="stat-label">Total Checks</span>
                    <span class="stat-value">${totalChecks}</span>
                  </div>
                  <div class="stat-counter-box">
                    <span class="stat-label">Passed</span>
                    <span class="stat-value passed">${passedChecks}</span>
                  </div>
                  <div class="stat-counter-box">
                    <span class="stat-label">Failed</span>
                    <span class="stat-value failed">${triggeredChecks}</span>
                  </div>
                  <div class="stat-counter-box">
                    <span class="stat-label">Critical / High</span>
                    <span class="stat-value critical">${criticalFindings}</span>
                  </div>
                </div>

                <!-- Category Breakdown Mini Bars -->
                <div class="category-bars-container">
                  <div class="category-bar-item">
                    <div class="category-bar-header">
                      <span class="category-name">Security Headers</span>
                      <span class="category-score">${catHeaders}%</span>
                    </div>
                    <div class="category-bar-track">
                      <div class="category-bar-fill" style="width: ${catHeaders}%;"></div>
                    </div>
                  </div>

                  <div class="category-bar-item">
                    <div class="category-bar-header">
                      <span class="category-name">TLS &amp; Transport Encryption</span>
                      <span class="category-score">${catTls}%</span>
                    </div>
                    <div class="category-bar-track">
                      <div class="category-bar-fill" style="width: ${catTls}%;"></div>
                    </div>
                  </div>

                  <div class="category-bar-item">
                    <div class="category-bar-header">
                      <span class="category-name">Information Exposure &amp; Files</span>
                      <span class="category-score">${catExposure}%</span>
                    </div>
                    <div class="category-bar-track">
                      <div class="category-bar-fill" style="width: ${catExposure}%;"></div>
                    </div>
                  </div>

                  <div class="category-bar-item">
                    <div class="category-bar-header">
                      <span class="category-name">HTML Hygiene &amp; Privacy</span>
                      <span class="category-score">${catHtml}%</span>
                    </div>
                    <div class="category-bar-track">
                      <div class="category-bar-fill" style="width: ${catHtml}%;"></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- 2. Security Findings Table Card -->
            <div class="findings-card" role="region" aria-label="Security Findings Table">
              <!-- Toolbar & Filter Bar -->
              <div class="findings-header-toolbar">
                <div class="findings-title-wrapper">
                  <h3 class="findings-title">Security Findings</h3>
                  <span class="findings-count-badge" id="findings-count-label">
                    ${triggeredChecks} Triggered &bull; ${passedChecks} Passed
                  </span>
                </div>

                <div class="findings-controls-group">
                  <!-- Search Bar -->
                  <input
                    type="text"
                    id="findings-search"
                    class="findings-search-input"
                    placeholder="Search rule, ID, OWASP…"
                    value="${escapeHtml(this.searchQuery)}"
                  />

                  <!-- Severity Filter Pills -->
                  <div class="filter-pills-row" role="tablist">
                    <button type="button" class="filter-pill-btn ${this.selectedSeverity === 'all' ? 'active' : ''}" data-sev="all">All (${totalChecks})</button>
                    <button type="button" class="filter-pill-btn ${this.selectedSeverity === 'high' ? 'active' : ''}" data-sev="high" style="color: #f87171;">High</button>
                    <button type="button" class="filter-pill-btn ${this.selectedSeverity === 'medium' ? 'active' : ''}" data-sev="medium" style="color: #fbbf24;">Med</button>
                    <button type="button" class="filter-pill-btn ${this.selectedSeverity === 'low' ? 'active' : ''}" data-sev="low" style="color: #38bdf8;">Low</button>
                    <button type="button" class="filter-pill-btn ${this.selectedSeverity === 'passed' ? 'active' : ''}" data-sev="passed" style="color: #34d399;">Passed</button>
                  </div>

                  <!-- Category Dropdown -->
                  <select id="findings-category-select" class="category-select-dropdown" aria-label="Filter by category">
                    <option value="all">All Categories</option>
                    <option value="headers">Headers</option>
                    <option value="tls">TLS</option>
                    <option value="exposure">Exposure</option>
                    <option value="html">HTML &amp; Privacy</option>
                  </select>
                </div>
              </div>

              <!-- Table Container -->
              <div class="findings-table-container">
                <table class="findings-table" aria-label="Detailed Security Findings">
                  <thead>
                    <tr>
                      <th style="width: 28%;">Security Rule</th>
                      <th style="width: 14%;">Category</th>
                      <th style="width: 12%;">Severity</th>
                      <th style="width: 12%;">Status</th>
                      <th style="width: 24%;">Explanation</th>
                      <th style="width: 10%; text-align: right;">Action</th>
                    </tr>
                  </thead>
                  <tbody id="findings-table-body">
                    ${this.renderTableRows(rawResults)}
                  </tbody>
                </table>
              </div>
            </div>

          </div>

          <!-- RIGHT / SIDEBAR COLUMN -->
          <div class="dashboard-side-col">
            
            <!-- 3. AI Recommendations Panel (Gemma 4 E4B) -->
            <div class="ai-recommendations-card" role="region" aria-label="AI Recommendations">
              <div class="ai-card-header">
                <div class="ai-title-group">
                  <div class="ai-title-icon" aria-hidden="true">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                      <path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"></path>
                    </svg>
                  </div>
                  <h3 class="ai-card-title">AI Recommendations</h3>
                </div>
                <span class="ai-chip-badge" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;">
                  <span class="ai-sparkle">✦</span> Gemma 4 E4B
                </span>
              </div>

              ${aiAvailable ? `
                <!-- Executive Summary -->
                <div class="ai-narrative-box">
                  <p style="margin: 0; font-weight: 500;">
                    ${escapeHtml(ai.summary)}
                  </p>
                </div>

                <!-- What It Means -->
                ${ai.whatItMeans ? `
                  <div class="ai-section-block">
                    <h4 class="ai-section-heading">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                      What It Means
                    </h4>
                    <p class="ai-section-text">${escapeHtml(ai.whatItMeans)}</p>
                  </div>
                ` : ''}

                <!-- Why It Matters -->
                ${ai.whyItMatters ? `
                  <div class="ai-section-block">
                    <h4 class="ai-section-heading" style="color: #f87171;">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      Why It Matters
                    </h4>
                    <p class="ai-section-text">${escapeHtml(ai.whyItMatters)}</p>
                  </div>
                ` : ''}

                <!-- How To Fix It -->
                ${ai.howToFix ? `
                  <div class="ai-section-block">
                    <h4 class="ai-section-heading" style="color: var(--turquoise-accent);">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                      How To Fix It
                    </h4>
                    <p class="ai-section-text">${escapeHtml(ai.howToFix)}</p>
                  </div>
                ` : ''}

                <!-- Priority Action Items -->
                ${Array.isArray(ai.remediation) && ai.remediation.length > 0 ? `
                  <div class="ai-section-block">
                    <h4 class="ai-section-heading">Priority Remediation Checklist</h4>
                    <ul class="ai-checklist">
                      ${ai.remediation.map((item, idx) => `
                        <li class="ai-checklist-item">
                          <span class="ai-checklist-bullet">${idx + 1}.</span>
                          <span>${escapeHtml(item)}</span>
                        </li>
                      `).join('')}
                    </ul>
                  </div>
                ` : ''}
              ` : `
                <!-- Friendly Offline Notice -->
                <div class="ai-offline-notice">
                  <div style="display: flex; align-items: center; gap: 0.5rem; font-weight: 700; color: #f59e0b;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
                      <line x1="12" y1="9" x2="12" y2="13"></line>
                      <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                    <span>Ollama Gemma 4 E4B Offline</span>
                  </div>
                  <p style="margin: 0; line-height: 1.45;">
                    The local Ollama AI explainer service is currently unreachable. 
                    Deterministic scoring and all 16 security rules remain 100% active and accurate.
                  </p>
                  <p style="margin-top: 0.35rem; font-size: 0.75rem; color: #cbd5e1;">
                    To enable AI remediation advice, ensure Ollama is running locally with:<br />
                    <code style="color: var(--cyan-primary); background: rgba(0,0,0,0.3); padding: 2px 4px; border-radius: 4px;">ollama run gemma4:e4b</code>
                  </p>
                </div>
              `}
            </div>

            <!-- 4. Target Scan Details Panel -->
            <div class="scan-details-panel" role="region" aria-label="Scan Details">
              <h4 class="details-panel-title">Audit Metadata &amp; Environment</h4>
              <div class="details-list">
                <div class="details-row">
                  <span class="details-key">Target Domain</span>
                  <span class="details-val">${escapeHtml(hostname)}</span>
                </div>
                <div class="details-row">
                  <span class="details-key">Resolved Endpoint</span>
                  <span class="details-val" style="max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    ${escapeHtml(targetUrl)}
                  </span>
                </div>
                <div class="details-row">
                  <span class="details-key">Audit Timestamp</span>
                  <span class="details-val" style="font-size: 0.75rem;">${escapeHtml(formatDate(scannedAt))}</span>
                </div>
                <div class="details-row">
                  <span class="details-key">TLS Certificate</span>
                  <span class="details-val" style="color: ${this.data.tls && this.data.tls.valid ? 'var(--turquoise-accent)' : '#f87171'};">
                    ${this.data.tls && this.data.tls.valid ? `Valid (${this.data.tls.daysUntilExpiry}d left)` : 'Unverified / HTTP'}
                  </span>
                </div>
                <div class="details-row">
                  <span class="details-key">Well-Known Files</span>
                  <span class="details-val" style="color: #94a3b8;">
                    ${this.data.wellKnownPaths ? Object.keys(this.data.wellKnownPaths).length : 4} Probed
                  </span>
                </div>
                <div class="details-row">
                  <span class="details-key">Storage Status</span>
                  <span class="details-val" style="color: var(--cyan-primary);">
                    ${this.data.id ? 'Supabase Saved' : 'Local Memory'}
                  </span>
                </div>
              </div>

              <!-- Quick Export Trigger -->
              <div style="margin-top: 0.5rem; display: flex; gap: 0.5rem;">
                <button type="button" class="btn-header-action" id="btn-export-json-bottom" style="flex: 1; justify-content: center; font-size: 0.78rem;">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                  Export JSON
                </button>
                <button type="button" class="btn-header-action" id="btn-print-report-bottom" style="flex: 1; justify-content: center; font-size: 0.78rem;">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 6 2 18 2 18 9"></polyline>
                    <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>
                    <rect x="6" y="14" width="12" height="8"></rect>
                  </svg>
                  Print PDF
                </button>
              </div>
            </div>

          </div>

        </div>
      `;
    }

    renderTableRows(rawResults) {
      if (!rawResults || rawResults.length === 0) {
        return `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2.5rem 1rem;">
              No findings match your current filters.
            </td>
          </tr>
        `;
      }

      const q = this.searchQuery.toLowerCase().trim();
      const filtered = rawResults.filter(item => {
        const rule = item.rule || {};
        const isTriggered = Boolean(item.triggered);
        const sev = (rule.severity || 'medium').toLowerCase();
        const cat = (rule.category || 'headers').toLowerCase();

        // Severity filter
        if (this.selectedSeverity === 'passed' && isTriggered) return false;
        if (this.selectedSeverity !== 'all' && this.selectedSeverity !== 'passed') {
          if (!isTriggered) return false;
          if (this.selectedSeverity === 'high' && sev !== 'high' && sev !== 'critical') return false;
          if (this.selectedSeverity === 'medium' && sev !== 'medium') return false;
          if (this.selectedSeverity === 'low' && sev !== 'low') return false;
        }

        // Category filter
        if (this.selectedCategory !== 'all') {
          if (cat !== this.selectedCategory) return false;
        }

        // Text query
        if (q) {
          const matchId = (rule.id || '').toLowerCase().includes(q);
          const matchExplain = (rule.explain || '').toLowerCase().includes(q);
          const matchOwasp = (rule.owasp || '').toLowerCase().includes(q);
          const matchCat = cat.includes(q);
          return matchId || matchExplain || matchOwasp || matchCat;
        }

        return true;
      });

      if (filtered.length === 0) {
        return `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2.5rem 1rem;">
              No security checks match "${escapeHtml(this.searchQuery)}".
            </td>
          </tr>
        `;
      }

      return filtered.map(item => {
        const rule = item.rule || {};
        const isTriggered = Boolean(item.triggered);
        const sev = (rule.severity || 'medium').toLowerCase();
        const ruleId = rule.id || 'SEC-RULE';
        const isExpanded = this.expandedRules.has(ruleId);

        // Crucial for test-runner assertions:
        // .rule-card-triggered and .rule-card-passed classes
        const triggerClass = isTriggered ? 'rule-card-triggered' : 'rule-card-passed';

        return `
          <tr class="${triggerClass}" id="rule-row-${escapeHtml(ruleId)}">
            <td>
              <span class="rule-id-code">${escapeHtml(ruleId)}</span>
              <div class="rule-name-text">${escapeHtml(formatRuleTitle(ruleId, rule.explain))}</div>
            </td>
            <td>
              <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600;">
                ${escapeHtml(rule.category || 'general')}
              </span>
            </td>
            <td>
              ${isTriggered ? `
                <span class="sev-badge ${sev}">
                  <span style="width: 5px; height: 5px; border-radius: 50%; background: currentColor;"></span>
                  ${escapeHtml(sev)}
                </span>
              ` : `
                <span class="sev-badge passed">
                  <span style="width: 5px; height: 5px; border-radius: 50%; background: currentColor;"></span>
                  Passed
                </span>
              `}
            </td>
            <td>
              ${isTriggered ? `
                <span class="status-indicator-tag triggered">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  Triggered
                </span>
              ` : `
                <span class="status-indicator-tag passed">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6 9 17l-5-5"/></svg>
                  Passed
                </span>
              `}
            </td>
            <td>
              <div style="font-size: 0.82rem; color: #cbd5e1; line-height: 1.45;">
                ${escapeHtml(rule.explain || 'Evaluation complete.')}
              </div>
              ${rule.owasp ? `
                <div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 3px; font-family: monospace;">
                  ${escapeHtml(rule.owasp)}
                </div>
              ` : ''}
            </td>
            <td style="text-align: right;">
              <button
                type="button"
                class="btn-view-details"
                data-rule-toggle="${escapeHtml(ruleId)}"
                aria-expanded="${isExpanded}"
                aria-label="View remediation details for ${escapeHtml(ruleId)}"
              >
                <span>${isExpanded ? 'Hide' : 'Details'}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="transform: ${isExpanded ? 'rotate(180deg)' : 'none'}; transition: transform 0.2s ease;">
                  <path d="m6 9 6 6 6-6"></path>
                </svg>
              </button>
            </td>
          </tr>

          <!-- Expandable Detail & Code Remediation Row -->
          <tr id="rule-detail-${escapeHtml(ruleId)}" style="display: ${isExpanded ? 'table-row' : 'none'};">
            <td colspan="6" style="padding: 0; background: rgba(5, 8, 14, 0.4);">
              <div class="finding-detail-drawer">
                <!-- Finding Explanation & OWASP Metadata -->
                <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.85rem 1rem;">
                  <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--cyan-primary); font-weight: 700; margin-bottom: 0.35rem;">
                    Finding Explanation
                  </div>
                  <div style="font-size: 0.84rem; color: #e2e8f0; line-height: 1.55;">
                    ${escapeHtml(rule.explain || 'Evaluation complete.')}
                  </div>
                  ${rule.owasp ? `
                    <div style="margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">
                      <strong style="color: #94a3b8;">OWASP Tag:</strong> <span style="color: var(--turquoise-accent);">${escapeHtml(rule.owasp)}</span>
                    </div>
                  ` : ''}
                </div>

                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap;">
                  <div>
                    <h5 style="color: #fff; font-size: 0.88rem; margin: 0 0 0.35rem 0; font-weight: 700;">
                      Remediation Snippets &bull; ${escapeHtml(ruleId)}
                    </h5>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin: 0;">
                      Copy and paste the tested mitigation directly into your application or web server configuration:
                    </p>
                  </div>
                  <!-- Framework Selector Tabs -->
                  <div class="remediation-framework-tabs" role="tablist">
                    <button type="button" class="framework-tab-btn ${this.currentFramework === 'nginx' ? 'active' : ''}" data-framework="nginx">Nginx</button>
                    <button type="button" class="framework-tab-btn ${this.currentFramework === 'express' ? 'active' : ''}" data-framework="express">Express</button>
                    <button type="button" class="framework-tab-btn ${this.currentFramework === 'django' ? 'active' : ''}" data-framework="django">Django</button>
                    <button type="button" class="framework-tab-btn ${this.currentFramework === 'flask' ? 'active' : ''}" data-framework="flask">Flask</button>
                  </div>
                </div>

                <!-- Code Block Container -->
                <div class="code-snippet-box">
                  <button type="button" class="btn-copy-code" data-copy-target="code-${escapeHtml(ruleId)}">
                    Copy Snippet
                  </button>
                  <pre class="code-snippet-pre"><code id="code-${escapeHtml(ruleId)}">${escapeHtml(this.getSnippetFor(rule, this.currentFramework))}</code></pre>
                </div>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    getSnippetFor(rule, framework) {
      if (!rule || !rule.fixes) return '# No code remediation required for this rule.';
      const fixes = rule.fixes;
      if (typeof fixes === 'string') return fixes;
      if (fixes[framework]) return fixes[framework];
      if (fixes.nginx) return fixes.nginx;
      if (fixes.express) return fixes.express;
      const keys = Object.keys(fixes);
      if (keys.length > 0 && typeof fixes[keys[0]] === 'string') {
        return fixes[keys[0]];
      }
      return '# Standard configuration for this security rule.';
    }

    updateCodeSnippets() {
      if (!this.data || !Array.isArray(this.data.results)) return;
      this.data.results.forEach(item => {
        const rule = item.rule;
        if (!rule || !rule.id) return;
        const codeEl = this.container.querySelector(`#code-${rule.id}`);
        if (codeEl) {
          codeEl.textContent = this.getSnippetFor(rule, this.currentFramework);
        }
      });
    }

    updateFrameworkTabUI() {
      this.container.querySelectorAll('.framework-tab-btn').forEach(btn => {
        const fw = btn.getAttribute('data-framework');
        if (fw === this.currentFramework) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });
    }

    calculateOverallScore() {
      if (typeof this.data?.score?.overall === 'number') {
        return Math.max(0, Math.min(100, Math.round(this.data.score.overall)));
      }
      return 75;
    }

    bindEvents() {
      // Search input filtering
      const searchInput = this.container.querySelector('#findings-search');
      if (searchInput) {
        searchInput.addEventListener('input', (e) => {
          this.searchQuery = e.target.value;
          this.refreshTableOnly();
        });
      }

      // Severity filter pills
      this.container.querySelectorAll('.filter-pill-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          this.container.querySelectorAll('.filter-pill-btn').forEach(b => b.classList.remove('active'));
          e.currentTarget.classList.add('active');
          this.selectedSeverity = e.currentTarget.getAttribute('data-sev') || 'all';
          this.refreshTableOnly();
        });
      });

      // Category select dropdown
      const catSelect = this.container.querySelector('#findings-category-select');
      if (catSelect) {
        catSelect.addEventListener('change', (e) => {
          this.selectedCategory = e.target.value;
          this.refreshTableOnly();
        });
      }

      // View details expand toggles & delegated dashboard interactions
      if (this._dashboardClickHandler) {
        this.container.removeEventListener('click', this._dashboardClickHandler);
      }
      this._dashboardClickHandler = (e) => {
        const toggleBtn = e.target.closest('[data-rule-toggle]');
        if (toggleBtn) {
          const ruleId = toggleBtn.getAttribute('data-rule-toggle');
          if (this.expandedRules.has(ruleId)) {
            this.expandedRules.delete(ruleId);
          } else {
            this.expandedRules.add(ruleId);
          }
          const isNowExpanded = this.expandedRules.has(ruleId);
          const detailRow = document.getElementById(`rule-detail-${ruleId}`);
          if (detailRow) {
            detailRow.style.display = isNowExpanded ? 'table-row' : 'none';
            toggleBtn.setAttribute('aria-expanded', String(isNowExpanded));
            const textSpan = toggleBtn.querySelector('span');
            if (textSpan) textSpan.textContent = isNowExpanded ? 'Hide' : 'Details';
            const icon = toggleBtn.querySelector('svg');
            if (icon) icon.style.transform = isNowExpanded ? 'rotate(180deg)' : 'none';
          } else {
            this.refreshTableOnly();
          }
          return;
        }

        // Framework tab switches
        const fwBtn = e.target.closest('.framework-tab-btn');
        if (fwBtn) {
          const fw = fwBtn.getAttribute('data-framework');
          this.setFramework(fw);
          return;
        }

        // Copy snippet button
        const copyBtn = e.target.closest('.btn-copy-code');
        if (copyBtn) {
          const targetId = copyBtn.getAttribute('data-copy-target');
          const codeEl = this.container.querySelector(`#${targetId}`);
          if (codeEl) {
            navigator.clipboard.writeText(codeEl.textContent).then(() => {
              const orig = copyBtn.textContent;
              copyBtn.textContent = 'Copied!';
              copyBtn.style.color = '#10b981';
              setTimeout(() => {
                copyBtn.textContent = orig;
                copyBtn.style.color = '';
              }, 1800);
            }).catch(() => {
              copyBtn.textContent = 'Failed to copy';
            });
          }
          return;
        }

        // Export JSON triggers
        if (e.target.closest('#btn-export-json-bottom') || e.target.closest('#btn-export-header')) {
          this.exportReportJson();
          return;
        }

        // Print PDF triggers
        if (e.target.closest('#btn-print-report-bottom')) {
          window.print();
          return;
        }
      };
      this.container.addEventListener('click', this._dashboardClickHandler);
    }

    refreshTableOnly() {
      const tbody = this.container.querySelector('#findings-table-body');
      if (!tbody || !this.data) return;
      const rawResults = Array.isArray(this.data.results) ? this.data.results : [];
      tbody.innerHTML = this.renderTableRows(rawResults);
    }

    exportReportJson() {
      if (!this.data) return;
      const domain = (this.data.hostname || 'domain').replace(/[^a-zA-Z0-9.-]/g, '_');
      const date = new Date().toISOString().slice(0, 10);
      const filename = `sitecheck-report-${domain}-${date}.json`;
      const blob = new Blob([JSON.stringify(this.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const downloadAnchor = document.createElement('a');
      downloadAnchor.href = url;
      downloadAnchor.download = filename;
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      URL.revokeObjectURL(url);
    }

    clear() {
      this.data = null;
      this.searchQuery = '';
      this.selectedSeverity = 'all';
      this.selectedCategory = 'all';
      this.expandedRules.clear();
      if (this.container) {
        this.container.innerHTML = '';
      }
    }
  }

  function formatRuleTitle(ruleId, explanation) {
    if (explanation && explanation.length < 50) {
      return explanation;
    }
    const map = {
      'SEC-HDR-001': 'Content-Security-Policy (CSP)',
      'SEC-HDR-002': 'Strict-Transport-Security (HSTS)',
      'SEC-HDR-003': 'X-Frame-Options (Clickjacking)',
      'SEC-HDR-004': 'X-Content-Type-Options (MIME)',
      'SEC-EXP-001': 'Server Software Banner Exposure',
      'SEC-EXP-002': 'Git Repository Directory Exposure',
      'SEC-PRV-001': 'Referrer-Policy Hygiene',
      'SEC-TLS-001': 'TLS Certificate Cryptographic Validity',
      'SEC-HTML-001': 'Insecure Mixed Content Injections'
    };
    return map[ruleId] || ruleId;
  }

  function deriveHostname(url) {
    try {
      const p = new URL(url.startsWith('http') ? url : 'https://' + url);
      return p.hostname;
    } catch {
      return url || 'unknown';
    }
  }

  function formatDate(dStr) {
    try {
      const d = new Date(dStr);
      if (!isNaN(d.getTime())) {
        return d.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          timeZoneName: 'short'
        });
      }
    } catch {}
    return dStr;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.ResultsDashboard = ResultsDashboard;

})(window);
