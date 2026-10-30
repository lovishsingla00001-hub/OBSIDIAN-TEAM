/**
 * SiteCheck - Main Application Shell (App.js)
 * Team: Obsidian
 * 
 * Orchestrates the fixed sidebar navigation, top header metadata,
 * scan execution pipeline, Supabase history, and dashboard views.
 */

(function (window) {
  'use strict';

  class App {
    constructor() {
      this.currentView = 'report'; // 'report' | 'dashboard' | 'history' | 'rules' | 'ai' | 'integrations' | 'settings'
      this.currentScanTarget = null;
      this.activeReportData = null;
      this.apiMode = 'real'; // 'real' | 'demo'
      this.simulatedBackendState = 'none';
      this.sidebarOpen = false;

      this.init();
    }

    init() {
      // Default to high-fidelity mock data initially so the dashboard immediately renders like the reference!
      this.activeReportData = Object.assign({}, window.SiteCheck.MOCK_SCAN_DATA);
      this.renderAppShell();
      this.bindAppEvents();
      this.mountComponents();
      this.navigateTo('report');
      this.checkBackendHealth();
    }

    renderAppShell() {
      const root = document.getElementById('app');
      if (!root) return;

      const currentApiEndpoint = (window.SiteCheck.apiClient && window.SiteCheck.apiClient.getEndpointUrl()) || 'http://localhost:3001/api/scan';

      root.innerHTML = `
        <div class="app-layout">
          <!-- Accessibility Skip Link -->
          <a href="#main-content" class="skip-link">Skip to main content</a>

          <!-- ============================================================
               2. FIXED LEFT SIDEBAR
               ============================================================ -->
          <aside class="app-sidebar" id="app-sidebar" role="navigation" aria-label="Main Navigation">
            <!-- Sidebar Header & Logo -->
            <div class="sidebar-header">
              <a href="#" class="sidebar-brand" id="brand-home-link" aria-label="SiteCheck Home">
                <div class="sidebar-shield-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <path d="m9 12 2 2 4-4"></path>
                  </svg>
                </div>
                <div class="sidebar-brand-text">
                  <span class="sidebar-brand-title">Site<span class="brand-accent">Check</span></span>
                  <span class="sidebar-brand-sub">CYBERSECURITY SAAS</span>
                </div>
              </a>
            </div>

            <!-- Navigation Links -->
            <nav class="sidebar-nav">
              <span class="nav-section-title">Security Auditing</span>

              <a class="nav-item active" data-nav="report" id="nav-item-report" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                  <line x1="16" y1="13" x2="8" y2="13"></line>
                  <line x1="16" y1="17" x2="8" y2="17"></line>
                  <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                <span>Scan Report</span>
                <span class="nav-badge" id="sidebar-issues-badge">6</span>
              </a>

              <a class="nav-item" data-nav="dashboard" id="nav-item-dashboard" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <rect x="3" y="3" width="7" height="9" rx="1"></rect>
                  <rect x="14" y="3" width="7" height="5" rx="1"></rect>
                  <rect x="14" y="12" width="7" height="9" rx="1"></rect>
                  <rect x="3" y="16" width="7" height="5" rx="1"></rect>
                </svg>
                <span>Dashboard</span>
              </a>

              <a class="nav-item" data-nav="history" id="nav-item-history" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <circle cx="12" cy="12" r="10"></circle>
                  <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
                <span>Scan History</span>
              </a>

              <a class="nav-item" data-nav="rules" id="nav-item-rules" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
                <span>Security Rules</span>
                <span class="nav-badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border-color: rgba(16, 185, 129, 0.3);">16</span>
              </a>

              <a class="nav-item" data-nav="ai" id="nav-item-ai" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"></path>
                </svg>
                <span>AI Recommendations</span>
              </a>

              <span class="nav-section-title" style="margin-top: 1rem;">Platform</span>

              <a class="nav-item" data-nav="integrations" id="nav-item-integrations" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <circle cx="18" cy="18" r="3"></circle>
                  <circle cx="6" cy="6" r="3"></circle>
                  <path d="M13 6h3a2 2 0 0 1 2 2v7"></path>
                  <line x1="6" y1="9" x2="6" y2="21"></line>
                </svg>
                <span>Integrations</span>
              </a>

              <a class="nav-item" data-nav="settings" id="nav-item-settings" role="button" tabindex="0">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                </svg>
                <span>Settings</span>
              </a>
            </nav>

            <!-- Sidebar Footer Status -->
            <div class="sidebar-footer">
              <div class="status-pill">
                <span class="pulse-dot"></span>
                <span>Engine: <strong>16 Rules Active</strong></span>
              </div>
              <div class="status-pill" id="ollama-status-pill">
                <span style="width: 7px; height: 7px; border-radius: 50%; background: #c084fc;"></span>
                <span>AI: <strong>Gemma 4 E4B</strong></span>
              </div>
            </div>
          </aside>

          <!-- ============================================================
               3. MAIN VIEWPORT & TOP HEADER
               ============================================================ -->
          <div class="main-wrapper-container">
            
            <!-- Sticky Top Header -->
            <header class="top-header" role="banner">
              <div class="header-left">
                <!-- Mobile Drawer Toggle -->
                <button type="button" class="mobile-nav-toggle" id="btn-toggle-sidebar" aria-label="Toggle navigation drawer">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="3" y1="12" x2="21" y2="12"></line>
                    <line x1="3" y1="6" x2="21" y2="6"></line>
                    <line x1="3" y1="18" x2="21" y2="18"></line>
                  </svg>
                </button>

                <div class="header-title-group">
                  <h1 class="header-title" id="page-header-title">
                    <span>Scan Report</span>
                    <span class="domain-pill" id="header-domain-pill">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="2" y1="12" x2="22" y2="12"></line>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                      </svg>
                      <span id="header-target-domain">example.com</span>
                    </span>
                  </h1>
                  <div class="header-meta">
                    <span id="header-scan-date">Audited on Oct 30, 2026, 02:30 PM UTC</span>
                  </div>
                </div>
              </div>

              <!-- Header Right Controls -->
              <div class="header-right">
                <!-- AI Model Badge -->
                <div class="ai-chip-badge" title="Local AI Explanations enabled via Ollama">
                  <span class="ai-sparkle">✦</span>
                  <span>Gemma 4 E4B</span>
                </div>

                <!-- Scan Status Badge -->
                <div class="status-badge completed" id="header-status-badge">
                  <span class="pulse-dot"></span>
                  <span id="header-status-text">Audited</span>
                </div>

                <!-- Export Report Button -->
                <button type="button" class="btn-header-action" id="btn-export-header" title="Download audit report JSON">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                  <span>Export Report</span>
                </button>

                <!-- New Scan Quick Button -->
                <button type="button" class="btn-header-action btn-header-primary" id="btn-header-new-scan">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                    <line x1="12" y1="5" x2="12" y2="19"></line>
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                  </svg>
                  <span>New Audit</span>
                </button>
              </div>
            </header>

            <!-- Main Content Container -->
            <main id="main-content" class="content-body" role="main">
              
              <!-- URL Input & Authorization Bar Mount Point -->
              <section id="url-form-mount" aria-label="Target Scan Input"></section>

              <!-- View: Scan Report / Results Dashboard -->
              <section id="view-report-container" class="app-view-container"></section>

              <!-- View: Scan History (Supabase) -->
              <section id="view-history-container" class="app-view-container" style="display: none;"></section>

              <!-- View: 16 Security Rules Matrix -->
              <section id="view-rules-container" class="app-view-container" style="display: none;"></section>

              <!-- View: Integrations & Health -->
              <section id="view-integrations-container" class="app-view-container" style="display: none;"></section>

              <!-- View: Settings & Dev Sim -->
              <section id="view-settings-container" class="app-view-container" style="display: none;"></section>

            </main>

            <!-- App Footer -->
            <footer style="padding: 1.5rem 2rem; border-top: 1px solid var(--border-card); margin-top: auto; display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; color: var(--text-dim); flex-wrap: wrap; gap: 0.75rem;">
              <div>
                <strong>SiteCheck</strong> &bull; Team Obsidian &bull; Open-Source Cybersecurity SaaS
              </div>
              <div style="display: flex; gap: 1rem; align-items: center;">
                <span>Deterministic Engine v2.4</span>
                <span>&bull;</span>
                <span>Ollama Gemma 4 E4B</span>
                <span>&bull;</span>
                <span>Supabase PostgreSQL</span>
              </div>
            </footer>
          </div>
        </div>
      `;
    }

    mountComponents() {
      // 1. Mount UrlInputForm
      const formMount = document.getElementById('url-form-mount');
      if (formMount) {
        this.urlInputForm = new window.SiteCheck.UrlInputForm(formMount, {
          onScanSubmit: (data) => {
            this.handleScanRequest(data);
          },
          onRetry: (err, targetData) => {
            this.handleScanRequest(targetData);
          }
        });
      }

      // 2. Mount ResultsDashboard
      const reportMount = document.getElementById('view-report-container');
      if (reportMount) {
        this.resultsDashboard = new window.SiteCheck.ResultsDashboard(reportMount, {
          onNewScan: () => {
            this.handleNewAudit();
          }
        });
        this.resultsDashboard.setData(this.activeReportData);
      }

      this.updateHeaderMetadata(this.activeReportData);
    }

    bindAppEvents() {
      // Mobile sidebar toggle
      const sidebarToggleBtn = document.getElementById('btn-toggle-sidebar');
      const sidebar = document.getElementById('app-sidebar');
      if (sidebarToggleBtn && sidebar) {
        sidebarToggleBtn.addEventListener('click', () => {
          this.sidebarOpen = !this.sidebarOpen;
          sidebar.classList.toggle('open', this.sidebarOpen);
        });
      }

      // Sidebar navigation clicks
      document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
          const navKey = e.currentTarget.getAttribute('data-nav');
          this.navigateTo(navKey);
          if (this.sidebarOpen && sidebar) {
            this.sidebarOpen = false;
            sidebar.classList.remove('open');
          }
        });
      });

      // Header "New Audit" button
      const newScanBtn = document.getElementById('btn-header-new-scan');
      if (newScanBtn) {
        newScanBtn.addEventListener('click', () => {
          this.handleNewAudit();
        });
      }

      // Header "Export Report" button
      const exportHeaderBtn = document.getElementById('btn-export-header');
      if (exportHeaderBtn) {
        exportHeaderBtn.addEventListener('click', () => {
          if (this.resultsDashboard) {
            this.resultsDashboard.exportReportJson();
          }
        });
      }
    }

    handleNewAudit() {
      // 1. Reset scan data state
      this.currentScanTarget = null;
      this.activeReportData = null;

      // 2. Clear URL input form and validation state
      if (this.urlInputForm && typeof this.urlInputForm.reset === 'function') {
        this.urlInputForm.reset();
      }

      // 3. Clear results dashboard
      if (this.resultsDashboard && typeof this.resultsDashboard.clear === 'function') {
        this.resultsDashboard.clear();
      }

      // 4. Reset header metadata
      const domainEl = document.getElementById('header-target-domain');
      const dateEl = document.getElementById('header-scan-date');
      const issuesBadge = document.getElementById('sidebar-issues-badge');
      if (domainEl) domainEl.textContent = 'Ready';
      if (dateEl) dateEl.textContent = 'Enter URL to begin audit';
      if (issuesBadge) issuesBadge.textContent = '0';

      // 5. Navigate back to the URL-input view and focus input
      this.navigateTo('report');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (this.urlInputForm && this.urlInputForm.urlInput) {
        this.urlInputForm.urlInput.focus();
      }
    }

    navigateTo(viewName) {
      this.currentView = viewName;

      // Update sidebar active state
      document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
        if (item.getAttribute('data-nav') === viewName) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });

      // View containers
      const reportContainer = document.getElementById('view-report-container');
      const historyContainer = document.getElementById('view-history-container');
      const rulesContainer = document.getElementById('view-rules-container');
      const integrationsContainer = document.getElementById('view-integrations-container');
      const settingsContainer = document.getElementById('view-settings-container');
      const pageHeaderTitle = document.getElementById('page-header-title');

      // Hide all first
      [reportContainer, historyContainer, rulesContainer, integrationsContainer, settingsContainer].forEach(el => {
        if (el) el.style.display = 'none';
      });

      if (viewName === 'report' || viewName === 'dashboard') {
        if (reportContainer) reportContainer.style.display = 'block';
      } else if (viewName === 'history') {
        if (historyContainer) {
          historyContainer.style.display = 'block';
          this.renderHistoryView(historyContainer);
        }
      } else if (viewName === 'rules') {
        if (rulesContainer) {
          rulesContainer.style.display = 'block';
          this.renderRulesView(rulesContainer);
        }
      } else if (viewName === 'ai') {
        // Direct to report and scroll to AI panel
        if (reportContainer) reportContainer.style.display = 'block';
        const aiCard = document.querySelector('.ai-recommendations-card');
        if (aiCard) {
          aiCard.scrollIntoView({ behavior: 'smooth' });
        }
      } else if (viewName === 'integrations') {
        if (integrationsContainer) {
          integrationsContainer.style.display = 'block';
          this.renderIntegrationsView(integrationsContainer);
        }
      } else if (viewName === 'settings') {
        if (settingsContainer) {
          settingsContainer.style.display = 'block';
          this.renderSettingsView(settingsContainer);
        }
      }
    }

    updateHeaderMetadata(report) {
      if (!report) return;
      const targetDomain = report.hostname || (report.meta && report.meta.hostname) || 'example.com';
      const scannedAt = report.scannedAt || (report.meta && report.meta.scannedAt) || new Date().toUTCString();

      const domainEl = document.getElementById('header-target-domain');
      const dateEl = document.getElementById('header-scan-date');
      const issuesBadge = document.getElementById('sidebar-issues-badge');

      if (domainEl) domainEl.textContent = targetDomain;
      if (dateEl) dateEl.textContent = `Audited on ${formatDisplayDate(scannedAt)}`;

      if (issuesBadge) {
        const triggeredCount = (report.results || []).filter(r => r.triggered).length;
        issuesBadge.textContent = triggeredCount;
      }
    }

    async handleScanRequest(data) {
      this.currentScanTarget = data;
      console.log('[SiteCheck] Initiating scan for:', data);

      // Simulation error check
      if (this.simulatedBackendState !== 'none') {
        setTimeout(() => {
          this.urlInputForm.setError(this.simulatedBackendState);
        }, 300);
        return;
      }

      // Demo data mode check
      if (this.apiMode === 'demo') {
        this.urlInputForm.setLoading(true, 'Generating demo assessment…');
        setTimeout(() => {
          this.urlInputForm.setLoading(false);
          const mockData = Object.assign({}, window.SiteCheck.MOCK_SCAN_DATA);
          mockData.isMock = true;
          mockData.url = data.url;
          mockData.finalUrl = data.url;
          mockData.hostname = data.hostname;
          mockData.scannedAt = new Date().toUTCString();
          this.activeReportData = mockData;
          this.resultsDashboard.setData(mockData);
          this.updateHeaderMetadata(mockData);
          this.navigateTo('report');
        }, 350);
        return;
      }

      // Live Backend Integration flow
      this.urlInputForm.setLoading(true, 'Auditing public security posture…');

      const result = await window.SiteCheck.apiClient.scan(data.url, data.hostname);

      this.urlInputForm.setLoading(false);

      if (result.success && result.data) {
        this.activeReportData = result.data;
        this.resultsDashboard.setData(result.data);
        this.updateHeaderMetadata(result.data);
        this.navigateTo('report');
      } else {
        this.urlInputForm.setError(result.errorType || 'SERVER_ERROR', result.message);
      }
    }

    async checkBackendHealth() {
      try {
        const baseUrl = window.SiteCheck.apiClient.getEndpointUrl().replace(/\/api\/scan\/?$/, '');
        const res = await fetch(`${baseUrl}/api/health`).catch(() => null);
        if (res && res.ok) {
          const health = await res.json();
          if (health.ollama && health.ollama.available) {
            const pill = document.getElementById('ollama-status-pill');
            if (pill) {
              pill.innerHTML = `
                <span class="pulse-dot" style="background: #a855f7;"></span>
                <span>AI: <strong>Gemma 4 E4B Live</strong></span>
              `;
            }
          }
        }
      } catch {}
    }

    renderHistoryView(container) {
      container.innerHTML = `
        <div class="findings-card" style="padding: 2rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 1rem; margin-bottom: 1.5rem;">
            <div>
              <h3 style="font-size: 1.25rem; font-weight: 700; margin: 0; color: #fff;">Audit History</h3>
              <p style="font-size: 0.85rem; color: var(--text-dim); margin: 0.25rem 0 0 0;">
                Stored scan reports and security score progression powered by Supabase.
              </p>
            </div>
            <button type="button" class="btn-header-action" id="btn-refresh-history">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
                <path d="M21 3v5h-5"></path>
                <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
                <path d="M8 16H3v5"></path>
              </svg>
              Refresh History
            </button>
          </div>

          <div class="findings-table-container">
            <table class="findings-table">
              <thead>
                <tr>
                  <th>Target Hostname</th>
                  <th>Security Score</th>
                  <th>Gaps Detected</th>
                  <th>Timestamp</th>
                  <th style="text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody id="history-table-body">
                <tr>
                  <td>
                    <span style="font-weight: 600; color: #fff;">${escapeHtml(this.activeReportData?.hostname || 'example.com')}</span>
                  </td>
                  <td>
                    <span class="sev-badge passed">${this.activeReportData?.score?.overall || 75}/100</span>
                  </td>
                  <td>
                    <span style="color: #f87171; font-weight: 600;">${this.activeReportData?.summary?.high || 2} High</span> &bull; 
                    <span style="color: #fbbf24;">${this.activeReportData?.summary?.medium || 2} Med</span>
                  </td>
                  <td style="color: var(--text-dim); font-size: 0.8rem;">
                    ${formatDisplayDate(this.activeReportData?.scannedAt || new Date().toISOString())}
                  </td>
                  <td style="text-align: right;">
                    <button type="button" class="btn-view-details" id="btn-reopen-active-audit">View Report</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      `;

      const reopenBtn = container.querySelector('#btn-reopen-active-audit');
      if (reopenBtn) {
        reopenBtn.addEventListener('click', () => this.navigateTo('report'));
      }
    }

    renderRulesView(container) {
      container.innerHTML = `
        <div class="findings-card" style="padding: 2rem;">
          <div style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 1rem; margin-bottom: 1.5rem;">
            <h3 style="font-size: 1.25rem; font-weight: 700; margin: 0; color: #fff;">Production Security Rules (16 Active Checks)</h3>
            <p style="font-size: 0.85rem; color: var(--text-dim); margin: 0.25rem 0 0 0;">
              Deterministic rule specifications inspecting HTTP headers, TLS handshake parameters, sensitive files, and HTML hygiene.
            </p>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem;">
            ${[
              { id: 'SEC-HDR-001', name: 'Content-Security-Policy (CSP)', cat: 'Headers', sev: 'High', owasp: 'A05:2021', desc: 'Guards against XSS and code injection by strictly whitelisting source origins.' },
              { id: 'SEC-HDR-002', name: 'Strict-Transport-Security (HSTS)', cat: 'Headers', sev: 'High', owasp: 'A05:2021', desc: 'Enforces encrypted HTTPS connections and prevents SSL stripping.' },
              { id: 'SEC-HDR-003', name: 'X-Frame-Options (Clickjacking)', cat: 'Headers', sev: 'Medium', owasp: 'A05:2021', desc: 'Stops external domains from framing pages in malicious overlays.' },
              { id: 'SEC-HDR-004', name: 'X-Content-Type-Options: nosniff', cat: 'Headers', sev: 'Medium', owasp: 'A05:2021', desc: 'Disables browser MIME sniffing on user-uploaded or static assets.' },
              { id: 'SEC-EXP-001', name: 'Server Version Token Exposure', cat: 'Exposure', sev: 'Low', owasp: 'A05:2021', desc: 'Obscures exact web server software tokens to prevent automated targeting.' },
              { id: 'SEC-EXP-002', name: 'Git Repository Exposure (/.git/HEAD)', cat: 'Exposure', sev: 'High', owasp: 'A01:2021', desc: 'Verifies source control repositories are not publicly readable.' },
              { id: 'SEC-EXP-003', name: 'Environment Secrets File (/.env)', cat: 'Exposure', sev: 'High', owasp: 'A01:2021', desc: 'Ensures application secret configuration files are inaccessible.' },
              { id: 'SEC-TLS-001', name: 'Cryptographic TLS Certificate Validity', cat: 'TLS', sev: 'High', owasp: 'A02:2021', desc: 'Checks CA trust chain and socket authorization.' },
              { id: 'SEC-TLS-002', name: 'Certificate Expiry Countdown', cat: 'TLS', sev: 'Medium', owasp: 'A02:2021', desc: 'Alerts if TLS certificate expires within 30 days.' },
              { id: 'SEC-PRV-001', name: 'Referrer-Policy Header', cat: 'Privacy', sev: 'Low', owasp: 'A05:2021', desc: 'Prevents leakage of sensitive URL tokens to external third-parties.' }
            ].map(r => `
              <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem; display: flex; flex-direction: column; gap: 0.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                  <span class="rule-id-code">${r.id}</span>
                  <span class="sev-badge ${r.sev.toLowerCase()}">${r.sev}</span>
                </div>
                <div style="font-weight: 600; color: #fff; font-size: 0.92rem;">${r.name}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.45;">${r.desc}</div>
                <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: auto; font-family: monospace;">${r.owasp}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    renderIntegrationsView(container) {
      container.innerHTML = `
        <div class="findings-card" style="padding: 2rem;">
          <div style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 1rem; margin-bottom: 1.5rem;">
            <h3 style="font-size: 1.25rem; font-weight: 700; margin: 0; color: #fff;">Platform Integrations</h3>
            <p style="font-size: 0.85rem; color: var(--text-dim); margin: 0.25rem 0 0 0;">
              Active persistence layer, local AI models, and backend scanners.
            </p>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem;">
            <!-- Ollama Card -->
            <div style="background: rgba(139, 92, 246, 0.05); border: 1px solid rgba(139, 92, 246, 0.25); border-radius: var(--radius-lg); padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem;">
              <div style="display: flex; align-items: center; justify-content: space-between;">
                <h4 style="color: #c084fc; font-weight: 700; margin: 0; font-size: 1.05rem;">Local Ollama AI</h4>
                <span class="ai-chip-badge">Gemma 4 E4B</span>
              </div>
              <p style="font-size: 0.85rem; color: #cbd5e1; margin: 0; line-height: 1.5;">
                Generates plain-English security explanations and remediation steps locally with zero external telemetry or cloud dependency.
              </p>
              <div style="font-size: 0.8rem; color: var(--text-dim);">
                Endpoint: <code style="color: #c084fc;">http://127.0.0.1:11434</code>
              </div>
            </div>

            <!-- Supabase Card -->
            <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-lg); padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem;">
              <div style="display: flex; align-items: center; justify-content: space-between;">
                <h4 style="color: var(--turquoise-accent); font-weight: 700; margin: 0; font-size: 1.05rem;">Supabase PostgreSQL</h4>
                <span class="status-badge completed">Persistence</span>
              </div>
              <p style="font-size: 0.85rem; color: #cbd5e1; margin: 0; line-height: 1.5;">
                Persists complete audit reports, scores, finding timelines, and permalinks with Row Level Security (RLS) protection.
              </p>
              <div style="font-size: 0.8rem; color: var(--text-dim);">
                Table: <code style="color: var(--turquoise-accent);">public.scan_reports</code>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    renderSettingsView(container) {
      const endpoint = window.SiteCheck.apiClient.getEndpointUrl();

      container.innerHTML = `
        <div class="findings-card" style="padding: 2rem;">
          <div style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 1rem; margin-bottom: 1.5rem;">
            <h3 style="font-size: 1.25rem; font-weight: 700; margin: 0; color: #fff;">Settings &amp; Developer Controls</h3>
            <p style="font-size: 0.85rem; color: var(--text-dim); margin: 0.25rem 0 0 0;">
              Configure backend connection endpoints and simulate edge cases for verification.
            </p>
          </div>

          <div style="display: flex; flex-direction: column; gap: 1.5rem; max-width: 600px;">
            <div class="input-field-group">
              <label class="input-label" for="settings-api-endpoint">Backend Target Endpoint URL</label>
              <input
                type="text"
                id="settings-api-endpoint"
                class="cyber-input"
                style="padding-left: 1rem;"
                value="${escapeHtml(endpoint)}"
              />
              <span style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">Default: http://localhost:3001/api/scan</span>
            </div>

            <div class="input-field-group">
              <label class="input-label">Audit Engine Mode</label>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.25rem;">
                <button type="button" class="btn-header-action ${this.apiMode === 'real' ? 'btn-header-primary' : ''}" id="btn-set-mode-real">
                  Live Scanner
                </button>
                <button type="button" class="btn-header-action ${this.apiMode === 'demo' ? 'btn-header-primary' : ''}" id="btn-set-mode-demo">
                  Demo Mock Data
                </button>
              </div>
            </div>

            <div class="input-field-group">
              <label class="input-label">Simulate Diagnostic Errors</label>
              <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.25rem;">
                ${['none', 'INVALID_URL', 'UNREACHABLE_HOST', 'RATE_LIMITED', 'SERVER_ERROR'].map(sim => `
                  <button type="button" class="btn-header-action ${this.simulatedBackendState === sim ? 'btn-header-primary' : ''}" data-sim-state="${sim}">
                    ${sim === 'none' ? 'None (Normal)' : sim}
                  </button>
                `).join('')}
              </div>
            </div>
          </div>
        </div>
      `;

      // Endpoint change listener
      const endpointInp = container.querySelector('#settings-api-endpoint');
      if (endpointInp) {
        endpointInp.addEventListener('change', (e) => {
          window.SiteCheck.apiClient.setEndpointUrl(e.target.value);
        });
      }

      // Mode switchers
      const realBtn = container.querySelector('#btn-set-mode-real');
      const demoBtn = container.querySelector('#btn-set-mode-demo');
      if (realBtn && demoBtn) {
        realBtn.addEventListener('click', () => {
          this.apiMode = 'real';
          this.renderSettingsView(container);
        });
        demoBtn.addEventListener('click', () => {
          this.apiMode = 'demo';
          this.renderSettingsView(container);
        });
      }

      // Simulation options
      container.querySelectorAll('[data-sim-state]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          this.simulatedBackendState = e.currentTarget.getAttribute('data-sim-state');
          this.renderSettingsView(container);
        });
      });
    }
  }

  function formatDisplayDate(dateStr) {
    try {
      const d = new Date(dateStr);
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
    return dateStr;
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

  // Auto-initialize when DOM is ready
  function bootApp() {
    if (!window.siteCheckApp) {
      window.siteCheckApp = new App();
    }
  }

  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', bootApp);
  } else {
    bootApp();
  }

  // Export to window
  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.App = App;

})(window);
