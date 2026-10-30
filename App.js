/**
 * SiteCheck - Main Application Shell (App.js - Step 4 Integration)
 * Team: Obsidian
 * 
 * Coordinates view transitions, loading states, real backend integration
 * via ApiClient, fallback to Demo Data, and safe error rendering.
 */

(function (window) {
  'use strict';

  class App {
    constructor() {
      this.currentView = 'input'; // 'input' | 'results'
      this.currentScanTarget = null;
      this.apiMode = 'real'; // 'real' | 'demo'
      this.simulatedBackendState = 'none'; // 'none' | 'INVALID_URL' | 'UNREACHABLE_HOST' | 'RATE_LIMITED' | 'SERVER_ERROR'
      this.init();
    }

    init() {
      this.renderLayout();
      this.bindGlobalEvents();
      this.navigateTo('input');
    }

    renderLayout() {
      const root = document.getElementById('app');
      if (!root) return;

      const currentApiEndpoint = (window.SiteCheck.apiClient && window.SiteCheck.apiClient.getEndpointUrl()) || 'http://localhost:3001/api/scan';

      root.innerHTML = `
        <!-- Accessibility Skip Link -->
        <a href="#main-content" class="skip-link">Skip to main content</a>

        <!-- Backend Configuration & Simulation Bar -->
        <div class="dev-sim-bar" role="region" aria-label="Backend Configuration and Simulation Bar">
          <div class="dev-sim-item">
            <span class="sim-label">BACKEND TARGET:</span>
            <input
              type="text"
              id="input-api-endpoint"
              class="sim-endpoint-input"
              value="${escapeHtml(currentApiEndpoint)}"
              title="Change backend endpoint URL (e.g., http://localhost:3001/api/scan)"
            />
          </div>

          <div class="dev-sim-item">
            <span class="sim-label">MODE:</span>
            <div class="sim-buttons-group">
              <button type="button" class="btn-sim-option active" id="btn-mode-real" title="Attempt real HTTP request to backend">Live API</button>
              <button type="button" class="btn-sim-option" id="btn-mode-demo" title="Use offline Demo mock data">Demo Data</button>
            </div>
          </div>

          <div class="dev-sim-item">
            <span class="sim-label">SIMULATE ERROR:</span>
            <div class="sim-buttons-group">
              <button type="button" class="btn-sim-option active" data-sim="none">None</button>
              <button type="button" class="btn-sim-option" data-sim="INVALID_URL">400 URL</button>
              <button type="button" class="btn-sim-option" data-sim="UNREACHABLE_HOST">504 Net</button>
              <button type="button" class="btn-sim-option" data-sim="RATE_LIMITED">429 Rate</button>
              <button type="button" class="btn-sim-option" data-sim="SERVER_ERROR">500 Err</button>
            </div>
          </div>
        </div>

        <!-- Top Header Navigation -->
        <header class="app-header" role="banner">
          <div class="header-container">
            <a href="#" class="brand-wrapper" id="brand-home-link" aria-label="SiteCheck Home">
              <svg class="brand-icon-shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <path d="m9 12 2 2 4-4"></path>
              </svg>
              <div class="brand-text-block">
                <span class="brand-title">
                  Site<span class="brand-accent">Check</span>
                </span>
                <span class="brand-tagline">Security & Privacy Analysis</span>
              </div>
            </a>

            <div class="header-badges">
              <button type="button" class="btn-demo-quickview" id="btn-toggle-demo" aria-label="Toggle Demo Report">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
                <span id="demo-toggle-label">Preview Demo Report</span>
              </button>
              <span class="team-badge" title="Hackathon Team Obsidian">
                <span class="team-badge-dot"></span>
                Team Obsidian
              </span>
            </div>
          </div>
        </header>

        <!-- Main Content Area -->
        <main id="main-content" class="main-wrapper" role="main">
          
          <!-- View Container: Input Screen -->
          <div id="view-input" class="view-panel">
            <!-- Hero Kicker & Headline -->
            <section class="hero-section" aria-labelledby="hero-title">
              <div class="hero-pill">
                <svg class="hero-pill-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="16" x2="12" y2="12"></line>
                  <line x1="12" y1="8" x2="12.01" y2="8"></line>
                </svg>
                <span>Automated Web Security &amp; Hygiene Auditing</span>
              </div>
              <h1 id="hero-title" class="hero-title">
                Inspect your website's security posture in <span class="text-gradient">plain English</span>.
              </h1>
              <p class="hero-subtitle">
                Instant analysis of security headers, TLS posture, exposure risks, and privacy hygiene with copy-paste code fixes for Express, Nginx, Django, and Flask.
              </p>
            </section>

            <!-- Dynamic Mount Point for URL Input Form -->
            <div id="form-container"></div>

            <!-- Scope & Privacy Notice Card -->
            <aside class="scope-notice-card" role="region" aria-labelledby="scope-notice-title" style="margin-top: 2rem;">
              <div class="notice-icon-box" aria-hidden="true">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
              </div>
              <div class="notice-content">
                <h3 id="scope-notice-title" class="notice-title">
                  Scope of Inspection &amp; Responsible Authorization Notice
                </h3>
                <p class="notice-text">
                  SiteCheck is designed exclusively to inspect publicly accessible information transmitted by web servers. 
                  Audits analyze HTTP response headers, TLS handshake parameters, cookie security flags, and public endpoint hygiene.
                </p>
                <ul class="notice-bullets">
                  <li>
                    <span class="bullet-dot"></span>
                    <span><strong>Non-Intrusive Testing:</strong> SiteCheck does not perform exploit payloads, invasive fuzzing, or denial-of-service tests.</span>
                  </li>
                  <li>
                    <span class="bullet-dot"></span>
                    <span><strong>Authorization Protocol:</strong> Typing the target domain confirms your acknowledgement and authorization. This is a user acknowledgement, not proof of ownership; the backend enforces destination restrictions.</span>
                  </li>
                  <li>
                    <span class="bullet-dot"></span>
                    <span><strong>Privacy Commitment:</strong> No scanned site credentials, sensitive payload data, or cookies are stored or monetized.</span>
                  </li>
                </ul>
              </div>
            </aside>
          </div>

          <!-- View Container: Results Dashboard (Step 2) -->
          <div id="view-results" class="view-panel" style="display: none;">
            <div id="dashboard-container"></div>
          </div>

        </main>

        <!-- Application Footer -->
        <footer class="app-footer" role="contentinfo">
          <div class="footer-content">
            <p><strong>SiteCheck</strong> &bull; Built by Team Obsidian for the 190-Minute Hackathon</p>
            <p>Designed for desktop and mobile &bull; Zero external dependencies &bull; Open-source security analysis</p>
          </div>
        </footer>
      `;
    }

    bindGlobalEvents() {
      // Home logo click returns to input view
      const homeLink = document.getElementById('brand-home-link');
      if (homeLink) {
        homeLink.addEventListener('click', (e) => {
          e.preventDefault();
          this.navigateTo('input');
        });
      }

      // Demo Report Quick Toggle button
      const demoToggleBtn = document.getElementById('btn-toggle-demo');
      if (demoToggleBtn) {
        demoToggleBtn.addEventListener('click', () => {
          if (this.currentView === 'input') {
            this.navigateTo('results', window.SiteCheck.MOCK_SCAN_DATA);
          } else {
            this.navigateTo('input');
          }
        });
      }

      // Endpoint URL input update
      const endpointInput = document.getElementById('input-api-endpoint');
      if (endpointInput && window.SiteCheck.apiClient) {
        endpointInput.addEventListener('change', (e) => {
          window.SiteCheck.apiClient.setEndpointUrl(e.target.value);
          console.log('[SiteCheck] Backend endpoint updated to:', window.SiteCheck.apiClient.getEndpointUrl());
        });
      }

      // Mode toggles (Live API vs Demo Data)
      const modeRealBtn = document.getElementById('btn-mode-real');
      const modeDemoBtn = document.getElementById('btn-mode-demo');
      if (modeRealBtn && modeDemoBtn) {
        modeRealBtn.addEventListener('click', () => {
          this.apiMode = 'real';
          modeRealBtn.classList.add('active');
          modeDemoBtn.classList.remove('active');
        });
        modeDemoBtn.addEventListener('click', () => {
          this.apiMode = 'demo';
          modeDemoBtn.classList.add('active');
          modeRealBtn.classList.remove('active');
        });
      }

      // Error simulation options
      document.querySelectorAll('.btn-sim-option[data-sim]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          document.querySelectorAll('.btn-sim-option[data-sim]').forEach(b => b.classList.remove('active'));
          e.currentTarget.classList.add('active');
          this.simulatedBackendState = e.currentTarget.getAttribute('data-sim');
        });
      });
    }

    navigateTo(viewName, reportData = null) {
      this.currentView = viewName;
      const inputView = document.getElementById('view-input');
      const resultsView = document.getElementById('view-results');
      const demoToggleLabel = document.getElementById('demo-toggle-label');

      if (viewName === 'results') {
        if (inputView) inputView.style.display = 'none';
        if (resultsView) resultsView.style.display = 'block';
        if (demoToggleLabel) demoToggleLabel.textContent = 'Back to URL Input';

        this.mountResultsDashboard(reportData || window.SiteCheck.MOCK_SCAN_DATA);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else {
        if (inputView) inputView.style.display = 'block';
        if (resultsView) resultsView.style.display = 'none';
        if (demoToggleLabel) demoToggleLabel.textContent = 'Preview Demo Report';

        this.mountUrlInputForm();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    }

    mountUrlInputForm() {
      const formContainer = document.getElementById('form-container');
      if (!formContainer) return;

      if (!this.urlInputForm) {
        this.urlInputForm = new window.SiteCheck.UrlInputForm(formContainer, {
          onScanSubmit: (data) => {
            this.handleScanRequest(data);
          },
          onRetry: (err, targetData) => {
            this.handleScanRequest(targetData);
          }
        });
      }
    }

    mountResultsDashboard(dataToRender) {
      const dashboardContainer = document.getElementById('dashboard-container');
      if (!dashboardContainer) return;

      const activeData = dataToRender || window.SiteCheck.MOCK_SCAN_DATA;

      if (!this.resultsDashboard) {
        this.resultsDashboard = new window.SiteCheck.ResultsDashboard(dashboardContainer, {
          onNewScan: () => {
            this.navigateTo('input');
          }
        });
      }
      
      this.resultsDashboard.setData(activeData);
    }

    async handleScanRequest(data) {
      this.currentScanTarget = data;
      console.log('[SiteCheck] Processing scan request for:', data);

      // Check if a manual error simulation is selected
      if (this.simulatedBackendState !== 'none') {
        setTimeout(() => {
          this.urlInputForm.setError(this.simulatedBackendState);
        }, 300);
        return;
      }

      // Check if Demo mode is explicitly chosen
      if (this.apiMode === 'demo') {
        setTimeout(() => {
          this.urlInputForm.setLoading(false);
          const mockData = Object.assign({}, window.SiteCheck.MOCK_SCAN_DATA);
          mockData.isMock = true;
          mockData.meta = Object.assign({}, mockData.meta, {
            targetUrl: data.url,
            hostname: data.hostname,
            scannedAt: new Date().toUTCString()
          });
          this.navigateTo('results', mockData);
        }, 350);
        return;
      }

      // Live Backend Integration flow
      this.urlInputForm.setLoading(true, 'Contacting security scanner…');

      const result = await window.SiteCheck.apiClient.scan(data.url, data.hostname);

      this.urlInputForm.setLoading(false);

      if (result.success && result.data) {
        // Render real scan results (isMock = false removes DEMO DATA banner)
        this.navigateTo('results', result.data);
      } else {
        // Render sanitized error state without stack traces
        this.urlInputForm.setError(result.errorType || 'SERVER_ERROR', result.message);
      }
    }
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
  window.addEventListener('DOMContentLoaded', () => {
    window.siteCheckApp = new App();
  });

  // Export to window
  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.App = App;

})(window);
