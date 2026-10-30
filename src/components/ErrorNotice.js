/**
 * SiteCheck - Error Notice Component (ErrorNotice.js)
 * Team: Obsidian
 * 
 * Renders sanitized, plain-English cybersecurity error cards without leaking
 * stack traces, internal paths, or sensitive credentials.
 */

(function (window) {
  'use strict';

  const ERROR_DEFINITIONS = {
    INVALID_URL: {
      title: 'Invalid Target URL',
      code: 'ERR_INVALID_TARGET_URL',
      body: 'The specified URL could not be parsed or contains an unsupported scheme. SiteCheck only inspects public HTTP and HTTPS websites.',
      suggestion: 'Check the URL format (e.g., https://example.com) and try again.'
    },
    UNREACHABLE_HOST: {
      title: 'Target Host Unreachable',
      code: 'ERR_HOST_UNREACHABLE',
      body: 'The target web server did not respond within the connection timeout window or the hostname could not be resolved.',
      suggestion: 'Verify that the website is online and accessible from the public internet.'
    },
    RATE_LIMITED: {
      title: 'Rate Limit Enforced',
      code: 'ERR_HTTP_429_THROTTLED',
      body: 'Too many security assessment requests were submitted in a short interval. To protect external websites and prevent abuse, SiteCheck allows 1 scan per domain per 60 seconds.',
      suggestion: 'Please wait approximately one minute before testing this domain again.'
    },
    SERVER_ERROR: {
      title: 'Security Engine Unavailable',
      code: 'ERR_INTERNAL_SCAN_FAILURE',
      body: 'The scanning engine encountered an unexpected internal issue while evaluating security rules.',
      suggestion: 'Our team has logged this occurrence. Please try again in a few moments.'
    }
  };

  class ErrorNotice {
    constructor(container, options = {}) {
      this.container = container;
      this.onRetry = options.onRetry || null;
    }

    render(errorType = 'SERVER_ERROR', customMessage = null) {
      const def = ERROR_DEFINITIONS[errorType] || ERROR_DEFINITIONS.SERVER_ERROR;
      const displayBody = customMessage ? escapeHtml(customMessage) : def.body;

      this.container.innerHTML = `
        <div class="error-notice-card" role="alert" aria-live="assertive">
          <div class="error-icon-box" style="color: #ef4444; flex-shrink: 0;" aria-hidden="true">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
          </div>
          <div style="flex: 1; display: flex; flex-direction: column; gap: 0.35rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
              <h4 class="error-notice-title" style="color: #f87171; font-weight: 700; margin: 0; font-size: 0.95rem;">
                ${escapeHtml(def.title)}
              </h4>
              <span class="error-code-badge">${escapeHtml(def.code)}</span>
            </div>
            <p class="error-notice-body" style="font-size: 0.85rem; color: #cbd5e1; margin: 0; line-height: 1.45;">
              ${displayBody}
            </p>
            <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 0.5rem; gap: 0.5rem;">
              <span style="font-size: 0.75rem; color: #94a3b8;">${escapeHtml(def.suggestion)}</span>
              <button type="button" class="btn-header-action" id="btn-err-retry" style="font-size: 0.78rem; padding: 0.3rem 0.75rem;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
                  <path d="M21 3v5h-5"></path>
                  <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
                  <path d="M8 16H3v5"></path>
                </svg>
                Retry Scan
              </button>
            </div>
          </div>
        </div>
      `;

      const retryBtn = this.container.querySelector('#btn-err-retry');
      if (retryBtn && typeof this.onRetry === 'function') {
        retryBtn.addEventListener('click', () => {
          this.onRetry(errorType);
        });
      }
    }

    clear() {
      this.container.innerHTML = '';
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

  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.ErrorNotice = ErrorNotice;
  window.SiteCheck.ERROR_DEFINITIONS = ERROR_DEFINITIONS;

})(window);
