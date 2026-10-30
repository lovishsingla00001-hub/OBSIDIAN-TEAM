/**
 * SiteCheck - URL Input & Authorization Form Component (UrlInputForm.js)
 * Team: Obsidian
 * 
 * Enforces URL normalization, protocol restriction (HTTP/HTTPS only),
 * mandatory domain confirmation matching, and loading/error handling.
 */

(function (window) {
  'use strict';

  class UrlInputForm {
    constructor(container, options = {}) {
      this.container = container;
      this.options = options;
      this.onScanSubmit = options.onScanSubmit || (() => {});
      this.onRetry = options.onRetry || (() => {});

      this.state = {
        rawUrl: '',
        normalizedUrl: '',
        hostname: '',
        isUrlValid: false,
        urlError: '',
        confirmationInput: '',
        isConfirmationValid: false,
        confirmationError: '',
        isSubmitting: false,
        activeErrorType: null
      };

      this.render();
      this.bindElements();
    }

    render() {
      this.container.innerHTML = `
        <div class="scan-bar-card">
          <!-- Quick Preset Targets -->
          <div class="preset-targets-row" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.85rem; flex-wrap: wrap;">
            <span style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">Quick Presets:</span>
            <button type="button" class="preset-chip" data-preset="https://example.com" data-host="example.com" style="background: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.3); color: #38bdf8; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px; cursor: pointer; transition: all 0.2s;">example.com</button>
            <button type="button" class="preset-chip" data-preset="http://localhost:3001" data-host="localhost" style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px; cursor: pointer; transition: all 0.2s;">localhost:3001</button>
            <button type="button" class="preset-chip" data-preset="https://lovishhxh.netlify.app" data-host="lovishhxh.netlify.app" style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); color: #c084fc; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px; cursor: pointer; transition: all 0.2s;">lovishhxh.netlify.app</button>
            <button type="button" class="preset-chip" data-preset="https://github.com" data-host="github.com" style="background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.15); color: #e2e8f0; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px; cursor: pointer; transition: all 0.2s;">github.com</button>
          </div>

          <form id="sitecheck-form" role="form" aria-label="Website Security Audit Form" aria-busy="false" novalidate>
            <div class="scan-form-grid">
              <!-- URL Input -->
              <div class="input-field-group">
                <label for="input-target-url" class="input-label">
                  <span>Target Website URL</span>
                  <span id="url-status-hint" style="font-size: 0.72rem; color: var(--text-dim); text-transform: none;">e.g. example.com or localhost:3001</span>
                </label>
                <div class="input-wrapper">
                  <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="2" y1="12" x2="22" y2="12"></line>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                  </svg>
                  <input
                    type="url"
                    id="input-target-url"
                    class="cyber-input"
                    placeholder="https://example.com"
                    autocomplete="url"
                    spellcheck="false"
                    aria-describedby="url-error-msg"
                    aria-invalid="false"
                  />
                </div>
                <div id="url-error-msg" class="input-feedback-msg" role="alert" aria-live="polite"></div>
              </div>

              <!-- Domain Authorization Confirmation Input -->
              <div class="input-field-group">
                <label for="input-domain-confirmation" class="input-label">
                  <span>Confirm Target Domain</span>
                  <span id="domain-match-hint" style="font-size: 0.72rem; color: var(--text-dim); text-transform: none;">Type hostname to authorize</span>
                </label>
                <div class="input-wrapper">
                  <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                  </svg>
                  <input
                    type="text"
                    id="input-domain-confirmation"
                    class="cyber-input"
                    placeholder="example.com"
                    autocomplete="off"
                    spellcheck="false"
                    aria-describedby="conf-error-msg"
                    aria-invalid="false"
                  />
                </div>
                <div id="conf-error-msg" class="input-feedback-msg" role="alert" aria-live="polite"></div>
              </div>

              <!-- Submit Button -->
              <div class="input-field-group" style="justify-content: flex-end;">
                <button
                  type="submit"
                  id="btn-run-security-scan"
                  class="btn-run-scan"
                  disabled
                  aria-label="Run Security Scan"
                >
                  <svg id="btn-icon-spinner" class="spinner-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display: none;" aria-hidden="true">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
                  </svg>
                  <svg id="btn-icon-shield" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <path d="m9 12 2 2 4-4"></path>
                  </svg>
                  <span id="btn-scan-text">Run Security Scan</span>
                </button>
              </div>
            </div>
          </form>

          <!-- Mount point for ErrorNotice -->
          <div id="error-notice-mount" style="margin-top: 1.25rem; display: none;"></div>
        </div>
      `;
    }

    bindElements() {
      this.formEl = this.container.querySelector('#sitecheck-form');
      this.urlInput = this.container.querySelector('#input-target-url');
      this.confInput = this.container.querySelector('#input-domain-confirmation');
      this.submitBtn = this.container.querySelector('#btn-run-security-scan');
      this.btnScanText = this.container.querySelector('#btn-scan-text');
      this.btnIconSpinner = this.container.querySelector('#btn-icon-spinner');
      this.btnIconShield = this.container.querySelector('#btn-icon-shield');
      this.urlErrorEl = this.container.querySelector('#url-error-msg');
      this.confErrorEl = this.container.querySelector('#conf-error-msg');
      this.errorMountEl = this.container.querySelector('#error-notice-mount');
      this.domainMatchHint = this.container.querySelector('#domain-match-hint');

      this.errorNotice = new window.SiteCheck.ErrorNotice(this.errorMountEl, {
        onRetry: (errorType) => {
          this.onRetry(errorType, {
            url: this.state.normalizedUrl || this.state.rawUrl,
            hostname: this.state.hostname
          });
        }
      });

      this.urlInput.addEventListener('input', (e) => {
        this.handleUrlChange(e.target.value);
      });

      // Quick auto-fill on blur if user typed a valid URL
      this.urlInput.addEventListener('blur', () => {
        if (this.state.isUrlValid && this.state.hostname && !this.confInput.value.trim()) {
          this.confInput.value = this.state.hostname;
          this.handleConfirmationChange(this.state.hostname);
        }
      });

      this.confInput.addEventListener('input', (e) => {
        this.handleConfirmationChange(e.target.value);
      });

      // Bind quick presets
      const presetChips = this.container.querySelectorAll('.preset-chip');
      presetChips.forEach(chip => {
        chip.addEventListener('click', (e) => {
          e.preventDefault();
          const pUrl = chip.getAttribute('data-preset');
          const pHost = chip.getAttribute('data-host');
          this.urlInput.value = pUrl;
          this.handleUrlChange(pUrl);
          this.confInput.value = pHost;
          this.handleConfirmationChange(pHost);
        });
      });

      this.formEl.addEventListener('submit', (e) => {
        e.preventDefault();
        this.handleSubmit();
      });
    }

    validateUrl(inputUrl) {
      const raw = (inputUrl || '').trim();
      if (!raw) {
        return { isValid: false, error: 'URL cannot be empty' };
      }

      // Check scheme
      const schemeMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):/);
      let toParse = raw;

      if (schemeMatch) {
        const scheme = schemeMatch[1].toLowerCase();
        if (scheme !== 'http' && scheme !== 'https') {
          return {
            isValid: false,
            error: `Unsupported scheme "${scheme}:". Only http:// and https:// are accepted.`
          };
        }
      } else {
        // Prepend http:// for localhost or loopback, https:// otherwise
        if (/^localhost(:\d+)?(\/.*)?$/i.test(raw) || /^127\.0\.0\.1(:\d+)?(\/.*)?$/.test(raw)) {
          toParse = 'http://' + raw;
        } else {
          toParse = 'https://' + raw;
        }
      }

      try {
        const parsed = new URL(toParse);
        const host = (parsed.hostname || '').toLowerCase();
        const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');

        if (!host || (!host.includes('.') && !isLocal)) {
          return { isValid: false, error: 'Please enter a valid domain name.' };
        }

        const normalizedHost = host;
        return {
          isValid: true,
          normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
          hostname: normalizedHost
        };
      } catch (err) {
        return { isValid: false, error: 'Malformed URL: ' + err.message };
      }
    }

    validateConfirmation(input, expectedHostname) {
      if (!input || !expectedHostname) {
        return { isValid: false, error: 'Confirmation required.' };
      }
      const cleanInput = String(input).trim().toLowerCase();
      const cleanExpected = String(expectedHostname).trim().toLowerCase();

      if (cleanInput === cleanExpected) {
        return { isValid: true };
      }
      return {
        isValid: false,
        error: `Domain mismatch. Please type exactly "${cleanExpected}".`
      };
    }

    handleUrlChange(value) {
      if (this.state.isSubmitting) return;

      this.state.rawUrl = value;
      this.clearError();

      const val = this.validateUrl(value);
      if (val.isValid) {
        this.state.isUrlValid = true;
        this.state.normalizedUrl = val.normalizedUrl;
        this.state.hostname = val.hostname;
        this.state.urlError = '';

        this.urlInput.classList.remove('has-error');
        this.urlInput.setAttribute('aria-invalid', 'false');
        this.urlErrorEl.textContent = '';
        if (this.domainMatchHint) {
          this.domainMatchHint.innerHTML = `Type <strong>${escapeHtml(val.hostname)}</strong> or <button type="button" id="btn-quick-confirm-host" style="background: none; border: none; color: var(--cyan-primary); text-decoration: underline; font-size: 0.72rem; cursor: pointer; padding: 0;">auto-fill</button>`;
          const btnQuick = this.domainMatchHint.querySelector('#btn-quick-confirm-host');
          if (btnQuick) {
            btnQuick.addEventListener('click', (e) => {
              e.preventDefault();
              this.confInput.value = val.hostname;
              this.handleConfirmationChange(val.hostname);
            });
          }
        }
      } else {
        this.state.isUrlValid = false;
        this.state.normalizedUrl = '';
        this.state.hostname = '';
        this.state.urlError = val.error;

        if (value.trim()) {
          this.urlInput.classList.add('has-error');
          this.urlInput.setAttribute('aria-invalid', 'true');
          this.urlErrorEl.textContent = val.error;
        } else {
          this.urlInput.classList.remove('has-error');
          this.urlInput.setAttribute('aria-invalid', 'false');
          this.urlErrorEl.textContent = '';
        }
      }

      // Re-verify confirmation
      if (this.state.confirmationInput) {
        this.handleConfirmationChange(this.state.confirmationInput);
      } else {
        this.updateSubmitButtonState();
      }
    }

    handleConfirmationChange(value) {
      if (this.state.isSubmitting) return;

      this.state.confirmationInput = value;
      this.clearError();

      if (!this.state.isUrlValid || !this.state.hostname) {
        this.state.isConfirmationValid = false;
        this.state.confirmationError = 'Please enter a valid URL first.';
        this.updateSubmitButtonState();
        return;
      }

      const conf = this.validateConfirmation(value, this.state.hostname);
      if (conf.isValid) {
        this.state.isConfirmationValid = true;
        this.state.confirmationError = '';
        this.confInput.classList.remove('has-error');
        this.confInput.setAttribute('aria-invalid', 'false');
        this.confErrorEl.textContent = '';
      } else {
        this.state.isConfirmationValid = false;
        this.state.confirmationError = conf.error;
        if (value.trim()) {
          this.confInput.classList.add('has-error');
          this.confInput.setAttribute('aria-invalid', 'true');
          this.confErrorEl.textContent = conf.error;
        } else {
          this.confInput.classList.remove('has-error');
          this.confInput.setAttribute('aria-invalid', 'false');
          this.confErrorEl.textContent = '';
        }
      }

      this.updateSubmitButtonState();
    }

    updateSubmitButtonState() {
      const canSubmit = this.state.isUrlValid && this.state.isConfirmationValid && !this.state.isSubmitting;
      this.submitBtn.disabled = !canSubmit;
    }

    setLoading(isLoading, customText = 'Running Security Audit…') {
      this.state.isSubmitting = Boolean(isLoading);

      if (this.state.isSubmitting) {
        this.submitBtn.classList.add('is-loading');
        this.submitBtn.disabled = true;
        this.urlInput.disabled = true;
        this.confInput.disabled = true;
        this.btnScanText.textContent = customText;
        if (this.btnIconSpinner) this.btnIconSpinner.style.display = 'inline-block';
        if (this.btnIconShield) this.btnIconShield.style.display = 'none';
        this.formEl.setAttribute('aria-busy', 'true');
      } else {
        this.submitBtn.classList.remove('is-loading');
        this.urlInput.disabled = false;
        this.confInput.disabled = false;
        this.btnScanText.textContent = 'Run Security Scan';
        if (this.btnIconSpinner) this.btnIconSpinner.style.display = 'none';
        if (this.btnIconShield) this.btnIconShield.style.display = 'inline-block';
        this.formEl.setAttribute('aria-busy', 'false');
        this.updateSubmitButtonState();
      }
    }

    setError(errorType, customMessage = null) {
      this.state.activeErrorType = errorType;
      this.errorMountEl.style.display = 'block';
      this.errorNotice.render(errorType, customMessage);
      this.setLoading(false);
    }

    clearError() {
      this.state.activeErrorType = null;
      if (this.errorMountEl) {
        this.errorMountEl.style.display = 'none';
        this.errorNotice.clear();
      }
    }

    handleSubmit() {
      if (this.state.isSubmitting) return;
      if (!this.state.isUrlValid || !this.state.isConfirmationValid) return;

      const payload = {
        url: this.state.normalizedUrl || this.state.rawUrl,
        hostname: this.state.hostname
      };

      this.onScanSubmit(payload);
    }

    reset() {
      this.state.rawUrl = '';
      this.state.normalizedUrl = '';
      this.state.hostname = '';
      this.state.isUrlValid = false;
      this.state.urlError = '';
      this.state.confirmationInput = '';
      this.state.isConfirmationValid = false;
      this.state.confirmationError = '';
      this.state.isSubmitting = false;
      this.state.activeErrorType = null;

      if (this.urlInput) {
        this.urlInput.value = '';
        this.urlInput.classList.remove('has-error');
        this.urlInput.setAttribute('aria-invalid', 'false');
        this.urlInput.disabled = false;
      }
      if (this.confInput) {
        this.confInput.value = '';
        this.confInput.classList.remove('has-error');
        this.confInput.setAttribute('aria-invalid', 'false');
        this.confInput.disabled = false;
      }
      if (this.urlErrorEl) this.urlErrorEl.textContent = '';
      if (this.confErrorEl) this.confErrorEl.textContent = '';
      if (this.domainMatchHint) {
        this.domainMatchHint.textContent = 'Type hostname to authorize';
      }
      this.clearError();
      this.updateSubmitButtonState();
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
  window.SiteCheck.UrlInputForm = UrlInputForm;

})(window);
