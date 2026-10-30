/**
 * SiteCheck - Backend Network Integration Client (apiClient.js)
 * Team: Obsidian
 * 
 * Communicates with the SiteCheck backend API endpoint (/api/scan)
 * to run security audits, retrieve scan history, and normalize network errors.
 */

(function (window) {
  'use strict';

  class ApiClient {
    constructor(options = {}) {
      // Determine default endpoint: relative if hosted together, or localhost:3001
      const isPort8000Or3000 = window.location && (window.location.port === '8000' || window.location.port === '3000');
      const defaultUrl = (window.location && window.location.origin && window.location.origin.startsWith('http') && !isPort8000Or3000)
        ? `${window.location.origin}/api/scan`
        : 'http://localhost:3001/api/scan';

      this.endpointUrl = options.endpointUrl || defaultUrl;
      this.timeoutMs = options.timeoutMs || 60000;
    }

    getEndpointUrl() {
      return this.endpointUrl;
    }

    setEndpointUrl(newUrl) {
      if (newUrl && typeof newUrl === 'string') {
        this.endpointUrl = newUrl.trim();
      }
    }

    /**
     * Executes a security audit request against the backend.
     * 
     * @param {string} url - Target website URL.
     * @param {string} hostname - Domain confirmation token.
     * @returns {Promise<{ success: boolean, data?: Object, errorType?: string, message?: string }>}
     */
    async scan(url, hostname) {
      if (!url) {
        return {
          success: false,
          errorType: 'INVALID_URL',
          message: 'Target URL cannot be empty.'
        };
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await fetch(this.endpointUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            url: url,
            domainConfirmation: hostname,
            confirmation: hostname
          }),
          signal: controller.signal
        });

        clearTimeout(timer);

        let body = null;
        try {
          body = await response.json();
        } catch {
          body = null;
        }

        if (response.ok && body && (body.success !== false)) {
          const scanReport = body.data || body;
          if (body.reportId) {
            scanReport.id = body.reportId;
          }
          scanReport.databaseSaved = Boolean(body.databaseSaved);
          // Ensure isMock is false for live backend reports
          scanReport.isMock = false;
          return {
            success: true,
            data: scanReport,
            reportId: body.reportId || scanReport.id || null
          };
        }

        // Handle error responses
        if (response.status === 400) {
          return {
            success: false,
            errorType: 'INVALID_URL',
            message: (body && body.error) || 'Invalid URL or domain confirmation mismatch.'
          };
        } else if (response.status === 429) {
          return {
            success: false,
            errorType: 'RATE_LIMITED',
            message: (body && body.error) || 'Rate limit exceeded: 1 scan per domain per 60 seconds.'
          };
        } else if (response.status === 504 || response.status === 502) {
          return {
            success: false,
            errorType: 'UNREACHABLE_HOST',
            message: (body && body.error) || 'Target web server did not respond or timed out.'
          };
        } else {
          return {
            success: false,
            errorType: 'SERVER_ERROR',
            message: (body && body.error) || `Backend scan failure (HTTP ${response.status}).`
          };
        }

      } catch (err) {
        clearTimeout(timer);

        if (err.name === 'AbortError') {
          return {
            success: false,
            errorType: 'UNREACHABLE_HOST',
            message: 'Scan timed out after 25 seconds waiting for the target website.'
          };
        }

        // Network connection error (e.g. backend server not yet started on port 3001)
        return {
          success: false,
          errorType: 'SERVER_ERROR',
          message: `Unable to connect to security backend at ${this.endpointUrl}. Ensure the SiteCheck server is running.`
        };
      }
    }

    /**
     * Retrieves past audit history for a domain from Supabase backend.
     */
    async getHistory(hostname) {
      if (!hostname) return { success: false, history: [] };
      try {
        const baseUrl = this.endpointUrl.replace(/\/api\/scan\/?$/, '');
        const res = await fetch(`${baseUrl}/api/history?hostname=${encodeURIComponent(hostname)}`);
        if (res.ok) {
          const json = await res.json();
          return { success: true, history: json.history || [] };
        }
      } catch {}
      return { success: false, history: [] };
    }

    /**
     * Retrieves recent public audits across all domains.
     */
    async getRecentScans() {
      try {
        const baseUrl = this.endpointUrl.replace(/\/api\/scan\/?$/, '');
        const res = await fetch(`${baseUrl}/api/recent`);
        if (res.ok) {
          const json = await res.json();
          return { success: true, scans: json.scans || [] };
        }
      } catch {}
      return { success: false, scans: [] };
    }
  }

  // Export singleton and class
  window.SiteCheck = window.SiteCheck || {};
  window.SiteCheck.ApiClient = ApiClient;
  window.SiteCheck.apiClient = new ApiClient();

})(window);
