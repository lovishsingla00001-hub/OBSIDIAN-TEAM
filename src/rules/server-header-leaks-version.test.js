import { describe, it, expect } from "vitest";
import rule from "./server-header-leaks-version.js";

describe("Rule: server-header-leaks-version", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("server-header-leaks-version");
    expect(rule.category).toBe("hygiene");
    expect(rule.severity).toBe("low");
    expect(typeof rule.check).toBe("function");
    expect(typeof rule.explain).toBe("string");
    expect(rule.explain.length).toBeGreaterThan(20);
    expect(typeof rule.owasp).toBe("string");
    expect(rule.owasp).toContain("A05:2021");
    expect(rule.fixes).toBeDefined();
    expect(typeof rule.fixes.express).toBe("string");
    expect(typeof rule.fixes.nginx).toBe("string");
    expect(typeof rule.fixes.django).toBe("string");
    expect(typeof rule.fixes.flask).toBe("string");
  });

  it("does not trigger (returns false) when Server header is missing", () => {
    const mockCtx = {
      headers: {
        "content-type": "text/html"
      }
    };

    expect(rule.check(mockCtx)).toBe(false);
  });

  it("does not trigger when Server header is empty or whitespace-only", () => {
    const emptyCtx = {
      headers: {
        server: ""
      }
    };
    const whitespaceCtx = {
      headers: {
        server: "   "
      }
    };

    expect(rule.check(emptyCtx)).toBe(false);
    expect(rule.check(whitespaceCtx)).toBe(false);
  });

  it("does not trigger on generic Server values that do not disclose a version", () => {
    const genericServers = [
      "nginx",
      "Apache",
      "cloudflare",
      "cloudflare-nginx",
      "gunicorn",
      "LiteSpeed",
      "Microsoft-IIS",
      "AmazonS3",
      "Caddy",
      "webserver"
    ];

    for (const serverVal of genericServers) {
      const mockCtx = {
        headers: {
          server: serverVal
        }
      };
      expect(rule.check(mockCtx)).toBe(false);
    }
  });

  it("triggers (returns true) when Server header discloses common software versions", () => {
    const versionedServers = [
      "nginx/1.18.0",
      "Apache/2.4.41 (Ubuntu)",
      "Microsoft-IIS/10.0",
      "LiteSpeed/1.7.16",
      "gunicorn/20.1.0",
      "Caddy/v2.6.4",
      "openresty/1.19.9.1",
      "envoy/1.22.0",
      "Apache/2.4"
    ];

    for (const serverVal of versionedServers) {
      const mockCtx = {
        headers: {
          server: serverVal
        }
      };
      expect(rule.check(mockCtx)).toBe(true);
    }
  });

  it("triggers when multiple products and versions are leaked", () => {
    const multiVersionCtx = {
      headers: {
        server: "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d"
      }
    };

    const pythonWerkzeugCtx = {
      headers: {
        server: "Werkzeug/3.0.1 Python/3.11.4"
      }
    };

    expect(rule.check(multiVersionCtx)).toBe(true);
    expect(rule.check(pythonWerkzeugCtx)).toBe(true);
  });

  it("handles case and whitespace edge cases safely", () => {
    const whitespaceVersionCtx = {
      headers: {
        server: "  nginx/1.24.0  "
      }
    };
    const uppercaseCtx = {
      headers: {
        server: "APACHE/2.4.52"
      }
    };

    expect(rule.check(whitespaceVersionCtx)).toBe(true);
    expect(rule.check(uppercaseCtx)).toBe(true);
  });

  it("gracefully returns false on null, undefined, or empty context", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
    expect(rule.check({ headers: undefined })).toBe(false);
  });
});

