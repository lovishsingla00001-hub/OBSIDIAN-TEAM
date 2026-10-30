import { describe, it, expect } from "vitest";
import rule from "./hsts-missing.js";

describe("Rule: hsts-missing", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("hsts-missing");
    expect(rule.category).toBe("headers");
    expect(rule.severity).toBe("medium");
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

  it("Test 1: triggers (returns true) when Strict-Transport-Security is missing on HTTPS", () => {
    const mockCtx = {
      url: "https://example.com",
      finalUrl: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8"
      },
      usedHttps: true
    };

    expect(rule.check(mockCtx)).toBe(true);
  });

  it("Test 2: does not trigger (returns false) when Strict-Transport-Security is present on HTTPS", () => {
    const mockCtx = {
      url: "https://example.com",
      finalUrl: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000; includeSubDomains"
      },
      usedHttps: true
    };

    expect(rule.check(mockCtx)).toBe(false);
  });

  it("does not report missing HSTS when the website is plain HTTP (has not reached HTTPS)", () => {
    const httpCtx = {
      url: "http://example.com",
      finalUrl: "http://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8"
      },
      usedHttps: false
    };

    // Should return false because HSTS cannot protect or be enforced on a plain HTTP site
    expect(rule.check(httpCtx)).toBe(false);
  });

  it("triggers when Strict-Transport-Security is empty or whitespace on HTTPS", () => {
    const emptyCtx = {
      usedHttps: true,
      headers: {
        "strict-transport-security": ""
      }
    };
    const whitespaceCtx = {
      usedHttps: true,
      headers: {
        "strict-transport-security": "   "
      }
    };

    expect(rule.check(emptyCtx)).toBe(true);
    expect(rule.check(whitespaceCtx)).toBe(true);
  });

  it("correctly identifies HTTPS via finalUrl or url when usedHttps flag is omitted", () => {
    const finalUrlHttpsCtx = {
      finalUrl: "https://secure.example.com",
      headers: {}
    };
    const initialUrlHttpsCtx = {
      url: "https://secure.example.com",
      headers: {}
    };

    expect(rule.check(finalUrlHttpsCtx)).toBe(true);
    expect(rule.check(initialUrlHttpsCtx)).toBe(true);
  });

  it("gracefully returns false when context or headers are null, undefined, or missing", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
    expect(rule.check({ headers: undefined })).toBe(false);
  });
});

