import { describe, it, expect } from "vitest";
import rule from "./csp-missing.js";

describe("Rule: csp-missing", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("csp-missing");
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

  it("Test 1: triggers (returns true) when Content-Security-Policy is completely missing", () => {
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

  it("Test 2: does not trigger (returns false) when Content-Security-Policy is present", () => {
    const mockCtx = {
      url: "https://example.com",
      finalUrl: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'; script-src 'self'"
      },
      usedHttps: true
    };

    expect(rule.check(mockCtx)).toBe(false);
  });

  it("triggers when Content-Security-Policy is an empty string or whitespace only", () => {
    const emptyCtx = {
      headers: {
        "content-security-policy": ""
      }
    };
    const whitespaceCtx = {
      headers: {
        "content-security-policy": "   "
      }
    };

    expect(rule.check(emptyCtx)).toBe(true);
    expect(rule.check(whitespaceCtx)).toBe(true);
  });

  it("triggers when only Content-Security-Policy-Report-Only is present (not enforced CSP)", () => {
    const reportOnlyCtx = {
      url: "https://example.com",
      headers: {
        "content-security-policy-report-only": "default-src 'self'; report-uri /csp-report"
      }
    };

    expect(rule.check(reportOnlyCtx)).toBe(true);
  });

  it("gracefully returns false when context or headers are null, undefined, or missing", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
    expect(rule.check({ headers: undefined })).toBe(false);
  });
});

