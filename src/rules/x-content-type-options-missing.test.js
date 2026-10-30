import { describe, it, expect } from "vitest";
import rule from "./x-content-type-options-missing.js";

describe("Rule: x-content-type-options-missing", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("x-content-type-options-missing");
    expect(rule.category).toBe("headers");
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

  it("Test 1: triggers (returns true) when X-Content-Type-Options is missing", () => {
    const mockCtx = {
      url: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8"
      }
    };

    expect(rule.check(mockCtx)).toBe(true);
  });

  it("Test 2: does not trigger (returns false) when X-Content-Type-Options is 'nosniff'", () => {
    const mockCtx = {
      url: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "x-content-type-options": "nosniff"
      }
    };

    expect(rule.check(mockCtx)).toBe(false);
  });

  it("does not trigger when 'nosniff' has mixed casing or surrounding whitespace", () => {
    const mixedCaseCtx = {
      headers: {
        "x-content-type-options": "noSniff"
      }
    };
    const whitespaceCtx = {
      headers: {
        "x-content-type-options": "  nosniff  "
      }
    };

    expect(rule.check(mixedCaseCtx)).toBe(false);
    expect(rule.check(whitespaceCtx)).toBe(false);
  });

  it("triggers when header value is empty or not 'nosniff'", () => {
    const emptyCtx = {
      headers: {
        "x-content-type-options": ""
      }
    };
    const invalidCtx = {
      headers: {
        "x-content-type-options": "none"
      }
    };

    expect(rule.check(emptyCtx)).toBe(true);
    expect(rule.check(invalidCtx)).toBe(true);
  });

  it("gracefully returns false when context or headers are null, undefined, or missing", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
    expect(rule.check({ headers: undefined })).toBe(false);
  });
});

