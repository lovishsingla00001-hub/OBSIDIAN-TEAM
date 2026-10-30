import { describe, it, expect } from "vitest";
import rule from "./x-frame-options-missing.js";

describe("Rule: x-frame-options-missing", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("x-frame-options-missing");
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

  it("triggers (returns true) when X-Frame-Options header is missing", () => {
    const mockCtx = {
      url: "https://example.com",
      statusCode: 200,
      headers: {
        "content-type": "text/html; charset=utf-8"
      }
    };

    expect(rule.check(mockCtx)).toBe(true);
  });

  it("triggers when X-Frame-Options header is empty or whitespace-only", () => {
    const emptyCtx = {
      headers: {
        "x-frame-options": ""
      }
    };
    const whitespaceCtx = {
      headers: {
        "x-frame-options": "   "
      }
    };

    expect(rule.check(emptyCtx)).toBe(true);
    expect(rule.check(whitespaceCtx)).toBe(true);
  });

  it("does not trigger (returns false) when X-Frame-Options is valid DENY", () => {
    const denyCtx = {
      headers: {
        "x-frame-options": "DENY"
      }
    };

    expect(rule.check(denyCtx)).toBe(false);
  });

  it("does not trigger (returns false) when X-Frame-Options is valid SAMEORIGIN", () => {
    const sameoriginCtx = {
      headers: {
        "x-frame-options": "SAMEORIGIN"
      }
    };

    expect(rule.check(sameoriginCtx)).toBe(false);
  });

  it("handles case-insensitive values and surrounding whitespace safely", () => {
    const lowercaseDenyCtx = {
      headers: {
        "x-frame-options": "deny"
      }
    };
    const mixedCaseSameOriginCtx = {
      headers: {
        "x-frame-options": "SameOrigin"
      }
    };
    const whitespaceDenyCtx = {
      headers: {
        "x-frame-options": "  DENY  "
      }
    };

    expect(rule.check(lowercaseDenyCtx)).toBe(false);
    expect(rule.check(mixedCaseSameOriginCtx)).toBe(false);
    expect(rule.check(whitespaceDenyCtx)).toBe(false);
  });

  it("triggers when X-Frame-Options contains an invalid or deprecated directive", () => {
    const invalidDirectives = ["ALLOW", "NONE", "1", "ALLOWALL", "TRUE"];

    for (const directive of invalidDirectives) {
      const invalidCtx = {
        headers: {
          "x-frame-options": directive
        }
      };
      expect(rule.check(invalidCtx)).toBe(true);
    }
  });

  it("gracefully returns false on null, undefined, or empty context", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
    expect(rule.check({ headers: undefined })).toBe(false);
  });
});

