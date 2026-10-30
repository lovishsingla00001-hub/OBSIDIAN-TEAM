import { describe, it, expect } from "vitest";
import rule from "./exposed-env.js";

describe("Rule: exposed-env", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("exposed-env");
    expect(rule.category).toBe("exposure");
    expect(rule.severity).toBe("high");
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

  it("Test 1: triggers (returns true) when /.env is publicly accessible (status 200)", () => {
    const exposedCtx = {
      url: "https://example.com",
      statusCode: 200,
      wellKnownPaths: {
        "/.git/HEAD": { status: 404 },
        "/.env": { status: 200 }
      }
    };

    expect(rule.check(exposedCtx)).toBe(true);
  });

  it("Test 2: does not trigger (returns false) when /.env returns 404 Not Found", () => {
    const protectedCtx = {
      url: "https://example.com",
      statusCode: 200,
      wellKnownPaths: {
        "/.git/HEAD": { status: 404 },
        "/.env": { status: 404 }
      }
    };

    expect(rule.check(protectedCtx)).toBe(false);
  });

  it("does not trigger when /.env returns 403 Forbidden", () => {
    const forbiddenCtx = {
      wellKnownPaths: {
        "/.env": { status: 403 }
      }
    };

    expect(rule.check(forbiddenCtx)).toBe(false);
  });

  it("triggers when alternative env paths like /.env.local or /.env.production return 200", () => {
    const localEnvCtx = {
      wellKnownPaths: {
        "/.env": { status: 404 },
        "/.env.local": { status: 200 }
      }
    };

    const prodEnvCtx = {
      wellKnownPaths: {
        "/.env": { status: 404 },
        "/.env.production": { status: 200 }
      }
    };

    expect(rule.check(localEnvCtx)).toBe(true);
    expect(rule.check(prodEnvCtx)).toBe(true);
  });

  it("gracefully returns false when context or wellKnownPaths are null, undefined, or missing", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ wellKnownPaths: null })).toBe(false);
    expect(rule.check({ wellKnownPaths: undefined })).toBe(false);
    expect(rule.check({ wellKnownPaths: {} })).toBe(false);
  });
});

