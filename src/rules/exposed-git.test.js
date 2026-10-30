import { describe, it, expect } from "vitest";
import rule from "./exposed-git.js";

describe("Rule: exposed-git", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("exposed-git");
    expect(rule.category).toBe("exposure");
    expect(rule.severity).toBe("high");
    expect(typeof rule.check).toBe("function");
    expect(typeof rule.explain).toBe("string");
    expect(rule.explain.length).toBeGreaterThan(20);
    expect(typeof rule.owasp).toBe("string");
    expect(rule.owasp).toContain("A01:2021");
    expect(rule.fixes).toBeDefined();
    expect(typeof rule.fixes.express).toBe("string");
    expect(typeof rule.fixes.nginx).toBe("string");
    expect(typeof rule.fixes.django).toBe("string");
    expect(typeof rule.fixes.flask).toBe("string");
  });

  it("Test 1: triggers (returns true) when /.git/HEAD is publicly accessible (status 200)", () => {
    const exposedCtx = {
      url: "https://example.com",
      statusCode: 200,
      wellKnownPaths: {
        "/.git/HEAD": { status: 200 },
        "/.env": { status: 404 }
      }
    };

    expect(rule.check(exposedCtx)).toBe(true);
  });

  it("Test 2: does not trigger (returns false) when /.git/HEAD returns 404 Not Found", () => {
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

  it("does not trigger when Git path is blocked with 403 Forbidden", () => {
    const forbiddenCtx = {
      url: "https://example.com",
      wellKnownPaths: {
        "/.git/HEAD": { status: 403 }
      }
    };

    expect(rule.check(forbiddenCtx)).toBe(false);
  });

  it("triggers when other Git endpoints such as /.git/config return 200", () => {
    const configExposedCtx = {
      wellKnownPaths: {
        "/.git/HEAD": { status: 404 },
        "/.git/config": { status: 200 }
      }
    };

    expect(rule.check(configExposedCtx)).toBe(true);
  });

  it("triggers when dynamic sub-paths under /.git/ return 200", () => {
    const subPathCtx = {
      wellKnownPaths: {
        "/.git/logs/HEAD": { status: 200 }
      }
    };

    expect(rule.check(subPathCtx)).toBe(true);
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

