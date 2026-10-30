import { describe, it, expect } from "vitest";
import rule from "./http-not-redirected.js";

describe("Rule: http-not-redirected", () => {
  it("conforms to the SiteCheck Rule Contract structure", () => {
    expect(rule.id).toBe("http-not-redirected");
    expect(rule.category).toBe("tls");
    expect(rule.severity).toBe("medium");
    expect(typeof rule.check).toBe("function");
    expect(typeof rule.explain).toBe("string");
    expect(rule.explain.length).toBeGreaterThan(20);
    expect(typeof rule.owasp).toBe("string");
    expect(rule.owasp).toContain("A02:2021");
    expect(rule.fixes).toBeDefined();
    expect(typeof rule.fixes.express).toBe("string");
    expect(typeof rule.fixes.nginx).toBe("string");
    expect(typeof rule.fixes.django).toBe("string");
    expect(typeof rule.fixes.flask).toBe("string");
  });

  it("Test 1: triggers (returns true) when HTTP does not redirect to HTTPS while HTTPS is available", () => {
    const mockCtx = {
      url: "http://example.com",
      finalUrl: "http://example.com",
      statusCode: 200,
      usedHttps: true,
      redirectedToHttps: false,
      tls: { valid: true, daysUntilExpiry: 90 }
    };

    expect(rule.check(mockCtx)).toBe(true);
  });

  it("Test 2: does not trigger (returns false) when HTTP correctly redirects to HTTPS", () => {
    const mockCtx = {
      url: "http://example.com",
      finalUrl: "https://example.com/",
      statusCode: 200,
      usedHttps: true,
      redirectedToHttps: true,
      tls: { valid: true, daysUntilExpiry: 90 }
    };

    expect(rule.check(mockCtx)).toBe(false);
  });

  it("does not flag when HTTPS is completely unavailable on the host", () => {
    const noHttpsCtx = {
      url: "http://example.com",
      finalUrl: "http://example.com",
      statusCode: 200,
      usedHttps: false,
      redirectedToHttps: false,
      tls: null
    };

    const invalidTlsCtx = {
      url: "http://example.com",
      finalUrl: "http://example.com",
      statusCode: 200,
      usedHttps: false,
      redirectedToHttps: false,
      tls: { valid: false }
    };

    expect(rule.check(noHttpsCtx)).toBe(false);
    expect(rule.check(invalidTlsCtx)).toBe(false);
  });

  it("triggers when initial URL and final URL are both HTTP while host has valid TLS", () => {
    const httpOnlyCtx = {
      url: "http://example.com/app",
      finalUrl: "http://example.com/app",
      tls: { valid: true }
    };

    expect(rule.check(httpOnlyCtx)).toBe(true);
  });

  it("does not trigger when initial URL is HTTP and final URL successfully upgraded to HTTPS", () => {
    const upgradedCtx = {
      url: "http://example.com",
      finalUrl: "https://example.com/dashboard",
      usedHttps: true
    };

    expect(rule.check(upgradedCtx)).toBe(false);
  });

  it("does not flag when target is already HTTPS with no failure evidence", () => {
    const directHttpsCtx = {
      url: "https://example.com",
      finalUrl: "https://example.com",
      usedHttps: true,
      tls: { valid: true }
    };

    expect(rule.check(directHttpsCtx)).toBe(false);
  });

  it("gracefully returns false on null, undefined, or empty context", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check(undefined)).toBe(false);
    expect(rule.check({})).toBe(false);
  });
});

