# Contributing to SiteCheck

Thank you for your interest in contributing to **SiteCheck**! SiteCheck is an open-source, read-only website security and privacy checker designed to analyze publicly available website signals and produce clear, beginner-friendly remediation reports.

This guide outlines everything you need to know to write, test, and submit security rules to SiteCheck.

---

## 1. Project Introduction

SiteCheck helps developers, students, and system administrators understand their website's security posture without needing specialized cybersecurity training. The architecture separates data collection from rule evaluation:

- **Fetcher (`fetchSiteContext`)**: Gathers public website data (HTTP response headers, status codes, HTML body, TLS parameters, and well-known path statuses).
- **Rules Engine**: Iterates over isolated, modular security rule definitions and executes their `check(ctx)` logic against the collected context.
- **Reporting & Remediation**: Surfaces actionable findings accompanied by copy-paste remediation configurations for popular frameworks.

Every rule is intentionally isolated into its own file so anyone can contribute a new security check without deep knowledge of the engine internals.

---

## 2. Where Security Rules Belong

All security rules reside in the `src/rules/` directory:

```text
src/rules/
├── _template.js           # Starter template for authors (not loaded as a rule)
├── csp-missing.js         # Content-Security-Policy check
├── csp-missing.test.js    # Vitest test suite for csp-missing
├── hsts-missing.js        # Strict-Transport-Security check
└── hsts-missing.test.js   # Vitest test suite for hsts-missing
```

- Each rule file must be named `<rule-id>.js` (matching the rule's `id` property).
- Each rule's test file should be co-located as `<rule-id>.test.js`.
- Template or helper files must be prefixed with an underscore (`_`) so the engine does not treat them as executable rules.

---

## 3. How to Create a New Rule

Creating a new rule takes just a few steps:

1. **Copy the Template**:
   ```bash
   cp src/rules/_template.js src/rules/your-rule-id.js
   ```
2. **Configure Metadata**:
   Update `id`, `category`, `severity`, and `owasp`.
3. **Implement the Check**:
   Write the evaluation logic inside `check(ctx)`.
4. **Write Plain-English Explanations**:
   Fill in `explain` with simple, jargon-free context explaining why this check matters.
5. **Add Remediation Snippets**:
   Provide tested, copy-paste snippets for **Express**, **Nginx**, **Django**, and **Flask**.
6. **Write Unit Tests**:
   Create `src/rules/your-rule-id.test.js` using Vitest with mock context objects.
7. **Verify Tests**:
   ```bash
   npx vitest run src/rules/your-rule-id.test.js
   ```

---

## 4. Rule Structure Documentation

Every rule file must export a single JavaScript object adhering to this schema:

```javascript
export default {
  id: "unique-rule-id",

  category: "headers",

  severity: "medium",

  check(ctx) {
    return false;
  },

  explain: "Beginner-friendly explanation.",

  owasp: "A05:2021-Security Misconfiguration",

  fixes: {
    express: "",
    nginx: "",
    django: "",
    flask: ""
  }
};
```

### Allowed Categories
- `headers` — Missing or weak HTTP security headers (e.g., CSP, HSTS, X-Content-Type-Options).
- `tls` — Certificate validity, cipher suite issues, expiration risks.
- `exposure` — Leaked sensitive files (e.g., `.git`, `.env`, backup archives).
- `privacy` — Tracking scripts, insecure cookies, referrer leakage.
- `hygiene` — Software version disclosures, outdated server signatures.

### Allowed Severity Levels
- `high` — Direct security compromise risk or immediate vulnerability (e.g., exposed `.env` file containing credentials).
- `medium` — Significant defense-in-depth weakness or missing critical security control (e.g., missing CSP or HSTS).
- `low` — Best practice deviation or informational hygiene finding (e.g., leaking server banner version).

---

## 5. How `check(ctx)` Works

The `check(ctx)` method receives a frozen context object containing data already collected by the crawler:

```javascript
ctx = {
  url: "http://example.com",
  finalUrl: "https://example.com/",
  statusCode: 200,

  headers: {
    // Note: All header keys are normalized to lowercase
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains"
  },

  html: "<!DOCTYPE html><html>...</html>",

  usedHttps: true,
  redirectedToHttps: true,

  tls: {
    valid: true,
    daysUntilExpiry: 90
  },

  wellKnownPaths: {
    "/.git/HEAD": { status: 404 },
    "/.env": { status: 404 }
  }
};
```

### Return Values
- **`true`**: The security problem **is detected** (flaw found; trigger warning).
- **`false`**: The security protection is present, or there is **insufficient evidence** to confirm a vulnerability.

> [!IMPORTANT]
> Never guess or assume. If a field in `ctx` is missing, `null`, or undefined, do not throw an exception and do not report a false positive. Return `false`.

---

## 6. Read-Only Security Requirements (Absolute Security Boundary)

SiteCheck operates strictly as a **passive, read-only** scanner.

Under **no circumstances** may a rule execute any active network requests or probing.

The `check(ctx)` function must **NEVER**:
- Make HTTP requests (`fetch()`, `axios`, `http.get`, etc.).
- Use DNS lookups or external APIs.
- Probe additional URLs or query string parameters.
- Send attack payloads or exploit scripts.
- Perform directory traversal or fuzzing.
- Attempt authentication bypass.
- Modify website resources or remote states.

> [!CAUTION]
> If your rule requires data that is not currently present in `ctx`, **DO NOT** attempt to fetch it yourself. Document the requirement in an issue or PR so the context collector (`fetchSiteContext()`) can gather it safely beforehand.

---

## 7. How to Write Beginner-Friendly Explanations

SiteCheck reports are read by developers of varying experience levels. Avoid dense jargon without explaining its real-world consequence.

### Principles:
1. **Explain the Purpose**: What does this protection do in plain terms?
2. **Explain the Risk**: What could an attacker do if this protection is missing?
3. **Avoid Fearmongering**: Accurately describe the impact without exaggerating.

### Example:
- **Poor**: *"RFC 6797 violation. Missing STS directive allows SSL stripping attacks."*
- **Good**: *"HTTP Strict Transport Security (HSTS) instructs web browsers to only communicate with your website over secure HTTPS connections. Without HSTS, an attacker on the same local network (such as public Wi-Fi) could downgrade connections to unencrypted HTTP and eavesdrop on user traffic."*

---

## 8. Framework-Specific Remediation Requirements

Every rule must provide functional, idiomatic remediation configuration for four major web application stacks under the `fixes` object:

1. **`express`**: Node.js / Express code, preferably using `helmet` middleware or direct header setters.
2. **`nginx`**: Configuration directives for `nginx.conf` (`server` or `location` blocks).
3. **`django`**: Python / Django configuration in `settings.py` or middleware.
4. **`flask`**: Python / Flask snippets using `Flask-Talisman` or `@app.after_request` hooks.

All code snippets should be ready for a developer to copy and paste directly into their project with minimal adaptation.

---

## 9. How to Write Vitest Tests

Every rule must be thoroughly tested using [Vitest](https://vitest.dev/). Tests must be deterministic, isolated, and execute with zero network calls using mocked `ctx` fixtures.

### Required Test Coverage
Each rule test file must include at least:
1. **Trigger Test**: Asserts that `check(ctx)` returns `true` when the protection is absent or ineffective.
2. **Pass Test**: Asserts that `check(ctx)` returns `false` when the protection is correctly configured.
3. **Edge Case Tests**: Validates behavior when optional context fields (e.g., `tls`, `headers`) are `null`, empty, or undefined.

### Example Test File (`src/rules/example.test.js`)
```javascript
import { describe, it, expect } from "vitest";
import rule from "./example.js";

describe("Rule: example-rule", () => {
  it("triggers (returns true) when protection is missing", () => {
    const mockCtx = {
      headers: {}
    };
    expect(rule.check(mockCtx)).toBe(true);
  });

  it("passes (returns false) when protection is present", () => {
    const mockCtx = {
      headers: {
        "x-example-header": "secure-value"
      }
    };
    expect(rule.check(mockCtx)).toBe(false);
  });

  it("safely handles null or undefined context", () => {
    expect(rule.check(null)).toBe(false);
    expect(rule.check({})).toBe(false);
    expect(rule.check({ headers: null })).toBe(false);
  });
});
```

To run your tests:
```bash
npx vitest run src/rules/<rule-id>.test.js
```

---

## 10. OWASP Reference Guidance

Map your rule to the most accurate category from the **OWASP Top 10 (2021)** or relevant **OWASP ASVS** standard:

- `A01:2021-Broken Access Control` — Unauthorized path or file exposure (e.g., `.git`, admin interfaces).
- `A02:2021-Cryptographic Failures` — Expired certificates, plain HTTP transmission, weak TLS.
- `A03:2021-Injection` — XSS mitigations, missing CSP script restrictions.
- `A05:2021-Security Misconfiguration` — Missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options), default credentials, error disclosure.
- `A07:2021-Identification and Authentication Failures` — Exposed `.env` secrets, missing session security.

Format: Use the official identifier and title, e.g., `"A05:2021-Security Misconfiguration"`.

---

## 11. Contributor Checklist

Before submitting a new rule, verify each item:

- [ ] File exists at `src/rules/<rule-id>.js`.
- [ ] Export is an ES Module (`export default { ... }`).
- [ ] `id` matches the filename (kebab-case) and is unique.
- [ ] `category` is one of: `headers`, `tls`, `exposure`, `privacy`, `hygiene`.
- [ ] `severity` is one of: `high`, `medium`, `low`.
- [ ] `check(ctx)` makes **zero** network requests or external calls.
- [ ] `check(ctx)` returns `true` only when the security flaw exists.
- [ ] `check(ctx)` gracefully handles `null`, `undefined`, or empty properties without throwing.
- [ ] `explain` provides a clear, beginner-friendly explanation.
- [ ] `owasp` references a recognized standard.
- [ ] `fixes` contains practical snippets for `express`, `nginx`, `django`, and `flask`.
- [ ] Vitest unit tests in `src/rules/<rule-id>.test.js` pass with 100% test success.
- [ ] No files outside `src/rules/` or `docs/` were modified.

---

## 12. Instructions for Submitting Contributions

1. Create a feature branch:
   ```bash
   git checkout -b rule/my-new-rule
   ```
2. Implement your rule and corresponding tests.
3. Run the test suite:
   ```bash
   npx vitest run
   ```
4. Commit your changes with a descriptive message:
   ```bash
   git add src/rules/my-new-rule.js src/rules/my-new-rule.test.js
   git commit -m "feat(rules): add my-new-rule security check"
   ```
5. Push to your fork or branch and open a Pull Request against `main`. Provide a brief summary of what the rule detects and evidence of passing unit tests.

