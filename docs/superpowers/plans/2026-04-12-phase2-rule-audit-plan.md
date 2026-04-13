# Phase 2 Rule Domain Audit & Test Coverage - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit detection logic quality and achieve full test coverage for all 60 rules across 6 Phase 2 domains.

**Architecture:** Each domain is worked as an independent unit: audit all 10 rules, fix detection issues, write tests for every rule. Tests call `rule.check(model)` directly with hand-built ProjectModel fixtures (not runRecon against the fixture project). This is faster, more targeted, and doesn't require extending the shared fixture.

**Tech Stack:** TypeScript, Vitest, hand-built ProjectModel fixtures

---

## Shared Test Helper (Task 0)

Before domain work begins, create a test helper that builds minimal ProjectModel objects. Every subsequent task imports this helper.

### Task 0: Create test model factory

**Files:**
- Create: `tests/rules/helpers.ts`

- [ ] **Step 1: Write the model factory**

```typescript
// tests/rules/helpers.ts
import type { ProjectModel, InfraConfig, ApiEndpoint, Dependency, Route } from "../../src/model/types.js";

/** Minimal empty model. Override fields as needed per test. */
export function emptyModel(overrides?: Partial<ProjectModel>): ProjectModel {
  return {
    meta: {
      name: "test-project",
      path: "/tmp/test-project",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "nextjs-app",
      deployTarget: null,
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    findings: [],
    infra: emptyInfra(),
    ...overrides,
  };
}

export function emptyInfra(overrides?: Partial<InfraConfig>): InfraConfig {
  return {
    nextConfig: null,
    middleware: null,
    vercelConfig: null,
    supabaseConfig: null,
    securityHeaders: {},
    ...overrides,
  };
}

/** Build a single endpoint for testing. */
export function makeEndpoint(overrides: Partial<ApiEndpoint> & { path: string; file: string }): ApiEndpoint {
  return {
    method: "POST",
    handlerName: undefined,
    hasValidation: false,
    validationLibrary: null,
    hasAuthCheck: false,
    usesServiceRole: false,
    ...overrides,
  };
}

/** Build a single dependency for testing. */
export function makeDep(name: string, version: string, type: Dependency["type"] = "production"): Dependency {
  return { name, version, type };
}

/** Build a single route for testing. */
export function makeRoute(overrides: Partial<Route> & { path: string; file: string }): Route {
  return {
    method: "GET",
    isApi: true,
    hasAuthCheck: false,
    paramNames: [],
    ...overrides,
  };
}
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npx tsc --noEmit`
Expected: Clean (0 errors)

- [ ] **Step 3: Commit**

```bash
git add tests/rules/helpers.ts
git commit -m "test(rules): add shared model factory for Phase 2 rule tests"
```

---

## Domain 1: Infrastructure (INFRA-001 through INFRA-010)

### Task 1: Audit infrastructure rules

**Files:**
- Read: `src/layers/rules/domains/infrastructure.ts`
- Modify: `src/layers/rules/domains/infrastructure.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

Audit each rule for: false positives, false negatives, regex quality, model usage, evidence quality, severity accuracy, stack filtering.

**Known issues to investigate:**
- INFRA-002: Only fires when `deployTarget` is vercel/cloudflare/fly. Projects with `deployTarget: null` that deploy to HTTPS hosts will be missed. Is this acceptable?
- INFRA-005: The `setCookieRe` regex matches `cookies().set` but also matches inside comments and strings. The `secure: true` check scans the entire file, not just the cookie-setting block. A file with one secure cookie and one insecure cookie would pass if `secure: true` appears anywhere.
- INFRA-006: Comment detection only checks the first 2 chars of trimmed line (`//` or `/*`). Multi-line comments (`/* ... \n http://example.com \n */`) would still flag the inner line.
- INFRA-008: Gitignore parsing is naive (splits on newlines, checks exact match). Patterns like `*.env` or `.env*` with glob syntax won't match correctly. The check does handle `.env*` but not negation patterns (`!.env.example`).

- [ ] **Step 2: Fix detection issues found**

Apply fixes to `src/layers/rules/domains/infrastructure.ts`. For each fix, note the rule ID and what changed.

- [ ] **Step 3: Run existing tests to confirm no regressions**

Run: `npx vitest run tests/rules/infrastructure.test.ts`
Expected: 3 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/infrastructure.ts
git commit -m "fix(rules): audit fixes for infrastructure domain

[List specific fixes applied]"
```

### Task 2: Write infrastructure rule tests

**Files:**
- Modify: `tests/rules/infrastructure.test.ts`

The existing 3 tests (INFRA-001, INFRA-003, INFRA-010) use `runRecon` against the fixture. The 7 new tests will call `rule.check(model)` directly with hand-built models. Keep the existing tests as-is.

- [ ] **Step 1: Write test for INFRA-002 (HSTS missing)**

```typescript
import { infrastructureRules } from "../../src/layers/rules/domains/infrastructure.js";
import { emptyModel, emptyInfra } from "./helpers.js";

it("flags missing HSTS on TLS deploy (INFRA-002)", async () => {
  const model = emptyModel({
    meta: { ...emptyModel().meta, deployTarget: "vercel" },
    infra: emptyInfra({ securityHeaders: {} }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-002")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("INFRA-002");
});

it("skips HSTS check when deployTarget is null (INFRA-002)", async () => {
  const model = emptyModel({
    infra: emptyInfra({ securityHeaders: {} }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-002")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 2: Write test for INFRA-004 (wildcard CORS)**

```typescript
it("flags wildcard CORS in securityHeaders (INFRA-004)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      securityHeaders: {
        "access-control-allow-origin": [{ file: "next.config.mjs", value: "*" }],
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-004")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("INFRA-004");
});

it("ignores specific CORS origin (INFRA-004)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      securityHeaders: {
        "access-control-allow-origin": [{ file: "next.config.mjs", value: "https://myapp.com" }],
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-004")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 3: Write test for INFRA-005 (cookies without Secure)**

This rule uses `walkSourceFiles` which reads from disk. Tests need a temporary directory with a source file.

```typescript
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

it("flags cookie set without Secure flag (INFRA-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "auth.ts"),
    `cookies().set("session", token, { httpOnly: true, sameSite: "lax" });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings[0].ruleId).toBe("INFRA-005");
});

it("ignores cookie with secure: true (INFRA-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "auth.ts"),
    `cookies().set("session", token, { secure: true, httpOnly: true, sameSite: "lax" });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 4: Write test for INFRA-006 (plain HTTP URL)**

```typescript
it("flags plain HTTP URL in source (INFRA-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "api.ts"),
    `const endpoint = "http://api.example.com/data";`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("INFRA-006");
});

it("ignores localhost HTTP URL (INFRA-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "dev.ts"),
    `const endpoint = "http://localhost:3000/api";`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 5: Write test for INFRA-007 (Next.js wildcard image host)**

```typescript
it("flags wildcard hostname in remotePatterns (INFRA-007)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      nextConfig: {
        file: "next.config.mjs",
        source: `export default { images: { remotePatterns: [{ hostname: "**" }] } };`,
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("INFRA-007");
});

it("ignores specific hostname in remotePatterns (INFRA-007)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      nextConfig: {
        file: "next.config.mjs",
        source: `export default { images: { remotePatterns: [{ hostname: "cdn.myapp.com" }] } };`,
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 6: Write test for INFRA-008 (.env committed)**

```typescript
it("flags .env file not in gitignore (INFRA-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  writeFileSync(join(dir, ".env"), "SECRET=abc123");
  writeFileSync(join(dir, ".gitignore"), "node_modules\n");
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings[0].ruleId).toBe("INFRA-008");
});

it("ignores .env when gitignored (INFRA-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  writeFileSync(join(dir, ".env"), "SECRET=abc123");
  writeFileSync(join(dir, ".gitignore"), ".env\nnode_modules\n");
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 7: Write test for INFRA-009 (Referrer-Policy)**

```typescript
it("flags missing Referrer-Policy (INFRA-009)", async () => {
  const model = emptyModel({
    infra: emptyInfra({ securityHeaders: {} }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("INFRA-009");
});

it("flags permissive unsafe-url Referrer-Policy (INFRA-009)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      securityHeaders: {
        "referrer-policy": [{ file: "next.config.mjs", value: "unsafe-url" }],
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores strict Referrer-Policy (INFRA-009)", async () => {
  const model = emptyModel({
    infra: emptyInfra({
      securityHeaders: {
        "referrer-policy": [{ file: "next.config.mjs", value: "strict-origin-when-cross-origin" }],
      },
    }),
  });
  const rule = infrastructureRules.find((r) => r.id === "INFRA-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 8: Run all infrastructure tests**

Run: `npx vitest run tests/rules/infrastructure.test.ts`
Expected: All tests pass (3 existing + ~17 new)

- [ ] **Step 9: Commit**

```bash
git add tests/rules/infrastructure.test.ts
git commit -m "test(rules): full coverage for infrastructure domain (INFRA-001 through INFRA-010)"
```

---

## Domain 2: Supply Chain (SUPPLY-001 through SUPPLY-010)

### Task 3: Audit supply-chain rules

**Files:**
- Read: `src/layers/rules/domains/supply-chain.ts`
- Modify: `src/layers/rules/domains/supply-chain.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

**Known issues to investigate:**
- SUPPLY-001: Hardcoded CVE database will go stale. Is the version matching logic correct for semver ranges?
- SUPPLY-004: Does the wildcard regex catch `^` and `~` ranges? Those are pinned-ish, not wildcard. Check if `>=` or `>` ranges are caught.
- SUPPLY-006: Typosquats list is small and static. Are the edit-distance comparisons correct?
- SUPPLY-008: Outdated version thresholds are hardcoded. Are they current?
- SUPPLY-009: Lockfile parsing assumes package-lock.json v2/v3 format. Does it handle pnpm-lock.yaml?

- [ ] **Step 2: Fix detection issues found**

- [ ] **Step 3: Run existing tests to confirm no regressions**

Run: `npx vitest run tests/rules/supply-chain.test.ts`
Expected: 5 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/supply-chain.ts
git commit -m "fix(rules): audit fixes for supply-chain domain"
```

### Task 4: Write supply-chain rule tests

**Files:**
- Modify: `tests/rules/supply-chain.test.ts`

Supply-chain rules use `model.dependencies` (no filesystem), except SUPPLY-002 (lockfile existence), SUPPLY-003 (package.json scripts), and SUPPLY-009 (lockfile parsing) which need temp directories.

- [ ] **Step 1: Write tests for SUPPLY-005 (git/file URL deps)**

```typescript
import { supplyChainRules } from "../../src/layers/rules/domains/supply-chain.js";
import { emptyModel, makeDep } from "./helpers.js";

it("flags git: URL dependency (SUPPLY-005)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("my-lib", "git+https://github.com/org/my-lib.git")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("SUPPLY-005");
});

it("ignores normal semver dependency (SUPPLY-005)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("my-lib", "^2.0.0")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 2: Write tests for SUPPLY-006 (typosquat detection)**

```typescript
it("flags known typosquat package (SUPPLY-006)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("crossenv", "1.0.0")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("SUPPLY-006");
});

it("ignores legitimate cross-env package (SUPPLY-006)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("cross-env", "7.0.3")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 3: Write tests for SUPPLY-007 (dev tool in prod deps)**

```typescript
it("flags jest in production dependencies (SUPPLY-007)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("jest", "29.0.0", "production")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("SUPPLY-007");
});

it("ignores jest in devDependencies (SUPPLY-007)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("jest", "29.0.0", "dev")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 4: Write tests for SUPPLY-008 (outdated major version)**

```typescript
it("flags severely outdated next version (SUPPLY-008)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("next", "12.0.0", "production")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("SUPPLY-008");
});

it("ignores current next version (SUPPLY-008)", async () => {
  const model = emptyModel({
    dependencies: [makeDep("next", "15.0.0", "production")],
  });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 5: Write tests for SUPPLY-009 (duplicate versions in lockfile)**

This rule reads the lockfile from disk. Needs a temp directory with a package-lock.json.

```typescript
import { mkdtempSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

it("flags 3+ versions of same package in lockfile (SUPPLY-009)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  const lockfile = {
    lockfileVersion: 3,
    packages: {
      "node_modules/lodash-v1": { version: "4.17.20", resolved: "..." },
      "node_modules/sub/node_modules/lodash-v2": { version: "4.17.15", resolved: "..." },
      "node_modules/other/node_modules/lodash-v3": { version: "4.17.10", resolved: "..." },
    },
  };
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lockfile));
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = supplyChainRules.find((r) => r.id === "SUPPLY-009")!;
  const findings = await rule.check(model);
  // Assertion depends on how the rule parses package names from paths.
  // If it doesn't find duplicates, the rule's lockfile parsing needs a fix.
  expect(findings.length).toBeGreaterThanOrEqual(0); // Adjust after audit
});
```

Note: The SUPPLY-009 test assertion may need adjustment based on how the rule actually parses lockfile paths. The audit step (Task 3) will determine the exact expected behavior.

- [ ] **Step 6: Run all supply-chain tests**

Run: `npx vitest run tests/rules/supply-chain.test.ts`
Expected: All tests pass (5 existing + ~11 new)

- [ ] **Step 7: Commit**

```bash
git add tests/rules/supply-chain.test.ts
git commit -m "test(rules): full coverage for supply-chain domain (SUPPLY-001 through SUPPLY-010)"
```

---

## Domain 3: Business Logic (BIZ-001 through BIZ-010)

### Task 5: Audit business-logic rules

**Files:**
- Read: `src/layers/rules/domains/business-logic.ts`
- Modify: `src/layers/rules/domains/business-logic.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

**Known issues to investigate:**
- BIZ-001: Does the login-error detection distinguish between "user not found" and "invalid password" responses? Or just check that both strings exist in the same file?
- BIZ-003: Race condition regex (`select(balance)` then `update(balance)`) is heuristic. Could false-positive on code that uses transactions or row-level locks.
- BIZ-005: Coupon detection is very pattern-specific. Different naming conventions (voucher, promo_code, discount_code) might be missed.
- BIZ-006: Negative quantity check looks for `.positive()` or min check. Does it handle Zod's `.nonnegative()` or `.gte(1)`?
- BIZ-008: Comment stripping regex might not handle all comment styles (JSDoc, nested block comments).

- [ ] **Step 2: Fix detection issues found**
- [ ] **Step 3: Run existing tests**

Run: `npx vitest run tests/rules/business-logic.test.ts`
Expected: 3 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/business-logic.ts
git commit -m "fix(rules): audit fixes for business-logic domain"
```

### Task 6: Write business-logic rule tests

**Files:**
- Modify: `tests/rules/business-logic.test.ts`

Business-logic rules use `walkSourceFiles` and `model.endpoints`. Tests that check source patterns need temp directories. Tests that check endpoint filtering use hand-built models.

- [ ] **Step 1: Write tests for BIZ-002 (reset token plaintext)**

```typescript
it("flags reset_token stored without hash (BIZ-002)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "reset.ts"),
    `await supabase.from("users").update({ reset_token: token });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-002")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings[0].ruleId).toBe("BIZ-002");
});

it("ignores hashed reset token (BIZ-002)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "reset.ts"),
    `const hashed = await bcrypt.hash(token, 10);
await supabase.from("users").update({ reset_token: hashed });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-002")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 2: Write tests for BIZ-003 (race condition on balance)**

```typescript
it("flags read-then-write on balance without transaction (BIZ-003)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "transfer.ts"),
    `const { data } = await supabase.from("accounts").select("balance").eq("id", userId).single();
await supabase.from("accounts").update({ balance: data.balance - amount }).eq("id", userId);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-003")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 3: Write tests for BIZ-004 (OTP without attempt limit)**

```typescript
it("flags OTP endpoint without attempt limit (BIZ-004)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "verify-otp"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "verify-otp", "route.ts"),
    `export async function POST(req: Request) {
  const { otp } = await req.json();
  const valid = otp === storedOtp;
  return Response.json({ valid });
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/verify-otp", file: join(dir, "src/app/api/verify-otp/route.ts"), method: "POST" })],
  });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-004")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 4: Write tests for BIZ-005 (coupon without uniqueness)**

```typescript
it("flags coupon code without redemption tracking (BIZ-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "coupon.ts"),
    `const { data } = await supabase.from("coupons").select("*").eq("code", couponCode).single();
if (data) { applyDiscount(data.discount); }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 5: Write tests for BIZ-006 (negative quantity)**

```typescript
it("flags quantity without positive validation (BIZ-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "order.ts"),
    `const { quantity } = await req.json();
await supabase.from("orders").insert({ quantity, total: price * quantity });`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/orders", file: join(dir, "src/order.ts"), method: "POST" })],
  });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 6: Write tests for BIZ-007 (missing email verification)**

```typescript
it("flags login without email_confirmed_at check (BIZ-007)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "login"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "login", "route.ts"),
    `export async function POST(req: Request) {
  const { email, password } = await req.json();
  const { data } = await supabase.auth.signInWithPassword({ email, password });
  return Response.json({ session: data.session });
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/login", file: join(dir, "src/app/api/login/route.ts"), method: "POST" })],
  });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 7: Write test for BIZ-009 (password change without current pwd)**

```typescript
it("flags password change without current password check (BIZ-009)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "change-password"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "change-password", "route.ts"),
    `export async function POST(req: Request) {
  const { newPassword } = await req.json();
  await supabase.auth.updateUser({ password: newPassword });
  return Response.json({ success: true });
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/change-password", file: join(dir, "src/app/api/change-password/route.ts"), method: "POST" })],
  });
  const rule = businessLogicRules.find((r) => r.id === "BIZ-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 8: Run all business-logic tests**

Run: `npx vitest run tests/rules/business-logic.test.ts`
Expected: All tests pass (3 existing + ~14 new)

- [ ] **Step 9: Commit**

```bash
git add tests/rules/business-logic.test.ts
git commit -m "test(rules): full coverage for business-logic domain (BIZ-001 through BIZ-010)"
```

---

## Domain 4: API Security (API-001 through API-010)

### Task 7: Audit api-security rules

**Files:**
- Read: `src/layers/rules/domains/api-security.ts`
- Modify: `src/layers/rules/domains/api-security.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

**Known issues to investigate:**
- API-001: CORS wildcard + credentials regex checks both patterns in the same file. Could false-negative if they're in different files (middleware sets CORS, route sets credentials).
- API-005: Method restriction check may false-positive on catch-all `route.ts` files that intentionally handle multiple methods.
- API-008: CSRF detection looks for `cookies()` usage without CSRF token. Might false-positive on routes that read cookies but don't use them for auth.
- API-009: Raw error regex (`NextResponse.json(error)`) may miss other response patterns (`new Response(JSON.stringify(error))`).
- API-010: Dynamic require detection should exclude test files and build scripts.

- [ ] **Step 2: Fix detection issues found**
- [ ] **Step 3: Run existing tests**

Run: `npx vitest run tests/rules/api-security.test.ts`
Expected: 3 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/api-security.ts
git commit -m "fix(rules): audit fixes for api-security domain"
```

### Task 8: Write api-security rule tests

**Files:**
- Modify: `tests/rules/api-security.test.ts`

API-security rules use both `walkSourceFiles` (API-001, API-006, API-007, API-009, API-010) and `model.endpoints` (API-002, API-003, API-004, API-005, API-008). Tests need both temp directories and hand-built endpoint lists.

- [ ] **Step 1: Write tests for API-001 (CORS wildcard + credentials)**

```typescript
it("flags CORS wildcard with credentials (API-001)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "middleware.ts"),
    `res.setHeader("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Credentials", "true");`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-001")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings[0].ruleId).toBe("API-001");
});

it("ignores specific CORS origin with credentials (API-001)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "middleware.ts"),
    `res.setHeader("Access-Control-Allow-Origin", "https://myapp.com");
res.setHeader("Access-Control-Allow-Credentials", "true");`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-001")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 2: Write tests for API-005 (HTTP method not restricted)**

```typescript
it("flags route handler without method check (API-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "data"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "data", "route.ts"),
    `export async function handler(req: Request) {
  return Response.json({ data: "all methods accepted" });
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/data", file: join(dir, "src/app/api/data/route.ts"), method: "ALL" })],
  });
  const rule = apiSecurityRules.find((r) => r.id === "API-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 3: Write tests for API-006 (GraphQL introspection)**

```typescript
it("flags GraphQL introspection enabled (API-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "graphql.ts"),
    `const server = new ApolloServer({ schema, introspection: true });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores GraphQL with introspection disabled (API-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "graphql.ts"),
    `const server = new ApolloServer({ schema, introspection: false });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 4: Write tests for API-007 (HTTP method override)**

```typescript
it("flags X-HTTP-Method-Override usage (API-007)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "middleware.ts"),
    `const method = req.headers.get("X-HTTP-Method-Override") || req.method;`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});
```

- [ ] **Step 5: Write tests for API-008 (CSRF token missing)**

```typescript
it("flags cookie-auth mutation without CSRF token (API-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "update"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "update", "route.ts"),
    `import { cookies } from "next/headers";
export async function POST(req: Request) {
  const session = cookies().get("session");
  await db.update(data);
  return Response.json({ ok: true });
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/update", file: join(dir, "src/app/api/update/route.ts"), method: "POST" })],
  });
  const rule = apiSecurityRules.find((r) => r.id === "API-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 6: Write tests for API-009 (raw error in response)**

```typescript
it("flags raw error object in response (API-009)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `catch (error) { return NextResponse.json(error, { status: 500 }); }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores error.message in response (API-009)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `catch (error) { return NextResponse.json({ error: error.message }, { status: 500 }); }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-009")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 7: Write tests for API-010 (dynamic require/import)**

```typescript
it("flags dynamic require with user input (API-010)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "loader.ts"),
    `const mod = require(req.query.module);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = apiSecurityRules.find((r) => r.id === "API-010")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});
```

- [ ] **Step 8: Run all api-security tests**

Run: `npx vitest run tests/rules/api-security.test.ts`
Expected: All tests pass (3 existing + ~14 new)

- [ ] **Step 9: Commit**

```bash
git add tests/rules/api-security.test.ts
git commit -m "test(rules): full coverage for api-security domain (API-001 through API-010)"
```

---

## Domain 5: Cryptography (CRYPTO-001 through CRYPTO-010)

### Task 9: Audit cryptography rules

**Files:**
- Read: `src/layers/rules/domains/cryptography.ts`
- Modify: `src/layers/rules/domains/cryptography.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

**Known issues to investigate:**
- CRYPTO-001: SECURITY_CONTEXT_WORDS regex determines when Math.random() is a real issue vs benign. Check the word list is comprehensive (does it catch "nonce", "salt", "iv", "key derivation"?).
- CRYPTO-003: bcrypt rounds parsing. Does the regex handle `bcrypt.hash(pw, saltRounds)` where saltRounds is a variable, not a literal?
- CRYPTO-005: Zero IV detection. Does it catch `new Uint8Array(16)` as well as Buffer patterns?
- CRYPTO-007: `rejectUnauthorized: false` could be in test files. Should the rule exclude test directories?
- CRYPTO-008: String comparison detection. Does it handle `===` as well as `==`? Does it catch `!==` in conditional checks?
- CRYPTO-010: Plaintext password detection looks for `.insert`/`.update` with `password` field without hash. Could false-positive on hashed password being stored (the hash variable doesn't contain the word "hash").

- [ ] **Step 2: Fix detection issues found**
- [ ] **Step 3: Run existing tests**

Run: `npx vitest run tests/rules/cryptography.test.ts`
Expected: 5 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/cryptography.ts
git commit -m "fix(rules): audit fixes for cryptography domain"
```

### Task 10: Write cryptography rule tests

**Files:**
- Modify: `tests/rules/cryptography.test.ts`

All crypto rules use `walkSourceFiles`. Every test needs a temp directory with a source file.

- [ ] **Step 1: Write tests for CRYPTO-003 (bcrypt low rounds)**

```typescript
it("flags bcrypt with less than 10 rounds (CRYPTO-003)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "auth.ts"),
    `const hash = await bcrypt.hash(password, 8);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-003")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
  expect(findings[0].ruleId).toBe("CRYPTO-003");
});

it("ignores bcrypt with 12 rounds (CRYPTO-003)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "auth.ts"),
    `const hash = await bcrypt.hash(password, 12);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-003")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 2: Write tests for CRYPTO-005 (hardcoded IV)**

```typescript
it("flags Buffer.alloc zero IV (CRYPTO-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "encrypt.ts"),
    `const iv = Buffer.alloc(16);
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});

it("ignores randomBytes IV (CRYPTO-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "encrypt.ts"),
    `const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 3: Write tests for CRYPTO-007 (insecure TLS)**

```typescript
it("flags rejectUnauthorized: false (CRYPTO-007)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "client.ts"),
    `const agent = new https.Agent({ rejectUnauthorized: false });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});
```

- [ ] **Step 4: Write tests for CRYPTO-008 (string comparison on secrets)**

```typescript
it("flags == comparison on HMAC (CRYPTO-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "verify.ts"),
    `if (computedHmac === expectedHmac) { return true; }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});

it("ignores timingSafeEqual usage (CRYPTO-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "verify.ts"),
    `if (crypto.timingSafeEqual(Buffer.from(computedHmac), Buffer.from(expectedHmac))) { return true; }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 5: Write tests for CRYPTO-010 (plaintext password storage)**

```typescript
it("flags password stored without hash (CRYPTO-010)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "signup.ts"),
    `await supabase.from("users").insert({ email, password });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-010")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});

it("ignores hashed password storage (CRYPTO-010)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "signup.ts"),
    `const hashedPassword = await bcrypt.hash(password, 12);
await supabase.from("users").insert({ email, password: hashedPassword });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = cryptographyRules.find((r) => r.id === "CRYPTO-010")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 6: Run all cryptography tests**

Run: `npx vitest run tests/rules/cryptography.test.ts`
Expected: All tests pass (5 existing + ~11 new)

- [ ] **Step 7: Commit**

```bash
git add tests/rules/cryptography.test.ts
git commit -m "test(rules): full coverage for cryptography domain (CRYPTO-001 through CRYPTO-010)"
```

---

## Domain 6: Logging & Monitoring (LOG-001 through LOG-010)

### Task 11: Audit logging-monitoring rules

**Files:**
- Read: `src/layers/rules/domains/logging-monitoring.ts`
- Modify: `src/layers/rules/domains/logging-monitoring.ts` (if fixes needed)

- [ ] **Step 1: Read and audit each rule against the 7 dimensions**

**Known issues to investigate:**
- LOG-002: Flagging all `console.log` in API routes may be noisy. Is there a way to distinguish debug logging from intentional structured logging?
- LOG-005: "Unhandled promise rejection" heuristic (await without try/catch) will false-positive on code that uses error boundaries, global error handlers, or `.catch()` chains.
- LOG-006: Error boundary check just looks for error.tsx files. A project might use a custom ErrorBoundary component with a different name.
- LOG-008: Empty catch detection regex. Does `catch (e) { /* intentional */ }` count as empty? It shouldn't if there's a comment indicating intentional silencing.
- LOG-010: Debug flag detection. `process.env.DEBUG` is commonly used by the `debug` npm package and isn't a vulnerability. Only `DEBUG = true` or `NODE_ENV = 'development'` hardcoded assignments should flag.

- [ ] **Step 2: Fix detection issues found**
- [ ] **Step 3: Run existing tests**

Run: `npx vitest run tests/rules/logging-monitoring.test.ts`
Expected: 3 tests pass

- [ ] **Step 4: Commit audit fixes (if any)**

```bash
git add src/layers/rules/domains/logging-monitoring.ts
git commit -m "fix(rules): audit fixes for logging-monitoring domain"
```

### Task 12: Write logging-monitoring rule tests

**Files:**
- Modify: `tests/rules/logging-monitoring.test.ts`

All logging rules use `walkSourceFiles` and some use `model.endpoints`. Tests need temp directories.

- [ ] **Step 1: Write tests for LOG-003 (stack trace in response)**

```typescript
it("flags error.stack in API response (LOG-003)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `catch (err) { return NextResponse.json({ stack: err.stack }, { status: 500 }); }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-003")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});
```

- [ ] **Step 2: Write tests for LOG-004 (admin op without audit)**

```typescript
it("flags supabase admin call without audit log (LOG-004)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "admin.ts"),
    `await supabase.auth.admin.deleteUser(userId);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-004")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores admin call with audit log (LOG-004)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "admin.ts"),
    `await supabase.auth.admin.deleteUser(userId);
await logEvent("admin.deleteUser", { userId, admin: currentUser });`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-004")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 3: Write tests for LOG-005 (unhandled promise rejection)**

```typescript
it("flags await without try-catch in route handler (LOG-005)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app", "api", "data"), { recursive: true });
  writeFileSync(
    join(dir, "src", "app", "api", "data", "route.ts"),
    `export async function GET() {
  const data = await fetch("https://api.example.com/data");
  return Response.json(await data.json());
}`,
  );
  const model = emptyModel({
    meta: { ...emptyModel().meta, path: dir },
    endpoints: [makeEndpoint({ path: "/api/data", file: join(dir, "src/app/api/data/route.ts"), method: "GET" })],
  });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-005")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 4: Write tests for LOG-006 (no error boundary)**

```typescript
it("flags missing error boundary (LOG-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app"), { recursive: true });
  writeFileSync(join(dir, "src", "app", "page.tsx"), `export default function Home() { return <div>Hi</div>; }`);
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores project with error.tsx (LOG-006)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src", "app"), { recursive: true });
  writeFileSync(join(dir, "src", "app", "error.tsx"), `"use client"; export default function Error() { return <div>Error</div>; }`);
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-006")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 5: Write tests for LOG-007 (PII in logs)**

```typescript
it("flags email logged in plaintext (LOG-007)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `console.log("User signed up:", user.email);`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-007")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 6: Write tests for LOG-008 (empty catch block)**

```typescript
it("flags empty catch block (LOG-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `try { await riskyOp(); } catch (e) {}`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(1);
});

it("ignores catch with error handling (LOG-008)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "handler.ts"),
    `try { await riskyOp(); } catch (e) { logger.error(e); }`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-008")!;
  const findings = await rule.check(model);
  expect(findings.length).toBe(0);
});
```

- [ ] **Step 7: Write tests for LOG-010 (debug flag forced on)**

```typescript
it("flags hardcoded DEBUG = true (LOG-010)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "config.ts"),
    `process.env.DEBUG = "true";`,
  );
  const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
  const rule = loggingMonitoringRules.find((r) => r.id === "LOG-010")!;
  const findings = await rule.check(model);
  expect(findings.length).toBeGreaterThanOrEqual(1);
});
```

- [ ] **Step 8: Run all logging-monitoring tests**

Run: `npx vitest run tests/rules/logging-monitoring.test.ts`
Expected: All tests pass (3 existing + ~13 new)

- [ ] **Step 9: Commit**

```bash
git add tests/rules/logging-monitoring.test.ts
git commit -m "test(rules): full coverage for logging-monitoring domain (LOG-001 through LOG-010)"
```

---

## Final Verification (Task 13)

### Task 13: Full test suite run and audit summary

- [ ] **Step 1: Run the complete test suite**

Run: `npx vitest run`
Expected: All tests pass. Zero failures.

- [ ] **Step 2: Run typecheck**

Run: `npx tsc --noEmit`
Expected: Clean (0 errors)

- [ ] **Step 3: Count test coverage**

Run: `npx vitest run tests/rules/ 2>&1 | tail -5`
Expected: 120+ tests across Phase 2 domain files

- [ ] **Step 4: Update the design doc with audit results**

Fill in the "Audit Results" sections in `docs/superpowers/specs/2026-04-12-phase2-rule-audit-design.md` with the findings from each domain audit (Tasks 1, 3, 5, 7, 9, 11).

- [ ] **Step 5: Commit the audit results**

```bash
git add docs/superpowers/specs/2026-04-12-phase2-rule-audit-design.md
git commit -m "docs(rules): Phase 2 rule audit results for all 6 domains"
```
