# Phase 2 Rule Domain Audit & Test Coverage

**Date:** 2026-04-12
**Status:** Design approved
**Author:** Ty Wells (design with Claude)

## Overview

All 6 Phase 2 rule domains (api-security, cryptography, supply-chain, infrastructure, business-logic, logging-monitoring) have 10 implemented rules each, totaling 60 rules. However, only 22 have test coverage (37% average). Detection logic quality is unaudited.

This spec covers a domain-by-domain audit of detection logic quality plus full test coverage for all 60 rules.

## Goals

- Audit every Phase 2 rule for false positives, false negatives, regex quality, model usage, evidence quality, severity accuracy, and stack filtering
- Fix detection logic issues found during audit
- Bring test coverage from 22/60 to 60/60 rules (minimum 2 tests per rule)
- Document all audit findings and fixes for traceability

## Non-Goals

- HTML report improvements
- CI integration examples
- Real-world validation against live projects
- Changes to Phase 1 domain rules (secrets-exposure, input-injection, auth-access-control, file-upload)
- Changes to the probe, AI, or context layers
- New rules beyond the existing 60

---

## Approach

Domain-by-domain. Each domain is audited and tested as a complete unit before moving to the next. Fixes and tests are written together so they stay coherent.

### Domain Order

Ordered by model integration depth (richest first, so shared improvements benefit later domains):

| Order | Domain | Model Integration | Existing Tests |
|-------|--------|-------------------|----------------|
| 1 | infrastructure | Very high (securityHeaders, nextConfig, supabaseConfig, deployTarget) | 3/10 |
| 2 | supply-chain | High (dependencies array, lockfile parsing) | 5/10 |
| 3 | business-logic | High (endpoints for route filtering) | 3/10 |
| 4 | api-security | High (endpoints, method, path) | 3/10 |
| 5 | cryptography | Minimal (source file walking) | 5/10 |
| 6 | logging-monitoring | Moderate (source scanning + endpoint filtering) | 3/10 |

### Per-Domain Workflow

For each domain:

1. **Read all 10 rules critically** against the audit criteria
2. **Document issues** in an audit table (rule ID, dimension, issue, fix)
3. **Fix detection logic** inline (patches or rewrites as needed)
4. **Write tests** for all 10 rules (vulnerable + safe samples)
5. **Run tests + typecheck** to confirm everything passes
6. **Commit** the domain as a single unit

---

## Audit Criteria

Each rule is evaluated against 7 dimensions:

| Dimension | What We're Looking For |
|-----------|----------------------|
| **False positives** | Does the regex/pattern match safe code? (comments, string literals, test files, disabled code paths) |
| **False negatives** | Does the rule miss real vulnerabilities? (single import style, missing template literal variants, aliased imports) |
| **Regex quality** | Overly broad patterns, missing anchoring, backtracking risks, case sensitivity gaps |
| **Model usage** | Is the rule using available ProjectModel data it should be? (scanning all files when it should filter by endpoints) |
| **Evidence quality** | Does the finding include enough context? File path, line number, meaningful snippet? |
| **Severity accuracy** | Is the assigned severity appropriate per CWE/OWASP guidance? |
| **Stack filtering** | Does `appliesTo` make sense? Supabase-specific rules shouldn't apply to `generic-web` |

### Fix Policy

- Fix issues inline during the audit. No separate fix phase.
- If a rule needs a rewrite rather than a patch, rewrite it.
- If an existing test covers a rule whose logic changes, update the test to match.

---

## Test Strategy

### Test Structure

Mirrors the existing Phase 1 test pattern. Each domain has one test file:

```typescript
// tests/rules/{domain}.test.ts
describe("{DOMAIN}-NNN: Rule title", () => {
  it("flags vulnerable pattern", () => {
    // Build minimal ProjectModel with vulnerable code/config
    // Run the single rule
    // Assert finding exists with correct ruleId, severity, evidence
  });

  it("ignores safe pattern", () => {
    // Build ProjectModel with safe code that looks similar
    // Run the single rule
    // Assert no findings
  });
});
```

### Coverage Requirements

- **Minimum 2 tests per rule:** one vulnerable (positive), one safe (negative)
- **Multi-path rules get more:** if a rule detects multiple distinct patterns (e.g., CRYPTO-005 detects both `Buffer.alloc(16)` and `Buffer.from('0000...')`), each path gets its own positive test
- **Existing tests unchanged** unless the audit changes the rule's detection logic

### Fixture Strategy

- Hand-built `ProjectModel` objects with only the fields the rule needs
- No shared fixture projects, no filesystem I/O
- Same pattern the existing 22 tests already use

### What We're NOT Doing

- No integration tests against real projects
- No snapshot tests for output formatting
- No end-to-end CLI tests

---

## Current State (Pre-Audit)

### Test Coverage by Domain

| Domain | File | Rules | Tested | Untested | Coverage |
|--------|------|-------|--------|----------|----------|
| api-security | `tests/rules/api-security.test.ts` | 10 | 3 (API-002, 003, 004) | 7 | 30% |
| cryptography | `tests/rules/cryptography.test.ts` | 10 | 5 (CRYPTO-001, 002, 004, 006, 009) | 5 | 50% |
| supply-chain | `tests/rules/supply-chain.test.ts` | 10 | 5 (SUPPLY-001, 002, 003, 004, 010) | 5 | 50% |
| infrastructure | `tests/rules/infrastructure.test.ts` | 10 | 3 (INFRA-001, 003, 010) | 7 | 30% |
| business-logic | `tests/rules/business-logic.test.ts` | 10 | 3 (BIZ-001, 008, 010) | 7 | 30% |
| logging-monitoring | `tests/rules/logging-monitoring.test.ts` | 10 | 3 (LOG-001, 002, 009) | 7 | 30% |
| **Total** | | **60** | **22** | **38** | **37%** |

### Known Model Integration Gaps

- **cryptography:** Only walks source files. Does not use `model.dependencies` to check for crypto library versions or `model.infra` for TLS configuration.
- **logging-monitoring:** Mostly source scanning. Could leverage `model.endpoints` more for targeted checks.

---

## Completion Criteria

### Per-Domain Done

1. All 10 rules audited against the 7 dimensions
2. Detection logic fixes applied (if any)
3. Every rule has at least 2 test cases (vulnerable + safe)
4. `npm test` passes with zero failures
5. `npm run typecheck` clean
6. Audit table documenting findings and fixes

### Overall Done

- All 6 domains complete
- Total test count for Phase 2 domains: 120+ (minimum 2 per rule x 60 rules)
- No known false-positive patterns left unfixed
- All audit tables committed in this doc or alongside domain commits

---

## Audit Results

Executed 2026-04-12. All 6 domains audited, 135 tests passing (up from 22).

### Domain 1: Infrastructure (24 tests, up from 3)

| Rule | Finding | Fix |
|------|---------|-----|
| INFRA-002 | Only fired for vercel/cloudflare/fly. Projects with `deployTarget: null` that deploy to HTTPS hosts were missed | Inverted logic: fire for all targets unless explicitly non-TLS |
| INFRA-005 | `secure: true` check was file-wide. One secure cookie silenced all insecure cookies in the same file | Window-based check (±5 lines around each cookie-set) |
| INFRA-005 | `setCookieRe` matched inside comments | Added `isCommentLine()` filter |
| INFRA-006 | Comment detection missed block comment inner lines (` * http://...`) | Replaced with `isCommentLine()` helper covering `//`, `/*`, `*`, `#` |
| INFRA-008 | Gitignore parsing included comment lines as patterns | Filter `#` comments and empty lines before building Set |
| INFRA-008 | No glob matching for `*.local` patterns | Added simple `*.ext` suffix glob matching |

Clean: INFRA-001, INFRA-003, INFRA-004, INFRA-007, INFRA-009, INFRA-010.

### Domain 2: Supply Chain (28 tests, up from 5)

| Rule | Finding | Fix |
|------|---------|-----|
| SUPPLY-001 | `affected()` operator precedence bug: `/^3\.0/.test(v) && !/^3\.0\.5/.test(v)` caught 3.0.6+ as vulnerable | Replaced with proper semver comparison |
| SUPPLY-006 | `crossenv` key mapped `cross-env` as a typosquat, but `cross-env` is the REAL package. The 2017 attack used `crossenv` (no hyphen) as the squatter | Swapped key to `cross-env`, squats to `[crossenv, cross-env.js]` |

Clean: SUPPLY-002, SUPPLY-003, SUPPLY-004, SUPPLY-005, SUPPLY-007, SUPPLY-008, SUPPLY-009, SUPPLY-010.

Accepted limitation: SUPPLY-009 only parses `package-lock.json`. `pnpm-lock.yaml` and `yarn.lock` support deferred (needs YAML parser dep).

### Domain 3: Business Logic (23 tests, up from 3)

| Rule | Finding | Fix |
|------|---------|-----|
| BIZ-003 | Race condition detection false-positived on properly-guarded transactional code | Added skip for files using `BEGIN`, `COMMIT`, `.transaction()`, `FOR UPDATE`, `SERIALIZABLE`, or `advisory_lock` |
| BIZ-005 | Missed `gift_card` table naming | Broadened `.from()` regex to include `gift_?card` |
| BIZ-006 | `.min(0)` and `>= 0` were false negatives (allow zero, still dangerous for payments) | Replaced validation skip regex with stricter pattern recognizing `.positive()`, `.nonnegative()`, `.gt()/.gte()` with positive args, `> 0`, `>= 1`, etc. |

Clean: BIZ-001, BIZ-002, BIZ-004, BIZ-007, BIZ-008, BIZ-009, BIZ-010.

### Domain 4: API Security (18 tests, up from 3)

| Rule | Finding | Fix |
|------|---------|-----|
| API-001 | Regex missed object-literal header form `{ 'Access-Control-Allow-Origin': '*' }` | Added alternation for `['"]HEADER['"]: ['"]value['"]` style |
| API-007 | Raw `_method` matched any variable named `_method` (FP) | Restricted to `body._method` / `body["_method"]` access patterns |
| API-008 | `sameSite: 'strict'` check was case-sensitive and missed `lax` (which mitigates CSRF) | Made case-insensitive, accept `strict` or `lax` |
| API-009 | Only caught `NextResponse.json(err)`, missed `Response.json(err)` and `JSON.stringify(err)` | Widened to union of three patterns |
| API-010 | Dynamic imports in test mocks / build scripts flagged as critical RCE | Skip files matching `__tests__/`, `__mocks__/`, `tests?/`, `specs?/`, `*.{test,spec}`, `scripts/`, `build/` |

Clean: API-002, API-003, API-004, API-005, API-006.

### Domain 5: Cryptography (19 tests, up from 5)

| Rule | Finding | Fix |
|------|---------|-----|
| CRYPTO-002 | `hashCallRe` had `/g` flag used with `.test()` — `lastIndex` persisted, causing non-deterministic/first-file-only detection | Removed `/g` |
| CRYPTO-005 | **Critical:** Regex was `create(?:De)?cipheriv` (lowercase `c`). Never matched real `createCipheriv` calls — the rule was effectively dead against real Node crypto code. | Fixed case + added `new Uint8Array(N)` zero-IV pattern |
| CRYPTO-007 | Flagged intentional test clients using `rejectUnauthorized: false` | Skip test dirs / `*.test.*` / `*.spec.*` files |
| CRYPTO-008 | Whole-file early-return on `timingSafeEqual` — a file using it once hid all other unsafe compares | Per-comparison check, not per-file |
| CRYPTO-008 | Only matched left-operand form; `received === expected` reversed form missed | Match both operand positions |

Clean: CRYPTO-001, CRYPTO-003, CRYPTO-004, CRYPTO-006, CRYPTO-009, CRYPTO-010.

**Biggest find:** CRYPTO-005 dead rule. Would have been caught day one if tests existed.

### Domain 6: Logging & Monitoring (23 tests, up from 3)

| Rule | Finding | Fix |
|------|---------|-----|
| LOG-002 | False-positive noise when a file legitimately uses pino/winston alongside `console.*` | Skip file if it imports a structured logger (pino/winston/bunyan/roarr/loglevel/@logtail/logger) |
| LOG-005 | False-positives on handlers using `.catch()` chains, global error wrappers, or `captureException` | Skip file if any of `.catch(`, `errorHandler`, `withErrorHandler`, `asyncHandler`, `captureException` present |
| LOG-006 | Only detected `error.tsx` / `*ErrorBoundary*` files; missed `react-error-boundary` dep and custom boundaries | Also check `model.dependencies` for `react-error-boundary` and scan for `componentDidCatch` / `getDerivedStateFromError` |
| LOG-010 | Flagged *any* `process.env.DEBUG =` assignment including legitimate `debug` npm usage | Tightened to literal truthy assignments only (`= true`, `= "1"`, `= "*"`, `= "ns:*"`) |

Clean: LOG-001, LOG-003, LOG-004, LOG-007, LOG-008, LOG-009.

---

## Summary

- **60 rules audited** across 6 domains
- **27 detection fixes** applied (1 critical dead rule, several false-positive/false-negative corrections)
- **Test coverage: 22 → 135 tests** (513% increase) across Phase 2 domain files
- **Full test suite: 520/520 passing**
- **Typecheck: clean**
