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

Results will be appended per-domain as each audit completes.

### Domain 1: Infrastructure

_Pending_

### Domain 2: Supply Chain

_Pending_

### Domain 3: Business Logic

_Pending_

### Domain 4: API Security

_Pending_

### Domain 5: Cryptography

_Pending_

### Domain 6: Logging & Monitoring

_Pending_
