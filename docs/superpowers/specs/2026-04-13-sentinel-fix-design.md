# Sentinel Fix Command - Design Spec

*Date: 2026-04-13*
*Status: Approved*

## Overview

Add a `sentinel fix` command that automatically remediates security findings using a hybrid approach: deterministic code transforms for simple patterns, AI-powered patches for complex fixes.

## CLI Interface

```bash
sentinel fix <path>                      # scan + fix everything
sentinel fix <path> --from report.json   # fix from existing scan report
sentinel fix <path> --rule INPUT-005     # fix only specific rule(s), repeatable
sentinel fix <path> --dry-run            # show patches, don't write files
sentinel fix <path> --no-ai             # deterministic fixes only (no API cost)
sentinel fix <path> --ai-provider anthropic --ai-model claude-sonnet-4-6
sentinel fix <path> --ai-max-cost 5.00   # budget cap in USD
```

Inherits AI flags from `scan` command (`--ai-provider`, `--ai-model`, `--ai-max-cost`, `--ai-concurrency`). Does NOT accept GitHub URLs since fixes must write to a local filesystem.

## Architecture

```
sentinel fix <path>
    |
    +-- 1. Acquire findings
    |     +-- Default: run full scan (recon + rules + context suppression)
    |     +-- --from: load findings from JSON report file
    |
    +-- 2. Classify each finding into a fix strategy
    |     +-- deterministic: a registered transform exists
    |     +-- ai: no transform, AI generates a patch
    |     +-- manual: no safe automated fix, skip with message
    |
    +-- 3. Group findings by file
    |     (so AI sees all findings for a file at once, avoids conflicting patches)
    |
    +-- 4. Apply deterministic transforms (per-file)
    |     +-- read file -> apply all deterministic transforms -> write file
    |
    +-- 5. Apply AI fixes (per-file, unless --no-ai)
    |     +-- send file + all AI findings -> get patched file -> write
    |
    +-- 6. Report results
          +-- fixed count, skipped count, failed count
          +-- files modified
          +-- suggest: run sentinel scan to verify
```

## Fix Registry

Each fixer registers alongside its rule. A fixer is:

```typescript
interface Fixer {
  ruleId: string;
  type: "deterministic" | "ai";
  // Deterministic: receives file content + finding evidence, returns patched content.
  // Return null to signal "could not fix this instance."
  apply?: (fileContent: string, finding: Finding) => string | null;
  // AI: prompt template ID (looked up in prompts.ts).
  // The AI runner fills the template with file content + finding context.
  aiPromptId?: string;
}
```

The registry is a simple Map<string, Fixer> populated at startup, same pattern as the rule registry.

## v1 Fixers - Deterministic

### CRYPTO-001: Math.random() in security context

- Find the `Math.random()` call at the reported line.
- Replace with `crypto.randomUUID()` (for string tokens) or `crypto.getRandomValues(new Uint32Array(1))[0]` (for numeric).
- Heuristic: if the result is used in string concatenation or `.toString(36)`, use `randomUUID()`. Otherwise use `getRandomValues`.
- Add `import { randomUUID } from 'node:crypto'` if not present. For client-side files (detected by path containing `components/` or `app/` without `api/`), use `globalThis.crypto.randomUUID()` instead.

### CRYPTO-002: MD5 hash usage

- Find `createHash('md5')` or `createHash("md5")` at the reported line.
- Replace the algorithm argument with `'sha256'`.
- If using a third-party `md5()` function import, replace import with `import { createHash } from 'node:crypto'` and replace `md5(value)` with `createHash('sha256').update(value).digest('hex')`.

### LOG-005: Missing try/catch in route handler

- Parse the handler function body (the exported GET/POST/PUT/PATCH/DELETE function).
- If the body is not already wrapped in try/catch, wrap it:
  ```typescript
  try {
    // existing body
  } catch (error) {
    console.error(`${METHOD} ${ROUTE} failed:`, error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
  ```
- Preserve the existing return type. Detect if using NextResponse or Response.

### INFRA-006: Missing security headers

- If `next.config.js` or `next.config.mjs` exists, add a `headers()` function returning standard security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
- If headers already partially exist, merge only missing ones.
- If no Next.js config exists, create `middleware.ts` that adds headers to all responses.

## v1 Fixers - AI-Powered

### INPUT-005: Missing body validation

**Prompt strategy:** Send the full route handler file. Instruct the AI to:
1. Read the handler and infer the expected request body shape from how `body` properties are accessed.
2. Generate a Zod schema that matches that shape.
3. Add `import { z } from 'zod'` if not present.
4. Add schema definition above the handler.
5. Add `const body = schema.parse(await request.json())` at the top of the handler, replacing the existing `await request.json()` call.
6. Add a try/catch around the parse that returns a 400 with validation errors.

**Validation:** The returned file must still contain all original exports and the handler function signatures.

### AUTH-002: No auth check on protected route

**Prompt strategy:** Send the route handler file. Instruct the AI to:
1. Add Supabase auth check at the top of each handler: `const supabase = createRouteHandlerClient({ cookies })` then `const { data: { user }, error } = await supabase.auth.getUser()`.
2. Return 401 if no user.
3. Add necessary imports (`createRouteHandlerClient` from `@supabase/auth-helpers-nextjs`, `cookies` from `next/headers`).
4. Preserve all existing handler logic after the auth check.

**Context awareness:** If the project context marks this route as intentionally public, the fixer skips it (already handled by context suppression, but defense in depth).

### API-004: No rate limiting

**Prompt strategy:** Send the route handler file. Instruct the AI to:
1. Add a simple in-memory rate limiter at the top of the file (Map-based, keyed by IP).
2. Check rate limit at the top of each handler, return 429 if exceeded.
3. Use reasonable defaults: 60 requests per minute per IP.
4. Add a comment noting this is a basic rate limiter suitable for single-instance deployments; for production scale, use Redis or Upstash.

## AI Fix Protocol

For each file that has AI findings:

1. Read the full file content.
2. Collect all AI findings for this file.
3. Build the prompt:
   - System: "You are a security engineer. Apply minimal changes to fix the specified vulnerabilities. Preserve all existing logic, exports, and type signatures. Return ONLY the complete fixed file content, no explanations."
   - User: file content + finding details (ruleId, title, line, remediation) for each finding in this file.
4. Call the AI provider (same provider/model infrastructure as `scan --ai`).
5. Validate the response:
   - Must be valid source code (parseable).
   - Must contain all original export names.
   - Must not be dramatically shorter than original (>50% reduction = likely truncated).
6. If valid, write the patched file.
7. If invalid, skip all AI findings for this file and report failure.

Budget tracking uses the same `--ai-max-cost` mechanism as the scan AI layer.

## Grouping Strategy

Findings are grouped by file before fixing. Within each file:
1. All deterministic fixes run first (they're fast and predictable).
2. Then AI fixes run on the already-deterministically-patched content.
3. This ordering ensures the AI sees the latest file state.

If a file has only deterministic findings, no AI call is made. If `--no-ai` is set, AI findings are reported as "skipped (--no-ai)".

## Output Format

```
SENTINEL FIX v0.1.0
Target: /path/to/project

Scanning... done (215 findings, 202 after context suppression)

Deterministic fixes:
  ok  CRYPTO-001  auto-rotate.mjs:151        Math.random() -> crypto.randomUUID()
  ok  CRYPTO-002  supabase-storage.ts:36     md5 -> sha256
  ok  LOG-005     api/content/route.ts:0     Added try/catch wrapper
  ... (85 more LOG-005 fixes)

AI fixes:
  ok  INPUT-005   api/content/route.ts       Added Zod validation (ContentSchema)
  ok  AUTH-002    api/graduates/route.ts     Added Supabase auth check
  --  API-004     api/settings/route.ts      Skipped (budget exhausted)
  !!  INPUT-005   api/invitations/route.ts   AI response invalid, skipped

Summary:
  Fixed:    142 findings
  Skipped:   52 (no fixer: 38, budget: 8, --rule filter: 6)
  Failed:     8 (AI validation errors)
  Files:     23 modified

Run `sentinel scan /path/to/project` to verify fixes.
```

In `--dry-run` mode, show unified diffs instead of writing files, and prefix each section with "Would fix:".

## File Structure

```
src/commands/fix.ts                 # CLI command definition + orchestration
src/layers/fix/index.ts             # Fix runner: classify, group, apply, report
src/layers/fix/registry.ts          # Fixer registration (Map<ruleId, Fixer>)
src/layers/fix/deterministic/
  +-- crypto-001.ts                 # Math.random replacement
  +-- crypto-002.ts                 # MD5 -> SHA-256
  +-- log-005.ts                    # try/catch wrapper
  +-- infra-006.ts                  # Security headers
src/layers/fix/ai/
  +-- index.ts                      # AI fix runner (group by file, call provider)
  +-- prompts.ts                    # Prompt templates per rule
  +-- validator.ts                  # Validate AI response before applying
```

## Safety Guarantees

1. Never writes files outside the project path.
2. `--dry-run` always available to preview changes.
3. Deterministic transforms are idempotent (safe to run twice).
4. AI fixes are validated before writing: unparseable or truncated responses are rejected.
5. Sentinel does not commit changes. User reviews the diff in git and commits manually.
6. Context suppressions are respected: findings suppressed by context are never "fixed."
7. `--ai-max-cost` prevents runaway API spend.

## Future Additions (Not in v1)

- `--interactive` mode: approve each fix before applying.
- Dashboard integration: "Fix" button on finding cards.
- Fix verification: automatic re-scan after fixing to confirm finding is resolved.
- Additional AI fixers for remaining rule domains (UPLOAD, SUPPLY, BUSINESS-LOGIC).
