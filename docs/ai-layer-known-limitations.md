# AI Layer — Known Limitations

Issues discovered while running the AI layer against real repos. Each entry
describes a case where the AI's output is technically accurate but fails a
user's actual security model, or where the per-endpoint analysis window
misses context that would change the finding's severity.

---

## 1. Magic-link-by-UUID endpoints flagged as critical IDOR (ADDRESSED 2026-04-11)

**Discovered:** 2026-04-11 (skutt scan)
**Status:** Addressed by `.sentinelrc.json` config + prompt prefix +
post-processing severity cap. See `src/layers/ai/magic-link.ts`.

**Symptom:** The AI escalates public endpoints that look up a resource by a
caller-supplied UUID to `critical` severity, labeling the pattern as IDOR.

**Example:** `/api/public/reservation/[id]` — a Next.js route intended to be
reached via a unique, unguessable link emailed to a specific recipient. There
is no authentication check because the UUID itself is the authentication.
The AI flagged 4 separate critical findings on this one file because each
HTTP method handler is analyzed as a separate endpoint and the same
design-intent issue surfaces from multiple angles.

**Why it happens:** The AI only sees one handler's source plus adjacent
helpers. It cannot tell the difference between:

- A true IDOR (authenticated user reaching another user's row via a
  sequential or predictable ID)
- A magic-link pattern (unauthenticated public route where the unguessable
  token IS the credential, like password reset links or Calendly booking URLs)

Both patterns look identical at the handler level: "no auth check, user
controls the ID, query by ID."

**Fix shipped — three layers:**

1. **Config** — `.sentinelrc.json` now accepts
   `ai.magicLinkRoutes: string[]`, an array of glob patterns. Example:
   ```json
   { "ai": { "magicLinkRoutes": ["/api/public/**", "/api/reset/*"] } }
   ```
   Globs support `*` (single segment) and `**` (any depth). `/api/public/**`
   matches both `/api/public` and `/api/public/anything/here`.

2. **Prompt prefix** — endpoints matching any configured pattern get a
   magic-link context block prepended to their per-endpoint prompt. It
   explains the access model ("unguessable token IS the credential"),
   tells the AI what NOT to report ("no auth check" as critical IDOR), and
   steers it toward genuine token-handling concerns (predictability,
   expiry, single-use enforcement, rate limits, HMAC binding, revocation,
   logging).

3. **Post-processing cap** — a safety net that enforces the cap
   deterministically. Any finding whose first-evidence file belongs to a
   matched endpoint, whose domain is `auth-access-control`, and whose
   issue tag is `idor` or `auth_bypass` gets its severity capped at
   `medium`. Other domains (injection, secrets, PII leak, crypto) pass
   through unchanged — SQL injection on a magic-link endpoint is still
   critical. Privilege-escalation findings (`privilege_escalation` tag)
   also pass through — the magic-link pattern doesn't imply anyone can
   set `is_admin`.

**Measured impact on skutt (replayed offline):** With
`magicLinkRoutes: ["/api/public/**"]`, 2 endpoints match. 6 findings
capped: 4 `critical`→`medium` and 2 `high`→`medium`, all on the two
matched files. Severity distribution shifts from `{critical 5, high 39}`
to `{critical 3, high 37}`, moving the noise out of the top-of-report
priority buckets. Non-auth findings (injection, PII leak) unchanged.

Replay on any saved scan result:
`npx tsx scripts/magic-link-replay.mjs <result.json> '/api/public/**'`

**Mitigations still surfaced for legitimate magic-link routes** (these
are the findings the AI layer SHOULD emit even at `medium` severity):
rate limiting, HMAC binding to recipient identity, token expiry,
single-use enforcement, access logging. The prompt prefix explicitly
directs the model to look for these.

---

## 2. Duplicate findings on multi-method route files (ADDRESSED 2026-04-11)

**Discovered:** 2026-04-11 (skutt scan)
**Status:** Addressed by post-processing dedup in `src/layers/ai/dedup.ts`.

**Symptom:** A single file exporting multiple HTTP method handlers (e.g.,
`GET` and `POST` in one `route.ts`) produces N-times-duplicated findings
when the file-level issue affects all methods (e.g., missing auth across
the whole handler set).

**Example:** `/api/public/reservation/[id]/route.ts` exports `GET` and
`POST`. Both handlers share the same "no auth check, service role client"
pattern. The AI flagged 4 separate critical findings — two from analyzing
GET, two from analyzing POST — all describing the same underlying issue.

**Why it happens:** The orchestrator processes each `(method, path)` tuple
as a separate endpoint, even when they share a source file. The per-endpoint
prompt sends only one handler at a time, so the AI has no way to deduplicate
across sibling handlers.

**Fix shipped:** `dedupAIFindings` runs in `runAI` after the orchestrator
returns. Each finding gets a primary issue tag via keyword classification
(IDOR, rate-limit, error-leak, CSRF/origin, RLS-bypass, privilege-escalation,
race-condition, PII-leak, input-injection, file-upload, auth-bypass). Findings
are grouped by `(first-evidence file, domain, tag)`. Broad tags
(`input_validation`, `business_logic`) and unclassified findings fall back
to literal normalized-title matching to avoid false merges.

Within a group, the strongest representative (highest severity, then
highest confidence) is kept and evidence from all collapsed siblings is
merged onto it. The merged finding count surfaces as `findingsCollapsed`
on `AIRunResult` and in the terminal report.

**Impact measured on skutt:** 268 → 188 AI findings (82 collapsed, 29.9%
reduction). No false merges observed when inspecting all 55 collapse
buckets manually. Rerun with `npx tsx scripts/dedup-replay.mjs <result.json>`
against any saved scan result.

**Not covered (tradeoffs):**

- Unclassified findings with novel phrasings don't cluster — they only
  collapse when their normalized titles match exactly. Expanding the
  keyword taxonomy over time will improve coverage.
- Tags are title-only. Descriptions are richer but would also cause more
  over-merging; keeping it title-only is the precision-preserving choice.
- Alternative fixes left for future work: batch-handler analysis (send
  all methods of one file in a single prompt) and prompt-level
  cross-reference (tell the AI about sibling handlers). Both reduce
  token spend and would catch more duplicates, but require orchestrator
  changes.

---

## 3. Severity inflation without bypass evidence

**Discovered:** 2026-04-11 (skutt scan)

**Symptom:** The AI sometimes labels a finding `critical` based on surface
characteristics (no auth check, service role client, mutation endpoint)
without citing a concrete bypass path that a real attacker could execute.

**Why it matters:** "Critical" should mean "exploitable in production with
reasonable preconditions." Inflating it to "mutation endpoint looks risky"
makes the severity label useless for prioritization.

**Example:** A `PATCH /api/invitations` route was marked critical because
it uses the service role client, even though the handler does enforce an
admin check via helper. The AI missed the helper — which brings us to
issue 4.

**Current workaround:** Treat critical findings as prompts for manual
review, not as definitive priorities. Sort by `confidence` alongside
severity when triaging.

**Possible fixes (future work):**

1. Require bypass citation: the prompt could require that `critical` findings
   include an explicit "exploitation path" field citing the attacker's
   reachable state.
2. Confidence-aware severity: findings where confidence is not `high` get
   their severity capped at `high`.
3. Post-processing downgrade: any finding where the AI's reasoning field
   doesn't include the word "attacker" or equivalent gets its severity
   capped.

---

## 4. Auth helpers outside the per-endpoint context window

**Discovered:** 2026-04-11 (skutt scan, implicit)

**Symptom:** The AI flags a handler as unauthenticated when the actual auth
check lives in a helper function imported from an unrelated path that
didn't make it into the adjacent-file context.

**Why it happens:** The context builder includes up to 5 adjacent files
(imports referenced by the handler). If the auth helper is imported via a
barrel file or re-exported from a deeper module, it may not be included.
Even if it is, the AI might not trace the call to confirm what the helper
does.

**Current workaround:** Adjacent-file inclusion already exists; the
limitation is coverage and the AI's willingness to assume the worst when
it can't see a helper's source.

**Possible fixes (future work):**

1. Better dependency walk: the context builder could detect
   auth-like imports (`requireAuth`, `getSession`, middleware helpers) and
   always include their source regardless of distance.
2. Project-level auth map: a pre-scan that lists every auth helper and its
   usage sites, fed into the prompt as a reference table. The AI can then
   say "this handler does not call any of the known auth helpers" with
   higher confidence.
3. Probe layer (v0.4): actually run the handler with/without credentials
   and observe the response. This is the probe layer's whole point.

---

## Prioritization

| # | Limitation | Impact | Effort | Status |
|---|---|---|---|---|
| 1 | Magic-link misclassified | High (noisy criticals) | Medium (config + prompt) | **Addressed** |
| 2 | Multi-method duplicates | Medium (triage friction) | Low (post-dedup) | Addressed (2d35b26) |
| 3 | Severity inflation | High (erodes trust) | Low (prompt constraint) | Addressed (1d28c6b) |
| 4 | Auth helper coverage | High (false negatives) | High (context builder redesign) | Open |

Remaining work: #4 is the Probe layer's job or a v0.4 refactor.
