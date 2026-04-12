# AI Layer — Known Limitations

Issues discovered while running the AI layer against real repos. Each entry
describes a case where the AI's output is technically accurate but fails a
user's actual security model, or where the per-endpoint analysis window
misses context that would change the finding's severity.

---

## 1. Magic-link-by-UUID endpoints flagged as critical IDOR

**Discovered:** 2026-04-11 (skutt scan)

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

**Current workaround:** Treat `critical` findings on routes under `public/**`
with manual review. Until the AI layer understands access-model conventions,
severity on these findings should be downgraded case-by-case.

**Possible fixes (future work):**

1. Config annotation: allow `.sentinelrc.json` to declare
   `magicLinkRoutes: ["/api/public/**"]`. Endpoints matching these globs get
   a prompt prefix explaining the intended access model, and findings on
   them are capped at `medium` severity unless the AI cites a concrete
   bypass beyond "no auth check."
2. Convention detection: routes under `/api/public/`, `/api/magic/`, or
   endpoints where the ID parameter is a UUID read from URL params might be
   heuristically classified as magic-link.
3. Cross-endpoint reasoning: a Stage A pass that identifies public routes
   and their access model at the project level, then informs the
   per-endpoint prompts.

**Mitigations we do recommend even for legitimate magic-link routes:** rate
limiting by IP, binding the link to the recipient email via HMAC, expiring
the token after use, and logging every access. These are findings the AI
layer should still surface — just not as critical IDOR.

---

## 2. Duplicate findings on multi-method route files

**Discovered:** 2026-04-11 (skutt scan)

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

**Current workaround:** Accept the duplication. A human reviewer can
collapse them when triaging.

**Possible fixes (future work):**

1. Post-processing dedup: after all endpoints are analyzed, group findings
   by `(file, domain, similar title)` and collapse near-duplicates.
2. Batch handler analysis: when a route file exports multiple methods, send
   them in a single call and let the AI describe file-level issues once.
   This would also reduce token spend.
3. Cross-reference in the prompt: include sibling handlers from the same
   file as read-only context, so the AI can say "this is a file-level
   issue, see POST" instead of re-listing it.

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

| # | Limitation | Impact | Effort |
|---|---|---|---|
| 1 | Magic-link misclassified | High (noisy criticals) | Medium (config + prompt) |
| 2 | Multi-method duplicates | Medium (triage friction) | Low (post-dedup) |
| 3 | Severity inflation | High (erodes trust) | Low (prompt constraint) |
| 4 | Auth helper coverage | High (false negatives) | High (context builder redesign) |

Next release should address #1 and #3 together — both live in the prompt
plus config plane and don't require architectural changes. #2 is a cheap
win for a post-pass. #4 is the Probe layer's job or a v0.4 refactor.
