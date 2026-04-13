# Probe v0.4 Intrusive Checks Design

**Parent spec:** `2026-04-12-probe-layer-design.md` section 6.3

## Summary

Three intrusive-level probe checks. These are the most aggressive checks in the catalog and require explicit `--level intrusive` plus interactive re-authorization every run (never cached).

## Checks

### I1: xss-reflection

- **Domain:** input-injection
- **What:** Inject benign marker strings (`<sentinel-marker-${nonce}/>`) into form/query/header inputs. Check for unescaped reflection in response body via literal substring match.
- **Markers contain no executable content.** Detection is substring match, not script execution.
- **Mutations:** None (read-only input, no stored state)
- **Cleanup:** None
- **Targets:** Endpoints with query or body inputs (from `target.inputs`)
- **Severity:** High if marker reflected unescaped, medium if HTML-entity-encoded marker found
- **CWE:** CWE-79

### I2: file-upload

- **Domain:** file-upload
- **What:** Upload benign test files (1-byte `.txt`, valid 100x100 PNG) to discovered upload endpoints. Catches missing MIME validation, accepts-anything behavior, path traversal via filename.
- **Mutations:** YES - creates files on target
- **Cleanup:** Blocking obligation registered BEFORE upload. Calls DELETE endpoint to remove uploaded file.
- **DECISION (2026-04-12):** If recon did NOT discover a DELETE endpoint for the upload target, the check SKIPS the upload entirely. No cleanup path = don't mutate. This prevents orphaned test artifacts.
- **Test files:** Generated in-memory, not read from disk
  - `sentinel-probe-${nonce}.txt` (1 byte: "x")
  - `sentinel-probe-${nonce}.png` (minimal valid PNG, ~68 bytes)
  - `sentinel-probe-../../../etc/sentinel-${nonce}.txt` (path traversal test filename)
- **Severity:** High if path traversal filename accepted, medium if no MIME validation, low if upload succeeds but is properly validated
- **CWE:** CWE-434 (unrestricted upload), CWE-22 (path traversal)

### I3: form-fuzzing

- **Domain:** business-logic
- **What:** Send POST with malformed bodies: truncated JSON, 10KB unicode string, type mismatches, missing required fields. Observe error reflection, 500 responses, server-side stack traces leaked.
- **Mutations:** None (reads only, backend may log noise)
- **Cleanup:** None
- **Targets:** POST endpoints with body inputs
- **Payloads:**
  - Truncated JSON: `{"key": "val`
  - Unicode stress: 10KB of mixed unicode (`\u0000`, emoji, RTL markers, null bytes)
  - Type mismatch: numbers where strings expected, arrays where objects expected
  - Empty object: `{}`
  - Oversized field: single field with 100KB string value
- **Detection:**
  - 500 response = medium finding (unhandled error)
  - Stack trace in body = medium finding (information disclosure)
  - Request body reflected verbatim in error = medium finding (error reflection)
  - All payloads return 4xx with generic error = no finding (properly handled)
- **CWE:** CWE-20 (improper input validation), CWE-209 (stack trace disclosure)

## Intrusive Authorization

Per the parent spec (section 5.3):
- Intrusive level is NEVER cached in `.sentinelrc.json`
- Always triggers interactive prompt with bold warning
- Requires explicit `--level intrusive` CLI flag
- Reads from `/dev/tty` (pipe-proof)
- Non-TTY sessions exit 3

This is already implemented in `authorization.ts`. No changes needed.

## Cleanup Protocol for file-upload

This is the first check that exercises the cleanup registry with real obligations.

```
1. Resolve DELETE endpoint from model (recon must have found it)
2. If no DELETE endpoint → SKIP check, return empty results
3. Generate nonce for test files
4. Register BLOCKING cleanup obligation (DELETE each uploaded file)
5. Upload test file via POST
6. Observe response (accepted? MIME checked? path traversal filename rejected?)
7. Record findings
8. Cleanup runs automatically via orchestrator (LIFO order)
```

The obligation is registered BEFORE the upload (invariant from parent spec section 8.1). If the upload fails, the cleanup callback runs but the DELETE is a no-op (file was never created). Harmless.

## File Structure

```
src/layers/probe/checks/intrusive/
  xss-reflection.ts
  file-upload.ts
  form-fuzzing.ts

tests/layers/probe/checks/intrusive/
  xss-reflection.test.ts
  file-upload.test.ts
  form-fuzzing.test.ts

tests/integration/
  probe-intrusive.test.ts
```

Modified:
- `src/layers/probe/index.ts` — add `loadIntrusiveChecks()`

## Testing

All tests use `MockHttpClient`. No real uploads, no real file creation. The cleanup registry integration is tested by verifying obligations are registered and the cleanup callback is invoked.

For file-upload specifically: mock the DELETE endpoint response to verify the cleanup callback makes the right request.
