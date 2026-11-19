import type { ApiEndpoint, Finding, Severity, SecurityDomain } from "../../model/types.js";
import { classifyIssueTag } from "./dedup.js";

// Convert a single glob pattern to a RegExp. Supported syntax:
//   /**        matches zero or more path segments (so /api/public/** matches
//              both /api/public and /api/public/foo/bar)
//   **         matches any sequence of characters including slashes
//   *          matches any sequence of characters EXCEPT slashes
//   everything else is matched literally (regex metacharacters are escaped)
//
// Anchored: the pattern must match the whole input string.
export function globToRegex(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    // /** as a whole segment: matches empty or "/any/thing".
    if (ch === "/" && glob[i + 1] === "*" && glob[i + 2] === "*") {
      const after = glob[i + 3];
      if (after === undefined || after === "/") {
        out += "(?:/.*)?";
        i += 2;
        continue;
      }
    }
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        out += ".*";
        i++;
      } else {
        out += "[^/]*";
      }
    } else if (/[.+?^${}()|[\]\\]/.test(ch)) {
      out += "\\" + ch;
    } else {
      out += ch;
    }
  }
  return new RegExp("^" + out + "$");
}

// Returns true if `path` matches ANY of the provided glob patterns.
// Patterns with no meaningful glob characters still work — they match
// literally.
export function isMagicLinkPath(path: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;
  for (const pattern of patterns) {
    if (globToRegex(pattern).test(path)) return true;
  }
  return false;
}

export function isMagicLinkEndpoint(endpoint: ApiEndpoint, patterns: string[]): boolean {
  return isMagicLinkPath(endpoint.path, patterns);
}

// The prompt prefix injected into the user message when analyzing a
// magic-link endpoint. Explains the intended access model so the AI
// stops flagging "no auth check" as critical IDOR and instead focuses
// on token-handling concerns that genuinely apply.
export const MAGIC_LINK_PROMPT_PREFIX = `MAGIC-LINK ENDPOINT (access model: unguessable token is the credential)

This endpoint is INTENTIONALLY unauthenticated. The access model is that
an unguessable token (typically a UUID) embedded in the URL is itself the
credential, emailed or SMS'd to a specific recipient. This is the same
pattern used by password-reset links, calendar booking confirmations, and
shareable document links.

Given this access model:

- DO NOT report "no auth check" or "IDOR via URL parameter" as a critical
  finding. The lack of a session-based auth check is by design; the token
  plays the role of authentication.
- DO report weaknesses in the TOKEN HANDLING itself, which are the real
  attack surface for this pattern:
    * Token predictability (sequential IDs, short tokens, insufficient entropy)
    * Missing expiry (token valid forever)
    * Missing single-use enforcement (token valid after first use)
    * Missing rate limiting (allows token enumeration)
    * Token leaked via referrer, logs, or query-string caching
    * Token not bound to the recipient (HMAC over user_id + token)
    * Broken token revocation (can't invalidate after the fact)
    * Cross-resource reuse (one token grants access to unrelated records)
- DO report ORTHOGONAL vulnerabilities the same way you would anywhere else:
  SQL injection in query parameters, XSS in reflected output, SSRF via
  fetched URLs, command injection, secrets exposure.
- When you report a finding whose root cause is "missing auth" on this
  endpoint, mark it AT MOST "medium" severity. We will enforce this cap.

`;

// Severity ladder; lower index = more severe.
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function capAtMedium(severity: Severity): Severity {
  const cap = SEVERITY_ORDER.indexOf("medium");
  const current = SEVERITY_ORDER.indexOf(severity);
  return current < cap ? "medium" : severity;
}

// Post-processing safety net. Any finding whose first-evidence file
// matches a magic-link route pattern AND whose issue type is an
// access-control complaint (IDOR or auth-bypass) gets its severity
// capped at "medium". The prompt guidance should prevent most of these
// at emit time; this enforces it deterministically for cases where the
// model didn't follow instructions or drifted.
//
// Non-access-control findings on magic-link endpoints (injection,
// secrets exposure, PII leak, crypto misuse) pass through unchanged.
export interface MagicLinkCapResult {
  findings: Finding[];
  cappedCount: number;
}

const CAPPABLE_DOMAINS = new Set<SecurityDomain>(["auth-access-control"]);
const CAPPABLE_TAGS = new Set(["idor", "auth_bypass"]);

export function applyMagicLinkSeverityCap(
  findings: Finding[],
  magicLinkRoutes: string[],
  endpoints: Pick<ApiEndpoint, "path" | "file">[],
): MagicLinkCapResult {
  if (magicLinkRoutes.length === 0) {
    return { findings, cappedCount: 0 };
  }
  const magicFiles = new Set(
    endpoints.filter((e) => isMagicLinkPath(e.path, magicLinkRoutes)).map((e) => e.file),
  );
  if (magicFiles.size === 0) {
    return { findings, cappedCount: 0 };
  }

  let cappedCount = 0;
  const out: Finding[] = findings.map((f) => {
    const file = f.evidence[0]?.file;
    if (!file || !magicFiles.has(file)) return f;
    if (!CAPPABLE_DOMAINS.has(f.domain)) return f;
    const tag = classifyIssueTag(f.title);
    if (!CAPPABLE_TAGS.has(tag)) return f;
    const capped = capAtMedium(f.severity);
    if (capped === f.severity) return f;
    cappedCount++;
    return { ...f, severity: capped };
  });
  return { findings: out, cappedCount };
}
