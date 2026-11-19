import type { Severity } from "./types.js";

/**
 * How bad it is that a security header is missing. The one table read by
 * everything that reports a missing header: the INFRA rules (repo scan) and
 * the security-headers probe (the running site). Change a value here, not at
 * the call site, so the same missing header never carries two severities.
 */
export const MISSING_HEADER_SEVERITY = {
  "strict-transport-security": "high",
  // High, not medium: with no CSP a single XSS hole runs any script from any
  // origin, and "high" is the default threshold monitors alert at.
  "content-security-policy": "high",
  "x-frame-options": "medium",
  "x-content-type-options": "low",
  "referrer-policy": "low",
  "permissions-policy": "low",
} as const satisfies Record<string, Severity>;

export type SecurityHeader = keyof typeof MISSING_HEADER_SEVERITY;
