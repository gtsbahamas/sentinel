import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const JWT_REGEX = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]{2,}/g;

const SENSITIVE_CLAIM_KEYS = new Set([
  "password", "passwd", "secret", "ssn", "credit_card", "creditcard",
  "card_number", "cvv", "pin", "private_key", "privatekey",
]);

type JwtParts = { header: Record<string, unknown>; payload: Record<string, unknown> };

function decodeJwtParts(jwt: string): JwtParts | undefined {
  const parts = jwt.split(".");
  if (parts.length < 2) return { header: {}, payload: {} } as never;
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString()) as Record<string, unknown>;
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString()) as Record<string, unknown>;
  } catch {
    // Malformed base64 or JSON — signal failure via absent result
    const failed: JwtParts | undefined = void 0 as JwtParts | undefined;
    return failed;
  }
  return { header, payload };
}

function extractJwts(text: string): string[] {
  const matches = text.match(JWT_REGEX);
  return matches ?? [];
}

export const jwtClaimAuditCheck: ProbeCheck = {
  id: "jwt-claim-audit",
  level: "standard" as AggressionLevel,
  domain: "cryptography" as SecurityDomain,
  description: "Decode JWT tokens found in responses and flag insecure algorithm choices, missing expiration, and sensitive claim exposure",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const priorCryptoFinding = ctx.priorFindings.find(
      (f) => f.domain === "cryptography",
    );

    const method = ctx.target.method === "POST" ? "POST" : "GET";

    let resp: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number };

    try {
      resp = await ctx.client.request({
        method,
        url: ctx.target.url,
        intent: "read",
      });
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "jwt-claim-audit", targetUrl: ctx.target.url });
        return { findings, confirmed, refuted, errors };
      }
      errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "jwt-claim-audit" });
      return { findings, confirmed, refuted, errors };
    }

    // Collect JWT candidates from response body and Set-Cookie headers
    const sources: string[] = [resp.body];
    for (const [key, value] of Object.entries(resp.headers)) {
      if (key.toLowerCase() === "set-cookie") {
        sources.push(value);
      }
    }

    const allJwts = new Set<string>();
    for (const source of sources) {
      for (const jwt of extractJwts(source)) {
        allJwts.add(jwt);
      }
    }

    if (allJwts.size === 0) {
      return { findings, confirmed, refuted, errors };
    }

    let algNoneFound = false;

    for (const jwt of allJwts) {
      const decoded = decodeJwtParts(jwt);
      if (!decoded) continue;

      const { header, payload } = decoded;
      const alg = header["alg"];

      // Flag: alg: "none"
      if (typeof alg === "string" && alg.toLowerCase() === "none") {
        if (!algNoneFound) {
          algNoneFound = true;
          const finding: ProbeFinding = {
            id: `PROBE-JWT-ALGNONE-${randomUUID().slice(0, 8)}`,
            domain: "cryptography",
            severity: "critical",
            confidence: "confirmed",
            title: `JWT with alg:none detected: ${ctx.target.url}`,
            description: `A JWT token in the response uses alg:none, meaning no signature verification is performed. This allows attackers to forge arbitrary tokens and bypass authentication.`,
            evidence: [],
            remediation: "Reject JWTs with alg:none. Enforce an explicit allowlist of secure algorithms (e.g. RS256, ES256) on the server.",
            references: [
              "https://cwe.mitre.org/data/definitions/327.html",
              "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            ],
            layer: "probe",
            cwe: "CWE-327",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "jwt-claim-audit",
              aggressionLevel: "standard",
              request: { method, url: ctx.target.url, headers: {} },
              response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
            },
            confirms: priorCryptoFinding?.id,
          };
          findings.push(finding);
          if (priorCryptoFinding) {
            confirmed.push({ findingId: priorCryptoFinding.id });
          }
        }
      }

      // Flag: missing exp claim
      if (!("exp" in payload)) {
        findings.push({
          id: `PROBE-JWT-NOEXP-${randomUUID().slice(0, 8)}`,
          domain: "cryptography",
          severity: "medium",
          confidence: "confirmed",
          title: `JWT missing exp claim: ${ctx.target.url}`,
          description: `A JWT token in the response is missing the exp (expiration) claim. Tokens without expiration remain valid indefinitely, increasing the impact of token theft.`,
          evidence: [],
          remediation: "Include an exp claim in all JWT tokens and enforce short expiration windows (e.g. 15 minutes for access tokens).",
          references: [
            "https://cwe.mitre.org/data/definitions/613.html",
            "https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4",
          ],
          layer: "probe",
          cwe: "CWE-613",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "jwt-claim-audit",
            aggressionLevel: "standard",
            request: { method, url: ctx.target.url, headers: {} },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
        });
      }

      // Flag: sensitive claim keys
      const foundSensitiveKeys: string[] = [];
      for (const key of Object.keys(payload)) {
        if (SENSITIVE_CLAIM_KEYS.has(key.toLowerCase())) {
          foundSensitiveKeys.push(key);
        }
      }

      if (foundSensitiveKeys.length > 0) {
        findings.push({
          id: `PROBE-JWT-SENSITIVE-${randomUUID().slice(0, 8)}`,
          domain: "cryptography",
          severity: "high",
          confidence: "confirmed",
          title: `JWT contains sensitive claims: ${ctx.target.url}`,
          description: `A JWT token in the response contains sensitive claim key(s): ${foundSensitiveKeys.join(", ")}. JWT payloads are base64-encoded and trivially decoded — sensitive data should never be stored in JWT claims.`,
          evidence: [],
          remediation: "Remove sensitive data from JWT claims. Store only identifiers (e.g. user ID) in the token and retrieve sensitive data server-side as needed.",
          references: [
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
          ],
          layer: "probe",
          cwe: "CWE-312",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "jwt-claim-audit",
            aggressionLevel: "standard",
            request: { method, url: ctx.target.url, headers: {} },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
        });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
