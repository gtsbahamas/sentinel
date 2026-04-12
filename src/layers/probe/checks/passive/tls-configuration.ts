import { randomUUID } from "crypto";
import * as tls from "tls";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1"]);

function inspectTls(hostname: string, port: number): Promise<{
  protocol: string;
  cipher: string;
  certValid: boolean;
  certExpiry: string | null;
  certSubject: string | null;
} | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      const protocol = socket.getProtocol() ?? "unknown";
      const cipher = socket.getCipher()?.name ?? "unknown";
      const cert = socket.getPeerCertificate();
      const certValid = socket.authorized;
      const certExpiry = cert?.valid_to ?? null;
      const rawCN = cert?.subject?.CN;
      const certSubject = typeof rawCN === "string" ? rawCN : Array.isArray(rawCN) ? rawCN[0] ?? null : null;
      socket.end();
      resolve({ protocol, cipher, certValid, certExpiry, certSubject });
    });
    socket.setTimeout(5000);
    socket.on("timeout", () => { socket.destroy(); resolve(null); });
    socket.on("error", () => { resolve(null); });
  });
}

export const tlsConfigurationCheck: ProbeCheck = {
  id: "tls-configuration",
  level: "passive" as AggressionLevel,
  domain: "cryptography" as SecurityDomain,
  description: "Inspect TLS handshake for weak protocols, ciphers, and cert issues",

  appliesTo(target: ProbeTarget): boolean {
    if (target.kind !== "baseline") return false;
    try {
      return new URL(target.url).protocol === "https:";
    } catch {
      return false;
    }
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];

    try {
      const u = new URL(ctx.target.url);
      const port = u.port ? parseInt(u.port, 10) : 443;
      const result = await inspectTls(u.hostname, port);

      if (!result) {
        errors.push({ kind: "target-unreachable", message: "TLS handshake failed or timed out", checkId: "tls-configuration", targetUrl: ctx.target.url });
        return { findings, confirmed: [], refuted: [], errors };
      }

      if (WEAK_PROTOCOLS.has(result.protocol)) {
        findings.push({
          id: `PROBE-TLS-${randomUUID().slice(0, 8)}`,
          domain: "cryptography",
          severity: "high",
          confidence: "confirmed",
          title: `Weak TLS protocol: ${result.protocol}`,
          description: `Server negotiated ${result.protocol}, which is deprecated and vulnerable to known attacks`,
          evidence: [],
          remediation: "Configure the server to support TLSv1.2+ only",
          references: ["https://datatracker.ietf.org/doc/html/rfc8996"],
          layer: "probe",
          cwe: "CWE-326",
          probeEvidence: {
            requestId: randomUUID(),
            checkId: "tls-configuration",
            aggressionLevel: "passive",
            request: { method: "GET", url: ctx.target.url, headers: {} },
            response: {
              status: 0,
              headers: {},
              bodyPreview: JSON.stringify(result),
              timingMs: 0,
            },
          },
        });
      }

      if (!result.certValid) {
        findings.push({
          id: `PROBE-TLS-${randomUUID().slice(0, 8)}`,
          domain: "cryptography",
          severity: "medium",
          confidence: "confirmed",
          title: "TLS certificate validation failed",
          description: `Certificate for ${result.certSubject ?? u.hostname} did not pass validation (self-signed, expired, or hostname mismatch)`,
          evidence: [],
          remediation: "Use a valid certificate from a trusted CA",
          references: [],
          layer: "probe",
          cwe: "CWE-295",
          probeEvidence: {
            requestId: randomUUID(),
            checkId: "tls-configuration",
            aggressionLevel: "passive",
            request: { method: "GET", url: ctx.target.url, headers: {} },
            response: {
              status: 0,
              headers: {},
              bodyPreview: JSON.stringify({ certValid: false, certExpiry: result.certExpiry, certSubject: result.certSubject }),
              timingMs: 0,
            },
          },
        });
      }
    } catch (err) {
      errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "tls-configuration" });
    }

    return { findings, confirmed: [], refuted: [], errors };
  },
};
