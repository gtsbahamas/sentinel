// ShipSafe push adapter.
//
// After a scan produces Finding[], this module POSTs the scan to a ShipSafe
// instance and streams findings into it. Failures are logged as warnings but
// never fail the scan — the scan's terminal/json/html output is the primary
// artifact, ShipSafe is a secondary sink.
//
// ShipSafe API contract (see shipsafe/web/src/app/api/scans/*):
//   POST   /api/scans                        { project_id, sentinel_run_id? } -> 201 { scan_id }
//   POST   /api/scans/:id/findings           { findings: FindingIngestInput[] } -> 201 { inserted }
//   PATCH  /api/scans/:id/status             { status: "running"|"complete"|"failed", ... } -> 200 { ok: true }
//
// Auth is `Authorization: Bearer ssk_<project-token>` on every request.
import type { Finding } from "../model/types.js";

export interface ShipSafeConfig {
  url: string;
  token: string;
  projectId: string;
  sentinelRunId?: string;
}

export interface ShipSafePushResult {
  ok: boolean;
  scanId?: string;
  inserted: number;
  skipped: number;
  error?: string;
}

// ShipSafe's /api/scans/:id/findings validator expects these exact fields
// (see shipsafe/web/src/app/api/scans/[id]/findings/route.ts::validateFinding).
// Note: snake_case at the wire boundary; Sentinel's internal Finding is
// camelCase/flat, so we translate here.
interface ShipSafeFindingInput {
  sentinel_finding_id: string;
  domain: string;
  severity: string;
  confidence: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  layer: string;
  evidence?: Record<string, unknown>;
  cwe?: string | null;
  owasp?: string | null;
}

const DEFAULT_BATCH_SIZE = 50;
// Give edge functions headroom for cold starts but don't hang the scan
// indefinitely if ShipSafe is unreachable.
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Resolve ShipSafe config from CLI options, falling back to env vars. Returns
 * null if the user hasn't opted in to ShipSafe pushing (no url/token/project).
 *
 * Env precedence: CLI flag > env var.
 */
export function resolveShipSafeConfig(opts: {
  url?: string;
  token?: string;
  projectId?: string;
  sentinelRunId?: string;
}): ShipSafeConfig | null {
  const url = (opts.url ?? process.env.SHIPSAFE_URL ?? "").trim();
  const token = (opts.token ?? process.env.SHIPSAFE_TOKEN ?? "").trim();
  const projectId = (opts.projectId ?? process.env.SHIPSAFE_PROJECT_ID ?? "").trim();
  const sentinelRunId = (opts.sentinelRunId ?? process.env.SHIPSAFE_RUN_ID)?.trim() || undefined;

  // All three are required to push. If only some are set, warn the caller
  // rather than silently skip — partial config is almost always a mistake.
  if (!url && !token && !projectId) return null;
  if (!url || !token || !projectId) {
    const missing: string[] = [];
    if (!url) missing.push("url");
    if (!token) missing.push("token");
    if (!projectId) missing.push("project-id");
    process.stderr.write(
      `[shipsafe] partial configuration, skipping push (missing: ${missing.join(", ")})\n`,
    );
    return null;
  }

  return { url: stripTrailingSlash(url), token, projectId, sentinelRunId };
}

function stripTrailingSlash(u: string): string {
  return u.endsWith("/") ? u.slice(0, -1) : u;
}

/**
 * Translate a Sentinel `Finding` to the ShipSafe ingest shape. Sentinel
 * `evidence` is an array of location records; ShipSafe accepts a single
 * optional object. We pack the primary evidence entry (file/line/snippet)
 * plus an `additional` array if there's more.
 */
// ShipSafe only accepts "high" | "medium" | "low" for confidence. Sentinel also
// emits "confirmed" for findings the verify pass has proven. Map "confirmed" to
// "high" at the wire boundary so ShipSafe never rejects a batch with
// confidence_invalid; preserve the original by prefixing the title below.
function mapConfidence(c: Finding["confidence"]): "high" | "medium" | "low" {
  return c === "confirmed" ? "high" : c;
}

function toShipSafeFinding(f: Finding): ShipSafeFindingInput {
  const [primary, ...rest] = f.evidence;
  const evidence: Record<string, unknown> | undefined = primary
    ? {
        file: primary.file,
        ...(primary.line !== undefined ? { line: primary.line } : {}),
        ...(primary.column !== undefined ? { column: primary.column } : {}),
        ...(primary.snippet !== undefined ? { snippet: primary.snippet } : {}),
        ...(primary.context !== undefined ? { context: primary.context } : {}),
        ...(rest.length > 0 ? { additional: rest } : {}),
        ...(f.references.length > 0 ? { references: f.references } : {}),
        ...(f.ruleId !== undefined ? { rule_id: f.ruleId } : {}),
      }
    : f.references.length > 0 || f.ruleId !== undefined
      ? {
          ...(f.references.length > 0 ? { references: f.references } : {}),
          ...(f.ruleId !== undefined ? { rule_id: f.ruleId } : {}),
        }
      : undefined;

  return {
    sentinel_finding_id: f.id,
    domain: f.domain,
    severity: f.severity,
    confidence: mapConfidence(f.confidence),
    title: f.title,
    description: f.description,
    impact: f.impact,
    remediation: f.remediation,
    layer: f.layer,
    ...(evidence !== undefined ? { evidence } : {}),
    ...(f.cwe !== undefined ? { cwe: f.cwe } : {}),
    ...(f.owasp !== undefined ? { owasp: f.owasp } : {}),
  };
}

interface RequestOptions {
  method: "POST" | "PATCH";
  path: string;
  body: unknown;
  timeoutMs?: number;
}

async function shipsafeRequest(
  config: ShipSafeConfig,
  opts: RequestOptions,
): Promise<{ ok: boolean; status: number; body: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetch(`${config.url}${opts.path}`, {
      method: opts.method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.token}`,
      },
      body: JSON.stringify(opts.body),
      signal: controller.signal,
    });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // Non-JSON body (edge function 502, HTML error page, etc.) — leave null.
    }
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(timeout);
  }
}

function describeError(body: unknown, status: number): string {
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error: unknown }).error;
    if (typeof err === "string") return `${status} ${err}`;
  }
  return `${status}`;
}

/**
 * Push a scan + findings to ShipSafe. Never throws — all errors are caught,
 * logged to stderr, and reported via the result object. The caller should
 * call this AFTER primary scan output (terminal/json/html) is written, so
 * a ShipSafe outage cannot break the main CLI contract.
 */
export async function pushToShipSafe(
  findings: Finding[],
  config: ShipSafeConfig,
  opts: { batchSize?: number; timeoutMs?: number } = {},
): Promise<ShipSafePushResult> {
  const batchSize = Math.max(1, opts.batchSize ?? DEFAULT_BATCH_SIZE);
  const result: ShipSafePushResult = { ok: false, inserted: 0, skipped: 0 };

  // Step 1: create the scan.
  let scanId: string;
  try {
    const createRes = await shipsafeRequest(config, {
      method: "POST",
      path: "/api/scans",
      body: {
        project_id: config.projectId,
        ...(config.sentinelRunId ? { sentinel_run_id: config.sentinelRunId } : {}),
      },
      timeoutMs: opts.timeoutMs,
    });
    if (!createRes.ok) {
      result.error = `create_scan_failed: ${describeError(createRes.body, createRes.status)}`;
      process.stderr.write(`[shipsafe] ${result.error}\n`);
      return result;
    }
    const body = createRes.body as { scan_id?: unknown } | null;
    if (!body || typeof body.scan_id !== "string") {
      result.error = "create_scan_invalid_response";
      process.stderr.write(`[shipsafe] ${result.error}\n`);
      return result;
    }
    scanId = body.scan_id;
    result.scanId = scanId;
  } catch (err) {
    result.error = `create_scan_network_error: ${err instanceof Error ? err.message : String(err)}`;
    process.stderr.write(`[shipsafe] ${result.error}\n`);
    return result;
  }

  // Step 2: batch-insert findings. A single batch failure doesn't abort the
  // whole push — we report partial success so the user sees what landed.
  // ShipSafe's ingest is transactional per-batch (Supabase insert of an array),
  // so a batch-level failure means zero from that batch were persisted.
  let sawBatchFailure = false;
  const batches = chunk(findings.map(toShipSafeFinding), batchSize);
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    try {
      const res = await shipsafeRequest(config, {
        method: "POST",
        path: `/api/scans/${scanId}/findings`,
        body: { findings: batch },
        timeoutMs: opts.timeoutMs,
      });
      if (!res.ok) {
        sawBatchFailure = true;
        result.skipped += batch.length;
        process.stderr.write(
          `[shipsafe] batch ${i + 1}/${batches.length} failed: ${describeError(res.body, res.status)}\n`,
        );
        continue;
      }
      const body = res.body as { inserted?: unknown } | null;
      const inserted =
        body && typeof body.inserted === "number" ? body.inserted : batch.length;
      result.inserted += inserted;
    } catch (err) {
      sawBatchFailure = true;
      result.skipped += batch.length;
      process.stderr.write(
        `[shipsafe] batch ${i + 1}/${batches.length} network error: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
  }

  // Step 3: mark the scan terminal. If ANY batch failed we report "failed"
  // so the dashboard shows the partial-ingest state; otherwise "complete".
  const finalStatus = sawBatchFailure ? "failed" : "complete";
  try {
    const res = await shipsafeRequest(config, {
      method: "PATCH",
      path: `/api/scans/${scanId}/status`,
      body: {
        status: finalStatus,
        completed_at: new Date().toISOString(),
        ...(sawBatchFailure
          ? { error: `partial_ingest: ${result.skipped} finding(s) not persisted` }
          : {}),
      },
      timeoutMs: opts.timeoutMs,
    });
    if (!res.ok) {
      // Status update failed but findings may have landed — don't overwrite
      // a per-batch error if one is already set.
      const statusErr = `status_update_failed: ${describeError(res.body, res.status)}`;
      process.stderr.write(`[shipsafe] ${statusErr}\n`);
      if (!result.error) result.error = statusErr;
    }
  } catch (err) {
    const statusErr = `status_update_network_error: ${err instanceof Error ? err.message : String(err)}`;
    process.stderr.write(`[shipsafe] ${statusErr}\n`);
    if (!result.error) result.error = statusErr;
  }

  result.ok = !sawBatchFailure && !result.error;
  if (result.ok) {
    process.stderr.write(
      `[shipsafe] pushed ${result.inserted} finding(s) to scan ${scanId}\n`,
    );
  }
  return result;
}

function chunk<T>(arr: T[], size: number): T[][] {
  if (arr.length === 0) return [];
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}
