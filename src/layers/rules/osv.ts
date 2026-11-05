// Live vulnerability lookups against OSV.dev (https://osv.dev, no API key).
//
// The scanned project's lockfile gives exact installed versions; those go to
// the OSV batch API, and every advisory id that comes back is fetched once for
// its severity, publish date and fixed version. Any failure — offline, OSV
// down, timeout, bad JSON — returns a "skipped" status with the reason, so the
// caller can fall back to the curated list and say the live check did not run.

import type { FindingAdvisory, Severity } from "../../model/types.js";
import { readLockfile, type LockedPackage, type Lockfile } from "../recon/lockfile.js";

export type Advisory = FindingAdvisory;

export type LiveVulnStatus =
  | { status: "ok"; lockfile: Lockfile; advisories: Advisory[] }
  | { status: "skipped"; reason: string; lockfile: Lockfile | null };

export interface LiveVulnOptions {
  fetch?: typeof fetch;
  /** Base URL, default https://api.osv.dev. */
  endpoint?: string;
  timeoutMs?: number;
}

const DEFAULT_ENDPOINT = "https://api.osv.dev";
const DEFAULT_TIMEOUT_MS = 15_000;
// OSV documents 1000 queries per querybatch call.
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 8;

let options: LiveVulnOptions = {};
// Long-lived hosts (MCP server, dashboard) rescan; advisories change, so a
// cached answer is only reused for a short while.
const MEMO_TTL_MS = 10 * 60_000;
const memo = new Map<string, { at: number; result: Promise<LiveVulnStatus> }>();

/** Override the OSV client (tests, offline tooling). Pass null to restore defaults. */
export function configureLiveVulnCheck(opts: LiveVulnOptions | null): void {
  options = opts ?? {};
  memo.clear();
}

/**
 * Live OSV status for the project at `root`. Memoised per root and lockfile
 * content so SUPPLY-001 and SUPPLY-011 share one round of network calls.
 */
export async function checkLiveVulnerabilities(root: string): Promise<LiveVulnStatus> {
  const lockfile = await readLockfile(root);
  if (!lockfile) {
    return { status: "skipped", reason: "no lockfile (pnpm-lock.yaml, package-lock.json or yarn.lock) to resolve exact versions", lockfile: null };
  }
  if (process.env.SENTINEL_OFFLINE === "1") {
    return { status: "skipped", reason: "SENTINEL_OFFLINE=1 is set", lockfile };
  }
  const key = `${root}\0${JSON.stringify(lockfile.packages)}`;
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < MEMO_TTL_MS) return hit.result;
  const result = queryOsv(lockfile);
  memo.set(key, { at: Date.now(), result });
  return result;
}

async function queryOsv(lockfile: Lockfile): Promise<LiveVulnStatus> {
  const doFetch = options.fetch ?? fetch;
  const endpoint = (options.endpoint ?? DEFAULT_ENDPOINT).replace(/\/$/, "");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const call = async (path: string, init?: RequestInit): Promise<unknown> => {
    const res = await doFetch(`${endpoint}${path}`, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`OSV ${path} returned HTTP ${res.status}`);
    return res.json();
  };

  try {
    // 1. Which advisory ids hit which locked package?
    const hits = new Map<string, LockedPackage[]>();
    for (let i = 0; i < lockfile.packages.length; i += BATCH_SIZE) {
      let pending = lockfile.packages.slice(i, i + BATCH_SIZE).map((pkg) => ({ pkg, pageToken: undefined as string | undefined }));
      while (pending.length) {
        const body = {
          queries: pending.map(({ pkg, pageToken }) => ({
            package: { name: pkg.name, ecosystem: "npm" },
            version: pkg.version,
            ...(pageToken ? { page_token: pageToken } : {}),
          })),
        };
        const data = (await call("/v1/querybatch", { method: "POST", body: JSON.stringify(body) })) as {
          results?: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }>;
        };
        if (!Array.isArray(data.results) || data.results.length !== pending.length) {
          throw new Error("OSV querybatch returned a malformed response");
        }
        const next: typeof pending = [];
        data.results.forEach((r, idx) => {
          const { pkg } = pending[idx];
          for (const v of r.vulns ?? []) {
            if (!hits.has(v.id)) hits.set(v.id, []);
            hits.get(v.id)!.push(pkg);
          }
          if (r.next_page_token) next.push({ pkg, pageToken: r.next_page_token });
        });
        pending = next;
      }
    }

    // 2. Details for each advisory id, once.
    const ids = [...hits.keys()];
    const records = new Map<string, OsvRecord>();
    for (let i = 0; i < ids.length; i += DETAIL_CONCURRENCY) {
      const slice = ids.slice(i, i + DETAIL_CONCURRENCY);
      const got = await Promise.all(slice.map((id) => call(`/v1/vulns/${encodeURIComponent(id)}`) as Promise<OsvRecord>));
      slice.forEach((id, idx) => records.set(id, got[idx]));
    }

    const advisories: Advisory[] = [];
    for (const [id, pkgs] of hits) {
      const rec = records.get(id)!;
      for (const pkg of pkgs) {
        advisories.push({
          id,
          aliases: rec.aliases ?? [],
          package: pkg.name,
          installedVersion: pkg.version,
          fixedVersion: fixedVersionFor(rec, pkg),
          published: rec.published ?? null,
          severity: severityOf(rec),
          summary: rec.summary ?? rec.details?.split("\n")[0] ?? id,
          source: "osv",
        });
      }
    }
    return { status: "ok", lockfile, advisories };
  } catch (err) {
    // undici reports "fetch failed" and keeps the useful part in cause.
    const e = err as Error & { cause?: { code?: unknown; message?: string } };
    const detail = typeof e.cause?.code === "string" ? e.cause.code : e.cause?.message;
    return { status: "skipped", reason: detail ? `${e.message} (${detail})` : e.message, lockfile };
  }
}

interface OsvRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  database_specific?: { severity?: string };
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
    database_specific?: { severity?: string };
  }>;
}

function severityOf(rec: OsvRecord): Severity {
  const label = (rec.database_specific?.severity ?? rec.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ?? "").toUpperCase();
  if (label === "CRITICAL") return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  // OSV MAL- records (malicious packages) carry no severity label.
  if (rec.id.startsWith("MAL-")) return "critical";
  return "medium";
}

/** The fixed version of the affected range that contains the installed version. */
export function fixedVersionFor(rec: OsvRecord, pkg: LockedPackage): string | null {
  const candidates: string[] = [];
  for (const aff of rec.affected ?? []) {
    if (aff.package?.name !== pkg.name || (aff.package?.ecosystem ?? "npm") !== "npm") continue;
    for (const range of aff.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      let introduced: string | null = null;
      for (const ev of range.events) {
        if (ev.introduced !== undefined) introduced = ev.introduced;
        if (ev.fixed !== undefined) {
          const lowOk = introduced === null || introduced === "0" || compareSemver(pkg.version, introduced) >= 0;
          if (lowOk && compareSemver(pkg.version, ev.fixed) < 0) return ev.fixed;
          candidates.push(ev.fixed);
          introduced = null;
        }
      }
    }
  }
  const above = candidates.filter((v) => compareSemver(v, pkg.version) > 0).sort(compareSemver);
  return above[0] ?? null;
}

export function compareSemver(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre] = v.replace(/^v/, "").split("+")[0].split(/-(.*)/s);
    return { nums: core.split(".").map((n) => parseInt(n, 10) || 0), pre: pre ?? "" };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d) return d;
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}
