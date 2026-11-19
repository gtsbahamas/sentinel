import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import type { AggressionLevel, ProbeAuthorizationEntry, ProbeConfig } from "../../model/types.js";

export interface AuthorizationResolution {
  state: "granted" | "needs-prompt" | "denied-deny-list" | "denied-public" | "denied-internal" | "expired";
  entry?: ProbeAuthorizationEntry;
  reason?: string;
}

const DEFAULT_DENY_HOSTS = [
  "google.com", "www.google.com",
  "microsoft.com", "www.microsoft.com",
  "amazon.com", "www.amazon.com", "aws.amazon.com",
  "apple.com", "icloud.com",
  "github.com", "gitlab.com",
  "cloudflare.com",
  "facebook.com", "meta.com",
  "openai.com", "anthropic.com",
];

const RFC1918_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
  "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
  "192.168."];

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function isRfc1918(hostname: string): boolean {
  return RFC1918_PREFIXES.some((p) => hostname.startsWith(p));
}

function isPublicHost(hostname: string): boolean {
  return !isLoopback(hostname) && !isRfc1918(hostname);
}

export function parseTargetOrigin(targetUrl: string): string {
  const u = new URL(targetUrl);
  const port = u.port ? `:${u.port}` : "";
  return `${u.protocol}//${u.hostname}${port}`;
}

export function resolveAuthorization(args: {
  targetUrl: string;
  requestedLevel: AggressionLevel;
  config: ProbeConfig;
  existingEntries: ProbeAuthorizationEntry[];
  authorizeFlagPresent: boolean;
}): AuthorizationResolution {
  const { targetUrl, requestedLevel, config, existingEntries, authorizeFlagPresent } = args;

  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return { state: "denied-deny-list", reason: `Invalid target URL: ${targetUrl}` };
  }

  const origin = parseTargetOrigin(targetUrl);
  const denyHosts = [...DEFAULT_DENY_HOSTS, ...config.denyHosts];

  if (denyHosts.some((h) => hostname === h || hostname.endsWith(`.${h}`))) {
    return { state: "denied-deny-list", reason: `${hostname} is on the deny-list` };
  }

  if (isRfc1918(hostname) && !config.allowInternalNetwork) {
    return { state: "denied-internal", reason: `${hostname} is an RFC1918 address; pass --internal-network` };
  }

  if (isPublicHost(hostname) && !config.allowPublicHosts) {
    return { state: "denied-public", reason: `${hostname} is a public host; pass --allow-public` };
  }

  if (requestedLevel === "intrusive") {
    return { state: "needs-prompt", reason: "Intrusive level always requires interactive re-authorization" };
  }

  const levelOrder: AggressionLevel[] = ["passive", "standard", "intrusive"];
  const requestedIdx = levelOrder.indexOf(requestedLevel);

  const matching = existingEntries.find((e) => {
    if (e.targetOrigin !== origin) return false;
    const entryIdx = levelOrder.indexOf(e.level);
    return entryIdx >= requestedIdx;
  });

  if (matching) {
    if (new Date(matching.expiresAt) < new Date()) {
      return { state: "expired", entry: matching, reason: "Authorization expired" };
    }
    return { state: "granted", entry: matching };
  }

  if (authorizeFlagPresent) {
    return { state: "needs-prompt" };
  }

  return { state: "needs-prompt", reason: `No authorization for ${origin} at level ${requestedLevel}; pass --authorize` };
}

export function buildAuthorizationEntry(
  targetUrl: string,
  level: "passive" | "standard",
  scopeNote: string,
  expiryDays = 30,
): ProbeAuthorizationEntry {
  const now = new Date();
  const expiry = new Date(now.getTime() + expiryDays * 24 * 60 * 60 * 1000);
  return {
    targetOrigin: parseTargetOrigin(targetUrl),
    level,
    grantedAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
    scopeNote,
  };
}

export async function loadAuthorizations(projectPath: string): Promise<ProbeAuthorizationEntry[]> {
  const configPath = join(projectPath, ".sentinelrc.json");
  if (!existsSync(configPath)) return [];
  try {
    const raw = JSON.parse(await readFile(configPath, "utf-8"));
    return raw?.probe?.authorizations ?? [];
  } catch {
    return [];
  }
}

export async function persistAuthorization(
  projectPath: string,
  entry: ProbeAuthorizationEntry,
): Promise<void> {
  const configPath = join(projectPath, ".sentinelrc.json");
  let config: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    try {
      config = JSON.parse(await readFile(configPath, "utf-8"));
    } catch {
      /* start fresh */
    }
  }

  const probe = (config.probe as Record<string, unknown>) ?? {};
  const existing = (probe.authorizations as ProbeAuthorizationEntry[]) ?? [];

  const filtered = existing.filter((e) => e.targetOrigin !== entry.targetOrigin);
  filtered.push(entry);

  config.probe = { ...probe, authorizations: filtered };
  await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

export async function removeExpiredAuthorizations(projectPath: string): Promise<number> {
  const configPath = join(projectPath, ".sentinelrc.json");
  if (!existsSync(configPath)) return 0;

  const config = JSON.parse(await readFile(configPath, "utf-8"));
  const probe = config.probe ?? {};
  const existing: ProbeAuthorizationEntry[] = probe.authorizations ?? [];

  const now = new Date();
  const valid = existing.filter((e) => new Date(e.expiresAt) > now);
  const removed = existing.length - valid.length;

  if (removed > 0) {
    config.probe = { ...probe, authorizations: valid };
    await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  }
  return removed;
}
