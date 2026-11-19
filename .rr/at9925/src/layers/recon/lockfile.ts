import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join } from "path";

/** A package at the exact version the lockfile installs. */
export interface LockedPackage {
  name: string;
  version: string;
}

export interface Lockfile {
  file: string;
  kind: "package-lock" | "pnpm-lock" | "yarn-lock";
  packages: LockedPackage[];
}

// Exact versions only. package.json ranges ("^4.17.0") say nothing about what
// is installed, so vulnerability lookups must resolve through a lockfile.
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;

function dedupe(pkgs: LockedPackage[]): LockedPackage[] {
  const seen = new Set<string>();
  const out: LockedPackage[] = [];
  for (const p of pkgs) {
    if (!p.name || !EXACT_VERSION.test(p.version)) continue;
    const key = `${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

/** Split "name@version" where name may itself start with "@scope/". */
function splitAt(spec: string): [string, string] | null {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  return [spec.slice(0, at), spec.slice(at + 1)];
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string): LockedPackage[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; link?: boolean; name?: string }>;
    dependencies?: Record<string, V1Dep>;
  };
  const out: LockedPackage[] = [];
  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.link || !entry.version) continue;
      const name = entry.name ?? path.split("node_modules/").pop();
      if (name) out.push({ name, version: entry.version });
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, V1Dep>) => {
      for (const [name, dep] of Object.entries(deps)) {
        if (dep.version) out.push({ name, version: dep.version });
        if (dep.dependencies) walk(dep.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return dedupe(out);
}

interface V1Dep {
  version?: string;
  dependencies?: Record<string, V1Dep>;
}

/**
 * pnpm-lock.yaml v5 ("/name/1.0.0"), v6 ("/name@1.0.0(peer@x)") and v9
 * ("name@1.0.0" under packages: and snapshots:). Only the top-level keys of
 * those two sections are read, so no YAML parse of the whole file is needed.
 */
export function parsePnpmLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let inSection = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inSection = /^(packages|snapshots):\s*$/.test(line);
      continue;
    }
    if (!inSection) continue;
    const m = line.match(/^ {2}(\S.*):\s*$/);
    if (!m) continue;
    let key = m[1].replace(/^['"]|['"]$/g, "");
    key = key.replace(/^\//, "").replace(/\(.*$/, "");
    let parsed = splitAt(key);
    if (!parsed || !EXACT_VERSION.test(parsed[1])) {
      // v5: "name/1.0.0" or "@scope/name/1.0.0_peer@x"
      const v5 = key.replace(/_.*$/, "");
      const slash = v5.lastIndexOf("/");
      parsed = slash > 0 ? [v5.slice(0, slash), v5.slice(slash + 1)] : null;
    }
    if (parsed) out.push({ name: parsed[0], version: parsed[1] });
  }
  return dedupe(out);
}

/** yarn.lock, classic (v1) and berry (v2+). */
export function parseYarnLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  let current: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.trimEnd().endsWith(":") && !line.startsWith("#")) {
      const first = line.slice(0, -1).split(",")[0].trim().replace(/^"|"$/g, "");
      current = first === "__metadata" || first.includes("@workspace:") ? null : first;
      continue;
    }
    if (!current) continue;
    const v = line.match(/^ {2}version:?\s+"?([^"\s]+)"?\s*$/);
    if (!v) continue;
    const parsed = splitAt(current);
    if (parsed) out.push({ name: parsed[0], version: v[1] });
    current = null;
  }
  return dedupe(out);
}

const LOCKFILES: Array<{ name: string; kind: Lockfile["kind"]; parse: (t: string) => LockedPackage[] }> = [
  { name: "pnpm-lock.yaml", kind: "pnpm-lock", parse: parsePnpmLock },
  { name: "package-lock.json", kind: "package-lock", parse: parsePackageLock },
  { name: "npm-shrinkwrap.json", kind: "package-lock", parse: parsePackageLock },
  { name: "yarn.lock", kind: "yarn-lock", parse: parseYarnLock },
];

/** The project's lockfile with exact installed versions, or null if none can be read. */
export async function readLockfile(root: string): Promise<Lockfile | null> {
  for (const { name, kind, parse } of LOCKFILES) {
    const file = join(root, name);
    if (!existsSync(file)) continue;
    try {
      return { file, kind, packages: parse(await readFile(file, "utf-8")) };
    } catch {
      continue;
    }
  }
  return null;
}
