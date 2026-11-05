import { readFile } from "fs/promises";
import fg from "fast-glob";
import { basename } from "path";

// System-level directories sentinel must never read, even when the user
// explicitly points it at them. This is a last-line safety net, not a
// trust boundary — scans should never target these paths in the first place.
// Anchor to absolute root so a project subdirectory like `src/components/dev/`
// is not mistaken for the `/dev/` system path.
const DENY_PATTERNS: RegExp[] = [
  /^\/proc\//,
  /^\/sys\//,
  /^\/dev\//,
  /^\/etc\//,
  /^\/root\//,
  /(?:^|\/)\.ssh\//,
];

export function isDeniedPath(path: string): boolean {
  for (const pattern of DENY_PATTERNS) {
    if (pattern.test(path)) return true;
  }

  // By default .env files are not read during the generic source walk —
  // they contain real secrets we don't want to echo into JSON output or
  // LLM prompts by accident. Rules that legitimately need them call
  // `readEnvFile` which does not consult the generic deny list.
  const name = basename(path);
  if (name === ".env" || /^\.env\.[a-z0-9]+$/.test(name)) {
    if (name === ".env.example" || name === ".env.sample") return false;
    return true;
  }

  return false;
}

export async function safeReadFile(path: string): Promise<string> {
  if (isDeniedPath(path)) {
    throw new Error(`Access denied: ${path}`);
  }
  return readFile(path, "utf-8");
}

// Read a .env-style file for security analysis. Bypasses the default
// deny on .env but still refuses system paths. Returns empty string if
// the file doesn't exist so rules can treat "missing" as "nothing to flag".
export async function readEnvFile(path: string): Promise<string> {
  for (const pattern of DENY_PATTERNS) {
    if (pattern.test(path)) {
      throw new Error(`Access denied: ${path}`);
    }
  }
  try {
    return await readFile(path, "utf-8");
  } catch {
    return "";
  }
}

export function parseEnvFile(contents: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of contents.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

export async function walkProject(
  projectPath: string,
  exclude: string[],
): Promise<string[]> {
  const patterns = ["**/*.{ts,tsx,js,jsx,mjs,cjs,json,md,yaml,yml,toml}"];
  const ignore = exclude.map((e) => `**/${e}/**`);

  const files = await fg(patterns, {
    cwd: projectPath,
    absolute: true,
    ignore,
    dot: true,
    followSymbolicLinks: false,
  });

  return files.filter((f) => !isDeniedPath(f));
}

// ---------------------------------------------------------------------------
// Repo-artifact walk (repo-integrity domain)
// ---------------------------------------------------------------------------

/** One file found by `walkRepoArtifacts`. `size` is bytes on disk. */
export interface RepoArtifact {
  /** Absolute path. */
  path: string;
  /** Path relative to the project root, POSIX separators — what we report. */
  rel: string;
  size: number;
}

// `walkProject` is extension-allowlisted to text source
// (**/*.{ts,tsx,js,jsx,mjs,cjs,json,md,yaml,yml,toml}), which is correct for
// every rule that parses code. It also means a committed .exe, .zip or .cmd is
// not scored low — it is never enumerated at all, so no rule can see it.
//
// This walk is the deliberate complement: EVERY file, no extension allowlist,
// stat'd but never read. Rules decide what to open.
//
// `public` is dropped from the caller's exclude list here on purpose. It is
// excluded from the source walk because it holds build output and static
// assets — which is exactly where a committed binary would sit unremarked.
// Ordinary assets (images, fonts, PDFs) match no rule in this domain, so
// re-including the directory costs a stat and buys the coverage that matters.
export async function walkRepoArtifacts(
  projectPath: string,
  exclude: string[],
): Promise<RepoArtifact[]> {
  const ignore = exclude.filter((e) => e !== "public").map((e) => `**/${e}/**`);

  const entries = await fg("**/*", {
    cwd: projectPath,
    absolute: true,
    ignore,
    dot: true,
    followSymbolicLinks: false,
    onlyFiles: true,
    stats: true,
    suppressErrors: true,
  });

  const out: RepoArtifact[] = [];
  for (const e of entries) {
    const abs = typeof e === "string" ? e : e.path;
    if (isDeniedPath(abs)) continue;
    const size = typeof e === "string" ? 0 : (e.stats?.size ?? 0);
    let rel = abs.startsWith(projectPath) ? abs.slice(projectPath.length) : abs;
    rel = rel.replace(/^[/\\]+/, "").split("\\").join("/");
    out.push({ path: abs, rel, size });
  }
  return out;
}
