import { readFile } from "fs/promises";
import fg from "fast-glob";
import { basename } from "path";

// System-level directories sentinel must never read, even when the user
// explicitly points it at them. This is a last-line safety net, not a
// trust boundary — scans should never target these paths in the first place.
const DENY_PATTERNS: RegExp[] = [
  /(?:^|\/)proc\//,
  /(?:^|\/)sys\//,
  /(?:^|\/)dev\//,
  /(?:^|\/)etc\//,
  /(?:^|\/)root\//,
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
