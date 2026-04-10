import { readFile } from "fs/promises";
import fg from "fast-glob";
import { basename } from "path";

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

  const name = basename(path);
  if (name === ".env" || /^\.env\.[a-z]+$/.test(name)) {
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
