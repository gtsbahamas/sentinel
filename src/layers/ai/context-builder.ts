import { readFile } from "fs/promises";
import { dirname, resolve as resolvePath, relative } from "path";
import type { ApiEndpoint, ProjectModel } from "../../model/types.js";
import type { AdjacentFile } from "./prompts.js";

export interface EndpointContext {
  handlerSource: string;
  adjacent: AdjacentFile[];
}

const CHARS_PER_TOKEN = 4;
const MAX_ADJACENT = 3;
const MAX_IMPORT_DEPTH = 1;

function approxTokens(s: string): number {
  return Math.ceil(s.length / CHARS_PER_TOKEN);
}

/**
 * Extract only the route handler function(s) from a Next.js App Router file.
 * Looks for exported GET/POST/PUT/DELETE/PATCH functions and returns just those,
 * plus any import statements (for context on what libraries are used).
 * Falls back to the full source if no handlers are found (e.g. Express/non-Next).
 */
function extractHandlers(source: string): string {
  const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
  const lines = source.split("\n");

  // Collect import lines (small, useful context for the LLM)
  const importLines: string[] = [];
  const handlerRanges: Array<[number, number]> = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Collect imports
    if (/^\s*import\s/.test(line)) {
      // Handle multi-line imports
      let importEnd = i;
      if (!line.includes("from") || (!line.trimEnd().endsWith(";") && !line.trimEnd().endsWith("'"))) {
        while (importEnd < lines.length - 1 && !lines[importEnd].includes("from")) {
          importEnd++;
        }
      }
      for (let j = i; j <= importEnd; j++) importLines.push(lines[j]);
      i = importEnd + 1;
      continue;
    }

    // Detect exported handler functions: export async function GET(
    // or export const GET = ...
    const exportMatch = line.match(
      new RegExp(`^\\s*export\\s+(?:async\\s+)?(?:function|const)\\s+(${HTTP_METHODS.join("|")})\\b`),
    );
    if (exportMatch) {
      // Find the end of this function by tracking brace depth
      let depth = 0;
      let started = false;
      let end = i;
      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === "{") { depth++; started = true; }
          if (ch === "}") depth--;
        }
        if (started && depth <= 0) {
          end = j;
          break;
        }
      }
      handlerRanges.push([i, end]);
      i = end + 1;
      continue;
    }

    i++;
  }

  // If we found handlers, return only imports + handlers (much smaller)
  if (handlerRanges.length > 0) {
    const parts = [importLines.join("\n"), ""];
    for (const [start, end] of handlerRanges) {
      parts.push(lines.slice(start, end + 1).join("\n"));
      parts.push("");
    }
    return parts.join("\n").trim();
  }

  // Fallback: return full source (Express, Pages Router, etc.)
  return source;
}

const IMPORT_RE = /import\s+(?:[\w{}*,\s]+from\s+)?["']([^"']+)["']/g;

function extractLocalImports(source: string): string[] {
  const results: string[] = [];
  let m: RegExpExecArray | null;
  IMPORT_RE.lastIndex = 0;
  while ((m = IMPORT_RE.exec(source)) !== null) {
    const spec = m[1];
    if (spec.startsWith(".") || spec.startsWith("/")) results.push(spec);
  }
  return results;
}

async function resolveImport(
  fromFile: string,
  spec: string,
  projectRoot: string,
): Promise<string | null> {
  const base = resolvePath(dirname(fromFile), spec);
  const candidates = [
    base,
    base + ".ts",
    base + ".tsx",
    base + ".js",
    base + ".jsx",
    resolvePath(base, "index.ts"),
    resolvePath(base, "index.tsx"),
  ].map((c) => c.replace(/\.js$/, ".ts"));

  for (const c of candidates) {
    try {
      await readFile(c, "utf-8");
      const rel = relative(projectRoot, c);
      if (rel.startsWith("..")) return null; // escape attempt — reject
      return c;
    } catch {
      continue;
    }
  }
  return null;
}

export async function buildContext(
  endpoint: ApiEndpoint,
  model: ProjectModel,
  maxTokens: number,
): Promise<EndpointContext | null> {
  const projectRoot = model.meta.path;

  let handlerSource: string;
  try {
    const fullSource = await readFile(endpoint.file, "utf-8");
    handlerSource = extractHandlers(fullSource);
  } catch {
    return null;
  }

  if (approxTokens(handlerSource) > maxTokens) {
    return null; // handler alone exceeds cap
  }

  // Walk imports BFS up to MAX_IMPORT_DEPTH, collect up to MAX_ADJACENT files.
  const collected: AdjacentFile[] = [];
  const seen = new Set<string>([endpoint.file]);
  const queue: Array<{ file: string; depth: number }> = [{ file: endpoint.file, depth: 0 }];

  while (queue.length > 0 && collected.length < MAX_ADJACENT) {
    const { file, depth } = queue.shift()!;
    if (depth >= MAX_IMPORT_DEPTH) continue;

    let source: string;
    try {
      source = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    for (const spec of extractLocalImports(source)) {
      if (collected.length >= MAX_ADJACENT) break;

      const resolved = await resolveImport(file, spec, projectRoot);
      if (!resolved || seen.has(resolved)) continue;
      seen.add(resolved);

      let adjSource: string;
      try {
        adjSource = await readFile(resolved, "utf-8");
      } catch {
        continue;
      }

      collected.push({ path: relative(projectRoot, resolved), content: adjSource });
      queue.push({ file: resolved, depth: depth + 1 });
    }
  }

  // Drop adjacent files in reverse until we fit under maxTokens.
  let adjacent = collected;
  let totalTokens =
    approxTokens(handlerSource) + adjacent.reduce((a, f) => a + approxTokens(f.content), 0);

  while (totalTokens > maxTokens && adjacent.length > 0) {
    adjacent = adjacent.slice(0, -1);
    totalTokens =
      approxTokens(handlerSource) + adjacent.reduce((a, f) => a + approxTokens(f.content), 0);
  }

  return { handlerSource, adjacent };
}
