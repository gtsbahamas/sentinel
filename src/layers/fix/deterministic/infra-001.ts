import { existsSync, readFileSync } from "fs";
import { dirname, basename, join } from "path";
import type { Fixer } from "../types.js";
import type { Finding } from "../../../model/types.js";

/**
 * INFRA-001: Content-Security-Policy header missing.
 *
 * Strategy:
 *   1. Inspect the project root inferred from the finding's evidence file path
 *      to decide which artifact to mutate:
 *        - Next.js (next.config.{js,mjs,ts,cjs}) → patch the config to add a
 *          CSP entry inside `async headers()`.
 *        - Vite (vercel.json present, no next.config) → patch vercel.json to
 *          add a Content-Security-Policy header under `headers`.
 *        - Both present → prefer Next.js (the runtime that actually serves
 *          the responses).
 *        - Neither present → return null. The runFix loop will surface this
 *          as "skipped" with the appropriate reason.
 *
 *   2. The CSP value is intentionally permissive enough to not break the
 *      typical Next.js / Vite + Supabase app on first deploy:
 *        - 'unsafe-inline' for scripts (Next inlines hydration script tags)
 *        - 'unsafe-eval' (Next dev mode + some libs)
 *        - https: for external assets and API calls (Supabase, fonts, images)
 *        - frame-ancestors 'none' (clickjacking protection)
 *      Operators can tighten from there.
 */

const NEXT_CONFIG_BASENAMES = new Set([
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "next.config.cjs",
]);

const NEXT_CONFIG_FILENAMES = [
  "next.config.ts",
  "next.config.mjs",
  "next.config.js",
  "next.config.cjs",
];

const CSP_VALUE =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
  "style-src 'self' 'unsafe-inline' https:; " +
  "img-src 'self' data: blob: https:; " +
  "font-src 'self' data: https:; " +
  "connect-src 'self' https: wss:; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'";

const CSP_HEADER_ENTRY_NEXT = `          { key: "Content-Security-Policy", value: "${CSP_VALUE}" },`;

const NEW_HEADERS_BLOCK_NEXT = `  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
${CSP_HEADER_ENTRY_NEXT}
        ],
      },
    ];
  },`;

// Match the start of an exported config object. Supports both:
//   const nextConfig = {              ← plain JS / .mjs
//   const nextConfig: NextConfig = {  ← TypeScript
//   const config: import('next').NextConfig = {
// We capture up to and including the opening brace.
const CONFIG_OBJECT_OPEN = /((?:const|let|var)\s+\w+(?:\s*:\s*[^=]+?)?\s*=\s*\{)/;

/** Find a sibling config file relative to the evidence file. */
function findSiblingConfig(evidenceFile: string, candidates: string[]): string | null {
  // The evidence file may itself be a config (real or synthetic). Climb up to
  // the project root by stripping directories until we find one of the
  // candidates as a sibling.
  let dir = dirname(evidenceFile);
  // Walk up at most 6 levels — enough for monorepos but bounded.
  for (let i = 0; i < 6; i++) {
    for (const candidate of candidates) {
      const probe = join(dir, candidate);
      if (existsSync(probe)) return probe;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

interface DetectedStack {
  kind: "nextjs" | "vite" | "none";
  configPath: string | null;
}

function detectStack(finding: Finding): DetectedStack {
  const evidenceFile = finding.evidence[0]?.file;
  if (!evidenceFile) return { kind: "none", configPath: null };

  // Check the literal evidence file first — it might already be a real config.
  const evBase = basename(evidenceFile);
  if (NEXT_CONFIG_BASENAMES.has(evBase) && existsSync(evidenceFile)) {
    return { kind: "nextjs", configPath: evidenceFile };
  }
  if (evBase === "vercel.json" && existsSync(evidenceFile)) {
    // Could be a vercel-deployed Next or Vite app — check siblings.
    const sibling = findSiblingConfig(evidenceFile, NEXT_CONFIG_FILENAMES);
    if (sibling) return { kind: "nextjs", configPath: sibling };
    return { kind: "vite", configPath: evidenceFile };
  }

  // Otherwise, search siblings for a real config. Prefer Next.js.
  const next = findSiblingConfig(evidenceFile, NEXT_CONFIG_FILENAMES);
  if (next) return { kind: "nextjs", configPath: next };

  const vercel = findSiblingConfig(evidenceFile, ["vercel.json"]);
  if (vercel) return { kind: "vite", configPath: vercel };

  return { kind: "none", configPath: null };
}

/** Add or extend the headers() block in a Next.js config string. */
function patchNextConfig(source: string): string | null {
  // Already configured — bail.
  if (/Content-Security-Policy/i.test(source)) return null;

  // Case 1: a headers() block already exists (e.g., infra-006 already ran).
  // Find the inner `headers: [` array of the first entry and prepend the CSP
  // header object so it lands alongside X-Frame-Options et al.
  if (/async\s+headers\s*\(\s*\)/.test(source)) {
    const innerHeadersOpen = /headers\s*:\s*\[/g;
    // The first match inside async headers() is the outer `return [`
    // (which uses `[` not `headers: [`). The second-level `headers: [`
    // is the inner per-source array. We match on `headers: [` directly.
    const match = innerHeadersOpen.exec(source);
    if (!match) return null;
    const insertAt = match.index + match[0].length;
    const before = source.slice(0, insertAt);
    const after = source.slice(insertAt);
    return `${before}\n${CSP_HEADER_ENTRY_NEXT}${after}`;
  }

  // Case 2: no headers() block — insert a fresh one after the config object's
  // opening brace.
  const m = CONFIG_OBJECT_OPEN.exec(source);
  if (!m) return null;
  const insertAfter = m.index + m[0].length;
  const before = source.slice(0, insertAfter);
  const after = source.slice(insertAfter);
  return `${before}\n${NEW_HEADERS_BLOCK_NEXT}${after}`;
}

/** Add a CSP header entry to vercel.json. */
function patchVercelJson(source: string): string | null {
  if (/Content-Security-Policy/i.test(source)) return null;

  let parsed: any;
  try {
    parsed = JSON.parse(source);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object") return null;

  const cspEntry = { key: "Content-Security-Policy", value: CSP_VALUE };

  if (!Array.isArray(parsed.headers)) {
    parsed.headers = [];
  }

  // Look for an existing source: "/(.*)" entry to extend.
  const target = parsed.headers.find(
    (h: any) => h && h.source === "/(.*)" && Array.isArray(h.headers),
  );

  if (target) {
    target.headers.push(cspEntry);
  } else {
    parsed.headers.push({
      source: "/(.*)",
      headers: [cspEntry],
    });
  }

  return JSON.stringify(parsed, null, 2) + "\n";
}

export const infra001Fixer: Fixer = {
  ruleId: "INFRA-001",
  type: "deterministic",

  apply(fileContent: string, finding: Finding): string | null {
    const stack = detectStack(finding);
    if (stack.kind === "none" || !stack.configPath) {
      return null;
    }

    // The runFix loop reads the evidence file and passes its content as
    // `fileContent`. The evidence file path is also what gets written to.
    // For us to be able to patch a different file (the real config) we need
    // the evidence file path to ALREADY be that config. That's true for the
    // common cases: discoverInfra emits the real next.config.* or vercel.json
    // path as the evidence; only when neither exists does it emit a synthetic
    // path, in which case we can't write anything useful and bail.
    const evidenceFile = finding.evidence[0]?.file;
    if (!evidenceFile || evidenceFile !== stack.configPath) {
      // Defensive: if we somehow detected a different config than what the
      // runFix loop is editing, refuse — better to skip than corrupt an
      // unrelated file.
      // Re-read the configPath ourselves to confirm if the detected file
      // matches the content we got. If contents match, proceed.
      try {
        const onDisk = readFileSync(stack.configPath, "utf-8");
        if (onDisk !== fileContent) return null;
      } catch {
        return null;
      }
    }

    if (stack.kind === "nextjs") {
      return patchNextConfig(fileContent);
    }
    if (stack.kind === "vite") {
      return patchVercelJson(fileContent);
    }
    return null;
  },
};
