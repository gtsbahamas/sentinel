import { existsSync } from "fs";
import { join } from "path";
import { safeReadFile } from "../../utils/fs.js";
import type { InfraConfig } from "../../model/types.js";

const NEXT_CONFIG_FILES = ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"];
const MIDDLEWARE_FILES = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];

// Parse `key: "value"` style header pairs out of a source blob.
// Intentionally forgiving — next.config source files are JS, not JSON, so
// we use a regex rather than a full parser.
function extractHeadersFromSource(source: string): Array<{ key: string; value: string }> {
  const headers: Array<{ key: string; value: string }> = [];
  // Match `{ key: "X-Frame-Options", value: "DENY" }` shapes produced by
  // Next.js headers() config and similar Vercel/Netlify formats.
  const pairRe = /key\s*:\s*["']([^"']+)["']\s*,\s*value\s*:\s*["']([^"']+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = pairRe.exec(source)) !== null) {
    headers.push({ key: m[1], value: m[2] });
  }
  // Also pick up raw `res.setHeader("X-Frame-Options", "DENY")`.
  const setHeaderRe = /setHeader\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']/g;
  while ((m = setHeaderRe.exec(source)) !== null) {
    headers.push({ key: m[1], value: m[2] });
  }
  // Also pick up `response.headers.set("X", "Y")`.
  const headersSetRe = /headers\s*\.\s*set\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']/g;
  while ((m = headersSetRe.exec(source)) !== null) {
    headers.push({ key: m[1], value: m[2] });
  }
  return headers;
}

// Parse `"headers": [{ source, headers: [ { key, value } ] }]` style from
// vercel.json.
function extractHeadersFromVercelJson(source: string): Array<{ key: string; value: string }> {
  const headers: Array<{ key: string; value: string }> = [];
  try {
    const parsed = JSON.parse(source);
    if (!Array.isArray(parsed.headers)) return headers;
    for (const entry of parsed.headers) {
      if (!Array.isArray(entry.headers)) continue;
      for (const h of entry.headers) {
        if (typeof h.key === "string" && typeof h.value === "string") {
          headers.push({ key: h.key, value: h.value });
        }
      }
    }
  } catch {
    // ignore malformed vercel.json
  }
  return headers;
}

export async function discoverInfra(projectPath: string): Promise<InfraConfig> {
  const securityHeaders: InfraConfig["securityHeaders"] = {};

  const record = (file: string, headers: Array<{ key: string; value: string }>) => {
    for (const h of headers) {
      const key = h.key.toLowerCase();
      if (!securityHeaders[key]) securityHeaders[key] = [];
      securityHeaders[key].push({ file, value: h.value });
    }
  };

  // Next.js config
  let nextConfig: InfraConfig["nextConfig"] = null;
  for (const rel of NEXT_CONFIG_FILES) {
    const p = join(projectPath, rel);
    if (!existsSync(p)) continue;
    const source = await safeReadFile(p).catch(() => "");
    nextConfig = { file: p, source };
    record(p, extractHeadersFromSource(source));
    break;
  }

  // Middleware
  let middleware: InfraConfig["middleware"] = null;
  for (const rel of MIDDLEWARE_FILES) {
    const p = join(projectPath, rel);
    if (!existsSync(p)) continue;
    const source = await safeReadFile(p).catch(() => "");
    middleware = { file: p, source };
    record(p, extractHeadersFromSource(source));
    break;
  }

  // Vercel
  let vercelConfig: InfraConfig["vercelConfig"] = null;
  const vercelPath = join(projectPath, "vercel.json");
  if (existsSync(vercelPath)) {
    const source = await safeReadFile(vercelPath).catch(() => "");
    vercelConfig = { file: vercelPath, source };
    record(vercelPath, extractHeadersFromVercelJson(source));
  }

  // Supabase
  let supabaseConfig: InfraConfig["supabaseConfig"] = null;
  const supabaseConfigPath = join(projectPath, "supabase", "config.toml");
  if (existsSync(supabaseConfigPath)) {
    const source = await safeReadFile(supabaseConfigPath).catch(() => "");
    supabaseConfig = { file: supabaseConfigPath, source };
  }

  return { nextConfig, middleware, vercelConfig, supabaseConfig, securityHeaders };
}
