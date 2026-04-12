import { readFile } from "fs/promises";
import fg from "fast-glob";
import { relative } from "path";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

type PublicRouteReason = ProjectContext["publicRoutes"][number]["reason"];

const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const AUTH_PATTERN = /getUser|getSession|auth\.getUser|auth\.getSession|createHmac|timingSafeEqual/;

function exportedMethods(source: string): string[] {
  const methods: string[] = [];
  for (const m of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]) {
    if (new RegExp(`export\\s+(?:async\\s+)?function\\s+${m}\\b`).test(source)) {
      methods.push(m);
    }
  }
  return methods;
}

interface PathPattern {
  test: (path: string) => boolean;
  glob: (path: string) => string;
  reason: PublicRouteReason;
}

const PATH_PATTERNS: PathPattern[] = [
  {
    test: (p) => /\/api\/public\//i.test(p),
    glob: (p) => {
      const match = p.match(/^(.*\/api\/public\/)/i);
      return match ? `${match[1]}**` : p;
    },
    reason: "magic-link",
  },
  {
    test: (p) => /\/api\/webhook/i.test(p),
    glob: () => "/api/webhook/**",
    reason: "webhook",
  },
  {
    test: (p) => /\/api\/health/i.test(p),
    glob: () => "/api/health",
    reason: "health-check",
  },
  {
    test: (p) => /\/api\/widget/i.test(p),
    glob: () => "/api/widget/**",
    reason: "widget",
  },
  {
    test: (p) => /\/api\/auth\/callback/i.test(p),
    glob: () => "/api/auth/callback",
    reason: "oauth-callback",
  },
];

function routePathFromFile(projectPath: string, file: string): string {
  // Given absolute file path, derive API route path
  const rel = relative(projectPath, file);
  // e.g. src/app/api/public/reservation/route.ts → /api/public/reservation
  const stripped = rel
    .replace(/^src\/app/, "")
    .replace(/\/route\.[tj]sx?$/, "")
    .replace(/\/page\.[tj]sx?$/, "");
  return stripped || "/";
}

export async function inferPublicRoutes(
  model: ProjectModel
): Promise<InferResult<ProjectContext["publicRoutes"]>> {
  // Prefer model.endpoints if populated; otherwise fall back to file scanning.
  type Candidate = { path: string; method: string; hasAuthCheck: boolean };
  let candidates: Candidate[] = [];

  if (model.endpoints.length > 0) {
    candidates = model.endpoints
      .filter((ep) => !ep.hasAuthCheck && MUTATION_METHODS.has(ep.method))
      .map((ep) => ({ path: ep.path, method: ep.method, hasAuthCheck: false }));
  } else {
    // Scan route files directly
    let files: string[] = [];
    try {
      files = await fg(`${model.meta.path}/src/app/api/**/route.{ts,tsx,js,jsx}`, {
        onlyFiles: true,
      });
    } catch {
      // nothing
    }

    for (const file of files) {
      let source = "";
      try {
        source = await readFile(file, "utf-8");
      } catch {
        continue;
      }
      const hasAuth = AUTH_PATTERN.test(source);
      if (hasAuth) continue;
      const routePath = routePathFromFile(model.meta.path, file);
      const methods = exportedMethods(source);
      for (const method of methods) {
        if (MUTATION_METHODS.has(method)) {
          candidates.push({ path: routePath, method, hasAuthCheck: false });
        }
      }
    }
  }

  const seen = new Set<string>();
  const results: ProjectContext["publicRoutes"] = [];

  for (const ep of candidates) {
    for (const pp of PATH_PATTERNS) {
      if (pp.test(ep.path)) {
        const globPattern = pp.glob(ep.path);
        if (!seen.has(globPattern)) {
          seen.add(globPattern);
          results.push({
            pattern: globPattern,
            reason: pp.reason,
          });
        }
        break;
      }
    }
  }

  const confidence: "high" | "medium" | "low" =
    results.length > 0 ? "high" : "low";

  return { value: results, confidence };
}
