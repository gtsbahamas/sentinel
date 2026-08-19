import type { ProjectModel, InfraConfig, ApiEndpoint, Dependency, Route } from "../../src/model/types.js";

/** Minimal empty model. Override fields as needed per test. */
export function emptyModel(overrides?: Partial<ProjectModel>): ProjectModel {
  return {
    meta: {
      name: "test-project",
      path: "/tmp/test-project",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "nextjs-app",
      deployTarget: null,
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    findings: [],
    infra: emptyInfra(),
    ...overrides,
  };
}

export function emptyInfra(overrides?: Partial<InfraConfig>): InfraConfig {
  return {
    nextConfig: null,
    middleware: null,
    vercelConfig: null,
    supabaseConfig: null,
    securityHeaders: {},
    ...overrides,
  };
}

/** Build a single endpoint for testing. */
export function makeEndpoint(overrides: Partial<ApiEndpoint> & { path: string; file: string }): ApiEndpoint {
  return {
    method: "POST",
    handlerName: undefined,
    hasValidation: false,
    validationLibrary: null,
    hasAuthCheck: false,
    usesServiceRole: false,
    ...overrides,
  };
}

/** Build a single dependency for testing. */
export function makeDep(name: string, version: string, type: Dependency["type"] = "production"): Dependency {
  return { name, version, type };
}

/** Build a single route for testing. */
export function makeRoute(overrides: Partial<Route> & { path: string; file: string }): Route {
  return {
    method: "GET",
    isApi: true,
    hasAuthCheck: false,
    paramNames: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fixture staging
// ---------------------------------------------------------------------------
//
// Several rules skip any path containing `/test/`, `/tests/` or `/fixtures/`
// because real projects keep intentionally-bad code there (see the v0.1.2-0.1.4
// false-positive work). That skip also matches `tests/fixtures/<name>` in this
// repo, so a test that scans a fixture IN PLACE silently exercises nothing:
// the rule returns zero findings for a path reason, not a code reason.
//
// stagedFixture() copies a fixture into a temp directory whose path carries no
// such marker, so the scan sees it the way it would see a real project. The
// copy is made once per worker process and removed on exit.

import { cpSync, mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");
const staged = new Map<string, string>();
let cleanupRegistered = false;

export function stagedFixture(name: string): string {
  const cached = staged.get(name);
  if (cached) return cached;

  const dir = mkdtempSync(join(tmpdir(), `sentinel-fx-${name}-`));
  cpSync(join(FIXTURES_DIR, name), dir, { recursive: true });
  staged.set(name, dir);

  if (!cleanupRegistered) {
    cleanupRegistered = true;
    process.on("exit", () => {
      for (const d of staged.values()) rmSync(d, { recursive: true, force: true });
    });
  }
  return dir;
}
