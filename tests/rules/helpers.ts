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
