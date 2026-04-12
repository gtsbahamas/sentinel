import { describe, it, expect } from "vitest";
import type { ProjectModel, DataModel, Dependency } from "../../../../src/model/types.js";
import { inferTenancy } from "../../../../src/layers/context/inferrers/tenancy.js";
import { inferFramework } from "../../../../src/layers/context/inferrers/framework.js";
import { inferDeployment } from "../../../../src/layers/context/inferrers/deployment.js";
import { inferExcludedPaths } from "../../../../src/layers/context/inferrers/excluded-paths.js";

function baseModel(overrides: Partial<ProjectModel> = {}): ProjectModel {
  return {
    meta: {
      name: "test-project",
      path: "/tmp/test-project",
      stack: "generic-web",
      packageManager: "pnpm",
      language: "typescript",
      framework: "unknown",
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
    infra: {
      nextConfig: null,
      middleware: null,
      vercelConfig: null,
      supabaseConfig: null,
      securityHeaders: {},
    },
    findings: [],
    ...overrides,
  };
}

function makeDataModel(name: string, partial: Partial<DataModel> = {}): DataModel {
  return {
    name,
    source: "supabase",
    hasRls: null,
    rlsPolicies: [],
    ...partial,
  };
}

function makeDep(name: string, partial: Partial<Dependency> = {}): Dependency {
  return {
    name,
    version: "1.0.0",
    type: "production",
    ...partial,
  };
}

// ============================================================================
// inferTenancy
// ============================================================================

describe("inferTenancy", () => {
  it("returns single-org with medium confidence when no data models exist", () => {
    const result = inferTenancy(baseModel());
    expect(result.value).toBe("single-org");
    expect(result.confidence).toBe("low");
  });

  it("returns single-org for models with no tenant-like table names", () => {
    const model = baseModel({
      dataModels: [
        makeDataModel("users"),
        makeDataModel("posts"),
        makeDataModel("comments"),
      ],
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("single-org");
    expect(result.confidence).toBe("medium");
  });

  it("returns multi-tenant when table named 'tenants' is present", () => {
    const model = baseModel({
      dataModels: [
        makeDataModel("tenants"),
        makeDataModel("users"),
        makeDataModel("posts"),
        makeDataModel("comments"),
      ],
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("multi-tenant");
  });

  it("returns multi-tenant with high confidence when majority of tables have tenant signals", () => {
    const model = baseModel({
      dataModels: [
        makeDataModel("organizations"),
        makeDataModel("workspaces"),
        makeDataModel("users"),
      ],
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("multi-tenant");
    expect(result.confidence).toBe("high");
  });

  it("returns multi-tenant for tables named organizations", () => {
    const model = baseModel({
      dataModels: [
        makeDataModel("organizations"),
        makeDataModel("users"),
        makeDataModel("posts"),
        makeDataModel("comments"),
        makeDataModel("settings"),
      ],
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("multi-tenant");
  });
});

// ============================================================================
// inferFramework
// ============================================================================

describe("inferFramework", () => {
  it("returns generic defaults when no Next.js signals present", () => {
    const result = inferFramework(baseModel());
    expect(result.value.routeHandlersServerOnly).toBe(false);
    expect(result.value.frameworkCatchesErrors).toBe(false);
    expect(result.value.serverOnlyImportGuard).toBe(false);
    expect(result.confidence).toBe("low");
  });

  it("detects Next.js via stack profile", () => {
    const model = baseModel({
      meta: {
        name: "test",
        path: "/tmp",
        stack: "nextjs-supabase",
        packageManager: "pnpm",
        language: "typescript",
        framework: "next",
        deployTarget: null,
      },
    });
    const result = inferFramework(model);
    expect(result.value.routeHandlersServerOnly).toBe(true);
    expect(result.value.frameworkCatchesErrors).toBe(true);
    expect(result.confidence).toBe("high");
  });

  it("detects Next.js via 'next' dependency", () => {
    const model = baseModel({
      dependencies: [makeDep("next"), makeDep("react"), makeDep("react-dom")],
    });
    const result = inferFramework(model);
    expect(result.value.routeHandlersServerOnly).toBe(true);
    expect(result.value.frameworkCatchesErrors).toBe(true);
    expect(result.confidence).toBe("high");
  });

  it("sets serverOnlyImportGuard=true when server-only package is present", () => {
    const model = baseModel({
      dependencies: [makeDep("next"), makeDep("server-only")],
    });
    const result = inferFramework(model);
    expect(result.value.serverOnlyImportGuard).toBe(true);
  });

  it("sets serverOnlyImportGuard=false when server-only package is absent", () => {
    const model = baseModel({
      dependencies: [makeDep("next")],
    });
    const result = inferFramework(model);
    expect(result.value.serverOnlyImportGuard).toBe(false);
  });
});

// ============================================================================
// inferDeployment
// ============================================================================

describe("inferDeployment", () => {
  it("returns unknown platform with low confidence when no config present", () => {
    const result = inferDeployment(baseModel());
    expect(result.value.platform).toBe("unknown");
    expect(result.value.platformHandles).toEqual([]);
    expect(result.confidence).toBe("low");
  });

  it("detects Vercel via vercelConfig in infra", () => {
    const model = baseModel({
      infra: {
        nextConfig: null,
        middleware: null,
        vercelConfig: { file: "vercel.json", source: '{"rewrites":[]}' },
        supabaseConfig: null,
        securityHeaders: {},
      },
    });
    const result = inferDeployment(model);
    expect(result.value.platform).toBe("vercel");
    expect(result.value.platformHandles).toContain("hsts");
    expect(result.value.platformHandles).toContain("ssl-termination");
    expect(result.value.platformHandles).toContain("ddos-protection");
    expect(result.confidence).toBe("high");
  });

  it("detects Vercel via meta.deployTarget", () => {
    const model = baseModel({
      meta: {
        name: "test",
        path: "/tmp",
        stack: "generic-web",
        packageManager: "pnpm",
        language: "typescript",
        framework: "unknown",
        deployTarget: "vercel",
      },
    });
    const result = inferDeployment(model);
    expect(result.value.platform).toBe("vercel");
    expect(result.confidence).toBe("high");
  });
});

// ============================================================================
// inferExcludedPaths
// ============================================================================

describe("inferExcludedPaths", () => {
  it("returns a list including scripts/", () => {
    const result = inferExcludedPaths(baseModel());
    expect(result.value).toContain("scripts/");
  });

  it("returns a list including tests/ and __tests__/", () => {
    const result = inferExcludedPaths(baseModel());
    expect(result.value).toContain("tests/");
    expect(result.value).toContain("__tests__/");
  });

  it("returns a list including cypress/ and e2e/", () => {
    const result = inferExcludedPaths(baseModel());
    expect(result.value).toContain("cypress/");
    expect(result.value).toContain("e2e/");
  });

  it("returns high confidence", () => {
    const result = inferExcludedPaths(baseModel());
    expect(result.confidence).toBe("high");
  });

  it("is not affected by model contents", () => {
    const withDeps = baseModel({
      dependencies: [makeDep("next"), makeDep("react")],
    });
    const withoutDeps = baseModel();
    expect(inferExcludedPaths(withDeps).value).toEqual(
      inferExcludedPaths(withoutDeps).value
    );
  });
});
