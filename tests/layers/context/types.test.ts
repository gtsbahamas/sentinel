import { describe, it, expect } from "vitest";
import { ProjectContextSchema, type ProjectContext } from "../../../src/layers/context/types.js";

describe("ProjectContextSchema", () => {
  const validContext: ProjectContext = {
    tenancy: "single-org",
    publicRoutes: [
      { pattern: "/api/public/**", reason: "magic-link" },
    ],
    validation: {
      library: "zod",
      schemaLocations: ["src/lib/validation/*.ts"],
      importedByRoutes: true,
    },
    migrations: {
      rlsStrategy: "dedicated-file",
      rlsFile: "supabase/migrations/00003_rls_policies.sql",
    },
    framework: {
      routeHandlersServerOnly: true,
      frameworkCatchesErrors: true,
      serverOnlyImportGuard: true,
    },
    excludedPaths: ["scripts/", "seed.ts"],
    auth: {
      defaultClient: "anon",
      roleModel: ["viewer", "editor", "manager", "admin"],
      roleCheckPattern: "supabase.rpc('is_manager')",
    },
    deployment: {
      platform: "vercel",
      platformHandles: ["hsts", "ssl-termination"],
    },
    delegations: [
      { provider: "supabase", responsibility: "OAuth state verification", mechanism: "exchangeCodeForSession()" },
    ],
    version: 1,
    generatedAt: "2026-04-12T00:00:00Z",
    generatedBy: "interactive",
    confidence: { tenancy: "high", auth: "high", validation: "high" },
  };

  it("accepts a valid context", () => {
    expect(ProjectContextSchema.safeParse(validContext).success).toBe(true);
  });

  it("rejects invalid tenancy value", () => {
    const bad = { ...validContext, tenancy: "federated" };
    expect(ProjectContextSchema.safeParse(bad).success).toBe(false);
  });

  it("accepts minimal context with defaults", () => {
    const minimal = {
      tenancy: "single-org",
      publicRoutes: [],
      validation: { library: "none", schemaLocations: [], importedByRoutes: false },
      migrations: { rlsStrategy: "none" },
      framework: { routeHandlersServerOnly: false, frameworkCatchesErrors: false, serverOnlyImportGuard: false },
      excludedPaths: [],
      auth: { defaultClient: "anon", roleModel: [] },
      deployment: { platform: "unknown", platformHandles: [] },
      delegations: [],
      version: 1,
      generatedAt: "2026-04-12T00:00:00Z",
      generatedBy: "auto",
      confidence: {},
    };
    expect(ProjectContextSchema.safeParse(minimal).success).toBe(true);
  });
});
