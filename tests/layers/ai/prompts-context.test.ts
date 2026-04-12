import { describe, it, expect } from "vitest";
import { buildProjectSummary } from "../../../src/layers/ai/prompts.js";
import type { ProjectModel } from "../../../src/model/types.js";
import type { ProjectContext } from "../../../src/layers/context/types.js";

describe("buildProjectSummary with context", () => {
  const model = {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript" },
    routes: [], endpoints: [], dataModels: [], authFlows: [], dependencies: [], infra: { securityHeaders: {} },
  } as unknown as ProjectModel;

  const context: ProjectContext = {
    tenancy: "single-org",
    publicRoutes: [{ pattern: "/api/public/**", reason: "magic-link" }],
    validation: { library: "zod", schemaLocations: ["src/lib/validation/*.ts"], importedByRoutes: true },
    migrations: { rlsStrategy: "dedicated-file", rlsFile: "00003_rls.sql" },
    framework: { routeHandlersServerOnly: true, frameworkCatchesErrors: true, serverOnlyImportGuard: true },
    excludedPaths: ["scripts/"],
    auth: { defaultClient: "anon", roleModel: ["viewer", "admin"] },
    deployment: { platform: "vercel", platformHandles: ["hsts"] },
    delegations: [{ provider: "supabase", responsibility: "OAuth state verification", mechanism: "exchangeCodeForSession()" }],
    version: 1, generatedAt: "2026-04-12", generatedBy: "auto", confidence: {},
  };

  it("includes context sections when provided", () => {
    const summary = buildProjectSummary(model, context);
    expect(summary).toContain("single-org");
    expect(summary).toContain("magic-link");
    expect(summary).toContain("zod");
    expect(summary).toContain("exchangeCodeForSession");
    expect(summary).toContain("vercel");
  });

  it("works without context", () => {
    const summary = buildProjectSummary(model);
    expect(summary).toContain("PROJECT: test");
    expect(summary).not.toContain("ARCHITECTURE CONTEXT");
  });
});
