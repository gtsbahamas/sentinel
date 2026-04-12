import { describe, it, expect } from "vitest";
import { resolveTargets } from "../../../src/layers/probe/target-resolver.js";
import type { ProjectModel, Finding } from "../../../src/model/types.js";

function emptyModel(overrides: Partial<ProjectModel> = {}): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
    ...overrides,
  };
}

describe("resolveTargets", () => {
  it("always includes a baseline target", () => {
    const targets = resolveTargets(emptyModel(), [], "http://localhost:3000");
    expect(targets).toHaveLength(1);
    expect(targets[0].kind).toBe("baseline");
    expect(targets[0].url).toBe("http://localhost:3000");
  });

  it("creates targets from model endpoints", () => {
    const model = emptyModel({
      endpoints: [
        { path: "/api/users", method: "GET", file: "src/api/users.ts", hasValidation: false, hasAuthCheck: true, usesServiceRole: false },
        { path: "/api/health", method: "GET", file: "src/api/health.ts", hasValidation: false, hasAuthCheck: false, usesServiceRole: false },
      ],
    });
    const targets = resolveTargets(model, [], "http://localhost:3000");
    expect(targets).toHaveLength(3);
    expect(targets[1].url).toBe("http://localhost:3000/api/users");
    expect(targets[1].auth).toBe("required");
    expect(targets[2].url).toBe("http://localhost:3000/api/health");
    expect(targets[2].auth).toBe("unauthenticated");
  });

  it("deduplicates targets", () => {
    const model = emptyModel({
      endpoints: [
        { path: "/api/data", method: "GET", file: "src/api/data.ts", hasValidation: false, hasAuthCheck: false, usesServiceRole: false },
      ],
    });
    const findings: Finding[] = [
      {
        id: "F1",
        domain: "auth-access-control",
        severity: "high",
        confidence: "medium",
        title: "No auth",
        description: "",
        evidence: [{ file: "src/api/data.ts", line: 10 }],
        remediation: "",
        references: [],
        layer: "rules",
      },
    ];
    const targets = resolveTargets(model, findings, "http://localhost:3000");
    const dataTargets = targets.filter((t) => t.url.includes("/api/data"));
    expect(dataTargets).toHaveLength(1);
    expect(dataTargets[0].fromFindingId).toBe("F1");
  });

  it("strips trailing slashes from base URL", () => {
    const targets = resolveTargets(emptyModel(), [], "http://localhost:3000/");
    expect(targets[0].url).toBe("http://localhost:3000");
  });
});
