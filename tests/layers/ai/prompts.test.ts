import { describe, it, expect } from "vitest";
import { buildProjectSummary, buildEndpointPrompt, buildStageAPrompt, SYSTEM_PREAMBLE, REPORT_FINDINGS_TOOL } from "../../../src/layers/ai/prompts.js";
import type { ProjectModel } from "../../../src/model/types.js";

function mkModel(partial: Partial<ProjectModel> = {}): ProjectModel {
  return {
    meta: { name: "demo", path: "/tmp/demo", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
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
    ...partial,
  };
}

describe("buildProjectSummary", () => {
  it("includes project meta and stack", () => {
    const s = buildProjectSummary(mkModel());
    expect(s).toContain("demo");
    expect(s).toContain("nextjs-supabase");
  });

  it("lists up to 50 routes and adds overflow marker when more", () => {
    const routes = Array.from({ length: 60 }, (_, i) => ({
      path: `/r${i}`,
      method: "GET" as const,
      file: `r${i}.ts`,
      isApi: true,
      hasAuthCheck: false,
      paramNames: [],
    }));
    const s = buildProjectSummary(mkModel({ routes }));
    expect(s).toContain("/r0");
    expect(s).toContain("/r49");
    expect(s).not.toContain("/r50");
    expect(s).toMatch(/and 10 more/);
  });

  it("renders securityHeaders as 'none' when empty", () => {
    const s = buildProjectSummary(mkModel());
    expect(s).toContain("Security headers present: none");
  });

  it("includes middleware: present when infra.middleware exists", () => {
    const model = mkModel({
      infra: { nextConfig: null, middleware: { file: "middleware.ts", source: "" }, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    });
    expect(buildProjectSummary(model)).toContain("Middleware: present");
  });
});

describe("buildEndpointPrompt", () => {
  it("includes method, path, file, and handler code", () => {
    const p = buildEndpointPrompt(
      {
        path: "/api/users/[id]",
        method: "PATCH",
        file: "src/app/api/users/[id]/route.ts",
        handlerName: "PATCH",
        hasValidation: false,
        validationLibrary: null,
        hasAuthCheck: true,
        usesServiceRole: false,
      },
      "export async function PATCH() { /* ... */ }",
      [],
    );
    expect(p).toContain("PATCH /api/users/[id]");
    expect(p).toContain("src/app/api/users/[id]/route.ts");
    expect(p).toContain("export async function PATCH()");
    expect(p).toContain("AUTH CHECK: present");
    expect(p).toContain("SERVICE ROLE: no");
  });

  it("marks service role bypass prominently", () => {
    const p = buildEndpointPrompt(
      {
        path: "/api/admin",
        method: "POST",
        file: "x.ts",
        hasValidation: false,
        validationLibrary: null,
        hasAuthCheck: false,
        usesServiceRole: true,
      },
      "",
      [],
    );
    expect(p).toContain("SERVICE ROLE: YES");
    expect(p).toContain("bypasses RLS");
  });

  it("includes adjacent files section when provided", () => {
    const p = buildEndpointPrompt(
      { path: "/x", method: "GET", file: "x.ts", hasValidation: false, validationLibrary: null, hasAuthCheck: false, usesServiceRole: false },
      "code",
      [{ path: "auth.ts", content: "export function getUser() {}" }],
    );
    expect(p).toContain("ADJACENT FILES");
    expect(p).toContain("auth.ts");
    expect(p).toContain("getUser");
  });

  it("prepends the magic-link prefix when isMagicLink=true", () => {
    const ep = {
      path: "/api/public/reservation/[id]",
      method: "GET" as const,
      file: "src/app/api/public/reservation/[id]/route.ts",
      hasValidation: false,
      validationLibrary: null,
      hasAuthCheck: false,
      usesServiceRole: true,
    };
    const withoutPrefix = buildEndpointPrompt(ep, "code", [], false);
    const withPrefix = buildEndpointPrompt(ep, "code", [], true);
    expect(withoutPrefix).not.toMatch(/MAGIC-LINK ENDPOINT/);
    expect(withPrefix).toMatch(/^MAGIC-LINK ENDPOINT/);
    expect(withPrefix).toContain("unguessable token");
    expect(withPrefix).toContain("DO NOT report");
    // Endpoint info still follows the prefix
    expect(withPrefix).toContain("GET /api/public/reservation/[id]");
  });
});

describe("buildStageAPrompt", () => {
  it("embeds the project summary and asks for project-wide risks", () => {
    const model = mkModel();
    const p = buildStageAPrompt(model);
    expect(p).toContain(buildProjectSummary(model));
    expect(p).toContain("project-wide security triage");
    expect(p).toContain("report_project_risks");
    expect(p).toContain("priority order");
  });
});

describe("REPORT_FINDINGS_TOOL", () => {
  it("has name report_findings and a JSON schema", () => {
    expect(REPORT_FINDINGS_TOOL.name).toBe("report_findings");
    expect(REPORT_FINDINGS_TOOL.schema).toBeTypeOf("object");
  });
});

describe("SYSTEM_PREAMBLE", () => {
  it("instructs the model to cap confidence at high", () => {
    expect(SYSTEM_PREAMBLE).toMatch(/confidence.*high/i);
    expect(SYSTEM_PREAMBLE).not.toMatch(/confirmed/i);
  });
});
