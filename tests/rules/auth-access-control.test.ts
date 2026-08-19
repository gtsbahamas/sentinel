import { describe, it, expect, afterEach } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { emptyModel, makeEndpoint, stagedFixture } from "./helpers.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = stagedFixture("vulnerable-nextjs");

describe("auth-access-control rules", () => {
  it("flags mutation endpoint without auth (AUTH-001)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth001 = findings.filter((f) => f.ruleId === "AUTH-001");
    expect(auth001.length).toBeGreaterThanOrEqual(1);
  });

  it("flags params.id without ownership check (AUTH-004)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth004 = findings.filter((f) => f.ruleId === "AUTH-004");
    expect(auth004.length).toBeGreaterThanOrEqual(1);
  });

  it("flags auth.admin usage without server-only import (AUTH-005)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth005 = findings.filter((f) => f.ruleId === "AUTH-005");
    expect(auth005.length).toBeGreaterThanOrEqual(1);
  });

  describe("AUTH-011: GET endpoint with service role and no auth check", () => {
    // Locate the rule once. The check is invoked directly so each case can
    // construct a focused synthetic model without standing up a fixture tree.
    const auth011 = authAccessControlRules.find((r) => r.id === "AUTH-011")!;

    let tempDirs: string[] = [];

    afterEach(() => {
      for (const dir of tempDirs) {
        try { rmSync(dir, { recursive: true, force: true }); } catch {}
      }
      tempDirs = [];
    });

    function makeTempFile(contents: string, name = "route.ts"): string {
      const dir = mkdtempSync(join(tmpdir(), "auth-011-"));
      tempDirs.push(dir);
      const filePath = join(dir, name);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, contents, "utf-8");
      return filePath;
    }

    it("fires on GET with usesServiceRole=true and no auth check", async () => {
      const file = makeTempFile("export async function GET() { return Response.json([]); }\n");
      const model = emptyModel({
        endpoints: [
          makeEndpoint({
            path: "/api/portal-users",
            method: "GET",
            file,
            usesServiceRole: true,
            hasAuthCheck: false,
          }),
        ],
      });
      const findings = await auth011.check(model);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("AUTH-011");
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].evidence[0].file).toBe(file);
    });

    it("does not fire when GET has an auth check (even with service role)", async () => {
      const file = makeTempFile("export async function GET() { return Response.json([]); }\n");
      const model = emptyModel({
        endpoints: [
          makeEndpoint({
            path: "/api/portal-users",
            method: "GET",
            file,
            usesServiceRole: true,
            hasAuthCheck: true,
          }),
        ],
      });
      const findings = await auth011.check(model);
      expect(findings).toHaveLength(0);
    });

    it("does not fire when GET does not use service role", async () => {
      const file = makeTempFile("export async function GET() { return Response.json([]); }\n");
      const model = emptyModel({
        endpoints: [
          makeEndpoint({
            path: "/api/public-catalog",
            method: "GET",
            file,
            usesServiceRole: false,
            hasAuthCheck: false,
          }),
        ],
      });
      const findings = await auth011.check(model);
      expect(findings).toHaveLength(0);
    });

    it("does not fire on POST with service role and no auth (that is AUTH-001's job)", async () => {
      const file = makeTempFile("export async function POST() { return Response.json({}); }\n");
      const model = emptyModel({
        endpoints: [
          makeEndpoint({
            path: "/api/portal-users",
            method: "POST",
            file,
            usesServiceRole: true,
            hasAuthCheck: false,
          }),
        ],
      });
      const findings = await auth011.check(model);
      expect(findings).toHaveLength(0);
    });

    it("respects the // sentinel:ignore AUTH-011 pragma", async () => {
      const file = makeTempFile(
        [
          "// sentinel:ignore AUTH-011",
          "// This is a deliberately public catalog endpoint.",
          "export async function GET() { return Response.json([]); }",
          "",
        ].join("\n"),
      );
      const model = emptyModel({
        endpoints: [
          makeEndpoint({
            path: "/api/public-catalog",
            method: "GET",
            file,
            usesServiceRole: true,
            hasAuthCheck: false,
          }),
        ],
      });
      const findings = await auth011.check(model);
      expect(findings).toHaveLength(0);
    });
  });

  describe("CONVENTION-001: declared auth convention enforcement", () => {
    const convention001 = authAccessControlRules.find((r) => r.id === "CONVENTION-001")!;

    let tempDirs: string[] = [];

    afterEach(() => {
      for (const dir of tempDirs) {
        try { rmSync(dir, { recursive: true, force: true }); } catch {}
      }
      tempDirs = [];
    });

    /**
     * Build a fake project root with a .sentinelrc.json and a set of
     * endpoint source files. Returns absolute paths so tests can plug them
     * into makeEndpoint() and the rule sees the same layout it would in
     * a real scan.
     */
    function makeProject(opts: {
      conventions?: unknown;
      files: Array<{ relPath: string; contents: string }>;
    }): { root: string; files: Record<string, string> } {
      const root = mkdtempSync(join(tmpdir(), "convention-001-"));
      tempDirs.push(root);
      const config: Record<string, unknown> = {
        stack: "nextjs-supabase",
        domains: ["all"],
        exclude: ["node_modules"],
        severity: { failOn: "high" },
        output: { format: "terminal", dir: ".sentinel/reports" },
      };
      if (opts.conventions !== undefined) config.conventions = opts.conventions;
      writeFileSync(join(root, ".sentinelrc.json"), JSON.stringify(config), "utf-8");

      const out: Record<string, string> = {};
      for (const f of opts.files) {
        const abs = join(root, f.relPath);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, f.contents, "utf-8");
        out[f.relPath] = abs;
      }
      return { root, files: out };
    }

    it("flags endpoint matching glob that omits the required helper", async () => {
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
        ],
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: "export async function GET() { return Response.json([]); }\n",
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const findings = await convention001.check(model);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("CONVENTION-001");
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].title).toContain("requireStaffPermission");
    });

    it("does not fire when the required helper is called", async () => {
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
        ],
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: [
              "import { requireStaffPermission } from '@/lib/staff/auth';",
              "export async function GET() {",
              "  await requireStaffPermission('users:read');",
              "  return Response.json([]);",
              "}",
              "",
            ].join("\n"),
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const findings = await convention001.check(model);
      expect(findings).toHaveLength(0);
    });

    it("does not fire on endpoints outside the convention glob", async () => {
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
        ],
        files: [
          {
            relPath: "src/app/api/public/health/route.ts",
            contents: "export async function GET() { return Response.json({ ok: true }); }\n",
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/public/health",
            method: "GET",
            file: files["src/app/api/public/health/route.ts"],
          }),
        ],
      });
      const findings = await convention001.check(model);
      expect(findings).toHaveLength(0);
    });

    it("applies multiple convention rules independently", async () => {
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
          { match: "src/app/api/portal/**", require: "requirePortalUser" },
        ],
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            // Missing requireStaffPermission → should flag
            contents: "export async function GET() { return Response.json([]); }\n",
          },
          {
            relPath: "src/app/api/portal/orders/route.ts",
            // Has requirePortalUser → should NOT flag
            contents: [
              "import { requirePortalUser } from '@/lib/portal/auth';",
              "export async function GET() {",
              "  await requirePortalUser();",
              "  return Response.json([]);",
              "}",
              "",
            ].join("\n"),
          },
          {
            relPath: "src/app/api/portal/settings/route.ts",
            // Missing requirePortalUser → should flag
            contents: "export async function POST() { return Response.json({}); }\n",
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
          makeEndpoint({
            path: "/api/portal/orders",
            method: "GET",
            file: files["src/app/api/portal/orders/route.ts"],
          }),
          makeEndpoint({
            path: "/api/portal/settings",
            method: "POST",
            file: files["src/app/api/portal/settings/route.ts"],
          }),
        ],
      });
      const findings = await convention001.check(model);
      expect(findings).toHaveLength(2);
      // Each convention rule applies independently — the admin endpoint
      // gets flagged for missing requireStaffPermission, the portal/settings
      // endpoint for missing requirePortalUser. Order isn't load-bearing.
      const helpers = findings.map((f) => f.title).join(" | ");
      expect(helpers).toContain("requireStaffPermission");
      expect(helpers).toContain("requirePortalUser");
    });

    it("respects the // sentinel:ignore CONVENTION-001 pragma", async () => {
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
        ],
        files: [
          {
            relPath: "src/app/api/admin/webhook/route.ts",
            contents: [
              "// sentinel:ignore CONVENTION-001",
              "// Vendor webhook — verified by HMAC, not session auth.",
              "export async function POST() { return Response.json({}); }",
              "",
            ].join("\n"),
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/webhook",
            method: "POST",
            file: files["src/app/api/admin/webhook/route.ts"],
          }),
        ],
      });
      const findings = await convention001.check(model);
      expect(findings).toHaveLength(0);
    });
  });

  describe("PATTERN-001: inferred auth pattern enforcement", () => {
    const convention001 = authAccessControlRules.find((r) => r.id === "CONVENTION-001")!;
    const pattern001 = authAccessControlRules.find((r) => r.id === "PATTERN-001")!;

    let tempDirs: string[] = [];

    afterEach(() => {
      for (const dir of tempDirs) {
        try { rmSync(dir, { recursive: true, force: true }); } catch {}
      }
      tempDirs = [];
    });

    function makeProject(opts: {
      conventions?: unknown;
      files: Array<{ relPath: string; contents: string }>;
    }): { root: string; files: Record<string, string> } {
      const root = mkdtempSync(join(tmpdir(), "pattern-001-"));
      tempDirs.push(root);
      const config: Record<string, unknown> = {
        stack: "nextjs-supabase",
        domains: ["all"],
        exclude: ["node_modules"],
        severity: { failOn: "high" },
        output: { format: "terminal", dir: ".sentinel/reports" },
      };
      if (opts.conventions !== undefined) config.conventions = opts.conventions;
      writeFileSync(join(root, ".sentinelrc.json"), JSON.stringify(config), "utf-8");

      const out: Record<string, string> = {};
      for (const f of opts.files) {
        const abs = join(root, f.relPath);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, f.contents, "utf-8");
        out[f.relPath] = abs;
      }
      return { root, files: out };
    }

    it("emits nothing when inferredPatterns is undefined", async () => {
      const { root, files } = makeProject({
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: "export async function GET() { return Response.json([]); }\n",
          },
        ],
      });
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
        // inferredPatterns intentionally omitted
      });
      const findings = await pattern001.check(model);
      expect(findings).toHaveLength(0);
    });

    it("emits nothing when inferredPatterns is empty", async () => {
      const { root, files } = makeProject({
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: "export async function GET() { return Response.json([]); }\n",
          },
        ],
      });
      const baseModel = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const model = { ...baseModel, inferredPatterns: [] };
      const findings = await pattern001.check(model);
      expect(findings).toHaveLength(0);
    });

    it("flags an endpoint that deviates from the inferred dominant helper", async () => {
      const { root, files } = makeProject({
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: "export async function GET() { return Response.json([]); }\n",
          },
        ],
      });
      const baseModel = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const model = {
        ...baseModel,
        inferredPatterns: [
          {
            domain: "auth" as const,
            pathGlob: "src/app/api/admin/**",
            dominantHelper: "requireStaffPermission",
            prevalence: 0.94,
            sampleSize: 17,
            evidenceFiles: [],
          },
        ],
      };
      const findings = await pattern001.check(model);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe("PATTERN-001");
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].description).toContain("94%");
      expect(findings[0].description).toContain("requireStaffPermission");
      expect(findings[0].description).toContain("n=17");
    });

    it("does not fire when the endpoint conforms to the inferred pattern", async () => {
      const { root, files } = makeProject({
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: [
              "import { requireStaffPermission } from '@/lib/staff/auth';",
              "export async function GET() {",
              "  await requireStaffPermission('users:read');",
              "  return Response.json([]);",
              "}",
              "",
            ].join("\n"),
          },
        ],
      });
      const baseModel = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const model = {
        ...baseModel,
        inferredPatterns: [
          {
            domain: "auth" as const,
            pathGlob: "src/app/api/admin/**",
            dominantHelper: "requireStaffPermission",
            prevalence: 0.94,
            sampleSize: 17,
            evidenceFiles: [],
          },
        ],
      };
      const findings = await pattern001.check(model);
      expect(findings).toHaveLength(0);
    });

    it("defers to CONVENTION-001 when both rules would fire on the same file", async () => {
      // Same file would be flagged by CONVENTION-001 (declared) AND
      // PATTERN-001 (inferred). PATTERN-001 must back off so the user sees
      // exactly one finding per endpoint.
      const { root, files } = makeProject({
        conventions: [
          { match: "src/app/api/admin/**", require: "requireStaffPermission" },
        ],
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: "export async function GET() { return Response.json([]); }\n",
          },
        ],
      });
      const baseModel = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const model = {
        ...baseModel,
        inferredPatterns: [
          {
            domain: "auth" as const,
            pathGlob: "src/app/api/admin/**",
            dominantHelper: "requireStaffPermission",
            prevalence: 0.94,
            sampleSize: 17,
            evidenceFiles: [],
          },
        ],
      };

      const conventionFindings = await convention001.check(model);
      const patternFindings = await pattern001.check(model);
      expect(conventionFindings).toHaveLength(1);
      expect(patternFindings).toHaveLength(0);
    });

    it("respects the // sentinel:ignore PATTERN-001 pragma", async () => {
      const { root, files } = makeProject({
        files: [
          {
            relPath: "src/app/api/admin/users/route.ts",
            contents: [
              "// sentinel:ignore PATTERN-001",
              "// This admin endpoint is intentionally public for service health checks.",
              "export async function GET() { return Response.json({ ok: true }); }",
              "",
            ].join("\n"),
          },
        ],
      });
      const baseModel = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [
          makeEndpoint({
            path: "/api/admin/users",
            method: "GET",
            file: files["src/app/api/admin/users/route.ts"],
          }),
        ],
      });
      const model = {
        ...baseModel,
        inferredPatterns: [
          {
            domain: "auth" as const,
            pathGlob: "src/app/api/admin/**",
            dominantHelper: "requireStaffPermission",
            prevalence: 0.94,
            sampleSize: 17,
            evidenceFiles: [],
          },
        ],
      };
      const findings = await pattern001.check(model);
      expect(findings).toHaveLength(0);
    });
  });
});
