import { describe, it, expect, afterEach } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { emptyModel, makeEndpoint } from "./helpers.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

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
});
