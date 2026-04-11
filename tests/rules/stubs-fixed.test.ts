import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../../src/layers/rules/domains/file-upload.js";

// Build a one-off fixture so we can put a real .env file on disk without
// polluting the shared vulnerable-nextjs fixture.
function scaffold(): string {
  const root = mkdtempSync(join(tmpdir(), "sentinel-stubs-"));
  mkdirSync(join(root, "src", "app", "api", "dl"), { recursive: true });
  mkdirSync(join(root, "supabase"), { recursive: true });

  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "stubs-fixture",
      version: "0.0.0",
      dependencies: { next: "14.2.0", react: "18.2.0", "@supabase/supabase-js": "2.39.0" },
    }),
  );
  writeFileSync(join(root, "tsconfig.json"), "{}");
  writeFileSync(join(root, "next.config.mjs"), "export default {};");

  // AUTH-007 fixture: short JWT_SECRET.
  writeFileSync(join(root, ".env"), "JWT_SECRET=tooshort\nSESSION_SECRET=ok-long-enough-32-chars-plus-ok\n");

  // UPLOAD-006 fixture: file response without Content-Disposition.
  writeFileSync(
    join(root, "src", "app", "api", "dl", "route.ts"),
    `export async function GET() {
       const buffer = new ArrayBuffer(10);
       return new Response(buffer, { headers: { "Content-Type": "application/pdf" } });
     }`,
  );

  // UPLOAD-008 fixture: public bucket without matching policy.
  writeFileSync(
    join(root, "supabase", "config.toml"),
    `[storage.buckets.assets]
public = true
`,
  );

  return root;
}

describe("fixed stubs produce real findings", () => {
  let fixturePath: string;

  beforeAll(() => {
    fixturePath = scaffold();
  });

  afterAll(() => {
    rmSync(fixturePath, { recursive: true, force: true });
  });

  it("AUTH-007 flags short JWT_SECRET", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth007 = findings.filter((f) => f.ruleId === "AUTH-007");
    expect(auth007.length).toBeGreaterThanOrEqual(1);
    expect(auth007.some((f) => /JWT_SECRET/.test(f.title))).toBe(true);
  });

  it("UPLOAD-006 flags file-serving route without Content-Disposition", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "UPLOAD-006").length).toBeGreaterThanOrEqual(1);
  });

  it("UPLOAD-008 flags public bucket without policy", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const upload008 = findings.filter((f) => f.ruleId === "UPLOAD-008");
    expect(upload008.length).toBeGreaterThanOrEqual(1);
    expect(upload008.some((f) => /assets/.test(f.title))).toBe(true);
  });
});
