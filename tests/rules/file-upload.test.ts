import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { fileUploadRules } from "../../src/layers/rules/domains/file-upload.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("file-upload rules", () => {
  it("flags upload without MIME validation (UPLOAD-001)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "UPLOAD-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags upload without size limit (UPLOAD-002)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "UPLOAD-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags user filename used as storage path (UPLOAD-004)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const u4 = findings.filter((f) => f.ruleId === "UPLOAD-004");
    expect(u4.length).toBeGreaterThanOrEqual(1);
    expect(u4[0].severity).toBe("critical");
  });
});
