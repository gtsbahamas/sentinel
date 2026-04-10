import { describe, it, expect } from "vitest";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("recon orchestrator", () => {
  it("builds a complete ProjectModel", async () => {
    const model = await runRecon(fixturePath, ["node_modules"]);
    expect(model.meta.stack).toBe("nextjs-supabase");
    expect(model.routes.length).toBeGreaterThan(0);
    expect(model.endpoints.length).toBeGreaterThan(0);
    expect(model.fileUploads.length).toBeGreaterThanOrEqual(1);
    expect(model.envVars.length).toBeGreaterThan(0);
    expect(model.dependencies.length).toBeGreaterThan(0);
    expect(model.findings).toEqual([]);
  });
});
