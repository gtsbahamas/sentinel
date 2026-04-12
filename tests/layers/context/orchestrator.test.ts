import { describe, it, expect } from "vitest";
import { inferContext } from "../../../src/layers/context/index.js";
import { runRecon } from "../../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferContext", () => {
  it("produces a valid ProjectContext from a fixture", async () => {
    const model = await runRecon(FIXTURE, []);
    const context = await inferContext(model);

    expect(context.tenancy).toBe("single-org");
    expect(context.validation.library).toBe("zod");
    expect(context.framework.frameworkCatchesErrors).toBe(true);
    expect(context.deployment.platform).toBe("vercel");
    expect(context.excludedPaths).toContain("scripts/");
    expect(context.version).toBe(1);
    expect(context.generatedBy).toBe("auto");
    expect(context.confidence).toBeDefined();
  });
});
