import { describe, it, expect } from "vitest";
import { inferValidation } from "../../../../src/layers/context/inferrers/validation.js";
import { inferMigrations } from "../../../../src/layers/context/inferrers/migrations.js";
import { runRecon } from "../../../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferValidation", () => {
  it("detects zod schemas imported by routes", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferValidation(model);
    expect(result.value.library).toBe("zod");
    expect(result.value.importedByRoutes).toBe(true);
    expect(result.value.schemaLocations.length).toBeGreaterThan(0);
    // 1 of 2 mutation endpoints import from validation/ → ratio 0.5 → medium confidence
    expect(result.confidence).toBe("medium");
  });

  it("returns none when no validation library is present", async () => {
    const model = await runRecon(FIXTURE, []);
    // Strip out zod to simulate no-library scenario
    const modelWithoutZod = {
      ...model,
      dependencies: model.dependencies.filter((d) => d.name !== "zod"),
    };
    const result = await inferValidation(modelWithoutZod);
    expect(result.value.library).toBe("none");
    expect(result.value.importedByRoutes).toBe(false);
    expect(result.value.schemaLocations).toEqual([]);
    expect(result.confidence).toBe("high");
  });
});

describe("inferMigrations", () => {
  it("detects dedicated RLS file", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferMigrations(model);
    expect(result.value.rlsStrategy).toBe("dedicated-file");
    expect(result.value.rlsFile).toContain("00003_rls");
    expect(result.confidence).toBe("high");
  });
});
