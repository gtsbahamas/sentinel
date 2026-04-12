import { describe, it, expect } from "vitest";
import { inferAuth } from "../../../../src/layers/context/inferrers/auth.js";
import { inferPublicRoutes } from "../../../../src/layers/context/inferrers/public-routes.js";
import { inferDelegations } from "../../../../src/layers/context/inferrers/delegations.js";
import { runRecon } from "../../../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferAuth", () => {
  it("detects anon client as default", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferAuth(model);
    expect(result.value.defaultClient).toBe("anon");
    expect(result.confidence).toMatch(/high|medium/);
  });

  it("returns roleModel as an array", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferAuth(model);
    expect(Array.isArray(result.value.roleModel)).toBe(true);
  });

  it("returns low confidence when no api route files found", async () => {
    // A minimal model with no route files at a non-existent path
    const model = await runRecon(FIXTURE, []);
    const emptyModel = { ...model, meta: { ...model.meta, path: "/nonexistent/path" } };
    const result = await inferAuth(emptyModel);
    expect(result.confidence).toBe("low");
  });
});

describe("inferPublicRoutes", () => {
  it("detects routes under /api/public/ as intentionally public", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferPublicRoutes(model);
    expect(result.value.length).toBeGreaterThan(0);
    expect(result.value[0].pattern).toContain("public");
  });

  it("assigns magic-link reason to /api/public/ routes", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferPublicRoutes(model);
    const publicEntry = result.value.find((r) => r.pattern.includes("public"));
    expect(publicEntry).toBeDefined();
    expect(publicEntry?.reason).toBe("magic-link");
  });

  it("returns high confidence when public routes are found", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferPublicRoutes(model);
    expect(result.confidence).toBe("high");
  });

  it("returns empty array when endpoints provided and all have auth checks", async () => {
    const model = await runRecon(FIXTURE, []);
    // Provide synthetic endpoints where all have auth (bypasses file scanning)
    const patchedModel = {
      ...model,
      endpoints: [
        {
          path: "/api/public/reservation",
          method: "POST" as const,
          file: "fake.ts",
          hasValidation: false,
          validationLibrary: null as null,
          hasAuthCheck: true,
          usesServiceRole: false,
        },
      ],
    };
    const result = await inferPublicRoutes(patchedModel);
    expect(result.value).toEqual([]);
    expect(result.confidence).toBe("low");
  });
});

describe("inferDelegations", () => {
  it("detects supabase auth delegation", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferDelegations(model);
    expect(result.value.some((d) => d.provider === "supabase")).toBe(true);
  });

  it("includes JWT verification delegation", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferDelegations(model);
    const jwtDelegation = result.value.find(
      (d) => d.provider === "supabase" && d.responsibility === "JWT verification"
    );
    expect(jwtDelegation).toBeDefined();
  });

  it("returns empty delegations when supabase/ssr is not in deps", async () => {
    const model = await runRecon(FIXTURE, []);
    const patchedModel = {
      ...model,
      dependencies: model.dependencies.filter((d) => d.name !== "@supabase/ssr"),
    };
    const result = await inferDelegations(patchedModel);
    expect(result.value).toEqual([]);
  });
});
