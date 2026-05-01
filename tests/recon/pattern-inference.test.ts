import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { inferAuthPatterns } from "../../src/layers/recon/pattern-inference.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { ApiEndpoint } from "../../src/model/types.js";
import { dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

// Track per-test scratch dirs so the afterEach can wipe them.
const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

// Create a tempdir mirroring the project layout `<root>/<group>/endpointN/route.ts`,
// where each route's source is supplied by the `helpers` array. Returns ApiEndpoint
// stubs whose `file` field points at the on-disk source so inferAuthPatterns
// can read them back.
async function makeEndpoints(
  group: string,
  helpers: Array<string | null>,
): Promise<ApiEndpoint[]> {
  const root = await mkdtemp(join(tmpdir(), "sentinel-pattern-"));
  tempDirs.push(root);
  const groupDir = join(root, group);

  const endpoints: ApiEndpoint[] = [];
  for (let i = 0; i < helpers.length; i++) {
    const dir = join(groupDir, `endpoint${i}`);
    await mkdir(dir, { recursive: true });
    const file = join(dir, "route.ts");
    const helper = helpers[i];
    const source = helper
      ? `export async function GET(req) {\n  await ${helper}(req);\n  return Response.json({ ok: true });\n}\n`
      : `export async function GET(req) {\n  const body = await req.json();\n  return Response.json({ ok: true });\n}\n`;
    await writeFile(file, source, "utf-8");
    endpoints.push({
      path: `/api/${group.replace(/^src\/app\/api\//, "")}/endpoint${i}`,
      method: "GET",
      file,
      hasValidation: false,
      validationLibrary: null,
      hasAuthCheck: !!helper,
      usesServiceRole: false,
    });
  }

  return endpoints;
}

describe("inferAuthPatterns", () => {
  it("emits a pattern when 5/5 admin endpoints share one helper (prevalence 1.0)", async () => {
    const endpoints = await makeEndpoints(
      "src/app/api/admin",
      Array(5).fill("requireStaffPermission"),
    );

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toHaveLength(1);
    expect(patterns[0].domain).toBe("auth");
    expect(patterns[0].pathGlob).toBe("src/app/api/admin/**");
    expect(patterns[0].dominantHelper).toBe("requireStaffPermission");
    expect(patterns[0].prevalence).toBe(1.0);
    expect(patterns[0].sampleSize).toBe(5);
    expect(patterns[0].evidenceFiles).toHaveLength(3); // capped at 3
  });

  it("emits a pattern at the 60% threshold (3 of 5 use the dominant helper)", async () => {
    const endpoints = await makeEndpoints("src/app/api/admin", [
      "requireStaffPermission",
      "requireStaffPermission",
      "requireStaffPermission",
      "getUser",
      "getUser",
    ]);

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toHaveLength(1);
    expect(patterns[0].dominantHelper).toBe("requireStaffPermission");
    expect(patterns[0].prevalence).toBeCloseTo(0.6, 5);
    expect(patterns[0].sampleSize).toBe(5);
  });

  it("emits nothing when sample size is below 5 (4 admin endpoints)", async () => {
    const endpoints = await makeEndpoints(
      "src/app/api/admin",
      Array(4).fill("requireStaffPermission"),
    );

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toEqual([]);
  });

  it("emits nothing when no helper reaches 60% (5/5 split between two helpers)", async () => {
    const endpoints = await makeEndpoints("src/app/api/admin", [
      "requireStaffPermission",
      "requireStaffPermission",
      "requireStaffPermission",
      "requireStaffPermission",
      "requireStaffPermission",
      "getUser",
      "getUser",
      "getUser",
      "getUser",
      "getUser",
    ]);

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toEqual([]);
  });

  it("emits one pattern per qualifying group (admin + portal with different helpers)", async () => {
    const adminEps = await makeEndpoints(
      "src/app/api/admin",
      Array(6).fill("requireStaffPermission"),
    );
    const portalEps = await makeEndpoints(
      "src/app/api/portal",
      Array(7).fill("requirePortalSession"),
    );

    const patterns = await inferAuthPatterns([...adminEps, ...portalEps]);

    expect(patterns).toHaveLength(2);
    const admin = patterns.find((p) => p.pathGlob === "src/app/api/admin/**");
    const portal = patterns.find((p) => p.pathGlob === "src/app/api/portal/**");
    expect(admin?.dominantHelper).toBe("requireStaffPermission");
    expect(admin?.sampleSize).toBe(6);
    expect(portal?.dominantHelper).toBe("requirePortalSession");
    expect(portal?.sampleSize).toBe(7);
  });

  it("falls into the catch-all group when path doesn't match a specific prefix", async () => {
    // Files under src/app/api/misc/ — no admin/portal/v1/internal — must
    // land in the src/app/api/** catch-all and be emitted there.
    const endpoints = await makeEndpoints(
      "src/app/api/misc",
      Array(5).fill("getServerUser"),
    );

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toHaveLength(1);
    expect(patterns[0].pathGlob).toBe("src/app/api/**");
    expect(patterns[0].dominantHelper).toBe("getServerUser");
    expect(patterns[0].sampleSize).toBe(5);
  });

  it("does NOT double-count admin endpoints into the catch-all group", async () => {
    // 6 admin endpoints with consistent helper. They should land in
    // src/app/api/admin/** only; the catch-all should see zero of them
    // and emit nothing.
    const endpoints = await makeEndpoints(
      "src/app/api/admin",
      Array(6).fill("requireStaffPermission"),
    );

    const patterns = await inferAuthPatterns(endpoints);

    expect(patterns).toHaveLength(1);
    expect(patterns[0].pathGlob).toBe("src/app/api/admin/**");
    expect(patterns.find((p) => p.pathGlob === "src/app/api/**")).toBeUndefined();
  });

  it("returns empty result for empty endpoint list", async () => {
    const patterns = await inferAuthPatterns([]);
    expect(patterns).toEqual([]);
  });
});

describe("inferAuthPatterns integration with runRecon", () => {
  it("runs against vulnerable-nextjs fixture and emits no patterns (catch-all has no auth helpers)", async () => {
    const model = await runRecon(fixturePath, ["node_modules"]);

    // The fixture has 7 endpoints, all under src/app/api/** (no admin/portal/etc.
    // subpaths), and none of them call any of the verb+noun auth helpers.
    // So the catch-all bucket has 7 endpoints but zero helper hits → no
    // dominant helper → no pattern emitted.
    expect(model.inferredPatterns).toBeDefined();
    expect(model.inferredPatterns).toEqual([]);
  });
});
