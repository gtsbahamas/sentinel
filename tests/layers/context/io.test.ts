import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, rm, mkdir } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";
import { readContext, writeContext } from "../../../src/layers/context/io.js";
import type { ProjectContext } from "../../../src/layers/context/types.js";

const MINIMAL_CONTEXT: ProjectContext = {
  tenancy: "single-org",
  publicRoutes: [],
  validation: { library: "none", schemaLocations: [], importedByRoutes: false },
  migrations: { rlsStrategy: "none" },
  framework: { routeHandlersServerOnly: false, frameworkCatchesErrors: false, serverOnlyImportGuard: false },
  excludedPaths: [],
  auth: { defaultClient: "anon", roleModel: [] },
  deployment: { platform: "unknown", platformHandles: [] },
  delegations: [],
  version: 1,
  generatedAt: "2026-04-12T00:00:00Z",
  generatedBy: "auto",
  confidence: {},
};

describe("context io", () => {
  let dir: string;

  beforeEach(async () => {
    dir = join(tmpdir(), `sentinel-ctx-test-${Date.now()}`);
    await mkdir(dir, { recursive: true });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns null when no context file exists", async () => {
    expect(await readContext(dir)).toBeNull();
  });

  it("round-trips a context file", async () => {
    await writeContext(dir, MINIMAL_CONTEXT);
    const loaded = await readContext(dir);
    expect(loaded).toEqual(MINIMAL_CONTEXT);
  });

  it("returns null for invalid JSON in context file", async () => {
    await mkdir(join(dir, ".sentinel"), { recursive: true });
    await writeFile(join(dir, ".sentinel", "context.json"), "not json", "utf-8");
    expect(await readContext(dir)).toBeNull();
  });
});
