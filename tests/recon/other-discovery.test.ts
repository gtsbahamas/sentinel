import { describe, it, expect } from "vitest";
import { discoverUploadHandlers } from "../../src/layers/recon/upload-discovery.js";
import { discoverEnvVars } from "../../src/layers/recon/env-discovery.js";
import { discoverDependencies } from "../../src/layers/recon/dep-discovery.js";
import { walkProject } from "../../src/utils/fs.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("other discovery", () => {
  it("finds upload handlers in the fixture", async () => {
    const files = await walkProject(fixturePath, ["node_modules"]);
    const uploads = await discoverUploadHandlers(files);
    expect(uploads.length).toBeGreaterThanOrEqual(1);
    const first = uploads[0];
    expect(first.usesUserFilename).toBe(true);
    expect(first.storageDestination).toBe("supabase");
  });

  it("maps env var usage", async () => {
    const files = await walkProject(fixturePath, ["node_modules"]);
    const envVars = await discoverEnvVars(fixturePath, files);
    const serviceRole = envVars.find((e) => e.name === "SUPABASE_SERVICE_ROLE_KEY");
    expect(serviceRole).toBeDefined();
    expect(serviceRole?.inExample).toBe(false);
    const publicUrl = envVars.find((e) => e.name === "NEXT_PUBLIC_SUPABASE_URL");
    expect(publicUrl?.clientExposed).toBe(true);
    expect(publicUrl?.inExample).toBe(true);
  });

  it("reads dependencies from package.json", async () => {
    const deps = await discoverDependencies(fixturePath);
    const next = deps.find((d) => d.name === "next");
    expect(next).toBeDefined();
    expect(next?.type).toBe("production");
  });
});
