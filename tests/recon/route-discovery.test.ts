import { describe, it, expect } from "vitest";
import { discoverRoutes } from "../../src/layers/recon/route-discovery.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("route-discovery", () => {
  it("finds app router routes from fixture", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const paths = routes.map((r) => r.path);
    expect(paths).toContain("/");
    expect(paths).toContain("/api/profile");
    expect(paths).toContain("/api/upload");
    expect(paths).toContain("/api/projects/[id]");
  });

  it("identifies API routes vs pages", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const apiRoutes = routes.filter((r) => r.isApi);
    const pageRoutes = routes.filter((r) => !r.isApi);
    expect(apiRoutes.length).toBeGreaterThanOrEqual(3);
    expect(pageRoutes.length).toBeGreaterThanOrEqual(1);
  });

  it("extracts param names from dynamic segments", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const dynamic = routes.find((r) => r.path === "/api/projects/[id]");
    expect(dynamic?.paramNames).toContain("id");
  });
});
