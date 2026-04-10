import { describe, it, expect } from "vitest";
import { discoverEndpoints } from "../../src/layers/recon/endpoint-discovery.js";
import { discoverRoutes } from "../../src/layers/recon/route-discovery.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("endpoint-discovery", () => {
  it("extracts API endpoints with validation and auth metadata", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost).toBeDefined();
    expect(profilePost?.hasValidation).toBe(false);
    expect(profilePost?.hasAuthCheck).toBe(false);
  });

  it("detects service role usage", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost?.usesServiceRole).toBe(true);
  });
});
