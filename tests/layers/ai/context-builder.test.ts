import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { buildContext } from "../../../src/layers/ai/context-builder.js";
import type { ApiEndpoint, ProjectModel } from "../../../src/model/types.js";

function mkFixture() {
  const root = mkdtempSync(join(tmpdir(), "ai-ctx-"));
  mkdirSync(join(root, "src", "app", "api", "users", "[id]"), { recursive: true });
  mkdirSync(join(root, "src", "lib"), { recursive: true });
  writeFileSync(
    join(root, "src", "app", "api", "users", "[id]", "route.ts"),
    `import { getUser } from "../../../../lib/auth.js";
import { updateSchema } from "../../../../lib/validation.js";
export async function PATCH(req: Request) { return new Response(); }`,
  );
  writeFileSync(
    join(root, "src", "lib", "auth.ts"),
    `export function getUser() { return null; }`,
  );
  writeFileSync(
    join(root, "src", "lib", "validation.ts"),
    `import { z } from "zod";
export const updateSchema = z.object({ name: z.string() });`,
  );
  return root;
}

function mkModel(root: string): ProjectModel {
  return {
    meta: { name: "t", path: root, stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

describe("buildContext", () => {
  let root: string;
  let endpoint: ApiEndpoint;

  beforeEach(() => {
    root = mkFixture();
    endpoint = {
      path: "/api/users/[id]",
      method: "PATCH",
      file: join(root, "src", "app", "api", "users", "[id]", "route.ts"),
      hasValidation: true,
      validationLibrary: "zod",
      hasAuthCheck: false,
      usesServiceRole: false,
    };
  });

  it("returns handler source + up to 5 adjacent files under the token cap", async () => {
    const ctx = await buildContext(endpoint, mkModel(root), 8000);
    expect(ctx).not.toBeNull();
    expect(ctx!.handlerSource).toContain("export async function PATCH");
    const paths = ctx!.adjacent.map((a) => a.path);
    expect(paths.some((p) => p.endsWith("auth.ts"))).toBe(true);
    expect(paths.some((p) => p.endsWith("validation.ts"))).toBe(true);
  });

  it("respects adjacent count cap of 5", async () => {
    // Make 10 local imports
    for (let i = 0; i < 10; i++) {
      writeFileSync(join(root, "src", "lib", `helper${i}.ts`), `export const x${i} = 1;`);
    }
    writeFileSync(
      endpoint.file,
      Array.from({ length: 10 }, (_, i) => `import { x${i} } from "../../../../lib/helper${i}.js";`).join("\n") +
        `\nexport async function PATCH() { return new Response(); }`,
    );
    const ctx = await buildContext(endpoint, mkModel(root), 8000);
    expect(ctx!.adjacent.length).toBeLessThanOrEqual(5);
  });

  it("drops adjacent files (in priority reverse order) when token budget is tight", async () => {
    const ctx = await buildContext(endpoint, mkModel(root), 50); // absurdly tight
    expect(ctx).not.toBeNull();
    // Handler is never dropped; adjacent is dropped first.
    expect(ctx!.handlerSource).toBeTruthy();
    expect(ctx!.adjacent.length).toBe(0);
  });

  it("returns null when handler alone exceeds the token cap", async () => {
    const huge = "x".repeat(50_000);
    writeFileSync(endpoint.file, huge);
    const ctx = await buildContext(endpoint, mkModel(root), 1000);
    expect(ctx).toBeNull();
  });

  it("returns an empty adjacent list when the handler has no local imports", async () => {
    writeFileSync(endpoint.file, `export async function PATCH() { return new Response(); }`);
    const ctx = await buildContext(endpoint, mkModel(root), 8000);
    expect(ctx!.adjacent).toEqual([]);
  });
});
