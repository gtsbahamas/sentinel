import { describe, it, expect } from "vitest";
import { detectStack } from "../../src/layers/recon/stack-detector.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("stack-detector", () => {
  it("detects nextjs-supabase stack from fixture", async () => {
    const meta = await detectStack(fixturePath);
    expect(meta.stack).toBe("nextjs-supabase");
    expect(meta.framework).toBe("nextjs-app");
    expect(meta.language).toBe("typescript");
  });

  it("detects package manager from lockfile", async () => {
    const meta = await detectStack(fixturePath);
    expect(["npm", "pnpm", "yarn"]).toContain(meta.packageManager);
  });
});
