import { describe, it, expect } from "vitest";
import { isDeniedPath, safeReadFile, walkProject } from "../../src/utils/fs.js";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("fs utils", () => {
  describe("isDeniedPath", () => {
    it("denies /proc paths", () => {
      expect(isDeniedPath("/proc/self/mem")).toBe(true);
    });
    it("denies .ssh paths", () => {
      expect(isDeniedPath("/home/user/.ssh/id_rsa")).toBe(true);
    });
    it("denies .env files", () => {
      expect(isDeniedPath("/project/.env")).toBe(true);
      expect(isDeniedPath("/project/.env.local")).toBe(true);
    });
    it("allows normal source files", () => {
      expect(isDeniedPath("/project/src/app/page.tsx")).toBe(false);
    });
    it("allows .env.example", () => {
      expect(isDeniedPath("/project/.env.example")).toBe(false);
    });
  });

  describe("safeReadFile", () => {
    it("throws on denied path", async () => {
      await expect(safeReadFile("/etc/passwd")).rejects.toThrow(/denied/);
    });
  });

  describe("walkProject", () => {
    const tmp = join(tmpdir(), `sentinel-walk-${Date.now()}`);

    it("returns file paths respecting exclude patterns", async () => {
      mkdirSync(join(tmp, "src"), { recursive: true });
      mkdirSync(join(tmp, "node_modules", "pkg"), { recursive: true });
      writeFileSync(join(tmp, "src", "index.ts"), "export {}");
      writeFileSync(join(tmp, "node_modules", "pkg", "index.js"), "module.exports = {}");

      const files = await walkProject(tmp, ["node_modules"]);
      const relative = files.map((f) => f.replace(tmp + "/", ""));
      expect(relative).toContain("src/index.ts");
      expect(relative).not.toContain("node_modules/pkg/index.js");

      rmSync(tmp, { recursive: true, force: true });
    });
  });
});
