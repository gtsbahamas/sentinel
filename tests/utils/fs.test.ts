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

    // Regression: deny-list patterns must anchor to true filesystem roots,
    // otherwise legitimate project subdirectories named `dev`, `etc`, etc.
    // are mistaken for system paths and blow up the walker mid-scan.
    describe("project subdirectories that share names with system paths (regression)", () => {
      it("allows project subdirectory named 'dev'", () => {
        expect(
          isDeniedPath("/Users/foo/project/src/components/dev/SourceLabel.tsx"),
        ).toBe(false);
      });
      it("allows package subdirectory named 'dev'", () => {
        expect(isDeniedPath("/Users/foo/work/pkg/dev/index.ts")).toBe(false);
      });
      it("allows project subdirectory named 'etc'", () => {
        expect(isDeniedPath("/home/user/repo/etc/config.ts")).toBe(false);
      });
      it("allows project subdirectory named 'proc'", () => {
        expect(isDeniedPath("/Users/foo/project/src/proc/handler.ts")).toBe(false);
      });
      it("allows project subdirectory named 'sys'", () => {
        expect(isDeniedPath("/Users/foo/project/src/sys/index.ts")).toBe(false);
      });
      it("allows project subdirectory named 'root'", () => {
        expect(isDeniedPath("/Users/foo/project/src/root/page.tsx")).toBe(false);
      });
    });

    describe("system paths still denied (safety intent preserved)", () => {
      it("denies /dev/null", () => {
        expect(isDeniedPath("/dev/null")).toBe(true);
      });
      it("denies /etc/passwd", () => {
        expect(isDeniedPath("/etc/passwd")).toBe(true);
      });
      it("denies /proc/self/cmdline", () => {
        expect(isDeniedPath("/proc/self/cmdline")).toBe(true);
      });
      it("denies /sys/kernel/something", () => {
        expect(isDeniedPath("/sys/kernel/something")).toBe(true);
      });
      it("denies /root/.bashrc", () => {
        expect(isDeniedPath("/root/.bashrc")).toBe(true);
      });
      it("denies /Users/foo/.ssh/id_rsa", () => {
        expect(isDeniedPath("/Users/foo/.ssh/id_rsa")).toBe(true);
      });
      it("denies /home/user/.ssh/known_hosts", () => {
        expect(isDeniedPath("/home/user/.ssh/known_hosts")).toBe(true);
      });
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
