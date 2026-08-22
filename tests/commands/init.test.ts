// Tests for `sentinel init`. Real temp dirs, no fs mocking — the contract
// under test is the SKILL.md write roundtrip into a fake skills dir.
// Mirrors shipsafe-mcp's install_monitor.test.ts pattern.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  installSkill,
  skillPathFor,
  userSkillsDir,
  projectSkillsDir,
} from "../../src/commands/init.js";

let scratch: string;

beforeEach(() => {
  scratch = mkdtempSync(join(tmpdir(), "sentinel-init-test-"));
  process.env.SENTINEL_SKILLS_DIR = scratch;
});

afterEach(() => {
  delete process.env.SENTINEL_SKILLS_DIR;
  if (scratch && existsSync(scratch)) rmSync(scratch, { recursive: true, force: true });
});

describe("paths", () => {
  it("user-level path honors SENTINEL_SKILLS_DIR", () => {
    expect(userSkillsDir()).toBe(scratch);
    expect(skillPathFor("user", "/ignored")).toBe(
      join(scratch, "sentinel-scan", "SKILL.md"),
    );
  });

  it("project path is rooted at the repo's .claude/skills", () => {
    expect(projectSkillsDir(scratch)).toBe(join(scratch, ".claude", "skills"));
    expect(skillPathFor("project", scratch)).toBe(
      join(scratch, ".claude", "skills", "sentinel-scan", "SKILL.md"),
    );
  });
});

describe("installSkill", () => {
  it("writes a fresh skill with frontmatter, marker, and the scan command", () => {
    const result = installSkill("user", scratch);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.replaced).toBe(false);
    const body = readFileSync(result.skillPath, "utf-8");
    expect(body.startsWith("---\nname: sentinel-scan\n")).toBe(true);
    expect(body).toContain("Managed by shipsafe-sentinel init");
    expect(body).toContain("npx shipsafe-sentinel scan . --fail-on high");
    expect(body).toContain("skip sentinel");
  });

  it("installs into the project's .claude/skills with --project", () => {
    const result = installSkill("project", scratch);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.skillPath).toBe(
      join(scratch, ".claude", "skills", "sentinel-scan", "SKILL.md"),
    );
    expect(existsSync(result.skillPath)).toBe(true);
  });

  it("re-running replaces a managed skill and reports replaced", () => {
    expect(installSkill("user", scratch).ok).toBe(true);
    const second = installSkill("user", scratch);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.replaced).toBe(true);
  });

  it("refuses to overwrite an unmanaged file at the skill path", () => {
    const dir = join(scratch, "sentinel-scan");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "SKILL.md"), "# hand-authored skill\n");
    const result = installSkill("user", scratch);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain("not placed by sentinel init");
    // and the file is untouched
    expect(readFileSync(join(dir, "SKILL.md"), "utf-8")).toBe("# hand-authored skill\n");
  });
});
