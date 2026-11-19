import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { spawnSync } from "child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { tmpdir } from "os";
import { fileURLToPath } from "url";
import { loadConfig, CONFIG_DEFAULTS, resetConfigWarnings } from "../src/config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const cli = join(root, "src", "cli.ts");
const fixture = join(__dirname, "fixtures", "vulnerable-nextjs");

function readmeConfigExample(): Record<string, unknown> {
  const readme = readFileSync(join(root, "README.md"), "utf-8");
  const section = readme.slice(readme.indexOf("## Config"));
  const block = /```json\n([\s\S]*?)```/.exec(section);
  if (!block) throw new Error("README has no JSON block under ## Config");
  return JSON.parse(block[1]);
}

describe("config keys the README documents", () => {
  let tmp: string;
  let stderr: string[];

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "sentinel-config-"));
    stderr = [];
    resetConfigWarnings();
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(tmp, { recursive: true, force: true });
  });

  function write(config: unknown) {
    writeFileSync(join(tmp, ".sentinelrc.json"), JSON.stringify(config));
  }

  it("`ignore` adds to the excluded paths, trailing slash or not", async () => {
    write({ ignore: ["test/", "supabase/migrations/", "scripts"] });
    const config = await loadConfig(tmp);
    expect(config.exclude).toEqual([
      ...CONFIG_DEFAULTS.exclude,
      "test",
      "supabase/migrations",
      "scripts",
    ]);
    expect(stderr.join("")).toBe("");
  });

  it("`ignore` adds to a user `exclude` list as well", async () => {
    write({ exclude: ["vendor/"], ignore: ["test/"] });
    const config = await loadConfig(tmp);
    expect(config.exclude).toEqual(["vendor", "test"]);
    expect(config.ignore).toEqual(["test"]);
  });

  it("top-level `failOn` sets the failing severity", async () => {
    write({ failOn: "critical" });
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("critical");
    expect(stderr.join("")).toBe("");
  });

  it("`severity.failOn` wins when both spellings are present", async () => {
    write({ failOn: "critical", severity: { failOn: "low" } });
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("low");
  });

  it("rejects an invalid top-level `failOn`", async () => {
    write({ failOn: "impossible-level" });
    await expect(loadConfig(tmp)).rejects.toThrow();
  });

  it("the README's own example loads with every key honoured and no warning", async () => {
    const example = readmeConfigExample();
    write(example);
    const config = await loadConfig(tmp);
    expect(stderr.join("")).toBe("");
    if (Array.isArray(example.ignore)) {
      for (const entry of example.ignore as string[]) {
        expect(config.exclude).toContain(entry.replace(/\/+$/, ""));
      }
    }
    if (typeof example.failOn === "string") {
      expect(config.severity.failOn).toBe(example.failOn);
    }
  });

  it("warns on stderr about an unknown key, top-level or nested, and still loads", async () => {
    write({ ignroe: ["test/"], ai: { enabeld: true }, severity: { failOn: "low", extra: 1 } });
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("low");
    const out = stderr.join("");
    expect(out).toContain("ignroe");
    expect(out).toContain("ai.enabeld");
    expect(out).toContain("severity.extra");
    expect(out).toContain(".sentinelrc.json");
  });

  it("the shipped .sentinelrc.defaults.json loads without a warning", async () => {
    write(JSON.parse(readFileSync(join(root, ".sentinelrc.defaults.json"), "utf-8")));
    await loadConfig(tmp);
    expect(stderr.join("")).toBe("");
  });

  it("warns once per config file, however many times it is loaded", async () => {
    write({ ignroe: [] });
    await loadConfig(tmp);
    await loadConfig(tmp);
    await loadConfig(tmp);
    expect(stderr.join("").match(/ignroe/g)).toHaveLength(1);
  });
});

describe("scan honours the documented keys end to end", () => {
  function scan(dir: string) {
    const res = spawnSync("npx", ["tsx", cli, "scan", dir, "--format", "json"], {
      cwd: root,
      encoding: "utf-8",
      env: { ...process.env, SENTINEL_OFFLINE: "1" },
      maxBuffer: 64 * 1024 * 1024,
    });
    const report = JSON.parse(res.stdout) as {
      findings: { severity: string; evidence: { file: string }[] }[];
    };
    return { res, report };
  }

  it("`ignore` removes every finding under that path, and an unknown key warns without breaking the JSON on stdout", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-scan-"));
    try {
      cpSync(fixture, tmp, { recursive: true });
      const inApi = (file: string) => file.includes("src/app/api/");
      const countInApi = (r: typeof before.report) =>
        r.findings.filter((f) => f.evidence.some((e) => inApi(e.file))).length;

      const before = scan(tmp);
      expect(countInApi(before.report)).toBeGreaterThan(0);

      writeFileSync(
        join(tmp, ".sentinelrc.json"),
        JSON.stringify({ ignore: ["src/app/api/"], notAKey: true }),
      );
      const ignored = scan(tmp);
      expect(countInApi(ignored.report)).toBe(0);
      // Findings elsewhere are untouched.
      expect(ignored.report.findings.length).toBe(
        before.report.findings.length - countInApi(before.report),
      );
      expect(ignored.res.stderr).toContain("notAKey");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }, 120_000);

  it("top-level `failOn` decides the exit code", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-failon-"));
    try {
      writeFileSync(join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
      const before = scan(tmp);
      const severities = new Set(before.report.findings.map((f) => f.severity));
      // The premise: something at the default bar (high), nothing critical.
      expect(severities.has("high")).toBe(true);
      expect(severities.has("critical")).toBe(false);
      expect(before.res.status).toBe(1);

      writeFileSync(join(tmp, ".sentinelrc.json"), JSON.stringify({ failOn: "critical" }));
      expect(scan(tmp).res.status).toBe(0);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }, 120_000);
});
