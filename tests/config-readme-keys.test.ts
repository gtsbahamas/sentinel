import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { spawnSync } from "child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { tmpdir } from "os";
import { fileURLToPath } from "url";
import { loadConfig, CONFIG_DEFAULTS, resetConfigWarnings } from "../src/config.js";
import { buildAuthorizationEntry, loadAuthorizations, persistAuthorization } from "../src/layers/probe/authorization.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const cli = join(root, "src", "cli.ts");
const fixture = join(__dirname, "fixtures", "vulnerable-nextjs");
// A spawned scan falls back to SHIPSAFE_* from the environment; never let a test push.
const offlineEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SHIPSAFE_")));

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

  it("`ignore` is read with or without a trailing slash, and the scan still walks those paths", async () => {
    write({ ignore: ["test/", "supabase/migrations/", "scripts"] });
    const config = await loadConfig(tmp);
    expect(config.ignore).toEqual(["test", "supabase/migrations", "scripts"]);
    // Not skipped by the walk: a finding there has to be found before it can be listed as ignored.
    expect(config.exclude).toEqual(CONFIG_DEFAULTS.exclude);
    expect(stderr.join("")).toBe("");
  });

  it("`ignore` leaves a user `exclude` list as written", async () => {
    write({ exclude: ["vendor/"], ignore: ["test/"] });
    const config = await loadConfig(tmp);
    expect(config.exclude).toEqual(["vendor"]);
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
        expect(config.ignore).toContain(entry.replace(/\/+$/, ""));
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

  it("does not warn about the `probe` key Sentinel writes itself when a probe is authorized", async () => {
    write({ failOn: "low" });
    await persistAuthorization(tmp, buildAuthorizationEntry("https://staging.example.com", "passive", "example"));
    const config = await loadConfig(tmp);
    expect(stderr.join("")).toBe("");
    expect(config.severity.failOn).toBe("low");
    expect(await loadAuthorizations(tmp)).toHaveLength(1);
  });

  it("leaves the value of `probe` to the probe layer: an odd one does not stop the load", async () => {
    write({ probe: [], failOn: "low" });
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("low");
    expect(config).not.toHaveProperty("probe");
  });

  it("still warns about a key it does not know inside `probe`", async () => {
    write({ probe: { authorisations: [] } });
    await loadConfig(tmp);
    expect(stderr.join("")).toContain("probe.authorisations");
  });

  it.each([
    [{ failOn: "High" }, "failOn"],
    [{ ignore: "test/" }, "ignore"],
    [{ severity: { failOn: "High" } }, "severity.failOn"],
    [{ ai: { maxCostUsd: "2" } }, "ai.maxCostUsd"],
  ])("a bad value %j is refused in one line naming the file and the key", async (config, key) => {
    write(config);
    const error: unknown = await loadConfig(tmp).catch((e) => e);
    expect(error).toBeInstanceOf(Error);
    const { name, message } = error as Error;
    expect(name).toBe("ConfigError");
    expect(message).toContain(join(tmp, ".sentinelrc.json"));
    expect(message).toContain(`\`${key}\``);
    expect(message).not.toContain("\n");
  });

  it("names only the key the file spells: a bad top-level `failOn` is not also blamed on `severity.failOn`", async () => {
    write({ failOn: "High" });
    const error = (await loadConfig(tmp).catch((e) => e)) as Error;
    expect(error.message).not.toContain("severity.failOn");
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
      env: { ...offlineEnv, SENTINEL_OFFLINE: "1" },
      maxBuffer: 64 * 1024 * 1024,
    });
    const report = JSON.parse(res.stdout) as {
      findings: { severity: string; evidence: { file: string }[] }[];
      ignored: { evidence: { file: string }[] }[];
      summary: { total: number; ignored: number };
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
      // What was left out is listed and counted, not silently gone.
      expect(ignored.report.ignored.length).toBe(countInApi(before.report));
      expect(ignored.report.ignored.every((f) => f.evidence.every((e) => inApi(e.file)))).toBe(true);
      expect(ignored.report.summary.ignored).toBe(ignored.report.ignored.length);
      expect(ignored.report.summary.total).toBe(ignored.report.findings.length);
      expect(ignored.res.stderr).toContain("notAKey");

      // The default terminal report says so too.
      const terminal = spawnSync("npx", ["tsx", cli, "scan", tmp], {
        cwd: root,
        encoding: "utf-8",
        env: { ...offlineEnv, SENTINEL_OFFLINE: "1", NO_COLOR: "1" },
        maxBuffer: 64 * 1024 * 1024,
      });
      expect(terminal.stdout).toContain(`IGNORED BY .sentinelrc.json (${ignored.report.ignored.length})`);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }, 120_000);

  it.each([
    [{ failOn: "High" }, "failOn"],
    [{ ignore: "test/" }, "ignore"],
  ])("a bad value %j stops the scan with one readable line and exit code 2, not a stack", (config, key) => {
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-badvalue-"));
    try {
      writeFileSync(join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
      writeFileSync(join(tmp, ".sentinelrc.json"), JSON.stringify(config));
      const res = spawnSync("npx", ["tsx", cli, "scan", tmp, "--format", "json"], {
        cwd: root,
        encoding: "utf-8",
        env: { ...offlineEnv, SENTINEL_OFFLINE: "1" },
      });
      expect(res.status).toBe(2);
      expect(res.stdout).toBe("");
      const lines = res.stderr.trim().split("\n");
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain(".sentinelrc.json");
      expect(lines[0]).toContain(`\`${key}\``);
      expect(res.stderr).not.toContain("ZodError");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }, 120_000);

  it("a blocking finding only under an ignored path does not set the exit code", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-ignore-exit-"));
    try {
      writeFileSync(join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
      writeFileSync(
        join(tmp, "package-lock.json"),
        JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "x", version: "1.0.0" } } }),
      );
      mkdirSync(join(tmp, "tools"));
      // MD5 trips CRYPTO-002 (critical).
      writeFileSync(
        join(tmp, "tools", "hash.ts"),
        'import { createHash } from "crypto";\nexport const h = (s: string) => createHash("md5").update(s).digest("hex");\n',
      );
      const before = scan(tmp);
      // The premise: the only finding at the default bar sits under tools/.
      const blocking = before.report.findings.filter((f) => f.severity === "critical" || f.severity === "high");
      expect(blocking.length).toBeGreaterThan(0);
      expect(blocking.every((f) => f.evidence.every((e) => e.file.includes("/tools/")))).toBe(true);
      expect(before.res.status).toBe(1);

      writeFileSync(join(tmp, ".sentinelrc.json"), JSON.stringify({ ignore: ["tools/"] }));
      const after = scan(tmp);
      expect(after.report.ignored.length).toBe(blocking.length);
      expect(after.res.status).toBe(0);
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
