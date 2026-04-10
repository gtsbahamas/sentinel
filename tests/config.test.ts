import { describe, it, expect } from "vitest";
import { loadConfig, CONFIG_DEFAULTS } from "../src/config.js";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("config", () => {
  const tmp = join(tmpdir(), `sentinel-test-${Date.now()}`);

  it("returns defaults when no .sentinelrc.json exists", async () => {
    mkdirSync(tmp, { recursive: true });
    const config = await loadConfig(tmp);
    expect(config.stack).toBe(CONFIG_DEFAULTS.stack);
    expect(config.domains).toEqual(CONFIG_DEFAULTS.domains);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("merges user config with defaults", async () => {
    mkdirSync(tmp, { recursive: true });
    writeFileSync(
      join(tmp, ".sentinelrc.json"),
      JSON.stringify({ severity: { failOn: "critical" } }),
    );
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("critical");
    expect(config.stack).toBe(CONFIG_DEFAULTS.stack);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("rejects invalid config", async () => {
    mkdirSync(tmp, { recursive: true });
    writeFileSync(
      join(tmp, ".sentinelrc.json"),
      JSON.stringify({ severity: { failOn: "impossible-level" } }),
    );
    await expect(loadConfig(tmp)).rejects.toThrow();
    rmSync(tmp, { recursive: true, force: true });
  });
});
