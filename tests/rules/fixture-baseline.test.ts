import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { runRules } from "../../src/layers/rules/index.js";
import { stagedFixture } from "./helpers.js";
import { findingKey, reconWithAllRules, sortKeys, type FindingKey } from "./support/all-rules.js";

// What every fixture in tests/fixtures alarmed on BEFORE `sentinel:ignore`
// became a shared path for all rules. No fixture carries the comment, so the
// full rule set must keep producing exactly this list: a scanner that goes
// quiet is the failure this file exists to catch.
//
// Regenerate (only when a rule change is meant to move it):
//   UPDATE_FIXTURE_BASELINE=1 npx vitest run tests/rules/fixture-baseline.test.ts

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_FILE = join(here, "fixture-baseline.json");
const FIXTURES = readdirSync(join(here, "..", "fixtures"), { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

async function scanFixture(name: string): Promise<FindingKey[]> {
  const { model, root } = await reconWithAllRules(stagedFixture(name));
  const findings = await runRules(model, null);
  return sortKeys(findings.map((f) => findingKey(f, root)));
}

describe("fixtures alarm exactly as before when no sentinel:ignore comment is present", () => {
  let offlineBefore: string | undefined;
  beforeAll(() => {
    offlineBefore = process.env.SENTINEL_OFFLINE;
    process.env.SENTINEL_OFFLINE = "1";
  });
  afterAll(() => {
    if (offlineBefore === undefined) delete process.env.SENTINEL_OFFLINE;
    else process.env.SENTINEL_OFFLINE = offlineBefore;
  });

  if (process.env.UPDATE_FIXTURE_BASELINE === "1") {
    it("writes the baseline", async () => {
      const out: Record<string, FindingKey[]> = {};
      for (const name of FIXTURES) out[name] = await scanFixture(name);
      writeFileSync(BASELINE_FILE, JSON.stringify(out, null, 2) + "\n");
    }, 120_000);
    return;
  }

  const baseline = JSON.parse(readFileSync(BASELINE_FILE, "utf-8")) as Record<string, FindingKey[]>;

  it("covers every fixture directory", () => {
    expect(Object.keys(baseline).sort()).toEqual(FIXTURES);
  });

  it("the baseline is not empty", () => {
    const total = Object.values(baseline).reduce((n, list) => n + list.length, 0);
    expect(total).toBeGreaterThan(50);
  });

  for (const name of FIXTURES) {
    it(`${name}: same findings, same severities`, async () => {
      expect(await scanFixture(name)).toEqual(baseline[name]);
    }, 60_000);
  }
});
