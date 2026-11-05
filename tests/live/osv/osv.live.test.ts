// Real api.osv.dev round trip for SUPPLY-001 (gtsbahamas/fleet#8880).
//
// Excluded from the default suite: it needs the network. Run it with
// npm run test:osv-live wherever api.osv.dev is reachable.

import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { checkLiveVulnerabilities, configureLiveVulnCheck } from "../../../src/layers/rules/osv.js";
import { supplyChainRules } from "../../../src/layers/rules/domains/supply-chain.js";
import { emptyModel } from "../../rules/helpers.js";

function project(pkgs: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "osv-live-"));
  const packages: Record<string, { version: string }> = { "": { version: "1.0.0" } };
  for (const [name, version] of Object.entries(pkgs)) packages[`node_modules/${name}`] = { version };
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "fixture", lockfileVersion: 3, packages }));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", dependencies: pkgs }));
  return dir;
}

beforeAll(() => configureLiveVulnCheck(null));

describe("live OSV.dev lookup", () => {
  it("lodash@4.17.20 from a lockfile yields GHSA-35jh-r3h4-6jhm with fixed version 4.17.21", async () => {
    const dir = project({ lodash: "4.17.20" });
    const live = await checkLiveVulnerabilities(dir);
    expect(live.status, live.status === "skipped" ? live.reason : "").toBe("ok");
    if (live.status !== "ok") return;
    const hit = live.advisories.find((a) => a.id === "GHSA-35jh-r3h4-6jhm");
    console.log("OSV live hit:", JSON.stringify(hit));
    expect(hit).toMatchObject({ package: "lodash", installedVersion: "4.17.20", fixedVersion: "4.17.21", severity: "high", source: "osv" });
    expect(hit?.published).toMatch(/^2021-02-15/);

    const model = emptyModel();
    model.meta.path = dir;
    const rule = supplyChainRules.find((r) => r.id === "SUPPLY-001")!;
    const findings = await rule.check(model);
    const f = findings.find((x) => x.advisory?.id === "GHSA-35jh-r3h4-6jhm");
    expect(f?.advisory?.fixedVersion).toBe("4.17.21");
  });

  it("a clean lockfile yields no advisories", async () => {
    const live = await checkLiveVulnerabilities(project({ "is-number": "7.0.0" }));
    expect(live.status, live.status === "skipped" ? live.reason : "").toBe("ok");
    if (live.status !== "ok") return;
    console.log("OSV live clean:", JSON.stringify(live.advisories));
    expect(live.advisories).toEqual([]);
  });
});
