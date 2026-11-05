// Live OSV.dev lookups for SUPPLY-001 (gtsbahamas/fleet#8880).
//
// The OSV client is injected through configureLiveVulnCheck() so these tests
// never depend on api.osv.dev being reachable. "Network blocked" is exercised
// two ways: a fetch that throws, and the real fetch pointed at a closed port.

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { supplyChainRules } from "../../src/layers/rules/domains/supply-chain.js";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { configureLiveVulnCheck } from "../../src/layers/rules/osv.js";
import { parsePackageLock, parsePnpmLock, parseYarnLock, readLockfile } from "../../src/layers/recon/lockfile.js";
import { emptyModel, makeDep } from "./helpers.js";

function getRule(id: string) {
  const rule = supplyChainRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

// Shape of the real OSV record for lodash's template() command injection.
const LODASH_ADVISORY = {
  id: "GHSA-35jh-r3h4-6jhm",
  summary: "Command Injection in lodash",
  aliases: ["CVE-2021-23337"],
  modified: "2024-02-15T00:00:00Z",
  published: "2021-02-15T11:50:49Z",
  database_specific: { severity: "HIGH" },
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

function projectWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "supply-osv-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

function packageLock(pkgs: Record<string, string>): string {
  const packages: Record<string, { version: string }> = { "": { version: "1.0.0" } };
  for (const [name, version] of Object.entries(pkgs)) packages[`node_modules/${name}`] = { version };
  return JSON.stringify({ name: "fixture", lockfileVersion: 3, packages });
}

type Call = { url: string; body: unknown };

/** Fake OSV: lodash@4.17.20 is affected by LODASH_ADVISORY, nothing else is. */
function fakeOsv(calls: Call[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, body });
    if (url.endsWith("/v1/querybatch")) {
      const results = (body.queries as Array<{ package: { name: string }; version: string }>).map((q) =>
        q.package.name === "lodash" && q.version === "4.17.20"
          ? { vulns: [{ id: LODASH_ADVISORY.id, modified: LODASH_ADVISORY.modified }] }
          : {},
      );
      return new Response(JSON.stringify({ results }), { status: 200 });
    }
    if (url.endsWith(`/v1/vulns/${LODASH_ADVISORY.id}`)) {
      return new Response(JSON.stringify(LODASH_ADVISORY), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

afterEach(() => configureLiveVulnCheck(null));

describe("supply-chain lockfile resolution", () => {
  it("reads exact versions from package-lock v3, including nested copies", () => {
    const pkgs = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { version: "1.0.0" },
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/a/node_modules/@scope/b": { version: "2.0.1" },
          "node_modules/linked": { link: true },
        },
      }),
    );
    expect(pkgs).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "@scope/b", version: "2.0.1" },
      ]),
    );
    expect(pkgs).toHaveLength(2);
  });

  it("reads exact versions from package-lock v1 nested dependencies", () => {
    const pkgs = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          lodash: { version: "4.17.20" },
          a: { version: "1.0.0", dependencies: { minimist: { version: "0.0.8" } } },
        },
      }),
    );
    expect(pkgs).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "a", version: "1.0.0" },
        { name: "minimist", version: "0.0.8" },
      ]),
    );
  });

  it("reads exact versions from pnpm-lock v9 and v6", () => {
    const v9 = parsePnpmLock(
      [
        "lockfileVersion: '9.0'",
        "packages:",
        "  lodash@4.17.20:",
        "    resolution: {integrity: sha512-x}",
        "  '@next/env@14.1.0':",
        "    resolution: {integrity: sha512-y}",
        "snapshots:",
        "  next@14.1.0(react@18.2.0):",
        "    dependencies: {}",
      ].join("\n"),
    );
    expect(v9).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "@next/env", version: "14.1.0" },
        { name: "next", version: "14.1.0" },
      ]),
    );
    const v6 = parsePnpmLock(
      ["lockfileVersion: '6.0'", "packages:", "  /lodash@4.17.20:", "    resolution: {integrity: sha512-x}", "  /@types/node/20.1.0:", "    dev: true"].join("\n"),
    );
    expect(v6).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "@types/node", version: "20.1.0" },
      ]),
    );
  });

  it("reads exact versions from yarn.lock classic and berry", () => {
    const classic = parseYarnLock(
      [
        "# yarn lockfile v1",
        "",
        'lodash@^4.17.0, lodash@^4.17.20:',
        '  version "4.17.20"',
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"',
        "",
        '"@babel/core@^7.0.0":',
        '  version "7.22.1"',
      ].join("\n"),
    );
    expect(classic).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.20" },
        { name: "@babel/core", version: "7.22.1" },
      ]),
    );
    const berry = parseYarnLock(
      ["__metadata:", "  version: 6", "", '"lodash@npm:^4.17.0":', "  version: 4.17.20", '  resolution: "lodash@npm:4.17.20"'].join("\n"),
    );
    expect(berry).toEqual([{ name: "lodash", version: "4.17.20" }]);
  });

  it("prefers the lockfile over package.json ranges", async () => {
    const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.20" }) });
    const lock = await readLockfile(dir);
    expect(lock?.file).toBe(join(dir, "package-lock.json"));
    expect(lock?.packages).toEqual([{ name: "lodash", version: "4.17.20" }]);
  });
});

describe("SUPPLY-001 live OSV lookups", () => {
  const rule001 = getRule("SUPPLY-001");

  it("flags a lockfile-pinned version with its OSV advisory id and fixed version", async () => {
    const calls: Call[] = [];
    configureLiveVulnCheck({ fetch: fakeOsv(calls) });
    const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.20", chalk: "5.3.0" }) });
    // package.json says a range; the query must carry the exact locked version.
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      dependencies: [makeDep("lodash", "^4.17.0"), makeDep("chalk", "^5.0.0")],
    });

    const findings = await rule001.check(model);

    const batch = calls.find((c) => c.url === "https://api.osv.dev/v1/querybatch");
    expect(batch).toBeDefined();
    expect((batch!.body as { queries: unknown[] }).queries).toEqual(
      expect.arrayContaining([{ package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" }]),
    );
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.severity).toBe("high");
    expect(f.title).toContain("GHSA-35jh-r3h4-6jhm");
    expect(f.remediation).toContain("4.17.21");
    expect(f.advisory).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      package: "lodash",
      installedVersion: "4.17.20",
      fixedVersion: "4.17.21",
      published: "2021-02-15T11:50:49Z",
      severity: "high",
      summary: "Command Injection in lodash",
      source: "osv",
    });
  });

  it("yields no findings and no skipped notice for a clean lockfile", async () => {
    configureLiveVulnCheck({ fetch: fakeOsv([]) });
    const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.21", chalk: "5.3.0" }) });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    expect(await rule001.check(model)).toEqual([]);
    expect(await getRule("SUPPLY-011").check(model)).toEqual([]);
  });

  it("does not apply the curated list when the live check succeeded", async () => {
    // lodash 4.17.20 is on the curated list, but OSV (the fake) says the
    // 4.17.21 lockfile entry is clean — the live answer wins.
    configureLiveVulnCheck({ fetch: fakeOsv([]) });
    const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.21" }) });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir }, dependencies: [makeDep("lodash", "4.17.20")] });
    expect(await rule001.check(model)).toEqual([]);
  });
});

describe("SUPPLY-001 offline fallback", () => {
  const blocked = (async () => {
    throw new TypeError("fetch failed: getaddrinfo ENOTFOUND api.osv.dev");
  }) as unknown as typeof fetch;

  it("with the network blocked, the scan finishes, uses the fallback list, and emits a skipped notice", async () => {
    configureLiveVulnCheck({ fetch: blocked });
    const dir = projectWith({
      "package.json": JSON.stringify({ name: "x", dependencies: { lodash: "^4.17.0" } }),
      "package-lock.json": packageLock({ lodash: "4.17.20" }),
    });
    resetRegistry();
    registerRules(supplyChainRules);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir }, dependencies: [makeDep("lodash", "^4.17.0")] });

    const findings = await runRules(model);

    const vuln = findings.filter((f) => f.ruleId === "SUPPLY-001");
    expect(vuln).toHaveLength(1);
    expect(vuln[0].title).toContain("lodash@4.17.20");
    expect(vuln[0].title).toContain("CVE-2021-23337");
    expect(vuln[0].advisory?.source).toBe("fallback");

    const notice = findings.filter((f) => f.ruleId === "SUPPLY-011");
    expect(notice).toHaveLength(1);
    expect(notice[0].severity).toBe("info");
    expect(notice[0].title.toLowerCase()).toContain("live vulnerability check skipped");
    expect(notice[0].description).toContain("ENOTFOUND");
  });

  it("treats a real connection refusal the same way (real fetch, closed port)", async () => {
    configureLiveVulnCheck({ endpoint: "http://127.0.0.1:9", timeoutMs: 3000 });
    const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.20" }) });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const vuln = await getRule("SUPPLY-001").check(model);
    expect(vuln.map((f) => f.title).join("\n")).toContain("lodash@4.17.20");
    const notice = await getRule("SUPPLY-011").check(model);
    expect(notice).toHaveLength(1);
    expect(notice[0].title.toLowerCase()).toContain("live vulnerability check skipped");
  });

  it("treats an OSV server error as skipped, never a silent pass", async () => {
    configureLiveVulnCheck({ fetch: (async () => new Response("upstream down", { status: 503 })) as typeof fetch });
    const dir = projectWith({ "package-lock.json": packageLock({ chalk: "5.3.0" }) });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    expect(await getRule("SUPPLY-001").check(model)).toEqual([]);
    const notice = await getRule("SUPPLY-011").check(model);
    expect(notice).toHaveLength(1);
    expect(notice[0].description).toContain("503");
  });

  it("SENTINEL_OFFLINE=1 skips the live check without touching the network and says so", async () => {
    const calls: Call[] = [];
    configureLiveVulnCheck({ fetch: fakeOsv(calls) });
    process.env.SENTINEL_OFFLINE = "1";
    try {
      const dir = projectWith({ "package-lock.json": packageLock({ lodash: "4.17.20" }) });
      const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
      expect((await getRule("SUPPLY-001").check(model)).length).toBe(1);
      const notice = await getRule("SUPPLY-011").check(model);
      expect(notice).toHaveLength(1);
      expect(notice[0].description).toContain("SENTINEL_OFFLINE");
      expect(calls).toHaveLength(0);
    } finally {
      delete process.env.SENTINEL_OFFLINE;
    }
  });
});
