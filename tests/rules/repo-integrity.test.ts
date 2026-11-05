import { describe, it, expect, afterEach } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import {
  repoIntegrityRules,
  resetRepoIntegrityCache,
} from "../../src/layers/rules/domains/repo-integrity.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";

// These rules exist because Sentinel v0.2.1 scanned github.com/jochi2018/Soup —
// an unattributed re-upload of MakazhanAlpamys/soup carrying a Lua-loader zip —
// and returned 0 critical. The source was genuinely clean; walkProject()'s
// extension allowlist meant the payload was never enumerated. Every assertion
// below is a property of that repo, or of a legitimate repo that must stay quiet.

const dirs: string[] = [];

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "repo-integrity-"));
  dirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

async function scan(dir: string) {
  resetRegistry();
  resetRepoIntegrityCache();
  registerRules(repoIntegrityRules);
  const model = await runRecon(dir, ["node_modules"]);
  return runRules(model);
}

const ids = (fs: Awaited<ReturnType<typeof scan>>) => fs.map((f) => f.ruleId);

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("repo-integrity — the trojan shape", () => {
  it("flags an undeclared committed archive (REPO-002)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "src/3.0.zip": "PK not really a zip, but the extension is the signal",
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-002");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
    expect(hit!.evidence[0].file).toBe("src/3.0.zip");
  });

  it("flags a README that links to an in-repo raw download (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "src/3.0.zip": "payload",
        "README.md":
          "# Download\n\n[![Download](https://img.shields.io/badge/x-y-green)](https://raw.githubusercontent.com/jochi2018/Soup/main/src/3.0.zip)\n",
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-003");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("critical");
  });

  // The trojan property REPO-003 actually exists to catch, now stated with a
  // remote present: the README of jochi2018/Soup points at jochi2018/Soup.
  it("flags a raw link when the remote says the link IS this repository (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config": '[remote "origin"]\n\turl = https://github.com/jochi2018/Soup.git\n',
        "src/3.0.zip": "payload",
        "README.md":
          "# Download\n\n[![Download](https://img.shields.io/badge/x-y-green)](https://raw.githubusercontent.com/jochi2018/Soup/main/src/3.0.zip)\n",
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-003");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("critical");
  });

  // Regression, 2026-09-04, found by self-scan. The raw-host branch asserted
  // "the link resolves into this repository" without ever checking whose repo
  // the URL named, so citing ANYONE else's raw file read as critical. The
  // relative-path branch had always proved presence before reporting; this is
  // the same standard applied to the branch that skipped it.
  it("does NOT flag a raw link into someone else's repository (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config":
          '[remote "origin"]\n\turl = https://github.com/gtsbahamas/shipsafe-web.git\n',
        "SECURITY.md":
          "We investigated [the payload](https://raw.githubusercontent.com/jochi2018/Soup/main/src/3.0.zip) and reported it.\n",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-003");
  });

  // Same owner is not the same repository.
  it("does NOT flag a raw link to a different repo under the same owner (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config": '[remote "origin"]\n\turl = git@github.com:acme/website.git\n',
        "README.md":
          "Grab [the installer](https://raw.githubusercontent.com/acme/installers/main/setup.exe).\n",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-003");
  });

  // With no remote to compare against, fall back to the evidence the relative
  // branch uses: is that exact path actually in this tree?
  it("does NOT flag a raw link whose path is absent, with no remote (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "README.md":
          "See [upstream's build](https://raw.githubusercontent.com/someone/else/main/dist/app.zip).\n",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-003");
  });

  // Inside a fence, `](url)` renders as literal text and cannot be clicked, so
  // it is documentation ABOUT a link. Security writing quotes hostile markdown
  // as evidence; the essay that surfaced this reproduces Soup's own badge.
  it("does NOT flag a raw link quoted inside a fenced code block (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config": '[remote "origin"]\n\turl = https://github.com/jochi2018/Soup.git\n',
        "src/3.0.zip": "payload",
        "essay.md": [
          "The whole attack is visible in one grep:",
          "",
          "```",
          "$ grep -rEi 'raw\\.githubusercontent' README.md",
          "README.md:[![Download Soup](https://img.shields.io/badge/x-y-green)](https://raw.githubusercontent.com/jochi2018/Soup/main/src/3.0.zip)",
          "```",
          "",
          "That is the entire thing.",
        ].join("\n"),
      }),
    );
    expect(ids(findings)).not.toContain("REPO-003");
  });

  it("flags a committed Windows executable as critical (REPO-001)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "util.exe": "MZ  fake PE header",
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-001");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("critical");
  });

  it("flags attribution that does not match the git remote (REPO-004)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config": '[remote "origin"]\n\turl = https://github.com/jochi2018/Soup.git\n',
        CODEOWNERS: "* @MakazhanAlpamys\n",
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-004");
    expect(hit).toBeDefined();
    expect(hit!.evidence[0].snippet).toContain("jochi2018");
  });

  it("flags a Lua-loader payload wearing a .txt extension (REPO-005)", async () => {
    // The real cert.txt: a string-shuffle deobfuscator over decimal escapes.
    const body =
      'local xI=function(k)local B=""for G=1,#k/2,1 do B=B..k[#k/2+k[G]]end return B end ' +
      'local AI={"\\116\\083\\112\\088"}' +
      "-".repeat(600);
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "cert.txt": body,
      }),
    );
    const hit = findings.find((f) => f.ruleId === "REPO-005");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("high");
  });
});

describe("repo-integrity — legitimate repositories stay quiet", () => {
  // shipsafe-web's own worker vendors shipsafe-sentinel-0.2.1.tgz via
  // `"shipsafe-sentinel": "file:./vendor/..."`. Declared means expected: this
  // must not fire, or the product flags itself on every scan.
  it("does NOT flag a tarball a manifest vendors via file: (REPO-002)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({
          name: "worker",
          version: "1.0.0",
          dependencies: { "shipsafe-sentinel": "file:./vendor/shipsafe-sentinel-0.2.1.tgz" },
        }),
        "vendor/shipsafe-sentinel-0.2.1.tgz": "tarball bytes",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-002");
  });

  // Regression: the first build reported `--output out.tar` in docs/commands.md
  // as a download link. Documentation names artifacts the tool PRODUCES; those
  // paths do not exist in the tree.
  it("does NOT flag docs naming an artifact the tool produces (REPO-003)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "docs/commands.md": "Run `soup export --output out.tar` to produce [out.tar](out.tar).\n",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-003");
  });

  it("does NOT flag CODEOWNERS that matches the remote (REPO-004)", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        ".git/config": '[remote "origin"]\n\turl = git@github.com:MakazhanAlpamys/soup.git\n',
        CODEOWNERS: "* @MakazhanAlpamys\n",
      }),
    );
    expect(ids(findings)).not.toContain("REPO-004");
  });

  it("is entirely silent on an ordinary source-only project", async () => {
    const findings = await scan(
      project({
        "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
        "README.md": "# App\n\nInstall with `npm install x`.\n",
        "src/index.ts": "export const hello = () => 'world';\n",
        "public/logo.png": "PNG fake",
      }),
    );
    expect(findings).toHaveLength(0);
  });
});
