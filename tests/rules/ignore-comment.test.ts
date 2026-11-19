import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { appendFileSync, cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { dirname, extname, join } from "path";
import { fileURLToPath } from "url";
import { registerRule, resetRegistry, runRulesWithIgnored } from "../../src/layers/rules/index.js";
import type { SecurityRule } from "../../src/layers/rules/registry.js";
import type { Finding } from "../../src/model/types.js";
import { emptyModel } from "./helpers.js";
import { findingKey, reconWithAllRules, sortKeys, type FindingKey } from "./support/all-rules.js";

// `// sentinel:ignore RULE-ID` is honoured for every rule through one path
// (src/layers/rules/ignore.ts), and an ignored finding is never dropped: it
// leaves the active list and is returned, counted, in `ignored`.

const here = dirname(fileURLToPath(import.meta.url));
const temps: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}
afterAll(() => {
  for (const d of temps) rmSync(d, { recursive: true, force: true });
});

/** A rule that always reports `file`, as rule `id`. */
function alwaysFires(id: string, file: string | null, opts: { omitRuleId?: boolean } = {}): SecurityRule {
  return {
    id,
    domain: "secrets-exposure",
    title: `${id} title`,
    description: "always fires",
    impact: "none",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: {},
    check: (): Finding[] => [
      {
        id: `${id}-finding`,
        domain: "secrets-exposure",
        severity: "high",
        confidence: "high",
        title: `${id} fired`,
        description: "fired",
        impact: "none",
        evidence: file === null ? [] : [{ file, line: 3 }],
        remediation: "none",
        references: [],
        layer: "rules",
        ...(opts.omitRuleId ? {} : { ruleId: id }),
      },
    ],
  };
}

function fileWith(contents: string, name = "route.ts"): string {
  const file = join(tempDir("sentinel-ignore-"), name);
  writeFileSync(file, contents);
  return file;
}

async function run(rules: SecurityRule[], root = "/tmp/none") {
  resetRegistry();
  for (const r of rules) registerRule(r);
  const base = emptyModel();
  return runRulesWithIgnored({ ...base, meta: { ...base.meta, path: root } });
}

describe("sentinel:ignore, one path for every rule", () => {
  it("without the comment the finding is active and nothing is ignored", async () => {
    const file = fileWith("export const a = 1;\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", file)]);
    expect(findings.map((f) => f.ruleId)).toEqual(["TEST-001"]);
    expect(ignored).toEqual([]);
  });

  it("with the comment the finding moves to `ignored`, with where the comment is", async () => {
    const file = fileWith("export const a = 1;\n// sentinel:ignore TEST-001 reviewed, public on purpose\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", file)]);
    expect(findings).toEqual([]);
    expect(ignored).toHaveLength(1);
    expect(ignored[0].ruleId).toBe("TEST-001");
    expect(ignored[0].file).toBe(file);
    expect(ignored[0].line).toBe(2);
    expect(ignored[0].finding.title).toBe("TEST-001 fired");
    expect(ignored[0].finding.severity).toBe("high");
  });

  it("works for a rule id no rule file ever named (nothing is per-rule)", async () => {
    const file = fileWith("# sentinel:ignore BRAND-NEW-042\n", "settings.py");
    const { findings, ignored } = await run([alwaysFires("BRAND-NEW-042", file)]);
    expect(findings).toEqual([]);
    expect(ignored.map((i) => i.ruleId)).toEqual(["BRAND-NEW-042"]);
  });

  it("a comment for one rule leaves every other rule's finding active", async () => {
    const file = fileWith("// sentinel:ignore TEST-001\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", file), alwaysFires("TEST-002", file)]);
    expect(findings.map((f) => f.ruleId)).toEqual(["TEST-002"]);
    expect(ignored.map((i) => i.ruleId)).toEqual(["TEST-001"]);
  });

  it("matches the whole rule id, never a prefix or a longer id", async () => {
    const file = fileWith("// sentinel:ignore TEST-0011\n// sentinel:ignore TEST-00\n// sentinel:ignore XTEST-001\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", file)]);
    expect(findings).toHaveLength(1);
    expect(ignored).toEqual([]);
  });

  it("one comment can name several rules", async () => {
    const file = fileWith("// sentinel:ignore TEST-001 TEST-002, TEST-003 — all three reviewed\n");
    const { findings, ignored } = await run([
      alwaysFires("TEST-001", file),
      alwaysFires("TEST-002", file),
      alwaysFires("TEST-003", file),
      alwaysFires("TEST-004", file),
    ]);
    expect(findings.map((f) => f.ruleId)).toEqual(["TEST-004"]);
    expect(ignored.map((i) => i.ruleId).sort()).toEqual(["TEST-001", "TEST-002", "TEST-003"]);
  });

  it("punctuation straight after the id still names that id", async () => {
    const file = fileWith("// sentinel:ignore TEST-001: public\n/* sentinel:ignore TEST-002*/\n// sentinel:ignore TEST-003—reviewed\n");
    const { findings, ignored } = await run([
      alwaysFires("TEST-001", file),
      alwaysFires("TEST-002", file),
      alwaysFires("TEST-003", file),
    ]);
    expect(findings).toEqual([]);
    expect(ignored.map((i) => i.line)).toEqual([1, 2, 3]);
  });

  it("words after the rule ids are a reason, not more rule ids", async () => {
    const file = fileWith("// sentinel:ignore TEST-001 because TEST-002 is handled elsewhere\n");
    const { findings } = await run([alwaysFires("TEST-001", file), alwaysFires("TEST-002", file)]);
    expect(findings.map((f) => f.ruleId)).toEqual(["TEST-002"]);
  });

  it("only the file the finding points at counts", async () => {
    const flagged = fileWith("export const a = 1;\n");
    fileWith("// sentinel:ignore TEST-001\n", "other.ts");
    const { findings, ignored } = await run([alwaysFires("TEST-001", flagged)]);
    expect(findings).toHaveLength(1);
    expect(ignored).toEqual([]);
  });

  it("a project-relative evidence path is read from the project root", async () => {
    const root = tempDir("sentinel-ignore-root-");
    writeFileSync(join(root, "app.ts"), "// sentinel:ignore TEST-001\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", "app.ts")], root);
    expect(findings).toEqual([]);
    expect(ignored).toHaveLength(1);
  });

  it("a finding with no file, or a file that cannot be read, stays active", async () => {
    const { findings, ignored } = await run([
      alwaysFires("TEST-001", null),
      alwaysFires("TEST-002", "/nonexistent/sentinel/route.ts"),
    ]);
    expect(findings.map((f) => f.ruleId).sort()).toEqual(["TEST-001", "TEST-002"]);
    expect(ignored).toEqual([]);
  });

  it("a finding that carries no ruleId is matched by the rule that produced it", async () => {
    const file = fileWith("// sentinel:ignore TEST-001\n");
    const { findings, ignored } = await run([alwaysFires("TEST-001", file, { omitRuleId: true })]);
    expect(findings).toEqual([]);
    expect(ignored.map((i) => i.ruleId)).toEqual(["TEST-001"]);
  });
});

// Every finding the repo's own fixtures produce, for every rule that fires on
// them: add the comment to the file the finding points at and exactly that
// rule's findings in that file move to `ignored`. Nothing else moves, and
// active + ignored always equals what fired without the comment.
describe("sentinel:ignore on the repo's fixtures, rule by rule", () => {
  const baseline = JSON.parse(readFileSync(join(here, "fixture-baseline.json"), "utf-8")) as Record<string, FindingKey[]>;
  const fixtures = readdirSync(join(here, "..", "fixtures"), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  let offlineBefore: string | undefined;
  beforeAll(() => {
    offlineBefore = process.env.SENTINEL_OFFLINE;
    process.env.SENTINEL_OFFLINE = "1";
  });
  afterAll(() => {
    if (offlineBefore === undefined) delete process.env.SENTINEL_OFFLINE;
    else process.env.SENTINEL_OFFLINE = offlineBefore;
  });

  // File types that have a line-comment syntax the scanner's own fixtures use.
  const COMMENT: Record<string, string> = {
    ".ts": "//", ".tsx": "//", ".js": "//", ".jsx": "//", ".mjs": "//", ".cjs": "//",
    ".py": "#", ".toml": "#", ".yml": "#", ".yaml": "#", ".sql": "--", "": "#",
  };

  const covered = new Set<string>();
  const notCommentable = new Set<string>();

  for (const name of fixtures) {
    const pairs = new Map<string, { ruleId: string; file: string }>();
    for (const k of baseline[name] ?? []) pairs.set(`${k.ruleId}\u0000${k.file}`, { ruleId: k.ruleId, file: k.file });
    if (pairs.size === 0) continue;

    it(`${name}: each rule's finding moves to ignored, and only that one`, async () => {
      for (const { ruleId, file } of pairs.values()) {
        const prefix = COMMENT[extname(file)];
        const dir = tempDir(`sentinel-ignore-fx-${name}-`);
        cpSync(join(here, "..", "fixtures", name), dir, { recursive: true });
        const target = join(dir, file);
        if (!file || prefix === undefined || !existsSync(target)) {
          notCommentable.add(ruleId);
          continue;
        }
        appendFileSync(target, `\n${prefix} sentinel:ignore ${ruleId}\n`);

        const { model, root } = await reconWithAllRules(dir);
        const result = await runRulesWithIgnored(model, null);
        const active = sortKeys(result.findings.map((f) => findingKey(f, root)));
        const ignored = sortKeys(result.ignored.map((i) => findingKey(i.finding, root)));

        const isTarget = (k: FindingKey) => k.ruleId === ruleId && k.file === file;
        expect(ignored, `${ruleId} in ${file}: ignored`).toEqual(baseline[name].filter(isTarget));
        expect(active, `${ruleId} in ${file}: still active`).toEqual(baseline[name].filter((k) => !isTarget(k)));
        expect(result.ignored.every((i) => i.ruleId === ruleId && i.file === join(root, file))).toBe(true);
        covered.add(ruleId);
        rmSync(dir, { recursive: true, force: true });
      }
    }, 120_000);
  }

  it("covers most rules the fixtures exercise, and says which it cannot", () => {
    const fired = new Set(Object.values(baseline).flat().map((k) => k.ruleId));
    // Rules whose only evidence is a file with no comment syntax (package.json,
    // a lockfile, a directory) cannot carry the comment at all.
    const uncovered = [...fired].filter((id) => !covered.has(id)).sort();
    expect(uncovered).toEqual([...notCommentable].filter((id) => !covered.has(id)).sort());
    expect(covered.size).toBeGreaterThanOrEqual(40);
  });
});
