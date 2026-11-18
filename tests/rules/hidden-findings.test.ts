// Real findings the guard recognition must not hide (independent re-read of PR #7, 2026-11-18).
//
// Every case here is vulnerable code written to look like something the new matchers accept: a guard
// that does not gate the write, a hash that is not the lookup, a check that is not validation. Each was
// reported before the recognition existed and has to stay reported. They live in the `atk` folders of the
// guard-semantics fixture, next to the guarded shapes that must stay quiet (false-positive-roots.test.ts).
import { describe, it, expect, beforeAll } from "vitest";
import { relative } from "path";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { inputInjectionRules } from "../../src/layers/rules/domains/input-injection.js";
import { cryptographyRules } from "../../src/layers/rules/domains/cryptography.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { Finding } from "../../src/model/types.js";
import { stagedFixture } from "./helpers.js";

const root = stagedFixture("guard-semantics");
let findings: Finding[] = [];

beforeAll(async () => {
  resetRegistry();
  registerRules([...authAccessControlRules, ...inputInjectionRules, ...cryptographyRules]);
  const model = await runRecon(root, ["node_modules"]);
  findings = await runRules(model);
});

/** Files (relative to the fixture) a rule reported. */
function files(ruleId: string): string[] {
  return [...new Set(findings.filter((f) => f.ruleId === ruleId).flatMap((f) => f.evidence.map((e) => relative(root, e.file))))].sort();
}

/** Lines of one file a rule reported. */
function lines(ruleId: string, file: string): number[] {
  return findings
    .filter((f) => f.ruleId === ruleId)
    .flatMap((f) => f.evidence)
    .filter((e) => relative(root, e.file) === file)
    .map((e) => e.line ?? 0)
    .sort((a, b) => a - b);
}

const atk = (p: string) => `src/app/api/atk/${p}/route.ts`;

describe("AUTH-001: a guard counts only when its answer gates the write", () => {
  const open: Array<[string, string]> = [
    ["a verification stored in an object while another field is tested", atk("a1-unrelated-if")],
    ["a write that runs before the guard, with both outcomes answered", atk("a2-success-return")],
    ["a write that runs before the guard is asked", atk("a5-write-first")],
    ["a helper that compares a constant with itself", atk("a7-self-compare")],
    ["a helper whose verification only picks a log label", atk("a8-soft-check")],
    ["a helper that throws for the signed-out, with the throw swallowed", atk("x1-swallowed-assert")],
    ["a helper that throws for the signed-out, called only behind a switch", atk("x2-branch-assert")],
    ["a guard tested the wrong way round, so the verified leave and the rest write", atk("p1-wrong-polarity")],
    ["a failed guard that only turns away when a second condition agrees", atk("p2-and-condition")],
    ["a failed guard whose leave sits behind a switch", atk("p3-nested-leave")],
    ["a guard that turns away only the signed-in and banned, never the signed-out", atk("p4-banned-only")],
  ];
  for (const [what, file] of open) {
    it(`still reports ${what}`, () => {
      expect(files("AUTH-001")).toContain(file);
    });
  }

  it("still reports a URL id hashed for a log line and then used raw", () => {
    expect(files("AUTH-001")).toContain(atk("records/[id]/purge"));
  });

  it("still reports a URL id hashed for a log line and then matched raw in a query builder", () => {
    expect(files("AUTH-001")).toContain(atk("records/[id]/match"));
  });
  it("still reports a URL id hashed for a log line and then written raw into a statement", () => {
    expect(files("AUTH-001")).toContain(atk("records/[id]/exec"));
  });

  it("still reports a limited route whose service-role client is built at the top of a helper's file", () => {
    expect(files("AUTH-001")).toContain(atk("a10-limited-module-admin"));
  });
  it("still reports a limited route that imports a service-role client and writes with it", () => {
    expect(files("AUTH-001")).toContain(atk("a11-limited-imported-admin"));
  });
  it("still reports a route that checks the shape of the address and limits nothing", () => {
    expect(files("AUTH-001")).toContain(atk("a12-ip-format"));
  });
});

describe("INPUT-005: reading the body is not checking it", () => {
  it("still reports a body that is only run through JSON.parse", () => {
    expect(files("INPUT-005")).toContain(atk("b1-json-parse"));
  });
  it("still reports a body that is only checked for being there at all", () => {
    expect(files("INPUT-005")).toContain(atk("b2-null-check"));
  });
  it("still reports a body whose only branch is a dry-run switch", () => {
    expect(files("INPUT-005")).toContain(atk("b3-dry-run"));
  });
  it("still reports a body with one picked value and another field in a tagged statement", () => {
    expect(files("INPUT-005")).toContain(atk("b4-pick-and-template"));
  });
  it("still reports a body with one picked value that is also handed whole to a constructor", () => {
    expect(files("INPUT-005")).toContain(atk("b5-pick-and-new"));
  });
  it("still reports a body whose only branch is a preview switch that returns nothing", () => {
    expect(files("INPUT-005")).toContain(atk("b6-preview-switch"));
  });
});

describe("CRYPTO-002: names written in camelCase and snake_case still say what is protected", () => {
  const file = "src/lib/atk/hashes.ts";
  it("still reports MD5 in makePasswordHash", () => expect(lines("CRYPTO-002", file)).toContain(3));
  it("still reports MD5 in hashPin", () => expect(lines("CRYPTO-002", file)).toContain(6));
  it("still reports SHA-1 in signPayload", () => expect(lines("CRYPTO-002", file)).toContain(9));
  it("still reports MD5 assigned to password_hash", () => expect(lines("CRYPTO-002", file)).toContain(12));
  it("still reports MD5 in hashPassword", () => expect(lines("CRYPTO-002", file)).toContain(16));
});

describe("CRYPTO-008: asking whether any candidate matches is a decision", () => {
  const file = "src/lib/atk/sigs.ts";
  it("still reports computed signatures compared with the one sent inside .some()", () => {
    expect(lines("CRYPTO-008", file)).toContain(4);
  });
  it("still reports the plain comparison", () => expect(lines("CRYPTO-008", file)).toContain(11));
  it("still reports a stored secret, not its hash, matched with the one sent inside .find()", () => {
    expect(lines("CRYPTO-008", "src/lib/atk/keys.ts")).toContain(4);
  });
  it("still reports a stored secret matched with the one sent inside a loop", () => {
    expect(lines("CRYPTO-008", "src/lib/atk/keys.ts")).toContain(7);
  });
});

describe("INPUT-001: only a value proven fixed is left out", () => {
  it("still reports a prop injected from a .js file with JSX", () => {
    expect(lines("INPUT-001", "src/components/atk/JsFile.js")).toContain(2);
  });
  it("still reports a prop that shares its name with a constant elsewhere in the file", () => {
    expect(lines("INPUT-001", "src/components/atk/Shadow2.tsx")).toContain(5);
  });
  it("still reports a prop handed over through a shorthand property", () => {
    expect(files("INPUT-001")).toContain("src/components/atk/Shorthand.tsx");
  });
  it("still reports a prop written inline", () => {
    expect(lines("INPUT-001", "src/components/atk/Plain.tsx")).toContain(2);
  });
  it("does not report a constant that nothing shadows", () => {
    expect(files("INPUT-001")).not.toContain("src/components/atk/Shadow.tsx");
  });
});

describe("INPUT-003: a test block inside a source file does not make the file test code", () => {
  it("still reports SQL built in a file that also carries in-source tests", () => {
    expect(lines("INPUT-003", "src/lib/atk/insource.ts")).toContain(3);
  });
  it("still reports the same SQL without the test block", () => {
    expect(lines("INPUT-003", "src/lib/atk/prod-sql.ts")).toContain(3);
  });
});
