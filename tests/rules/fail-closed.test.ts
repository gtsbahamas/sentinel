// Silencing fails closed (third independent re-read of PR #7, 2026-11-18).
//
// A finding is left out only when the code matches a small set of shapes that can be proven safe. Anything
// the analysis cannot prove stays reported, as it was before the guard recognition existed. The `rr`
// folders of the guard-semantics fixture hold the re-read's attack (22 open handlers, 12 guarded twins,
// 15 comparisons); the `fc` folders hold further variants of the same idea.
import { describe, it, expect, beforeAll } from "vitest";
import { relative } from "path";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { cryptographyRules } from "../../src/layers/rules/domains/cryptography.js";
import { handlerGuard } from "../../src/layers/rules/handler-analysis.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";
import { stagedFixture } from "./helpers.js";

const root = stagedFixture("guard-semantics");
let findings: Finding[] = [];
let model: ProjectModel;

beforeAll(async () => {
  resetRegistry();
  registerRules([...authAccessControlRules, ...cryptographyRules]);
  model = await runRecon(root, ["node_modules"]);
  findings = await runRules(model);
});

function files(ruleId: string): string[] {
  return [...new Set(findings.filter((f) => f.ruleId === ruleId).flatMap((f) => f.evidence.map((e) => relative(root, e.file))))].sort();
}

function lines(ruleId: string, file: string): number[] {
  return findings
    .filter((f) => f.ruleId === ruleId)
    .flatMap((f) => f.evidence)
    .filter((e) => relative(root, e.file) === file)
    .map((e) => e.line ?? 0)
    .sort((a, b) => a - b);
}

const rr = (p: string) => `src/app/api/rr/${p}/route.ts`;
const fc = (p: string) => `src/app/api/fc/${p}/route.ts`;
const api = (p: string) => `src/app/api/${p}/route.ts`;

describe("AUTH-001: a handler the analysis cannot prove guarded stays reported", () => {
  const open: Array<[string, string]> = [
    // the re-read's 22
    ["the verified leave early and everyone else reaches a kept write", rr("v01-polarity-kept")],
    ["the verified leave early and the write sits in the answer", rr("v01b-polarity-returned")],
    ["the verified leave early and everyone else reaches an outward call", rr("v01c-polarity-fetch")],
    ["the verified leave early and everyone else reaches a query-builder insert", rr("v01d-polarity-drizzle")],
    ["a guard behind an unrelated condition", rr("v03-nested-unrelated")],
    ["a guard in an else-if", rr("v03b-else-if")],
    ["the handler's own throw swallowed by its catch", rr("v04-swallowed-throw")],
    ["a failed check that leaves through a helper that writes", rr("v05-leave-does-work")],
    ["a failed check whose branch writes before it leaves", rr("v05b-leave-does-work-inline")],
    ["=== false asked of a helper that answers null", rr("v06-false-vs-null")],
    ["a field that is set when the check FAILED, behind an `in` test", rr("v07-field-polarity")],
    ["a field that is set when the check FAILED (!t.res)", rr("v07b-field-polarity")],
    ["leaving when there is no error (!s.error)", rr("v08-not-error")],
    ["a branch that writes and leaves before the guard", rr("v11-bypass-before")],
    ["the answer joined with a debug header through || in a variable", rr("v14-or-in-variable")],
    ["the answer replaced by true through ?: in a variable", rr("v14b-ternary-in-variable")],
    ["a missing member replaced by a stand-in through ??", rr("v14c-fallback-user")],
    ["the member joined with a preview header through ||", rr("v14d-dev-bypass")],
    ["the member handed to a helper that also accepts a header", rr("v15-call-argument")],
    ["a helper that leaves for the signed-IN (if (data.user) return { ok: false })", rr("v16-known-helper-hole")],
    ["a failed check that leaves on one path only", rr("v17-not-every-path")],
    ["a failed check that only decides together with a header", rr("v18-or-with-and")],
    // further variants
    ["a session read that is not awaited", fc("w01-unawaited")],
    ["a session read whose own failure is swallowed by a catch", fc("w02-read-throws-swallowed")],
    ["a member variable that is reassigned before the test", fc("w03-reassigned")],
    ["a write before the guard whose answer is kept", fc("w04-kept-write-first")],
    ["a helper that writes before it verifies", fc("w05-helper-writes-first")],
    ["a guard whose failure is answered ok by .catch()", fc("w06-catch-default")],
    ["a test of the whole answer object, which is never empty", fc("w07-whole-object")],
    ["=== undefined asked of a helper that answers null", fc("w08-undefined-vs-null")],
    ["!== false asked of a helper that answers null", fc("w09-not-false-on-null")],
    ["a helper whose field is true for the signed-out, through ?:", fc("w10-helper-ternary-polarity")],
    ["an error field that is empty whether or not anyone is signed in", fc("w11-error-always-empty")],
    ["a helper that throws for the signed-out, called without await", fc("w12-assert-not-awaited")],
    ["the write in the else of a positive test", fc("w13-work-in-else")],
    ["a guard written in a function that is never called", fc("w14-guard-never-called")],
    ["a sealed value replaced by true when no key is set", fc("w15-ternary-true")],
    ["a guard inside a loop that may not run", fc("w16-guard-in-empty-loop")],
    ["a limited form that stores before the limiter is asked", fc("w17-limited-write-first")],
    ["a limiter helper that stores before it counts", fc("w18-limited-late-helper")],
    ["a link route that stores what was sent before the link is looked at", "src/app/api/fc/links/[token]/w19-write-first/route.ts"],
  ];
  for (const [what, file] of open) {
    it(`still reports ${what}`, () => {
      expect(files("AUTH-001")).toContain(file);
    });
  }

  const guarded: Array<[string, string]> = [
    ["t.ok !== true", rr("s01-not-true")],
    ["!(who && who.id)", rr("s02-not-and")],
    ["if (who) { work; return } else { return 401 }", rr("s03-inside-else")],
    ["a refusing block that logs first", rr("s04-block-log")],
    ["who == null", rr("s05-eq-null")],
    ["t.ok === false where the helper answers false", rr("s06-eq-false")],
    ["!who?.id", rr("s08-optional-id")],
    ["if (!t.ok) return; else { work }", rr("s09-else-work")],
    ["if (t.ok) {} else return", rr("s10-positive-else-refuse")],
    ["the guard and the work inside a try whose catch answers 500", rr("s14-in-try")],
    ["!who || who.role !== admin", rr("s15-or-role")],
    ["who === null || who === undefined", rr("s16-typeof")],
    ["an error field that holds a refusal for everyone not signed in", fc("q01-error-field")],
    ["t.ok !== false where the helper answers false", fc("q03-not-false-on-boolean")],
    ["a guard at the top of the only branch that works", fc("q04-guard-in-branch")],
  ];
  for (const [what, file] of guarded) {
    it(`does not report ${what}`, () => {
      expect(files("AUTH-001")).not.toContain(file);
    });
  }

  // Every mutation handler in the fixture the guard recognition accepts, asked directly (the rule's older,
  // name-based exemptions are not in play here). A handler that newly appears in this list is a new silence
  // and has to be argued for; one that drops out is a false positive coming back.
  it("accepts exactly the handlers proven guarded, and no other", () => {
    const accepted = model.endpoints
      .filter((e) => ["POST", "PUT", "PATCH", "DELETE"].includes(e.method) && handlerGuard(model, e) !== null)
      .map((e) => relative(root, e.file));
    expect([...new Set(accepted)].sort()).toEqual(
      [
        fc("q01-error-field"),
        fc("q02-inline-chain"),
        fc("q03-not-false-on-boolean"),
        fc("q04-guard-in-branch"),
        api("forms/begin"),
        api("forms/enlist"),
        api("links/[token]/back"),
        api("links/[token]/keys"),
        api("links/[token]/remove"),
        api("member/desk"),
        api("member/either"),
        api("member/inside"),
        api("member/note"),
        api("member/policy"),
        api("member/thrown"),
        api("payment-events"),
        api("plan/resume"),
        api("provider-call"),
        rr("s01-not-true"),
        rr("s02-not-and"),
        rr("s03-inside-else"),
        rr("s04-block-log"),
        rr("s05-eq-null"),
        rr("s06-eq-false"),
        rr("s08-optional-id"),
        rr("s09-else-work"),
        rr("s10-positive-else-refuse"),
        rr("s14-in-try"),
        rr("s15-or-role"),
        rr("s16-typeof"),
        api("worker/beat"),
      ].sort(),
    );
  });
});

describe("CRYPTO-008: a comparison is a lookup only when the other side is proven to be a hash", () => {
  const attack = "src/lib/rr/crypto.ts";
  const flagged: Array<[string, string, number]> = [
    ["a stored secret matched with the one sent in find()", attack, 6],
    ["the same in some()", attack, 9],
    ["the same in filter()", attack, 12],
    ["a sent signature matched with the computed HMAC in a loop", attack, 17],
    ["a sent signature matched with the computed HMAC in find()", attack, 23],
    ["a field merely named like a hash matched with the value sent", attack, 27],
    ["a secret read from a header named x-digest-token", attack, 31],
    ["a row variable named hashRow", attack, 34],
    ["an id match beside a raw secret match", attack, 38],
    ["rows made from what was sent, matched with a hash of the body", "src/lib/fc/crypto.ts", 9],
    ["a keyed MAC of the value sent", "src/lib/fc/crypto.ts", 13],
    ["a variable merely named digest", "src/lib/fc/crypto.ts", 18],
    ["a helper merely named hashOf", "src/lib/fc/crypto.ts", 22],
    ["a hash that mixes in a server secret", "src/lib/fc/crypto.ts", 27],
    ["a key parameter that one caller fills with the token itself", "src/lib/fc/store.ts", 10],
    ["a key parameter nothing in the project is seen to fill (session)", "src/lib/store/memory.ts", 10],
    ["a key parameter nothing in the project is seen to fill (log)", "src/lib/store/memory.ts", 15],
    ["a key parameter nothing in the project is seen to fill (delete)", "src/lib/store/memory.ts", 20],
  ];
  for (const [what, file, line] of flagged) {
    it(`still reports ${what}`, () => {
      expect(lines("CRYPTO-008", file)).toContain(line);
    });
  }

  const quiet: Array<[string, string, number]> = [
    ["a stored hash matched with a hash helper's answer", attack, 45],
    ["a stored hash matched with a constant set from a hash helper", attack, 49],
    ["a stored key matched with an inline SHA-256 of the value sent", attack, 54],
    ["a key parameter every caller fills with a hash", "src/lib/fc/store.ts", 6],
  ];
  for (const [what, file, line] of quiet) {
    it(`does not report ${what}`, () => {
      expect(lines("CRYPTO-008", file)).not.toContain(line);
    });
  }
});
