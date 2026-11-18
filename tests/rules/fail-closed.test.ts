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
const zz = (p: string) => `src/app/api/zz/${p}/route.ts`;
const yy = (p: string) => `src/app/api/yy/${p}/route.ts`;
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
    // names prove nothing: the project's own code is read, whatever it is called
    ["the project's own function called timingSafeEqual", fc("x02-own-timing-safe-equal")],
    ["a write before the guard through an import renamed to log", fc("x03-ledger-named-log")],
    ["a write before the guard handed to .then() by name", fc("x04-then-by-name")],
    ["a guard's answer overwritten with Object.assign before the test", fc("x05-answer-rewritten")],
    // found by attacking the proof itself (second attack, same day)
    ["a thrower that is only the default of a destructured field", zz("a01-destructure-default")],
    ["a thrower behind ??=", zz("a02-nullish-assign")],
    ["a thrower in the argument of an optional call", zz("a03-optional-chain-arg")],
    ["a generator that would throw, called and never run", zz("a04-generator-throws")],
    ["a generator's answer, which is always an object", zz("a05-generator-answer")],
    ["a var declared a second time with what was sent", zz("a06-var-redeclared")],
    ["a var declared again inside a branch", zz("a07-var-hoisted-from-block")],
    ["a local function that is pointed at a write before the guard", zz("a08-let-fn-reassigned")],
    ["an exported let that is pointed at a function that admits everyone", zz("a09-module-let-reassigned")],
    ["a method picked from two objects, one of which admits everyone", zz("a10-method-by-reference")],
    ["an object whose method is a function passed by name", zz("a10b-loose-direct")],
    ["a local that shares the name of an inert import and writes", zz("a12-shadowed-import")],
    ["jsonwebtoken verify with a callback passed by name", zz("a13-jwt-callback-by-name")],
    ["a constant-time compare of two values that both came with the request", zz("a14-both-sides-sent")],
    ["a constant-time compare with an unkeyed checksum of the body", zz("a15-unkeyed-checksum")],
    ["a compare helper handed the same value twice", zz("a16-self-compare-in-helper")],
    ["the project's own parse() that writes, before the guard", zz("a17-own-parse-writes")],
    ["the project's own join() that writes, before the guard", zz("a18-own-join-writes")],
    ["a package store's replace(), before the guard", zz("a19-package-replace")],
    ["a getter that writes, read before the guard", zz("a21-getter-writes")],
    ["an error class whose constructor writes, built in the refusal", zz("a22-error-constructor-writes")],
    ["a thrown class whose constructor writes", zz("a23-thrown-constructor-writes")],
    ["a helper whose default argument writes", zz("a24-helper-default-argument")],
    ["a module's keys answered to everyone after a decorative check", zz("a25-leak-for-everyone")],
    ["a module value assigned through a for-of target", zz("a26-for-of-module-write")],
    ["a computed key that overrides the proven field", zz("a29-computed-key-override")],
    ["an address blocklist taken for a visitor limit", zz("a32-visitor-blocklist")],
    ["an address length check taken for a visitor limit", zz("a33-visitor-length-check")],
    ["a write before the guard through an unresolved import named log", zz("a44-subpath-import-log")],
    ["a write before the guard through an imported console", zz("a45-own-console")],
    ["a local write function that shares its name with an inert one in another scope", zz("a50-same-name-other-scope")],
    ["a signature checked with a key that came with the request", zz("a78-key-sent-with-request")],
    ["a proven field overwritten through a for-of target", zz("a79-truthy-then-override")],
    ["a link token that is hashed and stored, with nothing looked up", zz("l/[token]/a30-link-hash-no-lookup")],
  ];
  // Found by a second attack on the proof (41 more). After it the general proof was given up for a short
  // list of shapes; these are named by their folder, which says what each one does.
  const third = [
    "l/[token]/y32-hash-stored-answer-kept",
    "l/[token]/y34-hash-sent-outward",
    "y03-shipped-key",
    "y04-unset-means-echo",
    "y05-common-prefix",
    "y06-neither-side-sent",
    "y07-secret-in-same-object",
    "y08-rest-values",
    "y09-caller-brings-key",
    "y10-method-by-name",
    "y11-subclass-override",
    "y12-constructor-swaps-method",
    "y14z-holder-guest",
    "y15z-sink-disk",
    "y18-module-value-through-local",
    "y19-module-value-through-helper",
    "y20-mint-for-anyone",
    "y21-env-answered",
    "y22-array-from-by-name",
    "y23-replace-by-name",
    "y24-reviver-by-name",
    "y25-getter-by-destructuring",
    "y26-to-string-in-template",
    "y27-thenable-awaited",
    "y28-package-named-log",
    "y29-write-taken-for-count",
    "y30-limiter-answer-ignored",
    "y31-limiter-never-read",
    "y33-raw-bearer",
    "y35-patched-elsewhere",
    "y36-client-patched",
    "y40-switch-shadow",
    "y43-to-json",
    "y48-local-named-cookies",
  ];
  for (const name of third) open.push([`(third attack) ${name}`, yy(name)]);
  // Guards the short list cannot prove: reported again. A constant-time compare, a sealed value, a link
  // token and a visitor limit all need facts about values (which side is the server's secret, what is a
  // lookup, what is a count) that both attacks showed this analysis gets wrong.
  const unprovable: Array<[string, string]> = [
    ["a MAC compared in a helper, t.ok !== true", rr("s01-not-true")],
    ["a MAC compared in a helper, t.ok === false", rr("s06-eq-false")],
    ["a MAC compared in a helper, work in the else", rr("s09-else-work")],
    ["a MAC compared in a helper, if (t.ok) {} else return", rr("s10-positive-else-refuse")],
    ["a MAC compared in a helper, t.ok !== false", fc("q03-not-false-on-boolean")],
    ["a MAC compared in a helper, at the top of the only branch that works", fc("q04-guard-in-branch")],
    ["a session read beside a body read with .catch()", zz("s4-safe-early-return-value")],
  ];
  for (const [what, file] of unprovable) open.push([`(guarded, not provable) ${what}`, file]);
  for (const [what, file] of open) {
    it(`still reports ${what}`, () => {
      expect(files("AUTH-001")).toContain(file);
    });
  }

  const guarded: Array<[string, string]> = [
    ["!(who && who.id)", rr("s02-not-and")],
    ["if (who) { work; return } else { return 401 }", rr("s03-inside-else")],
    ["a refusing block that logs first", rr("s04-block-log")],
    ["who == null", rr("s05-eq-null")],
    ["!who?.id", rr("s08-optional-id")],
    ["the guard and the work inside a try whose catch answers 500", rr("s14-in-try")],
    ["!who || who.role !== admin", rr("s15-or-role")],
    ["who === null || who === undefined", rr("s16-typeof")],
    ["an error field that holds a refusal for everyone not signed in", fc("q01-error-field")],
  ];
  for (const [what, file] of guarded) {
    it(`does not report ${what}`, () => {
      expect(files("AUTH-001")).not.toContain(file);
    });
  }

  // The rule's older, name-based exemption already leaves this file out (it sees `auth.getUser(`), so the
  // recognition is asked directly: the project's own object with an `auth.getUser` is not a session read.
  it("does not accept the project's own object with an auth.getUser that answers anyone", () => {
    const own = model.endpoints.filter((e) => relative(root, e.file) === fc("x01-own-get-user"));
    expect(own.length).toBeGreaterThan(0);
    for (const e of own) expect(handlerGuard(model, e)).toBeNull();
  });

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
        api("member/desk"),
        api("member/either"),
        api("member/inside"),
        api("member/note"),
        api("member/policy"),
        api("member/thrown"),
        rr("s02-not-and"),
        rr("s03-inside-else"),
        rr("s04-block-log"),
        rr("s05-eq-null"),
        rr("s08-optional-id"),
        rr("s14-in-try"),
        rr("s15-or-role"),
        rr("s16-typeof"),
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
    ["the project's own createHash, which hashes nothing", "src/lib/fc/crypto.ts", 32],
    ["a key parameter that one caller fills with the token itself", "src/lib/fc/store.ts", 10],
    ["a key parameter nothing in the project is seen to fill (session)", "src/lib/store/memory.ts", 10],
    ["a key parameter nothing in the project is seen to fill (log)", "src/lib/store/memory.ts", 15],
    ["a key parameter nothing in the project is seen to fill (delete)", "src/lib/store/memory.ts", 20],
    ["a server secret hashed and matched with rows the caller sent", "src/lib/zz/c01.ts", 7],
    ["a hash over a secret joined to the body, through a const", "src/lib/zz/c02.ts", 9],
    ["a key parameter overwritten with the raw value", "src/lib/zz/c03.ts", 8],
    ["a raw caller that imports the lookup under another name", "src/lib/zz/c04.ts", 7],
    ["the lookup handed to map() over raw values", "src/lib/zz/c05.ts", 7],
    ["a var declared again with the raw value", "src/lib/zz/c06.ts", 9],
    ["a hash helper that is pointed at the identity", "src/lib/zz/c07.ts", 7],
    ["a raw caller that pulls the method out of its object", "src/lib/zz/c08.ts", 8],
    ["a server secret hashed and matched with rows read from the request", "src/lib/zz/c09.ts", 8],
    ["a second comparison of two secrets on the same line", "src/lib/zz/c10.ts", 7],
    ["a local that shadows the hash helper", "src/lib/zz/c11.ts", 8],
    ["a raw caller through .call()", "src/lib/zz/c12.ts", 7],
  ];
  for (const [what, file, line] of flagged) {
    it(`still reports ${what}`, () => {
      expect(lines("CRYPTO-008", file)).toContain(line);
    });
  }

  // The lookup exemption is gone: the shape it was written for is a hash in name only, and two attacks
  // found a dozen ways to make a real secret comparison look like a lookup. These are correct code and are
  // reported; the cost is a finding to dismiss, not a comparison that leaks.
  const lookups: Array<[string, string, number]> = [
    ["a stored hash matched with a hash helper's answer", attack, 45],
    ["a stored hash matched with a constant set from a hash helper", attack, 49],
    ["a stored key matched with an inline SHA-256 of the value sent", attack, 54],
    ["a key parameter every caller fills with a hash", "src/lib/fc/store.ts", 6],
  ];
  for (const [what, file, line] of lookups) {
    it(`reports, as before the exemption existed, ${what}`, () => {
      expect(lines("CRYPTO-008", file)).toContain(line);
    });
  }
  const third: Array<[string, number]> = [["k01", 8], ["k02", 9], ["k03", 8], ["k04", 7], ["k05", 9], ["k06", 10], ["k07", 8], ["k08", 3], ["k09", 8], ["k11", 10]];
  for (const [file, line] of third) {
    it(`still reports (third attack) ${file}:${line}`, () => {
      expect(lines("CRYPTO-008", `src/lib/yy/${file}.ts`)).toContain(line);
    });
  }
});
