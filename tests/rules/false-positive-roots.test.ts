// False positives fixed at their root (Seatrial triage of CallSitter and IslandFlow, 2026-11-18).
//
// Each case is a pair: code that IS guarded, in a shape the matcher used to miss, which must not be
// reported; and a twin that looks the same and is NOT guarded, which must still be reported. The fixture's
// helper names are deliberately plain (providerCall, deskAccess, enlist): nothing passes by its name.
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
function reported(ruleId: string): string[] {
  const files = findings
    .filter((f) => f.ruleId === ruleId)
    .flatMap((f) => f.evidence.map((e) => relative(root, e.file)));
  return [...new Set(files)].sort();
}

const api = (p: string) => `src/app/api/${p}/route.ts`;

describe("AUTH-001 follows the guard out of the route file", () => {
  const guarded: Array<[string, string]> = [
    ["a MAC check three hops away, result gates the handler", api("provider-call")],
    ["a MAC check directly in the if, extensionless import", api("payment-events")],
    ["the same guard through a path alias", api("worker/beat")],
    ["a value only this server could have sealed (AES-GCM)", api("plan/resume")],
    ["sign-in read in a helper, 401 without it", api("member/note")],
    ["sign-in read two helpers away", api("member/desk")],
    ["a helper that throws when nobody is signed in", api("member/policy")],
    ["a link token found by its hash", api("links/[token]/remove")],
    ["a link token hashed inside a method on an object", api("links/[token]/keys")],
    ["a public form limited per visitor", api("forms/enlist")],
    ["a public start limited per visitor inside a method", api("forms/begin")],
  ];
  for (const [what, file] of guarded) {
    it(`does not report ${what}`, () => {
      expect(reported("AUTH-001")).not.toContain(file);
    });
  }

  const unguarded: Array<[string, string]> = [
    ["a helper that parses and verifies nothing", api("twins/parsed-call")],
    ["a real guard whose answer is ignored", api("twins/ignored-result")],
    ["a MAC that is computed and never compared", api("twins/mac-only")],
    ["a helper that throws for an unrelated reason", api("twins/plain-context")],
    ["a record removed by a guessable id", api("twins/records/[id]/remove")],
    ["a URL token that is never used to find anything", api("twins/links/[token]/wipe")],
    ["a public form that reads the address and limits nothing", api("twins/forms/unlimited")],
    ["a rate-limited route that writes with the service role", api("twins/forms/limited-admin")],
    ["a rate-limited route whose privileged client comes from a helper", api("twins/forms/limited-admin-helper")],
    ["a rate-limited route whose privileged write is inside a helper", api("twins/forms/limited-write-helper")],
    ["a write with nothing in front of it", api("twins/open-write")],
    ["a guard in a package the scanner cannot read", api("twins/outside-helper")],
  ];
  for (const [what, file] of unguarded) {
    it(`still reports ${what}`, () => {
      expect(reported("AUTH-001")).toContain(file);
    });
  }
});

describe("INPUT-005 follows the body into the function that checks it", () => {
  it("does not report a body checked by the helper it is passed to", () => {
    expect(reported("INPUT-005")).not.toContain(api("forms/enlist"));
  });
  it("does not report a body checked inside a method on an object", () => {
    expect(reported("INPUT-005")).not.toContain(api("links/[token]/keys"));
    expect(reported("INPUT-005")).not.toContain(api("forms/begin"));
  });
  it("still reports a body handed to a helper that stores it unchecked", () => {
    expect(reported("INPUT-005")).toContain(api("twins/forms/unlimited"));
  });
  it("still reports a stored body when another variable of the same name is checked", () => {
    expect(reported("INPUT-005")).toContain(api("twins/same-name"));
  });
  it("still reports a body the helper only branches on", () => {
    expect(reported("INPUT-005")).toContain(api("twins/forms/branching"));
    expect(reported("AUTH-001")).toContain(api("twins/forms/branching"));
  });
  it("still reports a helper that only notices when the store itself fails", () => {
    expect(reported("INPUT-005")).toContain(api("twins/store-error"));
  });
  it("still reports a body written straight to storage", () => {
    expect(reported("INPUT-005")).toContain(api("twins/open-write"));
  });
});

describe("INPUT-001 looks at what is injected", () => {
  it("does not report fixed strings, local or imported", () => {
    expect(reported("INPUT-001")).not.toContain("src/app/layout.tsx");
  });
  it("still reports a prop injected as HTML", () => {
    expect(reported("INPUT-001")).toContain("src/components/RawNote.tsx");
  });
  it("still reports a template with an outside value in it", () => {
    expect(reported("INPUT-001")).toContain("src/components/Greeting.tsx");
  });
});

describe("INPUT-003 is about code a visitor can reach", () => {
  it("does not report SQL built inside test code", () => {
    expect(reported("INPUT-003")).not.toContain("test/db/roles.test.ts");
  });
  it("still reports the same SQL in code that ships", () => {
    expect(reported("INPUT-003")).toContain("src/lib/reports.ts");
  });
});

describe("CRYPTO-008 tells a lookup from a verification", () => {
  it("does not report finding a stored row by its key", () => {
    expect(reported("CRYPTO-008")).not.toContain("src/lib/store/memory.ts");
  });
  it("still reports a MAC decided with ===, alone or inside a loop", () => {
    const lines = findings
      .filter((f) => f.ruleId === "CRYPTO-008" && f.evidence[0].file.endsWith("check-mac.ts"))
      .map((f) => f.evidence[0].line);
    expect(lines).toContain(3);
    expect(lines).toContain(9);
  });
});

describe("CRYPTO-002 needs something being protected", () => {
  it("does not report MD5 as a change-detection checksum", () => {
    expect(reported("CRYPTO-002")).not.toContain("src/lib/profile.ts");
  });
  it("still reports MD5 over a password", () => {
    expect(reported("CRYPTO-002")).toContain("src/lib/legacy-login.ts");
  });
  it("still reports a general MD5 helper that a password is passed to", () => {
    expect(reported("CRYPTO-002")).toContain("src/lib/digests.ts");
  });
});
