import { describe, it, expect } from "vitest";
import { stagedFixture } from "./helpers.js";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { llmFeatureRules } from "../../src/layers/rules/domains/llm-features.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { Finding } from "../../src/model/types.js";

// LLM-006 approval gates: an approval only suppresses the finding when it
// actually stands in front of the outward action. A gate that is imported
// but never used, sits in a function nobody calls, guards a different
// action, or approves the whole run rather than the send, guards nothing.

async function trifectaFindings(variant: string): Promise<Finding[]> {
  resetRegistry();
  registerRules(llmFeatureRules);
  const model = await runRecon(stagedFixture(`llm-trifecta-${variant}`), ["node_modules"]);
  const findings = await runRules(model);
  return findings.filter((f) => f.ruleId === "LLM-006");
}

describe("LLM-006 approval gates", () => {
  it("still flags an ungated send when an Action Gate is imported but never used", async () => {
    const hits = await trifectaFindings("unused-gate-import");
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe("high");
    expect(hits[0].evidence[0].snippet).toContain("resend.emails.send");
  });

  it("still flags an ungated send when the only approval call is in a function nobody calls", async () => {
    const hits = await trifectaFindings("uncalled-approval");
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].snippet).toContain("resend.emails.send");
  });

  it("still flags an ungated send when an approval helper is defined but never called", async () => {
    const hits = await trifectaFindings("uncalled-arrow-approval");
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].snippet).toContain("resend.emails.send");
  });

  it("flags the outward action that has no approval when another one does", async () => {
    const hits = await trifectaFindings("gate-other-action");
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].snippet).toContain("fetch(args.url");
  });

  it("still flags when approval sits on a different tool than the outward one", async () => {
    const hits = await trifectaFindings("needs-approval-other-tool");
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].file).toMatch(/tools\/post-webhook\.ts$/);
  });

  it("still flags when a person approves starting the run, not the outward action", async () => {
    const hits = await trifectaFindings("route-approval");
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence[0].file).toMatch(/tools\/post-webhook\.ts$/);
  });

  it("stays quiet when the outward tool itself declares needsApproval", async () => {
    expect(await trifectaFindings("needs-approval")).toEqual([]);
  });

  it("stays quiet when the route only hands the model the outward tool wrapped in Action Gate", async () => {
    expect(await trifectaFindings("wrapped-tool")).toEqual([]);
  });

  it("stays quiet when the tool body asks Action Gate before it sends", async () => {
    expect(await trifectaFindings("action-gate-call")).toEqual([]);
  });
});
