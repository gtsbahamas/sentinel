import { describe, it, expect } from "vitest";
import { stagedFixture } from "./helpers.js";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { llmFeatureRules } from "../../src/layers/rules/domains/llm-features.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { Finding } from "../../src/model/types.js";

// LLM-006: the "lethal trifecta". An AI agent that can read private data, is
// fed untrusted content, and can act outward, with no human approval in
// front of the outward action. Each llm-trifecta-* fixture is the same
// small support agent with one thing changed.

async function trifectaFindings(variant: string): Promise<Finding[]> {
  resetRegistry();
  registerRules(llmFeatureRules);
  const model = await runRecon(stagedFixture(`llm-trifecta-${variant}`), ["node_modules"]);
  const findings = await runRules(model);
  return findings.filter((f) => f.ruleId === "LLM-006");
}

describe("LLM-006 lethal trifecta", () => {
  it("is registered as a high-severity llm-features rule linking Seatrial Action Gate", () => {
    const rule = llmFeatureRules.find((r) => r.id === "LLM-006");
    expect(rule).toBeDefined();
    expect(rule!.severity).toBe("high");
    expect(rule!.domain).toBe("llm-features");
    expect(rule!.references.external?.some((u) => /action-gate/.test(u))).toBe(true);
  });

  it("flags an agent with all three legs and no approval gate exactly once, at high", async () => {
    const hits = await trifectaFindings("ungated");
    expect(hits).toHaveLength(1);
    const f = hits[0];
    expect(f.severity).toBe("high");
    expect(f.evidence[0].file).toMatch(/api\/assistant\/route\.ts$/);
    expect(f.evidence[0].snippet).toContain("resend.emails.send");
    expect(f.title).toBe(
      "This AI feature can read private data, is fed untrusted content, and can send things out; drop one or put a human approval in front",
    );
    expect(f.remediation).toMatch(/Action Gate/);
    expect(f.remediation).toMatch(/https:\/\/\S+action-gate/);
  });

  it("names the three legs it found in the description", async () => {
    const [f] = await trifectaFindings("ungated");
    expect(f.description).toMatch(/private data/i);
    expect(f.description).toMatch(/untrusted/i);
    expect(f.description).toMatch(/send|out/i);
  });

  it("stays quiet when an approval step sits in front of the outward action", async () => {
    expect(await trifectaFindings("gated")).toEqual([]);
  });

  it("stays quiet with only two legs: no private data", async () => {
    expect(await trifectaFindings("no-private-data")).toEqual([]);
  });

  it("stays quiet with only two legs: no untrusted input", async () => {
    expect(await trifectaFindings("no-untrusted-input")).toEqual([]);
  });

  it("stays quiet with only two legs: no outward action", async () => {
    expect(await trifectaFindings("no-outward-action")).toEqual([]);
  });

  it("does not count an app-side write the model cannot reach (saving chat history)", async () => {
    expect(await trifectaFindings("history-write")).toEqual([]);
  });

  it("treats an agent and the tool modules it imports as one tool-set", async () => {
    const hits = await trifectaFindings("split-toolset");
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe("high");
    expect(hits[0].evidence[0].file).toMatch(/tools\/post-webhook\.ts$/);
    expect(hits[0].evidence[0].snippet).toContain("fetch(url");
  });
});
