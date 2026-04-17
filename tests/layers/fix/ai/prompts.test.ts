import { describe, it, expect } from "vitest";
import { getPromptTemplate } from "../../../../src/layers/fix/ai/prompts.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(ruleId: string, overrides?: Partial<Finding>): Finding {
  return {
    id: `finding-${ruleId}`,
    ruleId,
    domain: "input-injection",
    severity: "high",
    confidence: "high",
    title: `Test finding for ${ruleId}`,
    description: "Test description",
    impact: "Test impact",
    evidence: [{ file: "src/app/api/route.ts", line: 10, snippet: "const body = req.body" }],
    remediation: "Fix it",
    references: [],
    layer: "rules",
    ...overrides,
  };
}

describe("getPromptTemplate", () => {
  it("returns a template for INPUT-005", () => {
    const template = getPromptTemplate("INPUT-005");
    expect(template).toBeDefined();
    expect(template?.id).toBe("INPUT-005");
  });

  it("returns a template for AUTH-001", () => {
    const template = getPromptTemplate("AUTH-001");
    expect(template).toBeDefined();
    expect(template?.id).toBe("AUTH-001");
  });

  it("returns a template for API-004", () => {
    const template = getPromptTemplate("API-004");
    expect(template).toBeDefined();
    expect(template?.id).toBe("API-004");
  });

  it("returns undefined for unknown rule ID", () => {
    expect(getPromptTemplate("UNKNOWN-999")).toBeUndefined();
    expect(getPromptTemplate("")).toBeUndefined();
    expect(getPromptTemplate("CRYPTO-001")).toBeUndefined();
  });

  it("INPUT-005 prompt includes file content", () => {
    const template = getPromptTemplate("INPUT-005")!;
    const fileContent = `export async function POST(req: Request) { const body = req.body; }`;
    const findings = [makeFinding("INPUT-005")];
    const prompt = template.buildUserPrompt(fileContent, findings);
    expect(prompt).toContain(fileContent);
  });

  it("AUTH-001 prompt includes file content", () => {
    const template = getPromptTemplate("AUTH-001")!;
    const fileContent = `export async function GET(req: Request) { return Response.json({}); }`;
    const findings = [makeFinding("AUTH-001")];
    const prompt = template.buildUserPrompt(fileContent, findings);
    expect(prompt).toContain(fileContent);
  });

  it("API-004 prompt includes file content", () => {
    const template = getPromptTemplate("API-004")!;
    const fileContent = `export async function POST(req: Request) { return Response.json({ ok: true }); }`;
    const findings = [makeFinding("API-004")];
    const prompt = template.buildUserPrompt(fileContent, findings);
    expect(prompt).toContain(fileContent);
  });

  it("INPUT-005 prompt includes evidence file and line", () => {
    const template = getPromptTemplate("INPUT-005")!;
    const findings = [makeFinding("INPUT-005")];
    const prompt = template.buildUserPrompt("content", findings);
    expect(prompt).toContain("src/app/api/route.ts");
    expect(prompt).toContain("10");
  });

  it("all templates have a non-empty system prompt", () => {
    for (const id of ["INPUT-005", "AUTH-001", "API-004"]) {
      const template = getPromptTemplate(id)!;
      expect(template.system.trim().length).toBeGreaterThan(0);
    }
  });

  it("AUTH-001 prompt mentions Supabase auth", () => {
    const template = getPromptTemplate("AUTH-001")!;
    const prompt = template.buildUserPrompt("content", [makeFinding("AUTH-001")]);
    expect(prompt.toLowerCase()).toContain("supabase");
    expect(prompt).toContain("401");
  });

  it("API-004 prompt mentions rate limit and 429", () => {
    const template = getPromptTemplate("API-004")!;
    const prompt = template.buildUserPrompt("content", [makeFinding("API-004")]);
    expect(prompt.toLowerCase()).toContain("rate");
    expect(prompt).toContain("429");
  });

  it("INPUT-005 prompt mentions Zod and 400", () => {
    const template = getPromptTemplate("INPUT-005")!;
    const prompt = template.buildUserPrompt("content", [makeFinding("INPUT-005")]);
    expect(prompt.toLowerCase()).toContain("zod");
    expect(prompt).toContain("400");
  });
});
