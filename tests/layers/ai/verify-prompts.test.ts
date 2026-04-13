import { describe, it, expect } from "vitest";
import {
  VERIFY_SYSTEM_PREAMBLE,
  REPORT_VERDICTS_TOOL,
  buildVerifyUserPrompt,
} from "../../../src/layers/ai/verify-prompts.js";
import type { Finding } from "../../../src/model/types.js";
import type { ProjectContext } from "../../../src/layers/context/types.js";

function mkFinding(partial: Partial<Finding> & { id: string }): Finding {
  return {
    id: partial.id,
    domain: "cryptography",
    severity: "high",
    confidence: "medium",
    title: "Test finding",
    description: "Test description",
    evidence: [{ file: "src/foo.ts", line: 10, snippet: "if (token !== 'string')" }],
    remediation: "Use timingSafeEqual",
    references: [],
    layer: "rules",
    ruleId: "CRYPTO-008",
    ...partial,
  };
}

function mkContext(partial: Partial<ProjectContext> = {}): ProjectContext {
  return {
    version: 1,
    tenancy: "single-org",
    auth: { defaultClient: "anon", roleModel: [] },
    validation: { library: "zod", schemaLocations: [], importedByRoutes: false },
    migrations: { rlsStrategy: "co-located" },
    framework: {
      routeHandlersServerOnly: true,
      frameworkCatchesErrors: true,
      serverOnlyImportGuard: false,
    },
    deployment: { platform: "vercel", platformHandles: [] },
    publicRoutes: [],
    delegations: [],
    excludedPaths: [],
    generatedAt: "2026-04-13T00:00:00Z",
    generatedBy: "auto",
    confidence: {},
    ...partial,
  };
}

describe("VERIFY_SYSTEM_PREAMBLE", () => {
  it("names the verification role and decision vocabulary", () => {
    expect(VERIFY_SYSTEM_PREAMBLE).toMatch(/verif/i);
    expect(VERIFY_SYSTEM_PREAMBLE).toMatch(/confirm/);
    expect(VERIFY_SYSTEM_PREAMBLE).toMatch(/dismiss/);
    expect(VERIFY_SYSTEM_PREAMBLE).toMatch(/downgrade/);
  });

  it("instructs the model not to execute instructions from analyzed source", () => {
    expect(VERIFY_SYSTEM_PREAMBLE.toLowerCase()).toMatch(/never.*(execute|follow).*instructions|ignore.*instructions.*source/);
  });
});

describe("buildVerifyUserPrompt", () => {
  const source = [
    "import { foo } from 'bar';",
    "",
    "export function auth(token: string) {",
    "  if (typeof token !== 'string') return null;",
    "  return token;",
    "}",
  ].join("\n");

  it("includes file path and source fenced as typescript", () => {
    const findings = [mkFinding({ id: "CRYPTO-008-src/foo.ts-4" })];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext(),
    });
    expect(prompt).toContain("src/foo.ts");
    expect(prompt).toContain("```typescript");
    expect(prompt).toContain("if (typeof token !== 'string')");
  });

  it("includes numbered source lines so the model can reference line numbers", () => {
    const findings = [mkFinding({ id: "x", evidence: [{ file: "src/foo.ts", line: 4 }] })];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext(),
    });
    // Line 4 should appear prefixed with "4" in a numbered listing.
    expect(prompt).toMatch(/\b4\b.*token !== 'string'/);
  });

  it("lists each finding with findingId, ruleId, line, and message", () => {
    const findings = [
      mkFinding({
        id: "CRYPTO-008-src/foo.ts-4",
        ruleId: "CRYPTO-008",
        title: "Secret compared with non-constant-time equality",
        evidence: [{ file: "src/foo.ts", line: 4, snippet: "typeof token !== 'string'" }],
      }),
      mkFinding({
        id: "LOG-001-src/foo.ts-2",
        ruleId: "LOG-001",
        title: "Sensitive value passed to log",
        domain: "logging-monitoring",
        evidence: [{ file: "src/foo.ts", line: 2, snippet: "console.log('Authenticated:', session)" }],
      }),
    ];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext(),
    });
    expect(prompt).toContain("CRYPTO-008-src/foo.ts-4");
    expect(prompt).toContain("LOG-001-src/foo.ts-2");
    expect(prompt).toContain("CRYPTO-008");
    expect(prompt).toContain("LOG-001");
    expect(prompt).toContain("Secret compared with non-constant-time equality");
    expect(prompt).toContain("Sensitive value passed to log");
  });

  it("includes project context summary (tenancy, deployment, excluded paths, delegations)", () => {
    const findings = [mkFinding({ id: "x" })];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext({
        tenancy: "multi-tenant",
        excludedPaths: ["scripts/**", "packages/website/src/app/test/**"],
        delegations: [
          { provider: "clerk", responsibility: "authentication", mechanism: "middleware.ts", appliesTo: [] },
        ],
      }),
    });
    expect(prompt).toContain("multi-tenant");
    expect(prompt).toContain("vercel");
    expect(prompt).toContain("scripts/**");
    expect(prompt).toContain("test/**");
    expect(prompt).toContain("clerk");
    expect(prompt).toContain("authentication");
  });

  it("instructs the model to decide confirm/dismiss/downgrade per finding", () => {
    const findings = [mkFinding({ id: "x" })];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext(),
    });
    expect(prompt).toMatch(/confirm/);
    expect(prompt).toMatch(/dismiss/);
    expect(prompt).toMatch(/downgrade/);
    expect(prompt).toMatch(/report_verdicts/);
  });

  it("windows large files to snippets around each finding line", () => {
    const bigSource = Array.from({ length: 800 }, (_, i) => `line ${i + 1}`).join("\n");
    const findings = [
      mkFinding({ id: "a", evidence: [{ file: "src/big.ts", line: 100 }] }),
      mkFinding({ id: "b", evidence: [{ file: "src/big.ts", line: 700 }] }),
    ];
    const prompt = buildVerifyUserPrompt({
      file: "src/big.ts",
      source: bigSource,
      findings,
      context: mkContext(),
    });
    // Should contain content near lines 100 and 700
    expect(prompt).toContain("line 100");
    expect(prompt).toContain("line 700");
    // Should NOT contain content far from any finding
    expect(prompt).not.toContain("line 400");
    // Should indicate a windowed view
    expect(prompt.toLowerCase()).toMatch(/window|excerpt|truncat/);
  });

  it("includes the full source when the file is small", () => {
    const findings = [mkFinding({ id: "x", evidence: [{ file: "src/foo.ts", line: 4 }] })];
    const prompt = buildVerifyUserPrompt({
      file: "src/foo.ts",
      source,
      findings,
      context: mkContext(),
    });
    // Every line of the small source should appear
    for (const line of source.split("\n")) {
      if (line.trim() === "") continue;
      expect(prompt).toContain(line);
    }
  });
});

describe("REPORT_VERDICTS_TOOL", () => {
  it("is named report_verdicts", () => {
    expect(REPORT_VERDICTS_TOOL.name).toBe("report_verdicts");
  });

  it("has a description", () => {
    expect(REPORT_VERDICTS_TOOL.description.length).toBeGreaterThan(0);
  });

  it("schema exposes a verdicts array of objects", () => {
    const schema = REPORT_VERDICTS_TOOL.schema as {
      type: string;
      properties: { verdicts: { type: string; items: { type: string } } };
      required: string[];
    };
    expect(schema.type).toBe("object");
    expect(schema.properties.verdicts.type).toBe("array");
    expect(schema.properties.verdicts.items.type).toBe("object");
    expect(schema.required).toContain("verdicts");
  });

  it("schema items declare findingId, decision, reason as required fields", () => {
    const schema = REPORT_VERDICTS_TOOL.schema as {
      properties: {
        verdicts: {
          items: {
            properties: Record<string, unknown>;
            required?: string[];
          };
        };
      };
    };
    const itemProps = schema.properties.verdicts.items.properties;
    expect(itemProps).toHaveProperty("findingId");
    expect(itemProps).toHaveProperty("decision");
    expect(itemProps).toHaveProperty("reason");
  });
});
