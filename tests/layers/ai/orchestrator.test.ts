import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { runOrchestrator } from "../../../src/layers/ai/orchestrator.js";
import { MockProvider } from "../../../src/layers/ai/providers/mock.js";
import { BudgetTracker } from "../../../src/layers/ai/budget.js";
import type { AIConfig, ApiEndpoint, ProjectModel } from "../../../src/model/types.js";

function mkModel(root: string, endpoints: ApiEndpoint[]): ProjectModel {
  return {
    meta: { name: "t", path: root, stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
    routes: endpoints.map((e) => ({ path: e.path, method: e.method, file: e.file, isApi: true, hasAuthCheck: e.hasAuthCheck, paramNames: [] })),
    endpoints,
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

function mkFixture(paths: string[]): { root: string; endpoints: ApiEndpoint[] } {
  const root = mkdtempSync(join(tmpdir(), "ai-orch-"));
  const endpoints: ApiEndpoint[] = [];
  for (const p of paths) {
    const file = join(root, p);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, `export async function GET() { return new Response(); }`);
    endpoints.push({
      path: p.replace(/^src\/app/, "").replace(/\/route\.ts$/, ""),
      method: "GET",
      file,
      hasValidation: false,
      validationLibrary: null,
      hasAuthCheck: false,
      usesServiceRole: false,
    });
  }
  return { root, endpoints };
}

const baseConfig: AIConfig = {
  enabled: true,
  provider: "mock",
  model: "mock-1",
  deep: false,
  maxCostUsd: 10,
  maxTokensPerEndpoint: 8000,
  concurrency: 2,
  dryRun: false,
  magicLinkRoutes: [],
};

const validAIFinding = {
  ruleId: "AI-IDOR-001",
  domain: "auth-access-control",
  severity: "high",
  confidence: "medium",
  title: "Missing ownership check before user update",
  description: "This handler accepts an id without verifying ownership.",
  evidence: [{ file: "src/app/api/users/route.ts", line: 1 }],
  remediation: "Check that the authenticated user owns the resource.",
  reasoning: "The handler queries by id without checking session.user.id.",
};

describe("runOrchestrator", () => {
  let root: string;
  let endpoints: ApiEndpoint[];

  beforeEach(() => {
    ({ root, endpoints } = mkFixture([
      "src/app/api/users/route.ts",
      "src/app/api/products/route.ts",
      "src/app/api/stats/route.ts",
    ]));
  });

  it("runs every endpoint through the provider and returns AIRunResult", async () => {
    const model = mkModel(root, endpoints);
    const mock = new MockProvider({
      "/api/users": { rawFindings: [validAIFinding], usage: z(), stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/stats": { rawFindings: [], usage: z(), stopReason: "tool_use" },
    });
    const budget = new BudgetTracker(10, mockPricing());
    const result = await runOrchestrator(model, baseConfig, mock, budget);
    expect(mock.callCount).toBe(3);
    expect(result.endpointsAnalyzed).toBe(3);
    expect(result.endpointsSkipped).toBe(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].layer).toBe("ai");
    expect(result.budgetExhausted).toBe(false);
  });

  it("does not mutate the input ProjectModel", async () => {
    const model = mkModel(root, endpoints);
    const mock = new MockProvider({
      "/api/users": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/stats": { rawFindings: [], usage: z(), stopReason: "tool_use" },
    });
    const before = model.findings.length;
    await runOrchestrator(model, baseConfig, mock, new BudgetTracker(10, mockPricing()));
    expect(model.findings.length).toBe(before);
  });

  it("stops cleanly when budget is exhausted mid-scan", async () => {
    const model = mkModel(root, endpoints);
    // Each call costs $5 (5M input × $1/M). Budget $10 allows exactly 2 calls.
    // After call 2: cost = $10 = exhausted. Iter 3 halts at top-of-loop check.
    const usage = { inputTokens: 5_000_000, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 };
    const mock = new MockProvider({
      "/api/users": { rawFindings: [], usage, stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage, stopReason: "tool_use" },
      "/api/stats": { rawFindings: [], usage, stopReason: "tool_use" },
    });
    // Use real pricing, not mock (mock pricing is zero).
    const pricing = { inputPerMTokUsd: 1, outputPerMTokUsd: 5, cacheReadPerMTokUsd: 0.1, cacheWritePerMTokUsd: 1.25 };
    const budget = new BudgetTracker(10, pricing);
    const result = await runOrchestrator(model, { ...baseConfig, concurrency: 1 }, mock, budget);
    expect(result.budgetExhausted).toBe(true);
    expect(result.endpointsAnalyzed).toBe(2);
    expect(result.endpointsSkipped).toBe(1);
  });

  it("records AIError and continues when provider returns stopReason: error", async () => {
    const model = mkModel(root, endpoints);
    const mock = new MockProvider({
      "/api/users": { rawFindings: [validAIFinding], usage: z(), stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage: z(), stopReason: "error", rawError: "500" },
      "/api/stats": { rawFindings: [validAIFinding], usage: z(), stopReason: "tool_use" },
    });
    const result = await runOrchestrator(model, { ...baseConfig, concurrency: 1 }, mock, new BudgetTracker(10, mockPricing()));
    expect(result.endpointsAnalyzed).toBe(2);
    expect(result.endpointsSkipped).toBe(1);
    expect(result.errors.some((e) => e.kind === "provider")).toBe(true);
    expect(result.findings).toHaveLength(2);
  });

  it("drops single malformed findings without losing the rest from the same endpoint", async () => {
    const model = mkModel(root, endpoints);
    const bad = { ...validAIFinding, confidence: "confirmed" as never }; // cap-violating
    const mock = new MockProvider({
      "/api/users": { rawFindings: [bad, validAIFinding], usage: z(), stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/stats": { rawFindings: [], usage: z(), stopReason: "tool_use" },
    });
    const result = await runOrchestrator(model, { ...baseConfig, concurrency: 1 }, mock, new BudgetTracker(10, mockPricing()));
    expect(result.findings).toHaveLength(1);
    expect(result.errors.some((e) => e.kind === "parse")).toBe(true);
  });

  it("processes endpoints in the provided priorityOrder first", async () => {
    const model = mkModel(root, endpoints);
    const order: string[] = [];
    const mock = new MockProvider({
      "/api/users": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/products": { rawFindings: [], usage: z(), stopReason: "tool_use" },
      "/api/stats": { rawFindings: [], usage: z(), stopReason: "tool_use" },
    });
    // Wrap the mock to record order
    const original = mock.generateFindings.bind(mock);
    mock.generateFindings = async (req) => {
      order.push(req.userPrompt.match(/ENDPOINT: \w+ (\S+)/)?.[1] ?? "");
      return original(req);
    };
    await runOrchestrator(
      model,
      { ...baseConfig, concurrency: 1 },
      mock,
      new BudgetTracker(10, mockPricing()),
      ["/api/stats", "/api/users", "/api/products"],
    );
    expect(order).toEqual(["/api/stats", "/api/users", "/api/products"]);
  });

  it("injects the magic-link prompt prefix for endpoints matching magicLinkRoutes", async () => {
    const { root: root2, endpoints: eps } = mkFixture([
      "src/app/api/public/reset/route.ts",
      "src/app/api/users/route.ts",
    ]);
    const model = mkModel(root2, eps);
    // Override fixture paths to the human-readable ones the orchestrator sees
    model.endpoints[0].path = "/api/public/reset";
    model.endpoints[1].path = "/api/users";

    const prompts: Record<string, string> = {};
    const tracker: MockProvider & { seen?: unknown } = new MockProvider({});
    tracker.generateFindings = async (req) => {
      // Route by userPrompt substring — the prompt always contains the endpoint path.
      if (req.userPrompt.includes("/api/public/reset")) prompts["/api/public/reset"] = req.userPrompt;
      else if (req.userPrompt.includes("/api/users")) prompts["/api/users"] = req.userPrompt;
      return { rawFindings: [], usage: z(), stopReason: "tool_use" };
    };

    await runOrchestrator(
      model,
      { ...baseConfig, magicLinkRoutes: ["/api/public/**"] },
      tracker,
      new BudgetTracker(10, mockPricing()),
    );

    expect(prompts["/api/public/reset"]).toMatch(/^MAGIC-LINK ENDPOINT/);
    expect(prompts["/api/users"]).not.toMatch(/MAGIC-LINK ENDPOINT/);
  });
});

// ---- helpers ----
function z() {
  return { inputTokens: 100, outputTokens: 10, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 };
}
function mockPricing() {
  return { inputPerMTokUsd: 0, outputPerMTokUsd: 0, cacheReadPerMTokUsd: 0, cacheWritePerMTokUsd: 0 };
}
