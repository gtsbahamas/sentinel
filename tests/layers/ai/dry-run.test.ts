import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { runDryRun } from "../../../src/layers/ai/dry-run.js";
import { MockProvider } from "../../../src/layers/ai/providers/mock.js";
import type { AIConfig, ProjectModel } from "../../../src/model/types.js";

function mkModel(root: string, endpointCount: number): ProjectModel {
  const endpoints = Array.from({ length: endpointCount }, (_, i) => {
    const file = join(root, `src/app/api/r${i}/route.ts`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, `export async function GET() { return new Response(); }`);
    return {
      path: `/api/r${i}`,
      method: "GET" as const,
      file,
      hasValidation: false,
      validationLibrary: null,
      hasAuthCheck: false,
      usesServiceRole: false,
    };
  });
  return {
    meta: { name: "t", path: root, stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
    routes: [],
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

const config: AIConfig = {
  enabled: true,
  provider: "mock",
  model: "mock-1",
  deep: false,
  maxCostUsd: 2,
  maxTokensPerEndpoint: 8000,
  concurrency: 3,
  dryRun: true,
};

describe("runDryRun", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "ai-dry-"));
  });

  it("computes a total token estimate and calls the provider zero times", async () => {
    const model = mkModel(root, 5);
    const mock = new MockProvider({});
    const estimate = await runDryRun(model, config, mock);
    expect(estimate.endpointCount).toBe(5);
    expect(estimate.totalInputTokens).toBeGreaterThan(0);
    expect(estimate.estimatedCostUsd).toBe(0);
    expect(mock.callCount).toBe(0);
  });

  it("reports whether estimate is within the configured cap", async () => {
    const model = mkModel(root, 1);
    const mock = new MockProvider({});
    const estimate = await runDryRun(model, config, mock);
    expect(estimate.withinBudget).toBe(true);
    expect(estimate.maxCostUsd).toBe(2);
  });

  it("returns an empty result when there are no endpoints", async () => {
    const model = mkModel(root, 0);
    const mock = new MockProvider({});
    const estimate = await runDryRun(model, config, mock);
    expect(estimate.endpointCount).toBe(0);
    expect(estimate.totalInputTokens).toBe(0);
  });
});
