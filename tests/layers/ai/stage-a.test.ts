import { describe, it, expect } from "vitest";
import { runStageA } from "../../../src/layers/ai/stage-a.js";
import { MockProvider } from "../../../src/layers/ai/providers/mock.js";
import { BudgetTracker } from "../../../src/layers/ai/budget.js";
import type { ProjectModel } from "../../../src/model/types.js";

function mkModel(): ProjectModel {
  return {
    meta: { name: "t", path: "/tmp", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
    routes: [
      { path: "/api/users/[id]", method: "PATCH", file: "a.ts", isApi: true, hasAuthCheck: false, paramNames: [] },
      { path: "/api/admin/delete", method: "POST", file: "b.ts", isApi: true, hasAuthCheck: true, paramNames: [] },
    ],
    endpoints: [],
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

const zeroUsage = { inputTokens: 100, outputTokens: 20, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 };
const zeroPricing = { inputPerMTokUsd: 0, outputPerMTokUsd: 0, cacheReadPerMTokUsd: 0, cacheWritePerMTokUsd: 0 };

describe("runStageA", () => {
  it("returns StageARiskSummary on success", async () => {
    const mock = new MockProvider({
      "project-wide": {
        rawFindings: [
          {
            projectRisks: [
              { domain: "auth-access-control", description: "Handlers lack ownership checks", affectedEndpoints: ["/api/users/[id]"], severity: "high" },
            ],
            priorityOrder: ["/api/users/[id]", "/api/admin/delete"],
          },
        ],
        usage: zeroUsage,
        stopReason: "tool_use",
      },
    });
    const result = await runStageA(mkModel(), mock, new BudgetTracker(10, zeroPricing));
    expect(result).not.toBeNull();
    expect(result!.priorityOrder).toEqual(["/api/users/[id]", "/api/admin/delete"]);
    expect(result!.projectRisks).toHaveLength(1);
    expect(result!.projectRisks[0].domain).toBe("auth-access-control");
  });

  it("returns null on provider error (fallback handled by caller)", async () => {
    const mock = new MockProvider({
      "project-wide": { rawFindings: [], usage: zeroUsage, stopReason: "error", rawError: "rate-limited" },
    });
    const result = await runStageA(mkModel(), mock, new BudgetTracker(10, zeroPricing));
    expect(result).toBeNull();
  });

  it("returns null when response fails schema validation", async () => {
    const mock = new MockProvider({
      "project-wide": {
        rawFindings: [{ garbage: true }],
        usage: zeroUsage,
        stopReason: "tool_use",
      },
    });
    const result = await runStageA(mkModel(), mock, new BudgetTracker(10, zeroPricing));
    expect(result).toBeNull();
  });
});
