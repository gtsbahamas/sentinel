import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..", "..", "..");
const fixture = join(repoRoot, "tests", "fixtures", "ai-scan");

const LIVE = process.env.RUN_AI_LIVE_TESTS === "1";
const HAS_ANTHROPIC = !!process.env.ANTHROPIC_API_KEY;
const HAS_OPENAI = !!process.env.OPENAI_API_KEY;

describe.skipIf(!LIVE)("AI live smoke tests", () => {
  it.skipIf(!HAS_ANTHROPIC)(
    "runs against real Anthropic under $0.25 budget",
    () => {
      const stdout = execFileSync(
        "npx",
        [
          "tsx",
          join(repoRoot, "src", "cli.ts"),
          "scan",
          fixture,
          "--ai",
          "--ai-provider",
          "anthropic",
          "--ai-max-cost",
          "0.25",
          "--format",
          "json",
        ],
        {
          cwd: repoRoot,
          encoding: "utf-8",
          maxBuffer: 16 * 1024 * 1024,
        }
      );
      const parsed = JSON.parse(stdout);
      expect(parsed.runInfo.ai.enabled).toBe(true);
      expect(parsed.runInfo.ai.budgetExhausted).toBe(false);
      expect(parsed.runInfo.ai.endpointsAnalyzed).toBeGreaterThan(0);
    },
    120_000
  );

  it.skipIf(!HAS_OPENAI)("runs against real OpenAI under $0.25 budget", () => {
    const stdout = execFileSync(
      "npx",
      [
        "tsx",
        join(repoRoot, "src", "cli.ts"),
        "scan",
        fixture,
        "--ai",
        "--ai-provider",
        "openai",
        "--ai-max-cost",
        "0.25",
        "--format",
        "json",
      ],
      {
        cwd: repoRoot,
        encoding: "utf-8",
        maxBuffer: 16 * 1024 * 1024,
      }
    );
    const parsed = JSON.parse(stdout);
    expect(parsed.runInfo.ai.enabled).toBe(true);
    expect(parsed.runInfo.ai.budgetExhausted).toBe(false);
    expect(parsed.runInfo.ai.endpointsAnalyzed).toBeGreaterThan(0);
  }, 120_000);
});
