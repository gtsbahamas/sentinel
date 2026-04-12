import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const AIConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(["anthropic", "openai", "mock"]).default("anthropic"),
  model: z.string().default("claude-sonnet-4-6"),
  deep: z.boolean().default(false),
  maxCostUsd: z.number().positive().default(2.0),
  maxTokensPerEndpoint: z.number().int().positive().default(8000),
  concurrency: z.number().int().positive().default(3),
  // Glob patterns for endpoints that are intentionally unauthenticated
  // and protected by an unguessable token in the URL (password reset,
  // magic links, booking confirmations). The AI gets a per-endpoint
  // context prefix explaining this access model, and post-processing caps
  // severity for "no auth check" style findings on matching routes.
  magicLinkRoutes: z.array(z.string()).default([]),
});

const ConfigSchema = z.object({
  stack: z.enum(["nextjs-supabase", "react-vite-supabase", "generic-web"]),
  domains: z.array(z.string()),
  exclude: z.array(z.string()),
  severity: z.object({
    failOn: SeveritySchema,
  }),
  output: z.object({
    format: z.enum(["terminal", "json", "html", "all"]),
    dir: z.string(),
  }),
  ai: AIConfigSchema,
});

export type SentinelConfig = z.infer<typeof ConfigSchema>;

export const CONFIG_DEFAULTS: SentinelConfig = {
  stack: "nextjs-supabase",
  domains: ["all"],
  exclude: [
    "node_modules",
    ".next",
    "dist",
    "out",
    "build",
    ".git",
    ".claude/worktrees",
    "public",
    "widget-build",
  ],
  severity: { failOn: "high" },
  output: { format: "terminal", dir: ".sentinel/reports" },
  ai: {
    enabled: false,
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    deep: false,
    maxCostUsd: 2.0,
    maxTokensPerEndpoint: 8000,
    concurrency: 3,
    magicLinkRoutes: [],
  },
};

export async function loadConfig(projectPath: string): Promise<SentinelConfig> {
  const configPath = join(projectPath, ".sentinelrc.json");

  if (!existsSync(configPath)) {
    return CONFIG_DEFAULTS;
  }

  const raw = await readFile(configPath, "utf-8");
  const parsed = JSON.parse(raw);

  const merged = {
    ...CONFIG_DEFAULTS,
    ...parsed,
    severity: { ...CONFIG_DEFAULTS.severity, ...(parsed.severity ?? {}) },
    output: { ...CONFIG_DEFAULTS.output, ...(parsed.output ?? {}) },
    ai: { ...CONFIG_DEFAULTS.ai, ...(parsed.ai ?? {}) },
  };

  return ConfigSchema.parse(merged);
}
