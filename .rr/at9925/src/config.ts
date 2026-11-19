import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const VerifyConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(["anthropic", "openai", "ollama", "mock"]).default("anthropic"),
  model: z.string().default("claude-haiku-4-5"),
  maxCostUsd: z.number().positive().default(1.0),
  concurrency: z.number().int().positive().default(4),
  minSeverity: SeveritySchema.default("medium"),
  keepDismissed: z.boolean().default(false),
});

const AIConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(["anthropic", "openai", "ollama", "mock"]).default("anthropic"),
  model: z.string().default("claude-sonnet-4-6"),
  baseUrl: z.string().url().optional(),
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
  verify: VerifyConfigSchema.default({}),
});

// Declarative auth-convention rule. The user states a path glob and the
// auth helper that EVERY endpoint under that glob must call. CONVENTION-001
// reads this and flags endpoints that deviate from the declared pattern.
// `domain` is reserved for future expansion (validation conventions, error
// handling conventions, etc.); for now only "auth" is meaningful.
const ConventionRuleSchema = z.object({
  match: z.string(),
  require: z.string(),
  domain: z.enum(["auth"]).default("auth"),
});

export type ConventionRule = z.infer<typeof ConventionRuleSchema>;

// Pattern-inference tuning. Currently only one knob: a path-segment
// exclusion list that REPLACES (not merges with) the built-in defaults.
// The default list excludes auth-flow endpoints (login, signup, OTP, etc.)
// and non-session auth endpoints (webhooks, crons) so they don't pollute
// inferred session-helper patterns for the rest of their group.
const PatternInferenceSchema = z.object({
  excludePathSegments: z.array(z.string()).optional(),
});

export type PatternInferenceConfig = z.infer<typeof PatternInferenceSchema>;

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
  conventions: z.array(ConventionRuleSchema).optional(),
  patternInference: PatternInferenceSchema.optional(),
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
    verify: {
      enabled: false,
      provider: "anthropic",
      model: "claude-haiku-4-5",
      maxCostUsd: 1.0,
      concurrency: 4,
      minSeverity: "medium",
      keepDismissed: false,
    },
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
    // conventions: optional, no defaults. Caller-supplied or absent.
    conventions: parsed.conventions,
    // patternInference: optional, no defaults. Caller-supplied or absent.
    // The recon layer applies built-in defaults when this is missing.
    patternInference: parsed.patternInference,
  };

  return ConfigSchema.parse(merged);
}
