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
  // `exclude`: paths the project walk skips. `ignore`: paths the user wants
  // no findings from; each is added to `exclude` and findings there are dropped.
  exclude: z.array(z.string()),
  ignore: z.array(z.string()).optional(),
  severity: z.object({
    failOn: SeveritySchema,
  }),
  // Short spelling of `severity.failOn`; the nested key wins when both are set.
  failOn: SeveritySchema.optional(),
  output: z.object({
    format: z.enum(["terminal", "json", "html", "all"]),
    dir: z.string(),
  }),
  ai: AIConfigSchema,
  // Written by `probe --authorize` and read back by the probe layer alone
  // (src/layers/probe/authorization.ts); known here so it is not reported as a typo.
  // Its value is that layer's to judge, so nothing in it can stop a scan.
  probe: z.object({ authorizations: z.unknown() }).optional().catch(undefined),
  conventions: z.array(ConventionRuleSchema).optional(),
  patternInference: PatternInferenceSchema.optional(),
});

// The loaded config carries the failing severity once (top-level `failOn` is
// folded into `severity.failOn`). `exclude` already contains every `ignore`
// entry; `ignore` is kept so findings under those paths can be dropped too.
export type SentinelConfig = Omit<z.infer<typeof ConfigSchema>, "ignore" | "failOn" | "probe"> & {
  ignore: string[];
};

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
  ignore: [],
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

/**
 * A `.sentinelrc.json` value the scanner cannot use. The message is one line
 * meant for the person who wrote the file; the CLI prints it and exits 2.
 */
export class ConfigError extends Error {
  override name = "ConfigError";
}

// Whether the file itself has something at this path (top-level `failOn` is
// also checked as `severity.failOn`, which the user did not write).
function wrote(parsed: unknown, path: (string | number)[]): boolean {
  let at = parsed;
  for (const key of path) {
    if (!at || typeof at !== "object" || !(key in at)) return false;
    at = (at as Record<string | number, unknown>)[key];
  }
  return true;
}

function describeIssues(configPath: string, parsed: unknown, issues: z.ZodIssue[]): string {
  const written = issues.filter((issue) => wrote(parsed, issue.path));
  const problems = (written.length > 0 ? written : issues).map(
    (issue) => `\`${issue.path.join(".")}\`: ${issue.message.replace(/\s+/g, " ")}`,
  );
  return `${configPath} has ${problems.length === 1 ? "a value" : "values"} Sentinel cannot use. ${problems.join("; ")}`;
}

// Peel optional/default/catch wrappers to reach the object schema underneath, if any.
function objectShape(schema: z.ZodTypeAny): z.ZodRawShape | null {
  let inner = schema;
  while (inner instanceof z.ZodOptional || inner instanceof z.ZodDefault || inner instanceof z.ZodCatch) {
    inner = inner._def.innerType;
  }
  return inner instanceof z.ZodObject ? inner.shape : null;
}

// Dotted paths of every key in `value` that the schema does not define.
// Keys starting with "_" are notes to the reader (.sentinelrc.defaults.json
// uses them) and are never reported.
function unknownKeys(value: unknown, shape: z.ZodRawShape, prefix = ""): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const found: string[] = [];
  for (const [key, child] of Object.entries(value)) {
    const known = shape[key];
    if (!known) {
      if (!key.startsWith("_")) found.push(prefix + key);
      continue;
    }
    const childShape = objectShape(known);
    if (childShape) found.push(...unknownKeys(child, childShape, `${prefix}${key}.`));
  }
  return found;
}

// A scan loads the config several times; each file is warned about once.
const warnedConfigPaths = new Set<string>();

/** Forget which config files have been warned about (for tests). */
export function resetConfigWarnings(): void {
  warnedConfigPaths.clear();
}

// Goes to stderr so `--format json` output and the MCP stdio stream stay clean.
function warnUnknownKeys(configPath: string, parsed: unknown): void {
  if (warnedConfigPaths.has(configPath)) return;
  warnedConfigPaths.add(configPath);
  const unknown = unknownKeys(parsed, ConfigSchema.shape);
  if (unknown.length === 0) return;
  process.stderr.write(
    `Warning: ${configPath} has ${unknown.length === 1 ? "a key" : "keys"} Sentinel does not know and will not use: ${unknown.join(", ")}\n`,
  );
}

// "test/" and "test" name the same directory; the walker wants no trailing slash.
function normalizeExcludes(paths: string[]): string[] {
  return [...new Set(paths.map((p) => p.replace(/\/+$/, "")).filter((p) => p !== ""))];
}

/**
 * Load `.sentinelrc.json` from the project root over the defaults. Unknown
 * keys are reported once on stderr and otherwise left alone; invalid values
 * for known keys throw a ConfigError.
 */
export async function loadConfig(projectPath: string): Promise<SentinelConfig> {
  const configPath = join(projectPath, ".sentinelrc.json");

  if (!existsSync(configPath)) {
    return CONFIG_DEFAULTS;
  }

  const raw = await readFile(configPath, "utf-8");
  const parsed = JSON.parse(raw);

  warnUnknownKeys(configPath, parsed);

  const merged = {
    ...CONFIG_DEFAULTS,
    ...parsed,
    severity: {
      ...CONFIG_DEFAULTS.severity,
      ...(parsed.failOn !== undefined ? { failOn: parsed.failOn } : {}),
      ...(parsed.severity ?? {}),
    },
    output: { ...CONFIG_DEFAULTS.output, ...(parsed.output ?? {}) },
    ai: { ...CONFIG_DEFAULTS.ai, ...(parsed.ai ?? {}) },
    // conventions: optional, no defaults. Caller-supplied or absent.
    conventions: parsed.conventions,
    // patternInference: optional, no defaults. Caller-supplied or absent.
    // The recon layer applies built-in defaults when this is missing.
    patternInference: parsed.patternInference,
  };

  const result = ConfigSchema.safeParse(merged);
  if (!result.success) throw new ConfigError(describeIssues(configPath, parsed, result.error.issues));
  const { failOn: _failOn, probe: _probe, ...config } = result.data;
  const ignore = normalizeExcludes(config.ignore ?? []);
  return { ...config, ignore, exclude: normalizeExcludes([...config.exclude, ...ignore]) };
}
