import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

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
  };

  return ConfigSchema.parse(merged);
}
