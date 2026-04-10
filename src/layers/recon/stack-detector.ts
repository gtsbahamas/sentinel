import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, basename } from "path";
import type { ProjectMeta, StackProfile } from "../../model/types.js";

export async function detectStack(projectPath: string): Promise<ProjectMeta> {
  const pkgPath = join(projectPath, "package.json");
  if (!existsSync(pkgPath)) {
    throw new Error(`No package.json found in ${projectPath}`);
  }

  const pkg = JSON.parse(await readFile(pkgPath, "utf-8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  const hasNext = "next" in deps;
  const hasVite = "vite" in deps;
  const hasSupabase = "@supabase/supabase-js" in deps;

  let stack: StackProfile = "generic-web";
  let framework = "unknown";

  if (hasNext && hasSupabase) {
    stack = "nextjs-supabase";
    framework =
      existsSync(join(projectPath, "src", "app")) || existsSync(join(projectPath, "app"))
        ? "nextjs-app"
        : "nextjs-pages";
  } else if (hasVite && hasSupabase) {
    stack = "react-vite-supabase";
    framework = "vite-react";
  } else if (hasNext) {
    framework = "nextjs";
  } else if (hasVite) {
    framework = "vite";
  }

  const language: "typescript" | "javascript" = existsSync(join(projectPath, "tsconfig.json"))
    ? "typescript"
    : "javascript";

  let packageManager: "pnpm" | "npm" | "yarn" = "npm";
  if (existsSync(join(projectPath, "pnpm-lock.yaml"))) packageManager = "pnpm";
  else if (existsSync(join(projectPath, "yarn.lock"))) packageManager = "yarn";
  else if (existsSync(join(projectPath, "package-lock.json"))) packageManager = "npm";

  let deployTarget: string | null = null;
  if (existsSync(join(projectPath, "vercel.json"))) deployTarget = "vercel";
  else if (existsSync(join(projectPath, "wrangler.toml"))) deployTarget = "cloudflare";
  else if (existsSync(join(projectPath, "fly.toml"))) deployTarget = "fly";
  else if (existsSync(join(projectPath, "Dockerfile"))) deployTarget = "docker";

  return {
    name: pkg.name ?? basename(projectPath),
    path: projectPath,
    stack,
    packageManager,
    language,
    framework,
    deployTarget,
  };
}
