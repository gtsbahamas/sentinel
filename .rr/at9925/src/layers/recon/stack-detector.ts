import { readFile } from "fs/promises";
import { existsSync, readFileSync } from "fs";
import { join, basename } from "path";
import type { ProjectMeta, StackProfile } from "../../model/types.js";

export async function detectStack(projectPath: string): Promise<ProjectMeta> {
  const pkgPath = join(projectPath, "package.json");

  // ---- Node.js / JavaScript projects ----
  if (existsSync(pkgPath)) {
    return detectNodeStack(projectPath, pkgPath);
  }

  // ---- Go ----
  if (existsSync(join(projectPath, "go.mod"))) {
    return {
      name: basename(projectPath),
      path: projectPath,
      stack: "go",
      packageManager: "go",
      language: "go",
      framework: detectGoFramework(projectPath),
      deployTarget: detectDeployTarget(projectPath),
    };
  }

  // ---- Python ----
  if (
    existsSync(join(projectPath, "requirements.txt")) ||
    existsSync(join(projectPath, "pyproject.toml")) ||
    existsSync(join(projectPath, "setup.py"))
  ) {
    return {
      name: basename(projectPath),
      path: projectPath,
      stack: "python",
      packageManager: "pip",
      language: "python",
      framework: "unknown",
      deployTarget: detectDeployTarget(projectPath),
    };
  }

  // ---- Rust ----
  if (existsSync(join(projectPath, "Cargo.toml"))) {
    return {
      name: basename(projectPath),
      path: projectPath,
      stack: "rust",
      packageManager: "cargo",
      language: "rust",
      framework: "unknown",
      deployTarget: detectDeployTarget(projectPath),
    };
  }

  // ---- Unknown / polyglot ----
  return {
    name: basename(projectPath),
    path: projectPath,
    stack: "unknown",
    packageManager: "unknown",
    language: "unknown",
    framework: "unknown",
    deployTarget: detectDeployTarget(projectPath),
  };
}

// ---- Node-specific detection (original logic) ----

async function detectNodeStack(projectPath: string, pkgPath: string): Promise<ProjectMeta> {
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

  return {
    name: pkg.name ?? basename(projectPath),
    path: projectPath,
    stack,
    packageManager,
    language,
    framework,
    deployTarget: detectDeployTarget(projectPath),
  };
}

// ---- Go framework detection ----

function detectGoFramework(projectPath: string): string {
  // Quick check for common Go web frameworks in go.mod
  try {
    const goMod = readFileSync(join(projectPath, "go.mod"), "utf-8");
    if (goMod.includes("github.com/gin-gonic/gin")) return "gin";
    if (goMod.includes("github.com/labstack/echo")) return "echo";
    if (goMod.includes("github.com/gofiber/fiber")) return "fiber";
    if (goMod.includes("github.com/gorilla/mux")) return "gorilla-mux";
    if (goMod.includes("net/http")) return "net-http";
  } catch {
    // ignore read errors
  }
  return "unknown";
}

// ---- Deploy target detection (shared) ----

function detectDeployTarget(projectPath: string): string | null {
  if (existsSync(join(projectPath, "vercel.json"))) return "vercel";
  if (existsSync(join(projectPath, "wrangler.toml"))) return "cloudflare";
  if (existsSync(join(projectPath, "fly.toml"))) return "fly";
  if (existsSync(join(projectPath, "Dockerfile"))) return "docker";
  if (existsSync(join(projectPath, "docker-compose.yml"))) return "docker";
  if (existsSync(join(projectPath, "render.yaml"))) return "render";
  return null;
}
