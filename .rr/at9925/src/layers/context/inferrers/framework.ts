import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

function hasDependency(model: ProjectModel, pkgName: string): boolean {
  return model.dependencies.some((d) => d.name === pkgName);
}

export function inferFramework(
  model: ProjectModel
): InferResult<ProjectContext["framework"]> {
  const isNextJs =
    model.meta.stack === "nextjs-supabase" ||
    model.meta.framework === "next" ||
    hasDependency(model, "next");

  if (isNextJs) {
    const serverOnlyImportGuard = hasDependency(model, "server-only");
    return {
      value: {
        routeHandlersServerOnly: true,
        frameworkCatchesErrors: true,
        serverOnlyImportGuard,
      },
      confidence: "high",
    };
  }

  // Generic / unknown framework
  return {
    value: {
      routeHandlersServerOnly: false,
      frameworkCatchesErrors: false,
      serverOnlyImportGuard: false,
    },
    confidence: "low",
  };
}
