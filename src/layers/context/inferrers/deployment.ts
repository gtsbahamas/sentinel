import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const VERCEL_PLATFORM_HANDLES = ["hsts", "ssl-termination", "ddos-protection"];

export function inferDeployment(
  model: ProjectModel
): InferResult<ProjectContext["deployment"]> {
  const isVercel =
    model.infra.vercelConfig !== null ||
    model.meta.deployTarget === "vercel";

  if (isVercel) {
    return {
      value: {
        platform: "vercel",
        platformHandles: VERCEL_PLATFORM_HANDLES,
      },
      confidence: "high",
    };
  }

  return {
    value: {
      platform: "unknown",
      platformHandles: [],
    },
    confidence: "low",
  };
}
