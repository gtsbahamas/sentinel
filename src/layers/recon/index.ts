import { walkProject } from "../../utils/fs.js";
import { detectStack } from "./stack-detector.js";
import { discoverRoutes } from "./route-discovery.js";
import { discoverEndpoints } from "./endpoint-discovery.js";
import { discoverAuthFlows } from "./auth-discovery.js";
import { discoverUploadHandlers } from "./upload-discovery.js";
import { discoverEnvVars } from "./env-discovery.js";
import { discoverDependencies } from "./dep-discovery.js";
import type { ProjectModel } from "../../model/types.js";

export async function runRecon(
  projectPath: string,
  exclude: string[],
): Promise<ProjectModel> {
  const meta = await detectStack(projectPath);
  const files = await walkProject(projectPath, exclude);

  const [routes, authFlows, fileUploads, envVars, dependencies] = await Promise.all([
    discoverRoutes(projectPath, meta.framework),
    discoverAuthFlows(files),
    discoverUploadHandlers(files),
    discoverEnvVars(projectPath, files),
    discoverDependencies(projectPath),
  ]);

  const endpoints = await discoverEndpoints(routes);

  return {
    meta,
    routes,
    endpoints,
    fileUploads,
    authFlows,
    dataModels: [],
    dependencies,
    envVars,
    staticAssets: [],
    findings: [],
  };
}
