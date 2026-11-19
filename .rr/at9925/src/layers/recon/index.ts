import { walkProject } from "../../utils/fs.js";
import { detectStack } from "./stack-detector.js";
import { discoverRoutes } from "./route-discovery.js";
import { discoverEndpoints } from "./endpoint-discovery.js";
import { discoverAuthFlows } from "./auth-discovery.js";
import { discoverUploadHandlers } from "./upload-discovery.js";
import { discoverEnvVars } from "./env-discovery.js";
import { discoverDependencies } from "./dep-discovery.js";
import { discoverInfra } from "./infra-discovery.js";
import { inferAuthPatterns } from "./pattern-inference.js";
import { loadConfig } from "../../config.js";
import type { ProjectModel } from "../../model/types.js";
import type { ScanEventEmitter } from "../../dashboard/events.js";

export async function runRecon(
  projectPath: string,
  exclude: string[],
  emitter?: ScanEventEmitter,
): Promise<ProjectModel> {
  const meta = await detectStack(projectPath);
  const files = await walkProject(projectPath, exclude);

  const [routes, authFlows, fileUploads, envVars, dependencies, infra] = await Promise.all([
    discoverRoutes(projectPath, meta.framework),
    discoverAuthFlows(files),
    discoverUploadHandlers(files),
    discoverEnvVars(projectPath, files),
    discoverDependencies(projectPath),
    discoverInfra(projectPath),
  ]);

  const endpoints = await discoverEndpoints(routes);

  // Load config to pick up an optional `patternInference.excludePathSegments`
  // override. If the config file is missing or malformed, fall through with
  // null and let inferAuthPatterns apply its built-in defaults. The recon
  // layer must not crash on bad config.
  const config = await loadConfig(projectPath).catch(() => null);
  const excludePathSegments = config?.patternInference?.excludePathSegments;
  const inferredPatterns = await inferAuthPatterns(
    endpoints,
    excludePathSegments ? { excludePathSegments } : undefined,
  );

  if (emitter) {
    // Emit route events
    for (const route of routes) {
      if (route.isApi) {
        emitter.emitEvent({
          type: "recon:endpoint",
          data: {
            path: route.path,
            method: route.method ?? "GET",
            file: route.file,
            hasValidation: false,
            hasAuthCheck: route.hasAuthCheck ?? false,
            usesServiceRole: false,
          },
        });
      } else {
        emitter.emitEvent({
          type: "recon:route",
          data: {
            path: route.path,
            method: route.method ?? "GET",
            file: route.file,
            isApi: false,
            hasAuthCheck: route.hasAuthCheck ?? false,
          },
        });
      }
    }

    // Emit endpoint events
    for (const endpoint of endpoints) {
      emitter.emitEvent({
        type: "recon:endpoint",
        data: {
          path: endpoint.path,
          method: endpoint.method,
          file: endpoint.file,
          hasValidation: endpoint.hasValidation ?? false,
          hasAuthCheck: endpoint.hasAuthCheck ?? false,
          usesServiceRole: endpoint.usesServiceRole ?? false,
        },
      });

      // Emit edge for route-to-endpoint mapping
      emitter.emitEvent({
        type: "edge",
        data: {
          source: endpoint.file,
          target: endpoint.path,
          type: "exposes",
        },
      });
    }

    // Emit auth flow events
    for (const authFlow of authFlows) {
      emitter.emitEvent({
        type: "recon:authflow",
        data: {
          type: authFlow.type,
          file: authFlow.file,
          provider: authFlow.provider,
        },
      });
    }

    // Emit env var events
    for (const envVar of envVars) {
      emitter.emitEvent({
        type: "recon:envvar",
        data: {
          name: envVar.name,
          clientExposed: envVar.clientExposed ?? false,
          referencedIn: envVar.referencedIn ?? [],
        },
      });
    }
  }

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
    infra,
    findings: [],
    inferredPatterns,
  };
}
