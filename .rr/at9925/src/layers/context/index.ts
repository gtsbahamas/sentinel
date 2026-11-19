import type { ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "./types.js";
import { inferTenancy } from "./inferrers/tenancy.js";
import { inferFramework } from "./inferrers/framework.js";
import { inferDeployment } from "./inferrers/deployment.js";
import { inferExcludedPaths } from "./inferrers/excluded-paths.js";
import { inferValidation } from "./inferrers/validation.js";
import { inferMigrations } from "./inferrers/migrations.js";
import { inferAuth } from "./inferrers/auth.js";
import { inferPublicRoutes } from "./inferrers/public-routes.js";
import { inferDelegations } from "./inferrers/delegations.js";

export { readContext, writeContext } from "./io.js";
export type { ProjectContext } from "./types.js";

export async function inferContext(model: ProjectModel): Promise<ProjectContext> {
  const [tenancy, framework, deployment, excludedPaths, validation, migrations, auth, publicRoutes, delegations] =
    await Promise.all([
      Promise.resolve(inferTenancy(model)),
      Promise.resolve(inferFramework(model)),
      Promise.resolve(inferDeployment(model)),
      Promise.resolve(inferExcludedPaths(model)),
      inferValidation(model),
      inferMigrations(model),
      inferAuth(model),
      inferPublicRoutes(model),
      inferDelegations(model),
    ]);

  const confidence: Record<string, "high" | "medium" | "low"> = {
    tenancy: tenancy.confidence,
    framework: framework.confidence,
    deployment: deployment.confidence,
    excludedPaths: excludedPaths.confidence,
    validation: validation.confidence,
    migrations: migrations.confidence,
    auth: auth.confidence,
    publicRoutes: publicRoutes.confidence,
    delegations: delegations.confidence,
  };

  return {
    tenancy: tenancy.value,
    publicRoutes: publicRoutes.value,
    validation: validation.value,
    migrations: migrations.value,
    framework: framework.value,
    excludedPaths: excludedPaths.value,
    auth: auth.value,
    deployment: deployment.value,
    delegations: delegations.value,
    version: 1,
    generatedAt: new Date().toISOString(),
    generatedBy: "auto",
    confidence,
  };
}
