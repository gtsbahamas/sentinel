import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const TENANT_TABLE_PATTERNS = [
  /\btenant/i,
  /\borg(?:anization)?s?\b/i,
  /\bworkspace/i,
];

const TENANT_COLUMN_PATTERNS = [
  /^tenant_id$/i,
  /^org_id$/i,
  /^organization_id$/i,
  /^workspace_id$/i,
];

function hasTenantLikeName(name: string): boolean {
  // Check if the table name itself looks like a tenant-scoping column name
  return TENANT_COLUMN_PATTERNS.some((re) => re.test(name));
}

function tableNameSuggestsTenancy(name: string): boolean {
  return TENANT_TABLE_PATTERNS.some((re) => re.test(name));
}

export function inferTenancy(
  model: ProjectModel
): InferResult<ProjectContext["tenancy"]> {
  const tables = model.dataModels;

  if (tables.length === 0) {
    return { value: "single-org", confidence: "low" };
  }

  // Count tables whose names match tenant-column patterns (e.g. a table literally
  // named "tenant_id" is unusual, but we also look for tables named "tenants",
  // "organizations", "workspaces" as strong signals of multi-tenancy architecture).
  const tenantColumnMatches = tables.filter((dm) => hasTenantLikeName(dm.name));
  const tenantTableMatches = tables.filter((dm) =>
    tableNameSuggestsTenancy(dm.name)
  );

  const strongSignals = tenantColumnMatches.length + tenantTableMatches.length;

  if (strongSignals === 0) {
    return { value: "single-org", confidence: "medium" };
  }

  // If more than half the tables have tenant-like signals, it's clearly multi-tenant
  const ratio = strongSignals / tables.length;
  if (ratio > 0.5) {
    return { value: "multi-tenant", confidence: "high" };
  }

  // Some signals present but not dominant
  return { value: "multi-tenant", confidence: "medium" };
}
