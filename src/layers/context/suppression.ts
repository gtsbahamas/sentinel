import { minimatch } from "minimatch";
import type { Finding, SuppressedFinding } from "../../model/types.js";
import type { ProjectContext } from "./types.js";

/**
 * Apply the project context to findings. A finding the context removes is
 * never dropped: it comes back in `suppressed` with the reason, and every
 * report counts and lists it. `findings` are the ones that still alarm
 * (some with a lowered severity).
 */
export function splitContextSuppressions(
  findings: Finding[],
  context: ProjectContext | null,
): { findings: Finding[]; suppressed: SuppressedFinding[] } {
  if (!context) return { findings, suppressed: [] };

  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const reason = suppressionReason(f, context);
    if (reason) {
      suppressed.push({ finding: f, reason });
      continue;
    }

    // Downgrade LOG-005 when framework catches errors
    if (f.ruleId === "LOG-005" && context.framework.frameworkCatchesErrors) {
      kept.push({ ...f, severity: "info" as const });
      continue;
    }

    // Downgrade SECRETS-008 (missing .env.example) to info
    if (f.ruleId === "SECRETS-008") {
      kept.push({ ...f, severity: "info" as const });
      continue;
    }

    kept.push(f);
  }
  return { findings: kept, suppressed };
}

/** The findings that still alarm. Use splitContextSuppressions() anywhere the result is shown to a person. */
export function applyContextSuppressions(
  findings: Finding[],
  context: ProjectContext | null,
): Finding[] {
  return splitContextSuppressions(findings, context).findings;
}

// Why the project context removes this finding, or null when it does not.
function suppressionReason(f: Finding, context: ProjectContext): string | null {
  // Findings in excluded paths
  const file = f.evidence[0]?.file ?? "";
  const excluded = context.excludedPaths.find((p) => file.includes(p));
  if (excluded !== undefined) return `path is excluded by project context (${excluded})`;

  // AUTH-001 on intentionally public routes
  if (f.ruleId === "AUTH-001") {
    const routePath = extractPathFromTitle(f.title);
    const publicRoute = routePath && context.publicRoutes.find((pr) => minimatch(routePath, pr.pattern));
    if (publicRoute) return `route is public by project context (${publicRoute.pattern})`;
  }

  // AUTH-010 when OAuth state is delegated
  if (f.ruleId === "AUTH-010") {
    if (context.delegations.some((d) => d.responsibility === "OAuth state verification")) {
      return "OAuth state verification is delegated by project context";
    }
  }

  // Probe HSTS findings when platform handles it
  if (f.title.toLowerCase().includes("strict-transport-security") &&
      context.deployment.platformHandles.includes("hsts")) {
    return `HSTS is handled by the deployment platform (${context.deployment.platform})`;
  }

  // INFRA-010 (supabase config)
  if (f.ruleId === "INFRA-010") return "INFRA-010 (supabase config) is always suppressed when a project context is in use";

  return null;
}

function extractPathFromTitle(title: string): string | null {
  const match = title.match(/(?:POST|GET|PUT|PATCH|DELETE)\s+(\/\S+)/);
  return match ? match[1] : null;
}
