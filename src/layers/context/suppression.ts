import { minimatch } from "minimatch";
import type { Finding } from "../../model/types.js";
import type { ProjectContext } from "./types.js";

export function applyContextSuppressions(
  findings: Finding[],
  context: ProjectContext | null,
): Finding[] {
  if (!context) return findings;

  return findings
    .map((f) => {
      // Suppress findings in excluded paths
      const file = f.evidence[0]?.file ?? "";
      if (context.excludedPaths.some((p) => file.includes(p))) {
        return null;
      }

      // Suppress AUTH-001 on intentionally public routes
      if (f.ruleId === "AUTH-001") {
        const routePath = extractPathFromTitle(f.title);
        if (routePath && context.publicRoutes.some((pr) => minimatch(routePath, pr.pattern))) {
          return null;
        }
      }

      // Suppress AUTH-010 when OAuth state is delegated
      if (f.ruleId === "AUTH-010") {
        if (context.delegations.some((d) => d.responsibility === "OAuth state verification")) {
          return null;
        }
      }

      // Downgrade LOG-005 when framework catches errors
      if (f.ruleId === "LOG-005" && context.framework.frameworkCatchesErrors) {
        return { ...f, severity: "info" as const };
      }

      // Suppress probe HSTS findings when platform handles it
      if (f.title.toLowerCase().includes("strict-transport-security") &&
          context.deployment.platformHandles.includes("hsts")) {
        return null;
      }

      // Suppress INFRA-010 (supabase config)
      if (f.ruleId === "INFRA-010") {
        return null;
      }

      // Downgrade SECRETS-008 (missing .env.example) to info
      if (f.ruleId === "SECRETS-008") {
        return { ...f, severity: "info" as const };
      }

      return f;
    })
    .filter((f): f is Finding => f !== null);
}

function extractPathFromTitle(title: string): string | null {
  const match = title.match(/(?:POST|GET|PUT|PATCH|DELETE)\s+(\/\S+)/);
  return match ? match[1] : null;
}
