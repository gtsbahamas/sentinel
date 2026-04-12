import type { Finding, ProjectModel, ProbeTarget } from "../../model/types.js";

export function resolveTargets(
  model: ProjectModel,
  findings: Finding[],
  targetUrl: string,
): ProbeTarget[] {
  const targets: ProbeTarget[] = [];
  const seen = new Set<string>();

  const baseUrl = targetUrl.replace(/\/+$/, "");

  targets.push({
    kind: "baseline",
    url: baseUrl,
    method: "GET",
    auth: "unauthenticated",
    fromLayer: "recon",
  });
  seen.add(`GET:${baseUrl}`);

  for (const ep of model.endpoints) {
    const url = `${baseUrl}${ep.path}`;
    const key = `${ep.method}:${url}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const relatedFindings = findings.filter(
      (f) => f.evidence.some((e) => e.file === ep.file),
    );

    const route = model.routes.find((r) => r.path === ep.path && r.method === ep.method);

    targets.push({
      kind: "endpoint",
      url,
      method: ep.method,
      auth: ep.hasAuthCheck ? "required" : "unauthenticated",
      fromLayer: relatedFindings.length > 0 ? relatedFindings[0].layer : "recon",
      fromFindingId: relatedFindings[0]?.id,
      inputs: route?.paramNames.map((name: string) => ({
        name,
        in: "path" as const,
        type: "uuid" as const,
      })),
    });
  }

  for (const finding of findings) {
    for (const ev of finding.evidence) {
      const ep = model.endpoints.find((e) => e.file === ev.file);
      if (!ep) continue;
      const url = `${baseUrl}${ep.path}`;
      const key = `${ep.method}:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);

      targets.push({
        kind: "endpoint",
        url,
        method: ep.method,
        auth: ep.hasAuthCheck ? "required" : "unauthenticated",
        fromLayer: finding.layer,
        fromFindingId: finding.id,
      });
    }
  }

  return targets;
}
