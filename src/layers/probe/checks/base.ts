import type {
  AggressionLevel,
  Finding,
  ProbeFinding,
  ProbeError,
  ProbeTarget,
  ProjectModel,
  SecurityDomain,
} from "../../../model/types.js";
import type { HttpClient } from "../http-client.js";
import type { CleanupRegistry } from "../cleanup-registry.js";

export interface ProbeCheck {
  readonly id: string;
  readonly level: AggressionLevel;
  readonly domain: SecurityDomain;
  readonly description: string;

  appliesTo(target: ProbeTarget, model: ProjectModel): boolean;

  run(ctx: ProbeCheckContext): Promise<ProbeCheckResult>;
}

export interface ProbeCheckContext {
  target: ProbeTarget;
  model: ProjectModel;
  client: HttpClient;
  registry: CleanupRegistry;
  priorFindings: readonly Finding[];
  runId: string;
}

export interface ProbeCheckResult {
  findings: ProbeFinding[];
  confirmed: Array<{ findingId: string }>;
  refuted: Array<{ findingId: string }>;
  errors: ProbeError[];
}

const probeChecks: ProbeCheck[] = [];

export function registerProbeCheck(check: ProbeCheck): void {
  probeChecks.push(check);
}

export function getProbeChecks(level?: AggressionLevel): ProbeCheck[] {
  if (!level) return [...probeChecks];
  const levelOrder: AggressionLevel[] = ["passive", "standard", "intrusive"];
  const maxIdx = levelOrder.indexOf(level);
  return probeChecks.filter((c) => levelOrder.indexOf(c.level) <= maxIdx);
}

export function resetProbeRegistry(): void {
  probeChecks.length = 0;
}
