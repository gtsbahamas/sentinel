import { readFile } from "fs/promises";
import { glob } from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

type Delegation = ProjectContext["delegations"][number];

interface DelegationSignal {
  dep: string;
  sourcePattern: RegExp;
  provider: string;
  responsibility: string;
  mechanism?: string;
}

const DELEGATION_SIGNALS: DelegationSignal[] = [
  {
    dep: "@supabase/ssr",
    sourcePattern: /exchangeCodeForSession/,
    provider: "supabase",
    responsibility: "OAuth state verification",
    mechanism: "exchangeCodeForSession",
  },
  {
    dep: "@supabase/ssr",
    sourcePattern: /supabase\.auth\.getUser\b/,
    provider: "supabase",
    responsibility: "JWT verification",
    mechanism: "supabase.auth.getUser",
  },
];

export async function inferDelegations(
  model: ProjectModel
): Promise<InferResult<ProjectContext["delegations"]>> {
  const depNames = new Set(model.dependencies.map((d) => d.name));

  // Collect signals whose dep is present
  const activeSets = DELEGATION_SIGNALS.filter((s) => depNames.has(s.dep));

  if (activeSets.length === 0) {
    return { value: [], confidence: "high" };
  }

  // Scan source files for actual usage
  let files: string[] = [];
  try {
    files = await glob(`${model.meta.path}/src/**/*.{ts,tsx,js,jsx}`, {
      onlyFiles: true,
    });
  } catch {
    // Fall back to dep-only detection
  }

  const foundResponsibilities = new Set<string>();

  for (const file of files) {
    let source = "";
    try {
      source = await readFile(file, "utf-8");
    } catch {
      continue;
    }
    for (const signal of activeSets) {
      if (signal.sourcePattern.test(source)) {
        foundResponsibilities.add(signal.responsibility);
      }
    }
  }

  // Deduplicate by provider + responsibility
  const seen = new Set<string>();
  const results: Delegation[] = [];

  for (const signal of activeSets) {
    if (!foundResponsibilities.has(signal.responsibility)) continue;
    const key = `${signal.provider}::${signal.responsibility}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({
      provider: signal.provider,
      responsibility: signal.responsibility,
      ...(signal.mechanism ? { mechanism: signal.mechanism } : {}),
    });
  }

  const confidence: "high" | "medium" | "low" =
    results.length > 0 ? "high" : files.length > 0 ? "medium" : "low";

  return { value: results, confidence };
}
