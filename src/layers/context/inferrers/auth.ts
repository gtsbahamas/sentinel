import { readFile } from "fs/promises";
import { glob } from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const ANON_PATTERNS = [
  /\bcreateClient\b/,
  /SUPABASE_ANON_KEY\b/,
  /NEXT_PUBLIC_SUPABASE_ANON_KEY\b/,
];

const SERVICE_ROLE_PATTERNS = [
  /\bcreateServiceClient\b/,
  /SUPABASE_SERVICE_ROLE_KEY\b/,
];

const ROLE_CHECK_RE = /supabase\.rpc\(['"`]is_(\w+)['"`]\)/g;

export async function inferAuth(
  model: ProjectModel
): Promise<InferResult<ProjectContext["auth"]>> {
  const pattern = `${model.meta.path}/src/app/api/**/*.ts`;
  let files: string[] = [];
  try {
    files = await glob(pattern, { onlyFiles: true });
  } catch {
    // If glob fails, fall through with empty list
  }

  let anonCount = 0;
  let serviceCount = 0;
  const roleNames = new Set<string>();
  let firstRoleCheckPattern: string | undefined;

  for (const file of files) {
    let source = "";
    try {
      source = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    const hasAnon = ANON_PATTERNS.some((re) => re.test(source));
    const hasService = SERVICE_ROLE_PATTERNS.some((re) => re.test(source));

    if (hasAnon) anonCount++;
    if (hasService) serviceCount++;

    let match: RegExpExecArray | null;
    const re = new RegExp(ROLE_CHECK_RE.source, "g");
    while ((match = re.exec(source)) !== null) {
      roleNames.add(match[1]);
      if (!firstRoleCheckPattern) {
        firstRoleCheckPattern = match[0];
      }
    }
  }

  const defaultClient: "anon" | "service-role" =
    serviceCount > anonCount ? "service-role" : "anon";

  const total = anonCount + serviceCount;
  let confidence: "high" | "medium" | "low";
  if (total === 0) {
    confidence = "low";
  } else if (total >= 3) {
    confidence = "high";
  } else {
    confidence = "medium";
  }

  return {
    value: {
      defaultClient,
      roleModel: [...roleNames],
      ...(firstRoleCheckPattern
        ? { roleCheckPattern: firstRoleCheckPattern }
        : {}),
    },
    confidence,
  };
}
