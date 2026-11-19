import { readFile } from "fs/promises";
import { relative, dirname } from "path";
import fg from "fast-glob";
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
    files = await fg(`${model.meta.path}/src/**/*.{ts,tsx,js,jsx}`, {
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

  // Auto-detect custom token/link verifiers defined under src/lib. These are
  // application-owned auth primitives (e.g., `verifyReservationToken`) that
  // the AI layer would otherwise fail to recognize and flag as "missing auth".
  const customDelegations = await detectCustomVerifiers(model, files);
  for (const d of customDelegations) {
    const key = `${d.provider}::${d.responsibility}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(d);
  }

  const confidence: "high" | "medium" | "low" =
    results.length > 0 ? "high" : files.length > 0 ? "medium" : "low";

  return { value: results, confidence };
}

// Pattern for verifier exports we treat as custom auth primitives. We look
// for exported functions whose names start with `verify` and mention a token
// or link concept — the naming convention that app code uses for HMAC or
// nonce verification helpers.
const VERIFIER_EXPORT = /export\s+(?:async\s+)?function\s+(verify[A-Z][A-Za-z0-9]*(?:Token|Link|Signature|Code))\b/;

async function detectCustomVerifiers(
  model: ProjectModel,
  allFiles: string[],
): Promise<Delegation[]> {
  // 1. Find helper files under src/lib that export a verifier.
  const libFiles = allFiles.filter((f) => /\/src\/lib\//.test(f));
  type Verifier = { helperFile: string; fnName: string };
  const verifiers: Verifier[] = [];

  for (const file of libFiles) {
    let source = "";
    try {
      source = await readFile(file, "utf-8");
    } catch {
      continue;
    }
    const match = source.match(VERIFIER_EXPORT);
    if (match) {
      verifiers.push({ helperFile: file, fnName: match[1] });
    }
  }

  if (verifiers.length === 0) return [];

  // 2. For each verifier, find which route files import it. The AI prompt
  // uses these globs to scope the per-endpoint delegation hint.
  const results: Delegation[] = [];
  for (const v of verifiers) {
    const importers = await findImporters(allFiles, v.helperFile, v.fnName);
    const routeImporters = importers.filter((f) =>
      /\/src\/app\/(api\/)?[^/]+/.test(f),
    );
    if (routeImporters.length === 0) continue;

    const appliesTo = routeImporters
      .map((f) => relative(model.meta.path, f))
      .map((rel) => rel.replace(/^\.\/?/, ""));

    results.push({
      provider: "application",
      responsibility: "custom token verification",
      mechanism: v.fnName,
      appliesTo,
    });
  }

  return results;
}

async function findImporters(
  allFiles: string[],
  helperFile: string,
  fnName: string,
): Promise<string[]> {
  // Two markers: the helper's directory via "@/lib/..." alias or a relative
  // path, plus the verifier name appearing in an import statement.
  const helperBase = helperFile.replace(/\.[tj]sx?$/, "");
  const libMarkerMatch = helperBase.match(/\/src\/lib\/(.+)$/);
  const libAlias = libMarkerMatch ? `@/lib/${libMarkerMatch[1]}` : null;

  const result: string[] = [];
  for (const file of allFiles) {
    if (file === helperFile) continue;
    let source = "";
    try {
      source = await readFile(file, "utf-8");
    } catch {
      continue;
    }
    if (!source.includes(fnName)) continue;
    const importLine = new RegExp(
      `import[^;]*\\b${fnName}\\b[^;]*from\\s+["'][^"']+["']`,
    );
    if (!importLine.test(source)) continue;
    // Also confirm the import resolves to our helper (by alias or relative).
    const importsFromHelper =
      (libAlias && source.includes(libAlias)) ||
      source.includes(`/${dirname(helperFile).split("/").pop()}/`);
    if (!importsFromHelper && !libAlias) continue;
    result.push(file);
  }
  return result;
}
