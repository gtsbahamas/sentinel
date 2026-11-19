import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { safeReadFile } from "../../utils/fs.js";
import type { EnvVar } from "../../model/types.js";

const ENV_REFERENCE = /process\.env\.([A-Z0-9_]+)|import\.meta\.env\.([A-Z0-9_]+)/g;

export async function discoverEnvVars(
  projectPath: string,
  files: string[],
): Promise<EnvVar[]> {
  const usage = new Map<string, Set<string>>();

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) continue;
    const source = await safeReadFile(file);
    let match;
    const regex = new RegExp(ENV_REFERENCE.source, "g");
    while ((match = regex.exec(source)) !== null) {
      const name = match[1] ?? match[2];
      if (!name) continue;
      if (!usage.has(name)) usage.set(name, new Set());
      usage.get(name)!.add(file);
    }
  }

  const examplePath = join(projectPath, ".env.example");
  const exampleVars = new Set<string>();
  if (existsSync(examplePath)) {
    const content = await readFile(examplePath, "utf-8");
    for (const line of content.split("\n")) {
      const m = line.match(/^([A-Z0-9_]+)\s*=/);
      if (m) exampleVars.add(m[1]);
    }
  }

  const result: EnvVar[] = [];
  for (const [name, refs] of usage.entries()) {
    result.push({
      name,
      clientExposed: name.startsWith("NEXT_PUBLIC_") || name.startsWith("VITE_") || name.startsWith("PUBLIC_"),
      referencedIn: Array.from(refs),
      inExample: exampleVars.has(name),
    });
  }

  return result;
}
