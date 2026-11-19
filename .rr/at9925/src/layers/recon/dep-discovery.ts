import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import type { Dependency } from "../../model/types.js";

export async function discoverDependencies(projectPath: string): Promise<Dependency[]> {
  const pkgPath = join(projectPath, "package.json");
  if (!existsSync(pkgPath)) return [];
  const pkg = JSON.parse(await readFile(pkgPath, "utf-8"));
  const deps: Dependency[] = [];

  const addGroup = (obj: Record<string, string> | undefined, type: Dependency["type"]) => {
    if (!obj) return;
    for (const [name, version] of Object.entries(obj)) {
      deps.push({ name, version, type });
    }
  };

  addGroup(pkg.dependencies, "production");
  addGroup(pkg.devDependencies, "dev");
  addGroup(pkg.peerDependencies, "peer");
  addGroup(pkg.optionalDependencies, "optional");

  return deps;
}
