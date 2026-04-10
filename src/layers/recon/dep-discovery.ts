import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency } from "../../model/types.js";

export async function discoverDependencies(projectPath: string): Promise<Dependency[]> {
  const pkg = JSON.parse(await readFile(join(projectPath, "package.json"), "utf-8"));
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
