import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const RLS_PATTERN = /ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;

export async function inferMigrations(model: ProjectModel): Promise<InferResult<ProjectContext["migrations"]>> {
  const migrationFiles = await fg(["supabase/migrations/**/*.sql", "migrations/**/*.sql"], {
    cwd: model.meta.path, absolute: true, ignore: ["**/node_modules/**"],
  });

  if (migrationFiles.length === 0) {
    return { value: { rlsStrategy: "none" }, confidence: "high" };
  }

  const filesWithRls: string[] = [];
  for (const file of migrationFiles) {
    try {
      const source = await readFile(file, "utf-8");
      if (RLS_PATTERN.test(source)) {
        filesWithRls.push(file);
      }
      RLS_PATTERN.lastIndex = 0; // reset global regex
    } catch { /* skip */ }
  }

  if (filesWithRls.length === 0) {
    return { value: { rlsStrategy: "none" }, confidence: "high" };
  }

  if (filesWithRls.length === 1) {
    const relative = filesWithRls[0].replace(model.meta.path + "/", "");
    return { value: { rlsStrategy: "dedicated-file", rlsFile: relative }, confidence: "high" };
  }

  return { value: { rlsStrategy: "co-located" }, confidence: "high" };
}
