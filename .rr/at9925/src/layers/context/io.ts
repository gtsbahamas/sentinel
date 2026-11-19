import { readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { ProjectContextSchema, type ProjectContext } from "./types.js";

const CONTEXT_DIR = ".sentinel";
const CONTEXT_FILE = "context.json";

export async function readContext(projectPath: string): Promise<ProjectContext | null> {
  const filePath = join(projectPath, CONTEXT_DIR, CONTEXT_FILE);
  try {
    const raw = await readFile(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    const result = ProjectContextSchema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export async function writeContext(projectPath: string, context: ProjectContext): Promise<string> {
  const dirPath = join(projectPath, CONTEXT_DIR);
  await mkdir(dirPath, { recursive: true });
  const filePath = join(dirPath, CONTEXT_FILE);
  await writeFile(filePath, JSON.stringify(context, null, 2) + "\n", "utf-8");
  return filePath;
}
