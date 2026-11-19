import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const VALIDATION_LIBS = ["zod", "joi", "yup", "ajv"];
const SCHEMA_GLOBS = ["**/validation/**/*.ts", "**/schemas/**/*.ts", "**/validators/**/*.ts"];

export async function inferValidation(model: ProjectModel): Promise<InferResult<ProjectContext["validation"]>> {
  const lib = VALIDATION_LIBS.find((l) => model.dependencies.some((d) => d.name === l));
  if (!lib) {
    return { value: { library: "none", schemaLocations: [], importedByRoutes: false }, confidence: "high" };
  }

  const schemaFiles = await fg(SCHEMA_GLOBS, { cwd: model.meta.path, absolute: false, ignore: ["**/node_modules/**"] });
  if (schemaFiles.length === 0) {
    return { value: { library: lib as any, schemaLocations: [], importedByRoutes: false }, confidence: "medium" };
  }

  // Check how many mutation routes import from schema locations
  const mutationEndpoints = model.endpoints.filter((e) =>
    ["POST", "PUT", "PATCH", "DELETE"].includes(e.method),
  );

  let importCount = 0;
  for (const ep of mutationEndpoints) {
    try {
      const source = await readFile(ep.file, "utf-8");
      const firstLines = source.split("\n").slice(0, 15).join("\n");
      const importsValidation = firstLines.includes("validation/") || firstLines.includes("schemas/") || firstLines.includes("validators/");
      if (importsValidation) importCount++;
    } catch { /* skip */ }
  }

  const ratio = mutationEndpoints.length > 0 ? importCount / mutationEndpoints.length : 0;
  const importedByRoutes = ratio > 0.3;
  const confidence = ratio > 0.8 ? "high" : ratio > 0.3 ? "medium" : "low";

  return {
    value: { library: lib as any, schemaLocations: schemaFiles, importedByRoutes },
    confidence,
  };
}
