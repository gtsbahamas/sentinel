import type { ProjectModel } from "../../../model/types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const DEFAULT_EXCLUDED_PATHS = [
  "scripts/",
  "seed.ts",
  "tests/",
  "__tests__/",
  "cypress/",
  "e2e/",
];

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function inferExcludedPaths(_model: ProjectModel): InferResult<string[]> {
  return {
    value: DEFAULT_EXCLUDED_PATHS,
    confidence: "high",
  };
}
