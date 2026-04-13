import type { Fixer } from "../types.js";

const IMPORT_LINE = `import { randomUUID } from "node:crypto";`;

// Matches: Math.random().toString(36).substring(<anything>)
const PATTERN_CHAIN = /Math\.random\(\)\.toString\(36\)\.substring\([^)]*\)/g;
// Matches any remaining bare Math.random()
const PATTERN_BARE = /Math\.random\(\)/g;

export const crypto001Fixer: Fixer = {
  ruleId: "CRYPTO-001",
  type: "deterministic",

  apply(fileContent: string): string | null {
    if (!fileContent.includes("Math.random()")) {
      return null;
    }

    let result = fileContent;

    // Replace chained patterns first (more specific)
    result = result.replace(PATTERN_CHAIN, "crypto.randomUUID()");

    // Replace any remaining bare calls
    result = result.replace(PATTERN_BARE, "crypto.randomUUID()");

    // Add import if not already present
    if (!result.includes(IMPORT_LINE)) {
      result = `${IMPORT_LINE}\n${result}`;
    }

    return result;
  },
};
