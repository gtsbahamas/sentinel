import type { Fixer } from "../types.js";

// Matches: export async function GET(... { ... }
// Captures: (1) method name, (2) params+opening-brace, (3) body content, (4) closing-brace position
const HANDLER_RE =
  /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*(\([^)]*\)\s*(?::\s*\S+\s*)?\{)([\s\S]*?)(\n\})/g;

function bodyHasTryCatch(body: string): boolean {
  // Trim leading whitespace/newlines then check if it starts with try
  return /^\s*try\s*\{/.test(body);
}

function indentLines(text: string, indent: string): string {
  return text
    .split("\n")
    .map((line) => (line.trim() === "" ? line : indent + line))
    .join("\n");
}

export const log005Fixer: Fixer = {
  ruleId: "LOG-005",
  type: "deterministic",

  apply(fileContent: string): string | null {
    let modified = fileContent;
    let anyChange = false;

    // Collect all matches first (process last to first to preserve offsets)
    const matches: Array<{
      fullMatch: string;
      method: string;
      signature: string;
      body: string;
      index: number;
    }> = [];

    let match: RegExpExecArray | null;
    HANDLER_RE.lastIndex = 0;
    while ((match = HANDLER_RE.exec(fileContent)) !== null) {
      matches.push({
        fullMatch: match[0],
        method: match[1],
        signature: match[2],
        body: match[3],
        index: match.index,
      });
    }

    // Process from last to first to keep earlier offsets valid
    for (let i = matches.length - 1; i >= 0; i--) {
      const { fullMatch, method, signature, body, index } = matches[i];

      if (bodyHasTryCatch(body)) {
        continue;
      }

      // Determine base indentation of the handler body lines
      const bodyIndent = "  ";

      const indentedBody = indentLines(body.trimEnd(), bodyIndent);

      const catchBlock = [
        `} catch (error) {`,
        `  console.error(\`${method} handler failed:\`, error);`,
        `  return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });`,
        `}`,
      ]
        .map((line) => bodyIndent + line)
        .join("\n");

      const wrappedBody = `\n${bodyIndent}try {${indentedBody}\n${catchBlock}`;

      const replacement = `export async function ${method}${signature}${wrappedBody}\n}`;

      modified =
        modified.slice(0, index) +
        replacement +
        modified.slice(index + fullMatch.length);

      anyChange = true;
    }

    return anyChange ? modified : null;
  },
};
