import type { Fixer } from "../types.js";
import type { Finding } from "../../../model/types.js";

const NEXT_CONFIG_PATTERN = /next\.config\.(js|mjs|ts)$/;

const HEADERS_BLOCK = `  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "X-DNS-Prefetch-Control", value: "on" },
        ],
      },
    ];
  },`;

// Matches the opening of the exported config object, e.g.:
//   const nextConfig = {
//   const config = {
// Captures everything up to and including the opening brace.
const CONFIG_OBJECT_OPEN = /((?:const|let|var)\s+\w+\s*=\s*\{)/;

function isNextConfigFile(finding: Finding): boolean {
  return finding.evidence.some((e) => NEXT_CONFIG_PATTERN.test(e.file));
}

export const infra006Fixer: Fixer = {
  ruleId: "INFRA-006",
  type: "deterministic",

  apply(fileContent: string, finding: Finding): string | null {
    if (!isNextConfigFile(finding)) {
      return null;
    }

    // Already has headers — nothing to do.
    if (fileContent.includes("X-Content-Type-Options")) {
      return null;
    }

    // Find the config object opening brace and insert headers() after it.
    const match = CONFIG_OBJECT_OPEN.exec(fileContent);
    if (!match) {
      return null;
    }

    const insertAfter = match.index + match[0].length;
    const before = fileContent.slice(0, insertAfter);
    const after = fileContent.slice(insertAfter);

    return `${before}\n${HEADERS_BLOCK}${after}`;
  },
};
