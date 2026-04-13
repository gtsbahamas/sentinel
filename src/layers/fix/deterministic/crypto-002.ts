import type { Fixer } from "../types.js";

const MD5_PATTERN = /createHash\((['"])md5\1\)/g;

export const crypto002Fixer: Fixer = {
  ruleId: "CRYPTO-002",
  type: "deterministic",
  apply(fileContent: string): string | null {
    const hasMd5 = MD5_PATTERN.test(fileContent);
    MD5_PATTERN.lastIndex = 0;
    return hasMd5
      ? fileContent.replace(MD5_PATTERN, (_match, quote) => `createHash(${quote}sha256${quote})`)
      : null;
  },
};
