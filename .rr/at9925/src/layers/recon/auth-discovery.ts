import { safeReadFile } from "../../utils/fs.js";
import type { AuthFlow } from "../../model/types.js";

export async function discoverAuthFlows(files: string[]): Promise<AuthFlow[]> {
  const flows: AuthFlow[] = [];

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx)$/.test(file)) continue;
    const source = await safeReadFile(file);

    if (/signInWithPassword|signInWithOAuth|signUp/.test(source)) {
      if (/signUp/.test(source)) flows.push({ type: "signup", file });
      if (/signInWithPassword/.test(source)) flows.push({ type: "login", file });
      if (/signInWithOAuth/.test(source)) flows.push({ type: "oauth", file });
    }
    if (/signInWithOtp|magicLink/i.test(source)) {
      flows.push({ type: "magic-link", file });
    }
  }

  return flows;
}
