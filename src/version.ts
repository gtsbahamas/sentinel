import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

// The one place the scanner learns its own version: package.json, which sits
// one directory above both src/ and dist/. Anything that prints or reports a
// version imports VERSION from here.
const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");

export const VERSION: string = JSON.parse(readFileSync(pkgPath, "utf-8")).version;
