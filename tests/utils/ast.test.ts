import { describe, it, expect } from "vitest";
import {
  parseSource,
  findIdentifierUsages,
  findImportsFrom,
  findStringLiterals,
  walkAst,
} from "../../src/utils/ast.js";
import ts from "typescript";

describe("ast utils", () => {
  it("parses TypeScript source into a SourceFile", () => {
    const source = `const x = 42;`;
    const sf = parseSource("test.ts", source);
    expect(sf.fileName).toBe("test.ts");
  });

  it("finds identifier usages", () => {
    const source = `import { foo } from "mod"; foo(); foo();`;
    const sf = parseSource("test.ts", source);
    const usages = findIdentifierUsages(sf, "foo");
    expect(usages.length).toBeGreaterThanOrEqual(2);
  });

  it("finds imports from a specific module", () => {
    const source = `
      import { createClient } from "@supabase/supabase-js";
      import { a } from "other";
    `;
    const sf = parseSource("test.ts", source);
    const imports = findImportsFrom(sf, "@supabase/supabase-js");
    expect(imports).toContain("createClient");
  });

  it("finds string literals", () => {
    const source = `const secret = "sk-abc123"; const url = "https://x.com";`;
    const sf = parseSource("test.ts", source);
    const literals = findStringLiterals(sf);
    expect(literals).toContain("sk-abc123");
    expect(literals).toContain("https://x.com");
  });

  it("walks all nodes", () => {
    const source = `function a() { return 1; }`;
    const sf = parseSource("test.ts", source);
    let count = 0;
    walkAst(sf, () => { count++; });
    expect(count).toBeGreaterThan(5);
  });
});
