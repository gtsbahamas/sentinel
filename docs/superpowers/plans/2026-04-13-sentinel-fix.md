# Sentinel Fix Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `sentinel fix` command that auto-remediates security findings using deterministic transforms and AI-powered patches.

**Architecture:** Fix command runs a scan (or loads a report), classifies findings into fix strategies (deterministic/ai/manual), groups by file, applies deterministic transforms first, then AI fixes. Results are reported with counts of fixed/skipped/failed.

**Tech Stack:** TypeScript, Vitest, Anthropic/OpenAI SDKs (existing), Zod (existing)

**Spec:** `docs/superpowers/specs/2026-04-13-sentinel-fix-design.md`

---

## File Structure

```
src/commands/fix.ts                    # CLI command + orchestration
src/layers/fix/index.ts                # Fix runner: classify, group, apply, report
src/layers/fix/registry.ts             # Fixer registration (Map<ruleId, Fixer>)
src/layers/fix/types.ts                # Fixer interface, FixResult types
src/layers/fix/deterministic/
  +-- crypto-001.ts                    # Math.random replacement
  +-- crypto-002.ts                    # MD5 -> SHA-256
  +-- log-005.ts                       # try/catch wrapper
  +-- infra-006.ts                     # Security headers
src/layers/fix/ai/
  +-- index.ts                         # AI fix runner
  +-- prompts.ts                       # Prompt templates per rule
  +-- validator.ts                     # Validate AI response before writing
tests/layers/fix/
  +-- registry.test.ts                 # Fixer registry tests
  +-- deterministic/
  |   +-- crypto-001.test.ts
  |   +-- crypto-002.test.ts
  |   +-- log-005.test.ts
  |   +-- infra-006.test.ts
  +-- ai/
  |   +-- validator.test.ts
  |   +-- prompts.test.ts
tests/commands/fix.test.ts             # CLI integration test
```

---

### Task 1: Fix Types and Registry

**Files:**
- Create: `src/layers/fix/types.ts`
- Create: `src/layers/fix/registry.ts`
- Test: `tests/layers/fix/registry.test.ts`

- [ ] **Step 1: Write the failing test for fixer registry**

```typescript
// tests/layers/fix/registry.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import {
  registerFixer,
  getFixer,
  getAllFixers,
  resetFixerRegistry,
} from "../../../src/layers/fix/registry.js";
import type { Fixer } from "../../../src/layers/fix/types.js";

describe("fixer registry", () => {
  beforeEach(() => {
    resetFixerRegistry();
  });

  it("registers and retrieves a deterministic fixer", () => {
    const fixer: Fixer = {
      ruleId: "CRYPTO-001",
      type: "deterministic",
      apply: (content, _finding) => content.replace("Math.random()", "crypto.randomUUID()"),
    };
    registerFixer(fixer);
    expect(getFixer("CRYPTO-001")).toBe(fixer);
  });

  it("registers and retrieves an AI fixer", () => {
    const fixer: Fixer = {
      ruleId: "INPUT-005",
      type: "ai",
      aiPromptId: "input-005",
    };
    registerFixer(fixer);
    expect(getFixer("INPUT-005")).toBe(fixer);
  });

  it("returns undefined for unregistered rule", () => {
    expect(getFixer("NONEXISTENT")).toBeUndefined();
  });

  it("getAllFixers returns all registered fixers", () => {
    registerFixer({ ruleId: "A", type: "deterministic", apply: () => null });
    registerFixer({ ruleId: "B", type: "ai", aiPromptId: "b" });
    expect(getAllFixers()).toHaveLength(2);
  });

  it("resetFixerRegistry clears all fixers", () => {
    registerFixer({ ruleId: "A", type: "deterministic", apply: () => null });
    resetFixerRegistry();
    expect(getAllFixers()).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run tests/layers/fix/registry.test.ts`
Expected: FAIL (modules not found)

- [ ] **Step 3: Create types.ts**

```typescript
// src/layers/fix/types.ts
import type { Finding } from "../../model/types.js";

export interface Fixer {
  ruleId: string;
  type: "deterministic" | "ai";
  /** Deterministic: transform file content. Return null if unable to fix. */
  apply?: (fileContent: string, finding: Finding) => string | null;
  /** AI: prompt template ID looked up in prompts.ts */
  aiPromptId?: string;
}

export interface FixAttempt {
  findingId: string;
  ruleId: string;
  file: string;
  strategy: "deterministic" | "ai" | "manual";
  status: "fixed" | "skipped" | "failed";
  reason?: string;
  description?: string;
}

export interface FixResult {
  attempts: FixAttempt[];
  filesModified: string[];
}
```

- [ ] **Step 4: Create registry.ts**

```typescript
// src/layers/fix/registry.ts
import type { Fixer } from "./types.js";

const registry = new Map<string, Fixer>();

export function registerFixer(fixer: Fixer): void {
  registry.set(fixer.ruleId, fixer);
}

export function getFixer(ruleId: string): Fixer | undefined {
  return registry.get(ruleId);
}

export function getAllFixers(): Fixer[] {
  return Array.from(registry.values());
}

export function resetFixerRegistry(): void {
  registry.clear();
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/layers/fix/registry.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add src/layers/fix/types.ts src/layers/fix/registry.ts tests/layers/fix/registry.test.ts
git commit -m "feat(fix): add fixer types and registry"
```

---

### Task 2: Deterministic Fixer - CRYPTO-001 (Math.random)

**Files:**
- Create: `src/layers/fix/deterministic/crypto-001.ts`
- Test: `tests/layers/fix/deterministic/crypto-001.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/layers/fix/deterministic/crypto-001.test.ts
import { describe, it, expect } from "vitest";
import { crypto001Fixer } from "../../../../src/layers/fix/deterministic/crypto-001.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(file: string, line: number): Finding {
  return {
    id: `CRYPTO-001-${file}-${line}`,
    ruleId: "CRYPTO-001",
    domain: "cryptography",
    severity: "critical",
    confidence: "confirmed",
    title: "Math.random() in a security-sensitive context",
    description: "",
    impact: "",
    evidence: [{ file, line }],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

describe("crypto-001 fixer", () => {
  it("replaces Math.random() with crypto.randomUUID() in string context", () => {
    const input = `const token = Math.random().toString(36).substring(2);`;
    const result = crypto001Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toContain("crypto.randomUUID()");
    expect(result).not.toContain("Math.random()");
  });

  it("adds crypto import when missing", () => {
    const input = `const token = Math.random().toString(36);`;
    const result = crypto001Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toContain('import { randomUUID } from "node:crypto"');
  });

  it("does not duplicate crypto import", () => {
    const input = `import { randomUUID } from "node:crypto";\nconst token = Math.random().toString(36);`;
    const result = crypto001Fixer.apply!(input, makeFinding("test.ts", 2));
    const importCount = (result!.match(/import.*randomUUID/g) || []).length;
    expect(importCount).toBe(1);
  });

  it("is idempotent — running twice produces same result", () => {
    const input = `const token = Math.random().toString(36);`;
    const first = crypto001Fixer.apply!(input, makeFinding("test.ts", 1));
    const second = crypto001Fixer.apply!(first!, makeFinding("test.ts", 1));
    expect(second).toBe(first);
  });

  it("returns null if no Math.random() found", () => {
    const input = `const x = 42;`;
    const result = crypto001Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/fix/deterministic/crypto-001.test.ts`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement the fixer**

```typescript
// src/layers/fix/deterministic/crypto-001.ts
import type { Fixer } from "../types.js";

export const crypto001Fixer: Fixer = {
  ruleId: "CRYPTO-001",
  type: "deterministic",
  apply(content, _finding) {
    if (!content.includes("Math.random()")) return null;

    let result = content;

    // Replace Math.random() usages with crypto.randomUUID()
    // Common patterns: Math.random().toString(36), Math.random() * N
    result = result.replace(
      /Math\.random\(\)\.toString\(\d+\)[^;]*/g,
      "crypto.randomUUID()",
    );
    // Fallback: any remaining Math.random() in non-math contexts
    result = result.replace(/Math\.random\(\)/g, "crypto.randomUUID()");

    // Add import if not present
    if (!result.match(/import\s.*randomUUID.*from\s+["']node:crypto["']/)) {
      if (!result.match(/import\s.*from\s+["']node:crypto["']/)) {
        result = 'import { randomUUID } from "node:crypto";\n' + result;
      }
    }

    return result === content ? null : result;
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/fix/deterministic/crypto-001.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/fix/deterministic/crypto-001.ts tests/layers/fix/deterministic/crypto-001.test.ts
git commit -m "feat(fix): deterministic fixer for CRYPTO-001 (Math.random)"
```

---

### Task 3: Deterministic Fixer - CRYPTO-002 (MD5)

**Files:**
- Create: `src/layers/fix/deterministic/crypto-002.ts`
- Test: `tests/layers/fix/deterministic/crypto-002.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/layers/fix/deterministic/crypto-002.test.ts
import { describe, it, expect } from "vitest";
import { crypto002Fixer } from "../../../../src/layers/fix/deterministic/crypto-002.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(file: string, line: number): Finding {
  return {
    id: `CRYPTO-002-${file}-${line}`,
    ruleId: "CRYPTO-002",
    domain: "cryptography",
    severity: "critical",
    confidence: "confirmed",
    title: "MD5 used as a hash function",
    description: "",
    impact: "",
    evidence: [{ file, line }],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

describe("crypto-002 fixer", () => {
  it("replaces createHash('md5') with createHash('sha256')", () => {
    const input = `const hash = createHash('md5').update(data).digest('hex');`;
    const result = crypto002Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toContain("createHash('sha256')");
    expect(result).not.toContain("createHash('md5')");
  });

  it("handles double-quoted md5", () => {
    const input = `const hash = createHash("md5").update(data).digest("hex");`;
    const result = crypto002Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toContain('createHash("sha256")');
  });

  it("returns null if no md5 found", () => {
    const input = `const hash = createHash('sha256').update(data).digest('hex');`;
    const result = crypto002Fixer.apply!(input, makeFinding("test.ts", 1));
    expect(result).toBeNull();
  });

  it("is idempotent", () => {
    const input = `const hash = createHash('md5').update(data).digest('hex');`;
    const first = crypto002Fixer.apply!(input, makeFinding("test.ts", 1));
    const second = crypto002Fixer.apply!(first!, makeFinding("test.ts", 1));
    expect(second).toBeNull(); // no md5 left to fix
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/fix/deterministic/crypto-002.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement the fixer**

```typescript
// src/layers/fix/deterministic/crypto-002.ts
import type { Fixer } from "../types.js";

export const crypto002Fixer: Fixer = {
  ruleId: "CRYPTO-002",
  type: "deterministic",
  apply(content, _finding) {
    if (!content.match(/createHash\s*\(\s*['"]md5['"]\s*\)/)) return null;

    const result = content.replace(
      /createHash\s*\(\s*(['"])md5\1\s*\)/g,
      (_, quote) => `createHash(${quote}sha256${quote})`,
    );

    return result === content ? null : result;
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/fix/deterministic/crypto-002.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/fix/deterministic/crypto-002.ts tests/layers/fix/deterministic/crypto-002.test.ts
git commit -m "feat(fix): deterministic fixer for CRYPTO-002 (MD5 -> SHA-256)"
```

---

### Task 4: Deterministic Fixer - LOG-005 (try/catch wrapper)

**Files:**
- Create: `src/layers/fix/deterministic/log-005.ts`
- Test: `tests/layers/fix/deterministic/log-005.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/layers/fix/deterministic/log-005.test.ts
import { describe, it, expect } from "vitest";
import { log005Fixer } from "../../../../src/layers/fix/deterministic/log-005.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(file: string): Finding {
  return {
    id: `LOG-005-${file}-0`,
    ruleId: "LOG-005",
    domain: "logging-monitoring",
    severity: "medium",
    confidence: "high",
    title: "Route handler missing error boundary",
    description: "",
    impact: "",
    evidence: [{ file }],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

describe("log-005 fixer", () => {
  it("wraps a simple GET handler in try/catch", () => {
    const input = `import { NextResponse } from "next/server";

export async function GET() {
  const data = await fetchData();
  return NextResponse.json(data);
}`;
    const result = log005Fixer.apply!(input, makeFinding("route.ts"));
    expect(result).toContain("try {");
    expect(result).toContain("} catch (error)");
    expect(result).toContain('{ error: "Internal server error" }');
    expect(result).toContain("status: 500");
  });

  it("wraps POST handler", () => {
    const input = `import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json();
  return NextResponse.json({ ok: true });
}`;
    const result = log005Fixer.apply!(input, makeFinding("route.ts"));
    expect(result).toContain("try {");
    expect(result).toContain("console.error");
  });

  it("skips handler that already has try/catch", () => {
    const input = `export async function GET() {
  try {
    const data = await fetchData();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: "fail" }, { status: 500 });
  }
}`;
    const result = log005Fixer.apply!(input, makeFinding("route.ts"));
    expect(result).toBeNull();
  });

  it("is idempotent", () => {
    const input = `import { NextResponse } from "next/server";

export async function GET() {
  const data = await fetchData();
  return NextResponse.json(data);
}`;
    const first = log005Fixer.apply!(input, makeFinding("route.ts"));
    const second = log005Fixer.apply!(first!, makeFinding("route.ts"));
    expect(second).toBeNull(); // already has try/catch
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/fix/deterministic/log-005.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement the fixer**

```typescript
// src/layers/fix/deterministic/log-005.ts
import type { Fixer } from "../types.js";

const HANDLER_RE =
  /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{/g;

export const log005Fixer: Fixer = {
  ruleId: "LOG-005",
  type: "deterministic",
  apply(content, _finding) {
    let result = content;
    let modified = false;

    // Find each exported handler function
    let match: RegExpExecArray | null;
    const handlerRe = new RegExp(HANDLER_RE.source, "g");

    // Collect all handlers with their positions
    const handlers: { method: string; braceStart: number }[] = [];
    while ((match = handlerRe.exec(content)) !== null) {
      handlers.push({ method: match[1], braceStart: match.index + match[0].length - 1 });
    }

    // Process from last to first to preserve positions
    for (let i = handlers.length - 1; i >= 0; i--) {
      const { method, braceStart } = handlers[i];

      // Find matching closing brace
      let depth = 1;
      let pos = braceStart + 1;
      while (pos < result.length && depth > 0) {
        if (result[pos] === "{") depth++;
        if (result[pos] === "}") depth--;
        pos++;
      }
      const braceEnd = pos - 1;

      // Extract body between braces
      const body = result.substring(braceStart + 1, braceEnd);

      // Skip if already has try/catch
      if (body.match(/^\s*try\s*\{/m)) continue;

      // Indent body by 2 extra spaces and wrap
      const indentedBody = body
        .split("\n")
        .map((line) => (line.trim() ? "  " + line : line))
        .join("\n");

      const wrapped =
        ` {\n  try {${indentedBody}\n  } catch (error) {\n` +
        `    console.error(\`${method} handler failed:\`, error);\n` +
        `    return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });\n` +
        `  }\n}`;

      result = result.substring(0, braceStart) + wrapped + result.substring(braceEnd + 1);
      modified = true;
    }

    return modified ? result : null;
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/fix/deterministic/log-005.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/fix/deterministic/log-005.ts tests/layers/fix/deterministic/log-005.test.ts
git commit -m "feat(fix): deterministic fixer for LOG-005 (try/catch wrapper)"
```

---

### Task 5: Deterministic Fixer - INFRA-006 (Security Headers)

**Files:**
- Create: `src/layers/fix/deterministic/infra-006.ts`
- Test: `tests/layers/fix/deterministic/infra-006.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/layers/fix/deterministic/infra-006.test.ts
import { describe, it, expect } from "vitest";
import { infra006Fixer } from "../../../../src/layers/fix/deterministic/infra-006.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(file: string): Finding {
  return {
    id: `INFRA-006-${file}-0`,
    ruleId: "INFRA-006",
    domain: "infrastructure",
    severity: "medium",
    confidence: "high",
    title: "Missing security headers",
    description: "",
    impact: "",
    evidence: [{ file }],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

describe("infra-006 fixer", () => {
  it("adds headers to next.config.mjs without existing headers", () => {
    const input = `/** @type {import('next').NextConfig} */
const nextConfig = {};

export default nextConfig;`;
    const result = infra006Fixer.apply!(input, makeFinding("next.config.mjs"));
    expect(result).toContain("X-Content-Type-Options");
    expect(result).toContain("X-Frame-Options");
    expect(result).toContain("Referrer-Policy");
    expect(result).toContain("headers");
  });

  it("returns null for non-config files", () => {
    const input = `const x = 1;`;
    const result = infra006Fixer.apply!(input, makeFinding("src/app/page.tsx"));
    expect(result).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/fix/deterministic/infra-006.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement the fixer**

```typescript
// src/layers/fix/deterministic/infra-006.ts
import type { Fixer } from "../types.js";

const SECURITY_HEADERS = `
  async headers() {
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

export const infra006Fixer: Fixer = {
  ruleId: "INFRA-006",
  type: "deterministic",
  apply(content, finding) {
    const file = finding.evidence[0]?.file ?? "";
    if (!file.match(/next\.config\.(js|mjs|ts)$/)) return null;
    if (content.includes("X-Content-Type-Options")) return null;

    // Insert headers into the config object
    // Find the config object pattern: const nextConfig = { ... }
    const configMatch = content.match(/(const\s+\w+\s*=\s*\{)/);
    if (!configMatch) return null;

    const insertPos = configMatch.index! + configMatch[0].length;
    return content.substring(0, insertPos) + SECURITY_HEADERS + content.substring(insertPos);
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/fix/deterministic/infra-006.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/fix/deterministic/infra-006.ts tests/layers/fix/deterministic/infra-006.test.ts
git commit -m "feat(fix): deterministic fixer for INFRA-006 (security headers)"
```

---

### Task 6: AI Fix Infrastructure (Prompts + Validator)

**Files:**
- Create: `src/layers/fix/ai/prompts.ts`
- Create: `src/layers/fix/ai/validator.ts`
- Test: `tests/layers/fix/ai/validator.test.ts`
- Test: `tests/layers/fix/ai/prompts.test.ts`

- [ ] **Step 1: Write the failing test for validator**

```typescript
// tests/layers/fix/ai/validator.test.ts
import { describe, it, expect } from "vitest";
import { validateAIResponse } from "../../../../src/layers/fix/ai/validator.js";

describe("validateAIResponse", () => {
  it("accepts valid patched content", () => {
    const original = `export async function GET() {\n  return Response.json({ ok: true });\n}`;
    const patched = `import { z } from "zod";\nexport async function GET() {\n  return Response.json({ ok: true });\n}`;
    const result = validateAIResponse(original, patched);
    expect(result.valid).toBe(true);
  });

  it("rejects empty response", () => {
    const original = `export async function GET() { return Response.json({}); }`;
    const result = validateAIResponse(original, "");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("empty");
  });

  it("rejects response that lost more than 50% of content", () => {
    const original = "a".repeat(200);
    const patched = "a".repeat(80);
    const result = validateAIResponse(original, patched);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("truncated");
  });

  it("rejects response that lost exports", () => {
    const original = `export async function GET() { return Response.json({}); }\nexport async function POST() { return Response.json({}); }`;
    const patched = `export async function GET() { return Response.json({}); }`;
    const result = validateAIResponse(original, patched);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("export");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/fix/ai/validator.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement validator**

```typescript
// src/layers/fix/ai/validator.ts

export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

export function validateAIResponse(
  originalContent: string,
  patchedContent: string,
): ValidationResult {
  if (!patchedContent || patchedContent.trim().length === 0) {
    return { valid: false, reason: "AI returned empty response" };
  }

  // Check for dramatic content loss (likely truncation)
  if (patchedContent.length < originalContent.length * 0.5) {
    return { valid: false, reason: "Response appears truncated (>50% content loss)" };
  }

  // Check that all original exports are preserved
  const exportRe = /export\s+(?:async\s+)?function\s+(\w+)/g;
  const originalExports: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = exportRe.exec(originalContent)) !== null) {
    originalExports.push(m[1]);
  }
  for (const name of originalExports) {
    if (!patchedContent.includes(name)) {
      return { valid: false, reason: `Missing export: ${name}` };
    }
  }

  return { valid: true };
}
```

- [ ] **Step 4: Run validator test**

Run: `npx vitest run tests/layers/fix/ai/validator.test.ts`
Expected: PASS

- [ ] **Step 5: Write prompt templates**

```typescript
// src/layers/fix/ai/prompts.ts
import type { Finding } from "../../../model/types.js";

export interface PromptTemplate {
  id: string;
  system: string;
  buildUserPrompt: (fileContent: string, findings: Finding[]) => string;
}

const SYSTEM_BASE = `You are a security engineer applying minimal, targeted fixes to source code.
Rules:
- Preserve ALL existing logic, exports, and type signatures.
- Only add or modify code needed to fix the specified vulnerabilities.
- Return ONLY the complete fixed file content. No markdown fences, no explanations.
- If you add imports, place them with existing imports.`;

export const promptTemplates: Record<string, PromptTemplate> = {
  "input-005": {
    id: "input-005",
    system: SYSTEM_BASE,
    buildUserPrompt(fileContent, findings) {
      const findingList = findings
        .map((f) => `- ${f.title} at line ${f.evidence[0]?.line ?? "unknown"}`)
        .join("\n");
      return `Fix these vulnerabilities in the file below:\n${findingList}\n\nFor each POST/PUT/PATCH handler missing body validation:\n1. Infer the expected request body shape from how body properties are accessed in the handler.\n2. Create a Zod schema above the handler.\n3. Replace the raw \`await request.json()\` with schema.parse() wrapped in try/catch that returns 400 on validation failure.\n4. Add \`import { z } from "zod"\` if not present.\n\nFile content:\n\`\`\`typescript\n${fileContent}\n\`\`\``;
    },
  },
  "auth-002": {
    id: "auth-002",
    system: SYSTEM_BASE,
    buildUserPrompt(fileContent, findings) {
      const findingList = findings
        .map((f) => `- ${f.title} at line ${f.evidence[0]?.line ?? "unknown"}`)
        .join("\n");
      return `Fix these vulnerabilities in the file below:\n${findingList}\n\nFor each handler missing an auth check:\n1. Add \`import { createRouteHandlerClient } from "@supabase/auth-helpers-nextjs"\` if not present.\n2. Add \`import { cookies } from "next/headers"\` if not present.\n3. At the top of each handler, add:\n   const supabase = createRouteHandlerClient({ cookies });\n   const { data: { user }, error } = await supabase.auth.getUser();\n   if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });\n4. Preserve all existing handler logic after the auth check.\n\nFile content:\n\`\`\`typescript\n${fileContent}\n\`\`\``;
    },
  },
  "api-004": {
    id: "api-004",
    system: SYSTEM_BASE,
    buildUserPrompt(fileContent, findings) {
      const findingList = findings
        .map((f) => `- ${f.title} at line ${f.evidence[0]?.line ?? "unknown"}`)
        .join("\n");
      return `Fix these vulnerabilities in the file below:\n${findingList}\n\nAdd a simple in-memory rate limiter:\n1. Add a Map<string, { count: number; resetAt: number }> at the top of the file.\n2. Create a checkRateLimit(ip: string) function that allows 60 requests per minute per IP.\n3. At the top of each handler, extract the IP from headers and call checkRateLimit. Return 429 if exceeded.\n4. Add a comment noting this is suitable for single-instance deployments.\n\nFile content:\n\`\`\`typescript\n${fileContent}\n\`\`\``;
    },
  },
};

export function getPromptTemplate(id: string): PromptTemplate | undefined {
  return promptTemplates[id];
}
```

- [ ] **Step 6: Write prompt test**

```typescript
// tests/layers/fix/ai/prompts.test.ts
import { describe, it, expect } from "vitest";
import { getPromptTemplate } from "../../../../src/layers/fix/ai/prompts.js";

describe("prompt templates", () => {
  it("returns template for input-005", () => {
    const t = getPromptTemplate("input-005");
    expect(t).toBeDefined();
    expect(t!.system).toContain("security engineer");
  });

  it("returns template for auth-002", () => {
    expect(getPromptTemplate("auth-002")).toBeDefined();
  });

  it("returns template for api-004", () => {
    expect(getPromptTemplate("api-004")).toBeDefined();
  });

  it("returns undefined for unknown template", () => {
    expect(getPromptTemplate("nonexistent")).toBeUndefined();
  });

  it("input-005 prompt includes file content and finding info", () => {
    const t = getPromptTemplate("input-005")!;
    const prompt = t.buildUserPrompt("const x = 1;", [{
      id: "test", ruleId: "INPUT-005", domain: "input-injection",
      severity: "high", confidence: "high", title: "Missing validation",
      description: "", impact: "", evidence: [{ file: "test.ts", line: 5 }],
      remediation: "", references: [], layer: "rules",
    }]);
    expect(prompt).toContain("const x = 1;");
    expect(prompt).toContain("Missing validation");
    expect(prompt).toContain("Zod");
  });
});
```

- [ ] **Step 7: Run all tests**

Run: `npx vitest run tests/layers/fix/ai/`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/layers/fix/ai/prompts.ts src/layers/fix/ai/validator.ts tests/layers/fix/ai/
git commit -m "feat(fix): AI fix infrastructure (prompts + validator)"
```

---

### Task 7: AI Fix Runner

**Files:**
- Create: `src/layers/fix/ai/index.ts`

- [ ] **Step 1: Implement AI fix runner**

```typescript
// src/layers/fix/ai/index.ts
import { readFile, writeFile } from "fs/promises";
import type { Finding } from "../../../model/types.js";
import type { AIConfig } from "../../../model/types.js";
import type { FixAttempt } from "../types.js";
import { createProvider } from "../../../layers/ai/index.js";
import { getPromptTemplate } from "./prompts.js";
import { validateAIResponse } from "./validator.js";
import { getFixer } from "../registry.js";

export interface AIFixOptions {
  aiConfig: AIConfig;
  dryRun: boolean;
}

export async function runAIFixes(
  findingsByFile: Map<string, Finding[]>,
  options: AIFixOptions,
): Promise<{ attempts: FixAttempt[]; filesModified: string[] }> {
  const attempts: FixAttempt[] = [];
  const filesModified: string[] = [];
  const provider = createProvider(options.aiConfig);

  for (const [file, findings] of findingsByFile) {
    // Group findings by their prompt template
    const byPrompt = new Map<string, Finding[]>();
    for (const f of findings) {
      const fixer = getFixer(f.ruleId ?? "");
      if (!fixer || fixer.type !== "ai" || !fixer.aiPromptId) {
        attempts.push({
          findingId: f.id, ruleId: f.ruleId ?? "", file,
          strategy: "manual", status: "skipped", reason: "No AI fixer registered",
        });
        continue;
      }
      const key = fixer.aiPromptId;
      if (!byPrompt.has(key)) byPrompt.set(key, []);
      byPrompt.get(key)!.push(f);
    }

    if (byPrompt.size === 0) continue;

    let currentContent: string;
    try {
      currentContent = await readFile(file, "utf-8");
    } catch {
      for (const f of findings) {
        attempts.push({
          findingId: f.id, ruleId: f.ruleId ?? "", file,
          strategy: "ai", status: "failed", reason: "Could not read file",
        });
      }
      continue;
    }

    // Apply each prompt group sequentially (content changes between groups)
    let fileModified = false;
    for (const [promptId, promptFindings] of byPrompt) {
      const template = getPromptTemplate(promptId);
      if (!template) {
        for (const f of promptFindings) {
          attempts.push({
            findingId: f.id, ruleId: f.ruleId ?? "", file,
            strategy: "ai", status: "failed", reason: `Prompt template "${promptId}" not found`,
          });
        }
        continue;
      }

      const userPrompt = template.buildUserPrompt(currentContent, promptFindings);

      try {
        const response = await provider.generateFindings({
          systemPrompt: template.system,
          userPrompt,
          maxTokens: 8192,
        });

        // Extract the file content from the response
        const patchedContent = extractCodeFromResponse(response.rawText ?? "");
        const validation = validateAIResponse(currentContent, patchedContent);

        if (!validation.valid) {
          for (const f of promptFindings) {
            attempts.push({
              findingId: f.id, ruleId: f.ruleId ?? "", file,
              strategy: "ai", status: "failed", reason: validation.reason,
            });
          }
          continue;
        }

        if (!options.dryRun) {
          currentContent = patchedContent;
          fileModified = true;
        }

        for (const f of promptFindings) {
          attempts.push({
            findingId: f.id, ruleId: f.ruleId ?? "", file,
            strategy: "ai", status: "fixed",
            description: `Applied ${promptId} fix`,
          });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        for (const f of promptFindings) {
          attempts.push({
            findingId: f.id, ruleId: f.ruleId ?? "", file,
            strategy: "ai", status: "failed", reason: msg,
          });
        }
      }
    }

    if (fileModified) {
      await writeFile(file, currentContent, "utf-8");
      filesModified.push(file);
    }
  }

  return { attempts, filesModified };
}

function extractCodeFromResponse(text: string): string {
  // Strip markdown code fences if present
  const fenceMatch = text.match(/```(?:typescript|ts|javascript|js)?\n([\s\S]*?)```/);
  if (fenceMatch) return fenceMatch[1].trim();
  return text.trim();
}
```

- [ ] **Step 2: Commit**

```bash
git add src/layers/fix/ai/index.ts
git commit -m "feat(fix): AI fix runner"
```

---

### Task 8: Fix Runner (Orchestration)

**Files:**
- Create: `src/layers/fix/index.ts`

- [ ] **Step 1: Implement fix runner**

```typescript
// src/layers/fix/index.ts
import { readFile, writeFile } from "fs/promises";
import type { Finding } from "../../model/types.js";
import type { AIConfig } from "../../model/types.js";
import type { FixAttempt, FixResult } from "./types.js";
import { getFixer } from "./registry.js";
import { runAIFixes } from "./ai/index.js";

export interface FixOptions {
  findings: Finding[];
  ruleFilter?: string[];
  noAI: boolean;
  dryRun: boolean;
  aiConfig?: AIConfig;
}

export async function runFix(options: FixOptions): Promise<FixResult> {
  const { findings, ruleFilter, noAI, dryRun } = options;
  const attempts: FixAttempt[] = [];
  const filesModified: string[] = [];

  // Filter by rule if specified
  const filtered = ruleFilter
    ? findings.filter((f) => f.ruleId && ruleFilter.includes(f.ruleId))
    : findings;

  // Classify findings
  const deterministicByFile = new Map<string, { finding: Finding; fixer: NonNullable<ReturnType<typeof getFixer>> }[]>();
  const aiByFile = new Map<string, Finding[]>();

  for (const f of filtered) {
    const file = f.evidence[0]?.file;
    if (!file) {
      attempts.push({
        findingId: f.id, ruleId: f.ruleId ?? "", file: "",
        strategy: "manual", status: "skipped", reason: "No file in evidence",
      });
      continue;
    }

    const fixer = getFixer(f.ruleId ?? "");
    if (!fixer) {
      attempts.push({
        findingId: f.id, ruleId: f.ruleId ?? "", file,
        strategy: "manual", status: "skipped", reason: "No fixer available",
      });
      continue;
    }

    if (fixer.type === "deterministic" && fixer.apply) {
      if (!deterministicByFile.has(file)) deterministicByFile.set(file, []);
      deterministicByFile.get(file)!.push({ finding: f, fixer });
    } else if (fixer.type === "ai") {
      if (noAI) {
        attempts.push({
          findingId: f.id, ruleId: f.ruleId ?? "", file,
          strategy: "ai", status: "skipped", reason: "--no-ai flag set",
        });
      } else {
        if (!aiByFile.has(file)) aiByFile.set(file, []);
        aiByFile.get(file)!.push(f);
      }
    }
  }

  // Phase 1: deterministic fixes
  for (const [file, items] of deterministicByFile) {
    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      for (const { finding } of items) {
        attempts.push({
          findingId: finding.id, ruleId: finding.ruleId ?? "", file,
          strategy: "deterministic", status: "failed", reason: "Could not read file",
        });
      }
      continue;
    }

    let modified = false;
    for (const { finding, fixer } of items) {
      const patched = fixer.apply!(content, finding);
      if (patched !== null) {
        content = patched;
        modified = true;
        attempts.push({
          findingId: finding.id, ruleId: finding.ruleId ?? "", file,
          strategy: "deterministic", status: "fixed",
          description: finding.title,
        });
      } else {
        attempts.push({
          findingId: finding.id, ruleId: finding.ruleId ?? "", file,
          strategy: "deterministic", status: "skipped",
          reason: "Transform returned null (already fixed or not applicable)",
        });
      }
    }

    if (modified && !dryRun) {
      await writeFile(file, content, "utf-8");
      filesModified.push(file);
    }
  }

  // Phase 2: AI fixes
  if (!noAI && aiByFile.size > 0 && options.aiConfig) {
    const aiResult = await runAIFixes(aiByFile, {
      aiConfig: options.aiConfig,
      dryRun,
    });
    attempts.push(...aiResult.attempts);
    filesModified.push(...aiResult.filesModified);
  }

  return { attempts, filesModified: [...new Set(filesModified)] };
}
```

- [ ] **Step 2: Commit**

```bash
git add src/layers/fix/index.ts
git commit -m "feat(fix): fix runner orchestration (deterministic + AI)"
```

---

### Task 9: CLI Command + Fixer Registration

**Files:**
- Create: `src/commands/fix.ts`
- Modify: `src/cli.ts` (add fix command)

- [ ] **Step 1: Implement the fix command**

```typescript
// src/commands/fix.ts
import { readFile } from "fs/promises";
import { resolve } from "path";
import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../layers/rules/index.js";
import { secretsExposureRules } from "../layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../layers/rules/domains/file-upload.js";
import { supplyChainRules } from "../layers/rules/domains/supply-chain.js";
import { cryptographyRules } from "../layers/rules/domains/cryptography.js";
import { loggingMonitoringRules } from "../layers/rules/domains/logging-monitoring.js";
import { apiSecurityRules } from "../layers/rules/domains/api-security.js";
import { businessLogicRules } from "../layers/rules/domains/business-logic.js";
import { infrastructureRules } from "../layers/rules/domains/infrastructure.js";
import { readContext, inferContext } from "../layers/context/index.js";
import { applyContextSuppressions } from "../layers/context/suppression.js";
import { registerFixer, resetFixerRegistry } from "../layers/fix/registry.js";
import { crypto001Fixer } from "../layers/fix/deterministic/crypto-001.js";
import { crypto002Fixer } from "../layers/fix/deterministic/crypto-002.js";
import { log005Fixer } from "../layers/fix/deterministic/log-005.js";
import { infra006Fixer } from "../layers/fix/deterministic/infra-006.js";
import { runFix } from "../layers/fix/index.js";
import type { Finding, AIConfig } from "../model/types.js";
import type { SentinelConfig } from "../config.js";
import type { FixAttempt } from "../layers/fix/types.js";

export interface FixCommandOptions {
  path: string;
  from?: string;
  rule?: string[];
  dryRun: boolean;
  noAI: boolean;
  aiProvider?: "anthropic" | "openai" | "mock";
  aiModel?: string;
  aiMaxCost?: number;
  aiConcurrency?: number;
}

function registerAllFixers(): void {
  resetFixerRegistry();
  // Deterministic
  registerFixer(crypto001Fixer);
  registerFixer(crypto002Fixer);
  registerFixer(log005Fixer);
  registerFixer(infra006Fixer);
  // AI
  registerFixer({ ruleId: "INPUT-005", type: "ai", aiPromptId: "input-005" });
  registerFixer({ ruleId: "AUTH-002", type: "ai", aiPromptId: "auth-002" });
  registerFixer({ ruleId: "API-004", type: "ai", aiPromptId: "api-004" });
}

export async function runFixCommand(options: FixCommandOptions): Promise<number> {
  const config = await loadConfig(options.path);

  registerAllFixers();

  // Acquire findings
  let findings: Finding[];
  if (options.from) {
    process.stderr.write(`Loading findings from ${options.from}...\n`);
    const report = JSON.parse(await readFile(resolve(options.from), "utf-8"));
    findings = report.findings ?? [];
  } else {
    process.stderr.write("Scanning...\n");
    resetRegistry();
    registerRules(secretsExposureRules);
    registerRules(inputInjectionRules);
    registerRules(authAccessControlRules);
    registerRules(fileUploadRules);
    registerRules(supplyChainRules);
    registerRules(cryptographyRules);
    registerRules(loggingMonitoringRules);
    registerRules(apiSecurityRules);
    registerRules(businessLogicRules);
    registerRules(infrastructureRules);

    const model = await runRecon(options.path, config.exclude);
    const contextFromFile = await readContext(options.path);
    const context = contextFromFile ?? await inferContext(model);
    const rawFindings = await runRules(model, context);
    findings = applyContextSuppressions(rawFindings, context);
    process.stderr.write(`Scan complete: ${findings.length} findings after context suppression.\n\n`);
  }

  if (findings.length === 0) {
    process.stdout.write("No findings to fix.\n");
    return 0;
  }

  // Build AI config
  const aiConfig: AIConfig | undefined = options.noAI ? undefined : {
    enabled: true,
    provider: options.aiProvider ?? config.ai.provider,
    model: options.aiModel ?? config.ai.model,
    deep: false,
    maxCostUsd: options.aiMaxCost ?? config.ai.maxCostUsd,
    maxTokensPerEndpoint: config.ai.maxTokensPerEndpoint,
    concurrency: options.aiConcurrency ?? config.ai.concurrency,
    dryRun: false,
    magicLinkRoutes: [],
  };

  const prefix = options.dryRun ? "Would fix" : "Fixing";
  process.stderr.write(`${prefix} findings...\n\n`);

  const result = await runFix({
    findings,
    ruleFilter: options.rule,
    noAI: options.noAI,
    dryRun: options.dryRun,
    aiConfig,
  });

  // Report
  const fixed = result.attempts.filter((a) => a.status === "fixed");
  const skipped = result.attempts.filter((a) => a.status === "skipped");
  const failed = result.attempts.filter((a) => a.status === "failed");

  const label = options.dryRun ? "Would fix" : "Fixed";

  if (fixed.length > 0) {
    process.stdout.write(`Deterministic fixes:\n`);
    for (const a of fixed.filter((a) => a.strategy === "deterministic")) {
      const short = a.file.split("/").slice(-2).join("/");
      process.stdout.write(`  ok  ${a.ruleId.padEnd(12)} ${short.padEnd(35)} ${a.description ?? ""}\n`);
    }

    const aiFixed = fixed.filter((a) => a.strategy === "ai");
    if (aiFixed.length > 0) {
      process.stdout.write(`\nAI fixes:\n`);
      for (const a of aiFixed) {
        const short = a.file.split("/").slice(-2).join("/");
        process.stdout.write(`  ok  ${a.ruleId.padEnd(12)} ${short.padEnd(35)} ${a.description ?? ""}\n`);
      }
    }
  }

  if (failed.length > 0) {
    process.stdout.write(`\nFailed:\n`);
    for (const a of failed) {
      const short = a.file.split("/").slice(-2).join("/");
      process.stdout.write(`  !!  ${a.ruleId.padEnd(12)} ${short.padEnd(35)} ${a.reason ?? ""}\n`);
    }
  }

  process.stdout.write(`\nSummary:\n`);
  process.stdout.write(`  ${label}:    ${fixed.length} findings\n`);
  process.stdout.write(`  Skipped:  ${skipped.length}\n`);
  process.stdout.write(`  Failed:   ${failed.length}\n`);
  process.stdout.write(`  Files:    ${result.filesModified.length} modified\n`);
  process.stdout.write(`\nRun \`sentinel scan ${options.path}\` to verify fixes.\n`);

  return 0;
}
```

- [ ] **Step 2: Add fix command to cli.ts**

Add after the existing `context` command in `src/cli.ts`:

```typescript
import { runFixCommand } from "./commands/fix.js";

// ... (after the context command definition)

program
  .command("fix")
  .description("Auto-remediate security findings (deterministic + AI)")
  .argument("<path>", "Path to the project to fix")
  .option("--from <file>", "Load findings from a JSON scan report instead of scanning")
  .option("--rule <id>", "Fix only specific rule(s) (repeatable)",
    (val: string, prev: string[] = []) => [...prev, val], [] as string[])
  .option("--dry-run", "Show what would change without writing files")
  .option("--no-ai", "Skip AI-powered fixes (deterministic only)")
  .option("--ai-provider <name>", "AI provider (anthropic|openai|mock)")
  .option("--ai-model <id>", "AI model id")
  .option("--ai-max-cost <usd>", "Hard budget cap in USD", parseFloat)
  .option("--ai-concurrency <n>", "Parallel AI fix calls", parseInt)
  .action(async (path, options) => {
    const exitCode = await runFixCommand({
      path,
      from: options.from,
      rule: options.rule?.length ? options.rule : undefined,
      dryRun: !!options.dryRun,
      noAI: !options.ai,
      aiProvider: options.aiProvider,
      aiModel: options.aiModel,
      aiMaxCost: options.aiMaxCost,
      aiConcurrency: options.aiConcurrency,
    });
    exitAfterDrain(exitCode);
  });
```

- [ ] **Step 3: Build and verify help**

Run: `npm run build && node dist/cli.js fix --help`
Expected: Shows fix command with all options

- [ ] **Step 4: Commit**

```bash
git add src/commands/fix.ts src/cli.ts
git commit -m "feat(fix): sentinel fix CLI command with fixer registration"
```

---

### Task 10: Integration Test

**Files:**
- Create: `tests/commands/fix.test.ts`

- [ ] **Step 1: Write integration test**

```typescript
// tests/commands/fix.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

function sentinel(args: string[]): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync("npx", ["tsx", "src/cli.ts", ...args], {
      encoding: "utf-8",
      cwd: join(import.meta.dirname, "..", ".."),
      timeout: 30_000,
    });
    return { stdout, exitCode: 0 };
  } catch (err: any) {
    return { stdout: err.stdout ?? "", exitCode: err.status ?? 1 };
  }
}

describe("sentinel fix", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sentinel-fix-test-"));
    // Create a minimal project
    writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "test", dependencies: { next: "14" } }));
    mkdirSync(join(tmpDir, "src", "app", "api", "test"), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("fixes CRYPTO-001 (Math.random) deterministically", () => {
    const routeFile = join(tmpDir, "src", "app", "api", "test", "route.ts");
    writeFileSync(routeFile, `export async function GET() {
  const token = Math.random().toString(36).substring(2);
  return Response.json({ token });
}`);

    const { stdout } = sentinel(["fix", tmpDir, "--no-ai"]);
    expect(stdout).toContain("CRYPTO-001");
    expect(stdout).toContain("ok");

    const fixed = readFileSync(routeFile, "utf-8");
    expect(fixed).not.toContain("Math.random()");
    expect(fixed).toContain("crypto.randomUUID()");
  });

  it("--dry-run does not modify files", () => {
    const routeFile = join(tmpDir, "src", "app", "api", "test", "route.ts");
    const original = `export async function GET() {
  const token = Math.random().toString(36).substring(2);
  return Response.json({ token });
}`;
    writeFileSync(routeFile, original);

    sentinel(["fix", tmpDir, "--no-ai", "--dry-run"]);

    const content = readFileSync(routeFile, "utf-8");
    expect(content).toBe(original);
  });

  it("--rule filters to specific rules only", () => {
    const routeFile = join(tmpDir, "src", "app", "api", "test", "route.ts");
    writeFileSync(routeFile, `export async function GET() {
  const hash = createHash('md5').update('data').digest('hex');
  const token = Math.random().toString(36);
  return Response.json({ hash, token });
}`);

    sentinel(["fix", tmpDir, "--no-ai", "--rule", "CRYPTO-002"]);

    const fixed = readFileSync(routeFile, "utf-8");
    expect(fixed).toContain("sha256"); // CRYPTO-002 was fixed
    expect(fixed).toContain("Math.random()"); // CRYPTO-001 was NOT fixed (filtered out)
  });
});
```

- [ ] **Step 2: Run integration test**

Run: `npx vitest run tests/commands/fix.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 3: Commit**

```bash
git add tests/commands/fix.test.ts
git commit -m "test(fix): integration tests for sentinel fix command"
```

---

### Task 11: Build Verification

- [ ] **Step 1: Full build**

Run: `npm run build`
Expected: Clean build, no errors

- [ ] **Step 2: Run all tests**

Run: `npx vitest run`
Expected: All tests pass (existing + new)

- [ ] **Step 3: Smoke test against skutt**

Run: `node dist/cli.js fix /Users/tywells/Downloads/projects/skutt --no-ai --dry-run`
Expected: Shows deterministic fixes it would apply (CRYPTO-001, CRYPTO-002, LOG-005) without modifying files

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "chore: build verification for sentinel fix"
```

Plan complete and saved to `docs/superpowers/plans/2026-04-13-sentinel-fix.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?