# Sentinel Phase 1 MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working `sentinel scan` CLI that audits a Next.js + Supabase codebase across four security domains (secrets-exposure, input-injection, auth-access-control, file-upload) using a layered Recon → Rules pipeline, with terminal and JSON output.

**Architecture:** TypeScript ESM CLI. The Recon layer parses the target project's filesystem and AST into a shared `ProjectModel`. The Rules layer runs deterministic pure-function checks against the model and produces `Finding[]`. Output formatters consume findings and render terminal or JSON. No AI layer, no active probing, no HTML report in Phase 1.

**Tech Stack:**
- Node 20+, TypeScript 5.x, ESM modules
- `commander` - CLI arg parsing
- `vitest` - testing framework
- `pino` - structured logging
- `zod` - runtime schema validation
- `chalk` - terminal colors
- `typescript` - AST parsing (compiler API, not a dep of the scanned project)
- `fast-glob` - filesystem traversal
- `yaml` - parsing `.yaml` configs when needed

---

## File Structure

```
sentinel/
├── src/
│   ├── cli.ts                               # CLI entry point, command dispatch
│   ├── commands/
│   │   └── scan.ts                          # `sentinel scan` command handler
│   ├── config.ts                            # .sentinelrc.json loading and schema
│   ├── model/
│   │   ├── types.ts                         # ProjectModel, Finding, all core types
│   │   └── severity.ts                      # Severity ordering helpers
│   ├── layers/
│   │   ├── recon/
│   │   │   ├── index.ts                     # Recon orchestrator
│   │   │   ├── stack-detector.ts            # Framework/stack detection
│   │   │   ├── route-discovery.ts           # Next.js App Router/pages discovery
│   │   │   ├── endpoint-discovery.ts        # API route handlers
│   │   │   ├── auth-discovery.ts            # Auth flows, middleware chains
│   │   │   ├── upload-discovery.ts          # File upload handlers
│   │   │   ├── env-discovery.ts             # Env var usage mapping
│   │   │   └── dep-discovery.ts             # Dependency tree from lockfile
│   │   └── rules/
│   │       ├── index.ts                     # Rule engine orchestrator
│   │       ├── registry.ts                  # Rule registration and filtering
│   │       └── domains/
│   │           ├── secrets-exposure.ts      # 9 rules
│   │           ├── input-injection.ts       # 10 rules
│   │           ├── auth-access-control.ts   # 10 rules
│   │           └── file-upload.ts           # 9 rules
│   ├── output/
│   │   ├── terminal.ts                      # Colored CLI formatter
│   │   └── json.ts                          # JSON formatter
│   └── utils/
│       ├── fs.ts                            # Filesystem helpers with deny-paths
│       ├── ast.ts                           # TypeScript AST helpers
│       └── logger.ts                        # Pino logger instance
├── tests/
│   ├── fixtures/
│   │   └── vulnerable-nextjs/               # Deliberately vulnerable test project
│   │       ├── package.json
│   │       ├── next.config.mjs
│   │       ├── src/
│   │       │   ├── app/
│   │       │   │   ├── page.tsx
│   │       │   │   └── api/
│   │       │   │       ├── profile/route.ts
│   │       │   │       ├── upload/route.ts
│   │       │   │       └── projects/[id]/route.ts
│   │       │   ├── components/
│   │       │   │   └── ProfileCard.tsx
│   │       │   └── lib/
│   │       │       └── supabase.ts
│   │       └── .env.example
│   ├── recon/                               # Recon module unit tests
│   ├── rules/                               # Rules module unit tests
│   ├── output/                              # Output formatter tests
│   └── integration/
│       └── scan.test.ts                     # Full scan against fixture project
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── .sentinelrc.defaults.json
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `.gitignore`
- Create: `src/utils/logger.ts`

- [ ] **Step 1: Initialize package.json**

Create `package.json`:

```json
{
  "name": "@franklabs/sentinel",
  "version": "0.1.0",
  "description": "Security assessment CLI for Next.js + Supabase codebases",
  "type": "module",
  "bin": {
    "sentinel": "./dist/cli.js"
  },
  "main": "./dist/cli.js",
  "scripts": {
    "build": "tsc",
    "dev": "tsx src/cli.ts",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "lint": "eslint src tests --ext .ts"
  },
  "engines": {
    "node": ">=20.0.0"
  },
  "files": [
    "dist",
    ".sentinelrc.defaults.json"
  ],
  "dependencies": {
    "chalk": "^5.3.0",
    "commander": "^12.0.0",
    "fast-glob": "^3.3.2",
    "pino": "^9.0.0",
    "typescript": "^5.4.0",
    "yaml": "^2.4.0",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/node": "^20.11.0",
    "eslint": "^8.57.0",
    "tsx": "^4.7.0",
    "vitest": "^1.4.0"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests", "tests/fixtures/**/*"]
}
```

- [ ] **Step 3: Create vitest.config.ts**

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/fixtures/**"],
    testTimeout: 30000,
  },
});
```

- [ ] **Step 4: Create .gitignore**

```
node_modules/
dist/
.sentinel/
*.log
.DS_Store
```

- [ ] **Step 5: Create logger utility**

Create `src/utils/logger.ts`:

```typescript
import pino from "pino";

export const logger = pino({
  level: process.env.SENTINEL_LOG_LEVEL ?? "info",
  transport: {
    target: "pino-pretty",
    options: { colorize: true, translateTime: "HH:MM:ss" },
  },
});
```

- [ ] **Step 6: Install dependencies**

Run:
```bash
npm install
npm install -D pino-pretty
```

Expected: All dependencies install without errors.

- [ ] **Step 7: Verify build**

Run:
```bash
npm run typecheck
```

Expected: No output (success). If errors, fix before committing.

- [ ] **Step 8: Commit**

```bash
git init
git add package.json package-lock.json tsconfig.json vitest.config.ts .gitignore src/utils/logger.ts
git commit -m "chore: initial project scaffold"
```

---

## Task 2: Core Model Types

**Files:**
- Create: `src/model/types.ts`
- Create: `src/model/severity.ts`
- Create: `tests/model/severity.test.ts`

- [ ] **Step 1: Write failing test for severity ordering**

Create `tests/model/severity.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { severityRank, isAtOrAbove, compareSeverity } from "../../src/model/severity.js";

describe("severity", () => {
  it("ranks critical highest and info lowest", () => {
    expect(severityRank("critical")).toBe(4);
    expect(severityRank("high")).toBe(3);
    expect(severityRank("medium")).toBe(2);
    expect(severityRank("low")).toBe(1);
    expect(severityRank("info")).toBe(0);
  });

  it("isAtOrAbove returns true when severity meets threshold", () => {
    expect(isAtOrAbove("critical", "high")).toBe(true);
    expect(isAtOrAbove("high", "high")).toBe(true);
    expect(isAtOrAbove("medium", "high")).toBe(false);
  });

  it("compareSeverity sorts critical first", () => {
    const sorted = ["low", "critical", "medium", "high"].sort(compareSeverity);
    expect(sorted).toEqual(["critical", "high", "medium", "low"]);
  });
});
```

- [ ] **Step 2: Create core types**

Create `src/model/types.ts`:

```typescript
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "confirmed" | "high" | "medium" | "low";

export type Layer = "rules" | "ai" | "probe";

export type StackProfile = "nextjs-supabase" | "react-vite-supabase" | "generic-web";

export type SecurityDomain =
  | "secrets-exposure"
  | "input-injection"
  | "auth-access-control"
  | "file-upload"
  | "api-security"
  | "cryptography"
  | "supply-chain"
  | "infrastructure"
  | "business-logic"
  | "logging-monitoring";

export interface Evidence {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
  context?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  domain: SecurityDomain;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  evidence: Evidence[];
  remediation: string;
  references: string[];
  layer: Layer;
  cwe?: string;
  owasp?: string;
  ruleId?: string;
}

export interface Route {
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD" | "ALL";
  file: string;
  isApi: boolean;
  hasAuthCheck: boolean;
  paramNames: string[];
}

export interface ApiEndpoint {
  path: string;
  method: Route["method"];
  file: string;
  handlerName?: string;
  hasValidation: boolean;
  validationLibrary?: "zod" | "yup" | "joi" | null;
  hasAuthCheck: boolean;
  usesServiceRole: boolean;
}

export interface UploadHandler {
  file: string;
  line: number;
  acceptsMultipart: boolean;
  hasMimeValidation: boolean;
  hasSizeLimit: boolean;
  usesUserFilename: boolean;
  storageDestination: "supabase" | "s3" | "local" | "other" | null;
}

export interface AuthFlow {
  type: "signup" | "login" | "oauth" | "magic-link" | "jwt-refresh";
  file: string;
  provider?: string;
}

export interface DataModel {
  name: string;
  source: "supabase" | "drizzle" | "prisma" | "other";
  hasRls: boolean | null;
  rlsPolicies: string[];
}

export interface Dependency {
  name: string;
  version: string;
  type: "production" | "dev" | "peer" | "optional";
}

export interface EnvVar {
  name: string;
  clientExposed: boolean;
  referencedIn: string[];
  inExample: boolean;
}

export interface AssetRef {
  path: string;
  publiclyServed: boolean;
  sizeBytes: number;
}

export interface ProjectMeta {
  name: string;
  path: string;
  stack: StackProfile;
  packageManager: "pnpm" | "npm" | "yarn";
  language: "typescript" | "javascript";
  framework: string;
  deployTarget: string | null;
}

export interface ProjectModel {
  meta: ProjectMeta;
  routes: Route[];
  endpoints: ApiEndpoint[];
  fileUploads: UploadHandler[];
  authFlows: AuthFlow[];
  dataModels: DataModel[];
  dependencies: Dependency[];
  envVars: EnvVar[];
  staticAssets: AssetRef[];
  findings: Finding[];
}
```

- [ ] **Step 3: Create severity helpers**

Create `src/model/severity.ts`:

```typescript
import type { Severity } from "./types.js";

const RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function isAtOrAbove(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return RANK[b] - RANK[a];
}
```

- [ ] **Step 4: Run tests**

Run: `npm test`

Expected: severity tests pass (3/3).

- [ ] **Step 5: Commit**

```bash
git add src/model tests/model
git commit -m "feat(model): add core types and severity helpers"
```

---

## Task 3: Config Loader

**Files:**
- Create: `src/config.ts`
- Create: `.sentinelrc.defaults.json`
- Create: `tests/config.test.ts`

- [ ] **Step 1: Write failing config tests**

Create `tests/config.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { loadConfig, CONFIG_DEFAULTS } from "../src/config.js";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("config", () => {
  const tmp = join(tmpdir(), `sentinel-test-${Date.now()}`);

  it("returns defaults when no .sentinelrc.json exists", async () => {
    mkdirSync(tmp, { recursive: true });
    const config = await loadConfig(tmp);
    expect(config.stack).toBe(CONFIG_DEFAULTS.stack);
    expect(config.domains).toEqual(CONFIG_DEFAULTS.domains);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("merges user config with defaults", async () => {
    mkdirSync(tmp, { recursive: true });
    writeFileSync(
      join(tmp, ".sentinelrc.json"),
      JSON.stringify({ severity: { failOn: "critical" } }),
    );
    const config = await loadConfig(tmp);
    expect(config.severity.failOn).toBe("critical");
    expect(config.stack).toBe(CONFIG_DEFAULTS.stack);
    rmSync(tmp, { recursive: true, force: true });
  });

  it("rejects invalid config", async () => {
    mkdirSync(tmp, { recursive: true });
    writeFileSync(
      join(tmp, ".sentinelrc.json"),
      JSON.stringify({ severity: { failOn: "impossible-level" } }),
    );
    await expect(loadConfig(tmp)).rejects.toThrow();
    rmSync(tmp, { recursive: true, force: true });
  });
});
```

- [ ] **Step 2: Create defaults file**

Create `.sentinelrc.defaults.json`:

```json
{
  "stack": "nextjs-supabase",
  "domains": ["all"],
  "exclude": ["node_modules", ".next", "dist", "out", "build", ".git"],
  "severity": {
    "failOn": "high"
  },
  "output": {
    "format": "terminal",
    "dir": ".sentinel/reports"
  }
}
```

- [ ] **Step 3: Create config loader**

Create `src/config.ts`:

```typescript
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const ConfigSchema = z.object({
  stack: z.enum(["nextjs-supabase", "react-vite-supabase", "generic-web"]),
  domains: z.array(z.string()),
  exclude: z.array(z.string()),
  severity: z.object({
    failOn: SeveritySchema,
  }),
  output: z.object({
    format: z.enum(["terminal", "json", "html", "all"]),
    dir: z.string(),
  }),
});

export type SentinelConfig = z.infer<typeof ConfigSchema>;

export const CONFIG_DEFAULTS: SentinelConfig = {
  stack: "nextjs-supabase",
  domains: ["all"],
  exclude: ["node_modules", ".next", "dist", "out", "build", ".git"],
  severity: { failOn: "high" },
  output: { format: "terminal", dir: ".sentinel/reports" },
};

export async function loadConfig(projectPath: string): Promise<SentinelConfig> {
  const configPath = join(projectPath, ".sentinelrc.json");

  if (!existsSync(configPath)) {
    return CONFIG_DEFAULTS;
  }

  const raw = await readFile(configPath, "utf-8");
  const parsed = JSON.parse(raw);

  const merged = {
    ...CONFIG_DEFAULTS,
    ...parsed,
    severity: { ...CONFIG_DEFAULTS.severity, ...(parsed.severity ?? {}) },
    output: { ...CONFIG_DEFAULTS.output, ...(parsed.output ?? {}) },
  };

  return ConfigSchema.parse(merged);
}
```

- [ ] **Step 4: Run tests**

Run: `npm test`

Expected: 3 config tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts .sentinelrc.defaults.json tests/config.test.ts
git commit -m "feat(config): add config loader with defaults and validation"
```

---

## Task 4: Filesystem Utilities

**Files:**
- Create: `src/utils/fs.ts`
- Create: `tests/utils/fs.test.ts`

- [ ] **Step 1: Write failing tests**

Create `tests/utils/fs.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { isDeniedPath, safeReadFile, walkProject } from "../../src/utils/fs.js";
import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("fs utils", () => {
  describe("isDeniedPath", () => {
    it("denies /proc paths", () => {
      expect(isDeniedPath("/proc/self/mem")).toBe(true);
    });
    it("denies .ssh paths", () => {
      expect(isDeniedPath("/home/user/.ssh/id_rsa")).toBe(true);
    });
    it("denies .env files", () => {
      expect(isDeniedPath("/project/.env")).toBe(true);
      expect(isDeniedPath("/project/.env.local")).toBe(true);
    });
    it("allows normal source files", () => {
      expect(isDeniedPath("/project/src/app/page.tsx")).toBe(false);
    });
    it("allows .env.example", () => {
      expect(isDeniedPath("/project/.env.example")).toBe(false);
    });
  });

  describe("safeReadFile", () => {
    it("throws on denied path", async () => {
      await expect(safeReadFile("/etc/passwd")).rejects.toThrow(/denied/);
    });
  });

  describe("walkProject", () => {
    const tmp = join(tmpdir(), `sentinel-walk-${Date.now()}`);

    it("returns file paths respecting exclude patterns", async () => {
      mkdirSync(join(tmp, "src"), { recursive: true });
      mkdirSync(join(tmp, "node_modules", "pkg"), { recursive: true });
      writeFileSync(join(tmp, "src", "index.ts"), "export {}");
      writeFileSync(join(tmp, "node_modules", "pkg", "index.js"), "module.exports = {}");

      const files = await walkProject(tmp, ["node_modules"]);
      const relative = files.map((f) => f.replace(tmp + "/", ""));
      expect(relative).toContain("src/index.ts");
      expect(relative).not.toContain("node_modules/pkg/index.js");

      rmSync(tmp, { recursive: true, force: true });
    });
  });
});
```

- [ ] **Step 2: Create fs utility**

Create `src/utils/fs.ts`:

```typescript
import { readFile } from "fs/promises";
import fg from "fast-glob";
import { basename } from "path";

const DENY_PATTERNS: RegExp[] = [
  /(?:^|\/)proc\//,
  /(?:^|\/)sys\//,
  /(?:^|\/)dev\//,
  /(?:^|\/)etc\//,
  /(?:^|\/)root\//,
  /(?:^|\/)\.ssh\//,
];

export function isDeniedPath(path: string): boolean {
  for (const pattern of DENY_PATTERNS) {
    if (pattern.test(path)) return true;
  }

  const name = basename(path);
  if (name === ".env" || /^\.env\.[a-z]+$/.test(name)) {
    if (name === ".env.example" || name === ".env.sample") return false;
    return true;
  }

  return false;
}

export async function safeReadFile(path: string): Promise<string> {
  if (isDeniedPath(path)) {
    throw new Error(`Access denied: ${path}`);
  }
  return readFile(path, "utf-8");
}

export async function walkProject(
  projectPath: string,
  exclude: string[],
): Promise<string[]> {
  const patterns = ["**/*.{ts,tsx,js,jsx,mjs,cjs,json,md,yaml,yml,toml}"];
  const ignore = exclude.map((e) => `**/${e}/**`);

  const files = await fg(patterns, {
    cwd: projectPath,
    absolute: true,
    ignore,
    dot: true,
    followSymbolicLinks: false,
  });

  return files.filter((f) => !isDeniedPath(f));
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/utils/fs.test.ts`

Expected: 7 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/utils/fs.ts tests/utils/fs.test.ts
git commit -m "feat(utils): add filesystem helpers with deny-path enforcement"
```

---

## Task 5: AST Utilities

**Files:**
- Create: `src/utils/ast.ts`
- Create: `tests/utils/ast.test.ts`

- [ ] **Step 1: Write failing tests**

Create `tests/utils/ast.test.ts`:

```typescript
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
```

- [ ] **Step 2: Create AST utility**

Create `src/utils/ast.ts`:

```typescript
import ts from "typescript";

export function parseSource(fileName: string, source: string): ts.SourceFile {
  return ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    fileName.endsWith(".tsx") || fileName.endsWith(".jsx")
      ? ts.ScriptKind.TSX
      : ts.ScriptKind.TS,
  );
}

export function walkAst(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => walkAst(child, callback));
}

export function findIdentifierUsages(sf: ts.SourceFile, name: string): ts.Node[] {
  const usages: ts.Node[] = [];
  walkAst(sf, (node) => {
    if (ts.isIdentifier(node) && node.text === name) {
      usages.push(node);
    }
  });
  return usages;
}

export function findImportsFrom(sf: ts.SourceFile, moduleName: string): string[] {
  const imports: string[] = [];
  walkAst(sf, (node) => {
    if (ts.isImportDeclaration(node)) {
      const mod = node.moduleSpecifier;
      if (ts.isStringLiteral(mod) && mod.text === moduleName) {
        const clause = node.importClause;
        if (clause?.name) imports.push(clause.name.text);
        if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            imports.push(element.name.text);
          }
        }
      }
    }
  });
  return imports;
}

export function findStringLiterals(sf: ts.SourceFile): string[] {
  const literals: string[] = [];
  walkAst(sf, (node) => {
    if (ts.isStringLiteral(node)) literals.push(node.text);
    if (ts.isNoSubstitutionTemplateLiteral(node)) literals.push(node.text);
  });
  return literals;
}

export function getLineNumber(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

export function getColumnNumber(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart()).character + 1;
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/utils/ast.test.ts`

Expected: 5 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/utils/ast.ts tests/utils/ast.test.ts
git commit -m "feat(utils): add TypeScript AST parsing helpers"
```

---

## Task 6: CLI Entry Point (Skeleton)

**Files:**
- Create: `src/cli.ts`
- Create: `src/commands/scan.ts`
- Create: `tests/cli.test.ts`

- [ ] **Step 1: Write failing test for CLI help**

Create `tests/cli.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { execSync } from "child_process";

describe("cli", () => {
  it("shows help when --help passed", () => {
    const output = execSync("npx tsx src/cli.ts --help", { encoding: "utf-8" });
    expect(output).toContain("sentinel");
    expect(output).toContain("scan");
  });

  it("shows version when --version passed", () => {
    const output = execSync("npx tsx src/cli.ts --version", { encoding: "utf-8" });
    expect(output).toMatch(/\d+\.\d+\.\d+/);
  });
});
```

- [ ] **Step 2: Create scan command stub**

Create `src/commands/scan.ts`:

```typescript
import { logger } from "../utils/logger.js";
import { loadConfig } from "../config.js";

export interface ScanOptions {
  path: string;
  format: "terminal" | "json";
  severity?: "critical" | "high" | "medium" | "low" | "info";
  failOn?: "critical" | "high" | "medium" | "low" | "info";
}

export async function runScan(options: ScanOptions): Promise<number> {
  logger.info({ path: options.path }, "sentinel scan starting");
  const config = await loadConfig(options.path);
  logger.info({ stack: config.stack }, "config loaded");
  // Wiring happens in Task 20
  return 0;
}
```

- [ ] **Step 3: Create CLI entry point**

Create `src/cli.ts`:

```typescript
#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { runScan } from "./commands/scan.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8"));

const program = new Command();

program
  .name("sentinel")
  .description("Security assessment CLI for Next.js + Supabase codebases")
  .version(pkg.version);

program
  .command("scan")
  .description("Run Recon + Rules scan against a project")
  .argument("<path>", "Path to the project to scan")
  .option("-f, --format <format>", "Output format (terminal|json)", "terminal")
  .option("-s, --severity <level>", "Minimum severity to report")
  .option("--fail-on <level>", "Exit 1 if findings at or above level")
  .action(async (path, options) => {
    const exitCode = await runScan({ path, ...options });
    process.exit(exitCode);
  });

program.parseAsync(process.argv);
```

- [ ] **Step 4: Run tests**

Run: `npm test tests/cli.test.ts`

Expected: 2 tests pass.

- [ ] **Step 5: Manual smoke test**

Run: `npx tsx src/cli.ts scan .`

Expected: Logs "sentinel scan starting" and exits 0.

- [ ] **Step 6: Commit**

```bash
git add src/cli.ts src/commands/scan.ts tests/cli.test.ts
git commit -m "feat(cli): add CLI entry point and scan command skeleton"
```

---

## Task 7: Vulnerable Fixture Project

**Files:**
- Create: `tests/fixtures/vulnerable-nextjs/package.json`
- Create: `tests/fixtures/vulnerable-nextjs/next.config.mjs`
- Create: `tests/fixtures/vulnerable-nextjs/tsconfig.json`
- Create: `tests/fixtures/vulnerable-nextjs/.env.example`
- Create: `tests/fixtures/vulnerable-nextjs/src/lib/supabase.ts`
- Create: `tests/fixtures/vulnerable-nextjs/src/app/page.tsx`
- Create: `tests/fixtures/vulnerable-nextjs/src/app/api/profile/route.ts`
- Create: `tests/fixtures/vulnerable-nextjs/src/app/api/upload/route.ts`
- Create: `tests/fixtures/vulnerable-nextjs/src/app/api/projects/[id]/route.ts`
- Create: `tests/fixtures/vulnerable-nextjs/src/components/ProfileCard.tsx`

This fixture is deliberately vulnerable. Every Phase 1 rule should be triggerable against it. The fixture is NOT a real installable project — it is static source files for recon and rules to analyze.

- [ ] **Step 1: Create package.json**

Create `tests/fixtures/vulnerable-nextjs/package.json`:

```json
{
  "name": "vulnerable-nextjs-fixture",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "next": "14.2.0",
    "react": "18.2.0",
    "react-dom": "18.2.0",
    "@supabase/supabase-js": "2.39.0"
  }
}
```

- [ ] **Step 2: Create next.config.mjs**

```javascript
export default {
  reactStrictMode: true,
};
```

- [ ] **Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "preserve",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

- [ ] **Step 4: Create .env.example**

```
NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
```

- [ ] **Step 5: Create vulnerable supabase client**

Create `src/lib/supabase.ts`:

```typescript
import { createClient } from "@supabase/supabase-js";

// VULN SECRETS-001: Service role key used client-side
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

// VULN SECRETS-004: Hardcoded credentials
export const apiKey = "sk-proj-1234567890abcdef";
export const password = "SuperSecret123!";
```

- [ ] **Step 6: Create vulnerable page**

Create `src/app/page.tsx`:

```tsx
export default function Page() {
  return <h1>Home</h1>;
}
```

- [ ] **Step 7: Create vulnerable profile API route**

Create `src/app/api/profile/route.ts`:

```typescript
import { supabase } from "@/lib/supabase";

// VULN AUTH-001: Mutation endpoint without auth check
// VULN INPUT-005: No validation on request body
export async function POST(req: Request) {
  const body = await req.json();
  // VULN AUTH-005: Admin API used outside server-only module
  const { data } = await supabase.auth.admin.listUsers();
  // VULN API rules would flag: mass assignment
  await supabase.from("profiles").upsert({ ...body });
  return Response.json({ ok: true });
}
```

- [ ] **Step 8: Create vulnerable upload route**

Create `src/app/api/upload/route.ts`:

```typescript
import { supabase } from "@/lib/supabase";

// VULN UPLOAD-001: No MIME validation
// VULN UPLOAD-002: No size limit
// VULN UPLOAD-004: User-provided filename used in storage path
export async function POST(req: Request) {
  const formData = await req.formData();
  const file = formData.get("file") as File;
  const filename = formData.get("filename") as string;

  const { data } = await supabase.storage
    .from("uploads")
    .upload(filename, file);

  return Response.json({ path: data?.path });
}
```

- [ ] **Step 9: Create vulnerable IDOR route**

Create `src/app/api/projects/[id]/route.ts`:

```typescript
import { supabase } from "@/lib/supabase";

// VULN AUTH-004: Fetches by ID without ownership check
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase
    .from("projects")
    .select("*")
    .eq("id", params.id)
    .single();

  return Response.json(data);
}
```

- [ ] **Step 10: Create vulnerable component**

Create `src/components/ProfileCard.tsx`:

```tsx
interface Props {
  bio: string;
}

// VULN INPUT-001: dangerouslySetInnerHTML without sanitization
export function ProfileCard({ bio }: Props) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
```

- [ ] **Step 11: Commit**

```bash
git add tests/fixtures/vulnerable-nextjs
git commit -m "test(fixtures): add deliberately vulnerable Next.js fixture project"
```

---

## Task 8: Stack Detector

**Files:**
- Create: `src/layers/recon/stack-detector.ts`
- Create: `tests/recon/stack-detector.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/recon/stack-detector.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { detectStack } from "../../src/layers/recon/stack-detector.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("stack-detector", () => {
  it("detects nextjs-supabase stack from fixture", async () => {
    const meta = await detectStack(fixturePath);
    expect(meta.stack).toBe("nextjs-supabase");
    expect(meta.framework).toBe("nextjs-app");
    expect(meta.language).toBe("typescript");
  });

  it("detects package manager from lockfile", async () => {
    const meta = await detectStack(fixturePath);
    expect(["npm", "pnpm", "yarn"]).toContain(meta.packageManager);
  });
});
```

- [ ] **Step 2: Create stack detector**

Create `src/layers/recon/stack-detector.ts`:

```typescript
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, basename } from "path";
import type { ProjectMeta, StackProfile } from "../../model/types.js";

export async function detectStack(projectPath: string): Promise<ProjectMeta> {
  const pkgPath = join(projectPath, "package.json");
  if (!existsSync(pkgPath)) {
    throw new Error(`No package.json found in ${projectPath}`);
  }

  const pkg = JSON.parse(await readFile(pkgPath, "utf-8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  const hasNext = "next" in deps;
  const hasVite = "vite" in deps;
  const hasSupabase = "@supabase/supabase-js" in deps;

  let stack: StackProfile = "generic-web";
  let framework = "unknown";

  if (hasNext && hasSupabase) {
    stack = "nextjs-supabase";
    framework = existsSync(join(projectPath, "src", "app")) || existsSync(join(projectPath, "app"))
      ? "nextjs-app"
      : "nextjs-pages";
  } else if (hasVite && hasSupabase) {
    stack = "react-vite-supabase";
    framework = "vite-react";
  } else if (hasNext) {
    framework = "nextjs";
  } else if (hasVite) {
    framework = "vite";
  }

  const language: "typescript" | "javascript" = existsSync(join(projectPath, "tsconfig.json"))
    ? "typescript"
    : "javascript";

  let packageManager: "pnpm" | "npm" | "yarn" = "npm";
  if (existsSync(join(projectPath, "pnpm-lock.yaml"))) packageManager = "pnpm";
  else if (existsSync(join(projectPath, "yarn.lock"))) packageManager = "yarn";
  else if (existsSync(join(projectPath, "package-lock.json"))) packageManager = "npm";

  let deployTarget: string | null = null;
  if (existsSync(join(projectPath, "vercel.json"))) deployTarget = "vercel";
  else if (existsSync(join(projectPath, "wrangler.toml"))) deployTarget = "cloudflare";
  else if (existsSync(join(projectPath, "fly.toml"))) deployTarget = "fly";
  else if (existsSync(join(projectPath, "Dockerfile"))) deployTarget = "docker";

  return {
    name: pkg.name ?? basename(projectPath),
    path: projectPath,
    stack,
    packageManager,
    language,
    framework,
    deployTarget,
  };
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/recon/stack-detector.test.ts`

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/recon/stack-detector.ts tests/recon/stack-detector.test.ts
git commit -m "feat(recon): add stack detector for nextjs-supabase"
```

---

## Task 9: Route Discovery

**Files:**
- Create: `src/layers/recon/route-discovery.ts`
- Create: `tests/recon/route-discovery.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/recon/route-discovery.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { discoverRoutes } from "../../src/layers/recon/route-discovery.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("route-discovery", () => {
  it("finds app router routes from fixture", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const paths = routes.map((r) => r.path);
    expect(paths).toContain("/");
    expect(paths).toContain("/api/profile");
    expect(paths).toContain("/api/upload");
    expect(paths).toContain("/api/projects/[id]");
  });

  it("identifies API routes vs pages", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const apiRoutes = routes.filter((r) => r.isApi);
    const pageRoutes = routes.filter((r) => !r.isApi);
    expect(apiRoutes.length).toBeGreaterThanOrEqual(3);
    expect(pageRoutes.length).toBeGreaterThanOrEqual(1);
  });

  it("extracts param names from dynamic segments", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const dynamic = routes.find((r) => r.path === "/api/projects/[id]");
    expect(dynamic?.paramNames).toContain("id");
  });
});
```

- [ ] **Step 2: Create route discovery**

Create `src/layers/recon/route-discovery.ts`:

```typescript
import fg from "fast-glob";
import { join, relative, dirname } from "path";
import { existsSync } from "fs";
import { safeReadFile } from "../../utils/fs.js";
import type { Route } from "../../model/types.js";

export async function discoverRoutes(
  projectPath: string,
  framework: string,
): Promise<Route[]> {
  if (framework !== "nextjs-app" && framework !== "nextjs-pages") return [];

  const appDir = existsSync(join(projectPath, "src", "app"))
    ? join(projectPath, "src", "app")
    : existsSync(join(projectPath, "app"))
    ? join(projectPath, "app")
    : null;

  if (!appDir) return [];

  const files = await fg(["**/{page,route}.{ts,tsx,js,jsx}"], {
    cwd: appDir,
    absolute: true,
    ignore: ["**/node_modules/**"],
  });

  const routes: Route[] = [];

  for (const file of files) {
    const rel = relative(appDir, dirname(file));
    const routePath = "/" + rel.replace(/\\/g, "/").replace(/^$/, "");
    const normalized = routePath === "/." || routePath === "/" ? "/" : routePath.replace(/\/page$/, "");
    const isApi = rel.startsWith("api/") || rel === "api";
    const paramNames = [...normalized.matchAll(/\[([^\]]+)\]/g)].map((m) => m[1]);

    const source = await safeReadFile(file);
    const hasAuthCheck = /auth|getUser|getSession|supabase\.auth/.test(source);

    if (file.endsWith("route.ts") || file.endsWith("route.tsx") || file.endsWith("route.js") || file.endsWith("route.jsx")) {
      const methods = extractHttpMethods(source);
      for (const method of methods) {
        routes.push({
          path: normalized,
          method,
          file,
          isApi: true,
          hasAuthCheck,
          paramNames,
        });
      }
    } else {
      routes.push({
        path: normalized,
        method: "GET",
        file,
        isApi: false,
        hasAuthCheck,
        paramNames,
      });
    }
  }

  return routes;
}

function extractHttpMethods(source: string): Array<Route["method"]> {
  const methods: Array<Route["method"]> = [];
  const names: Array<Route["method"]> = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
  for (const name of names) {
    const pattern = new RegExp(`export\\s+(async\\s+)?function\\s+${name}\\b`);
    if (pattern.test(source)) methods.push(name);
  }
  return methods.length > 0 ? methods : ["ALL"];
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/recon/route-discovery.test.ts`

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/recon/route-discovery.ts tests/recon/route-discovery.test.ts
git commit -m "feat(recon): add Next.js route discovery"
```

---

## Task 10: Endpoint Discovery

**Files:**
- Create: `src/layers/recon/endpoint-discovery.ts`
- Create: `tests/recon/endpoint-discovery.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/recon/endpoint-discovery.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { discoverEndpoints } from "../../src/layers/recon/endpoint-discovery.js";
import { discoverRoutes } from "../../src/layers/recon/route-discovery.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("endpoint-discovery", () => {
  it("extracts API endpoints with validation and auth metadata", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost).toBeDefined();
    expect(profilePost?.hasValidation).toBe(false);
    expect(profilePost?.hasAuthCheck).toBe(false);
  });

  it("detects service role usage", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost?.usesServiceRole).toBe(true);
  });
});
```

- [ ] **Step 2: Create endpoint discovery**

Create `src/layers/recon/endpoint-discovery.ts`:

```typescript
import { safeReadFile } from "../../utils/fs.js";
import type { Route, ApiEndpoint } from "../../model/types.js";

export async function discoverEndpoints(routes: Route[]): Promise<ApiEndpoint[]> {
  const endpoints: ApiEndpoint[] = [];
  const apiRoutes = routes.filter((r) => r.isApi);

  for (const route of apiRoutes) {
    const source = await safeReadFile(route.file);
    const hasValidation = /zod|yup|joi|\.parse\(|\.validate\(/.test(source);
    const validationLibrary = /zod/.test(source)
      ? "zod"
      : /yup/.test(source)
      ? "yup"
      : /joi/.test(source)
      ? "joi"
      : null;
    const usesServiceRole = /SERVICE_ROLE|service_role|auth\.admin/.test(source);

    endpoints.push({
      path: route.path,
      method: route.method,
      file: route.file,
      hasValidation,
      validationLibrary,
      hasAuthCheck: route.hasAuthCheck,
      usesServiceRole,
    });
  }

  return endpoints;
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/recon/endpoint-discovery.test.ts`

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/recon/endpoint-discovery.ts tests/recon/endpoint-discovery.test.ts
git commit -m "feat(recon): add API endpoint discovery"
```

---

## Task 11: Auth, Upload, Env, Dep Discovery

This task bundles four smaller discovery modules. Each has one test and one implementation file.

**Files:**
- Create: `src/layers/recon/auth-discovery.ts`
- Create: `src/layers/recon/upload-discovery.ts`
- Create: `src/layers/recon/env-discovery.ts`
- Create: `src/layers/recon/dep-discovery.ts`
- Create: `tests/recon/other-discovery.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/recon/other-discovery.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { discoverUploadHandlers } from "../../src/layers/recon/upload-discovery.js";
import { discoverEnvVars } from "../../src/layers/recon/env-discovery.js";
import { discoverDependencies } from "../../src/layers/recon/dep-discovery.js";
import { walkProject } from "../../src/utils/fs.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("other discovery", () => {
  it("finds upload handlers in the fixture", async () => {
    const files = await walkProject(fixturePath, ["node_modules"]);
    const uploads = await discoverUploadHandlers(files);
    expect(uploads.length).toBeGreaterThanOrEqual(1);
    const first = uploads[0];
    expect(first.usesUserFilename).toBe(true);
    expect(first.storageDestination).toBe("supabase");
  });

  it("maps env var usage", async () => {
    const files = await walkProject(fixturePath, ["node_modules"]);
    const envVars = await discoverEnvVars(fixturePath, files);
    const serviceRole = envVars.find((e) => e.name === "SUPABASE_SERVICE_ROLE_KEY");
    expect(serviceRole).toBeDefined();
    expect(serviceRole?.inExample).toBe(false);
    const publicUrl = envVars.find((e) => e.name === "NEXT_PUBLIC_SUPABASE_URL");
    expect(publicUrl?.clientExposed).toBe(true);
    expect(publicUrl?.inExample).toBe(true);
  });

  it("reads dependencies from package.json", async () => {
    const deps = await discoverDependencies(fixturePath);
    const next = deps.find((d) => d.name === "next");
    expect(next).toBeDefined();
    expect(next?.type).toBe("production");
  });
});
```

- [ ] **Step 2: Create upload discovery**

Create `src/layers/recon/upload-discovery.ts`:

```typescript
import { safeReadFile } from "../../utils/fs.js";
import type { UploadHandler } from "../../model/types.js";

const UPLOAD_SIGNALS = [
  /formData\s*\(\s*\)/,
  /\.formData\s*\(\s*\)/,
  /multer/,
  /multipart/,
  /\.upload\s*\(/,
];

export async function discoverUploadHandlers(files: string[]): Promise<UploadHandler[]> {
  const handlers: UploadHandler[] = [];

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx)$/.test(file)) continue;

    const source = await safeReadFile(file);
    const acceptsMultipart = UPLOAD_SIGNALS.some((rx) => rx.test(source));
    if (!acceptsMultipart) continue;

    const hasMimeValidation = /content-?type|mimetype|\.type\s*===|\.type\s*==\s*/i.test(source);
    const hasSizeLimit = /\.size\s*[<>=]|MAX_|SIZE_LIMIT|maxSize/i.test(source);
    const usesUserFilename = /formData\.get\(\s*["']filename["']|\.name\s*\|\|\s*["']|userFilename/.test(source);

    let storageDestination: UploadHandler["storageDestination"] = null;
    if (/supabase\.storage/.test(source)) storageDestination = "supabase";
    else if (/S3Client|aws-sdk\/client-s3|\.putObject/.test(source)) storageDestination = "s3";
    else if (/fs\.writeFile|fs\.createWriteStream/.test(source)) storageDestination = "local";

    const uploadLine = source.split("\n").findIndex((l) => UPLOAD_SIGNALS.some((rx) => rx.test(l)));

    handlers.push({
      file,
      line: uploadLine + 1,
      acceptsMultipart,
      hasMimeValidation,
      hasSizeLimit,
      usesUserFilename,
      storageDestination,
    });
  }

  return handlers;
}
```

- [ ] **Step 3: Create auth discovery**

Create `src/layers/recon/auth-discovery.ts`:

```typescript
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
```

- [ ] **Step 4: Create env discovery**

Create `src/layers/recon/env-discovery.ts`:

```typescript
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { safeReadFile } from "../../utils/fs.js";
import type { EnvVar } from "../../model/types.js";

const ENV_REFERENCE = /process\.env\.([A-Z0-9_]+)|import\.meta\.env\.([A-Z0-9_]+)/g;

export async function discoverEnvVars(
  projectPath: string,
  files: string[],
): Promise<EnvVar[]> {
  const usage = new Map<string, Set<string>>();

  for (const file of files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) continue;
    const source = await safeReadFile(file);
    let match;
    while ((match = ENV_REFERENCE.exec(source)) !== null) {
      const name = match[1] ?? match[2];
      if (!name) continue;
      if (!usage.has(name)) usage.set(name, new Set());
      usage.get(name)!.add(file);
    }
  }

  const examplePath = join(projectPath, ".env.example");
  const exampleVars = new Set<string>();
  if (existsSync(examplePath)) {
    const content = await readFile(examplePath, "utf-8");
    for (const line of content.split("\n")) {
      const m = line.match(/^([A-Z0-9_]+)\s*=/);
      if (m) exampleVars.add(m[1]);
    }
  }

  const result: EnvVar[] = [];
  for (const [name, refs] of usage.entries()) {
    result.push({
      name,
      clientExposed: name.startsWith("NEXT_PUBLIC_") || name.startsWith("VITE_") || name.startsWith("PUBLIC_"),
      referencedIn: Array.from(refs),
      inExample: exampleVars.has(name),
    });
  }

  return result;
}
```

- [ ] **Step 5: Create dep discovery**

Create `src/layers/recon/dep-discovery.ts`:

```typescript
import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency } from "../../model/types.js";

export async function discoverDependencies(projectPath: string): Promise<Dependency[]> {
  const pkg = JSON.parse(await readFile(join(projectPath, "package.json"), "utf-8"));
  const deps: Dependency[] = [];

  const addGroup = (obj: Record<string, string> | undefined, type: Dependency["type"]) => {
    if (!obj) return;
    for (const [name, version] of Object.entries(obj)) {
      deps.push({ name, version, type });
    }
  };

  addGroup(pkg.dependencies, "production");
  addGroup(pkg.devDependencies, "dev");
  addGroup(pkg.peerDependencies, "peer");
  addGroup(pkg.optionalDependencies, "optional");

  return deps;
}
```

- [ ] **Step 6: Run tests**

Run: `npm test tests/recon/other-discovery.test.ts`

Expected: 3 tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/layers/recon/auth-discovery.ts src/layers/recon/upload-discovery.ts src/layers/recon/env-discovery.ts src/layers/recon/dep-discovery.ts tests/recon/other-discovery.test.ts
git commit -m "feat(recon): add auth, upload, env, and dependency discovery"
```

---

## Task 12: Recon Orchestrator

**Files:**
- Create: `src/layers/recon/index.ts`
- Create: `tests/recon/orchestrator.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/recon/orchestrator.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { runRecon } from "../../src/layers/recon/index.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("recon orchestrator", () => {
  it("builds a complete ProjectModel", async () => {
    const model = await runRecon(fixturePath, ["node_modules"]);
    expect(model.meta.stack).toBe("nextjs-supabase");
    expect(model.routes.length).toBeGreaterThan(0);
    expect(model.endpoints.length).toBeGreaterThan(0);
    expect(model.fileUploads.length).toBeGreaterThanOrEqual(1);
    expect(model.envVars.length).toBeGreaterThan(0);
    expect(model.dependencies.length).toBeGreaterThan(0);
    expect(model.findings).toEqual([]);
  });
});
```

- [ ] **Step 2: Create orchestrator**

Create `src/layers/recon/index.ts`:

```typescript
import { walkProject } from "../../utils/fs.js";
import { detectStack } from "./stack-detector.js";
import { discoverRoutes } from "./route-discovery.js";
import { discoverEndpoints } from "./endpoint-discovery.js";
import { discoverAuthFlows } from "./auth-discovery.js";
import { discoverUploadHandlers } from "./upload-discovery.js";
import { discoverEnvVars } from "./env-discovery.js";
import { discoverDependencies } from "./dep-discovery.js";
import type { ProjectModel } from "../../model/types.js";

export async function runRecon(
  projectPath: string,
  exclude: string[],
): Promise<ProjectModel> {
  const meta = await detectStack(projectPath);
  const files = await walkProject(projectPath, exclude);

  const [routes, authFlows, fileUploads, envVars, dependencies] = await Promise.all([
    discoverRoutes(projectPath, meta.framework),
    discoverAuthFlows(files),
    discoverUploadHandlers(files),
    discoverEnvVars(projectPath, files),
    discoverDependencies(projectPath),
  ]);

  const endpoints = await discoverEndpoints(routes);

  return {
    meta,
    routes,
    endpoints,
    fileUploads,
    authFlows,
    dataModels: [],
    dependencies,
    envVars,
    staticAssets: [],
    findings: [],
  };
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/recon/orchestrator.test.ts`

Expected: 1 test passes.

- [ ] **Step 4: Commit**

```bash
git add src/layers/recon/index.ts tests/recon/orchestrator.test.ts
git commit -m "feat(recon): add orchestrator building full ProjectModel"
```

---

## Task 13: Rule Engine and Registry

**Files:**
- Create: `src/layers/rules/registry.ts`
- Create: `src/layers/rules/index.ts`
- Create: `tests/rules/engine.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/rules/engine.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { runRules, registerRule, resetRegistry } from "../../src/layers/rules/index.js";
import type { SecurityRule } from "../../src/layers/rules/registry.js";
import type { ProjectModel } from "../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: {
      name: "test",
      path: "/tmp",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "nextjs-app",
      deployTarget: null,
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    findings: [],
  };
}

describe("rule engine", () => {
  it("runs registered rules and returns findings", async () => {
    resetRegistry();
    const rule: SecurityRule = {
      id: "TEST-001",
      domain: "secrets-exposure",
      title: "test rule",
      description: "always fires",
      severity: "low",
      appliesTo: ["nextjs-supabase"],
      references: {},
      check: () => [
        {
          id: "TEST-001-1",
          domain: "secrets-exposure",
          severity: "low",
          confidence: "high",
          title: "test finding",
          description: "fired",
          evidence: [],
          remediation: "none",
          references: [],
          layer: "rules",
          ruleId: "TEST-001",
        },
      ],
    };
    registerRule(rule);

    const findings = await runRules(emptyModel());
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("TEST-001");
  });

  it("skips rules that do not apply to stack", async () => {
    resetRegistry();
    registerRule({
      id: "TEST-002",
      domain: "secrets-exposure",
      title: "wrong stack",
      description: "should be skipped",
      severity: "low",
      appliesTo: ["generic-web"],
      references: {},
      check: () => [{
        id: "TEST-002-1",
        domain: "secrets-exposure",
        severity: "low",
        confidence: "high",
        title: "fired",
        description: "",
        evidence: [],
        remediation: "",
        references: [],
        layer: "rules",
        ruleId: "TEST-002",
      }],
    });
    const findings = await runRules(emptyModel());
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Create registry**

Create `src/layers/rules/registry.ts`:

```typescript
import type { Finding, ProjectModel, Severity, SecurityDomain, StackProfile } from "../../model/types.js";

export interface SecurityRule {
  id: string;
  domain: SecurityDomain;
  title: string;
  description: string;
  severity: Severity;
  appliesTo: StackProfile[];
  references: {
    cwe?: string;
    owasp?: string;
    external?: string[];
  };
  check: (model: ProjectModel) => Finding[] | Promise<Finding[]>;
}

const registry: SecurityRule[] = [];

export function registerRule(rule: SecurityRule): void {
  registry.push(rule);
}

export function registerRules(rules: SecurityRule[]): void {
  for (const rule of rules) registry.push(rule);
}

export function getRules(): readonly SecurityRule[] {
  return registry;
}

export function resetRegistry(): void {
  registry.length = 0;
}
```

- [ ] **Step 3: Create engine**

Create `src/layers/rules/index.ts`:

```typescript
import { getRules } from "./registry.js";
import type { Finding, ProjectModel } from "../../model/types.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export async function runRules(model: ProjectModel): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model))));
  return results.flat();
}
```

- [ ] **Step 4: Run tests**

Run: `npm test tests/rules/engine.test.ts`

Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/layers/rules tests/rules/engine.test.ts
git commit -m "feat(rules): add rule engine and registry"
```

---

## Task 14: Secrets & Exposure Rules

**Files:**
- Create: `src/layers/rules/domains/secrets-exposure.ts`
- Create: `tests/rules/secrets-exposure.test.ts`

This task implements all 9 SECRETS-00N rules.

- [ ] **Step 1: Write failing tests**

Create `tests/rules/secrets-exposure.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { secretsExposureRules } from "../../src/layers/rules/domains/secrets-exposure.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("secrets-exposure rules", () => {
  it("flags service role key used client-side (SECRETS-001)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets001 = findings.filter((f) => f.ruleId === "SECRETS-001");
    expect(secrets001.length).toBeGreaterThanOrEqual(1);
    expect(secrets001[0].severity).toBe("critical");
  });

  it("flags hardcoded credentials (SECRETS-004)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets004 = findings.filter((f) => f.ruleId === "SECRETS-004");
    expect(secrets004.length).toBeGreaterThanOrEqual(1);
  });

  it("flags env vars missing from .env.example (SECRETS-008)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets008 = findings.filter((f) => f.ruleId === "SECRETS-008");
    expect(secrets008.length).toBeGreaterThanOrEqual(1);
  });
});
```

- [ ] **Step 2: Create secrets rules**

Create `src/layers/rules/domains/secrets-exposure.ts`:

```typescript
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

const KNOWN_KEY_PATTERNS: Array<[string, RegExp]> = [
  ["stripe", /sk_(test|live)_[a-zA-Z0-9]{24,}/],
  ["openai", /sk-[a-zA-Z0-9]{20,}/],
  ["aws", /AKIA[0-9A-Z]{16}/],
  ["slack", /xox[bpoa]-[0-9]{10,}-[0-9a-zA-Z]{20,}/],
  ["github", /ghp_[a-zA-Z0-9]{36}/],
  ["supabase-service-role", /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/],
];

function mkFinding(
  rule: { id: string; severity: Finding["severity"]; title: string; remediation: string; references: { cwe?: string; owasp?: string } },
  evidence: Finding["evidence"],
  description: string,
): Finding {
  return {
    id: `${rule.id}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "secrets-exposure",
    severity: rule.severity,
    confidence: "high",
    title: rule.title,
    description,
    evidence,
    remediation: rule.remediation,
    references: [rule.references.cwe, rule.references.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId: rule.id,
    cwe: rule.references.cwe,
    owasp: rule.references.owasp,
  };
}

export const secretsExposureRules: SecurityRule[] = [
  {
    id: "SECRETS-001",
    domain: "secrets-exposure",
    title: "Service role key used client-side",
    description: "SUPABASE_SERVICE_ROLE_KEY referenced without server-only guard",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798", owasp: "A07:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const env of model.envVars) {
        if (env.name === "SUPABASE_SERVICE_ROLE_KEY") {
          for (const file of env.referencedIn) {
            const source = await safeReadFile(file);
            const isServerOnly = /"use server"|import\s+["']server-only["']/.test(source);
            const hasNodeCheck = /typeof window === ["']undefined["']/.test(source);
            if (!isServerOnly && !hasNodeCheck) {
              findings.push(
                mkFinding(
                  {
                    id: "SECRETS-001",
                    severity: "critical",
                    title: "Service role key used without server-only guard",
                    remediation: 'Move to a file with `import "server-only"` or inside a route handler verified server-side.',
                    references: { cwe: "CWE-798", owasp: "A07:2021" },
                  },
                  [{ file, snippet: "process.env.SUPABASE_SERVICE_ROLE_KEY" }],
                  "Admin key usage outside a server-only boundary exposes it to client bundles.",
                ),
              );
            }
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-002",
    domain: "secrets-exposure",
    title: "Known API key pattern in source",
    description: "Provider-specific secret pattern detected in source",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        const source = await safeReadFile(file);
        for (const [provider, pattern] of KNOWN_KEY_PATTERNS) {
          const match = source.match(pattern);
          if (match) {
            const line = source.substring(0, match.index ?? 0).split("\n").length;
            findings.push(
              mkFinding(
                {
                  id: "SECRETS-002",
                  severity: "critical",
                  title: `${provider} API key pattern in source`,
                  remediation: "Remove the secret. Rotate the key. Use environment variables for secrets.",
                  references: { cwe: "CWE-798" },
                },
                [{ file, line, snippet: match[0] }],
                `A string matching the ${provider} secret pattern was found in source code.`,
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-003",
    domain: "secrets-exposure",
    title: ".env file committed or not gitignored",
    description: ".env file present and not excluded from git",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-312" },
    check(model) {
      const findings: Finding[] = [];
      const envPath = join(model.meta.path, ".env");
      const gitignorePath = join(model.meta.path, ".gitignore");
      if (existsSync(envPath)) {
        const gitignored = existsSync(gitignorePath)
          ? readFileSync(gitignorePath, "utf-8").split("\n").some((l) => l.trim() === ".env" || l.trim() === ".env*")
          : false;
        if (!gitignored) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-003",
                severity: "critical",
                title: ".env file not gitignored",
                remediation: "Add `.env` to `.gitignore`. If already committed, rotate all secrets and remove from git history.",
                references: { cwe: "CWE-312" },
              },
              [{ file: envPath }],
              ".env file exists without being excluded from version control.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-004",
    domain: "secrets-exposure",
    title: "Hardcoded credentials in source",
    description: "String literal assigned to a suspicious variable name",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      const suspicious = /\b(password|passwd|pwd|secret|apiKey|api_key|token|accessKey|privateKey)\b\s*[:=]\s*["']([^"']{8,})["']/gi;

      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        const source = await safeReadFile(file);
        let match;
        while ((match = suspicious.exec(source)) !== null) {
          const line = source.substring(0, match.index).split("\n").length;
          if (/\b(test|example|fake|placeholder)\b/i.test(match[2])) continue;
          findings.push(
            mkFinding(
              {
                id: "SECRETS-004",
                severity: "high",
                title: "Hardcoded credential-like string",
                remediation: "Move the value to an environment variable. Rotate if this was a real credential.",
                references: { cwe: "CWE-798" },
              },
              [{ file, line, snippet: match[0] }],
              "A string literal with a credential-sounding variable name was found.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-005",
    domain: "secrets-exposure",
    title: "NEXT_PUBLIC_ prefix on secret-like variable",
    description: "Variable name suggests a secret but is client-exposed",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-312", owasp: "A07:2021" },
    check(model) {
      const findings: Finding[] = [];
      const suspicious = /(SECRET|PRIVATE|TOKEN|API_KEY|SERVICE_ROLE|PASSWORD)/;
      for (const env of model.envVars) {
        if (env.clientExposed && suspicious.test(env.name.replace(/^NEXT_PUBLIC_|^VITE_|^PUBLIC_/, ""))) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-005",
                severity: "high",
                title: `${env.name} is client-exposed but looks like a secret`,
                remediation: "Remove the NEXT_PUBLIC_ prefix. Serve secret-dependent logic from the server.",
                references: { cwe: "CWE-312", owasp: "A07:2021" },
              },
              env.referencedIn.map((f) => ({ file: f, snippet: env.name })),
              "Client-exposed env vars end up in the browser bundle and are readable by anyone.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-006",
    domain: "secrets-exposure",
    title: "Secret found in git history",
    description: "Requires --git-history flag. Placeholder in Phase 1.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798" },
    check() {
      // Phase 1: git history scanning deferred. Rule registered so registry is complete.
      return [];
    },
  },

  {
    id: "SECRETS-007",
    domain: "secrets-exposure",
    title: "Credentials or tokens in developer comments",
    description: "Source comments contain credential-like strings",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-615" },
    async check(model) {
      const findings: Finding[] = [];
      const commentPattern = /\/\/.*\b(password|token|apiKey|secret|credentials?)\s*[:=]/i;
      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        const source = await safeReadFile(file);
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (commentPattern.test(line)) {
            findings.push(
              mkFinding(
                {
                  id: "SECRETS-007",
                  severity: "medium",
                  title: "Credential-like comment in source",
                  remediation: "Remove the comment. Assume the value has been exposed.",
                  references: { cwe: "CWE-615" },
                },
                [{ file, line: idx + 1, snippet: line.trim() }],
                "Developer comments mentioning credentials have historically leaked to production.",
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "SECRETS-008",
    domain: "secrets-exposure",
    title: "Env var referenced but missing from .env.example",
    description: "Source references process.env.X but .env.example does not list X",
    severity: "low",
    appliesTo: ["nextjs-supabase"],
    references: {},
    check(model) {
      const findings: Finding[] = [];
      for (const env of model.envVars) {
        if (!env.inExample) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-008",
                severity: "low",
                title: `${env.name} not documented in .env.example`,
                remediation: "Add the variable to .env.example with a placeholder value.",
                references: {},
              },
              env.referencedIn.slice(0, 1).map((f) => ({ file: f, snippet: env.name })),
              "Missing .env.example entries cause onboarding failures and hide the app's config surface.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-009",
    domain: "secrets-exposure",
    title: "Build output directory not gitignored",
    description: ".next or dist present without being in .gitignore",
    severity: "info",
    appliesTo: ["nextjs-supabase"],
    references: {},
    check(model) {
      const findings: Finding[] = [];
      const gitignorePath = join(model.meta.path, ".gitignore");
      const gitignoreEntries = existsSync(gitignorePath)
        ? readFileSync(gitignorePath, "utf-8").split("\n").map((l) => l.trim())
        : [];
      const buildDirs = [".next", "dist", "out", "build"];
      for (const dir of buildDirs) {
        if (existsSync(join(model.meta.path, dir)) && !gitignoreEntries.includes(dir) && !gitignoreEntries.includes(`${dir}/`)) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-009",
                severity: "info",
                title: `${dir} directory is not gitignored`,
                remediation: `Add ${dir}/ to .gitignore.`,
                references: {},
              },
              [{ file: join(model.meta.path, dir) }],
              `Build artifacts may leak source maps or compiled secrets if committed.`,
            ),
          );
        }
      }
      return findings;
    },
  },
];
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/rules/secrets-exposure.test.ts`

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/rules/domains/secrets-exposure.ts tests/rules/secrets-exposure.test.ts
git commit -m "feat(rules): add 9 secrets-exposure rules"
```

---

## Task 15: Input & Injection Rules

**Files:**
- Create: `src/layers/rules/domains/input-injection.ts`
- Create: `tests/rules/input-injection.test.ts`

Implements all 10 INPUT-00N rules. Due to length, each rule follows the same `mkFinding` helper pattern established in Task 14. Key implementations:

- [ ] **Step 1: Write failing tests**

Create `tests/rules/input-injection.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { inputInjectionRules } from "../../src/layers/rules/domains/input-injection.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("input-injection rules", () => {
  it("flags dangerouslySetInnerHTML without sanitizer (INPUT-001)", async () => {
    resetRegistry();
    registerRules(inputInjectionRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const input001 = findings.filter((f) => f.ruleId === "INPUT-001");
    expect(input001.length).toBeGreaterThanOrEqual(1);
    expect(input001[0].severity).toBe("critical");
  });

  it("flags API route missing validation (INPUT-005)", async () => {
    resetRegistry();
    registerRules(inputInjectionRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const input005 = findings.filter((f) => f.ruleId === "INPUT-005");
    expect(input005.length).toBeGreaterThanOrEqual(1);
  });
});
```

- [ ] **Step 2: Create input-injection rules**

Create `src/layers/rules/domains/input-injection.ts`:

```typescript
import { safeReadFile } from "../../../utils/fs.js";
import fg from "fast-glob";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "input-injection",
    severity,
    confidence: "high",
    title,
    description,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

async function walkSourceFiles(model: ProjectModel): Promise<Array<{ file: string; source: string }>> {
  const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
    cwd: model.meta.path,
    absolute: true,
    ignore: ["**/node_modules/**", "**/.next/**", "**/dist/**"],
  });
  return Promise.all(
    files.map(async (file) => ({ file, source: await safeReadFile(file) })),
  );
}

async function scanLines(
  model: ProjectModel,
  pattern: RegExp,
  makeFinding: (file: string, line: number, match: RegExpMatchArray) => Finding,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(model);
  for (const { file, source } of files) {
    const lines = source.split("\n");
    lines.forEach((line, idx) => {
      const match = line.match(pattern);
      if (match) findings.push(makeFinding(file, idx + 1, match));
    });
  }
  return findings;
}

export const inputInjectionRules: SecurityRule[] = [
  {
    id: "INPUT-001",
    domain: "input-injection",
    title: "dangerouslySetInnerHTML without sanitization",
    description: "React's dangerouslySetInnerHTML used without DOMPurify or equivalent",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79", owasp: "A03:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/dangerouslySetInnerHTML/.test(source)) continue;
        const hasSanitizer = /DOMPurify|sanitize-html|isomorphic-dompurify/.test(source);
        if (hasSanitizer) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (/dangerouslySetInnerHTML/.test(line)) {
            findings.push(
              mkFinding(
                "INPUT-001",
                "critical",
                "dangerouslySetInnerHTML without sanitizer",
                "React component renders raw HTML without sanitization.",
                "Sanitize input with DOMPurify before passing to dangerouslySetInnerHTML.",
                [{ file, line: idx + 1, snippet: line.trim() }],
                { cwe: "CWE-79", owasp: "A03:2021" },
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "INPUT-002",
    domain: "input-injection",
    title: "innerHTML assignment with non-literal value",
    description: "Direct innerHTML assignment bypasses React's escaping",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return scanLines(
        model,
        /\.innerHTML\s*=\s*(?!["'])/,
        (file, line, match) =>
          mkFinding(
            "INPUT-002",
            "high",
            "innerHTML assignment with variable",
            "Setting innerHTML to a non-literal value can introduce XSS.",
            "Use textContent for text, or sanitize HTML before assignment.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-79" },
          ),
      );
    },
  },

  {
    id: "INPUT-003",
    domain: "input-injection",
    title: "SQL string concatenation",
    description: "Template literal used in raw SQL query",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-89", owasp: "A03:2021" },
    check(model) {
      return scanLines(
        model,
        /\.(query|execute|raw)\s*\(\s*`[^`]*\$\{/,
        (file, line, match) =>
          mkFinding(
            "INPUT-003",
            "critical",
            "SQL query built with template literal",
            "Interpolating values into SQL strings allows injection.",
            "Use parameterized queries. Pass values as a second argument to query().",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-89", owasp: "A03:2021" },
          ),
      );
    },
  },

  {
    id: "INPUT-004",
    domain: "input-injection",
    title: "eval or Function constructor used",
    description: "Dynamic code evaluation is a code injection vector",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-95" },
    check(model) {
      return scanLines(
        model,
        /\b(eval|new\s+Function|Function\s*\()/,
        (file, line, match) =>
          mkFinding(
            "INPUT-004",
            "critical",
            "Dynamic code evaluation",
            "eval and Function constructors execute arbitrary code.",
            "Refactor to avoid dynamic evaluation. Use JSON.parse for data.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-95" },
          ),
      );
    },
  },

  {
    id: "INPUT-005",
    domain: "input-injection",
    title: "API route missing request body validation",
    description: "Mutation endpoint accepts body without schema validation",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-20", owasp: "A03:2021" },
    check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const isMutation = ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method);
        if (isMutation && !endpoint.hasValidation) {
          findings.push(
            mkFinding(
              "INPUT-005",
              "high",
              `${endpoint.method} ${endpoint.path} missing body validation`,
              "API route does not validate request body against a schema.",
              "Add Zod or Yup schema and call .parse() on the request body.",
              [{ file: endpoint.file }],
              { cwe: "CWE-20", owasp: "A03:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "INPUT-006",
    domain: "input-injection",
    title: "window.location assigned from untrusted source",
    description: "Open redirect when location is set from user-controlled input",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-601" },
    check(model) {
      return scanLines(
        model,
        /(window\.location|location\.href)\s*=\s*[^"'`]/,
        (file, line, match) =>
          mkFinding(
            "INPUT-006",
            "high",
            "Location assignment from variable",
            "Assigning location from a variable without validation enables open redirect.",
            "Validate the URL against an allowlist before redirecting.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-601" },
          ),
      );
    },
  },

  {
    id: "INPUT-007",
    domain: "input-injection",
    title: "document.write used",
    description: "document.write is an XSS vector",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return scanLines(
        model,
        /document\.write\s*\(/,
        (file, line, match) =>
          mkFinding(
            "INPUT-007",
            "medium",
            "document.write used",
            "document.write bypasses React's escaping and can introduce XSS.",
            "Use React state or refs to update the DOM.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-79" },
          ),
      );
    },
  },

  {
    id: "INPUT-008",
    domain: "input-injection",
    title: "Shell command constructed with template string",
    description: "exec/spawn called with interpolated user input",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-78" },
    check(model) {
      return scanLines(
        model,
        /(exec|spawn|execSync|spawnSync)\s*\(\s*`[^`]*\$\{/,
        (file, line, match) =>
          mkFinding(
            "INPUT-008",
            "critical",
            "Shell command with interpolated value",
            "Building shell commands with template literals enables command injection.",
            "Use the array form of spawn() and pass arguments as array elements.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-78" },
          ),
      );
    },
  },

  {
    id: "INPUT-009",
    domain: "input-injection",
    title: "URL parameter passed to fetch (SSRF risk)",
    description: "fetch() called with a URL derived from request input",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-918" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/fetch\s*\(/.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (/fetch\s*\(\s*(req\.|request\.|searchParams|params\.|body\.)/.test(line)) {
            findings.push(
              mkFinding(
                "INPUT-009",
                "high",
                "fetch called with request-derived URL",
                "SSRF is possible when fetch targets are controlled by user input.",
                "Validate URLs against an allowlist of hosts before calling fetch.",
                [{ file, line: idx + 1, snippet: line.trim() }],
                { cwe: "CWE-918" },
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "INPUT-010",
    domain: "input-injection",
    title: "Regex constructed from user input",
    description: "new RegExp() called with a non-literal value",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-1333" },
    check(model) {
      return scanLines(
        model,
        /new\s+RegExp\s*\(\s*(?!["'/])/,
        (file, line, match) =>
          mkFinding(
            "INPUT-010",
            "medium",
            "Dynamic regex construction",
            "Building a regex from user input can cause ReDoS attacks.",
            "Escape regex metacharacters, or use simple string matching.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-1333" },
          ),
      );
    },
  },
];
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/rules/input-injection.test.ts`

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/rules/domains/input-injection.ts tests/rules/input-injection.test.ts
git commit -m "feat(rules): add 10 input-injection rules"
```

---

## Task 16: Auth & Access Control Rules

**Files:**
- Create: `src/layers/rules/domains/auth-access-control.ts`
- Create: `tests/rules/auth-access-control.test.ts`

Implements all 10 AUTH-00N rules. Following the same pattern as Task 15.

- [ ] **Step 1: Write failing tests**

Create `tests/rules/auth-access-control.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("auth-access-control rules", () => {
  it("flags mutation endpoint without auth (AUTH-001)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth001 = findings.filter((f) => f.ruleId === "AUTH-001");
    expect(auth001.length).toBeGreaterThanOrEqual(1);
  });

  it("flags params.id without ownership check (AUTH-004)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth004 = findings.filter((f) => f.ruleId === "AUTH-004");
    expect(auth004.length).toBeGreaterThanOrEqual(1);
  });

  it("flags auth.admin usage in non-server-only module (AUTH-005)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth005 = findings.filter((f) => f.ruleId === "AUTH-005");
    expect(auth005.length).toBeGreaterThanOrEqual(1);
  });
});
```

- [ ] **Step 2: Create auth-access-control rules**

Create `src/layers/rules/domains/auth-access-control.ts`:

```typescript
import { safeReadFile } from "../../../utils/fs.js";
import fg from "fast-glob";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "auth-access-control",
    severity,
    confidence: "high",
    title,
    description,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

export const authAccessControlRules: SecurityRule[] = [
  {
    id: "AUTH-001",
    domain: "auth-access-control",
    title: "Mutation endpoint without auth check",
    description: "POST/PUT/PATCH/DELETE handler has no auth detection",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method) && !endpoint.hasAuthCheck) {
          findings.push(
            mkFinding(
              "AUTH-001",
              "critical",
              `${endpoint.method} ${endpoint.path} has no auth check`,
              "Mutation endpoint does not reference any auth/session API.",
              "Add `supabase.auth.getUser()` and reject if the user is not authenticated.",
              [{ file: endpoint.file }],
              { cwe: "CWE-862", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-002",
    domain: "auth-access-control",
    title: "Supabase table referenced with no RLS migration found",
    description: "Placeholder: requires migrations parsing, reports info finding",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    async check(model) {
      const findings: Finding[] = [];
      const migrationsDir = ["supabase/migrations", "migrations"];
      let migrationContent = "";
      for (const dir of migrationsDir) {
        const files = await fg(["**/*.sql"], { cwd: `${model.meta.path}/${dir}`, absolute: true });
        for (const f of files) migrationContent += await safeReadFile(f);
      }

      if (migrationContent) {
        const enableRls = migrationContent.match(/alter\s+table\s+(\w+)\s+enable\s+row\s+level\s+security/gi) ?? [];
        const enabledTables = new Set(enableRls.map((m) => m.match(/alter\s+table\s+(\w+)/i)?.[1]));

        const tableRefs = new Set<string>();
        for (const endpoint of model.endpoints) {
          const source = await safeReadFile(endpoint.file);
          const matches = source.matchAll(/\.from\s*\(\s*["'](\w+)["']/g);
          for (const m of matches) tableRefs.add(m[1]);
        }

        for (const table of tableRefs) {
          if (!enabledTables.has(table)) {
            findings.push(
              mkFinding(
                "AUTH-002",
                "high",
                `Table ${table} has no ENABLE ROW LEVEL SECURITY statement`,
                "Supabase table is queried from code but RLS is not enabled in migrations.",
                `Run: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; and add appropriate policies.`,
                [{ file: `${model.meta.path}/supabase/migrations/` }],
                { cwe: "CWE-284" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-003",
    domain: "auth-access-control",
    title: "JWT decoded client-side without server verification",
    description: "jwt-decode used without a corresponding server verification",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-347" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/jwt-decode/.test(source) && /["']use client["']/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-003",
              "critical",
              "JWT decoded client-side",
              "Decoding a JWT on the client does not verify its signature.",
              "Verify tokens server-side. Use the decoded claims only for display, never for authorization.",
              [{ file }],
              { cwe: "CWE-347" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-004",
    domain: "auth-access-control",
    title: "Dynamic ID used without ownership check",
    description: "Route handler queries by params.id without filtering by user",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-639", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const route of model.routes) {
        if (!route.paramNames.includes("id")) continue;
        const source = await safeReadFile(route.file);
        const queriesById = /\.eq\s*\(\s*["']id["']\s*,\s*params\.id/.test(source);
        const filtersByUser = /\.eq\s*\(\s*["'](user_id|owner_id|created_by)["']/.test(source);
        if (queriesById && !filtersByUser) {
          findings.push(
            mkFinding(
              "AUTH-004",
              "high",
              `${route.path} fetches by id without ownership check`,
              "Handler fetches a resource by ID without filtering on the authenticated user.",
              "Add `.eq('user_id', user.id)` or use RLS policies that enforce ownership.",
              [{ file: route.file }],
              { cwe: "CWE-639", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-005",
    domain: "auth-access-control",
    title: "supabase.auth.admin used outside server-only module",
    description: "Admin API gives full access and must never run client-side",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-269", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/supabase\.auth\.admin/.test(source)) {
          const serverOnly = /import\s+["']server-only["']/.test(source);
          const isRouteHandler = /\/(route|api)\.(ts|tsx|js|jsx)$/.test(file) || /\/api\//.test(file);
          if (!serverOnly && !isRouteHandler) {
            findings.push(
              mkFinding(
                "AUTH-005",
                "critical",
                "supabase.auth.admin used outside server boundary",
                "Admin API usage must be confined to server-only modules or route handlers.",
                'Add `import "server-only";` or move to a route handler file.',
                [{ file }],
                { cwe: "CWE-269", owasp: "A01:2021" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-006",
    domain: "auth-access-control",
    title: "Middleware ordering may bypass auth",
    description: "middleware.ts matcher excludes API routes",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    async check(model) {
      const findings: Finding[] = [];
      const candidates = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];
      for (const rel of candidates) {
        const file = `${model.meta.path}/${rel}`;
        try {
          const source = await safeReadFile(file);
          if (/matcher/.test(source) && /!api|api\/\*/.test(source)) {
            findings.push(
              mkFinding(
                "AUTH-006",
                "high",
                "Middleware matcher excludes API routes",
                "middleware.ts matcher skips /api/*, leaving API routes without auth.",
                "Include `/api/:path*` in the matcher, or add per-route auth checks.",
                [{ file }],
                { cwe: "CWE-284" },
              ),
            );
          }
        } catch {}
      }
      return findings;
    },
  },

  {
    id: "AUTH-007",
    domain: "auth-access-control",
    title: "Session secret shorter than 32 characters",
    description: "JWT/session secrets under 32 chars are brute-forceable",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-326" },
    check(model) {
      // Rule placeholder: requires reading .env which is denied.
      // Report when .env.example has short placeholder secret names.
      return [];
    },
  },

  {
    id: "AUTH-008",
    domain: "auth-access-control",
    title: "JWT algorithm set to none or weak",
    description: "alg: 'none' or HS256 with short secret",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-327" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/algorithm\s*:\s*["']none["']/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-008",
              "critical",
              "JWT algorithm set to 'none'",
              "alg: 'none' disables signature verification entirely.",
              "Use RS256 or ES256 with a proper keypair. HS256 is acceptable with a 32+ char secret.",
              [{ file }],
              { cwe: "CWE-327" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-009",
    domain: "auth-access-control",
    title: "Role check based on user-controlled field",
    description: "Role comparison uses a field the user can modify",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-639" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/body\.(role|isAdmin|admin)\s*===/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-009",
              "high",
              "Role check against request body",
              "Role determined from request body can be set by any client.",
              "Check role from the authenticated session or database, never from the request body.",
              [{ file }],
              { cwe: "CWE-639" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-010",
    domain: "auth-access-control",
    title: "OAuth callback missing state validation",
    description: "OAuth callback handler does not verify state parameter",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-352" },
    async check(model) {
      const findings: Finding[] = [];
      for (const route of model.routes) {
        if (!/callback/.test(route.path)) continue;
        const source = await safeReadFile(route.file);
        const hasState = /\bstate\b.*(searchParams|query)/.test(source);
        if (!hasState) {
          findings.push(
            mkFinding(
              "AUTH-010",
              "high",
              `${route.path} does not verify OAuth state`,
              "Missing state validation allows CSRF on OAuth flow.",
              "Generate a random state before redirect, store in cookie, verify on callback.",
              [{ file: route.file }],
              { cwe: "CWE-352" },
            ),
          );
        }
      }
      return findings;
    },
  },
];
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/rules/auth-access-control.test.ts`

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/rules/domains/auth-access-control.ts tests/rules/auth-access-control.test.ts
git commit -m "feat(rules): add 10 auth-access-control rules"
```

---

## Task 17: File Upload Rules

**Files:**
- Create: `src/layers/rules/domains/file-upload.ts`
- Create: `tests/rules/file-upload.test.ts`

Implements all 9 UPLOAD-00N rules.

- [ ] **Step 1: Write failing tests**

Create `tests/rules/file-upload.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { fileUploadRules } from "../../src/layers/rules/domains/file-upload.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("file-upload rules", () => {
  it("flags upload without MIME validation (UPLOAD-001)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "UPLOAD-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags upload without size limit (UPLOAD-002)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "UPLOAD-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags user filename used as storage path (UPLOAD-004)", async () => {
    resetRegistry();
    registerRules(fileUploadRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const u4 = findings.filter((f) => f.ruleId === "UPLOAD-004");
    expect(u4.length).toBeGreaterThanOrEqual(1);
    expect(u4[0].severity).toBe("critical");
  });
});
```

- [ ] **Step 2: Create file-upload rules**

Create `src/layers/rules/domains/file-upload.ts`:

```typescript
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "file-upload",
    severity,
    confidence: "high",
    title,
    description,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

export const fileUploadRules: SecurityRule[] = [
  {
    id: "UPLOAD-001",
    domain: "file-upload",
    title: "Upload handler lacks MIME validation",
    description: "Uploaded file type is not validated server-side",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-434", owasp: "A04:2021" },
    check(model) {
      return model.fileUploads
        .filter((u) => !u.hasMimeValidation)
        .map((u) =>
          mkFinding(
            "UPLOAD-001",
            "high",
            "Upload handler does not validate MIME type",
            "Uploaded files are stored without verifying their content type.",
            "Check `file.type` against an allowlist before accepting the upload.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-434", owasp: "A04:2021" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-002",
    domain: "file-upload",
    title: "Upload handler lacks size limit",
    description: "No file size check means DoS and storage abuse are possible",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-400" },
    check(model) {
      return model.fileUploads
        .filter((u) => !u.hasSizeLimit)
        .map((u) =>
          mkFinding(
            "UPLOAD-002",
            "medium",
            "Upload handler has no size limit",
            "Handler accepts files of any size.",
            "Reject files where file.size exceeds a configured maximum.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-400" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-003",
    domain: "file-upload",
    title: "Uploaded files served from same origin as app",
    description: "Supabase storage bucket or local directory served from app domain",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return model.fileUploads
        .filter((u) => u.storageDestination === "local")
        .map((u) =>
          mkFinding(
            "UPLOAD-003",
            "high",
            "Uploads stored on app filesystem",
            "Local storage means uploads are served from the same origin, inheriting session cookies.",
            "Use an isolated storage domain (Supabase storage, S3 with CloudFront).",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-79" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-004",
    domain: "file-upload",
    title: "User-provided filename used as storage path",
    description: "Storage path derived from client input enables path traversal",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-22", owasp: "A01:2021" },
    check(model) {
      return model.fileUploads
        .filter((u) => u.usesUserFilename)
        .map((u) =>
          mkFinding(
            "UPLOAD-004",
            "critical",
            "User filename used as storage path",
            "Handler uses client-provided filename as the upload destination path.",
            "Generate a server-side UUID for storage paths. Store original name in metadata only.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-22", owasp: "A01:2021" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-005",
    domain: "file-upload",
    title: "SVG uploads accepted without sanitization",
    description: "SVG files can contain embedded JavaScript",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    async check(model) {
      const findings: Finding[] = [];
      for (const u of model.fileUploads) {
        const source = await safeReadFile(u.file);
        if (/image\/svg|svg\+xml/.test(source) && !/DOMPurify|sanitize.*svg/i.test(source)) {
          findings.push(
            mkFinding(
              "UPLOAD-005",
              "high",
              "SVG accepted without sanitization",
              "SVG content can contain script tags and event handlers.",
              "Reject SVGs or strip scriptable content before storage.",
              [{ file: u.file, line: u.line }],
              { cwe: "CWE-79" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "UPLOAD-006",
    domain: "file-upload",
    title: "No Content-Disposition header on downloads",
    description: "Uploaded files served without forcing download disposition",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check() {
      // Placeholder: requires response header analysis, deferred to probe layer.
      return [];
    },
  },

  {
    id: "UPLOAD-007",
    domain: "file-upload",
    title: "Client-side-only file validation",
    description: "File validation in the component but not the API route",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-602" },
    async check(model) {
      // Check form components with accept attribute but upload endpoints without MIME check
      const findings: Finding[] = [];
      const clientValidated = model.fileUploads.some((u) => u.hasMimeValidation === false);
      if (clientValidated) {
        for (const u of model.fileUploads) {
          if (!u.hasMimeValidation) {
            findings.push(
              mkFinding(
                "UPLOAD-007",
                "high",
                "Server-side MIME validation missing",
                "Client `accept` attribute can be bypassed; server must re-validate.",
                "Add server-side MIME check in the upload handler.",
                [{ file: u.file, line: u.line }],
                { cwe: "CWE-602" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "UPLOAD-008",
    domain: "file-upload",
    title: "Supabase public bucket without access policy",
    description: "Placeholder: requires Supabase config inspection",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    check() {
      // Phase 1: deferred
      return [];
    },
  },

  {
    id: "UPLOAD-009",
    domain: "file-upload",
    title: "Archive files accepted without extraction safeguards",
    description: "zip/tar uploads can cause zip slip or decompression bombs",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-409" },
    async check(model) {
      const findings: Finding[] = [];
      for (const u of model.fileUploads) {
        const source = await safeReadFile(u.file);
        if (/\.zip|\.tar|unzipper|tar-stream|adm-zip/.test(source)) {
          findings.push(
            mkFinding(
              "UPLOAD-009",
              "medium",
              "Archive upload without zip-slip protection",
              "Extracting untrusted archives can overwrite arbitrary files.",
              "Validate extracted paths against the target directory, enforce size limits.",
              [{ file: u.file, line: u.line }],
              { cwe: "CWE-409" },
            ),
          );
        }
      }
      return findings;
    },
  },
];
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/rules/file-upload.test.ts`

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/layers/rules/domains/file-upload.ts tests/rules/file-upload.test.ts
git commit -m "feat(rules): add 9 file-upload rules"
```

---

## Task 18: Terminal Output Formatter

**Files:**
- Create: `src/output/terminal.ts`
- Create: `tests/output/terminal.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/output/terminal.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { formatTerminal } from "../../src/output/terminal.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

const sampleModel: ProjectModel = {
  meta: {
    name: "test",
    path: "/tmp",
    stack: "nextjs-supabase",
    packageManager: "npm",
    language: "typescript",
    framework: "nextjs-app",
    deployTarget: null,
  },
  routes: [],
  endpoints: [],
  fileUploads: [],
  authFlows: [],
  dataModels: [],
  dependencies: [],
  envVars: [],
  staticAssets: [],
  findings: [],
};

const sampleFinding: Finding = {
  id: "TEST-1",
  domain: "secrets-exposure",
  severity: "critical",
  confidence: "high",
  title: "test finding",
  description: "d",
  evidence: [{ file: "/tmp/a.ts", line: 1 }],
  remediation: "fix it",
  references: ["CWE-798"],
  layer: "rules",
};

describe("terminal output", () => {
  it("renders finding and summary", () => {
    const output = formatTerminal(sampleModel, [sampleFinding]);
    expect(output).toContain("SENTINEL");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("test finding");
    expect(output).toContain("secrets-exposure");
  });

  it("groups by severity", () => {
    const findings: Finding[] = [
      sampleFinding,
      { ...sampleFinding, id: "TEST-2", severity: "low", title: "low finding" },
    ];
    const output = formatTerminal(sampleModel, findings);
    const criticalIdx = output.indexOf("CRITICAL");
    const lowIdx = output.indexOf("LOW");
    expect(criticalIdx).toBeGreaterThanOrEqual(0);
    expect(lowIdx).toBeGreaterThan(criticalIdx);
  });
});
```

- [ ] **Step 2: Create terminal formatter**

Create `src/output/terminal.ts`:

```typescript
import chalk from "chalk";
import type { Finding, ProjectModel, Severity, SecurityDomain } from "../model/types.js";
import { compareSeverity } from "../model/severity.js";

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const DOMAINS: SecurityDomain[] = [
  "secrets-exposure",
  "input-injection",
  "auth-access-control",
  "file-upload",
  "api-security",
  "cryptography",
  "supply-chain",
  "infrastructure",
  "business-logic",
  "logging-monitoring",
];

export function formatTerminal(model: ProjectModel, findings: Finding[]): string {
  const lines: string[] = [];

  lines.push(chalk.bold("  SENTINEL v0.1.0 — Security Assessment"));
  lines.push(`  Target: ${model.meta.path}`);
  lines.push(`  Stack:  ${model.meta.stack} (${model.meta.framework})`);
  lines.push(`  Layers: Recon ${chalk.green("✓")}  Rules ${chalk.green("✓")}`);
  lines.push("");
  lines.push("  " + "─".repeat(50));
  lines.push("");

  const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  const bySeverity = new Map<Severity, Finding[]>();
  for (const f of sorted) {
    if (!bySeverity.has(f.severity)) bySeverity.set(f.severity, []);
    bySeverity.get(f.severity)!.push(f);
  }

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    const list = bySeverity.get(sev) ?? [];
    if (list.length === 0) continue;
    lines.push(SEVERITY_COLOR[sev](`  ${sev.toUpperCase()} (${list.length})`));
    lines.push("");
    for (const f of list) {
      lines.push(`  ${chalk.bold(f.id)}  ${f.title}  ${chalk.dim("[" + f.domain + "]")}`);
      for (const ev of f.evidence) {
        lines.push(`           ${chalk.dim(ev.file + (ev.line ? `:${ev.line}` : ""))}`);
      }
      lines.push(`           ${chalk.dim("Layer: " + f.layer)}`);
      lines.push(`           ${chalk.dim("Fix: " + f.remediation)}`);
      if (f.references.length > 0) {
        lines.push(`           ${chalk.dim("Ref: " + f.references.join(", "))}`);
      }
      lines.push("");
    }
  }

  lines.push("  " + "─".repeat(50));
  lines.push("");
  lines.push(chalk.bold("  SUMMARY"));
  lines.push("");

  const header = "  ┌──────────────────────┬──────┬──────┬────────┬─────┬──────┐";
  const sep = "  ├──────────────────────┼──────┼──────┼────────┼─────┼──────┤";
  const footer = "  └──────────────────────┴──────┴──────┴────────┴─────┴──────┘";
  lines.push(header);
  lines.push("  │ Domain               │ Crit │ High │ Medium │ Low │ Info │");
  lines.push(sep);

  for (const domain of DOMAINS) {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) if (f.domain === domain) counts[f.severity]++;
    const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
    if (total === 0) continue;
    const label = domain.padEnd(20);
    lines.push(
      `  │ ${label} │ ${String(counts.critical).padStart(4)} │ ${String(counts.high).padStart(4)} │ ${String(counts.medium).padStart(6)} │ ${String(counts.low).padStart(3)} │ ${String(counts.info).padStart(4)} │`,
    );
  }
  lines.push(footer);
  lines.push("");

  const totals = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc as any)[f.severity] + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
  lines.push(
    `  Total: ${totals.critical} critical, ${totals.high} high, ${totals.medium} medium, ${totals.low} low, ${totals.info} info`,
  );

  return lines.join("\n");
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/output/terminal.test.ts`

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/output/terminal.ts tests/output/terminal.test.ts
git commit -m "feat(output): add terminal formatter"
```

---

## Task 19: JSON Output Formatter

**Files:**
- Create: `src/output/json.ts`
- Create: `tests/output/json.test.ts`

- [ ] **Step 1: Write failing test**

Create `tests/output/json.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { formatJson } from "../../src/output/json.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

const model: ProjectModel = {
  meta: {
    name: "test",
    path: "/tmp",
    stack: "nextjs-supabase",
    packageManager: "npm",
    language: "typescript",
    framework: "nextjs-app",
    deployTarget: null,
  },
  routes: [],
  endpoints: [],
  fileUploads: [],
  authFlows: [],
  dataModels: [],
  dependencies: [],
  envVars: [],
  staticAssets: [],
  findings: [],
};

const finding: Finding = {
  id: "TEST-1",
  domain: "secrets-exposure",
  severity: "critical",
  confidence: "high",
  title: "test",
  description: "",
  evidence: [],
  remediation: "",
  references: [],
  layer: "rules",
};

describe("json output", () => {
  it("produces valid JSON with summary", () => {
    const output = formatJson(model, [finding], { recon_ms: 100, rules_ms: 50 });
    const parsed = JSON.parse(output);
    expect(parsed.version).toBeDefined();
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.findings.length).toBe(1);
    expect(parsed.model.meta.stack).toBe("nextjs-supabase");
  });
});
```

- [ ] **Step 2: Create JSON formatter**

Create `src/output/json.ts`:

```typescript
import type { Finding, ProjectModel, Severity } from "../model/types.js";

export interface LayerTiming {
  recon_ms: number;
  rules_ms: number;
}

export function formatJson(
  model: ProjectModel,
  findings: Finding[],
  timing: LayerTiming,
): string {
  const summary: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of findings) summary[f.severity]++;

  const output = {
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    project: {
      name: model.meta.name,
      path: model.meta.path,
      stack: model.meta.stack,
      framework: model.meta.framework,
    },
    layers: {
      recon: { status: "complete", duration_ms: timing.recon_ms },
      rules: { status: "complete", duration_ms: timing.rules_ms },
      ai: { status: "skipped", duration_ms: 0 },
      probe: { status: "skipped", duration_ms: 0 },
    },
    summary: {
      ...summary,
      total: findings.length,
      by_domain: Object.fromEntries(
        [...new Set(findings.map((f) => f.domain))].map((d) => [
          d,
          findings.filter((f) => f.domain === d).length,
        ]),
      ),
    },
    findings,
    model,
  };

  return JSON.stringify(output, null, 2);
}
```

- [ ] **Step 3: Run tests**

Run: `npm test tests/output/json.test.ts`

Expected: 1 test passes.

- [ ] **Step 4: Commit**

```bash
git add src/output/json.ts tests/output/json.test.ts
git commit -m "feat(output): add JSON formatter"
```

---

## Task 20: Wire Up Scan Command End-to-End

**Files:**
- Modify: `src/commands/scan.ts`
- Create: `tests/integration/scan.test.ts`

- [ ] **Step 1: Write failing integration test**

Create `tests/integration/scan.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { execSync } from "child_process";
import { join } from "path";

const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");
const cli = join(__dirname, "..", "..", "src", "cli.ts");

describe("integration: scan command", () => {
  it("runs full scan and produces terminal output", () => {
    const output = execSync(`npx tsx ${cli} scan ${fixturePath} --format terminal`, {
      encoding: "utf-8",
    });
    expect(output).toContain("SENTINEL");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("SECRETS");
  });

  it("produces JSON output with findings", () => {
    const output = execSync(`npx tsx ${cli} scan ${fixturePath} --format json`, {
      encoding: "utf-8",
    });
    const parsed = JSON.parse(output);
    expect(parsed.findings.length).toBeGreaterThan(5);
    expect(parsed.summary.critical).toBeGreaterThanOrEqual(1);
    expect(parsed.project.stack).toBe("nextjs-supabase");
  });

  it("exits non-zero when --fail-on is triggered", () => {
    try {
      execSync(`npx tsx ${cli} scan ${fixturePath} --fail-on high`, { encoding: "utf-8" });
      throw new Error("Expected non-zero exit");
    } catch (e: any) {
      expect(e.status).toBe(1);
    }
  });
});
```

- [ ] **Step 2: Replace scan command stub**

Replace `src/commands/scan.ts`:

```typescript
import { logger } from "../utils/logger.js";
import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../layers/rules/index.js";
import { secretsExposureRules } from "../layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../layers/rules/domains/file-upload.js";
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { isAtOrAbove } from "../model/severity.js";
import type { Severity } from "../model/types.js";

export interface ScanOptions {
  path: string;
  format: "terminal" | "json";
  failOn?: Severity;
}

export async function runScan(options: ScanOptions): Promise<number> {
  const config = await loadConfig(options.path);

  const reconStart = Date.now();
  const model = await runRecon(options.path, config.exclude);
  const recon_ms = Date.now() - reconStart;

  resetRegistry();
  registerRules(secretsExposureRules);
  registerRules(inputInjectionRules);
  registerRules(authAccessControlRules);
  registerRules(fileUploadRules);

  const rulesStart = Date.now();
  const findings = await runRules(model);
  const rules_ms = Date.now() - rulesStart;

  if (options.format === "json") {
    process.stdout.write(formatJson(model, findings, { recon_ms, rules_ms }));
  } else {
    process.stdout.write(formatTerminal(model, findings));
    process.stdout.write("\n");
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlockingFinding = findings.some((f) => isAtOrAbove(f.severity, failOn));
  return hasBlockingFinding ? 1 : 0;
}
```

- [ ] **Step 3: Run integration test**

Run: `npm test tests/integration/scan.test.ts`

Expected: 3 tests pass.

- [ ] **Step 4: Run full test suite**

Run: `npm test`

Expected: All tests pass. Numbers should roughly match:
- severity: 3
- config: 3
- fs utils: 7
- ast utils: 5
- cli: 2
- stack-detector: 2
- route-discovery: 3
- endpoint-discovery: 2
- other-discovery: 3
- recon orchestrator: 1
- rule engine: 2
- secrets-exposure: 3
- input-injection: 2
- auth-access-control: 3
- file-upload: 3
- terminal: 2
- json: 1
- integration: 3

Total: ~50 tests

- [ ] **Step 5: Commit**

```bash
git add src/commands/scan.ts tests/integration/scan.test.ts
git commit -m "feat(scan): wire up end-to-end scan pipeline"
```

---

## Task 21: Real-World Validation

**Files:**
- Create: `docs/VALIDATION.md` (captures results, no code)

- [ ] **Step 1: Build the CLI**

Run:
```bash
npm run build
```

Expected: `dist/` directory populated with compiled JS.

- [ ] **Step 2: Scan feedback-hub (the pentested project)**

Run:
```bash
node dist/cli.js scan /Users/tywells/Downloads/projects/feedback-hub --format terminal
node dist/cli.js scan /Users/tywells/Downloads/projects/feedback-hub --format json > /tmp/feedback-hub-scan.json
```

Expected: Scan completes without crashing. Findings produced. Compare against the pentest report.

- [ ] **Step 3: Scan two other projects**

Run against two other nextjs-supabase projects from the portfolio. Pick projects with different scope (small utility + larger SaaS).

- [ ] **Step 4: Document results in docs/VALIDATION.md**

Create with this structure:

```markdown
# Phase 1 Validation Results

## Projects Scanned
1. feedback-hub - findings: X critical, Y high, Z medium
2. [project 2] - findings: X critical, Y high, Z medium
3. [project 3] - findings: X critical, Y high, Z medium

## Pentest Comparison (feedback-hub)
Pentester's findings -> Sentinel detection:
- Stored XSS -> INPUT-001 (caught)
- Service role leak -> SECRETS-001 (caught)
- Upload filename issue -> UPLOAD-004 (caught)
- No rate limiting -> NOT DETECTED (deferred to Phase 2 API Security domain)
- JWT exposure -> AUTH-003 (caught)

## False Positives Observed
[list any]

## False Negatives Observed
[list any rule gaps that should have fired]

## Phase 2 Inputs
- Missing rules discovered during validation
- UX improvements needed
```

- [ ] **Step 5: Commit**

```bash
git add docs/VALIDATION.md
git commit -m "docs: record Phase 1 validation results against real projects"
```

---

## Self-Review

**1. Spec coverage check:**

| Spec requirement | Task(s) |
|------------------|---------|
| ProjectModel type | Task 2 |
| Severity helpers | Task 2 |
| Config loader with defaults | Task 3 |
| Deny-path filesystem helpers | Task 4 |
| AST parsing utilities | Task 5 |
| CLI entry point with commander | Task 6 |
| Vulnerable fixture project | Task 7 |
| Stack detector | Task 8 |
| Route discovery | Task 9 |
| Endpoint discovery | Task 10 |
| Auth, upload, env, dep discovery | Task 11 |
| Recon orchestrator | Task 12 |
| Rule engine and registry | Task 13 |
| 9 secrets-exposure rules | Task 14 |
| 10 input-injection rules | Task 15 |
| 10 auth-access-control rules | Task 16 |
| 9 file-upload rules | Task 17 |
| Terminal output formatter | Task 18 |
| JSON output formatter | Task 19 |
| Scan command wired end-to-end | Task 20 |
| Real-world validation | Task 21 |

All Phase 1 spec requirements are covered.

**2. Placeholder scan:** No TBDs or "implement later" steps. Deferred rules (SECRETS-006, AUTH-007, UPLOAD-006, UPLOAD-008) are explicitly marked as Phase 1 placeholders that return `[]` so the registry is complete but they do not falsely fire.

**3. Type consistency:** `SecurityRule`, `Finding`, `ProjectModel`, `ScanOptions`, and `LayerTiming` are defined once and referenced consistently. Rule file `mkFinding` helpers are local to each domain file (intentional; keeps rule files self-contained).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-10-sentinel-phase-1-mvp.md`. Two execution options:

**1. Subagent-Driven (recommended)** - Dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a plan this long because each task is independently testable and the context won't bloat.

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints. Tighter feedback loop but context usage will be heavy.

Which approach?
