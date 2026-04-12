# Context Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a context layer between recon and rules that auto-infers project architecture to reduce false positive rate from 76% to ~9%.

**Architecture:** New `src/layers/context/` module with 9 inferrers producing a `ProjectContext`. Consumed by rules (via post-filter + direct parameter) and AI (via enriched prompt). Separate `sentinel context` CLI command for interactive generation.

**Tech Stack:** TypeScript, Zod (schema validation), Commander (CLI), minimatch (glob patterns), Vitest (tests)

**Spec:** `docs/2026-04-12-context-layer-design.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `src/layers/context/types.ts` | `ProjectContext` interface + Zod schema |
| `src/layers/context/index.ts` | `inferContext(model)` orchestrator |
| `src/layers/context/io.ts` | Read/write `.sentinel/context.json` |
| `src/layers/context/inferrers/tenancy.ts` | Single-org vs multi-tenant detection |
| `src/layers/context/inferrers/public-routes.ts` | Identify intentionally unauthenticated routes |
| `src/layers/context/inferrers/validation.ts` | Trace imports to find schema files |
| `src/layers/context/inferrers/migrations.ts` | Read all migrations together for RLS |
| `src/layers/context/inferrers/framework.ts` | Detect framework error handling, server-only |
| `src/layers/context/inferrers/excluded-paths.ts` | Non-deployed directories |
| `src/layers/context/inferrers/auth.ts` | Supabase client usage, role patterns |
| `src/layers/context/inferrers/deployment.ts` | Platform detection from config files |
| `src/layers/context/inferrers/delegations.ts` | Third-party SDK security delegation |
| `src/layers/context/suppression.ts` | `applyContextSuppressions(findings, context)` |
| `src/commands/context.ts` | `sentinel context` command handler |
| `tests/layers/context/types.test.ts` | Schema validation tests |
| `tests/layers/context/io.test.ts` | Read/write round-trip tests |
| `tests/layers/context/inferrers/*.test.ts` | One test file per inferrer |
| `tests/layers/context/suppression.test.ts` | Suppression logic tests |
| `tests/fixtures/context/single-org-nextjs/` | Fixture: single-org Next.js+Supabase project |
| `tests/fixtures/context/multi-tenant/` | Fixture: multi-tenant project |

### Modified files

| File | Change |
|------|--------|
| `src/model/types.ts` | Add `ProjectContext` import, optional `context` field on `ProjectModel` |
| `src/layers/rules/registry.ts` | Add `context` parameter to `SecurityRule.check()` signature |
| `src/layers/rules/index.ts` | Pass context to `runRules()`, pass to each rule |
| `src/layers/rules/domains/auth-access-control.ts` | AUTH-001: skip public routes. AUTH-002: check dedicated RLS file |
| `src/layers/rules/domains/input-injection.ts` | INPUT-005: follow imports when `validation.importedByRoutes` |
| `src/layers/rules/domains/logging-monitoring.ts` | LOG-005: downgrade when `framework.frameworkCatchesErrors` |
| `src/commands/scan.ts` | Load context after recon, apply suppression after rules |
| `src/commands/probe.ts` | Load context, apply suppression |
| `src/layers/ai/prompts.ts` | Enrich `buildProjectSummary()` with context |
| `src/cli.ts` | Register `sentinel context` command |

---

### Task 1: ProjectContext Type and Schema

**Files:**
- Create: `src/layers/context/types.ts`
- Create: `tests/layers/context/types.test.ts`

- [ ] **Step 1: Write the test for schema validation**

```typescript
// tests/layers/context/types.test.ts
import { describe, it, expect } from "vitest";
import { ProjectContextSchema, type ProjectContext } from "../../src/layers/context/types.js";

describe("ProjectContextSchema", () => {
  const validContext: ProjectContext = {
    tenancy: "single-org",
    publicRoutes: [
      { pattern: "/api/public/**", reason: "magic-link" },
    ],
    validation: {
      library: "zod",
      schemaLocations: ["src/lib/validation/*.ts"],
      importedByRoutes: true,
    },
    migrations: {
      rlsStrategy: "dedicated-file",
      rlsFile: "supabase/migrations/00003_rls_policies.sql",
    },
    framework: {
      routeHandlersServerOnly: true,
      frameworkCatchesErrors: true,
      serverOnlyImportGuard: true,
    },
    excludedPaths: ["scripts/", "seed.ts"],
    auth: {
      defaultClient: "anon",
      roleModel: ["viewer", "editor", "manager", "admin"],
      roleCheckPattern: "supabase.rpc('is_manager')",
    },
    deployment: {
      platform: "vercel",
      platformHandles: ["hsts", "ssl-termination"],
    },
    delegations: [
      { provider: "supabase", responsibility: "OAuth state verification", mechanism: "exchangeCodeForSession()" },
    ],
    version: 1,
    generatedAt: "2026-04-12T00:00:00Z",
    generatedBy: "interactive",
    confidence: { tenancy: "high", auth: "high", validation: "high" },
  };

  it("accepts a valid context", () => {
    expect(ProjectContextSchema.safeParse(validContext).success).toBe(true);
  });

  it("rejects invalid tenancy value", () => {
    const bad = { ...validContext, tenancy: "federated" };
    expect(ProjectContextSchema.safeParse(bad).success).toBe(false);
  });

  it("accepts minimal context with defaults", () => {
    const minimal = {
      tenancy: "single-org",
      publicRoutes: [],
      validation: { library: "none", schemaLocations: [], importedByRoutes: false },
      migrations: { rlsStrategy: "none" },
      framework: { routeHandlersServerOnly: false, frameworkCatchesErrors: false, serverOnlyImportGuard: false },
      excludedPaths: [],
      auth: { defaultClient: "anon", roleModel: [] },
      deployment: { platform: "unknown", platformHandles: [] },
      delegations: [],
      version: 1,
      generatedAt: "2026-04-12T00:00:00Z",
      generatedBy: "auto",
      confidence: {},
    };
    expect(ProjectContextSchema.safeParse(minimal).success).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/types.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement the type and schema**

```typescript
// src/layers/context/types.ts
import { z } from "zod";

export const PublicRouteReasonSchema = z.enum([
  "magic-link", "webhook", "health-check", "widget", "oauth-callback", "custom",
]);

export const ProjectContextSchema = z.object({
  tenancy: z.enum(["single-org", "multi-tenant", "per-user"]),

  publicRoutes: z.array(z.object({
    pattern: z.string(),
    reason: PublicRouteReasonSchema,
    description: z.string().optional(),
  })),

  validation: z.object({
    library: z.enum(["zod", "joi", "yup", "ajv", "none", "custom"]),
    schemaLocations: z.array(z.string()),
    importedByRoutes: z.boolean(),
  }),

  migrations: z.object({
    rlsStrategy: z.enum(["co-located", "dedicated-file", "none"]),
    rlsFile: z.string().optional(),
  }),

  framework: z.object({
    routeHandlersServerOnly: z.boolean(),
    frameworkCatchesErrors: z.boolean(),
    serverOnlyImportGuard: z.boolean(),
  }),

  excludedPaths: z.array(z.string()),

  auth: z.object({
    defaultClient: z.enum(["anon", "service-role"]),
    roleModel: z.array(z.string()),
    roleCheckPattern: z.string().optional(),
  }),

  deployment: z.object({
    platform: z.enum(["vercel", "cloudflare", "aws", "fly", "self-hosted", "unknown"]),
    platformHandles: z.array(z.string()),
  }),

  delegations: z.array(z.object({
    provider: z.string(),
    responsibility: z.string(),
    mechanism: z.string().optional(),
  })),

  version: z.literal(1),
  generatedAt: z.string(),
  generatedBy: z.enum(["auto", "interactive", "manual"]),
  confidence: z.record(z.string(), z.enum(["high", "medium", "low"])),
});

export type ProjectContext = z.infer<typeof ProjectContextSchema>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/context/types.test.ts`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/context/types.ts tests/layers/context/types.test.ts
git commit -m "feat(context): add ProjectContext type and Zod schema"
```

---

### Task 2: Context I/O (Read/Write .sentinel/context.json)

**Files:**
- Create: `src/layers/context/io.ts`
- Create: `tests/layers/context/io.test.ts`

- [ ] **Step 1: Write the test**

```typescript
// tests/layers/context/io.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, rm, mkdir } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";
import { readContext, writeContext } from "../../src/layers/context/io.js";
import type { ProjectContext } from "../../src/layers/context/types.js";

const MINIMAL_CONTEXT: ProjectContext = {
  tenancy: "single-org",
  publicRoutes: [],
  validation: { library: "none", schemaLocations: [], importedByRoutes: false },
  migrations: { rlsStrategy: "none" },
  framework: { routeHandlersServerOnly: false, frameworkCatchesErrors: false, serverOnlyImportGuard: false },
  excludedPaths: [],
  auth: { defaultClient: "anon", roleModel: [] },
  deployment: { platform: "unknown", platformHandles: [] },
  delegations: [],
  version: 1,
  generatedAt: "2026-04-12T00:00:00Z",
  generatedBy: "auto",
  confidence: {},
};

describe("context io", () => {
  let dir: string;

  beforeEach(async () => {
    dir = join(tmpdir(), `sentinel-ctx-test-${Date.now()}`);
    await mkdir(dir, { recursive: true });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns null when no context file exists", async () => {
    expect(await readContext(dir)).toBeNull();
  });

  it("round-trips a context file", async () => {
    await writeContext(dir, MINIMAL_CONTEXT);
    const loaded = await readContext(dir);
    expect(loaded).toEqual(MINIMAL_CONTEXT);
  });

  it("returns null for invalid JSON in context file", async () => {
    await mkdir(join(dir, ".sentinel"), { recursive: true });
    await writeFile(join(dir, ".sentinel", "context.json"), "not json", "utf-8");
    expect(await readContext(dir)).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/io.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```typescript
// src/layers/context/io.ts
import { readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { ProjectContextSchema, type ProjectContext } from "./types.js";

const CONTEXT_DIR = ".sentinel";
const CONTEXT_FILE = "context.json";

export async function readContext(projectPath: string): Promise<ProjectContext | null> {
  const filePath = join(projectPath, CONTEXT_DIR, CONTEXT_FILE);
  try {
    const raw = await readFile(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    const result = ProjectContextSchema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export async function writeContext(projectPath: string, context: ProjectContext): Promise<string> {
  const dirPath = join(projectPath, CONTEXT_DIR);
  await mkdir(dirPath, { recursive: true });
  const filePath = join(dirPath, CONTEXT_FILE);
  await writeFile(filePath, JSON.stringify(context, null, 2) + "\n", "utf-8");
  return filePath;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/context/io.test.ts`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/context/io.ts tests/layers/context/io.test.ts
git commit -m "feat(context): add read/write for .sentinel/context.json"
```

---

### Task 3: Test Fixtures for Context Inferrers

**Files:**
- Create: `tests/fixtures/context/single-org-nextjs/package.json`
- Create: `tests/fixtures/context/single-org-nextjs/src/app/api/users/route.ts`
- Create: `tests/fixtures/context/single-org-nextjs/src/lib/validation/users.ts`
- Create: `tests/fixtures/context/single-org-nextjs/src/lib/supabase/server.ts`
- Create: `tests/fixtures/context/single-org-nextjs/supabase/migrations/00001_schema.sql`
- Create: `tests/fixtures/context/single-org-nextjs/supabase/migrations/00003_rls.sql`
- Create: `tests/fixtures/context/single-org-nextjs/vercel.json`
- Create: `tests/fixtures/context/single-org-nextjs/next.config.ts`
- Create: `tests/fixtures/context/single-org-nextjs/src/app/api/public/reservation/route.ts`
- Create: `tests/fixtures/context/single-org-nextjs/scripts/seed.ts`

- [ ] **Step 1: Create fixture directory and files**

```bash
mkdir -p tests/fixtures/context/single-org-nextjs/src/app/api/users
mkdir -p tests/fixtures/context/single-org-nextjs/src/app/api/public/reservation
mkdir -p tests/fixtures/context/single-org-nextjs/src/lib/validation
mkdir -p tests/fixtures/context/single-org-nextjs/src/lib/supabase
mkdir -p tests/fixtures/context/single-org-nextjs/supabase/migrations
mkdir -p tests/fixtures/context/single-org-nextjs/scripts
```

```json
// tests/fixtures/context/single-org-nextjs/package.json
{
  "name": "test-single-org",
  "dependencies": {
    "next": "16.0.0",
    "@supabase/ssr": "0.10.0",
    "zod": "4.0.0"
  }
}
```

```typescript
// tests/fixtures/context/single-org-nextjs/src/app/api/users/route.ts
import { createClient } from "@/lib/supabase/server";
import { updateUserSchema } from "@/lib/validation/users";
export async function PATCH(request: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const body = await request.json();
  const parsed = updateUserSchema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "Invalid" }, { status: 400 });
  return Response.json({ ok: true });
}
```

```typescript
// tests/fixtures/context/single-org-nextjs/src/lib/validation/users.ts
import { z } from "zod";
export const updateUserSchema = z.object({ name: z.string() });
```

```typescript
// tests/fixtures/context/single-org-nextjs/src/lib/supabase/server.ts
import { createServerClient } from "@supabase/ssr";
export async function createClient() {
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} as any });
}
export async function createServiceClient() {
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { cookies: {} as any });
}
```

```sql
-- tests/fixtures/context/single-org-nextjs/supabase/migrations/00001_schema.sql
CREATE TABLE users (id uuid PRIMARY KEY, name text, email text);
CREATE TABLE content (id uuid PRIMARY KEY, title text, body text, created_by uuid);
```

```sql
-- tests/fixtures/context/single-org-nextjs/supabase/migrations/00003_rls.sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE content ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_select" ON users FOR SELECT USING (true);
CREATE POLICY "content_select" ON content FOR SELECT USING (true);
```

```json
// tests/fixtures/context/single-org-nextjs/vercel.json
{ "framework": "nextjs" }
```

```typescript
// tests/fixtures/context/single-org-nextjs/next.config.ts
export default { /* next config */ };
```

```typescript
// tests/fixtures/context/single-org-nextjs/src/app/api/public/reservation/route.ts
export async function POST(request: Request) {
  const { token } = await request.json();
  // magic-link flow — no auth check
  return Response.json({ ok: true });
}
```

```typescript
// tests/fixtures/context/single-org-nextjs/scripts/seed.ts
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.URL!, process.env.KEY!);
await supabase.auth.admin.createUser({ email: "test@test.com", password: "test" });
```

- [ ] **Step 2: Verify fixture directory structure**

Run: `find tests/fixtures/context/single-org-nextjs -type f | sort`
Expected: All files listed above

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/context/
git commit -m "test(context): add single-org-nextjs fixture for inferrer tests"
```

---

### Task 4: Core Inferrers (tenancy, framework, deployment, excluded-paths)

**Files:**
- Create: `src/layers/context/inferrers/tenancy.ts`
- Create: `src/layers/context/inferrers/framework.ts`
- Create: `src/layers/context/inferrers/deployment.ts`
- Create: `src/layers/context/inferrers/excluded-paths.ts`
- Create: `tests/layers/context/inferrers/core.test.ts`

These four inferrers are the simplest — they read `ProjectModel` fields and return values with confidence. Grouped into one task because each is <30 lines.

- [ ] **Step 1: Write the tests**

```typescript
// tests/layers/context/inferrers/core.test.ts
import { describe, it, expect } from "vitest";
import { inferTenancy } from "../../../src/layers/context/inferrers/tenancy.js";
import { inferFramework } from "../../../src/layers/context/inferrers/framework.js";
import { inferDeployment } from "../../../src/layers/context/inferrers/deployment.js";
import { inferExcludedPaths } from "../../../src/layers/context/inferrers/excluded-paths.js";
import type { ProjectModel } from "../../../src/model/types.js";

function baseModel(overrides: Partial<ProjectModel> = {}): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript", deployTarget: "vercel" },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { securityHeaders: {}, middleware: null, supabaseConfig: null, nextConfig: null, vercelConfig: null },
    findings: [],
    ...overrides,
  } as ProjectModel;
}

describe("inferTenancy", () => {
  it("returns single-org when no tenant columns exist", () => {
    const model = baseModel({
      dataModels: [
        { name: "users", source: "migration", hasRls: true, columns: ["id", "name", "email"] },
      ] as any,
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("single-org");
    expect(result.confidence).toBe("medium");
  });

  it("returns multi-tenant when tenant_id columns found", () => {
    const model = baseModel({
      dataModels: [
        { name: "users", source: "migration", hasRls: true, columns: ["id", "tenant_id", "name"] },
        { name: "tasks", source: "migration", hasRls: true, columns: ["id", "tenant_id", "title"] },
      ] as any,
    });
    const result = inferTenancy(model);
    expect(result.value).toBe("multi-tenant");
    expect(result.confidence).toBe("high");
  });
});

describe("inferFramework", () => {
  it("detects Next.js App Router conventions", () => {
    const model = baseModel({
      meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript", deployTarget: "vercel" } as any,
      dependencies: [{ name: "next", version: "16.0.0", type: "production" }] as any,
    });
    const result = inferFramework(model);
    expect(result.value.routeHandlersServerOnly).toBe(true);
    expect(result.value.frameworkCatchesErrors).toBe(true);
  });
});

describe("inferDeployment", () => {
  it("detects Vercel from config", () => {
    const model = baseModel({
      infra: { vercelConfig: { framework: "nextjs" } } as any,
    });
    const result = inferDeployment(model);
    expect(result.value.platform).toBe("vercel");
    expect(result.value.platformHandles).toContain("hsts");
  });

  it("returns unknown when no platform config found", () => {
    const model = baseModel();
    const result = inferDeployment(model);
    expect(result.value.platform).toBe("unknown");
  });
});

describe("inferExcludedPaths", () => {
  it("detects scripts directory", () => {
    const model = baseModel({
      meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript", deployTarget: "vercel" } as any,
    });
    const result = inferExcludedPaths(model);
    expect(result.value).toContain("scripts/");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/inferrers/core.test.ts`
Expected: FAIL — modules not found

- [ ] **Step 3: Implement tenancy inferrer**

```typescript
// src/layers/context/inferrers/tenancy.ts
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const TENANT_COLUMNS = ["tenant_id", "org_id", "organization_id", "workspace_id"];

export function inferTenancy(model: ProjectModel): InferResult<ProjectContext["tenancy"]> {
  const allColumns = model.dataModels.flatMap((m) => (m as any).columns ?? []);
  const tenantColumns = allColumns.filter((c: string) => TENANT_COLUMNS.includes(c.toLowerCase()));

  if (tenantColumns.length === 0) {
    return { value: "single-org", confidence: "medium" };
  }

  const tablesWithTenant = model.dataModels.filter((m) =>
    ((m as any).columns ?? []).some((c: string) => TENANT_COLUMNS.includes(c.toLowerCase())),
  );

  if (tablesWithTenant.length / Math.max(model.dataModels.length, 1) > 0.5) {
    return { value: "multi-tenant", confidence: "high" };
  }

  return { value: "multi-tenant", confidence: "medium" };
}
```

- [ ] **Step 4: Implement framework inferrer**

```typescript
// src/layers/context/inferrers/framework.ts
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

export function inferFramework(model: ProjectModel): InferResult<ProjectContext["framework"]> {
  const isNextjs = model.meta.stack === "nextjs-supabase" ||
    model.dependencies.some((d) => d.name === "next");

  const hasServerOnly = model.dependencies.some((d) => d.name === "server-only");

  if (isNextjs) {
    return {
      value: {
        routeHandlersServerOnly: true,
        frameworkCatchesErrors: true,
        serverOnlyImportGuard: hasServerOnly,
      },
      confidence: "high",
    };
  }

  return {
    value: {
      routeHandlersServerOnly: false,
      frameworkCatchesErrors: false,
      serverOnlyImportGuard: hasServerOnly,
    },
    confidence: "medium",
  };
}
```

- [ ] **Step 5: Implement deployment inferrer**

```typescript
// src/layers/context/inferrers/deployment.ts
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const PLATFORM_HANDLES: Record<string, string[]> = {
  vercel: ["hsts", "ssl-termination", "ddos-protection"],
  cloudflare: ["hsts", "ssl-termination", "ddos-protection", "waf"],
  aws: ["ssl-termination"],
  fly: ["ssl-termination"],
};

export function inferDeployment(model: ProjectModel): InferResult<ProjectContext["deployment"]> {
  if (model.infra.vercelConfig || model.meta.deployTarget === "vercel") {
    return {
      value: { platform: "vercel", platformHandles: PLATFORM_HANDLES.vercel },
      confidence: "high",
    };
  }

  // Check for other platforms by known config files (future: fly.toml, wrangler.toml)
  return {
    value: { platform: "unknown", platformHandles: [] },
    confidence: "low",
  };
}
```

- [ ] **Step 6: Implement excluded-paths inferrer**

```typescript
// src/layers/context/inferrers/excluded-paths.ts
import type { ProjectModel } from "../../../model/types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const KNOWN_NON_DEPLOYED = ["scripts/", "seed.ts", "tests/", "__tests__/", "cypress/", "e2e/"];

export function inferExcludedPaths(_model: ProjectModel): InferResult<string[]> {
  // These directories are universally non-deployed in Next.js/Vite projects.
  // Future: check if directories actually exist in the project.
  return {
    value: [...KNOWN_NON_DEPLOYED],
    confidence: "high",
  };
}
```

- [ ] **Step 7: Run tests**

Run: `npx vitest run tests/layers/context/inferrers/core.test.ts`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/layers/context/inferrers/tenancy.ts src/layers/context/inferrers/framework.ts src/layers/context/inferrers/deployment.ts src/layers/context/inferrers/excluded-paths.ts tests/layers/context/inferrers/core.test.ts
git commit -m "feat(context): add tenancy, framework, deployment, and excluded-paths inferrers"
```

---

### Task 5: Validation and Migrations Inferrers

**Files:**
- Create: `src/layers/context/inferrers/validation.ts`
- Create: `src/layers/context/inferrers/migrations.ts`
- Create: `tests/layers/context/inferrers/validation.test.ts`

These inferrers need to read files (follow imports, scan migrations), so they're async and more substantial.

- [ ] **Step 1: Write the tests**

```typescript
// tests/layers/context/inferrers/validation.test.ts
import { describe, it, expect } from "vitest";
import { inferValidation } from "../../../src/layers/context/inferrers/validation.js";
import { inferMigrations } from "../../../src/layers/context/inferrers/migrations.js";
import { runRecon } from "../../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferValidation", () => {
  it("detects zod schemas imported by routes", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferValidation(model);
    expect(result.value.library).toBe("zod");
    expect(result.value.importedByRoutes).toBe(true);
    expect(result.value.schemaLocations.length).toBeGreaterThan(0);
    expect(result.confidence).toBe("high");
  });
});

describe("inferMigrations", () => {
  it("detects dedicated RLS file", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferMigrations(model);
    expect(result.value.rlsStrategy).toBe("dedicated-file");
    expect(result.value.rlsFile).toContain("00003_rls");
    expect(result.confidence).toBe("high");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/inferrers/validation.test.ts`
Expected: FAIL — modules not found

- [ ] **Step 3: Implement validation inferrer**

```typescript
// src/layers/context/inferrers/validation.ts
import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const VALIDATION_LIBS = ["zod", "joi", "yup", "ajv"];
const SCHEMA_GLOBS = ["**/validation/**/*.ts", "**/schemas/**/*.ts", "**/validators/**/*.ts"];

export async function inferValidation(model: ProjectModel): Promise<InferResult<ProjectContext["validation"]>> {
  const lib = VALIDATION_LIBS.find((l) => model.dependencies.some((d) => d.name === l));

  if (!lib) {
    return { value: { library: "none", schemaLocations: [], importedByRoutes: false }, confidence: "high" };
  }

  const schemaFiles = await fg(SCHEMA_GLOBS, { cwd: model.meta.path, absolute: false, ignore: ["**/node_modules/**"] });

  if (schemaFiles.length === 0) {
    return { value: { library: lib as any, schemaLocations: [], importedByRoutes: false }, confidence: "medium" };
  }

  // Check how many mutation routes import from schema locations
  const mutationEndpoints = model.endpoints.filter((e) =>
    ["POST", "PUT", "PATCH", "DELETE"].includes(e.method),
  );

  let importCount = 0;
  for (const ep of mutationEndpoints) {
    try {
      const source = await readFile(ep.file, "utf-8");
      const firstLines = source.split("\n").slice(0, 15).join("\n");
      const importsValidation = schemaFiles.some((sf) => {
        const base = sf.replace(/\.ts$/, "").replace(/\\/g, "/");
        return firstLines.includes("validation/") || firstLines.includes("schemas/") || firstLines.includes("validators/");
      });
      if (importsValidation) importCount++;
    } catch {
      // file read failed, skip
    }
  }

  const ratio = mutationEndpoints.length > 0 ? importCount / mutationEndpoints.length : 0;
  const importedByRoutes = ratio > 0.3;
  const confidence = ratio > 0.8 ? "high" : ratio > 0.3 ? "medium" : "low";

  return {
    value: {
      library: lib as any,
      schemaLocations: schemaFiles,
      importedByRoutes,
    },
    confidence,
  };
}
```

- [ ] **Step 4: Implement migrations inferrer**

```typescript
// src/layers/context/inferrers/migrations.ts
import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const RLS_PATTERN = /ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;

export async function inferMigrations(model: ProjectModel): Promise<InferResult<ProjectContext["migrations"]>> {
  const migrationFiles = await fg(["supabase/migrations/**/*.sql", "migrations/**/*.sql"], {
    cwd: model.meta.path, absolute: true, ignore: ["**/node_modules/**"],
  });

  if (migrationFiles.length === 0) {
    return { value: { rlsStrategy: "none" }, confidence: "high" };
  }

  // Check each migration file for RLS statements
  const filesWithRls: string[] = [];
  for (const file of migrationFiles) {
    try {
      const source = await readFile(file, "utf-8");
      if (RLS_PATTERN.test(source)) {
        filesWithRls.push(file);
      }
      RLS_PATTERN.lastIndex = 0; // reset global regex
    } catch {
      // skip unreadable files
    }
  }

  if (filesWithRls.length === 0) {
    return { value: { rlsStrategy: "none" }, confidence: "high" };
  }

  if (filesWithRls.length === 1) {
    // RLS concentrated in one file — dedicated strategy
    const relative = filesWithRls[0].replace(model.meta.path + "/", "");
    return { value: { rlsStrategy: "dedicated-file", rlsFile: relative }, confidence: "high" };
  }

  // RLS spread across multiple migration files — co-located strategy
  return { value: { rlsStrategy: "co-located" }, confidence: "high" };
}
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run tests/layers/context/inferrers/validation.test.ts`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/layers/context/inferrers/validation.ts src/layers/context/inferrers/migrations.ts tests/layers/context/inferrers/validation.test.ts
git commit -m "feat(context): add validation and migrations inferrers"
```

---

### Task 6: Auth, Public Routes, and Delegations Inferrers

**Files:**
- Create: `src/layers/context/inferrers/auth.ts`
- Create: `src/layers/context/inferrers/public-routes.ts`
- Create: `src/layers/context/inferrers/delegations.ts`
- Create: `tests/layers/context/inferrers/auth.test.ts`

- [ ] **Step 1: Write the tests**

```typescript
// tests/layers/context/inferrers/auth.test.ts
import { describe, it, expect } from "vitest";
import { inferAuth } from "../../../src/layers/context/inferrers/auth.js";
import { inferPublicRoutes } from "../../../src/layers/context/inferrers/public-routes.js";
import { inferDelegations } from "../../../src/layers/context/inferrers/delegations.js";
import { runRecon } from "../../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferAuth", () => {
  it("detects anon client as default", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferAuth(model);
    expect(result.value.defaultClient).toBe("anon");
    expect(result.confidence).toMatch(/high|medium/);
  });
});

describe("inferPublicRoutes", () => {
  it("detects routes under /api/public/ as intentionally public", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = inferPublicRoutes(model);
    expect(result.value.length).toBeGreaterThan(0);
    expect(result.value[0].pattern).toContain("public");
  });
});

describe("inferDelegations", () => {
  it("detects supabase auth delegation", async () => {
    const model = await runRecon(FIXTURE, []);
    const result = await inferDelegations(model);
    // Fixture has @supabase/ssr dependency
    expect(result.value.some((d) => d.provider === "supabase")).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/inferrers/auth.test.ts`
Expected: FAIL — modules not found

- [ ] **Step 3: Implement auth inferrer**

```typescript
// src/layers/context/inferrers/auth.ts
import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const ROLE_RPC_PATTERN = /supabase\.rpc\(["']is_(\w+)["']\)/g;
const SERVICE_CLIENT_PATTERN = /createServiceClient|SUPABASE_SERVICE_ROLE_KEY/;
const ANON_CLIENT_PATTERN = /createClient|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY/;

export async function inferAuth(model: ProjectModel): Promise<InferResult<ProjectContext["auth"]>> {
  const routeFiles = await fg(["src/app/api/**/*.ts"], {
    cwd: model.meta.path, absolute: true, ignore: ["**/node_modules/**"],
  });

  let anonCount = 0;
  let serviceCount = 0;
  const roles = new Set<string>();

  for (const file of routeFiles) {
    try {
      const source = await readFile(file, "utf-8");
      if (ANON_CLIENT_PATTERN.test(source)) anonCount++;
      if (SERVICE_CLIENT_PATTERN.test(source)) serviceCount++;

      let match: RegExpExecArray | null;
      const rpcRegex = new RegExp(ROLE_RPC_PATTERN.source, "g");
      while ((match = rpcRegex.exec(source)) !== null) {
        roles.add(match[1]);
      }
    } catch {
      // skip
    }
  }

  const defaultClient: "anon" | "service-role" = anonCount >= serviceCount ? "anon" : "service-role";
  const confidence = routeFiles.length > 5 ? "high" : "medium";
  const firstRole = roles.size > 0 ? undefined : undefined;
  const roleCheckPattern = roles.size > 0 ? `supabase.rpc('is_${[...roles][0]}')` : undefined;

  return {
    value: {
      defaultClient,
      roleModel: [...roles],
      roleCheckPattern,
    },
    confidence,
  };
}
```

- [ ] **Step 4: Implement public-routes inferrer**

```typescript
// src/layers/context/inferrers/public-routes.ts
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

const PUBLIC_PATH_PATTERNS = [
  { regex: /\/api\/public\//, reason: "magic-link" as const },
  { regex: /\/api\/webhook/, reason: "webhook" as const },
  { regex: /\/api\/health/, reason: "health-check" as const },
  { regex: /\/api\/widget/, reason: "widget" as const },
  { regex: /\/api\/auth\/callback/, reason: "oauth-callback" as const },
];

export function inferPublicRoutes(model: ProjectModel): InferResult<ProjectContext["publicRoutes"]> {
  const unauthMutations = model.endpoints.filter(
    (e) => !e.hasAuthCheck && ["POST", "PUT", "PATCH", "DELETE"].includes(e.method),
  );

  const publicRoutes: ProjectContext["publicRoutes"] = [];

  for (const ep of unauthMutations) {
    const match = PUBLIC_PATH_PATTERNS.find((p) => p.regex.test(ep.path));
    if (match) {
      // Check if pattern already covered
      const globPattern = ep.path.replace(/\[.*?\]/g, "*");
      if (!publicRoutes.some((pr) => pr.pattern === globPattern)) {
        publicRoutes.push({ pattern: globPattern, reason: match.reason });
      }
    }
  }

  return {
    value: publicRoutes,
    confidence: publicRoutes.length > 0 ? "medium" : "high",
  };
}
```

- [ ] **Step 5: Implement delegations inferrer**

```typescript
// src/layers/context/inferrers/delegations.ts
import { readFile } from "fs/promises";
import fg from "fast-glob";
import type { ProjectModel } from "../../../model/types.js";
import type { ProjectContext } from "../types.js";

type InferResult<T> = { value: T; confidence: "high" | "medium" | "low" };

interface DelegationPattern {
  dependency: string;
  provider: string;
  codePattern: RegExp;
  responsibility: string;
  mechanism: string;
}

const KNOWN_DELEGATIONS: DelegationPattern[] = [
  {
    dependency: "@supabase/ssr",
    provider: "supabase",
    codePattern: /exchangeCodeForSession/,
    responsibility: "OAuth state verification",
    mechanism: "exchangeCodeForSession()",
  },
  {
    dependency: "@supabase/ssr",
    provider: "supabase",
    codePattern: /supabase\.auth\.getUser/,
    responsibility: "JWT verification",
    mechanism: "auth.getUser()",
  },
];

export async function inferDelegations(model: ProjectModel): Promise<InferResult<ProjectContext["delegations"]>> {
  const depNames = new Set(model.dependencies.map((d) => d.name));
  const candidates = KNOWN_DELEGATIONS.filter((d) => depNames.has(d.dependency));

  if (candidates.length === 0) {
    return { value: [], confidence: "high" };
  }

  // Scan source files for actual usage of delegation patterns
  const sourceFiles = await fg(["src/**/*.ts"], {
    cwd: model.meta.path, absolute: true, ignore: ["**/node_modules/**"],
  });

  const found: ProjectContext["delegations"] = [];
  const seen = new Set<string>();

  for (const file of sourceFiles) {
    try {
      const source = await readFile(file, "utf-8");
      for (const candidate of candidates) {
        const key = `${candidate.provider}:${candidate.responsibility}`;
        if (!seen.has(key) && candidate.codePattern.test(source)) {
          seen.add(key);
          found.push({
            provider: candidate.provider,
            responsibility: candidate.responsibility,
            mechanism: candidate.mechanism,
          });
        }
      }
    } catch {
      // skip
    }
  }

  return { value: found, confidence: "high" };
}
```

- [ ] **Step 6: Run tests**

Run: `npx vitest run tests/layers/context/inferrers/auth.test.ts`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/layers/context/inferrers/auth.ts src/layers/context/inferrers/public-routes.ts src/layers/context/inferrers/delegations.ts tests/layers/context/inferrers/auth.test.ts
git commit -m "feat(context): add auth, public-routes, and delegations inferrers"
```

---

### Task 7: Context Orchestrator

**Files:**
- Create: `src/layers/context/index.ts`
- Create: `tests/layers/context/orchestrator.test.ts`

- [ ] **Step 1: Write the test**

```typescript
// tests/layers/context/orchestrator.test.ts
import { describe, it, expect } from "vitest";
import { inferContext } from "../../src/layers/context/index.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("inferContext", () => {
  it("produces a valid ProjectContext from a fixture", async () => {
    const model = await runRecon(FIXTURE, []);
    const context = await inferContext(model);

    expect(context.tenancy).toBe("single-org");
    expect(context.validation.library).toBe("zod");
    expect(context.framework.frameworkCatchesErrors).toBe(true);
    expect(context.deployment.platform).toBe("vercel");
    expect(context.excludedPaths).toContain("scripts/");
    expect(context.version).toBe(1);
    expect(context.generatedBy).toBe("auto");
    expect(context.confidence).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/orchestrator.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```typescript
// src/layers/context/index.ts
import type { ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "./types.js";
import { inferTenancy } from "./inferrers/tenancy.js";
import { inferFramework } from "./inferrers/framework.js";
import { inferDeployment } from "./inferrers/deployment.js";
import { inferExcludedPaths } from "./inferrers/excluded-paths.js";
import { inferValidation } from "./inferrers/validation.js";
import { inferMigrations } from "./inferrers/migrations.js";
import { inferAuth } from "./inferrers/auth.js";
import { inferPublicRoutes } from "./inferrers/public-routes.js";
import { inferDelegations } from "./inferrers/delegations.js";

export { readContext, writeContext } from "./io.js";
export type { ProjectContext } from "./types.js";

export async function inferContext(model: ProjectModel): Promise<ProjectContext> {
  const [tenancy, framework, deployment, excludedPaths, validation, migrations, auth, publicRoutes, delegations] =
    await Promise.all([
      Promise.resolve(inferTenancy(model)),
      Promise.resolve(inferFramework(model)),
      Promise.resolve(inferDeployment(model)),
      Promise.resolve(inferExcludedPaths(model)),
      inferValidation(model),
      inferMigrations(model),
      inferAuth(model),
      Promise.resolve(inferPublicRoutes(model)),
      inferDelegations(model),
    ]);

  const confidence: Record<string, "high" | "medium" | "low"> = {
    tenancy: tenancy.confidence,
    framework: framework.confidence,
    deployment: deployment.confidence,
    excludedPaths: excludedPaths.confidence,
    validation: validation.confidence,
    migrations: migrations.confidence,
    auth: auth.confidence,
    publicRoutes: publicRoutes.confidence,
    delegations: delegations.confidence,
  };

  return {
    tenancy: tenancy.value,
    publicRoutes: publicRoutes.value,
    validation: validation.value,
    migrations: migrations.value,
    framework: framework.value,
    excludedPaths: excludedPaths.value,
    auth: auth.value,
    deployment: deployment.value,
    delegations: delegations.value,
    version: 1,
    generatedAt: new Date().toISOString(),
    generatedBy: "auto",
    confidence,
  };
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/layers/context/orchestrator.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/context/index.ts tests/layers/context/orchestrator.test.ts
git commit -m "feat(context): add inferContext orchestrator"
```

---

### Task 8: Context Suppression Filter

**Files:**
- Create: `src/layers/context/suppression.ts`
- Create: `tests/layers/context/suppression.test.ts`

- [ ] **Step 1: Write the test**

```typescript
// tests/layers/context/suppression.test.ts
import { describe, it, expect } from "vitest";
import { applyContextSuppressions } from "../../src/layers/context/suppression.js";
import type { Finding } from "../../src/model/types.js";
import type { ProjectContext } from "../../src/layers/context/types.js";

function mkFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "test-1",
    domain: "auth-access-control",
    severity: "critical",
    confidence: "high",
    title: "Test finding",
    description: "Test",
    evidence: [{ file: "/src/app/api/test/route.ts" }],
    remediation: "Fix it",
    references: [],
    layer: "rules",
    ruleId: "AUTH-001",
    ...overrides,
  } as Finding;
}

const CTX: ProjectContext = {
  tenancy: "single-org",
  publicRoutes: [{ pattern: "/api/public/**", reason: "magic-link" }],
  validation: { library: "zod", schemaLocations: [], importedByRoutes: true },
  migrations: { rlsStrategy: "dedicated-file", rlsFile: "supabase/migrations/00003.sql" },
  framework: { routeHandlersServerOnly: true, frameworkCatchesErrors: true, serverOnlyImportGuard: false },
  excludedPaths: ["scripts/"],
  auth: { defaultClient: "anon", roleModel: ["admin"] },
  deployment: { platform: "vercel", platformHandles: ["hsts"] },
  delegations: [{ provider: "supabase", responsibility: "OAuth state verification" }],
  version: 1,
  generatedAt: "2026-04-12T00:00:00Z",
  generatedBy: "auto",
  confidence: {},
};

describe("applyContextSuppressions", () => {
  it("suppresses AUTH-001 on public routes", () => {
    const findings = [mkFinding({ ruleId: "AUTH-001", title: "POST /api/public/reservation has no auth", evidence: [{ file: "/src/app/api/public/reservation/route.ts" }] as any })];
    const result = applyContextSuppressions(findings, CTX);
    expect(result).toHaveLength(0);
  });

  it("keeps AUTH-001 on non-public routes", () => {
    const findings = [mkFinding({ ruleId: "AUTH-001", title: "POST /api/users has no auth" })];
    const result = applyContextSuppressions(findings, CTX);
    expect(result).toHaveLength(1);
  });

  it("suppresses findings in excluded paths", () => {
    const findings = [mkFinding({ ruleId: "AUTH-005", evidence: [{ file: "/project/scripts/seed.ts" }] as any })];
    const result = applyContextSuppressions(findings, CTX);
    expect(result).toHaveLength(0);
  });

  it("downgrades LOG-005 when framework catches errors", () => {
    const findings = [mkFinding({ ruleId: "LOG-005", severity: "medium", domain: "logging-monitoring" })];
    const result = applyContextSuppressions(findings, CTX);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe("info");
  });

  it("suppresses probe HSTS findings when platform handles it", () => {
    const findings = [mkFinding({ ruleId: undefined, title: "Missing security header: strict-transport-security", layer: "probe" as any })];
    const result = applyContextSuppressions(findings, CTX);
    expect(result).toHaveLength(0);
  });

  it("returns all findings when context is null", () => {
    const findings = [mkFinding({}), mkFinding({ ruleId: "LOG-005" })];
    const result = applyContextSuppressions(findings, null as any);
    expect(result).toHaveLength(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/context/suppression.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```typescript
// src/layers/context/suppression.ts
import { minimatch } from "minimatch";
import type { Finding } from "../../model/types.js";
import type { ProjectContext } from "./types.js";

export function applyContextSuppressions(
  findings: Finding[],
  context: ProjectContext | null,
): Finding[] {
  if (!context) return findings;

  return findings
    .map((f) => {
      // Suppress findings in excluded paths
      const file = f.evidence[0]?.file ?? "";
      if (context.excludedPaths.some((p) => file.includes(p))) {
        return null;
      }

      // Suppress AUTH-001 on intentionally public routes
      if (f.ruleId === "AUTH-001") {
        const routePath = extractPathFromTitle(f.title);
        if (routePath && context.publicRoutes.some((pr) => minimatch(routePath, pr.pattern))) {
          return null;
        }
      }

      // Suppress AUTH-010 when OAuth state is delegated
      if (f.ruleId === "AUTH-010") {
        if (context.delegations.some((d) => d.responsibility === "OAuth state verification")) {
          return null;
        }
      }

      // Downgrade LOG-005 when framework catches errors
      if (f.ruleId === "LOG-005" && context.framework.frameworkCatchesErrors) {
        return { ...f, severity: "info" as const };
      }

      // Suppress probe HSTS findings when platform handles it
      if (f.title.toLowerCase().includes("strict-transport-security") &&
          context.deployment.platformHandles.includes("hsts")) {
        return null;
      }

      // Suppress INFRA-010 (supabase config) when in excluded/config paths
      if (f.ruleId === "INFRA-010") {
        return null; // supabase config.toml is always local dev config
      }

      // Downgrade SECRETS-008 (missing .env.example) to info
      if (f.ruleId === "SECRETS-008") {
        return { ...f, severity: "info" as const };
      }

      return f;
    })
    .filter((f): f is Finding => f !== null);
}

function extractPathFromTitle(title: string): string | null {
  // Titles like "POST /api/public/reservation has no auth check"
  const match = title.match(/(?:POST|GET|PUT|PATCH|DELETE)\s+(\/\S+)/);
  return match ? match[1] : null;
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/layers/context/suppression.test.ts`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/context/suppression.ts tests/layers/context/suppression.test.ts
git commit -m "feat(context): add context suppression filter"
```

---

### Task 9: Wire Context into Scan Pipeline

**Files:**
- Modify: `src/commands/scan.ts:1-5,78-96,129`
- Modify: `src/layers/rules/registry.ts:3,15`
- Modify: `src/layers/rules/index.ts:7-10`

- [ ] **Step 1: Write integration test**

```typescript
// tests/integration/context-scan.test.ts
import { describe, it, expect } from "vitest";
import { runRecon } from "../../src/layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { loggingMonitoringRules } from "../../src/layers/rules/domains/logging-monitoring.js";
import { inferContext } from "../../src/layers/context/index.js";
import { applyContextSuppressions } from "../../src/layers/context/suppression.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("context-aware scan pipeline", () => {
  it("reduces findings when context is applied", async () => {
    const model = await runRecon(FIXTURE, []);

    resetRegistry();
    registerRules(authAccessControlRules);
    registerRules(loggingMonitoringRules);

    const context = await inferContext(model);
    const rawFindings = await runRules(model, context);
    const suppressed = applyContextSuppressions(rawFindings, context);

    // With context, public route AUTH-001 findings should be suppressed
    // and LOG-005 findings should be downgraded to info
    const authFindings = suppressed.filter((f) => f.ruleId === "AUTH-001");
    const publicAuthFindings = authFindings.filter((f) => f.title.includes("public"));
    expect(publicAuthFindings).toHaveLength(0);

    const logFindings = suppressed.filter((f) => f.ruleId === "LOG-005");
    for (const f of logFindings) {
      expect(f.severity).toBe("info");
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/integration/context-scan.test.ts`
Expected: FAIL — `runRules` doesn't accept context parameter

- [ ] **Step 3: Update rule signature and runRules**

Update `src/layers/rules/registry.ts`:

```typescript
// Change line 15 from:
//   check: (model: ProjectModel) => Finding[] | Promise<Finding[]>;
// To:
  check: (model: ProjectModel, context?: ProjectContext | null) => Finding[] | Promise<Finding[]>;
```

Add import at line 1:
```typescript
import type { Finding, ProjectModel, Severity, SecurityDomain, StackProfile } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
```

Update `src/layers/rules/index.ts`:

```typescript
import { getRules } from "./registry.js";
import type { Finding, ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export async function runRules(model: ProjectModel, context?: ProjectContext | null): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model, context))));
  return results.flat();
}
```

- [ ] **Step 4: Update scan.ts to load context and apply suppressions**

In `src/commands/scan.ts`, add imports at the top:

```typescript
import { inferContext, readContext } from "../layers/context/index.js";
import { applyContextSuppressions } from "../layers/context/suppression.js";
```

After recon (line 80), add context loading:

```typescript
  // Context phase: load saved context or auto-infer
  const contextFromFile = await readContext(options.path);
  const context = contextFromFile ?? await inferContext(model);
  if (!contextFromFile) {
    process.stderr.write("No .sentinel/context.json found. Using auto-inferred context.\n");
    process.stderr.write("Run `sentinel context` to reduce false positives.\n\n");
  }
```

Pass context to runRules (line 95):

```typescript
  const ruleFindings = await runRules(model, context);
```

Apply suppression after combining findings (line 129):

```typescript
  const rawFindings = [...ruleFindings, ...(aiResult?.findings ?? [])];
  const allFindings = applyContextSuppressions(rawFindings, context);
```

- [ ] **Step 5: Run all tests to check for regressions**

Run: `npx vitest run`
Expected: All existing tests pass (context param is optional, so no breaking changes). New integration test passes.

- [ ] **Step 6: Commit**

```bash
git add src/layers/rules/registry.ts src/layers/rules/index.ts src/commands/scan.ts tests/integration/context-scan.test.ts
git commit -m "feat(context): wire context into scan pipeline"
```

---

### Task 10: Enrich AI Prompt with Context

**Files:**
- Modify: `src/layers/ai/prompts.ts:21-50`

- [ ] **Step 1: Write the test**

```typescript
// tests/layers/ai/prompts-context.test.ts
import { describe, it, expect } from "vitest";
import { buildProjectSummary } from "../../src/layers/ai/prompts.js";
import type { ProjectModel } from "../../src/model/types.js";
import type { ProjectContext } from "../../src/layers/context/types.js";

describe("buildProjectSummary with context", () => {
  it("includes context sections when provided", () => {
    const model = {
      meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript" },
      routes: [], endpoints: [], dataModels: [], authFlows: [], dependencies: [], infra: { securityHeaders: {} },
    } as unknown as ProjectModel;

    const context: ProjectContext = {
      tenancy: "single-org",
      publicRoutes: [{ pattern: "/api/public/**", reason: "magic-link" }],
      validation: { library: "zod", schemaLocations: ["src/lib/validation/*.ts"], importedByRoutes: true },
      migrations: { rlsStrategy: "dedicated-file", rlsFile: "00003_rls.sql" },
      framework: { routeHandlersServerOnly: true, frameworkCatchesErrors: true, serverOnlyImportGuard: true },
      excludedPaths: ["scripts/"],
      auth: { defaultClient: "anon", roleModel: ["viewer", "admin"] },
      deployment: { platform: "vercel", platformHandles: ["hsts"] },
      delegations: [{ provider: "supabase", responsibility: "OAuth state verification", mechanism: "exchangeCodeForSession()" }],
      version: 1, generatedAt: "2026-04-12", generatedBy: "auto", confidence: {},
    };

    const summary = buildProjectSummary(model, context);
    expect(summary).toContain("single-org");
    expect(summary).toContain("magic-link");
    expect(summary).toContain("Zod");
    expect(summary).toContain("exchangeCodeForSession");
    expect(summary).toContain("Vercel");
  });

  it("works without context", () => {
    const model = {
      meta: { name: "test", path: "/test", stack: "nextjs-supabase", framework: "next", language: "typescript" },
      routes: [], endpoints: [], dataModels: [], authFlows: [], dependencies: [], infra: { securityHeaders: {} },
    } as unknown as ProjectModel;

    const summary = buildProjectSummary(model);
    expect(summary).toContain("PROJECT: test");
    expect(summary).not.toContain("ARCHITECTURE CONTEXT");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/ai/prompts-context.test.ts`
Expected: FAIL — buildProjectSummary doesn't accept context

- [ ] **Step 3: Update buildProjectSummary**

In `src/layers/ai/prompts.ts`, change the function signature and add a context section:

```typescript
export function buildProjectSummary(model: ProjectModel, context?: ProjectContext | null): string {
```

Add import:
```typescript
import type { ProjectContext } from "../context/types.js";
```

At the end of the function, before the final return, append:

```typescript
  const contextSection = context ? `

ARCHITECTURE CONTEXT:
  Tenancy: ${context.tenancy}
  Auth: ${context.auth.defaultClient} client, roles: ${context.auth.roleModel.join(", ") || "none detected"}
  Validation: ${context.validation.library !== "none" ? `${context.validation.library} schemas${context.validation.importedByRoutes ? " (imported by routes from " + context.validation.schemaLocations.join(", ") + ")" : ""}` : "none"}
  RLS: ${context.migrations.rlsStrategy}${context.migrations.rlsFile ? ` (${context.migrations.rlsFile})` : ""}
  Deployment: ${context.deployment.platform}${context.deployment.platformHandles.length > 0 ? ` (handles: ${context.deployment.platformHandles.join(", ")})` : ""}
  Intentionally public routes:
${context.publicRoutes.map((r) => `    ${r.pattern} (${r.reason})`).join("\n") || "    none"}
  Security delegated to third parties:
${context.delegations.map((d) => `    ${d.provider}: ${d.responsibility}${d.mechanism ? ` via ${d.mechanism}` : ""}`).join("\n") || "    none"}
  Non-deployed paths: ${context.excludedPaths.join(", ") || "none"}

IMPORTANT: Use this architecture context to avoid false positives. Do NOT flag:
- Public routes listed above as missing auth (they are intentionally unauthenticated)
- Security responsibilities delegated to third parties (the provider handles it)
- Files in non-deployed paths (scripts, seeds, tests — they don't run in production)` : "";

  return baseSummary + contextSection;
```

Where `baseSummary` is the existing return value assigned to a variable instead of returned directly.

- [ ] **Step 4: Update callers to pass context**

In `src/layers/ai/index.ts` (or wherever `buildProjectSummary` is called), pass context through. The orchestrator already caches the project summary; it needs the context parameter added.

- [ ] **Step 5: Run tests**

Run: `npx vitest run tests/layers/ai/prompts-context.test.ts`
Expected: PASS

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/layers/ai/prompts.ts tests/layers/ai/prompts-context.test.ts
git commit -m "feat(context): enrich AI prompt with architecture context"
```

---

### Task 11: `sentinel context` CLI Command

**Files:**
- Create: `src/commands/context.ts`
- Modify: `src/cli.ts:8,110`

- [ ] **Step 1: Write the command handler**

```typescript
// src/commands/context.ts
import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { inferContext, writeContext, readContext } from "../layers/context/index.js";

export interface ContextOptions {
  path: string;
  show?: boolean;
  acceptDefaults?: boolean;
  only?: string;
}

export async function runContextCommand(options: ContextOptions): Promise<number> {
  const config = await loadConfig(options.path);

  // Show mode: display current context and exit
  if (options.show) {
    const existing = await readContext(options.path);
    if (!existing) {
      process.stdout.write("No .sentinel/context.json found. Run `sentinel context` to generate.\n");
      return 1;
    }
    process.stdout.write(JSON.stringify(existing, null, 2) + "\n");
    return 0;
  }

  process.stderr.write("Running recon...\n");
  const model = await runRecon(options.path, config.exclude);
  process.stderr.write(`Recon complete. ${model.routes.length} routes, ${model.dataModels.length} tables detected.\n\n`);

  process.stderr.write("Inferring project context...\n");
  const context = await inferContext(model);

  // Display inferred context
  process.stderr.write(`\n── Tenancy Model ──\n`);
  process.stderr.write(`  Inferred: ${context.tenancy} (${context.confidence.tenancy} confidence)\n`);

  process.stderr.write(`\n── Auth Architecture ──\n`);
  process.stderr.write(`  Default client: ${context.auth.defaultClient}\n`);
  process.stderr.write(`  Roles: ${context.auth.roleModel.join(", ") || "none detected"}\n`);

  process.stderr.write(`\n── Validation Strategy ──\n`);
  process.stderr.write(`  Library: ${context.validation.library}\n`);
  process.stderr.write(`  Imported by routes: ${context.validation.importedByRoutes}\n`);

  process.stderr.write(`\n── Migration Strategy ──\n`);
  process.stderr.write(`  RLS: ${context.migrations.rlsStrategy}${context.migrations.rlsFile ? ` (${context.migrations.rlsFile})` : ""}\n`);

  process.stderr.write(`\n── Framework ──\n`);
  process.stderr.write(`  Server-only handlers: ${context.framework.routeHandlersServerOnly}\n`);
  process.stderr.write(`  Framework catches errors: ${context.framework.frameworkCatchesErrors}\n`);

  process.stderr.write(`\n── Deployment ──\n`);
  process.stderr.write(`  Platform: ${context.deployment.platform}\n`);
  process.stderr.write(`  Platform handles: ${context.deployment.platformHandles.join(", ") || "none"}\n`);

  process.stderr.write(`\n── Public Routes ──\n`);
  if (context.publicRoutes.length > 0) {
    for (const r of context.publicRoutes) {
      process.stderr.write(`  ${r.pattern} (${r.reason})\n`);
    }
  } else {
    process.stderr.write("  none detected\n");
  }

  process.stderr.write(`\n── Third-Party Delegations ──\n`);
  if (context.delegations.length > 0) {
    for (const d of context.delegations) {
      process.stderr.write(`  ${d.provider}: ${d.responsibility}\n`);
    }
  } else {
    process.stderr.write("  none detected\n");
  }

  process.stderr.write(`\n── Excluded Paths ──\n`);
  process.stderr.write(`  ${context.excludedPaths.join(", ")}\n`);

  // Write context file
  const filePath = await writeContext(options.path, context);
  process.stderr.write(`\nContext written to ${filePath}\n`);
  process.stderr.write("Commit this file so CI and teammates use the same context.\n");

  return 0;
}
```

- [ ] **Step 2: Register the command in cli.ts**

Add import at line 8:
```typescript
import { runContextCommand } from "./commands/context.js";
```

Add command registration before `program.parseAsync` (before line 112):

```typescript
program
  .command("context")
  .description("Generate or display project context for smarter scanning")
  .argument("<path>", "Path to the project")
  .option("--show", "Display current context without regenerating")
  .option("--accept-defaults", "Accept all auto-inferred values without prompting")
  .option("--only <sections>", "Regenerate only specific sections (comma-separated)")
  .action(async (path, options) => {
    const exitCode = await runContextCommand({
      path,
      show: options.show,
      acceptDefaults: options.acceptDefaults,
      only: options.only,
    });
    exitAfterDrain(exitCode);
  });
```

- [ ] **Step 3: Test the command**

Run: `npx tsx src/cli.ts context tests/fixtures/context/single-org-nextjs`
Expected: Prints inferred context sections and writes `.sentinel/context.json`

Run: `npx tsx src/cli.ts context tests/fixtures/context/single-org-nextjs --show`
Expected: Prints the saved context JSON

- [ ] **Step 4: Run all tests**

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/commands/context.ts src/cli.ts
git commit -m "feat(context): add sentinel context CLI command"
```

---

### Task 12: Full Regression Test

**Files:**
- None new — verification pass

- [ ] **Step 1: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass (263 existing + new context tests)

- [ ] **Step 2: Run sentinel scan against fixture with context**

```bash
npx tsx src/cli.ts context tests/fixtures/context/single-org-nextjs --accept-defaults
npx tsx src/cli.ts scan tests/fixtures/context/single-org-nextjs -f json -o /tmp/context-scan.json
```

Verify the output has fewer findings than without context.

- [ ] **Step 3: Run sentinel scan against skutt (real-world validation)**

```bash
npx tsx src/cli.ts context ~/Downloads/projects/skutt --accept-defaults
npx tsx src/cli.ts scan ~/Downloads/projects/skutt -f json -o /tmp/skutt-with-context.json
```

Compare finding counts to the baseline 221. Expect significant reduction.

- [ ] **Step 4: Commit any test fixes**

```bash
git add -A
git commit -m "test(context): full regression pass"
```
