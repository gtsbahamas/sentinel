# Context Layer Design Spec

*Date: 2026-04-12*
*Status: Approved*

## Problem

Sentinel's rules layer produces a 76% false positive rate on real projects. The root cause: rules are single-file pattern matchers with no understanding of the application's architecture, threat model, or intentional design decisions. The AI layer suffers similarly, generating findings based on generic assumptions (multi-tenant, no centralized validation) that don't match the target app.

Evidence from the skutt scan: 221 findings, 168 false positives. Categories:
- 44 INPUT-005: Validation exists in imported schemas; scanner doesn't follow imports
- 23 AUTH-002: RLS exists in a dedicated migration file; scanner checks per-table
- 83 LOG-005: Next.js catches handler errors; scanner assumes bare async functions crash
- 7 INFRA-006: SVG xmlns attributes matched as HTTP URLs
- 11 misc: Seed scripts, dev config, and non-security findings flagged as issues

## Solution

A new **context layer** that runs after recon, before rules. It builds a `ProjectContext` describing the application's architecture, then rules and AI consume it to suppress, downgrade, or adjust findings.

Two modes:
- **`sentinel context <path>`**: Interactive command. Runs inference, presents assumptions, user confirms or corrects. Writes `.sentinel/context.json`.
- **`sentinel scan <path>`**: If context file exists, loads it. If not, runs auto-inference silently with a warning about higher false positive rates.

## Architecture

### Pipeline position

```
Recon → Context → Rules(model + context) → AI(model + context) → Probe → Output
         ↕
  .sentinel/context.json
```

### Module structure

```
src/layers/context/
├── index.ts                  # inferContext(model) → ProjectContext
├── types.ts                  # ProjectContext type + Zod schema
├── inferrers/
│   ├── tenancy.ts            # Single-org vs multi-tenant detection
│   ├── public-routes.ts      # Cross-ref routes with auth + naming patterns
│   ├── validation.ts         # Follow imports to find schema files
│   ├── migrations.ts         # Read all migrations together for RLS
│   ├── framework.ts          # Detect framework conventions from stack
│   ├── excluded-paths.ts     # Identify non-deployed directories
│   ├── auth.ts               # Trace Supabase client imports, role patterns
│   ├── deployment.ts         # Read vercel.json, fly.toml, etc.
│   └── delegations.ts        # Pattern-match known third-party SDK calls
├── interactive.ts            # CLI prompts for sentinel context command
└── io.ts                     # Read/write .sentinel/context.json
```

Each inferrer is a pure function: `(model: ProjectModel) => { value: T, confidence: "high" | "medium" | "low" }`. They don't depend on each other and can run in parallel.

## Type Contract

```typescript
interface ProjectContext {
  tenancy: "single-org" | "multi-tenant" | "per-user";

  publicRoutes: Array<{
    pattern: string;
    reason: "magic-link" | "webhook" | "health-check" | "widget" | "oauth-callback" | "custom";
    description?: string;
  }>;

  validation: {
    library: "zod" | "joi" | "yup" | "ajv" | "none" | "custom";
    schemaLocations: string[];
    importedByRoutes: boolean;
  };

  migrations: {
    rlsStrategy: "co-located" | "dedicated-file" | "none";
    rlsFile?: string;
  };

  framework: {
    routeHandlersServerOnly: boolean;
    frameworkCatchesErrors: boolean;
    serverOnlyImportGuard: boolean;
  };

  excludedPaths: string[];

  auth: {
    defaultClient: "anon" | "service-role";
    roleModel: string[];
    roleCheckPattern?: string;
  };

  deployment: {
    platform: "vercel" | "cloudflare" | "aws" | "fly" | "self-hosted" | "unknown";
    platformHandles: string[];
  };

  delegations: Array<{
    provider: string;
    responsibility: string;
    mechanism?: string;
  }>;

  version: 1;
  generatedAt: string;
  generatedBy: "auto" | "interactive" | "manual";
  confidence: Record<string, "high" | "medium" | "low">;
}
```

## Inference Examples

### Validation strategy inferrer

1. Read `model.dependencies` for zod/joi/yup/ajv.
2. Glob for files matching `**/validation/**/*.ts` or `**/schemas/**/*.ts`.
3. For each route file referenced by `model.endpoints`, read first 10 lines for imports from schema locations.
4. If >80% of mutation routes import from schema files: `importedByRoutes: true`, confidence `high`.
5. If 30-80%: confidence `medium`.
6. If <30%: confidence `low`.

### Tenancy inferrer

1. Scan `model.dataModels` for `tenant_id`, `org_id`, or `organization_id` columns.
2. Check middleware for tenant extraction patterns.
3. Check auth flows for multi-org session handling.
4. No tenant signals found: `single-org`, confidence `medium`.
5. Tenant column in >50% of tables: `multi-tenant`, confidence `high`.

### Public routes inferrer

1. Find routes where `hasAuthCheck === false` and method is POST/PATCH/PUT/DELETE.
2. Check path patterns: `/api/public/**`, `/api/webhook/**`, `/api/health`.
3. Check for magic-link patterns: route reads a token param, does a DB lookup, no session required.
4. Each match gets a reason tag and confidence based on how many signals aligned.

## CLI: `sentinel context`

```bash
# Interactive generation
sentinel context /path/to/project

# Auto-accept all inferences
sentinel context /path/to/project --accept-defaults

# Regenerate specific sections
sentinel context /path/to/project --only tenancy,auth

# Display current context
sentinel context /path/to/project --show
```

### Interactive flow

For each context section:
1. Display the inferred value with evidence and confidence.
2. Ask user to confirm or correct.
3. Save with updated confidence (`high` for user-confirmed values).

Corrections are saved to `.sentinel/context.json`. The file is meant to be committed to version control.

### Behavior of `sentinel scan`

| Scenario | Behavior |
|----------|----------|
| `.sentinel/context.json` exists | Load silently. Full suppression active. |
| No context file | Auto-infer without prompts. Warn: "No context file. Run `sentinel context` to reduce false positives." |
| Context file is stale | Warn: "Context generated on [date] but project structure has changed. Consider re-running `sentinel context`." Stale when: route count differs by >10%, new tables exist that aren't in context, or new migration files were added since `generatedAt`. |

## Suppression Logic

### Post-rule filter

A `applyContextSuppressions(findings, context)` function runs after rules execute. It handles path exclusions, public route matching, platform-handled security, and third-party delegations.

### Rules that need deeper changes

These rules can't be fixed by post-filtering alone. They need the `context` parameter to change how they check:

- **AUTH-002**: When `migrations.rlsStrategy === "dedicated-file"`, read that file for `ENABLE ROW LEVEL SECURITY` statements instead of scanning per-table migration.
- **INPUT-005**: When `validation.importedByRoutes === true`, follow imports from route files to `schemaLocations` before flagging missing validation.

### Rule signature change

```typescript
// Current
interface SecurityRule {
  check(model: ProjectModel): Finding[];
}

// New
interface SecurityRule {
  check(model: ProjectModel, context: ProjectContext | null): Finding[];
}
```

`context` is nullable. Existing rules continue to work without context. Rules opt in to using context.

### Suppression categories

- **Suppressed**: Finding contradicts confirmed context. Removed from output.
- **Downgraded**: Finding is technically accurate but low-risk given context. Severity reduced.
- **Changed**: Rule checks differently based on context (AUTH-002, INPUT-005).

### Suppression mapping

| Rule | Context Field | Action |
|------|--------------|--------|
| AUTH-001 | `publicRoutes` | Suppress if endpoint matches a public route pattern |
| AUTH-002 | `migrations.rlsStrategy` | Check dedicated RLS file instead of per-table |
| AUTH-005 | `excludedPaths` | Suppress if file is in an excluded path |
| AUTH-010 | `delegations` | Suppress if OAuth state is delegated to provider |
| INPUT-005 | `validation.importedByRoutes` | Follow imports to schema files before flagging |
| LOG-005 | `framework.frameworkCatchesErrors` | Downgrade to info or suppress |
| LOG-004 | `excludedPaths` | Suppress if file is in an excluded path |
| LOG-007 | `excludedPaths` | Suppress if file is in an excluded path |
| INFRA-010 | `excludedPaths` | Suppress config-only files |
| SECRETS-008 | N/A | Downgrade to info (not security-relevant) |
| Probe HSTS | `deployment.platformHandles` | Suppress if platform handles HSTS |

### AI layer integration

The `buildProjectSummary()` prompt function gets enriched with context:

```
"This is a single-org, role-gated Next.js + Supabase app.
Auth uses anon client with RLS. Roles: viewer, editor, manager, admin.
These routes are intentionally public: [list with reasons].
Validation schemas live in src/lib/validation/, imported by routes.
OAuth state verification is delegated to Supabase (exchangeCodeForSession).
Deploys to Vercel (HSTS handled by platform)."
```

This prevents the AI from generating findings based on wrong architectural assumptions.

## Expected Impact

Based on the skutt scan (221 findings, 168 false positives):

| Metric | Before Context | After Context |
|--------|---------------|---------------|
| Total findings | 221 | ~53 |
| False positives | 168 | ~5 |
| False positive rate | 76% | ~9% |
| Real findings preserved | 53 | 48 |

The ~5 remaining false positives are rule bugs (INFRA-006 SVG xmlns, SECRETS-009 .gitignore check) that need regex fixes independent of context.

## Testing Strategy

### Unit tests for inferrers

Fixture-based. Minimal project directories that trigger specific inference outcomes:

```
tests/fixtures/context/
├── single-org-nextjs/
├── multi-tenant-nextjs/
├── no-validation/
├── validation-in-routes/
├── dedicated-rls-file/
└── co-located-rls/
```

Each test: build `ProjectModel` from fixture, run inferrer, assert value and confidence.

### Integration tests for suppression

Baseline: the 221 skutt findings. Apply a skutt-like context. Assert:
- False positives (AUTH-001, AUTH-002, INPUT-005, LOG-005): suppressed or downgraded
- Real findings (SECRETS-001, INPUT-001, INFRA-001): still present
- No real finding accidentally suppressed

### End-to-end test

Run `sentinel context --accept-defaults` against a fixture. Assert generated context file matches expected values.

### Bidirectional suppression tests

Every suppression tested in both directions:
1. With context: finding suppressed
2. Without context (null): finding still fires

Prevents context from becoming a blanket mute.

## Non-Goals

- LLM-powered context inference (future enhancement for `sentinel context`)
- Per-finding user annotations ("this finding is a false positive")
- Context sharing across projects
- Runtime context from the probe layer feeding back into context

## Build Order

1. `ProjectContext` type + Zod schema + io (read/write)
2. Individual inferrers (9 modules, parallelizable)
3. `inferContext()` orchestrator
4. Rule signature change (`context` parameter)
5. `applyContextSuppressions()` post-filter
6. Update AUTH-002 and INPUT-005 for deeper context checks
7. AI prompt enrichment in `buildProjectSummary()`
8. `sentinel context` CLI command with interactive prompts
9. Probe suppression for platform-handled findings
10. Integration tests against skutt baseline
