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
    // Glob patterns (relative to project root) that declare which routes this
    // delegation covers. When present, the AI layer emits a per-endpoint hint
    // telling the model to treat `mechanism` as the auth primitive for
    // matching files, instead of looking for session-based auth.
    appliesTo: z.array(z.string()).optional(),
  })),

  version: z.literal(1),
  generatedAt: z.string(),
  generatedBy: z.enum(["auto", "interactive", "manual"]),
  confidence: z.record(z.string(), z.enum(["high", "medium", "low"])),
});

export type ProjectContext = z.infer<typeof ProjectContextSchema>;
