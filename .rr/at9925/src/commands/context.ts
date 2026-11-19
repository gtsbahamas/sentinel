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

  const filePath = await writeContext(options.path, context);
  process.stderr.write(`\nContext written to ${filePath}\n`);
  process.stderr.write("Commit this file so CI and teammates use the same context.\n");

  return 0;
}
