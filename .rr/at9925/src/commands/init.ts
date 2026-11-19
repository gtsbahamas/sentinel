// `sentinel init` — wire Sentinel into an AI coding agent's recurring
// workflow. v1 target: Claude Code. Installs a `sentinel-scan` skill that
// makes the agent run a Sentinel scan at the moments that matter (before a
// push/deploy/PR, after security-sensitive edits) instead of only when a
// human remembers to.
//
// Two install destinations:
//   default        ~/.claude/skills/sentinel-scan/SKILL.md   (this machine)
//   --project      ./.claude/skills/sentinel-scan/SKILL.md   (committed with
//                  the repo — every contributor's agent picks it up)
//
// Refuses to overwrite a SKILL.md it didn't write (marker check). Mirrors
// the shipsafe-mcp install-monitor pattern.
//
// SENTINEL_SKILLS_DIR overrides the user-level destination (tests only).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join, resolve } from "path";

const SKILL_MARKER = "Managed by shipsafe-sentinel init";

const SKILL_BODY = `---
name: sentinel-scan
description: Use BEFORE pushing, opening a PR, deploying, or calling security-sensitive work done — and AFTER editing auth, session, or payment code, API routes, file uploads, CORS/CSP/headers, env or secret handling, SQL/queries, or dependency manifests. Runs the free Sentinel security scan on the project and reports findings so vulnerabilities are caught in the loop, not in production. ${SKILL_MARKER}.
---

# Sentinel Scan

Sentinel is a security scanner for AI-written code (Next.js + Supabase focus,
deterministic rule layer runs free with no account or API key). This skill
makes scanning part of the working loop.

## When to fire

- The user is about to push, open a PR, deploy, or asks "is this ready/secure?"
- You just wrote or edited: auth/session/payment logic, API routes, file
  uploads, CORS/CSP/security headers, env/secret handling, raw SQL, or
  dependency manifests.
- NOT for unrelated docs/copy edits. If the user includes "skip sentinel" in
  the prompt, skip for that request only.

## Protocol

**1. Scan.** From the project root:

\`\`\`bash
npx shipsafe-sentinel scan . --fail-on high
\`\`\`

Exit code 1 means findings at or above **high** exist. The terminal report
lists each finding with file, rule id, severity, and remediation.

**2. Low-noise mode (repos with a baseline).** If \`.sentinel/baseline.json\`
exists, compare instead of re-reporting known findings:

\`\`\`bash
npx shipsafe-sentinel scan . -f json -o .sentinel/current.json
npx shipsafe-sentinel diff .sentinel/baseline.json .sentinel/current.json --fail-on high
\`\`\`

Only NEW findings gate. Offer to refresh the baseline after findings are
fixed (\`mv .sentinel/current.json .sentinel/baseline.json\`).

**3. Report honestly.**

- Findings: list them by severity with file:line, say plainly whether you
  introduced any of them this session, and offer to fix the real ones now.
  Do not auto-fix without asking.
- Clean: say "Sentinel: no findings at high or above" — do NOT call the app
  "secure"; the rule layer checks known classes, not business logic.
- Scanner failed: show the error. Never report a failed scan as a pass.

**4. Fixes.** After the user approves fixing a finding, make the fix, then
re-run the scan to prove the finding is gone before calling it done.

---

**Bypass once:** include "skip sentinel" in your prompt.
**Uninstall:** \`rm -rf <this skill's directory>\`
**Reinstall / update:** \`npx shipsafe-sentinel init\` (or \`--project\` for the repo-local copy)

Do not edit by hand; re-running init refuses to overwrite unmanaged files.
`;

export type InitTarget = "user" | "project";

export type InitResult =
  | { ok: true; skillPath: string; replaced: boolean; target: InitTarget }
  | { ok: false; error: string };

export function userSkillsDir(): string {
  const override = process.env.SENTINEL_SKILLS_DIR?.trim();
  if (override && override.length > 0) return override;
  return join(homedir(), ".claude", "skills");
}

export function projectSkillsDir(projectRoot: string): string {
  return join(resolve(projectRoot), ".claude", "skills");
}

export function skillPathFor(target: InitTarget, projectRoot: string): string {
  const base = target === "project" ? projectSkillsDir(projectRoot) : userSkillsDir();
  return join(base, "sentinel-scan", "SKILL.md");
}

export function installSkill(target: InitTarget, projectRoot: string): InitResult {
  const path = skillPathFor(target, projectRoot);
  const dir = dirname(path);

  let replaced = false;
  if (existsSync(path)) {
    const existing = readFileSync(path, "utf-8");
    if (!existing.includes(SKILL_MARKER)) {
      return {
        ok: false,
        error:
          `existing file at ${path} was not placed by sentinel init. ` +
          `Move or remove it, then re-run.`,
      };
    }
    replaced = true;
  }

  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path, SKILL_BODY, { mode: 0o644 });
  } catch (e) {
    return { ok: false, error: `cannot write ${path}: ${(e as Error).message}` };
  }

  return { ok: true, skillPath: path, replaced, target };
}

export interface InitOptions {
  withClaudeCode?: boolean;
  project?: boolean;
  cwd?: string;
}

export async function runInit(options: InitOptions): Promise<number> {
  // v1 supports exactly one agent platform; the flag exists so the invocation
  // reads explicitly and future platforms slot in beside it.
  const target: InitTarget = options.project ? "project" : "user";
  const projectRoot = options.cwd ?? process.cwd();

  const result = installSkill(target, projectRoot);
  if (!result.ok) {
    process.stderr.write(`init failed: ${result.error}\n`);
    return 1;
  }

  const verb = result.replaced ? "Updated" : "Installed";
  const scopeLine =
    target === "project"
      ? "Repo-local install: commit .claude/skills/sentinel-scan/ and every\ncontributor's Claude Code picks it up."
      : "User-level install: applies to Claude Code sessions on this machine.\nTip: `sentinel init --project` installs into this repo instead, so the\nskill ships to your whole team when committed.";

  process.stdout.write(
    `${verb} the Sentinel scan skill for Claude Code:\n` +
      `  ${result.skillPath}\n\n` +
      `Claude Code will now run \`npx shipsafe-sentinel scan\` before pushes,\n` +
      `PRs, and deploys, and after security-sensitive edits.\n\n` +
      `${scopeLine}\n\n` +
      `Bypass once:  include "skip sentinel" in your prompt\n` +
      `Uninstall:    rm -rf ${dirname(result.skillPath)}\n`,
  );
  return 0;
}
