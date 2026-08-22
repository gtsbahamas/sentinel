# shipsafe-sentinel

Security assessment CLI for Next.js + Supabase codebases. The scanner behind [Seatrial](https://seatrial.io) — the safety and trust layer for AI-built software and AI agents.

**Sentinel is a [Seatrial](https://seatrial.io) product.** The npm name stays `shipsafe-sentinel` for channel continuity.

```bash
npx shipsafe-sentinel scan .
```

Runs on your machine. No code leaves your box unless you `--format json` and pipe it somewhere yourself.

## Let your coding agent run it for you

```bash
npx shipsafe-sentinel init            # this machine (~/.claude/skills)
npx shipsafe-sentinel init --project  # this repo — commit it, whole team gets it
```

Installs a Claude Code skill so the agent runs a Sentinel scan before pushes,
PRs, and deploys, and after touching auth, API routes, uploads, headers, or
secrets — instead of only when a human remembers to. The `--project` install
lives in `.claude/skills/` and rides the repo to every contributor.

## What it catches

- Hardcoded secrets (OpenAI keys, Supabase service roles, JWT secrets, generic AWS/GCP credentials)
- Missing auth on API routes (Next.js `app/api/**`)
- Unvalidated request bodies (missing Zod `.parse()` on POST/PUT handlers)
- Row Level Security misuse (service role leaks, USING without WITH CHECK, unprotected tables)
- CSP / CORS / HTTPS misconfiguration in `next.config.*`
- Prompt injection surface area (user input concatenated into model prompts)
- Unbounded database reads (missing `.limit()`, `.range()`)
- Plain-text credential comparison (timing-attack-prone `===` / `!==`)

Full rule catalog: `shipsafe-sentinel scan --list-rules`.

## Output

```
[CRITICAL] app/api/generate-caption/route.ts:14
  OpenAI API key hardcoded in client-rendered route (SECRETS-001)
  Fix: move to process.env.OPENAI_API_KEY, rotate the current key.

  → ShipSafe Week 2 walks this end-to-end:
    https://shipsafe-web-eight.vercel.app/dashboard/coaching/week/2

[LOW] src/layout.tsx:8
  No error boundary in root layout
```

Critical and High findings link to the matching week of the 12-week coaching curriculum. Medium/Low/Info stay quiet — no link spam.

## Install

```bash
# Run without installing
npx shipsafe-sentinel scan .

# Or install globally
npm i -g shipsafe-sentinel
shipsafe-sentinel scan .
```

Requires Node 20+.

## Config

Optional `.sentinelrc.json` in your repo root:

```json
{
  "ignore": ["test/", "scripts/", "supabase/migrations/"],
  "failOn": "high",
  "ai": {
    "enabled": true,
    "provider": "anthropic"
  }
}
```

AI-layer checks require `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in env. The deterministic rule layer runs without any API key.

## Formats

```bash
shipsafe-sentinel scan . --format terminal   # default, colored
shipsafe-sentinel scan . --format json       # CI-friendly
shipsafe-sentinel scan . --format html       # static report
```

Exit codes: `0` = no findings at or above `failOn`, `1` = findings present, `2` = scanner error.

## Use as an MCP server

Sentinel can run as a [Model Context Protocol](https://modelcontextprotocol.io) server so an AI agent (Claude Code, Cursor, VS Code) can invoke the scanner as a tool. At-keystroke security feedback while you code.

Add this to your project's `.mcp.json` for Claude Code:

```json
{
  "mcpServers": {
    "shipsafe-sentinel": {
      "command": "npx",
      "args": ["shipsafe-sentinel", "mcp"]
    }
  }
}
```

The agent then has a `scan_project` tool that returns the same JSON report `sentinel scan --format json` produces.

Cursor and VS Code both support MCP servers as well; see the [Cursor MCP docs](https://docs.cursor.com/context/model-context-protocol) and the [VS Code MCP extension](https://marketplace.visualstudio.com/search?term=mcp) for setup.

## Auth pattern inference

Sentinel reads your codebase, infers the dominant auth helper per route group, and flags new code that deviates. This catches the specific failure mode of AI-generated routes silently skipping the project's established auth pattern.

```bash
shipsafe-sentinel patterns .             # show what was inferred
shipsafe-sentinel patterns . --init      # write to .sentinelrc.json
```

After `--init`, deviations get flagged as CONVENTION-001 (precise) instead of PATTERN-001 (heuristic).

## How this fits with ShipSafe coaching

The scanner is free forever and works standalone. If you want a human to walk the findings with you — strip anything sensitive, prioritize what actually matters for your stack, teach you the pattern so it doesn't recur — that's [ShipSafe coaching](https://shipsafe-web-eight.vercel.app). Members-only, tied to the [Early AI-dopters](https://www.skool.com/earlyaidopters) community.

You don't need to enroll to use this tool. Scan your repo, fix what's critical, move on.

## CI integration

A reusable GitHub Action ships with this repo so any project can wire shipsafe-sentinel into pull requests in under a minute. Drop it in your workflow, set `fail-on: critical`, and the build fails the moment a critical finding lands on a PR.

```yaml
- name: ShipSafe Sentinel scan
  uses: gtsbahamas/sentinel/.github/actions/scan@master
  with:
    path: "."
    fail-on: "critical"
```

`fail-on: critical` is the recommended default for CI gates. It blocks the obvious foot-guns (hardcoded secrets, missing auth, RLS leaks) without drowning the build in lower-severity noise. Tighten to `high` once your team is keeping critical at zero.

Full input reference: [`.github/actions/scan/action.yml`](./.github/actions/scan/action.yml).

## Contributing

New rules live in `src/layers/rules/`. Each rule is a TypeScript module that exports a `Rule` object with `id`, `severity`, `detect(context)`, and `describe(finding)`. PRs welcome.

Reporting a false positive or a gap: open an issue with the file pattern and expected behavior.

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 Ty Wells / Frank Labs.
