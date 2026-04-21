# shipsafe-sentinel

Security assessment CLI for Next.js + Supabase codebases. The scanner behind [ShipSafe](https://shipsafe-web-eight.vercel.app) coaching.

```bash
npx shipsafe-sentinel scan .
```

Runs on your machine. No code leaves your box unless you `--format json` and pipe it somewhere yourself.

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

## How this fits with ShipSafe coaching

The scanner is free forever and works standalone. If you want a human to walk the findings with you — strip anything sensitive, prioritize what actually matters for your stack, teach you the pattern so it doesn't recur — that's [ShipSafe coaching](https://shipsafe-web-eight.vercel.app). Members-only, tied to the [Early AI-dopters](https://www.skool.com/earlyaidopters) community.

You don't need to enroll to use this tool. Scan your repo, fix what's critical, move on.

## Contributing

New rules live in `src/layers/rules/`. Each rule is a TypeScript module that exports a `Rule` object with `id`, `severity`, `detect(context)`, and `describe(finding)`. PRs welcome.

Reporting a false positive or a gap: open an issue with the file pattern and expected behavior.

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 Ty Wells / Frank Labs.
