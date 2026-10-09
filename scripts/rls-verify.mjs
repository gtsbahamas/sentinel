#!/usr/bin/env node
// Re-probes every table the lanes marked fixed, with every anon-role key the project
// has (legacy anon JWT and publishable keys), and records what an anonymous caller gets.
//
//   SUPABASE_ACCESS_TOKEN=... node scripts/rls-verify.mjs [--out docs/rls-verify-2026-10-06.json]
//
// Pass = every key gets 401/403/404, or 200/206 with a total of 0. Read-only.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN?.trim();
if (!TOKEN) {
  console.error('SUPABASE_ACCESS_TOKEN is not set');
  process.exit(2);
}
const args = process.argv.slice(2);
const out = args.includes('--out') ? args[args.indexOf('--out') + 1] : 'docs/rls-verify-2026-10-06.json';
const dir = 'docs/rls-lane-results';

async function retry(fn) {
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i >= 4) throw e;
      await new Promise((r) => setTimeout(r, 3000 * (i + 1)));
    }
  }
}

const targets = new Map();
for (const f of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
  const v = JSON.parse(readFileSync(`${dir}/${f}`, 'utf8'));
  for (const p of Array.isArray(v) ? v : [v]) {
    const fixed = (p.tables ?? []).filter((t) => t.status === 'fixed').map((t) => t.table);
    if (fixed.length) targets.set(p.ref, { name: p.project, tables: fixed });
  }
}

const results = [];
let pass = 0, fail = 0;
for (const [ref, { name, tables }] of targets) {
  const keys = await retry(async () => {
    const res = await fetch(`https://api.supabase.com/v1/projects/${ref}/api-keys?reveal=true`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    return await res.json();
  });
  const anonKeys = keys.filter((k) => k.name === 'anon' || k.type === 'publishable');
  // The server-side path: legacy service_role JWT, or a secret key where legacy keys are off.
  const serverKeys = keys.filter((k) => k.name === 'service_role' || k.type === 'secret');
  for (const table of tables) {
    const probes = [];
    for (const k of anonKeys) {
      const r = await retry(async () => {
        const res = await fetch(`https://${ref}.supabase.co/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
          headers: {
            apikey: k.api_key,
            Prefer: 'count=exact',
            ...(k.api_key.startsWith('sb_') ? {} : { Authorization: `Bearer ${k.api_key}` }),
          },
        });
        const range = res.headers.get('content-range') ?? '';
        const body = await res.text();
        const total = Number(range.split('/')[1]);
        return { key: k.type === 'publishable' ? 'publishable' : 'legacy-anon', status: res.status, total: Number.isFinite(total) ? total : null, rows: res.ok ? JSON.parse(body || '[]').length : 0 };
      });
      probes.push(r);
    }
    let server = null;
    for (const k of serverKeys) {
      server = await retry(async () => {
        const res = await fetch(`https://${ref}.supabase.co/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
          method: 'HEAD',
          headers: { apikey: k.api_key, Prefer: 'count=exact', ...(k.api_key.startsWith('sb_') ? {} : { Authorization: `Bearer ${k.api_key}` }) },
        });
        const total = Number((res.headers.get('content-range') ?? '').split('/')[1]);
        return { status: res.status, total: Number.isFinite(total) ? total : null };
      });
      if (server.status === 200 || server.status === 206) break;
    }
    const ok = probes.every((p) => [401, 403, 404].includes(p.status) || ((p.status === 200 || p.status === 206) && p.rows === 0 && (p.total ?? 0) === 0));
    ok ? pass++ : fail++;
    const serverOk = server && (server.status === 200 || server.status === 206);
    if (!serverOk) console.error(`SERVER-PATH ${name} ${table} ${JSON.stringify(server)}`);
    results.push({ project: name, ref, table, pass: ok, probes, server_path: server });
    if (!ok) console.error(`FAIL ${name} ${table} ${JSON.stringify(probes)}`);
  }
}
writeFileSync(out, JSON.stringify({ verified_at: new Date().toISOString(), pass, fail, results }, null, 2));
console.error(`anon lock-out: ${pass} pass, ${fail} fail across ${results.length} fixed tables -> ${out}`);
process.exit(fail ? 1 : 0);
