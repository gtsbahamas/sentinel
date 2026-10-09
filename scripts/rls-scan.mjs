#!/usr/bin/env node
// Live RLS exposure scan across every Supabase project the access token can see.
//
//   SUPABASE_ACCESS_TOKEN=... node scripts/rls-scan.mjs [--out docs/rls-scan-YYYY-MM-DD] [--project <ref>...]
//
// For each ACTIVE_HEALTHY project it reads pg_class.relrowsecurity and the anon /
// authenticated grants on every public-schema table, and then probes each RLS-off
// table over the public REST API with the project's own anon key (HEAD + count),
// so "exposed" means a real anon-key read succeeded, not just a grant on paper.
// Writes <out>.json (raw) and <out>.md (summary). Read-only: it never changes data.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { loadExclusions, classifyRlsOff } from './rls-exclusions.mjs';
const exclusions = loadExclusions();

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN?.trim();
if (!TOKEN) {
  console.error('SUPABASE_ACCESS_TOKEN is not set');
  process.exit(2);
}
const API = 'https://api.supabase.com/v1';
const args = process.argv.slice(2);
const today = new Date().toISOString().slice(0, 10);
const outIdx = args.indexOf('--out');
const out = outIdx >= 0 ? args[outIdx + 1] : `docs/rls-scan-${today}`;
const only = args.flatMap((a, i) => (args[i - 1] === '--project' ? [a] : []));

const SENSITIVE = /(email|phone|password|passwd|secret|token|api_?key|ssn|dob|birth|address|salary|wage|payment|card|iban|account_?number|bank|balance|amount|price|invoice|credential|session|otp|pin\b|name|first_name|last_name|ip_address|lat|lng|location|medical|health|note|message|body|content)/i;

async function api(path, init = {}) {
  for (let attempt = 0; attempt < 5; attempt++) {
    let res;
    try {
      res = await fetch(`${API}${path}`, {
        ...init,
        headers: { Authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', ...init.headers },
      });
    } catch (e) {
      if (attempt === 4) throw e;
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)));
      continue;
    }
    if (res.status === 429 || res.status >= 500) {
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
      continue;
    }
    const text = await res.text();
    if (!res.ok) throw new Error(`${res.status} ${path}: ${text.slice(0, 200)}`);
    return text ? JSON.parse(text) : null;
  }
  throw new Error(`rate limited: ${path}`);
}

const SQL = `
select c.relname as table,
       c.relrowsecurity as rls,
       c.relforcerowsecurity as force_rls,
       greatest(c.reltuples, 0)::bigint as est_rows,
       has_table_privilege('anon', c.oid, 'SELECT') as anon_select,
       has_table_privilege('anon', c.oid, 'INSERT') or has_table_privilege('anon', c.oid, 'UPDATE')
         or has_table_privilege('anon', c.oid, 'DELETE') as anon_write,
       has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select,
       has_table_privilege('authenticated', c.oid, 'INSERT') or has_table_privilege('authenticated', c.oid, 'UPDATE')
         or has_table_privilege('authenticated', c.oid, 'DELETE') as auth_write,
       has_table_privilege('anon', c.oid, 'TRUNCATE') as anon_truncate,
       has_table_privilege('authenticated', c.oid, 'TRUNCATE') as auth_truncate,
       (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname)::int as policies,
       (select string_agg(a.attname, ',' order by a.attnum) from pg_attribute a
          where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped) as columns
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r', 'p')
order by c.relname`;

// Every key that maps to the anon role: the legacy anon JWT and any publishable
// key. Projects that disabled legacy keys answer 401 to the anon JWT while the
// publishable key still reads, so probing only one of them under-reports.
async function anonKeys(ref) {
  const keys = await api(`/projects/${ref}/api-keys?reveal=true`);
  return keys.filter((x) => x.name === 'anon' || x.type === 'publishable').map((x) => x.api_key).filter(Boolean);
}

async function probe(ref, key, table) {
  try {
    const res = await fetch(`https://${ref}.supabase.co/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, {
      method: 'HEAD',
      headers: { apikey: key, Prefer: 'count=exact', ...(key.startsWith('sb_') ? {} : { Authorization: `Bearer ${key}` }) },
    });
    const range = res.headers.get('content-range') ?? '';
    await res.arrayBuffer();
    const total = Number(range.split('/')[1]);
    return { status: res.status, total: Number.isFinite(total) ? total : null };
  } catch (e) {
    return { status: 0, error: String(e) };
  }
}

const projects = (await api('/projects')).filter(
  (p) => p.status === 'ACTIVE_HEALTHY' && (only.length === 0 || only.includes(p.id)),
);
const result = { scanned_at: new Date().toISOString(), projects: [] };

for (const p of projects) {
  const entry = { ref: p.id, name: p.name, org: p.organization_id, tables: [], rls_off: [] };
  try {
    const rows = await api(`/projects/${p.id}/database/query`, {
      method: 'POST',
      body: JSON.stringify({ query: SQL, read_only: true }),
    });
    entry.tables = rows;
    const off = rows.filter((r) => !r.rls);
    if (off.length) {
      const keys = await anonKeys(p.id).catch(() => []);
      for (const t of off) {
        const cols = (t.columns ?? '').split(',');
        const sensitiveCols = cols.filter((c) => SENSITIVE.test(c));
        let probeRes = { status: null, error: 'no anon key' };
        for (const key of keys) {
          probeRes = await probe(p.id, key, t.table);
          if (probeRes.status === 200 || probeRes.status === 206) break;
        }
        entry.rls_off.push({
          table: t.table,
          est_rows: Number(t.est_rows),
          anon_select: t.anon_select,
          anon_write: t.anon_write,
          auth_select: t.auth_select,
          auth_write: t.auth_write,
          anon_truncate: t.anon_truncate,
          auth_truncate: t.auth_truncate,
          policies: t.policies,
          sensitive_columns: sensitiveCols,
          anon_probe: probeRes,
        });
      }
    }
  } catch (e) {
    entry.error = String(e.message ?? e);
  }
  result.projects.push(entry);
  console.error(`${p.name.padEnd(36)} tables=${entry.tables.length} rls_off=${entry.rls_off.length}${entry.error ? ' ERROR ' + entry.error : ''}`);
}

const classification = classifyRlsOff(result, exclusions);
result.summary = { open: classification.open.length, excluded: classification.excluded.length, errors: classification.errors.length };
for (const p of result.projects) for (const t of p.rls_off) {
  const excluded = classification.excluded.find(e => e.ref === p.ref && e.table === t.table);
  t.status = excluded ? 'excluded' : 'open';
  if (excluded) t.exclusion_reason = excluded.exclusion.reason;
}
mkdirSync(dirname(out), { recursive: true });
writeFileSync(`${out}.json`, JSON.stringify(result, null, 2));

const exposed = (t) => t.anon_probe?.status === 200 || t.anon_probe?.status === 206;
const lines = [
  `# RLS scan ${result.scanned_at}`,
  '',
  `Projects scanned: ${result.projects.length}. Public tables with RLS off: ${result.projects.reduce((n, p) => n + p.rls_off.length, 0)}. Of those, readable with the anon key right now: ${result.projects.reduce((n, p) => n + p.rls_off.filter(exposed).length, 0)}.`,
  '',
  `Open findings: ${result.summary.open}. Reviewed exclusions: ${result.summary.excluded}. Scan errors: ${result.summary.errors}.`,
  '',
  '| project | ref | table | anon read (HTTP / rows) | anon write grant | sensitive columns | status / reason |',
  '|---|---|---|---|---|---|---|',
];
for (const p of result.projects) {
  if (p.error) lines.push(`| ${p.name} | ${p.ref} | (scan error: ${p.error.slice(0, 80)}) | | | |`);
  for (const t of p.rls_off) {
    lines.push(
      `| ${p.name} | ${p.ref} | ${t.table} | ${t.anon_probe?.status ?? '-'} / ${t.anon_probe?.total ?? '-'} | ${t.anon_write ? 'yes' : 'no'} | ${t.sensitive_columns.join(' ') || '-'} | ${t.status}${t.exclusion_reason ? ': ' + t.exclusion_reason : ''} |`,
    );
  }
}
writeFileSync(`${out}.md`, lines.join('\n') + '\n');
console.error(`wrote ${out}.json and ${out}.md`);

process.exitCode = result.summary.open || result.summary.errors ? 1 : 0;
