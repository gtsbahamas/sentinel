#!/usr/bin/env node
// Builds docs/rls-remediation-<date>.md from the baseline scan, the lane results
// (docs/rls-lane-results/*.json, one object or array of objects per file, shaped as in
// docs/rls-lockdown-contract.md) and, when present, the after-scan.
//
//   node scripts/rls-report.mjs --before docs/rls-scan-2026-10-06-before.json \
//     [--after docs/rls-scan-2026-10-06-after.json] --out docs/rls-remediation-2026-10-06.md
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';

import { loadExclusions, classifyRlsOff, matchesExclusion } from './rls-exclusions.mjs';

const args = process.argv.slice(2);
const arg = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : undefined);
const exclusions = loadExclusions(arg('--exclusions'));
const before = JSON.parse(readFileSync(arg('--before'), 'utf8'));
const after = arg('--after') && existsSync(arg('--after')) ? JSON.parse(readFileSync(arg('--after'), 'utf8')) : null;
const out = arg('--out');
const lanesDir = 'docs/rls-lane-results';

const lanes = new Map();
if (existsSync(lanesDir)) {
  for (const f of readdirSync(lanesDir).filter((f) => f.endsWith('.json'))) {
    const v = JSON.parse(readFileSync(`${lanesDir}/${f}`, 'utf8'));
    for (const p of Array.isArray(v) ? v : [v]) lanes.set(p.ref, p);
  }
}
const afterOff = new Map();
for (const p of after?.projects ?? []) afterOff.set(p.ref, new Map(p.rls_off.map((t) => [t.table, t])));

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const rows = [];
let fixed = 0, excluded = 0, open = 0;
for (const p of before.projects) {
  const lane = lanes.get(p.ref);
  for (const t of p.rls_off) {
    const l = lane?.tables?.find((x) => x.table === t.table);
    const stillOff = after ? afterOff.get(p.ref)?.has(t.table) : null;
    const exclusion = exclusions.find(e => e.ref === p.ref && e.table === t.table);
    const current = afterOff.get(p.ref)?.get(t.table) ?? t;
    let status = l?.status === 'excluded' ? 'open' : l?.status ?? 'open';
    if (exclusion && matchesExclusion(current, exclusion) && (!after || stillOff)) status = 'excluded';
    if (status === 'fixed' && stillOff) status = 'open (after-scan still shows RLS off)';
    if (status === 'fixed') fixed++; else if (status === 'excluded') excluded++; else open++;
    const sensitive = l?.sensitive ?? t.sensitive_columns.length > 0;
    rows.push(
      `| ${esc(p.name)} | ${esc(t.table)} | ${sensitive ? 'yes' : 'no'} | ${t.anon_probe?.status ?? '-'} / ${t.anon_probe?.total ?? '-'} | ${esc(l?.access ?? '-')} | ${esc(l?.action ?? '-')} | ${esc(l?.migration ?? lane?.migration ? `${lane.repo}/${l?.migration ?? lane.migration}${lane.commit ? ` @${String(lane.commit).slice(0, 8)}` : ''}` : '-')} | ${esc(l?.anon_after ?? '-')} | ${esc(l?.app_path_after ?? '-')} | ${esc(status)}${(status === 'excluded' ? exclusion?.reason : l?.reason) ? ': ' + esc(status === 'excluded' ? exclusion.reason : l.reason) : ''} |`,
    );
  }
}

const classification = after ? classifyRlsOff(after, exclusions) : classifyRlsOff(before, exclusions);
const total = rows.length;
const md = [
  `# RLS remediation — ${before.scanned_at.slice(0, 10)}`,
  '',
  `Baseline: live scan of every ACTIVE_HEALTHY Supabase project the account can see (${before.projects.length} projects) by \`scripts/rls-scan.mjs\`, at ${before.scanned_at}. Raw: \`docs/rls-scan-2026-10-06-before.json\`.`,
  after ? `After-scan: ${after.scanned_at}, \`${arg("--after")}\`.` : 'After-scan: not yet run.',
  '',
  `**Totals:** ${total} public tables with RLS off at baseline, across ${before.projects.filter((p) => p.rls_off.length).length} projects. fixed ${fixed}, excluded ${excluded}, open ${open}.`,
  '',
  `Current open findings: ${classification.open.length}. Reviewed exclusions: ${classification.excluded.length}. Scan errors: ${classification.errors.length}.`,
  '',
  '## Open findings',
  ...classification.open.map(t => `- ${t.project} (${t.ref}) public.${t.table}`),
  ...(classification.open.length ? [] : ['None.']),
  '',
  '## Reviewed exclusions',
  ...classification.excluded.map(t => `- ${t.project} (${t.ref}) public.${t.table}: ${t.exclusion.reason}`),
  '',
  'Columns: *anon before* is HTTP status / row count from a real anon-key REST read at baseline (200 with 0 = readable but empty). *anon after* and *app path after* are the lane proofs recorded after the migration was applied.',
  '',
  '| project | table | sensitive | anon before | access path found | action taken | migration | anon after | app path after | status |',
  '|---|---|---|---|---|---|---|---|---|---|',
  ...rows,
  '',
];
const extra = arg('--append');
if (extra && existsSync(extra)) md.push(readFileSync(extra, 'utf8'));
writeFileSync(out, md.join('\n'));
console.error(`wrote ${out}: ${total} tables, fixed ${fixed}, excluded ${excluded}, open ${open}`);
