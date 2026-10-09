import { readFileSync } from 'node:fs';
export function loadExclusions(path = 'docs/rls-exclusions.json') {
  const exclusions = JSON.parse(readFileSync(path, 'utf8'));
  const keys = new Set();
  if (!Array.isArray(exclusions)) throw new Error('RLS exclusions must be an array');
  for (const e of exclusions) {
    const key = `${e.ref}:${e.table}`;
    if (!e.ref || !e.table || !e.reason?.trim() || typeof e.expected_anon_write !== 'boolean' || keys.has(key)) throw new Error(`Invalid or duplicate RLS exclusion: ${key}`);
    keys.add(key);
  }
  return exclusions;
}
export function matchesExclusion(row, exclusion) {
  return ['anon_write', 'auth_write', 'anon_truncate', 'auth_truncate'].every(field =>
    exclusion[`expected_${field}`] === undefined || row[field] === exclusion[`expected_${field}`]);
}
export function classifyRlsOff(scan, exclusions) {
  const open = [], excluded = [], errors = [];
  for (const p of scan.projects) {
    if (p.error) errors.push({ref:p.ref, error:p.error});
    for (const t of p.rls_off) {
      const e = exclusions.find(e => e.ref === p.ref && e.table === t.table);
      const row = {ref:p.ref, project:p.name, ...t};
      if (e && matchesExclusion(t, e)) excluded.push({...row, exclusion:e});
      else open.push({...row, ...(e ? {exclusion_drift:'client write privileges differ from reviewed exclusion'} : {})});
    }
  }
  return {open, excluded, errors};
}
