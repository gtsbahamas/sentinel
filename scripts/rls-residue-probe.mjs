// Metadata-only probes; every IslandFlow/MGO SQL request is rolled back.
import { writeFileSync } from 'node:fs';
const token = process.env.SUPABASE_ACCESS_TOKEN;
if (!token) throw new Error('SUPABASE_ACCESS_TOKEN required');
const targets = [
  {ref:'eiqntvlwhfgvnqjdyuip', project:'e2e-test-app', table:'shipsafe_demo_customers'},
  {ref:'tyqxwawlgdhcpisyqyfd', project:'IslandFlow', table:'spatial_ref_sys'},
  {ref:'qfxgiyeufgjsovxupfej', project:'MGO Management Dashboard', table:'spatial_ref_sys'},
];
const results = [];
for (const t of targets) {
  const metadata = `SELECT current_user, pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls, role, has_table_privilege(role,c.oid,'SELECT') AS can_select, has_table_privilege(role,c.oid,'INSERT') AS can_insert, has_table_privilege(role,c.oid,'UPDATE') AS can_update, has_table_privilege(role,c.oid,'DELETE') AS can_delete, has_table_privilege(role,c.oid,'TRUNCATE') AS can_truncate FROM pg_class c CROSS JOIN (VALUES ('anon'),('authenticated')) r(role) WHERE c.oid='public.${t.table}'::regclass;`;
  async function query(query) {
    const r = await fetch(`https://api.supabase.com/v1/projects/${t.ref}/database/query`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({query,read_only:false})});
    return {status:r.status, response:await r.json()};
  }
  const baselineQuery = `BEGIN; ${metadata} ROLLBACK;`;
  const baseline = await query(baselineQuery);
  const revokeQuery = `BEGIN; REVOKE INSERT, UPDATE, DELETE ON TABLE public.${t.table} FROM anon, authenticated; ${metadata} ROLLBACK;`;
  const trial = t.table === 'spatial_ref_sys' ? await query(revokeQuery) : null;
  // No mutation is applied unless the rollback trial proves all writes removed.
  const proved = trial?.status>=200 && trial?.status<300 && Array.isArray(trial.response) && trial.response.length===2 && trial.response.every(r=>!r.can_insert&&!r.can_update&&!r.can_delete);
  let applied = null;
  if(proved) throw new Error('Revoke proved effective: preserve trial evidence and apply reviewed migration separately');
  const ownerRoleQuery = `BEGIN; SET LOCAL ROLE supabase_admin; REVOKE INSERT, UPDATE, DELETE ON TABLE public.${t.table} FROM anon, authenticated; ${metadata} ROLLBACK;`;
  const owner_role_trial = trial ? await query(ownerRoleQuery) : null;
  const readback = await query(baselineQuery);
  results.push({...t,baseline_query:baselineQuery,baseline,trial_query:trial?revokeQuery:null,trial,owner_role_query:trial?ownerRoleQuery:null,owner_role_trial,applied,readback,decision:trial?'Excluded: rollback revoke did not remove all write privileges; no live mutation applied.':'Excluded: intentional readable demo; confirm writes revoked.'});
  console.error(t.project,JSON.stringify({baseline,trial,readback}));
}
writeFileSync('docs/rls-signal-evidence/residue-probes.json',JSON.stringify({observed_at:new Date().toISOString(),results},null,2)+'\n');
