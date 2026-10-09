// Independent audit harness. No row bodies, committed writes, or builder edits.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { classifyRlsOff, loadExclusions } from '../../../scripts/rls-exclusions.mjs';
const base = 'docs/rls-signal-evidence/independent/run-20261007-cold-1318';
fs.mkdirSync(base, {recursive:true});
const save = (name, data) => fs.writeFileSync(`${base}/${name}.json`, JSON.stringify(data,null,2)+'\n');
const token = process.env.SUPABASE_ACCESS_TOKEN?.trim();
assert(token, 'token missing');
const realFetch = globalThis.fetch;
const sqlLog = [];
// The production scanner query is metadata only. Wrap every query for the audit.
globalThis.fetch = async (url, init={}) => {
  if(String(url).endsWith('/database/query')) {
    const body = JSON.parse(init.body);
    if(!/^BEGIN;/i.test(body.query.trim())) body.query = `BEGIN; ${body.query}; ROLLBACK;`;
    assert(/^BEGIN;[\s\S]*ROLLBACK;$/i.test(body.query.trim()));
    sqlLog.push({ref:String(url).split('/')[5], query:body.query, read_only:body.read_only});
    init = {...init, body:JSON.stringify(body)};
  }
  return realFetch(url, init);
};
process.argv = [process.argv[0], 'scripts/rls-scan.mjs', '--out', `${base}/scan`];
await import('../../../scripts/rls-scan.mjs');
save('scanner-sql-requests',sqlLog);
const scan = JSON.parse(fs.readFileSync(`${base}/scan.json`));
assert.equal(scan.projects.length,45);
assert.deepEqual(scan.summary,{open:0,excluded:3,errors:0});
const exclusions = loadExclusions();
const expected = exclusions.map(e=>`${e.ref}:${e.table}`).sort();
assert.equal(expected.length,3);
assert.deepEqual(scan.projects.flatMap(p=>p.rls_off.map(t=>`${p.ref}:${t.table}`)).sort(),expected);
for(const p of scan.projects) assert.deepEqual(p.tables.filter(t=>!t.rls).map(t=>t.table),p.rls_off.map(t=>t.table));
const residues=[];
for(const t of exclusions) {
  const metadata = `SELECT current_user, pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls, role, has_table_privilege(role,c.oid,'SELECT') AS can_select, has_table_privilege(role,c.oid,'INSERT') AS can_insert, has_table_privilege(role,c.oid,'UPDATE') AS can_update, has_table_privilege(role,c.oid,'DELETE') AS can_delete, has_table_privilege(role,c.oid,'TRUNCATE') AS can_truncate FROM pg_class c CROSS JOIN (VALUES ('anon'),('authenticated')) r(role) WHERE c.oid='public.${t.table}'::regclass ORDER BY role;`;
  async function query(inner, read_only=true) {
    const query = `BEGIN; ${inner} ROLLBACK;`;
    const res = await fetch(`https://api.supabase.com/v1/projects/${t.ref}/database/query`, {method:'POST',headers:{Authorization:`Bearer ${token}`,'content-type':'application/json'},body:JSON.stringify({query,read_only})});
    return {query,status:res.status,response:await res.json()};
  }
  const baseline = await query(metadata);
  assert.equal(baseline.response.length,2);
  let trial=null, owner_trial=null;
  if(t.table==='spatial_ref_sys') {
    trial=await query(`REVOKE INSERT, UPDATE, DELETE ON TABLE public.spatial_ref_sys FROM anon, authenticated; ${metadata}`,false);
    assert.equal(trial.response.length,2);
    assert(trial.response.every(r=>r.owner==='supabase_admin' && r.can_insert && r.can_update && r.can_delete && r.can_truncate));
    owner_trial=await query(`SET LOCAL ROLE supabase_admin; REVOKE INSERT, UPDATE, DELETE ON TABLE public.spatial_ref_sys FROM anon, authenticated; ${metadata}`,false);
    assert(owner_trial.status>=400);
    assert.match(JSON.stringify(owner_trial.response), /42501[\s\S]*permission denied to set role/);
  } else {
    assert(baseline.response.every(r=>r.can_select && !r.can_insert && !r.can_update && !r.can_delete && !r.can_truncate));
  }
  const readback=await query(metadata);
  assert.deepEqual(readback.response,baseline.response);
  residues.push({ref:t.ref,table:t.table,baseline,trial,owner_trial,readback});
  save('residue-rollback', {observed_at:new Date().toISOString(),results:residues});
}
const baseline=JSON.parse(fs.readFileSync('docs/rls-scan-2026-10-06-before.json'));
const baselineIds=baseline.projects.flatMap(p=>p.rls_off.map(t=>`${p.ref}:${t.table}`)).sort();
assert.equal(baseline.projects.length,45);
assert.equal(baseline.projects.filter(p=>p.rls_off.length).length,22);
assert.equal(baselineIds.length,112);
const targets=new Map();
for(const file of fs.readdirSync('docs/rls-lane-results').filter(f=>f.endsWith('.json'))) {
  const data=JSON.parse(fs.readFileSync(`docs/rls-lane-results/${file}`));
  for(const p of Array.isArray(data)?data:[data]) for(const t of p.tables??[]) if(t.status==='fixed') targets.set(`${p.ref}:${t.table}`,{ref:p.ref,table:t.table});
}
assert.equal(targets.size,109);
assert.deepEqual([...targets.keys(),...expected].sort(),baselineIds);
const builder=JSON.parse(fs.readFileSync('docs/rls-verify-2026-10-07-signal-closeout.json'));
assert.equal(builder.pass,109); assert.equal(builder.fail,0); assert.equal(builder.results.length,109);
assert.deepEqual(builder.results.map(t=>`${t.ref}:${t.table}`).sort(),[...targets.keys()].sort());
const safe=p=>[401,403,404].includes(p.status)||([200,206].includes(p.status)&&p.total===0);
assert(builder.results.every(r=>r.pass && r.probes.length>0 && r.probes.every(p=>safe(p)&&p.rows===0) && [200,206].includes(r.server_path?.status)));
save('baseline-builder-reconciliation',{baseline:112,affected:22,active:45,fixed:109,builder_verified_at:builder.verified_at,builder_actual_nonempty_safe:109,builder_server_success:109,exact_partition:true});
const fixedResults=[];
for(const ref of new Set([...targets.values()].map(t=>t.ref))) {
  const res=await fetch(`https://api.supabase.com/v1/projects/${ref}/api-keys?reveal=true`,{headers:{Authorization:`Bearer ${token}`}});
  assert(res.ok,'key metadata unavailable');
  const keys=await res.json();
  const anon=keys.filter(k=>k.name==='anon'||k.type==='publishable');
  const server=keys.filter(k=>k.name==='service_role'||k.type==='secret');
  assert(anon.length && server.length);
  async function head(table,k) {
    const r=await fetch(`https://${ref}.supabase.co/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,{method:'HEAD',headers:{apikey:k.api_key,Prefer:'count=exact',...(k.api_key.startsWith('sb_')?{}:{Authorization:`Bearer ${k.api_key}`})}});
    const range=r.headers.get('content-range');
    const value=range?.split('/')[1];
    await r.arrayBuffer();
    return {key:k.type==='publishable'?'publishable':k.name,status:r.status,total:value && value!=='*'?Number(value):null};
  }
  for(const t of [...targets.values()].filter(t=>t.ref===ref)) {
    const probes=await Promise.all(anon.map(k=>head(t.table,k)));
    let server_path=null;
    for(const k of server) {server_path=await head(t.table,k); if([200,206].includes(server_path.status)) break;}
    fixedResults.push({...t,probes,server_path,pass:probes.length>0&&probes.every(safe)&&[200,206].includes(server_path?.status)});
  }
  console.error(`independent HEAD fixed ${fixedResults.length}/109`);
  save('fixed-head',{observed_at:new Date().toISOString(),pass:fixedResults.filter(r=>r.pass).length,fail:fixedResults.filter(r=>!r.pass).length,results:fixedResults});
}
assert.equal(fixedResults.length,109); assert(fixedResults.every(r=>r.pass));
// Independent challenge of all four grant fields, project identity, unknown tables and collection errors.
const demo=scan.projects.find(p=>p.ref===exclusions[0].ref);
const copy=()=>structuredClone({projects:[demo]});
const challenges=[];
let c=copy(); c.projects[0].rls_off.push({...c.projects[0].rls_off[0],table:'independent_unknown'});
assert.equal(classifyRlsOff(c,exclusions).open.length,1); challenges.push('unknown table open');
for(const field of ['anon_write','auth_write','anon_truncate','auth_truncate']) {
  c=copy();c.projects[0].rls_off[0][field]=true;
  assert.equal(classifyRlsOff(c,exclusions).open.length,1);challenges.push(`${field} drift open`);
}
c=copy();c.projects[0].error='controlled independent collection error';
assert.equal(classifyRlsOff(c,exclusions).errors.length,1);challenges.push('collection error unresolved');
c=copy();c.projects[0].ref='independent-other-project';
assert.equal(classifyRlsOff(c,exclusions).open.length,1);challenges.push('same table other project open');
save('challenge-results',{challenges,passed:challenges.length});
save('all-sql-requests',sqlLog);
save('audit-result',{status:'passed',observed_at:new Date().toISOString(),active:45,rls_off:3,excluded:3,errors:0,open:0,fixed:109,head_pass:109});
console.error('independent live audit passed');
