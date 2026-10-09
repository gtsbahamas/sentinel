import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {classifyRlsOff,loadExclusions} from '../../../scripts/rls-exclusions.mjs';
const root='docs/rls-signal-evidence/independent';
const read=f=>JSON.parse(fs.readFileSync(f));
const save=(f,x)=>fs.writeFileSync(`${root}/${f}.json`,JSON.stringify(x,null,2)+'\n');
const baseline=read('docs/rls-scan-2026-10-06-before.json');
const exclusions=loadExclusions();
const builderScan=read('docs/rls-scan-2026-10-07-signal-closeout.json');
const builder=read('docs/rls-verify-2026-10-07-signal-closeout.json');
const ids=s=>s.projects.flatMap(p=>p.rls_off.map(t=>`${p.ref}:${t.table}`)).sort();
const targets=new Set();
for(const f of fs.readdirSync('docs/rls-lane-results').filter(f=>f.endsWith('.json'))) {
 const data=read(`docs/rls-lane-results/${f}`);
 for(const p of Array.isArray(data)?data:[data]) for(const t of p.tables??[]) if(t.status==='fixed') targets.add(`${p.ref}:${t.table}`);
}
assert.equal(baseline.projects.length,45);assert.equal(baseline.projects.filter(p=>p.rls_off.length).length,22);assert.equal(ids(baseline).length,112);
assert.equal(targets.size,109);assert.deepEqual([...targets,...exclusions.map(e=>`${e.ref}:${e.table}`)].sort(),ids(baseline));
const classified=classifyRlsOff(builderScan,exclusions);
assert.equal(builderScan.projects.length,45);assert.equal(classified.open.length,0);assert.equal(classified.errors.length,0);assert.equal(classified.excluded.length,3);
for(const p of builderScan.projects) assert.deepEqual(p.tables.filter(t=>!t.rls).map(t=>t.table),p.rls_off.map(t=>t.table));
assert.equal(builder.pass,109);assert.equal(builder.fail,0);assert.equal(builder.results.length,109);
assert.deepEqual(builder.results.map(t=>`${t.ref}:${t.table}`).sort(),[...targets].sort());
const safe=p=>[401,403,404].includes(p.status)||([200,206].includes(p.status)&&p.rows===0&&p.total===0);
assert(builder.results.every(r=>r.pass&&r.probes.length>0&&r.probes.every(safe)&&[200,206].includes(r.server_path?.status)));
const saved=read('docs/rls-signal-evidence/residue-probes.json');
assert.equal(saved.results.length,3);
for(const r of saved.results) {
 assert(/^BEGIN;[\s\S]*ROLLBACK;$/i.test(r.baseline_query));
 assert.deepEqual(r.baseline.response,r.readback.response);
 if(r.table==='spatial_ref_sys') {
  assert.equal(r.trial_query,`BEGIN; REVOKE INSERT, UPDATE, DELETE ON TABLE public.spatial_ref_sys FROM anon, authenticated; ${r.baseline_query.slice(7,-10)} ROLLBACK;`);
  assert.equal(r.trial.status,201);assert(r.trial.response.every(x=>x.owner==='supabase_admin'&&x.can_insert&&x.can_update&&x.can_delete&&x.can_truncate));
  assert.equal(r.owner_role_trial.status,400);assert.match(JSON.stringify(r.owner_role_trial.response),/42501[\s\S]*permission denied to set role/);
 } else assert(r.baseline.response.every(x=>x.can_select&&!x.can_insert&&!x.can_update&&!x.can_delete&&!x.can_truncate));
}
save('static-observations',{revision:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),observed_at:new Date().toISOString(),baseline:{active:45,affected:22,rls_off:112},exact_fixed_partition:109,builder_scan:{scanned_at:builderScan.scanned_at,active:45,excluded:3,open:0,errors:0},builder_verify:{verified_at:builder.verified_at,pass:109,fail:0,actual_nonempty_safe_probes:109,server_paths_available:109,probe_count:builder.results.reduce((n,r)=>n+r.probes.length,0)},builder_residue_saved_evidence_valid:true,live_independent_confirmation:'blocked: worker unreachable'});
// Independent fixture, including collection error and deliberately stale lane states.
const fixture=`${root}/report-fixture`;fs.mkdirSync(`${fixture}/docs/rls-lane-results`,{recursive:true});
const row=(table,anon_write=false)=>({table,rls:false,anon_write,auth_write:false,anon_truncate:false,auth_truncate:false,sensitive_columns:[],anon_probe:{status:206,total:3}});
const scan={scanned_at:'2026-10-07T19:00:00Z',projects:[{ref:'independent-fixture',name:'Fixture',tables:[],rls_off:[row('catalog'),row('unknown'),row('drift',true)]},{ref:'error-fixture',name:'Error',error:'controlled fixture collection error',tables:[],rls_off:[]}]};
const ex=['catalog','drift'].map(table=>({ref:'independent-fixture',table,reason:'Independent fixture reviewed read-only catalog',expected_anon_write:false,expected_auth_write:false,expected_anon_truncate:false,expected_auth_truncate:false}));
for(const n of ['before','after'])fs.writeFileSync(`${fixture}/${n}.json`,JSON.stringify(scan));
fs.writeFileSync(`${fixture}/docs/rls-exclusions.json`,JSON.stringify(ex));
fs.writeFileSync(`${fixture}/docs/rls-lane-results/stale.json`,JSON.stringify({ref:'independent-fixture',tables:scan.projects[0].rls_off.map(r=>({table:r.table,status:'excluded'}))}));
const script=fs.realpathSync('scripts/rls-report.mjs');
execFileSync(process.execPath,[script,'--before','before.json','--after','after.json','--out','report.md'],{cwd:fixture});
const report=fs.readFileSync(`${fixture}/report.md`,'utf8');
assert.match(report,/Current open findings: 2\. Reviewed exclusions: 1\. Scan errors: 1\./);
const open=report.split('## Open findings')[1].split('## Reviewed exclusions')[0];
assert.match(open,/public.unknown/);assert.match(open,/public.drift/);assert(!open.includes('public.catalog'));
assert.match(report.split('## Reviewed exclusions')[1],/public.catalog/);
const challengeResults=[];
for(const field of ['anon_write','auth_write','anon_truncate','auth_truncate']){
 const t=row('catalog');t[field]=true;
 assert.equal(classifyRlsOff({projects:[{ref:'independent-fixture',name:'Fixture',rls_off:[t]}]},ex).open.length,1);
 challengeResults.push(`${field}: reopened`);
}
assert.equal(classifyRlsOff({projects:[{ref:'other-project',name:'Other',rls_off:[row('catalog')]}]},ex).open.length,1);
save('independent-fixture-results',{passed:true,grant_challenges:challengeResults,unknown_table_open:true,other_project_open:true,collection_error_unresolved:true,report_separation:true,stale_lane_does_not_override:true});
console.log('Static evidence reconciliation and independent fixture challenges passed. Live audit blocked.');
