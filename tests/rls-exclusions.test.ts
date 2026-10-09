import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
// @ts-expect-error Standalone scripts intentionally have no TS build dependency.
import { classifyRlsOff, loadExclusions } from '../scripts/rls-exclusions.mjs';

const repo = path.resolve('.');
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

type Table = { table: string; rls?: boolean; anon_write: boolean };
type Scan = {
  scanned_at: string;
  projects: { ref: string; name: string; tables: Table[]; rls_off: Table[]; error?: string }[];
};

function latestCommittedScan(): { file: string; scan: Scan } {
  // Read git objects, not working-tree files: staged/untracked probes are not committed proof.
  const files = execFileSync('git', ['ls-tree', '-r', '--name-only', 'HEAD', '--', 'docs'], { cwd: repo, encoding: 'utf8' })
    .trim().split('\n').filter((file) => /^docs\/rls-scan-\d{4}-\d{2}-\d{2}(?:-[^/]+)?\.json$/.test(file));
  expect(files.length, 'There must be a committed live scan').toBeGreaterThan(0);
  const candidates = files.map((file) => {
    const scan = JSON.parse(execFileSync('git', ['show', `HEAD:${file}`], { cwd: repo, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })) as Scan;
    expect(Number.isFinite(Date.parse(scan.scanned_at)), `${file} must have a valid collection timestamp`).toBe(true);
    return { file, scan, date: file.match(/\d{4}-\d{2}-\d{2}/)![0] };
  });
  // A same-day '-signal-closeout' suffix sorts before '.json'; collection time resolves that tie.
  candidates.sort((a, b) => a.date.localeCompare(b.date) || Date.parse(a.scan.scanned_at) - Date.parse(b.scan.scanned_at) || a.file.localeCompare(b.file));
  return candidates[candidates.length - 1];
}

const fixtureRow = (table: string, anon_write = false) => ({
  table, rls: false, anon_write, anon_select: true, auth_select: true,
  est_rows: 3, policies: 0, sensitive_columns: [], anon_probe: { status: 206, total: 3 },
});
const fixtureScan = (rows: ReturnType<typeof fixtureRow>[]): Scan => ({
  scanned_at: '2026-10-07T20:00:00.000Z',
  projects: [{ ref: 'fixture-project', name: 'Fixture', tables: rows, rls_off: rows }],
});
const fixtureExclusion = { ref: 'fixture-project', table: 'catalog', reason: 'Read-only public catalog', expected_anon_write: false };

describe('RLS residual exclusion coverage', () => {
  it('covers every public RLS-off table in the latest committed scan with no collection errors', () => {
    const { file, scan } = latestCommittedScan();
    const exclusions = loadExclusions(path.join(repo, 'docs/rls-exclusions.json'));
    expect(scan.projects.length, `${file} cannot be an empty scan`).toBeGreaterThan(0);
    for (const project of scan.projects) {
      expect(project.error, `${file}: ${project.name} must have collected successfully`).toBeUndefined();
      expect(project.rls_off.map((row) => row.table).sort(), `${file}: ${project.name} must list all public RLS-off tables`)
        .toEqual(project.tables.filter((row) => row.rls === false).map((row) => row.table).sort());
    }
    const result = classifyRlsOff(scan, exclusions);
    expect(result.errors, `${file}: collection errors cannot be excluded`).toEqual([]);
    expect(result.open, `${file}: unknown tables or changed grants require remediation`).toEqual([]);
    expect(result.excluded.length).toBe(scan.projects.reduce((sum, project) => sum + project.rls_off.length, 0));
    // The capsule permits only these two owner-controlled PostGIS catalogs to
    // retain writes after a proven failed revoke. Never extend that exception by name alone.
    const ownerControlledCatalogs = new Set(['tyqxwawlgdhcpisyqyfd:spatial_ref_sys', 'qfxgiyeufgjsovxupfej:spatial_ref_sys']);
    for (const entry of exclusions) {
      if (!entry.expected_anon_write) continue;
      expect(ownerControlledCatalogs.has(`${entry.ref}:${entry.table}`), 'Writable exclusions are limited to the two proven PostGIS owner restrictions').toBe(true);
      expect(entry.reason).toMatch(/supabase_admin/);
      expect(entry.reason).toMatch(/REVOKE/i);
      expect(entry.evidence, 'An owner restriction needs observed live proof').toBeTruthy();
      expect(fs.existsSync(path.resolve(repo, entry.evidence)), 'The live proof must be present').toBe(true);
    }
    expect(exclusions.find((entry: { ref: string; table: string }) => entry.ref === 'eiqntvlwhfgvnqjdyuip' && entry.table === 'shipsafe_demo_customers')?.expected_anon_write).toBe(false);
  });

  it('rejects a new RLS-off table instead of treating it as closed work', () => {
    const result = classifyRlsOff(fixtureScan([fixtureRow('catalog'), fixtureRow('new_customers')]), [fixtureExclusion]);
    expect(result.excluded.map((row: Table) => row.table)).toEqual(['catalog']);
    expect(result.open.map((row: Table) => row.table)).toEqual(['new_customers']);
  });

  it('reopens excluded tables when anonymous write grants return', () => {
    const result = classifyRlsOff(fixtureScan([fixtureRow('catalog', true)]), [fixtureExclusion]);
    expect(result.excluded).toEqual([]);
    expect(result.open.map((row: Table) => row.table)).toEqual(['catalog']);
  });

  it('does not apply a catalog exclusion to a different project', () => {
    const scan = fixtureScan([fixtureRow('catalog')]);
    scan.projects[0].ref = 'another-project';
    expect(classifyRlsOff(scan, [fixtureExclusion]).open).toHaveLength(1);
  });

  it('keeps project collection errors unresolved even when there are no reported rows', () => {
    const scan = fixtureScan([]);
    scan.projects[0].error = 'permission denied';
    expect(classifyRlsOff(scan, [fixtureExclusion]).errors).toHaveLength(1);
  });

  it('reports explicit exclusions separately from unknown open tables and grant drift', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rls-exclusions-report-'));
    roots.push(root);
    fs.mkdirSync(path.join(root, 'docs/rls-lane-results'), { recursive: true });
    const before = fixtureScan([fixtureRow('catalog'), fixtureRow('new_customers'), fixtureRow('write_drift', true)]);
    const exclusions = [fixtureExclusion, { ...fixtureExclusion, table: 'write_drift' }];
    fs.writeFileSync(path.join(root, 'before.json'), JSON.stringify(before));
    fs.writeFileSync(path.join(root, 'after.json'), JSON.stringify(before));
    fs.writeFileSync(path.join(root, 'docs/rls-exclusions.json'), JSON.stringify(exclusions));
    // A stale lane marking everything excluded must not override the current scan safeguards.
    fs.writeFileSync(path.join(root, 'docs/rls-lane-results/stale.json'), JSON.stringify({
      ref: 'fixture-project', tables: before.projects[0].rls_off.map((row) => ({ table: row.table, status: 'excluded', reason: 'Historical note' })),
    }));
    const result = spawnSync(process.execPath, [path.join(repo, 'scripts/rls-report.mjs'), '--before', 'before.json', '--after', 'after.json', '--out', 'report.md'], { cwd: root, encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0);
    const report = fs.readFileSync(path.join(root, 'report.md'), 'utf8');
    expect(report).toMatch(/fixed 0, excluded 1, open 2/);
    expect(report.split('\n').find((line) => line.includes('| catalog |'))).toMatch(/excluded/);
    for (const table of ['new_customers', 'write_drift']) {
      expect(report.split('\n').find((line) => line.includes(`| ${table} |`))).toMatch(/open/);
    }
  });
});
