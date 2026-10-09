#!/usr/bin/env node
// Static migration guard. All configured SQL history must leave every public
// table with RLS enabled. DISABLE is always rejected; there are no exemptions.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function tokens(sql) {
  const result = [];
  for (let i = 0; i < sql.length;) {
    if (/\s/.test(sql[i])) { i++; continue; }
    if (sql.startsWith('--', i)) { const end = sql.indexOf('\n', i); i = end < 0 ? sql.length : end; continue; }
    if (sql.startsWith('/*', i)) {
      let depth = 1; i += 2;
      while (i < sql.length && depth) {
        if (sql.startsWith('/*', i)) { depth++; i += 2; }
        else if (sql.startsWith('*/', i)) { depth--; i += 2; }
        else i++;
      }
      if (depth) throw new Error('Unterminated SQL comment');
      continue;
    }
    if (sql[i] === "'" || sql[i] === '$') {
      const quote = sql[i] === "'" ? "'" : sql.slice(i).match(/^\$(?:[a-zA-Z_][\w]*)?\$/)?.[0];
      if (quote) {
        const start = i;
        i += quote.length;
        let closed = false;
        while (i < sql.length) {
          if (sql.startsWith(quote, i)) {
            i += quote.length;
            if (quote === "'" && sql[i] === "'") { i++; continue; }
            closed = true; break;
          }
          if (quote === "'" && sql[i] === '\\') throw new Error('Backslash-escaped SQL strings are unsupported; use dollar-quoted strings');
          i++;
        }
        if (!closed) throw new Error('Unterminated SQL string');
        // Do not interpret code inside functions/strings as executed migration DDL.
        const content = sql.slice(start + quote.length, i - quote.length);
        result.push({ value: '<string>', quoted: true, raw: sql.slice(start, i),
          content: quote === "'" ? content.replaceAll("''", "'") : content }); continue;
      }
    }
    if (sql[i] === '"') {
      let value = ''; i++; let closed = false;
      while (i < sql.length) {
        if (sql[i] === '"') {
          if (sql[i + 1] === '"') { value += '"'; i += 2; }
          else { i++; closed = true; break; }
        } else value += sql[i++];
      }
      if (!closed) throw new Error('Unterminated SQL identifier');
      result.push({ value, quoted: true }); continue;
    }
    const word = sql.slice(i).match(/^[a-zA-Z_][\w$]*/)?.[0];
    if (word) { result.push({ value: word.toLowerCase(), quoted: false }); i += word.length; }
    else result.push({ value: sql[i++], quoted: false });
  }
  return result;
}

export function migrationEvents(sql) {
  const ts = tokens(sql), events = [];
  const is = (i, word) => ts[i]?.value === word && !ts[i]?.quoted;
  const name = (i) => {
    if (!ts[i] || ts[i].value === ';') throw new Error('Missing table identifier');
    if (is(i + 1, '.')) return { schema: ts[i].value, table: ts[i + 2]?.value, next: i + 3 };
    return { schema: 'public', table: ts[i].value, next: i + 1 };
  };
  for (let i = 0; i < ts.length; i++) {
    // Ambiguous search paths must not silently turn an unqualified public table
    // into a skipped table. Explicit schema names are required in those files.
    if (is(i, 'set') && (is(i + 1, 'search_path') || is(i + 2, 'search_path'))) throw new Error('SET search_path is unsupported; use explicit schema-qualified migration DDL');
    if (is(i, 'set_config') && ts[i + 2]?.raw?.toLowerCase().includes('search_path')) throw new Error('set_config search_path is unsupported; use explicit schema-qualified migration DDL');
    if (is(i, 'do') && !is(i + 1, 'nothing') && !is(i + 1, 'update')) {
      const body = ts.slice(i + 1).find(t => t.raw);
      // Tokenize the executed body too: SQL comments can legally separate DDL
      // keywords, and raw-text regexes would silently miss that table/RLS DDL.
      // Strings and quoted identifiers cannot supply executable keywords.
      const bodyTokens = body ? tokens(body.content) : [];
      const bodyCode = bodyTokens.map(t => t.quoted ? '<literal>' : t.value).join(' ');
      const nestedDo = bodyTokens.some((t, j) => !t.quoted && t.value === 'do'
        && !['nothing', 'update'].includes(bodyTokens[j + 1]?.value));
      if (!body || nestedDo || /\bexecute\b|\b(?:create\s+(?:(?:unlogged|temp(?:orary)?)\s+)?|drop\s+)table\b|\brow\s+level\s+security\b|\b(?:search_path|set_config|call|rename)\b|\bset\s+schema\b/.test(bodyCode)) throw new Error('Dynamic table/RLS DDL in DO blocks is unsupported; use explicit top-level CREATE TABLE and ALTER TABLE ENABLE ROW LEVEL SECURITY');
    }
    if (is(i, 'call')) throw new Error('CALL migrations are unsupported; use explicit top-level table/RLS DDL');
    if (is(i, 'create')) {
      let j = i + 1;
      if (is(j, 'temporary') || is(j, 'temp')) continue;
      if (is(j, 'unlogged')) j++;
      if (!is(j++, 'table')) continue;
      if (is(j, 'if') && is(j + 1, 'not') && is(j + 2, 'exists')) j += 3;
      const n = name(j);
      if (n.schema === 'public') events.push({ type: 'create', table: n.table });
    } else if (is(i, 'alter') && is(i + 1, 'table')) {
      let j = i + 2;
      if (is(j, 'if') && is(j + 1, 'exists')) j += 2;
      if (is(j, 'only')) j++;
      const n = name(j); j = n.next;
      for (let k = j; k < ts.length && !is(k, ';'); k++) {
        if (is(k, 'rename') || (is(k, 'set') && is(k + 1, 'schema'))) throw new Error('ALTER TABLE rename/schema moves are unsupported; require explicit guard review');
      }
      if (n.schema !== 'public') continue;
      for (; j < ts.length && !is(j, ';'); j++) {
        if ((is(j, 'enable') || is(j, 'disable')) && is(j + 1, 'row') && is(j + 2, 'level') && is(j + 3, 'security')) {
          events.push({ type: ts[j].value, table: n.table });
        }
      }
    } else if (is(i, 'drop') && is(i + 1, 'table')) {
      let j = i + 2;
      if (is(j, 'if') && is(j + 1, 'exists')) j += 2;
      while (j < ts.length) {
        const n = name(j);
        if (n.schema === 'public') events.push({ type: 'drop', table: n.table });
        j = n.next;
        if (!is(j, ',')) break;
        j++;
      }
    }
  }
  return events;
}

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name)).flatMap(e => {
    const p = path.join(dir,e.name);
    return e.isDirectory() ? walk(p) : e.name.endsWith('.sql') ? [p] : [];
  });
}
export function checkMigrations(root, dirs = ['drizzle', 'supabase/migrations']) {
  const files = [...new Set(dirs.flatMap(d => walk(path.resolve(root,d))))];
  if (!files.length) return { files: 0, tables: 0, errors: ['No SQL migrations found (guard must not silently pass an incorrect path)'] };
  const states = new Map(), errors = [], seenCreates = new Set();
  for (const file of files) {
    const rel = path.relative(root,file).split(path.sep).join('/'), sql = fs.readFileSync(file,'utf8');
    let events;
    try { events = migrationEvents(sql); } catch (error) { errors.push(`${rel}: ${error.message}`); continue; }
    const duplicateCreates = new Set();
    const localStates = new Map();
    for (const e of events) {
      if (e.type === 'drop') { states.delete(e.table); }
      else if (e.type === 'create') {
        if (seenCreates.has(e.table)) duplicateCreates.add(e.table);
        seenCreates.add(e.table); localStates.set(e.table, false); states.set(e.table, false);
      }
      else { states.set(e.table, e.type === 'enable'); if (localStates.has(e.table)) localStates.set(e.table, e.type === 'enable'); }
      if (e.type === 'disable') errors.push(`${rel}: public.${e.table} DISABLE ROW LEVEL SECURITY is forbidden`);
    }
    for (const table of duplicateCreates) if (!localStates.get(table)) errors.push(`${rel}: repeated CREATE TABLE public.${table} requires ENABLE ROW LEVEL SECURITY in the same migration`);
  }
  for (const [table, enabled] of states) if (!enabled) errors.push(`Migration history leaves public.${table} with RLS off: CREATE TABLE requires matching ALTER TABLE ENABLE ROW LEVEL SECURITY`);
  return { files: files.length, tables: states.size, errors };
}

if (process.argv[1] && fs.existsSync(process.argv[1]) && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  const args = process.argv.slice(2); let root = process.cwd(), dirs = [];
  try {
    for (let i=0;i<args.length;i++) {
      if (args[i] === '--root') root = path.resolve(args[++i]);
      else if (args[i] === '--dir') dirs.push(args[++i]);
      else throw new Error(`Unknown argument: ${args[i]}`);
    }
    const result = checkMigrations(root, dirs.length ? dirs : undefined);
    for (const error of result.errors) console.error(error);
    console.log(`RLS migration guard: ${result.errors.length ? 'FAIL' : 'PASS'} (${result.files} SQL files, ${result.tables} public tables, ${result.errors.length} errors)`);
    process.exitCode = result.errors.length ? 1 : 0;
  } catch (error) { console.error(`RLS migration guard: ${error.message}`); process.exitCode = 1; }
}
