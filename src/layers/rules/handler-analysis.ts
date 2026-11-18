// Follows a route handler's calls into the project's own code, so a rule can ask what a helper DOES
// instead of what it is called.
//
// The rules used to read the route file alone and look for guard-shaped names. Real handlers keep the
// guard one or two calls away (`const t = await twilioRequest(req); if (!t.ok) return t.res;`), so a
// correctly guarded route was reported as open. This module resolves those calls (relative, aliased and
// extensionless imports, methods on objects) and answers four questions:
//
//   handlerGuard          is the handler gated by a verified request, a link token or a visitor limit?
//   bodyCheckedDownstream is the request body rejected by the function it is handed to?
//   isFixedText           is an expression a string nobody outside the code can influence?
//   project.source        the parsed file, for rules that need to look at one expression.
//
// It fails closed. A call that cannot be resolved, a helper in a package, an ambiguous method, a guard
// whose answer is ignored: each leaves the finding in place. Nothing here passes by its name.
//
// Work is lazy and bounded: rules call in only for an endpoint they are about to report, files are parsed
// once per scan, and a call chain is followed at most MAX_HOPS deep.

import ts from "typescript";
import { existsSync, readFileSync, statSync } from "fs";
import { dirname, join, resolve, sep } from "path";
import { isDeniedPath } from "../../utils/fs.js";
import type { ApiEndpoint, ProjectModel } from "../../model/types.js";

type Fn = ts.FunctionDeclaration | ts.MethodDeclaration | ts.ArrowFunction | ts.FunctionExpression;

const MAX_HOPS = 4;
const MAX_CLOSURE_FILES = 150;
const MAX_METHOD_CANDIDATES = 3;
const MAX_FILE_BYTES = 1_000_000;
const EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"];

// Methods of the language and the web platform. `x.get(...)` is far more likely to be a Map or Headers
// than the project's one class with a `get` method, so these never resolve to project code.
const PLATFORM_METHODS = new Set(
  (
    "get set has add delete clear keys values entries forEach map filter find findIndex findLast some every reduce " +
    "push pop shift unshift slice splice concat join includes indexOf sort reverse flat flatMap at fill " +
    "trim trimStart trimEnd toLowerCase toUpperCase toString toFixed normalize padStart padEnd startsWith endsWith " +
    "split replace replaceAll match matchAll test exec substring charAt charCodeAt localeCompare repeat " +
    "then catch finally json text formData arrayBuffer blob clone append update digest final subarray " +
    "from of isArray assign freeze fromEntries stringify parse now floor ceil round abs min max random " +
    "log warn error info debug call apply bind next redirect rewrite getAll getTime toISOString valueOf"
  ).split(" "),
);

// Calls that only change a value's shape. A tainted value stays tainted through them.
const COERCION_FUNCTIONS = new Set(["String", "Number", "Boolean", "parseInt", "parseFloat", "decodeURIComponent", "encodeURIComponent"]);
const COERCION_METHODS = new Set(["trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "toString", "normalize", "slice", "substring", "replace", "replaceAll"]);

const SUCCESS_FIELD = /^(?:ok|success|succeeded|successful|valid|saved|done|accepted|created|updated)$/;

// ---------------------------------------------------------------------------
// Project: parsed files, import resolution, declarations
// ---------------------------------------------------------------------------

export class Project {
  readonly root: string;
  private texts = new Map<string, string | null>();
  private parsed = new Map<string, ts.SourceFile | null>();
  private closures = new Map<string, string[]>();
  private methods = new Map<string, { fns: Fn[]; unknown: boolean }>();
  private aliases: Array<{ prefix: string; suffix: string; targets: string[] }> | null = null;
  private deps: Set<string> | null = null;
  // Proofs kept per scan. `cuts` counts walks stopped short (depth, a cycle): a "no" with one of those in
  // it is not final and is not kept. `checks` counts session reads met while proving.
  readonly proofMemo = new Map<Fn, Map<string, { fails: Set<"false" | "null" | "undefined" | "other">; checks: number } | null>>();
  readonly proofActive = new Set<Fn>();
  cuts = 0;
  checks = 0;
  readonly followed = new Set<ts.Node>();

  constructor(root: string) {
    this.root = resolve(root);
  }

  text(file: string): string | null {
    if (this.texts.has(file)) return this.texts.get(file) ?? null;
    let out: string | null = null;
    try {
      if (!isDeniedPath(file) && statSync(file).size <= MAX_FILE_BYTES) out = readFileSync(file, "utf-8");
    } catch {
      out = null;
    }
    this.texts.set(file, out);
    return out;
  }

  source(file: string): ts.SourceFile | null {
    const abs = resolve(file);
    if (this.parsed.has(abs)) return this.parsed.get(abs) ?? null;
    const text = this.text(abs);
    const sf =
      text === null
        ? null
        : ts.createSourceFile(abs, text, ts.ScriptTarget.Latest, true, scriptKind(abs));
    this.parsed.set(abs, sf);
    return sf;
  }

  private aliasList(): Array<{ prefix: string; suffix: string; targets: string[] }> {
    if (this.aliases) return this.aliases;
    this.aliases = [];
    for (const name of ["tsconfig.json", "jsconfig.json"]) {
      const path = join(this.root, name);
      if (!existsSync(path)) continue;
      try {
        const { config } = ts.parseConfigFileTextToJson(path, readFileSync(path, "utf-8"));
        const options = config?.compilerOptions ?? {};
        const base = resolve(this.root, options.baseUrl ?? ".");
        for (const [pattern, targets] of Object.entries((options.paths ?? {}) as Record<string, string[]>)) {
          const star = pattern.indexOf("*");
          this.aliases.push({
            prefix: star < 0 ? pattern : pattern.slice(0, star),
            suffix: star < 0 ? "\u0000" : pattern.slice(star + 1),
            targets: targets.map((t) => resolve(base, t)),
          });
        }
      } catch {
        // An unreadable config means no aliases: imports through them stay unresolved.
      }
      break;
    }
    return this.aliases;
  }

  private isProjectFile(path: string): boolean {
    if (!path.startsWith(this.root + sep) || path.includes(`${sep}node_modules${sep}`)) return false;
    try {
      return statSync(path).isFile();
    } catch {
      return false;
    }
  }

  /** The project file an import points at, or null for packages and anything not found. */
  resolveModule(from: string, spec: string): string | null {
    const bases: string[] = [];
    if (spec.startsWith(".")) {
      bases.push(resolve(dirname(from), spec));
    } else {
      for (const a of this.aliasList()) {
        if (a.suffix === "\u0000") {
          if (spec === a.prefix) bases.push(...a.targets);
        } else if (spec.startsWith(a.prefix) && spec.endsWith(a.suffix) && spec.length >= a.prefix.length + a.suffix.length) {
          const middle = spec.slice(a.prefix.length, spec.length - a.suffix.length);
          bases.push(...a.targets.map((t) => t.replace("*", middle)));
        }
      }
    }
    for (const base of bases) {
      const bare = base.replace(/\.(?:js|jsx|mjs)$/, "");
      const tries = [base, ...EXTENSIONS.map((e) => base + e), ...EXTENSIONS.map((e) => join(base, `index${e}`))];
      if (bare !== base) tries.push(...EXTENSIONS.map((e) => bare + e));
      for (const t of tries) if (this.isProjectFile(t)) return t;
    }
    return null;
  }

  /** Project files reachable from `entry` through imports, nearest first, capped. */
  closure(entry: string): string[] {
    const cached = this.closures.get(entry);
    if (cached) return cached;
    const seen = new Set<string>([entry]);
    const queue = [entry];
    for (let i = 0; i < queue.length && queue.length < MAX_CLOSURE_FILES; i++) {
      const text = this.text(queue[i]);
      if (!text) continue;
      for (const m of text.matchAll(/(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']([^"'\n]+)["']/g)) {
        const target = this.resolveModule(queue[i], m[1]);
        if (target && !seen.has(target) && queue.length < MAX_CLOSURE_FILES) {
          seen.add(target);
          queue.push(target);
        }
      }
    }
    this.closures.set(entry, queue);
    return queue;
  }

  /** A function declared at the top of a file: `function name`, `const name = () =>`, or the default export. */
  private topLevel(sf: ts.SourceFile, name: string): Fn | null {
    for (const s of sf.statements) {
      if (ts.isFunctionDeclaration(s) && s.body) {
        const isDefault = s.modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword) ?? false;
        if (s.name?.text === name || (name === "default" && isDefault)) return s.name ? declaredFn(s.name) : s;
      }
      if (ts.isVariableStatement(s)) {
        for (const d of s.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name) return declaredFn(d.name);
        }
      }
      if (name === "default" && ts.isExportAssignment(s)) {
        const e = unwrap(s.expression);
        if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) return e;
        if (ts.isIdentifier(e)) return this.topLevel(sf, e.text);
      }
    }
    return null;
  }

  /** The module an identifier was imported from in `file`, with the name it has there. */
  importOf(file: string, local: string): { spec: string; name: string; namespace: boolean } | null {
    const sf = this.source(file);
    if (!sf) return null;
    for (const s of sf.statements) {
      if (!ts.isImportDeclaration(s) || !ts.isStringLiteral(s.moduleSpecifier) || !s.importClause) continue;
      const spec = s.moduleSpecifier.text;
      const clause = s.importClause;
      if (clause.name?.text === local) return { spec, name: "default", namespace: false };
      const named = clause.namedBindings;
      if (named && ts.isNamespaceImport(named) && named.name.text === local) return { spec, name: "*", namespace: true };
      if (named && ts.isNamedImports(named)) {
        for (const el of named.elements) {
          if (el.name.text === local) return { spec, name: (el.propertyName ?? el.name).text, namespace: false };
        }
      }
    }
    return null;
  }

  /** The function `name` refers to in `file`: declared there, imported, or re-exported. */
  lookup(file: string, name: string, hops = 4): Fn | null {
    const sf = this.source(file);
    if (!sf || hops < 0) return null;
    const here = this.topLevel(sf, name);
    if (here) return here;
    const imported = this.importOf(file, name);
    if (imported && !imported.namespace) {
      const target = this.resolveModule(file, imported.spec);
      return target ? this.lookup(target, imported.name, hops - 1) : null;
    }
    for (const s of sf.statements) {
      if (!ts.isExportDeclaration(s)) continue;
      const from = s.moduleSpecifier && ts.isStringLiteral(s.moduleSpecifier) ? this.resolveModule(file, s.moduleSpecifier.text) : null;
      if (s.exportClause && ts.isNamedExports(s.exportClause)) {
        for (const el of s.exportClause.elements) {
          if (el.name.text !== name) continue;
          const original = (el.propertyName ?? el.name).text;
          if (from) return this.lookup(from, original, hops - 1);
          if (original !== name) return this.lookup(file, original, hops - 1);
        }
      } else if (!s.exportClause && from) {
        const found = this.lookup(from, name, hops - 1);
        if (found) return found;
      }
    }
    return null;
  }

  /**
   * A top-level `const name = <expression>` in `file`, or the same through an import. Only the file's own
   * top level is read: what a name means inside a function is decided by scope (`declarationOf`), so a
   * parameter or a destructured prop that shares the name is never mistaken for the constant.
   */
  constant(file: string, name: string, hops = 3): { file: string; value: ts.Expression } | null {
    const d = this.topVariable(file, name, hops);
    if (!d || !d.initializer || !ts.isIdentifier(d.name) || (d.parent.flags & ts.NodeFlags.Const) === 0) return null;
    return { file: d.getSourceFile().fileName, value: d.initializer };
  }

  /** The top-level variable `name` stands for in `file`: declared there, imported, or re-exported. */
  topVariable(file: string, name: string, hops = 3): ts.VariableDeclaration | null {
    const sf = this.source(file);
    if (!sf || hops < 0) return null;
    for (const s of sf.statements) {
      if (!ts.isVariableStatement(s)) continue;
      for (const d of s.declarationList.declarations) if (bindingNames(d.name).includes(name)) return d;
    }
    const imported = this.importOf(file, name);
    if (imported) {
      const target = imported.namespace ? null : this.resolveModule(file, imported.spec);
      return target ? this.topVariable(target, imported.name, hops - 1) : null;
    }
    for (const s of sf.statements) {
      if (!ts.isExportDeclaration(s) || !s.moduleSpecifier || !ts.isStringLiteral(s.moduleSpecifier)) continue;
      const from = this.resolveModule(file, s.moduleSpecifier.text);
      if (!from) continue;
      if (s.exportClause && ts.isNamedExports(s.exportClause)) {
        const el = s.exportClause.elements.find((x) => x.name.text === name);
        if (el) return this.topVariable(from, (el.propertyName ?? el.name).text, hops - 1);
      } else if (!s.exportClause) {
        const found = this.topVariable(from, name, hops - 1);
        if (found) return found;
      }
    }
    return null;
  }

  /**
   * Methods and function-valued properties called `name` in the files `entry` reaches. `unknown` is set
   * when something of that name cannot be read as a function written in place (`{ admit: anyone }`, a
   * getter, `x.admit = ...`, a shorthand property) or the files reached could not all be looked at: the
   * call may then run something that is not in `fns`.
   */
  methodsOf(entry: string, name: string): { fns: Fn[]; unknown: boolean } {
    const key = `${entry}\u0000${name}`;
    const cached = this.methods.get(key);
    if (cached) return cached;
    const fns: Fn[] = [];
    const files = this.closure(entry);
    let unknown = files.length >= MAX_CLOSURE_FILES;
    for (const file of files) {
      if (!this.text(file)?.includes(name)) continue;
      const sf = this.source(file);
      if (!sf) {
        unknown = true;
        continue;
      }
      each(sf, (n) => {
        if (ts.isMethodDeclaration(n) && propertyKey(n.name) === name) {
          if (n.body && !n.asteriskToken) fns.push(n);
          else if (n.body) unknown = true;
        } else if ((ts.isPropertyAssignment(n) || ts.isPropertyDeclaration(n)) && propertyKey(n.name) === name) {
          const init = n.initializer ? unwrap(n.initializer) : undefined;
          if (init && (ts.isArrowFunction(init) || (ts.isFunctionExpression(init) && !init.asteriskToken))) fns.push(init);
          else if (ts.isPropertyAssignment(n) || init) unknown = true;
        } else if (ts.isShorthandPropertyAssignment(n) && n.name.text === name) unknown = true;
        else if ((ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n)) && propertyKey(n.name) === name) unknown = true;
        else if (ts.isBinaryExpression(n) && n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && n.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
          const left = unwrap(n.left);
          if (ts.isPropertyAccessExpression(left) && left.name.text === name) unknown = true;
          if (ts.isElementAccessExpression(left) && (!ts.isStringLiteralLike(left.argumentExpression) || left.argumentExpression.text === name)) unknown = true;
        }
      });
    }
    const out = { fns, unknown };
    this.methods.set(key, out);
    return out;
  }

  methodsNamed(entry: string, name: string): Fn[] {
    const { fns, unknown } = this.methodsOf(entry, name);
    return unknown ? [] : fns;
  }

  /**
   * The import behind a local name when it is shown to come from a package: a Node built-in, or a package
   * the project's package.json lists. An import that merely fails to resolve (`#internal/log`, a path
   * mapping this does not know) is not a package; it is code that could not be read.
   */
  packageImport(file: string, local: string): { spec: string; name: string } | null {
    const imported = this.importOf(file, local);
    if (!imported || this.resolveModule(file, imported.spec) !== null) return null;
    if (/^(?:node:)?(?:crypto|buffer|util|url)$/.test(imported.spec)) return imported;
    const m = /^(@[\w.-]+\/[\w.-]+|[\w.-]+)(?:\/|$)/.exec(imported.spec);
    return m && this.dependencies().has(m[1]) ? imported : null;
  }

  private dependencies(): Set<string> {
    if (this.deps) return this.deps;
    this.deps = new Set();
    try {
      const pkg = JSON.parse(readFileSync(join(this.root, "package.json"), "utf-8"));
      for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
        for (const name of Object.keys(pkg?.[key] ?? {})) this.deps.add(name);
      }
    } catch {
      // No readable package.json: no import is taken for a package.
    }
    return this.deps;
  }

  /**
   * The project functions a call may run. Empty when it cannot be known: a package, a parameter, a platform
   * method, or more candidates than can be checked. With several candidates, callers require ALL to hold.
   */
  resolveCall(call: ts.CallExpression, entry: string): Fn[] {
    const file = call.getSourceFile().fileName;
    const callee = unwrap(call.expression);
    if (ts.isIdentifier(callee)) {
      // Scope decides what the name means at the call. A parameter, a `let` that is pointed elsewhere, a
      // local that merely shares the name of an import: none of those is the function found by its name.
      const declared = declarationOf(callee);
      if (declared) {
        const fn = declaredFn(declared);
        return fn ? [fn] : [];
      }
      const found = this.lookup(file, callee.text);
      return found ? [found] : [];
    }
    if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return [];
    const name = callee.name.text;
    const object = unwrap(callee.expression);
    if (object.kind === ts.SyntaxKind.ThisKeyword) {
      const cls = enclosing(call, ts.isClassLike);
      const named = cls?.members.filter((x) => propertyKey(x.name) === name) ?? [];
      const m = named.length === 1 ? named[0] : undefined;
      return m && ts.isMethodDeclaration(m) && m.body && !m.asteriskToken ? [m] : [];
    }
    if (ts.isIdentifier(object)) {
      const imported = this.importOf(file, object.text);
      if (imported?.namespace) {
        const target = this.resolveModule(file, imported.spec);
        const found = target ? this.lookup(target, name) : null;
        return found ? [found] : [];
      }
      if (imported && !this.resolveModule(file, imported.spec)) return []; // a package's object, or code that could not be read
    }
    if (PLATFORM_METHODS.has(name)) return [];
    const candidates = this.methodsNamed(entry, name);
    return candidates.length > 0 && candidates.length <= MAX_METHOD_CANDIDATES ? candidates : [];
  }
}

/** `.js` files routinely hold JSX; read as plain TypeScript the markup is lost and so is whatever it injects. */
function scriptKind(file: string): ts.ScriptKind {
  if (/\.[jt]sx$/.test(file)) return ts.ScriptKind.TSX;
  return /\.[cm]?js$/.test(file) ? ts.ScriptKind.JSX : ts.ScriptKind.TS;
}

const projects = new WeakMap<ProjectModel, Project>();

/** One Project per scan: the model object is new for every scan, so nothing stale survives a rescan. */
export function projectFor(model: ProjectModel): Project {
  let p = projects.get(model);
  if (!p) {
    p = new Project(model.meta.path);
    projects.set(model, p);
  }
  return p;
}

// ---------------------------------------------------------------------------
// Syntax helpers
// ---------------------------------------------------------------------------

function unwrap(e: ts.Expression): ts.Expression {
  let cur = e;
  while (
    ts.isParenthesizedExpression(cur) ||
    ts.isNonNullExpression(cur) ||
    ts.isAsExpression(cur) ||
    ts.isSatisfiesExpression(cur) ||
    ts.isAwaitExpression(cur) ||
    ts.isTypeAssertionExpression(cur)
  ) {
    cur = cur.expression;
  }
  return cur;
}

function each(node: ts.Node, visit: (n: ts.Node) => void): void {
  visit(node);
  ts.forEachChild(node, (c) => each(c, visit));
}

function isFn(n: ts.Node): n is Fn {
  return ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n);
}

function enclosing<T extends ts.Node>(node: ts.Node, is: (n: ts.Node) => n is T): T | undefined {
  for (let cur = node.parent; cur; cur = cur.parent) if (is(cur)) return cur;
  return undefined;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((el) => (ts.isOmittedExpression(el) ? [] : bindingNames(el.name)));
}

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) return [name];
  return name.elements.flatMap((el) => (ts.isOmittedExpression(el) ? [] : bindingIdentifiers(el.name)));
}

/**
 * The declaration an identifier refers to: the nearest parameter, variable, loop or catch binding of that
 * name around it. Two variables that merely share a name (a request `body` and a response `body`) are
 * different declarations, so a fact about one never leaks to the other.
 */
function declarationOf(id: ts.Identifier): ts.Identifier | null {
  const find = (name: ts.BindingName | undefined) => (name ? bindingIdentifiers(name).find((b) => b.text === id.text) : undefined);
  const inList = (list: ts.Node | undefined) => {
    if (!list || !ts.isVariableDeclarationList(list)) return undefined;
    for (const d of list.declarations) {
      const b = find(d.name);
      if (b) return b;
    }
    return undefined;
  };
  for (let scope: ts.Node | undefined = id.parent; scope; scope = scope.parent) {
    let found: ts.Identifier | undefined;
    if (isFn(scope)) {
      for (const p of scope.parameters) found ??= find(p.name);
      if (!found && scope.body) found = hoistedVar(scope.body, id.text);
    } else if (ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope) || ts.isModuleBlock(scope)) {
      for (const st of scope.statements) {
        if (ts.isVariableStatement(st)) found ??= inList(st.declarationList);
        if (ts.isFunctionDeclaration(st) && st.name?.text === id.text) found ??= st.name;
      }
    } else if (ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) {
      found = inList(scope.initializer);
    } else if (ts.isCatchClause(scope)) {
      found = find(scope.variableDeclaration?.name);
    }
    if (found) return found;
  }
  return null;
}

/** A `var` of that name anywhere in a function's body (not in functions inside it): it is the function's. */
function hoistedVar(body: ts.Node, name: string): ts.Identifier | undefined {
  let found: ts.Identifier | undefined;
  const walk = (n: ts.Node): void => {
    if (found || isFn(n)) return;
    if (ts.isVariableDeclarationList(n) && (n.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0) {
      for (const d of n.declarations) found ??= bindingIdentifiers(d.name).find((b) => b.text === name);
    }
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(body, walk);
  return found;
}

/**
 * The function a declared name stands for, when it can stand for nothing else: a function declaration that
 * is the only one of its name and is never assigned to, or a `const` set to a function written in place.
 * A generator is left out: calling one runs none of its body.
 */
function declaredFn(decl: ts.Identifier): Fn | null {
  const p = decl.parent;
  if (ts.isFunctionDeclaration(p) && p.name === decl && p.body && !p.asteriskToken) {
    const scope = p.parent;
    const siblings = ts.isSourceFile(scope) || ts.isBlock(scope) || ts.isModuleBlock(scope) ? scope.statements : [];
    const same = siblings.filter((st) => ts.isFunctionDeclaration(st) && st.name?.text === decl.text);
    return same.length === 1 && !isReassigned(decl) ? p : null;
  }
  if (ts.isVariableDeclaration(p) && p.name === decl && p.initializer && ts.isVariableDeclarationList(p.parent) && (p.parent.flags & ts.NodeFlags.Const) !== 0) {
    const init = unwrap(p.initializer);
    if (ts.isArrowFunction(init) || (ts.isFunctionExpression(init) && !init.asteriskToken)) return init;
  }
  return null;
}

/**
 * True when a branch turns the request away rather than doing the work another way: it throws, or returns
 * nothing, a constant (`null`, `false`, `[]`, `{ status: "invalid" }`), a result marked failed
 * (`{ ok: false, ... }`, `{ error: ... }`) or a 4xx answer. `if (input.id) return db.update(input)` is a
 * branch, not a refusal.
 */
function refuses(branch: ts.Statement): boolean {
  const statements = ts.isBlock(branch) ? [...branch.statements] : [branch];
  const last = statements[statements.length - 1];
  if (!last) return false;
  if (ts.isThrowStatement(last)) return true;
  if (!ts.isReturnStatement(last)) return false;
  if (!last.expression) return true;
  const e = unwrap(last.expression);
  const constant = (x: ts.Expression): boolean => {
    const v = unwrap(x);
    return (
      ts.isStringLiteral(v) || ts.isNoSubstitutionTemplateLiteral(v) || ts.isNumericLiteral(v) || v.kind === ts.SyntaxKind.NullKeyword ||
      v.kind === ts.SyntaxKind.TrueKeyword || v.kind === ts.SyntaxKind.FalseKeyword || (ts.isIdentifier(v) && v.text === "undefined") ||
      (ts.isArrayLiteralExpression(v) && v.elements.length === 0)
    );
  };
  if (constant(e)) return true;
  if (ts.isObjectLiteralExpression(e)) {
    const props = e.properties.filter(ts.isPropertyAssignment);
    // `{ ok: true }` says the work is done (a dry run, a no-op): the opposite of turning the request away.
    if (props.some((p) => unwrap(p.initializer).kind === ts.SyntaxKind.TrueKeyword && SUCCESS_FIELD.test(p.name.getText()))) return false;
    if (props.length === e.properties.length && props.every((p) => constant(p.initializer))) return true;
    if (props.some((p) => unwrap(p.initializer).kind === ts.SyntaxKind.FalseKeyword || /^errors?$/.test(p.name.getText()))) return true;
  }
  return /\b4\d\d\b/.test(e.getText());
}

function ifRefuses(s: ts.IfStatement): boolean {
  return refuses(s.thenStatement) || (!!s.elseStatement && refuses(s.elseStatement));
}

function propertyKey(name: ts.PropertyName | ts.BindingName | undefined): string | null {
  if (!name) return null;
  return ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : null;
}

function callsIn(nodes: ts.Node[]): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  for (const node of nodes) each(node, (n) => void (ts.isCallExpression(n) && out.push(n)));
  return out;
}

/** `token` in `x.token` or `{ token: 1 }` names a property; it is not a use of the variable `token`. */
function isPropertyName(id: ts.Identifier): boolean {
  const p = id.parent;
  return (ts.isPropertyAccessExpression(p) && p.name === id) || (ts.isPropertyAssignment(p) && p.name === id) || (ts.isBindingElement(p) && p.propertyName === id);
}

function calleeName(call: ts.CallExpression): string {
  const c = unwrap(call.expression);
  return ts.isIdentifier(c) ? c.text : ts.isPropertyAccessExpression(c) ? c.name.text : "";
}

function isCoercion(call: ts.CallExpression): boolean {
  const c = unwrap(call.expression);
  return ts.isIdentifier(c) ? COERCION_FUNCTIONS.has(c.text) : ts.isPropertyAccessExpression(c) && COERCION_METHODS.has(c.name.text);
}

// ---------------------------------------------------------------------------
// Verified requests
// ---------------------------------------------------------------------------
//
// This section fails closed, and it is deliberately small. Two attacks on a more general proof found some
// eighty real handlers it left out; each generality (methods found by name, a list of harmless calls, working
// out which side of a compare is the server's secret) was a way in. What is left is one check and a short
// grammar. Everything else stays reported, as it was before any of this existed.
//
// THE CHECK. A Supabase session read: `client.auth.getUser()` or `.getClaims()`, awaited, on a client made in
// the same function by a `create...Client` of an `@supabase/*` package the project lists, or by a project
// function that does nothing but return one (after `await cookies()`). Nothing else is a check: not a
// constant-time compare, not another library, not a name.
//
// A PROVEN VALUE is one that can only be truthy for a signed-in caller: the user of that read, a `const` set
// from it, or the answer of a project helper proven by this same grammar. The proof carries what the value
// holds otherwise (false, null, undefined), so `=== false` on a helper that answers null is not a guard.
//
// THE GRAMMAR. A function is walked from the top with one fact: has every request that reaches this point
// passed a test of a proven value? Until it has, only these statements may appear:
//
//   const x = <quiet>;         if (<quiet>) ... else ...        return <quiet>;        throw new SomeError(...);
//   console.log(<quiet>);      await helper(<quiet>);           try { ... } catch { ... }
//
// and a <quiet> expression is built only from literals, locals, their fields, `! === && || ?? ?:`, and these
// calls: reading the request (`req.text()`, `req.json()`, `req.formData()`, `req.headers.get("name")`),
// `cookies()`/`headers()`, making the client, the session read, `new Response(...)`/`Response.json(...)`, and a
// project function called by its own name whose body keeps to this grammar. No method of the project's, no
// loop, no assignment, no callback, no module value. After the test, the code is free.
//
// A point is past the test: after `if (<false only for the verified>) <leaves>`; inside
// `if (<true only for the verified>) { ... }`; after a statement that calls a helper which throws unless the
// caller is signed in; and after a `try` only when its `catch` leaves.

/** What a value holds when the check behind it failed. "other" is anything not known to be one of the three. */
type Empty = "false" | "null" | "undefined" | "other";

/** The value can only be truthy for a verified request; `fails` is what it holds otherwise. */
interface Proof {
  fails: Set<Empty>;
}

/** What a walk of a function is asked to show. */
type Sense =
  | "truthy" // its answer (at a path) is truthy only for a verified request
  | "empty" // its answer (at a path) is empty only for a verified request: `{ error: Response }` for everyone else
  | "asserts" // it returns at all only for a verified request: it throws otherwise
  | "quiet"; // nothing but the grammar above runs for an unverified request

interface Ctx {
  project: Project;
}

const MAX_PROOF_DEPTH = MAX_HOPS;
const SUPABASE_CLIENT = /^create\w*Client$/;
const ERROR_CLASSES = /^(?:Type|Range|Syntax|Reference|Eval|URI)?Error$/;

/** Thrown inside a walk when a statement is outside the grammar. */
class Unproven extends Error {}

function isAsync(fn: Fn): boolean {
  return (ts.getModifiers(fn as ts.HasModifiers) ?? []).some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
}

/** A name nothing in the file declares or imports: the language's or the platform's own. */
function isGlobal(id: ts.Identifier, project: Project): boolean {
  return declarationOf(id) === null && project.importOf(id.getSourceFile().fileName, id.text) === null;
}

/** A name declared inside a function (a parameter or a local), as opposed to a module's variable or a global. */
function isLocal(id: ts.Identifier): boolean {
  const d = declarationOf(id);
  for (let cur: ts.Node | undefined = d ?? undefined; cur; cur = cur.parent) if (isFn(cur)) return true;
  return false;
}

function emptyLiteral(x: ts.Expression): Empty | null {
  if (x.kind === ts.SyntaxKind.FalseKeyword) return "false";
  if (x.kind === ts.SyntaxKind.NullKeyword) return "null";
  if (ts.isIdentifier(x) && x.text === "undefined" && declarationOf(x) === null) return "undefined";
  return null;
}

function stripParens(e: ts.Expression): ts.Expression {
  let x = e;
  while (ts.isParenthesizedExpression(x)) x = x.expression;
  return x;
}

/** The expression inside brackets, type assertions and `await`, and whether an `await` was on the way. */
function peel(e: ts.Expression, awaitedHint = false): { x: ts.Expression; awaited: boolean } {
  let x = e;
  let awaited = awaitedHint;
  for (;;) {
    if (ts.isAwaitExpression(x)) {
      awaited = true;
      x = x.expression;
    } else if (ts.isParenthesizedExpression(x) || ts.isNonNullExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x) || ts.isTypeAssertionExpression(x)) {
      x = x.expression;
    } else return { x, awaited };
  }
}

function isAssignment(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

const reassigned = new WeakMap<ts.Identifier, boolean>();

/** A name that is written to, or has a field written, anywhere after its declaration no longer holds what it was set from. */
function isReassigned(decl: ts.Identifier): boolean {
  const known = reassigned.get(decl);
  if (known !== undefined) return known;
  let scope: ts.Node = decl;
  while (scope.parent && !isFn(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
  // A function's own name is looked for in what holds the function.
  if (ts.isFunctionDeclaration(scope) && scope.name === decl && scope.parent) {
    scope = scope.parent;
    while (scope.parent && !isFn(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
  }
  let found = false;
  const refers = (n: ts.Node): boolean => {
    let hit = false;
    each(n, (c) => {
      if (!hit && ts.isIdentifier(c) && c.text === decl.text && !isPropertyName(c) && declarationOf(c) === decl) hit = true;
    });
    return hit;
  };
  each(scope, (n) => {
    if (found) return;
    if (ts.isBinaryExpression(n) && isAssignment(n.operatorToken.kind) && refers(n.left)) found = true;
    if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) && (n.operator === ts.SyntaxKind.PlusPlusToken || n.operator === ts.SyntaxKind.MinusMinusToken) && refers(n.operand)) found = true;
    if ((ts.isForOfStatement(n) || ts.isForInStatement(n)) && !ts.isVariableDeclarationList(n.initializer) && refers(n.initializer)) found = true;
    if (ts.isDeleteExpression(n) && refers(n.expression)) found = true;
  });
  reassigned.set(decl, found);
  return found;
}

/** A binding with no default values and no rest: every name in it holds exactly the field it names. */
function plainBinding(name: ts.BindingName): boolean {
  if (ts.isIdentifier(name)) return true;
  if (!ts.isObjectBindingPattern(name)) return false;
  return name.elements.every((el) => !el.dotDotDotToken && !el.initializer && propertyKey(el.propertyName ?? el.name) !== null && plainBinding(el.name));
}

/** What a `const` is set from, and the fields a destructuring picked on the way. Null for anything else. */
function boundTo(id: ts.Identifier): { init: ts.Expression; prefix: string[] } | null {
  const decl = declarationOf(id);
  if (!decl) return null;
  let node: ts.Node = decl;
  const prefix: string[] = [];
  while (ts.isBindingElement(node.parent)) {
    const el: ts.BindingElement = node.parent;
    if (el.dotDotDotToken || el.initializer || !ts.isObjectBindingPattern(el.parent)) return null;
    const key = propertyKey(el.propertyName ?? el.name);
    if (key === null) return null;
    prefix.unshift(key);
    node = el.parent;
  }
  const d = node.parent;
  if (!ts.isVariableDeclaration(d) || !d.initializer || !ts.isVariableDeclarationList(d.parent)) return null;
  // Only a `const` is followed, and not once a field of it is written (`t.ok = true`).
  if ((d.parent.flags & ts.NodeFlags.Const) === 0 || isReassigned(decl)) return null;
  return { init: d.initializer, prefix };
}

/**
 * The project function a call runs, when that can be told from the call alone: a name that stands for one
 * function and nothing else (see declaredFn), here or imported, or `ns.name()` on a namespace import. A
 * method (`x.check()`, `this.check()`) is never resolved: which object `x` is cannot be read off the code.
 */
function helperOf(call: ts.CallExpression, cx: Ctx): Fn | null {
  if ((call.flags & ts.NodeFlags.OptionalChain) !== 0) return null;
  const file = call.getSourceFile().fileName;
  const callee = stripParens(call.expression);
  if (ts.isIdentifier(callee)) {
    const declared = declarationOf(callee);
    return declared ? declaredFn(declared) : cx.project.lookup(file, callee.text);
  }
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && declarationOf(callee.expression) === null) {
    const imported = cx.project.importOf(file, callee.expression.text);
    const target = imported?.namespace ? cx.project.resolveModule(file, imported.spec) : null;
    return target ? cx.project.lookup(target, callee.name.text) : null;
  }
  return null;
}

/** True when evaluating the node runs something: a call, a `new`, an `await`. Functions written there are not run. */
function runsCode(node: ts.Node): boolean {
  let runs = false;
  const walk = (n: ts.Node): void => {
    if (runs || (isFn(n) && n !== node) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n)) return;
    if (ts.isCallExpression(n) || ts.isNewExpression(n) || ts.isAwaitExpression(n) || ts.isTaggedTemplateExpression(n) || ts.isSpreadElement(n) || ts.isSpreadAssignment(n)) runs = true;
    else ts.forEachChild(n, walk);
  };
  walk(node);
  return runs;
}

/** `cookies()` or `headers()` from next/headers. */
function isNextHeaders(call: ts.CallExpression, cx: Ctx): boolean {
  const callee = stripParens(call.expression);
  if (!ts.isIdentifier(callee) || declarationOf(callee) !== null || call.arguments.length > 0) return false;
  const pkg = cx.project.packageImport(call.getSourceFile().fileName, callee.text);
  return !!pkg && pkg.spec === "next/headers" && (pkg.name === "cookies" || pkg.name === "headers");
}

/**
 * A Supabase client, by where it comes from: a `create...Client(...)` imported from an `@supabase/*` package
 * the project lists, a local `const` set to one, or a call of a project function that only makes one.
 */
function isClient(e: ts.Expression, cx: Ctx, depth = 0): boolean {
  if (depth > 3) return false;
  const { x } = peel(e);
  if (ts.isIdentifier(x)) {
    const b = isLocal(x) ? boundTo(x) : null;
    return !!b && b.prefix.length === 0 && isClient(b.init, cx, depth + 1);
  }
  if (!ts.isCallExpression(x) || (x.flags & ts.NodeFlags.OptionalChain) !== 0) return false;
  const callee = stripParens(x.expression);
  if (!ts.isIdentifier(callee)) return false;
  if (declarationOf(callee) === null) {
    const pkg = cx.project.packageImport(x.getSourceFile().fileName, callee.text);
    if (pkg) return /^@supabase\//.test(pkg.spec) && SUPABASE_CLIENT.test(pkg.name) && x.arguments.every((a) => !runsCode(a));
  }
  const maker = helperOf(x, cx);
  return !!maker && x.arguments.length === 0 && isClientMaker(maker, cx, depth + 1);
}

/** A project function that does nothing but hand back a Supabase client, after `cookies()` at most. */
function isClientMaker(fn: Fn, cx: Ctx, depth: number): boolean {
  if (!fn.body || fn.asteriskToken || fn.parameters.length > 0) return false;
  if (!ts.isBlock(fn.body)) return isClient(fn.body, cx, depth);
  const statements = fn.body.statements;
  const last = statements[statements.length - 1];
  if (!last || !ts.isReturnStatement(last) || !last.expression) return false;
  for (const s of statements.slice(0, -1)) {
    if (!ts.isVariableStatement(s) || (s.declarationList.flags & ts.NodeFlags.Const) === 0) return false;
    for (const d of s.declarationList.declarations) {
      const init = d.initializer ? peel(d.initializer).x : null;
      if (!ts.isIdentifier(d.name) || !init || !ts.isCallExpression(init) || !isNextHeaders(init, cx)) return false;
    }
  }
  return isClient(last.expression, cx, depth);
}

/** The one check: `client.auth.getUser()` / `.getClaims()`. Gives the field of its answer that is null without a session. */
function sessionRead(call: ts.CallExpression, cx: Ctx): string[] | null {
  if ((call.flags & ts.NodeFlags.OptionalChain) !== 0) return null;
  const callee = stripParens(call.expression);
  if (!ts.isPropertyAccessExpression(callee)) return null;
  const auth = stripParens(callee.expression);
  if (!ts.isPropertyAccessExpression(auth) || auth.name.text !== "auth" || !isClient(auth.expression, cx)) return null;
  if (callee.name.text === "getUser") return ["data", "user"];
  return callee.name.text === "getClaims" ? ["data"] : null;
}

/** A parameter of `fn` itself, written as a plain name and never assigned to. */
function isOwnParameter(e: ts.Expression, fn: Fn): boolean {
  if (!ts.isIdentifier(e)) return false;
  const d = declarationOf(e);
  return !!d && ts.isParameter(d.parent) && d.parent.name === d && d.parent.parent === fn && !d.parent.dotDotDotToken && !isReassigned(d);
}

/** May `new X(...)` run for anyone? `Response`, the language's errors, and a project class that adds nothing to run. */
function isQuietClass(name: ts.Identifier, cx: Ctx, depth = 0): boolean {
  if (depth > 3 || declarationOf(name) !== null) return false;
  const file = name.getSourceFile().fileName;
  const cls = classNamed(cx.project, file, name.text, 3);
  if (!cls) return isGlobal(name, cx.project) && (name.text === "Response" || ERROR_CLASSES.test(name.text));
  if (cls.members.some((m) => ts.isConstructorDeclaration(m) || ts.isClassStaticBlockDeclaration(m) || (ts.isPropertyDeclaration(m) && !!m.initializer))) return false;
  const base = cls.heritageClauses?.find((h) => h.token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
  if (!base) return true;
  return ts.isIdentifier(base) && ERROR_CLASSES.test(base.text) && isGlobal(base, cx.project);
}

/** The one class of that name at the top of a file, here or where it is imported from. */
function classNamed(project: Project, file: string, name: string, hops: number): ts.ClassDeclaration | null {
  const sf = project.source(file);
  if (!sf || hops < 0) return null;
  const here = sf.statements.filter((st): st is ts.ClassDeclaration => ts.isClassDeclaration(st) && st.name?.text === name);
  if (here.length > 0) return here.length === 1 ? here[0] : null;
  const imported = project.importOf(file, name);
  const target = imported && !imported.namespace ? project.resolveModule(file, imported.spec) : null;
  return target && imported ? classNamed(project, target, imported.name, hops - 1) : null;
}

/** A <quiet> expression of the grammar at the top of this section, inside `fn`. */
function isQuiet(e: ts.Node, fn: Fn, cx: Ctx, depth: number): boolean {
  const q = (n: ts.Node): boolean => isQuiet(n, fn, cx, depth);
  if (ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e) || ts.isSatisfiesExpression(e) || ts.isAwaitExpression(e)) return q(e.expression);
  if (ts.isStringLiteralLike(e) || ts.isNumericLiteral(e)) return true;
  if (e.kind === ts.SyntaxKind.TrueKeyword || e.kind === ts.SyntaxKind.FalseKeyword || e.kind === ts.SyntaxKind.NullKeyword) return true;
  if (ts.isIdentifier(e)) return isLocal(e) || (e.text === "undefined" && isGlobal(e, cx.project));
  if (ts.isTemplateExpression(e)) return e.templateSpans.every((s) => q(s.expression));
  if (ts.isPropertyAccessExpression(e)) return ts.isIdentifier(e.name) && q(e.expression);
  if (ts.isElementAccessExpression(e)) return (ts.isStringLiteralLike(e.argumentExpression) || ts.isNumericLiteral(e.argumentExpression)) && q(e.expression);
  if (ts.isArrayLiteralExpression(e)) return e.elements.every((el) => !ts.isSpreadElement(el) && q(el));
  if (ts.isObjectLiteralExpression(e)) {
    return e.properties.every((p) => (ts.isPropertyAssignment(p) && propertyKey(p.name) !== null && q(p.initializer)) || (ts.isShorthandPropertyAssignment(p) && q(p.name)));
  }
  if (ts.isPrefixUnaryExpression(e)) return (e.operator === ts.SyntaxKind.ExclamationToken || e.operator === ts.SyntaxKind.MinusToken) && q(e.operand);
  if (ts.isTypeOfExpression(e)) return q(e.expression);
  if (ts.isConditionalExpression(e)) return q(e.condition) && q(e.whenTrue) && q(e.whenFalse);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    const reads =
      op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken ||
      op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken;
    return reads && q(e.left) && q(e.right);
  }
  if (ts.isNewExpression(e)) return ts.isIdentifier(e.expression) && isQuietClass(e.expression, cx) && (e.arguments ?? []).every(q);
  if (ts.isCallExpression(e)) return isQuietCall(e, fn, cx, depth);
  return false;
}

function isQuietCall(call: ts.CallExpression, fn: Fn, cx: Ctx, depth: number): boolean {
  if ((call.flags & ts.NodeFlags.OptionalChain) !== 0) return false;
  // Making the client has its own rule for what it may be handed (configuration: nothing that runs).
  if (isClient(call, cx)) return true;
  if (!call.arguments.every((a) => isQuiet(a, fn, cx, depth))) return false;
  if (isNextHeaders(call, cx) || sessionRead(call, cx)) return true;
  const helper = helperOf(call, cx);
  if (helper) return proveFn(helper, "quiet", [], cx, depth + 1) !== null;
  const callee = stripParens(call.expression);
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return false;
  const name = callee.name.text;
  const object = stripParens(callee.expression);
  if (ts.isIdentifier(object) && declarationOf(object) === null) {
    if (object.text === "console") return isGlobal(object, cx.project) && /^(?:log|warn|error|info|debug)$/.test(name);
    if (object.text === "Response") return isGlobal(object, cx.project) && name === "json";
    const pkg = cx.project.packageImport(call.getSourceFile().fileName, object.text);
    return !!pkg && pkg.spec === "next/server" && pkg.name === "NextResponse" && name === "json";
  }
  // Reading the request this function was handed.
  if (isOwnParameter(object, fn)) return /^(?:text|json|formData)$/.test(name) && call.arguments.length === 0;
  if (ts.isPropertyAccessExpression(object) && object.name.text === "headers" && isOwnParameter(stripParens(object.expression), fn)) {
    return name === "get" && call.arguments.length === 1 && ts.isStringLiteralLike(call.arguments[0]);
  }
  return false;
}

function union(a: Proof, b: Proof): Proof {
  return { fails: new Set([...a.fails, ...b.fails]) };
}

/** Follows a variable to what it was set from, once: `const a = b, b = a` leads nowhere. */
function following<T>(cx: Ctx, init: ts.Expression, go: () => T): T | null {
  if (cx.project.followed.has(init)) return null;
  cx.project.followed.add(init);
  try {
    return go();
  } finally {
    cx.project.followed.delete(init);
  }
}

/**
 * Proof that an expression (or the field of it at `path`) can only be truthy for a verified request.
 *
 *   the session read                `(await sb.auth.getUser()).data.user`
 *   a project helper, itself proven `await currentMember(req)`, `(await deskAccess(req)).ok`
 *   a const set from one            `const { data: { user } } = await sb.auth.getUser()`
 *   `a && b`                        when either side is proven
 *   `a || b`, `a ?? b`, `c ? a : b` when BOTH sides are proven (an empty literal counts as proven)
 *   `!x`, `x === true`, `x !== null` through the condition rules below
 *
 * Anything else is not proven: a parameter, a `let`, a method's answer, a call that is not awaited, the whole
 * of an answer object.
 */
function proveValue(e: ts.Expression, path: string[], cx: Ctx, depth: number, awaitedHint = false): Proof | null {
  const { x, awaited } = peel(e, awaitedHint);
  const empty = emptyLiteral(x);
  // An empty literal is never truthy, so the claim holds of it whatever the path.
  if (empty) return { fails: new Set([path.length ? "other" : empty]) };
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return b ? following(cx, b.init, () => proveValue(b.init, [...b.prefix, ...path], cx, depth)) : null;
  }
  if ((x.flags & ts.NodeFlags.OptionalChain) !== 0 && !ts.isPropertyAccessExpression(x)) return null;
  // `who?.id` and `who.id` are both empty when `who` is.
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name)) return proveValue(x.expression, [x.name.text, ...path], cx, depth);
  if (ts.isElementAccessExpression(x) && ts.isStringLiteralLike(x.argumentExpression)) return proveValue(x.expression, [x.argumentExpression.text, ...path], cx, depth);
  if (ts.isObjectLiteralExpression(x)) {
    // `{ ok: false, res }` asked for `ok`. As a whole an object is always truthy, so it proves nothing; a
    // spread, a method, a getter or a computed key can put anything in any field.
    if (path.length === 0 || x.properties.some((p) => (!ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p)) || propertyKey(p.name) === null)) return null;
    const p = [...x.properties].reverse().find((q) => propertyKey(q.name) === path[0]);
    if (!p) return { fails: new Set<Empty>([path.length > 1 ? "other" : "undefined"]) };
    return proveValue(ts.isPropertyAssignment(p) ? p.initializer : (p as ts.ShorthandPropertyAssignment).name, path.slice(1), cx, depth);
  }
  if (ts.isCallExpression(x)) return proveCall(x, awaited, path, cx, depth);
  if (path.length > 0) return null;
  if (ts.isConditionalExpression(x)) {
    const a = proveValue(x.whenTrue, [], cx, depth);
    const b = a && proveValue(x.whenFalse, [], cx, depth);
    return a && b ? union(a, b) : null;
  }
  if (ts.isBinaryExpression(x)) {
    const op = x.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      const a = proveValue(x.left, [], cx, depth);
      const b = proveValue(x.right, [], cx, depth);
      if (a && b) return union(a, b);
      // Unverified means the proven side was empty. With the left proven the result IS the left; with only
      // the right proven the left may have stopped it at any empty value.
      if (a) return a;
      return b ? union(b, { fails: new Set<Empty>(["other"]) }) : null;
    }
    if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      const a = proveValue(x.left, [], cx, depth);
      const b = a && proveValue(x.right, [], cx, depth);
      return a && b ? union(a, b) : null;
    }
  }
  // `!x`, `x === true`, `x != null`: a yes/no that says yes only for the verified.
  if (ts.isPrefixUnaryExpression(x) || ts.isBinaryExpression(x)) return yesMeansVerified(x, cx, depth) ? { fails: new Set<Empty>(["false"]) } : null;
  return null;
}

function proveCall(call: ts.CallExpression, awaited: boolean, path: string[], cx: Ctx, depth: number): Proof | null {
  const callee = stripParens(call.expression);
  if (ts.isIdentifier(callee) && callee.text === "Boolean" && isGlobal(callee, cx.project) && call.arguments.length === 1 && path.length === 0) {
    return proveValue(call.arguments[0], [], cx, depth) ? { fails: new Set<Empty>(["false"]) } : null;
  }
  const helper = helperOf(call, cx);
  if (helper) {
    // The promise of an answer is always truthy; only the awaited answer says anything.
    return isAsync(helper) && !awaited ? null : proveFn(helper, "truthy", path, cx, depth + 1);
  }
  const read = awaited ? sessionRead(call, cx) : null;
  if (!read || path.length < read.length || !read.every((k, i) => path[i] === k)) return null;
  cx.project.checks++;
  // A field below the proven one (`user.id`) is truthy only when the proven one is.
  return { fails: new Set<Empty>([path.length === read.length ? "null" : "other"]) };
}

/** An expression that is never empty: a new object, an object or array written out, a response being built. */
function neverEmpty(e: ts.Expression, path: string[], depth = 0): boolean {
  const x = peel(e).x;
  if (path.length > 0) {
    if (!ts.isObjectLiteralExpression(x) || x.properties.some((p) => !ts.isPropertyAssignment(p) || propertyKey(p.name) === null)) return false;
    const p = [...x.properties].reverse().find((q) => propertyKey(q.name) === path[0]);
    return !!p && ts.isPropertyAssignment(p) && neverEmpty(p.initializer, path.slice(1), depth);
  }
  if (ts.isNewExpression(x) || ts.isObjectLiteralExpression(x) || ts.isArrayLiteralExpression(x) || x.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (ts.isStringLiteralLike(x)) return x.text.length > 0;
  if (ts.isCallExpression(x)) return /^(?:Response|NextResponse)\.json$/.test(x.expression.getText().replace(/\s+/g, ""));
  if (ts.isIdentifier(x) && depth < 2) {
    const b = boundTo(x);
    return !!b && neverEmpty(b.init, b.prefix, depth + 1);
  }
  return false;
}

/**
 * Proof of the opposite reading: the expression (at `path`) can only be EMPTY for a verified request, as in
 * `const a = await access(); if (a.error) return a.error`. Holds for a project helper every one of whose
 * returns to the unverified puts something that is never empty in that field.
 */
function proveEmptyMeansVerified(e: ts.Expression, path: string[], cx: Ctx, depth: number, awaitedHint = false): boolean {
  const { x, awaited } = peel(e, awaitedHint);
  if (neverEmpty(x, path)) return true;
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return !!b && !!following(cx, b.init, () => proveEmptyMeansVerified(b.init, [...b.prefix, ...path], cx, depth));
  }
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name) && (x.flags & ts.NodeFlags.OptionalChain) === 0) return proveEmptyMeansVerified(x.expression, [x.name.text, ...path], cx, depth);
  if (!ts.isCallExpression(x)) return false;
  const helper = helperOf(x, cx);
  return !!helper && (!isAsync(helper) || awaited) && proveFn(helper, "empty", path, cx, depth + 1) !== null;
}

const subset = (fails: Set<Empty>, of: Empty[]): boolean => [...fails].every((f) => of.includes(f));

/** `x === false`, `x == null`, `x !== true` ...: the value compared and the literal it is compared with. */
function comparison(e: ts.Expression): { value: ts.Expression; literal: "true" | Empty; equal: boolean; strict: boolean } | null {
  if (!ts.isBinaryExpression(e)) return null;
  const op = e.operatorToken.kind;
  const equal = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken;
  const unequal = op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
  if (!equal && !unequal) return null;
  const strict = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken;
  const literal = (x: ts.Expression): "true" | Empty | null => {
    const v = stripParens(x);
    return v.kind === ts.SyntaxKind.TrueKeyword ? "true" : emptyLiteral(v);
  };
  const right = literal(e.right);
  if (right) return { value: e.left, literal: right, equal, strict };
  const left = literal(e.left);
  return left ? { value: e.right, literal: left, equal, strict } : null;
}

/** The empty values a comparison with `literal` is true for. */
function covered(literal: Empty, strict: boolean): Empty[] {
  if (literal === "false") return strict ? ["false"] : [];
  return strict ? [literal] : ["null", "undefined"];
}

/** True when the condition can only be TRUE for a verified request. */
function yesMeansVerified(c: ts.Expression, cx: Ctx, depth: number): boolean {
  const e = stripParens(c);
  if (ts.isPrefixUnaryExpression(e)) return e.operator === ts.SyntaxKind.ExclamationToken && noMeansVerified(e.operand, cx, depth);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) return yesMeansVerified(e.left, cx, depth) || yesMeansVerified(e.right, cx, depth);
    if (op === ts.SyntaxKind.BarBarToken) return yesMeansVerified(e.left, cx, depth) && yesMeansVerified(e.right, cx, depth);
    const cmp = comparison(e);
    if (!cmp) return false;
    const p = proveValue(cmp.value, [], cx, depth);
    if (!p) return false;
    // `x === true` is true only for a truthy x. `x !== false` is true for everything but false, so it is
    // true only for the verified when false is all a failed check ever leaves.
    if (cmp.literal === "true") return cmp.equal && cmp.strict;
    return !cmp.equal && subset(p.fails, covered(cmp.literal, cmp.strict));
  }
  return proveValue(e, [], cx, depth) !== null;
}

/** True when the condition can only be FALSE for a verified request: the test a refusal hangs on. */
function noMeansVerified(c: ts.Expression, cx: Ctx, depth: number): boolean {
  const e = stripParens(c);
  if (ts.isPrefixUnaryExpression(e)) return e.operator === ts.SyntaxKind.ExclamationToken && yesMeansVerified(e.operand, cx, depth);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    // Every part of an `&&` has to turn the unverified away by itself: the other part can say no first.
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) return noMeansVerified(e.left, cx, depth) && noMeansVerified(e.right, cx, depth);
    if (op === ts.SyntaxKind.BarBarToken) {
      if (noMeansVerified(e.left, cx, depth) || noMeansVerified(e.right, cx, depth)) return true;
      return coveredTogether(e, cx, depth);
    }
    const cmp = comparison(e);
    if (!cmp) return false;
    const p = proveValue(cmp.value, [], cx, depth);
    if (!p) return false;
    if (cmp.literal === "true") return !cmp.equal && cmp.strict;
    return cmp.equal && subset(p.fails, covered(cmp.literal, cmp.strict));
  }
  return proveEmptyMeansVerified(e, [], cx, depth);
}

/** `who === null || who === undefined`: neither test catches every failure, the two together do. */
function coveredTogether(e: ts.BinaryExpression, cx: Ctx, depth: number): boolean {
  const parts: ts.Expression[] = [];
  const flatten = (x: ts.Expression): void => {
    const v = stripParens(x);
    if (ts.isBinaryExpression(v) && v.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      flatten(v.left);
      flatten(v.right);
    } else parts.push(v);
  };
  flatten(e);
  const byValue = new Map<string, { value: ts.Expression; covers: Empty[] }>();
  for (const part of parts) {
    const cmp = comparison(part);
    if (!cmp || !cmp.equal || cmp.literal === "true") continue;
    const key = stripParens(cmp.value).getText().replace(/\s+/g, "");
    const entry = byValue.get(key) ?? { value: cmp.value, covers: [] };
    entry.covers.push(...covered(cmp.literal, cmp.strict));
    byValue.set(key, entry);
  }
  for (const { value, covers } of byValue.values()) {
    const p = proveValue(value, [], cx, depth);
    if (p && subset(p.fails, covers)) return true;
  }
  return false;
}

/** Walks a function's statements by the grammar at the top of this section. */
class Walk {
  fails = new Set<Empty>();

  constructor(
    private cx: Ctx,
    private fn: Fn,
    private sense: Sense,
    private path: string[],
    private depth: number,
  ) {}

  private quiet(node: ts.Node | undefined): void {
    if (node && !isQuiet(node, this.fn, this.cx, this.depth)) throw new Unproven();
  }

  seq(statements: readonly ts.Statement[], gated: boolean): boolean {
    let g = gated;
    for (const s of statements) g = this.stmt(s, g);
    return g;
  }

  stmt(s: ts.Statement, gated: boolean): boolean {
    if (gated) return true;
    if (ts.isBlock(s)) return this.seq(s.statements, false);
    if (ts.isEmptyStatement(s) || ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s)) return false;
    if (ts.isIfStatement(s)) {
      this.quiet(s.expression);
      const yes = yesMeansVerified(s.expression, this.cx, this.depth);
      const no = noMeansVerified(s.expression, this.cx, this.depth);
      const afterThen = this.stmt(s.thenStatement, yes);
      const afterElse = s.elseStatement ? this.stmt(s.elseStatement, no) : no;
      return afterThen && afterElse;
    }
    if (ts.isTryStatement(s)) {
      // A catch receives whatever threw before the test, the guard's own refusal included: the code after
      // the `try` is past the test only when the catch leaves.
      if (s.finallyBlock || !s.catchClause) throw new Unproven();
      const afterTry = this.seq(s.tryBlock.statements, false);
      const afterCatch = this.seq(s.catchClause.block.statements, false);
      return afterTry && afterCatch;
    }
    if (ts.isReturnStatement(s)) {
      this.returns(s.expression);
      return true; // nothing runs past it
    }
    if (ts.isThrowStatement(s)) {
      const thrown = stripParens(s.expression);
      if (!ts.isNewExpression(thrown) && !(ts.isIdentifier(thrown) && isLocal(thrown))) throw new Unproven();
      this.quiet(thrown);
      return true;
    }
    if (ts.isVariableStatement(s)) {
      if ((s.declarationList.flags & ts.NodeFlags.Const) === 0) throw new Unproven();
      for (const d of s.declarationList.declarations) {
        if (!d.initializer || !plainBinding(d.name)) throw new Unproven();
        this.quiet(d.initializer);
      }
      return s.declarationList.declarations.some((d) => this.asserts(d.initializer!));
    }
    if (ts.isExpressionStatement(s)) {
      // A call made for its own sake: logging, or a helper that is quiet or throws for the unverified.
      if (!ts.isCallExpression(peel(s.expression).x)) throw new Unproven();
      this.quiet(s.expression);
      return this.asserts(s.expression);
    }
    throw new Unproven();
  }

  /** What an unverified request may be handed back, by what is being shown. */
  private returns(e: ts.Expression | undefined): void {
    this.quiet(e);
    if (e && this.asserts(e)) return;
    if (this.sense === "quiet") return;
    if (this.sense === "asserts") throw new Unproven();
    if (this.sense === "empty") {
      if (!e || !proveEmptyMeansVerified(e, this.path, this.cx, this.depth, isAsync(this.fn))) throw new Unproven();
      return;
    }
    if (!e) {
      this.fails.add("undefined");
      return;
    }
    const p = proveValue(e, this.path, this.cx, this.depth, isAsync(this.fn));
    if (!p) throw new Unproven();
    for (const f of p.fails) this.fails.add(f);
  }

  /** The body of `const check = () => <expression>` is its answer. */
  answer(e: ts.Expression): void {
    this.returns(e);
  }

  /**
   * Is the expression, as a whole, a call of a helper that throws unless the request is verified?
   * `await mustBeIn()` or `const who = await mustBeIn()`: nothing wrapped around the call, so it is sure to run.
   */
  private asserts(e: ts.Expression): boolean {
    const { x, awaited } = peel(e);
    if (!ts.isCallExpression(x)) return false;
    const helper = helperOf(x, this.cx);
    return !!helper && (!isAsync(helper) || awaited) && proveFn(helper, "asserts", [], this.cx, this.depth + 1) !== null;
  }
}

/**
 * Shows one thing about a project function by walking its body (see Walk): that its answer at `path` is
 * truthy only for a verified request, empty only for one, that it returns at all only for one, or just that
 * it keeps to the grammar. Answers are kept per function: nothing here depends on who is asking.
 */
function proveFn(fn: Fn, sense: Sense, path: string[], cx: Ctx, depth: number): Proof | null {
  const key = `${sense}\u0000${path.join("\u0000")}`;
  const memo = cx.project.proofMemo.get(fn)?.get(key);
  if (memo !== undefined) {
    if (memo) cx.project.checks += memo.checks;
    return memo;
  }
  // Calling a generator runs none of its body; a default value runs with the call.
  if (!fn.body || fn.asteriskToken || fn.parameters.some((p) => p.initializer || p.dotDotDotToken || !plainBinding(p.name))) return null;
  if (depth > MAX_PROOF_DEPTH || cx.project.proofActive.has(fn)) {
    cx.project.cuts++;
    return null;
  }
  const cuts = cx.project.cuts;
  const checks = cx.project.checks;
  cx.project.proofActive.add(fn);
  let result: (Proof & { checks: number }) | null = null;
  try {
    const walk = new Walk(cx, fn, sense, path, depth);
    let gatedAtEnd = true;
    if (ts.isBlock(fn.body)) gatedAtEnd = walk.seq(fn.body.statements, false);
    else walk.answer(fn.body);
    // Running off the end answers `undefined`: fine for "truthy" and "quiet", not for the other two.
    if (sense === "truthy") result = { fails: gatedAtEnd ? walk.fails : new Set<Empty>([...walk.fails, "undefined"]), checks: 0 };
    else if (sense === "quiet" || gatedAtEnd) result = { fails: new Set(), checks: 0 };
  } catch (err) {
    if (!(err instanceof Unproven)) {
      cx.project.proofActive.delete(fn);
      throw err;
    }
  }
  cx.project.proofActive.delete(fn);
  if (result) result.checks = cx.project.checks - checks;
  // A "no" reached while a cycle or the depth limit cut the walk short is not final.
  if (result || cuts === cx.project.cuts) {
    const byKey = cx.project.proofMemo.get(fn) ?? new Map<string, (Proof & { checks: number }) | null>();
    byKey.set(key, result);
    cx.project.proofMemo.set(fn, byKey);
  }
  return result;
}

/**
 * The handler keeps to the grammar: everything it does for a request that has not passed a test of a proven
 * value is quiet, and a session read is somewhere in the proof.
 */
function verifiedRequest(handler: Fn, cx: Ctx): boolean {
  if (!handler.body || !ts.isBlock(handler.body)) return false;
  const checks = cx.project.checks;
  return proveFn(handler, "quiet", [], cx, 0) !== null && cx.project.checks > checks;
}

// ---------------------------------------------------------------------------
// Following a value: URL token -> hash, visitor address -> limit, body -> rejection
// ---------------------------------------------------------------------------

interface Taint {
  /** Variables (by declaration) that carry the value. */
  whole: Set<ts.Identifier>;
  /** Fields that carry it, when only some fields of an object do: declaration -> field names. */
  members: Map<ts.Identifier, Set<string>>;
  /** Expressions that produce it. */
  nodes: Set<ts.Node>;
}

const emptyTaint = (): Taint => ({ whole: new Set(), members: new Map(), nodes: new Set() });

function addField(t: Taint, object: ts.Identifier, field: string): void {
  const fields = t.members.get(object) ?? new Set<string>();
  fields.add(field);
  t.members.set(object, fields);
}

function isCarrier(id: ts.Identifier, t: Taint): boolean {
  if (t.whole.size === 0) return false;
  const d = declarationOf(id);
  return d !== null && t.whole.has(d);
}

function carryingFields(t: Taint, object: ts.Identifier): string[] {
  if (t.members.size === 0) return [];
  const d = declarationOf(object);
  return d ? [...(t.members.get(d) ?? [])] : [];
}

/** How far "carries the value" reaches: not through calls, through any call, or only through calls that are not awaited. */
type Through = boolean | "sync";

/**
 * Does the expression carry the value? With `throughCalls` off, the result of an ordinary call is a new
 * value (`f(token)` is not the token); with it on, anything computed from the value counts. "sync" stops at
 * awaited calls: `isEmail(x)` says something about x, while `await db.insert(x)` says whether the database
 * took it, which is the store's outcome and not a check of what was sent.
 */
function carries(e: ts.Node, t: Taint, throughCalls: Through): boolean {
  if (t.nodes.has(e)) return true;
  if (ts.isIdentifier(e)) return !isPropertyName(e) && isCarrier(e, t);
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression) && carryingFields(t, e.expression).includes(e.name.text)) return true;
  if (ts.isCallExpression(e) && !throughCalls && !isCoercion(e)) return false;
  if (throughCalls === "sync" && ts.isAwaitExpression(e)) {
    const awaited = unwrap(e.expression);
    if (ts.isCallExpression(awaited) && !isCoercion(awaited)) return false;
  }
  if (isFn(e)) return false;
  return ts.forEachChild(e, (c) => carries(c, t, throughCalls) || undefined) ?? false;
}

/** Variables set from the value carry it too, whether declared with it or assigned it later. */
function spread(fn: Fn, t: Taint, throughCalls: Through): void {
  if (!fn.body) return;
  each(fn.body, (n) => {
    if (ts.isVariableDeclaration(n) && n.initializer && carries(n.initializer, t, throughCalls)) {
      for (const b of bindingIdentifiers(n.name)) t.whole.add(b);
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && carries(n.right, t, throughCalls)) {
      const d = declarationOf(n.left);
      if (d) t.whole.add(d);
    }
  });
}

/** What the callee's parameters carry, given what the call's arguments carry. Null when they carry nothing. */
function intoCallee(call: ts.CallExpression, target: Fn, t: Taint): Taint | null {
  const next = emptyTaint();
  let any = false;
  call.arguments.forEach((raw, i) => {
    const param = target.parameters[i];
    if (!param || param.dotDotDotToken) return;
    const arg = unwrap(raw);
    if (ts.isObjectLiteralExpression(arg)) {
      for (const prop of arg.properties) {
        const key = prop.name && ts.isIdentifier(prop.name) ? prop.name.text : null;
        const carried =
          (ts.isPropertyAssignment(prop) && carries(prop.initializer, t, false)) || (ts.isShorthandPropertyAssignment(prop) && isCarrier(prop.name, t));
        if (!key || !carried) continue;
        any = true;
        if (ts.isIdentifier(param.name)) addField(next, param.name, key);
        else if (ts.isObjectBindingPattern(param.name)) {
          for (const el of param.name.elements) {
            const from = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : null;
            if (from === key) for (const b of bindingIdentifiers(el.name)) next.whole.add(b);
          }
        }
      }
    } else if (carries(arg, t, false)) {
      any = true;
      for (const b of bindingIdentifiers(param.name)) next.whole.add(b);
    } else if (ts.isIdentifier(arg) && ts.isIdentifier(param.name)) {
      // An object passed along whole keeps its carrying fields: `f(input)` after `input.visitor` carried.
      for (const field of carryingFields(t, arg)) {
        any = true;
        addField(next, param.name, field);
      }
    }
  });
  return any ? next : null;
}

function callCarries(call: ts.CallExpression, t: Taint): boolean {
  return call.arguments.some((raw) => {
    const arg = unwrap(raw);
    if (ts.isIdentifier(arg) && carryingFields(t, arg).length > 0) return true;
    if (!ts.isObjectLiteralExpression(arg)) return carries(arg, t, false);
    return arg.properties.some(
      (p) => (ts.isPropertyAssignment(p) && carries(p.initializer, t, false)) || (ts.isShorthandPropertyAssignment(p) && isCarrier(p.name, t)),
    );
  });
}

interface Sink {
  throughCalls: Through;
  hit(fn: Fn, t: Taint, project: Project, entry: string): boolean;
}

/** Follows the value from `fn` into the functions it is passed to until `sink` sees it used. */
function reaches(fn: Fn, t: Taint, sink: Sink, project: Project, entry: string, hops: number, seen: Set<Fn>): boolean {
  seen.add(fn);
  spread(fn, t, sink.throughCalls);
  if (sink.hit(fn, t, project, entry)) return true;
  if (hops <= 0 || !fn.body) return false;
  for (const call of callsIn([fn.body])) {
    if (isCoercion(call) || !callCarries(call, t)) continue;
    const targets = project.resolveCall(call, entry).filter((x) => !seen.has(x));
    if (targets.length === 0) continue;
    const all = targets.every((target) => {
      const next = intoCallee(call, target, t);
      return next !== null && reaches(target, next, sink, project, entry, hops - 1, seen);
    });
    if (all) return true;
  }
  return false;
}

/**
 * True when a condition only asks whether the value is there at all (`!input`, `input == null`,
 * `typeof input !== "object"`). That says nothing about what the value holds.
 */
function onlyPresence(condition: ts.Expression, t: Taint): boolean {
  const refs: ts.Identifier[] = [];
  each(condition, (n) => {
    if (ts.isIdentifier(n) && !isPropertyName(n) && isCarrier(n, t)) refs.push(n);
  });
  if (refs.length === 0) return false;
  const logical = (k: ts.SyntaxKind) => k === ts.SyntaxKind.BarBarToken || k === ts.SyntaxKind.AmpersandAmpersandToken;
  const empty = (e: ts.Expression) => {
    const v = unwrap(e);
    return v.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(v) && v.text === "undefined") || (ts.isStringLiteralLike(v) && /^(?:object|undefined)$/.test(v.text));
  };
  return refs.every((id) => {
    let cur: ts.Node = id;
    for (;;) {
      if (cur === condition) return true;
      const p = cur.parent;
      if (ts.isParenthesizedExpression(p) || ts.isTypeOfExpression(p)) cur = p;
      else if (ts.isPrefixUnaryExpression(p) && p.operator === ts.SyntaxKind.ExclamationToken) cur = p;
      else if (ts.isBinaryExpression(p) && logical(p.operatorToken.kind)) cur = p;
      else if (ts.isBinaryExpression(p) && /^[!=]==?$/.test(p.operatorToken.getText()) && empty(p.left === cur ? p.right : p.left)) cur = p;
      else return false;
    }
  });
}

/**
 * `if (input.dryRun) return` leaves when a flag that was sent is set. A caller who leaves the flag out is
 * not turned away, so it is a switch, unlike `if (!input.email) return` (a required field), a comparison,
 * or a test of something worked out from the input (`if (problem) return`).
 */
function isSwitch(s: ts.IfStatement): boolean {
  const c = unwrap(s.expression);
  const root = ts.isIdentifier(c) ? c : ts.isPropertyAccessExpression(c) && ts.isIdentifier(c.expression) ? c.expression : null;
  if (!root || (s.elseStatement && refuses(s.elseStatement))) return false;
  let d: ts.Node | null = declarationOf(root);
  while (d && (ts.isIdentifier(d) || ts.isBindingElement(d) || ts.isObjectBindingPattern(d) || ts.isArrayBindingPattern(d))) d = d.parent;
  return !!d && ts.isParameter(d);
}

// Objects whose `parse` reads a format. It answers "is this JSON", never "is this what we accept".
const FORMAT_READERS = /^(?:JSON|JSON5|Date|Number|Math|qs|querystring|url|URL|path|cookie|cookies|YAML|yaml|superjson|Papa|csv|xml|ini|toml|dotenv)$/;

/** The function turns the request away depending on what the value holds, or runs the value through a schema. */
const rejection: Sink = {
  throughCalls: "sync",
  hit(fn, t, project, entry) {
    if (!fn.body) return false;
    let found = false;
    each(fn.body, (n) => {
      if (found) return;
      if (ts.isIfStatement(n) && ifRefuses(n) && carries(n.expression, t, "sync") && !onlyPresence(n.expression, t) && !isSwitch(n)) found = true;
      if (ts.isCallExpression(n) && /^(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync)$/.test(calleeName(n)) && n.arguments.some((a) => carries(a, t, true))) {
        const callee = unwrap(n.expression);
        // `JSON.parse(raw)` reads a format and accepts anything in it.
        if (ts.isPropertyAccessExpression(callee) && FORMAT_READERS.test(callee.expression.getText())) return;
        // The project's own `parse(x)` is judged by what it does (it is followed), not by its name.
        if (ts.isIdentifier(callee) && project.resolveCall(n, entry).length > 0) return;
        found = true;
      }
    });
    return found;
  },
};

// ---------------------------------------------------------------------------
// Entry points for rules
// ---------------------------------------------------------------------------

function findHandler(sf: ts.SourceFile, method: string): Fn | null {
  for (const s of sf.statements) {
    const exported = ts.canHaveModifiers(s) && (ts.getModifiers(s)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(s) && s.body && s.name?.text === method) return declaredFn(s.name);
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text === method) return declaredFn(d.name);
      }
    }
  }
  return null;
}

export type HandlerGuard = "verified-request";

/**
 * "verified-request" when a mutation handler is shown to be gated by a session read that is not written in
 * the route file itself (see the grammar above), or null. Null means "not proven", never "open": the
 * finding stays, as it would have without this module.
 */
export function handlerGuard(model: ProjectModel, endpoint: ApiEndpoint): HandlerGuard | null {
  try {
    const project = projectFor(model);
    const sf = project.source(resolve(endpoint.file));
    const handler = sf ? findHandler(sf, endpoint.method) : null;
    return handler && verifiedRequest(handler, { project }) ? "verified-request" : null;
  } catch {
    return null;
  }
}

/** A `?:` (or a chain of them) whose every outcome is a literal written in the code. */
function picksLiteral(e: ts.Expression, top = true): boolean {
  const x = unwrap(e);
  if (ts.isConditionalExpression(x)) return picksLiteral(x.whenTrue, false) && picksLiteral(x.whenFalse, false);
  if (top) return false;
  return (
    ts.isStringLiteralLike(x) || ts.isNumericLiteral(x) || x.kind === ts.SyntaxKind.NullKeyword || x.kind === ts.SyntaxKind.TrueKeyword ||
    x.kind === ts.SyntaxKind.FalseKeyword || (ts.isIdentifier(x) && x.text === "undefined")
  );
}

/**
 * True when every function the request body is handed to refuses based on what it was given. Validation
 * written in a helper is still validation; a helper that just stores the value is not.
 */
export function bodyCheckedDownstream(model: ProjectModel, endpoint: ApiEndpoint): boolean {
  try {
    const project = projectFor(model);
    const entry = resolve(endpoint.file);
    const sf = project.source(entry);
    const handler = sf ? findHandler(sf, endpoint.method) : null;
    const req = handler?.parameters[0];
    if (!handler?.body || !req || !ts.isIdentifier(req.name)) return false;

    const body = emptyTaint();
    const reads = new RegExp(`\\b${req.name.text}\\s*\\.\\s*(?:json|formData|text)\\s*\\(`);
    each(handler.body, (n) => {
      if (ts.isVariableDeclaration(n) && n.initializer && reads.test(n.initializer.getText())) for (const b of bindingIdentifiers(n.name)) body.whole.add(b);
      // `let body; try { body = await req.json() } catch { ... }`
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && reads.test(n.right.getText())) {
        const d = declarationOf(n.left);
        if (d) body.whole.add(d);
      }
    });
    if (!body.whole.size) return false;
    spread(handler, body, false);

    // `const reason = b.reason === "a" ? "a" : b.reason === "b" ? "b" : null` holds one of the values written
    // in the code, never what was sent. Such a variable no longer carries the body.
    const picked = new Set<ts.Identifier>();
    each(handler.body, (n) => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && body.whole.has(n.name) && n.initializer && picksLiteral(n.initializer)) picked.add(n.name);
    });
    for (const d of picked) body.whole.delete(d);

    const handedTo = callsIn([handler.body]).filter((c) => !isCoercion(c) && callCarries(c, body));
    if (handedTo.length === 0) {
      // Nothing that was sent reaches any call. That is a checked body only when the handler picked its
      // values from the code's own list and turns away a request that matched none of them; a body copied
      // field by field into an object (`row.email = b.email`), written into a tagged statement or handed to
      // a constructor has gone somewhere this does not follow.
      let copied = false;
      let refused = false;
      each(handler.body, (n) => {
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && !ts.isIdentifier(n.left) && carries(n.right, body, false)) copied = true;
        if (ts.isTaggedTemplateExpression(n) && carries(n.template, body, false)) copied = true;
        if (ts.isNewExpression(n) && (n.arguments ?? []).some((a) => carries(a, body, false))) copied = true;
        if (!ts.isIfStatement(n) || !ifRefuses(n)) return;
        each(n.expression, (c) => {
          if (!ts.isIdentifier(c) || isPropertyName(c)) return;
          const d = declarationOf(c);
          if (d && picked.has(d)) refused = true;
        });
      });
      return refused && !copied;
    }
    return handedTo.every((call) => {
      const targets = project.resolveCall(call, entry);
      return (
        targets.length > 0 &&
        targets.every((target) => {
          const next = intoCallee(call, target, body);
          return next !== null && reaches(target, next, rejection, project, entry, MAX_HOPS - 1, new Set());
        })
      );
    });
  } catch {
    return false;
  }
}

/**
 * True when an expression is text fixed in the source: a literal, a template or concatenation of fixed
 * parts, or a `const` (here or imported) set to one. Anything from a parameter, prop or call is not.
 */
export function isFixedText(e: ts.Expression, project: Project, hops = 4): boolean {
  const x = unwrap(e);
  if (ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x) || ts.isNumericLiteral(x)) return true;
  if (ts.isTemplateExpression(x)) return x.templateSpans.every((s) => isFixedText(s.expression, project, hops));
  if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken) return isFixedText(x.left, project, hops) && isFixedText(x.right, project, hops);
  if (ts.isIdentifier(x) && hops > 0) {
    // Scope decides what the name means here. A parameter, a destructured prop or a `let` of that name is
    // not the constant, whatever else the file declares.
    const local = declarationOf(x);
    if (local) {
      const d = local.parent;
      const fixed = ts.isVariableDeclaration(d) && d.name === local && !!d.initializer && (d.parent.flags & ts.NodeFlags.Const) !== 0;
      return fixed && isFixedText(d.initializer!, project, hops - 1);
    }
    const c = project.constant(x.getSourceFile().fileName, x.text);
    return c !== null && isFixedText(c.value, project, hops - 1);
  }
  return false;
}

/** The source text of the function around a line (or the line itself at the top level), with its name. */
export function enclosingFunctionText(project: Project, file: string, line: number): string | null {
  const sf = project.source(file);
  if (!sf) return null;
  const pos = sf.getPositionOfLineAndCharacter(line - 1, 0);
  const lineEnd = line < sf.getLineStarts().length ? sf.getLineStarts()[line] : sf.text.length;
  const around: ts.Node[] = [];
  each(sf, (n) => {
    if (isFn(n) && n.getStart() < lineEnd && n.getEnd() >= pos) around.push(n);
  });
  if (around.length === 0) return sf.text.slice(pos, lineEnd);
  const fn = around.reduce((a, b) => (b.getEnd() - b.getStart() < a.getEnd() - a.getStart() ? b : a));
  // `const name = () => ...` and `name: () => ...` carry the name outside the function node.
  const holder = ts.isVariableDeclaration(fn.parent) || ts.isPropertyAssignment(fn.parent) || ts.isPropertyDeclaration(fn.parent) ? fn.parent : fn;
  return holder.getText();
}

/** The name a function is known by, when the line sits in a small named helper: `const md5 = (s) => ...`. */
export function enclosingFunctionName(project: Project, file: string, line: number): string | null {
  const sf = project.source(file);
  if (!sf) return null;
  const pos = sf.getPositionOfLineAndCharacter(line - 1, 0);
  const lineEnd = line < sf.getLineStarts().length ? sf.getLineStarts()[line] : sf.text.length;
  const around: Fn[] = [];
  each(sf, (n) => {
    if (isFn(n) && n.getStart() < lineEnd && n.getEnd() >= pos) around.push(n);
  });
  if (around.length === 0) return null;
  const fn = around.reduce((a, b) => (b.getEnd() - b.getStart() < a.getEnd() - a.getStart() ? b : a));
  if ((ts.isFunctionDeclaration(fn) || ts.isMethodDeclaration(fn)) && fn.name && ts.isIdentifier(fn.name)) return fn.name.text;
  const holder = fn.parent;
  if ((ts.isVariableDeclaration(holder) || ts.isPropertyAssignment(holder) || ts.isPropertyDeclaration(holder)) && ts.isIdentifier(holder.name)) return holder.name.text;
  return null;
}

/**
 * What each call of the function `name` (declared in `declaredIn`) says about its use: the calling line and
 * the name of the function it sits in, for that file and files that import it. A general helper means what
 * its callers use it for.
 */
export function callerTexts(project: Project, declaredIn: string, name: string, files: Array<{ file: string; source: string }>): string[] {
  const out: string[] = [];
  const home = resolve(declaredIn);
  const calls = new RegExp(`\\b${name}\\s*\\(`);
  for (const { file, source } of files) {
    if (!calls.test(source)) continue;
    const abs = resolve(file);
    if (abs !== home) {
      const imported = project.importOf(abs, name);
      if (!imported || project.resolveModule(abs, imported.spec) !== home) continue;
    }
    source.split("\n").forEach((text, idx) => {
      if (!calls.test(text)) return;
      if (abs === home && enclosingFunctionName(project, abs, idx + 1) === name) return; // the helper itself
      // The call's own line and the name of the function it is in: `hashPassword` / `md5(password)`.
      // The whole calling function would be too much; a long one mentions everything.
      out.push(`${enclosingFunctionName(project, abs, idx + 1) ?? ""} ${text}`);
    });
  }
  return out;
}
