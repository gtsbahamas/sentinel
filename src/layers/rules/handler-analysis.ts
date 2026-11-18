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

// Libraries whose whole job is to answer "is this request who it says it is".
const AUTH_PACKAGES = /^(?:twilio|stripe|svix|jose|jsonwebtoken|next-auth|@auth\/|@clerk\/|better-auth|@octokit\/webhooks|@supabase\/ssr)/;
const AUTH_CALLS = new Set(["validateRequest", "validateRequestWithBody", "jwtVerify", "verify", "getServerSession", "getToken", "auth", "currentUser"]);

const CLIENT_ADDRESS = /x-forwarded-for|x-real-ip|x-vercel-forwarded-for|cf-connecting-ip|true-client-ip|fly-client-ip/i;
const SERVICE_ROLE = /SERVICE_ROLE|service_role|auth\s*\.\s*admin\b/;
const DATA_WRITE = /\.from\s*\(\s*["'`][\w.-]+["'`]\s*\)[\s\S]{0,300}?\.(?:insert|update|upsert|delete)\s*\(|\.rpc\s*\(|\bauth\s*\.\s*admin\b/;

// ---------------------------------------------------------------------------
// Project: parsed files, import resolution, declarations
// ---------------------------------------------------------------------------

export class Project {
  readonly root: string;
  private texts = new Map<string, string | null>();
  private parsed = new Map<string, ts.SourceFile | null>();
  private closures = new Map<string, string[]>();
  private methods = new Map<string, Fn[]>();
  private aliases: Array<{ prefix: string; suffix: string; targets: string[] }> | null = null;
  readonly guardMemo = new Map<Fn, boolean>();

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
        : ts.createSourceFile(abs, text, ts.ScriptTarget.Latest, true, /\.[jt]sx$/.test(abs) ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
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
        if (s.name?.text === name || (name === "default" && isDefault)) return s;
      }
      if (ts.isVariableStatement(s)) {
        for (const d of s.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer) {
            const init = unwrap(d.initializer);
            if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
          }
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

  /** A top-level `const name = <expression>` in `file`, or the same through an import. */
  constant(file: string, name: string, hops = 3): { file: string; value: ts.Expression } | null {
    const sf = this.source(file);
    if (!sf || hops < 0) return null;
    const found: ts.Expression[] = [];
    let other = false;
    each(sf, (n) => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name) {
        const isConst = (n.parent.flags & ts.NodeFlags.Const) !== 0;
        if (isConst && n.initializer) found.push(n.initializer);
        else other = true;
      }
      if (ts.isParameter(n) && bindingNames(n.name).includes(name)) other = true;
    });
    // One const and nothing else by that name: no shadowing to reason about.
    if (found.length === 1 && !other) return { file, value: found[0] };
    if (found.length || other) return null;
    const imported = this.importOf(file, name);
    if (!imported || imported.namespace) return null;
    const target = this.resolveModule(file, imported.spec);
    return target ? this.constant(target, imported.name, hops - 1) : null;
  }

  /** Methods and function-valued properties called `name` in the files `entry` reaches. */
  methodsNamed(entry: string, name: string): Fn[] {
    const key = `${entry}\u0000${name}`;
    const cached = this.methods.get(key);
    if (cached) return cached;
    const out: Fn[] = [];
    for (const file of this.closure(entry)) {
      if (!this.text(file)?.includes(name)) continue;
      const sf = this.source(file);
      if (!sf) continue;
      each(sf, (n) => {
        if (ts.isMethodDeclaration(n) && n.body && ts.isIdentifier(n.name) && n.name.text === name) out.push(n);
        if ((ts.isPropertyAssignment(n) || ts.isPropertyDeclaration(n)) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer) {
          const init = unwrap(n.initializer);
          if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) out.push(init);
        }
      });
    }
    this.methods.set(key, out);
    return out;
  }

  /**
   * The project functions a call may run. Empty when it cannot be known: a package, a parameter, a platform
   * method, or more candidates than can be checked. With several candidates, callers require ALL to hold.
   */
  resolveCall(call: ts.CallExpression, entry: string): Fn[] {
    const file = call.getSourceFile().fileName;
    const callee = unwrap(call.expression);
    if (ts.isIdentifier(callee)) {
      if (isParameterInScope(call, callee.text)) return [];
      const nested = nestedFunction(call, callee.text);
      if (nested) return [nested];
      const found = this.lookup(file, callee.text);
      return found ? [found] : [];
    }
    if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return [];
    const name = callee.name.text;
    const object = unwrap(callee.expression);
    if (object.kind === ts.SyntaxKind.ThisKeyword) {
      const cls = enclosing(call, ts.isClassLike);
      const m = cls?.members.find((x): x is ts.MethodDeclaration => ts.isMethodDeclaration(x) && !!x.body && ts.isIdentifier(x.name) && x.name.text === name);
      return m ? [m] : [];
    }
    if (ts.isIdentifier(object)) {
      const imported = this.importOf(file, object.text);
      if (imported?.namespace) {
        const target = this.resolveModule(file, imported.spec);
        const found = target ? this.lookup(target, name) : null;
        return found ? [found] : [];
      }
      if (imported && !this.resolveModule(file, imported.spec)) return []; // a package's object
    }
    if (PLATFORM_METHODS.has(name)) return [];
    const candidates = this.methodsNamed(entry, name);
    return candidates.length > 0 && candidates.length <= MAX_METHOD_CANDIDATES ? candidates : [];
  }
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

/** What a variable was initialised from, when the identifier refers to a variable. */
function initializerOf(id: ts.Identifier): ts.Expression | null {
  let cur: ts.Node | undefined = declarationOf(id) ?? undefined;
  while (cur && (ts.isIdentifier(cur) || ts.isBindingElement(cur) || ts.isObjectBindingPattern(cur) || ts.isArrayBindingPattern(cur))) cur = cur.parent;
  return cur && ts.isVariableDeclaration(cur) ? (cur.initializer ?? null) : null;
}

function isParameterInScope(node: ts.Node, name: string): boolean {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (isFn(cur) && cur.parameters.some((p) => bindingNames(p.name).includes(name))) return true;
  }
  return false;
}

/** A function declared inside one of the functions around `node`. */
function nestedFunction(node: ts.Node, name: string): Fn | null {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (!isFn(cur) || !cur.body) continue;
    const found: Fn[] = [];
    each(cur.body, (n) => {
      if (ts.isFunctionDeclaration(n) && n.body && n.name?.text === name) found.push(n);
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer) {
        const init = unwrap(n.initializer);
        if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) found.push(init);
      }
    });
    if (found.length) return found[0];
  }
  return null;
}

/** True when the statement can leave the function: it holds a return or a throw of its own. */
function leaves(node: ts.Node, only?: ts.SyntaxKind): boolean {
  let out = false;
  const walk = (n: ts.Node) => {
    if (out || isFn(n)) return;
    if (only ? n.kind === only : ts.isReturnStatement(n) || ts.isThrowStatement(n)) out = true;
    else ts.forEachChild(n, walk);
  };
  walk(node);
  return out;
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
    if (props.length === e.properties.length && props.every((p) => constant(p.initializer))) return true;
    if (props.some((p) => unwrap(p.initializer).kind === ts.SyntaxKind.FalseKeyword || /^errors?$/.test(p.name.getText()))) return true;
  }
  return /\b4\d\d\b/.test(e.getText());
}

function ifRefuses(s: ts.IfStatement): boolean {
  return refuses(s.thenStatement) || (!!s.elseStatement && refuses(s.elseStatement));
}

function ifLeaves(s: ts.IfStatement, only?: ts.SyntaxKind): boolean {
  return leaves(s.thenStatement, only) || (!!s.elseStatement && leaves(s.elseStatement, only));
}

/**
 * The expressions that decide what a function does next: the conditions of ifs that can leave it and, for
 * a helper (whose answer its caller acts on), the conditions of `?:` and what it returns. Local variables in them are replaced by what they
 * were set from, so `const t = await guard(req); if (!t.ok) return` leads back to the guard call.
 */
function decisions(fn: Fn, asHelper: boolean, only?: ts.SyntaxKind): ts.Node[] {
  const withReturns = asHelper;
  const out: ts.Node[] = [];
  if (!fn.body) return out;
  if (withReturns && !ts.isBlock(fn.body)) out.push(fn.body);
  each(fn.body, (n) => {
    if (ts.isIfStatement(n) && ifLeaves(n, only)) out.push(n.expression);
    if (asHelper && !only && ts.isConditionalExpression(n)) out.push(n.condition);
    if (withReturns && ts.isReturnStatement(n) && n.expression && enclosing(n, isFn) === fn) out.push(n.expression);
  });
  const added = new Set<ts.Node>(out);
  for (let i = 0; i < out.length && out.length < 200; i++) {
    each(out[i], (n) => {
      if (!ts.isIdentifier(n) || isPropertyName(n)) return;
      const init = initializerOf(n);
      if (init && !added.has(init)) {
        added.add(init);
        out.push(init);
      }
    });
  }
  return out;
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
// Verified requests: signatures, sealed values, sessions
// ---------------------------------------------------------------------------

/** A call that itself decides whether the caller is genuine. */
function isVerification(call: ts.CallExpression, project: Project): boolean {
  const callee = unwrap(call.expression);
  const name = calleeName(call);
  if (name === "timingSafeEqual" || name === "constructEvent" || name === "constructEventAsync") return true;
  if (ts.isPropertyAccessExpression(callee)) {
    const object = callee.expression.getText();
    if (name === "verify" && /\bsubtle$/.test(object)) return true;
    if (/^(?:getUser|getSession|getClaims)$/.test(name) && /\bauth$/.test(object)) return true;
  }
  let rootId: ts.Expression = callee;
  while (ts.isPropertyAccessExpression(rootId) || ts.isCallExpression(rootId)) rootId = unwrap(rootId.expression);
  if (ts.isIdentifier(rootId) && AUTH_CALLS.has(name)) {
    const imported = project.importOf(call.getSourceFile().fileName, rootId.text);
    if (imported && AUTH_PACKAGES.test(imported.spec)) return true;
  }
  return false;
}

/**
 * True when a function's own outcome depends on a verification: one sits in a condition or in what it
 * returns, directly or through another such function. Computing a MAC is not enough; it has to be compared.
 */
function isGuardFn(fn: Fn, project: Project, entry: string, hops: number, active = new Set<Fn>()): boolean {
  const memo = project.guardMemo.get(fn);
  if (memo !== undefined) return memo;
  if (active.has(fn)) return false;
  active.add(fn);
  let result = false;
  const text = fn.getText();
  // Authenticated decryption: only a value sealed with the server's key opens.
  if (/\bcreateDecipheriv\s*\(/.test(text) && /\.setAuthTag\s*\(/.test(text)) result = true;
  if (!result) {
    for (const call of callsIn(decisions(fn, true))) {
      if (isVerification(call, project)) result = true;
      else if (hops > 0) {
        const targets = project.resolveCall(call, entry);
        result = targets.length > 0 && targets.every((t) => isGuardFn(t, project, entry, hops - 1, active));
      }
      if (result) break;
    }
  }
  active.delete(fn);
  // A "no" reached while part of a cycle was cut short is not final, so only top-level answers are kept.
  if (result || active.size === 0) project.guardMemo.set(fn, result);
  return result;
}

/** A helper that throws unless the caller is verified, so calling it is the guard. */
function isAssertFn(fn: Fn, project: Project, entry: string, hops: number): boolean {
  const throwing = decisions(fn, false, ts.SyntaxKind.ThrowStatement);
  for (const call of callsIn(throwing)) {
    if (isVerification(call, project)) return true;
    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every((t) => isGuardFn(t, project, entry, hops))) return true;
  }
  return false;
}

function verifiedRequest(handler: Fn, project: Project, entry: string): boolean {
  for (const call of callsIn(decisions(handler, false))) {
    if (isVerification(call, project)) return true;
    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every((t) => isGuardFn(t, project, entry, MAX_HOPS - 1))) return true;
  }
  if (!handler.body) return false;
  for (const call of callsIn([handler.body])) {
    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every((t) => isAssertFn(t, project, entry, MAX_HOPS - 1))) return true;
  }
  return false;
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
  hit(fn: Fn, t: Taint): boolean;
}

/** Follows the value from `fn` into the functions it is passed to until `sink` sees it used. */
function reaches(fn: Fn, t: Taint, sink: Sink, project: Project, entry: string, hops: number, seen: Set<Fn>): boolean {
  seen.add(fn);
  spread(fn, t, sink.throughCalls);
  if (sink.hit(fn, t)) return true;
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

/** The value is hashed, or compared in constant time: it is a secret being looked up, not an id. */
const hashedLookup: Sink = {
  throughCalls: false,
  hit(fn, t) {
    if (!fn.body) return false;
    return callsIn([fn.body]).some((call) => {
      const name = calleeName(call);
      const callee = unwrap(call.expression);
      const receiver = ts.isPropertyAccessExpression(callee) ? callee.expression.getText() : "";
      const hashing = (name === "update" && /\bcreateH(?:ash|mac)\s*\(/.test(receiver)) || (name === "digest" && /\bsubtle$/.test(receiver));
      const comparing = name === "timingSafeEqual";
      return (hashing || comparing) && call.arguments.some((a) => carries(a, t, true));
    });
  },
};

/** A count kept for this visitor is compared with a limit, and going over is refused. */
const visitorLimit: Sink = {
  throughCalls: false,
  hit(fn, t) {
    if (!fn.body) return false;
    const counts = new Set<ts.Node>();
    const countVars = new Set<ts.Identifier>();
    for (const call of callsIn([fn.body])) {
      if (!isCoercion(call) && call.arguments.some((a) => carries(a, t, true))) counts.add(call);
    }
    const holdsCount = (n: ts.Node): boolean => {
      let found = false;
      each(n, (c) => {
        if (found || counts.has(c)) found = true;
        else if (ts.isIdentifier(c) && countVars.size > 0 && !isPropertyName(c)) {
          const d = declarationOf(c);
          if (d && countVars.has(d)) found = true;
        }
      });
      return found;
    };
    each(fn.body, (n) => {
      if (ts.isVariableDeclaration(n) && n.initializer && holdsCount(n.initializer)) for (const b of bindingIdentifiers(n.name)) countVars.add(b);
    });
    let limited = false;
    each(fn.body, (n) => {
      if (limited || !ts.isIfStatement(n) || !ifRefuses(n)) return;
      each(n.expression, (c) => {
        if (!ts.isBinaryExpression(c)) return;
        const op = c.operatorToken.kind;
        const relational =
          op === ts.SyntaxKind.GreaterThanToken || op === ts.SyntaxKind.GreaterThanEqualsToken || op === ts.SyntaxKind.LessThanToken || op === ts.SyntaxKind.LessThanEqualsToken;
        if (relational && (holdsCount(c.left) || holdsCount(c.right))) limited = true;
      });
      // A limiter library answers yes/no instead of a number: `if (!success) return 429`.
      if (!limited && holdsCount(n.expression) && /\b429\b/.test(n.getText())) limited = true;
    });
    return limited;
  },
};

/** The function turns the request away depending on the value, or runs the value through a schema. */
const rejection: Sink = {
  throughCalls: "sync",
  hit(fn, t) {
    if (!fn.body) return false;
    let found = false;
    each(fn.body, (n) => {
      if (found) return;
      if (ts.isIfStatement(n) && ifRefuses(n) && carries(n.expression, t, "sync")) found = true;
      if (ts.isCallExpression(n) && /^(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync)$/.test(calleeName(n)) && n.arguments.some((a) => carries(a, t, true))) {
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
    if (ts.isFunctionDeclaration(s) && s.body && s.name?.text === method) return s;
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || d.name.text !== method || !d.initializer) continue;
        const init = unwrap(d.initializer);
        if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
      }
    }
  }
  return null;
}

/** The dynamic URL segments, as the handler's second argument hands them over. */
function urlParams(handler: Fn): Taint {
  const t = emptyTaint();
  const second = handler.parameters[1];
  if (!second) return t;
  if (ts.isIdentifier(second.name)) addField(t, second.name, "params");
  else for (const b of bindingIdentifiers(second.name)) t.whole.add(b);
  return t;
}

/** Expressions in the handler that produce the visitor's network address, or a key made from it. */
function visitorAddress(handler: Fn, project: Project, entry: string): Taint {
  const t = emptyTaint();
  if (!handler.body) return t;
  each(handler.body, (n) => {
    if (ts.isCallExpression(n)) {
      if (calleeName(n) === "get" && n.arguments[0] && CLIENT_ADDRESS.test(n.arguments[0].getText())) t.nodes.add(n);
      const targets = project.resolveCall(n, entry);
      if (targets.length > 0 && targets.every((f) => CLIENT_ADDRESS.test(f.getText()))) t.nodes.add(n);
    }
    if (ts.isPropertyAccessExpression(n) && n.name.text === "ip" && /^(?:req|request|_req)$/.test(n.expression.getText())) t.nodes.add(n);
  });
  return t;
}

/** Does the function, or anything it calls within `hops`, contain `what`? */
function withinReach(what: RegExp, fn: Fn, project: Project, entry: string, hops: number, seen = new Set<Fn>()): boolean {
  if (seen.has(fn)) return false;
  seen.add(fn);
  if (what.test(fn.getText())) return true;
  if (hops <= 0 || !fn.body) return false;
  return callsIn([fn.body]).some((call) => project.resolveCall(call, entry).some((t) => withinReach(what, t, project, entry, hops - 1, seen)));
}

export type HandlerGuard = "verified-request" | "link-token" | "visitor-limit";

/**
 * How a mutation handler is protected when the protection is not written in the route file itself, or
 * null when none can be shown.
 *
 *  verified-request  leaving the handler early depends on a signature check, a sealed value or a session
 *                    read, reached through the project's own helpers.
 *  link-token        a URL segment is hashed (or compared in constant time) before anything is looked up:
 *                    the link is the permission. A plain id never qualifies.
 *  visitor-limit     a public endpoint that counts requests per visitor address and refuses over a limit.
 *                    Never accepted for a route that works with the service role.
 */
export function handlerGuard(model: ProjectModel, endpoint: ApiEndpoint): HandlerGuard | null {
  try {
    const project = projectFor(model);
    const entry = resolve(endpoint.file);
    const sf = project.source(entry);
    const handler = sf ? findHandler(sf, endpoint.method) : null;
    if (!sf || !handler) return null;

    if (verifiedRequest(handler, project, entry)) return "verified-request";

    const params = urlParams(handler);
    if ((params.whole.size || params.members.size) && reaches(handler, params, hashedLookup, project, entry, MAX_HOPS, new Set())) return "link-token";

    const visitor = visitorAddress(handler, project, entry);
    if (visitor.nodes.size) {
      const walked = new Set<Fn>();
      if (reaches(handler, visitor, visitorLimit, project, entry, MAX_HOPS, walked)) {
        // A limit is not permission to write past row security. When the handler, or a helper within
        // two calls of it, writes to tables or calls auth.admin, and a service-role client is within the
        // same reach, the route stays reported.
        const writes = [...walked].some((f) => DATA_WRITE.test(f.getText())) || withinReach(DATA_WRITE, handler, project, entry, 2);
        const privileged = writes && (SERVICE_ROLE.test(sf.text) || withinReach(SERVICE_ROLE, handler, project, entry, 2));
        if (!privileged) return "visitor-limit";
      }
    }
    return null;
  } catch {
    return null;
  }
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

    const handedTo = callsIn([handler.body]).filter((c) => !isCoercion(c) && callCarries(c, body));
    if (handedTo.length === 0) return false;
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
    const c = project.constant(x.getSourceFile().fileName, x.text);
    return c !== null && isFixedText(c.value, project, hops - 1);
  }
  return false;
}

/**
 * True when an equality on this line finds a stored record by its key: one side is a field of the row being
 * iterated (`for (const s of rows) if (s.tokenHash === h)`, `rows.find((r) => r.tokenHash === h)`). That is
 * what a database index does, and its timing says nothing about the caller's secret. Comparing the iterated
 * value itself (`sigs.some((sig) => sig === expected)`) is a verification and is not matched.
 */
export function isRecordLookup(project: Project, file: string, line: number, mentions: RegExp): boolean {
  const sf = project.source(file);
  if (!sf) return false;
  const start = sf.getPositionOfLineAndCharacter(line - 1, 0);
  const end = line < sf.getLineStarts().length ? sf.getLineStarts()[line] : sf.text.length;
  const equalities: ts.BinaryExpression[] = [];
  each(sf, (n) => {
    if (!ts.isBinaryExpression(n) || n.getStart() < start || n.getStart() >= end) return;
    const op = n.operatorToken.kind;
    const equality =
      op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
    if (equality && mentions.test(n.getText())) equalities.push(n);
  });
  if (equalities.length === 0) return false;

  const iterated = (side: ts.Expression): boolean => {
    const s = unwrap(side);
    if (!ts.isPropertyAccessExpression(s) || !ts.isIdentifier(s.expression)) return false;
    const row = s.expression.text;
    for (let cur: ts.Node = s; cur.parent; cur = cur.parent) {
      const p = cur.parent;
      if ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && ts.isVariableDeclarationList(p.initializer)) {
        if (p.initializer.declarations.some((d) => bindingNames(d.name).includes(row))) return true;
      }
      if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && p.parameters.some((x) => bindingNames(x.name).includes(row))) {
        const call = p.parent;
        return ts.isCallExpression(call) && call.arguments.includes(p) && /^(?:find|findLast|findIndex|findLastIndex|filter|some|every)$/.test(calleeName(call));
      }
    }
    return false;
  };
  return equalities.every((b) => iterated(b.left) || iterated(b.right));
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
