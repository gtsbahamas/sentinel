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

interface Frame {
  call: ts.CallExpression;
  target: Fn;
  parent: Frame | null;
}

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

const SUCCESS_FIELD = /^(?:ok|success|succeeded|successful|valid|saved|done|accepted|created|updated)$/;
// Names every module can use without importing them; a function that touches nothing else keeps no state.
const PURE_GLOBALS = new Set("String Number Boolean Math JSON Array Object RegExp Buffer parseInt parseFloat isNaN isFinite undefined NaN Infinity encodeURIComponent decodeURIComponent".split(" "));
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
  private methods = new Map<string, { fns: Fn[]; unknown: boolean }>();
  private aliases: Array<{ prefix: string; suffix: string; targets: string[] }> | null = null;
  private deps: Set<string> | null = null;
  private getters = new Map<string, Set<string>>();
  /** The call being followed into a helper, innermost first: where a helper's parameters get their values. */
  frame: Frame | null = null;
  /** Counts answers that depended on a call site's arguments: those are not kept per function. */
  siteDependent = 0;
  // Proofs and "is inert" answers, kept per scan. `cuts` counts the times a walk was stopped short (depth,
  // a cycle): a "no" reached with one of those inside it is not final and is not kept.
  readonly proofMemo = new Map<Fn, Map<string, { fails: Set<"false" | "null" | "undefined" | "other"> } | null>>();
  readonly proofActive = new Set<Fn>();
  readonly inertMemo = new Map<Fn, boolean>();
  readonly inertActive = new Set<Fn>();
  cuts = 0;
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

  /** Names of getters declared in the files `entry` reaches: reading such a property runs code. */
  gettersIn(entry: string): Set<string> {
    const cached = this.getters.get(entry);
    if (cached) return cached;
    const out = new Set<string>();
    for (const file of this.closure(entry)) {
      if (!/\bget\s|defineProperty|Proxy/.test(this.text(file) ?? "")) continue;
      const sf = this.source(file);
      if (!sf) continue;
      each(sf, (n) => {
        if (ts.isGetAccessorDeclaration(n)) out.add(propertyKey(n.name) ?? "*");
        if (ts.isIdentifier(n) && (n.text === "defineProperty" || n.text === "defineProperties" || n.text === "Proxy")) out.add("*");
      });
    }
    this.getters.set(entry, out);
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

/** What a variable was initialised from, when the identifier refers to a variable. */
function initializerOf(id: ts.Identifier): ts.Expression | null {
  let cur: ts.Node | undefined = declarationOf(id) ?? undefined;
  while (cur && (ts.isIdentifier(cur) || ts.isBindingElement(cur) || ts.isObjectBindingPattern(cur) || ts.isArrayBindingPattern(cur))) cur = cur.parent;
  return cur && ts.isVariableDeclaration(cur) ? (cur.initializer ?? null) : null;
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
// Verified requests: signatures, sealed values, sessions
// ---------------------------------------------------------------------------
//
// Everything in this section fails closed. A handler counts as guarded only when a proof goes through; a
// proof is built from the few shapes listed here, and every question whose answer is not known is answered
// "not proven", which leaves the finding in place.
//
//   A value is proven when it can only be truthy for a verified request: the answer of one of the listed
//   library checks, a `const` set directly from one, or the answer of a project helper whose body is proven
//   by this same rule. With the proof comes what the value holds when the check failed (false, null,
//   undefined), so `=== false` on a helper that answers null is seen for what it is.
//
//   A statement is gated when every request that reaches it passed a test of a proven value (or a call that
//   throws unless the request is verified). Everything that is NOT gated has to be inert: built only from
//   calls on a short allow-list of things that read, compute or answer. An unknown call is an effect.

/** An expression's text with local variables replaced by what they were set from, so two names for one value read the same. */
function settledText(e: ts.Expression, depth = 3): string {
  const x = unwrap(e);
  if (ts.isIdentifier(x) && depth > 0) {
    const init = initializerOf(x);
    const d = declarationOf(x);
    if (init && d && ts.isVariableDeclaration(d.parent)) return settledText(init, depth - 1);
  }
  return x.getText().replace(/\s+/g, "");
}

/** A name nothing in the file declares or imports: the language's or the platform's own. */
function isGlobal(id: ts.Identifier, project: Project): boolean {
  return declarationOf(id) === null && project.importOf(id.getSourceFile().fileName, id.text) === null;
}

function isLogging(call: ts.CallExpression, project: Project): boolean {
  let root: ts.Expression = unwrap(call.expression);
  while (ts.isPropertyAccessExpression(root) || ts.isCallExpression(root)) root = unwrap(root.expression);
  if (!ts.isIdentifier(root)) return false;
  // `console` is the platform's; a `logger` counts only when it is imported, not when it is a local name
  // for something else (`const log = ledger`).
  if (root.text === "console") return isGlobal(root, project);
  if (!/^(?:logger|log)$/i.test(root.text) || declarationOf(root) !== null) return false;
  // A logger from a package. The project's own `log` is read like any other of its functions.
  return project.packageImport(call.getSourceFile().fileName, root.text) !== null;
}

/** The statement a node belongs to. */
function statementOf(node: ts.Node): ts.Statement | null {
  for (let cur: ts.Node | undefined = node; cur; cur = cur.parent) {
    if (isFn(cur)) return null;
    if (ts.isStatement(cur) && !ts.isBlock(cur)) return cur;
  }
  return null;
}

/** True when control never runs past the statement: it is a return or a throw, or ends in one on every path. */
function alwaysLeaves(s: ts.Statement): boolean {
  if (ts.isReturnStatement(s) || ts.isThrowStatement(s)) return true;
  if (ts.isBlock(s)) return s.statements.length > 0 && alwaysLeaves(s.statements[s.statements.length - 1]);
  if (ts.isIfStatement(s)) return !!s.elseStatement && alwaysLeaves(s.thenStatement) && alwaysLeaves(s.elseStatement);
  return false;
}

/** What a value holds when the check behind it failed. "other" is anything not known to be one of the three. */
type Empty = "false" | "null" | "undefined" | "other";

/** The value can only be truthy for a verified request; `fails` is what it holds otherwise. */
interface Proof {
  fails: Set<Empty>;
}

/** What a function's answer is asked to prove. */
type Sense =
  | "truthy" // truthy (at a path) only for a verified request
  | "empty" // empty (at a path) only for a verified request: `{ error: Response }` for everyone else
  | "asserts" // returns at all only for a verified request: it throws otherwise
  | "handler"; // a route handler: nothing but inert code runs for an unverified request

interface Ctx {
  project: Project;
  entry: string;
}

// Helpers a proof may pass through, one inside the other.
const MAX_PROOF_DEPTH = MAX_HOPS;

/** Thrown inside a walk when a statement cannot be shown to be inert or gated. */
class Unproven extends Error {}

function isAsync(fn: Fn): boolean {
  return (ts.getModifiers(fn as ts.HasModifiers) ?? []).some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
}

function emptyLiteral(x: ts.Expression): Empty | null {
  if (x.kind === ts.SyntaxKind.FalseKeyword) return "false";
  if (x.kind === ts.SyntaxKind.NullKeyword) return "null";
  if (ts.isIdentifier(x) && x.text === "undefined" && declarationOf(x) === null) return "undefined";
  return null;
}

/** `name(...)` or `crypto.name(...)` where the name comes from Node's crypto module, not from the project. */
function nodeCrypto(call: ts.CallExpression, name: string, project: Project): boolean {
  const callee = unwrap(call.expression);
  const file = call.getSourceFile().fileName;
  const builtin = (local: ts.Identifier) => {
    const imported = declarationOf(local) === null ? project.packageImport(file, local.text) : null;
    return imported && /^(?:node:)?crypto$/.test(imported.spec) ? imported : null;
  };
  if (ts.isIdentifier(callee)) return builtin(callee)?.name === name;
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== name) return false;
  const object = unwrap(callee.expression);
  if (!ts.isIdentifier(object)) return false;
  return builtin(object) !== null || (object.text === "crypto" && isGlobal(object, project));
}

/** True when every return of the function hands back something `is` accepts. */
function returnsOnly(fn: Fn, is: (e: ts.Expression) => boolean): boolean {
  if (!fn.body) return false;
  if (!ts.isBlock(fn.body)) return is(fn.body);
  const returned: Array<ts.Expression | undefined> = [];
  const walk = (n: ts.Node): void => {
    if (isFn(n)) return;
    if (ts.isReturnStatement(n)) returned.push(n.expression);
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(fn.body, walk);
  return returned.length > 0 && returned.every((r) => !!r && is(r));
}

/**
 * Is the expression an export of a package matching `pkg`, or something made by calling or constructing
 * one: `new Stripe(key)`, `createClient(url, key)`, a `const` (here or imported) set to one, a project
 * function that returns one? This is where an object's methods get their meaning from: `x.auth.getUser()`
 * reads a session only when `x` is a Supabase client, whatever the method is called.
 */
function madeBy(e: ts.Expression, pkg: RegExp, exportName: RegExp | null, cx: Ctx, depth = 0): boolean {
  if (depth > 5) return false;
  const { x } = peel(e);
  if (ts.isPropertyAccessExpression(x)) return madeBy(x.expression, pkg, exportName, cx, depth + 1);
  if (ts.isNewExpression(x)) return madeBy(x.expression, pkg, exportName, cx, depth + 1);
  if (ts.isCallExpression(x)) {
    const targets = cx.project.resolveCall(x, cx.entry);
    if (targets.length > 0) return targets.every((t) => returnsOnly(t, (r) => madeBy(r, pkg, exportName, cx, depth + 1)));
    return madeBy(x.expression, pkg, exportName, cx, depth + 1);
  }
  if (!ts.isIdentifier(x)) return false;
  const b = boundTo(x);
  if (b) return b.prefix.length === 0 && madeBy(b.init, pkg, exportName, cx, depth + 1);
  if (declarationOf(x) !== null) return false; // a parameter: whatever the caller passed
  const file = x.getSourceFile().fileName;
  const fromPackage = cx.project.packageImport(file, x.text);
  if (fromPackage) return pkg.test(fromPackage.spec) && (!exportName || exportName.test(fromPackage.name));
  const top = cx.project.topVariable(file, x.text);
  if (!top || !top.initializer || !ts.isIdentifier(top.name) || (top.parent.flags & ts.NodeFlags.Const) === 0) return false;
  return madeBy(top.initializer, pkg, exportName, cx, depth + 1);
}

const SUPABASE_CLIENT = /^create\w*Client$/;

/**
 * Is the value worked out from a secret the server holds (`process.env.X`)? A comparison proves something
 * about the caller only when one side is: two values that both came with the request, or an unkeyed
 * checksum of the body, match for anyone. Constants are followed to what they were set from, the project's
 * own functions to what they return, and a helper's parameter to the argument at the call being followed.
 */
function secretDerived(e: ts.Node, cx: Ctx, frame: Frame | null = cx.project.frame, depth = 0): boolean {
  if (depth > 10) return false;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found || isFn(n) || ts.isTypeNode(n)) return;
    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "process" && n.name.text === "env" && isGlobal(n.expression, cx.project)) {
      found = true;
      return;
    }
    if (ts.isIdentifier(n)) {
      if (isPropertyName(n)) return;
      const d = declarationOf(n);
      if (!d) {
        const c = cx.project.constant(n.getSourceFile().fileName, n.text);
        if (c && secretDerived(c.value, cx, null, depth + 1)) found = true;
        return;
      }
      const param = d.parent;
      if (ts.isParameter(param) && param.name === d && isFn(param.parent)) {
        cx.project.siteDependent++;
        if (isReassigned(d)) return;
        const index = param.parent.parameters.indexOf(param);
        for (let f = frame; f; f = f.parent) {
          if (f.target !== param.parent) continue;
          const arg = f.call.arguments[index];
          if (arg && !ts.isSpreadElement(arg) && !f.call.arguments.slice(0, index).some(ts.isSpreadElement) && secretDerived(arg, cx, f.parent, depth + 1)) found = true;
          break;
        }
        return;
      }
      const b = boundTo(n);
      if (b && secretDerived(b.init, cx, frame, depth + 1)) found = true;
      return;
    }
    if (ts.isCallExpression(n)) {
      const targets = cx.project.resolveCall(n, cx.entry);
      if (targets.length > 0) {
        if (targets.every((t) => returnsOnly(t, (r) => secretDerived(r, cx, { call: n, target: t, parent: frame }, depth + 1)))) found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(e);
  return found;
}

/** Runs `go` while the call into `target` is the innermost one being followed. */
function inFrame<T>(cx: Ctx, call: ts.CallExpression, target: Fn, go: () => T): T {
  const parent = cx.project.frame;
  cx.project.frame = { call, target, parent };
  try {
    return go();
  } finally {
    cx.project.frame = parent;
  }
}

type PlatformCheck = { kind: "value"; path: string[]; fails: Empty[]; awaited: boolean } | { kind: "asserts"; awaited: boolean };

/**
 * The library calls that decide whether a request is genuine, with how each one says no: which field of its
 * answer is empty for an unverified request, or that it throws. Only these are taken on trust.
 */
function platformCheck(call: ts.CallExpression, cx: Ctx): PlatformCheck | null {
  const callee = unwrap(call.expression);
  const name = calleeName(call);
  const value = (path: string[], fails: Empty[], awaited: boolean): PlatformCheck => ({ kind: "value", path, fails, awaited });
  // Each of these is taken for what it is only when the thing it is called on is shown to come from the
  // library: a project function that happens to be called `timingSafeEqual`, or an object with its own
  // `auth.getUser`, is read like any other project code (and so is not found here).
  if (name === "timingSafeEqual") {
    // Comparing a value with itself answers yes for everyone.
    if (!nodeCrypto(call, name, cx.project) || call.arguments.length !== 2 || settledText(call.arguments[0]) === settledText(call.arguments[1])) return null;
    // One side has to rest on a secret the server holds.
    if (!call.arguments.some((a) => secretDerived(a, cx))) return null;
    return value([], ["false"], false);
  }
  if (name === "constructEvent" || name === "constructEventAsync") {
    if (!ts.isPropertyAccessExpression(callee) || !madeBy(callee.expression, /^stripe$/, null, cx)) return null;
    if (!call.arguments[2] || !secretDerived(call.arguments[2], cx)) return null;
    return { kind: "asserts", awaited: name === "constructEventAsync" };
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const object = unwrap(callee.expression);
    if (name === "verify" && /^(?:globalThis\.)?(?:crypto|webcrypto)\.subtle$/.test(object.getText().replace(/\s+/g, "")) && outerRoot(object, cx.project)) {
      return call.arguments[1] && secretDerived(call.arguments[1], cx) ? value([], ["false"], true) : null;
    }
    if (/^(?:getUser|getSession|getClaims)$/.test(name) && ts.isPropertyAccessExpression(object) && object.name.text === "auth") {
      if (!madeBy(object.expression, /^@supabase\//, SUPABASE_CLIENT, cx)) return null;
      if (name === "getUser") return value(["data", "user"], ["null"], true);
      if (name === "getSession") return value(["data", "session"], ["null"], true);
      return value(["data"], ["null"], true);
    }
  }
  let rootId: ts.Expression = callee;
  while (ts.isPropertyAccessExpression(rootId) || ts.isCallExpression(rootId)) rootId = unwrap(rootId.expression);
  if (!ts.isIdentifier(rootId) || !AUTH_CALLS.has(name) || declarationOf(rootId) !== null) return null;
  const spec = cx.project.packageImport(call.getSourceFile().fileName, rootId.text)?.spec;
  if (!spec || !AUTH_PACKAGES.test(spec)) return null;
  const args = call.arguments;
  const keyed = (i: number): boolean => !!args[i] && secretDerived(args[i], cx);
  const receiverKeyed = ts.isPropertyAccessExpression(callee) && secretDerived(callee.expression, cx);
  switch (name) {
    case "validateRequest":
    case "validateRequestWithBody":
      return /^twilio/.test(spec) && keyed(0) ? value([], ["false"], false) : null;
    case "jwtVerify":
      return /^jose/.test(spec) && args.length <= 3 && keyed(1) ? { kind: "asserts", awaited: true } : null;
    case "verify":
      // jsonwebtoken hands a failure to a callback, when given one, instead of throwing: the callback is the
      // third or fourth argument, written out or passed by name.
      if (/^jsonwebtoken/.test(spec)) return keyed(1) && (args.length === 2 || (args.length === 3 && ts.isObjectLiteralExpression(unwrap(args[2])))) ? { kind: "asserts", awaited: false } : null;
      if (/^svix/.test(spec)) return receiverKeyed && args.length === 2 ? { kind: "asserts", awaited: false } : null;
      return /^@octokit\/webhooks/.test(spec) && receiverKeyed ? value([], ["false"], true) : null;
    case "getServerSession":
    case "getToken":
      return /^next-auth/.test(spec) ? value([], ["null"], true) : null;
    case "auth":
      if (/^@clerk\//.test(spec)) return value(["userId"], ["null"], true);
      return /^(?:next-auth|@auth\/)/.test(spec) ? value([], ["null"], true) : null;
    case "currentUser":
      return /^@clerk\//.test(spec) ? value([], ["null"], true) : null;
    default:
      return null;
  }
}

/** A call that itself decides whether the caller is genuine. Used only to let the call run ungated. */
function isVerification(call: ts.CallExpression, cx: Ctx): boolean {
  return platformCheck(call, cx) !== null;
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

/** What a variable is set from, and the fields a destructuring picked on the way. Null unless it is set exactly once. */
function boundTo(id: ts.Identifier): { init: ts.Expression; prefix: string[] } | null {
  const decl = declarationOf(id);
  if (!decl) return null;
  let node: ts.Node = decl;
  const prefix: string[] = [];
  while (ts.isBindingElement(node.parent)) {
    const el: ts.BindingElement = node.parent;
    // A default (`{ user = guest }`), a rest element or an array pattern can put something else in the name.
    if (el.dotDotDotToken || el.initializer || !ts.isObjectBindingPattern(el.parent)) return null;
    const key = propertyKey(el.propertyName ?? el.name);
    if (key === null) return null;
    prefix.unshift(key);
    node = el.parent;
  }
  const d = node.parent;
  if (!ts.isVariableDeclaration(d) || !d.initializer || !ts.isVariableDeclarationList(d.parent)) return null;
  // A `var` can be declared twice and is the whole function's; only `let` and `const` are followed. Even a
  // `const` stops holding what it was set from once a field of it is written (`t.ok = true`).
  if ((d.parent.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0 || isReassigned(decl)) return null;
  return { init: d.initializer, prefix };
}

const reassigned = new WeakMap<ts.Identifier, boolean>();

function isAssignment(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

/** A `let` that is written to anywhere after its declaration no longer holds what it was set from. */
function isReassigned(decl: ts.Identifier): boolean {
  const known = reassigned.get(decl);
  if (known !== undefined) return known;
  let scope: ts.Node = decl;
  while (scope.parent && !isFn(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
  // A function's own name, and a parameter, are looked for in the function; anything else in what holds it.
  if (isFn(scope) && ts.isFunctionDeclaration(scope) && scope.name === decl && scope.parent) scope = scope.parent;
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

function union(a: Proof, b: Proof): Proof {
  return { fails: new Set([...a.fails, ...b.fails]) };
}

/**
 * Proof that an expression (or the field of it at `path`) can only be truthy for a verified request.
 *
 *   a listed library check          `timingSafeEqual(a, b)`, `(await sb.auth.getUser()).data.user`
 *   a project helper, itself proven `await currentMember(req)`, `(await providerCall(req)).ok`
 *   a variable set once from one    `const { data: { user } } = await sb.auth.getUser()`
 *   `a && b`                        when either side is proven
 *   `a || b`, `a ?? b`, `c ? a : b` when BOTH sides are proven (an empty literal counts as proven)
 *   `!x`, `x === true`, `x !== null` through the condition rules below
 *
 * Anything else is not proven: a parameter, a reassigned variable, an unresolved call, a call that is not
 * awaited, the whole of an answer object.
 */
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

function proveValue(e: ts.Expression, path: string[], cx: Ctx, depth: number, awaitedHint = false): Proof | null {
  const { x, awaited } = peel(e, awaitedHint);
  const empty = emptyLiteral(x);
  // An empty literal is never truthy, so the claim holds of it whatever the path.
  if (empty) return { fails: new Set([path.length ? "other" : empty]) };
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return b ? following(cx, b.init, () => proveValue(b.init, [...b.prefix, ...path], cx, depth)) : null;
  }
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name)) return proveValue(x.expression, [x.name.text, ...path], cx, depth);
  if (ts.isElementAccessExpression(x) && ts.isStringLiteralLike(x.argumentExpression)) return proveValue(x.expression, [x.argumentExpression.text, ...path], cx, depth);
  if (ts.isObjectLiteralExpression(x)) {
    // `{ ok: false, res }` asked for `ok`. As a whole an object is always truthy, so it proves nothing.
    // A spread, a method, a getter or a computed key can put anything in any field.
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
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee) && callee.text === "Boolean" && isGlobal(callee, cx.project) && call.arguments.length === 1 && path.length === 0) {
    return proveValue(call.arguments[0], [], cx, depth) ? { fails: new Set<Empty>(["false"]) } : null;
  }
  const targets = cx.project.resolveCall(call, cx.entry);
  if (targets.length === 0) {
    const p = platformCheck(call, cx);
    if (!p || (p.awaited && !awaited)) return null;
    if (p.kind === "asserts") return { fails: new Set() };
    if (path.length < p.path.length || !p.path.every((k, i) => path[i] === k)) return null;
    // A field below the proven one (`user.id`) is truthy only when the proven one is.
    return { fails: new Set<Empty>(path.length === p.path.length ? p.fails : ["other"]) };
  }
  let out: Proof = { fails: new Set() };
  for (const t of targets) {
    // The promise of an answer is always truthy; only the awaited answer says anything.
    if (isAsync(t) && !awaited) return null;
    const p = inFrame(cx, call, t, () => proveFn(t, "truthy", path, cx, depth + 1));
    if (!p) return null;
    out = union(out, p);
  }
  return out;
}

/** An expression that is never empty: a new object, an object or array written out, a response being built. */
function neverEmpty(e: ts.Expression, path: string[], depth = 0): boolean {
  const x = unwrap(e);
  if (path.length > 0) {
    if (!ts.isObjectLiteralExpression(x) || x.properties.some((p) => !ts.isPropertyAssignment(p))) return false;
    const p = x.properties.find((q) => propertyKey(q.name) === path[0]);
    return !!p && ts.isPropertyAssignment(p) && neverEmpty(p.initializer, path.slice(1), depth);
  }
  if (ts.isNewExpression(x) || ts.isObjectLiteralExpression(x) || ts.isArrayLiteralExpression(x) || x.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (ts.isStringLiteralLike(x)) return x.text.length > 0;
  if (ts.isCallExpression(x)) return /^(?:Response|NextResponse)\.(?:json|redirect)$/.test(unwrap(x.expression).getText().replace(/\s+/g, ""));
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
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name)) return proveEmptyMeansVerified(x.expression, [x.name.text, ...path], cx, depth);
  if (!ts.isCallExpression(x)) return false;
  const targets = cx.project.resolveCall(x, cx.entry);
  return targets.length > 0 && targets.every((t) => (!isAsync(t) || awaited) && inFrame(cx, x, t, () => proveFn(t, "empty", path, cx, depth + 1)) !== null);
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

function stripParens(e: ts.Expression): ts.Expression {
  let x = e;
  while (ts.isParenthesizedExpression(x)) x = x.expression;
  return x;
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

// --- Inert code: the allow-list ------------------------------------------------------------------------

// Methods that read a string, an array, a buffer or a date and change nothing.
const READ_METHODS = new Set(
  (
    "includes indexOf lastIndexOf slice concat join trim trimStart trimEnd toLowerCase toUpperCase toString toFixed normalize " +
    "padStart padEnd startsWith endsWith split match matchAll test substring charAt charCodeAt localeCompare " +
    "repeat at flat subarray toISOString getTime valueOf parse safeParse parseAsync safeParseAsync"
  ).split(" "),
);
const NO_ARGUMENT_READS = new Set("json text formData arrayBuffer blob clone keys values entries".split(" "));
const PROMISE_METHODS = new Set(["then", "catch", "finally"]);
// Array methods that only count as reads when handed a function, which is then read too. `db.find({...})` is a query.
const CALLBACK_METHODS = new Set("map filter find findIndex findLast some every reduce flatMap forEach".split(" "));
// Lookups in what came with the request. `cache.get(key)` and `kv.get(key)` read a store and are not on the list.
const LOOKUP_METHODS = new Set(["get", "getAll", "has"]);
const REQUEST_DATA = /(?:headers|cookies|searchParams|formData|params)(?:\(\))?$/i;
const REQUEST_DATA_SOURCE = /\.formData\(\)|\bnew\s+(?:URLSearchParams|Map|Headers|FormData|URL)\b|\bcookies\(\)|\bheaders\(\)|\.searchParams\b|\.headers\b/;
const CIPHER_METHODS = new Set(["update", "digest", "final", "setAuthTag", "getAuthTag", "setAAD"]);
const CIPHER_MAKERS = new Set(["createHash", "createHmac", "createDecipheriv", "createCipheriv"]);
const CRYPTO_FUNCTIONS = new Set([...CIPHER_MAKERS, "timingSafeEqual", "randomBytes", "randomUUID", "getRandomValues", "scryptSync", "pbkdf2Sync"]);
const STATIC_READS: Record<string, Set<string> | "any"> = {
  Buffer: new Set(["from", "concat", "byteLength", "isBuffer", "alloc", "compare"]),
  Object: new Set(["keys", "values", "entries", "fromEntries"]),
  Array: new Set(["from", "isArray", "of"]),
  JSON: new Set(["parse", "stringify"]),
  Date: new Set(["now", "parse"]),
  Promise: new Set(["all", "allSettled", "race", "any", "resolve", "reject"]),
  Response: new Set(["json", "redirect", "error"]),
  NextResponse: new Set(["json", "redirect", "next", "rewrite"]),
  URL: new Set(["canParse"]),
  crypto: CRYPTO_FUNCTIONS,
  "crypto.subtle": new Set(["digest", "importKey", "verify", "sign"]),
  Math: "any",
  Number: "any",
  String: "any",
};
const GLOBAL_READS = new Set(["structuredClone", "atob", "btoa", "isNaN", "isFinite", "encodeURI", "decodeURI"]);
const INERT_CLASSES = /^(?:Response|URL|URLSearchParams|Headers|FormData|TextEncoder|TextDecoder|Date|Map|Set|RegExp|Uint8Array|(?:Type|Range|Syntax|Reference|Eval|URI|Aggregate)?Error)$/;

/**
 * May `new X(...)` run for anyone? Only for the platform's own value classes, `NextResponse`, and a project
 * class that adds nothing to run: no constructor, no field initialisers, extending nothing or one of these.
 */
function isInertNew(n: ts.NewExpression, cx: Ctx, depth = 0): boolean {
  const c = unwrap(n.expression);
  return ts.isIdentifier(c) && isInertClass(c, cx, depth);
}

function isInertClass(name: ts.Identifier, cx: Ctx, depth: number): boolean {
  if (depth > 3) return false;
  const file = name.getSourceFile().fileName;
  if (declarationOf(name) !== null) return false; // a local or a parameter: whatever it was set to
  const cls = classNamed(cx.project, file, name.text, 3);
  if (!cls) {
    if (isGlobal(name, cx.project)) return INERT_CLASSES.test(name.text);
    const pkg = cx.project.packageImport(file, name.text);
    return !!pkg && pkg.spec === "next/server" && pkg.name === "NextResponse";
  }
  if (!cls || cls.members.some((m) => ts.isConstructorDeclaration(m) || ts.isClassStaticBlockDeclaration(m) || (ts.isPropertyDeclaration(m) && !!m.initializer))) return false;
  const base = cls.heritageClauses?.find((h) => h.token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
  if (!base) return true;
  return ts.isIdentifier(base) && isInertClass(base, cx, depth + 1);
}

/** The one class of that name at the top of a file, here or where it is imported from. */
function classNamed(project: Project, file: string, name: string, hops: number): ts.ClassDeclaration | null {
  const sf = project.source(file);
  if (!sf || hops < 0) return null;
  const here = sf.statements.filter((st): st is ts.ClassDeclaration => ts.isClassDeclaration(st) && st.name?.text === name);
  if (here.length > 0) return here.length === 1 && !isReassigned(here[0].name!) ? here[0] : null;
  const imported = project.importOf(file, name);
  const target = imported && !imported.namespace ? project.resolveModule(file, imported.spec) : null;
  return target && imported ? classNamed(project, target, imported.name, hops - 1) : null;
}

/** A value that is only data, by where it comes from: something written out, a local, `process.env`. */
function isDataReceiver(e: ts.Expression, cx: Ctx): boolean {
  let root = unwrap(e);
  while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) root = unwrap(root.expression);
  const written = (v: ts.Expression): boolean =>
    ts.isStringLiteralLike(v) || ts.isTemplateExpression(v) || ts.isRegularExpressionLiteral(v) || ts.isNumericLiteral(v) || (ts.isArrayLiteralExpression(v) && v.elements.every((el) => written(unwrap(el))));
  // What a call or a `new` hands back is judged where the call itself is read.
  if (written(root) || ts.isCallExpression(root) || ts.isNewExpression(root) || ts.isBinaryExpression(root) || ts.isConditionalExpression(root)) return true;
  if (!ts.isIdentifier(root)) return false;
  if (isLocal(root)) return true;
  if (isGlobal(root, cx.project)) return root.text === "process";
  // A module's own constant, here or imported, when it is written-out data.
  const c = cx.project.constant(root.getSourceFile().fileName, root.text);
  return !!c && written(unwrap(c.value));
}

/** The project has a method of that name: a call of it is the project's code unless shown otherwise. */
function ownMethodsInert(name: string, cx: Ctx, depth: number): boolean {
  const { fns, unknown } = cx.project.methodsOf(cx.entry, name);
  return !unknown && fns.every((f) => isInertFn(f, cx, depth + 1));
}

/** The root name of `a.b.c` when nothing in the file's functions declares it: a global or an import. */
function outerRoot(e: ts.Expression, project: Project): boolean {
  let root = unwrap(e);
  while (ts.isPropertyAccessExpression(root)) root = unwrap(root.expression);
  return ts.isIdentifier(root) && isGlobal(root, project);
}

/** A hash, MAC or cipher object: `createHash(...)`, a chain of `.update()` on one, or a variable set from one. */
function isCipherObject(e: ts.Expression, project: Project, depth = 0): boolean {
  const x = unwrap(e);
  if (depth > 4) return false;
  if (ts.isCallExpression(x)) {
    const name = calleeName(x);
    if (CIPHER_MAKERS.has(name)) return nodeCrypto(x, name, project);
    const callee = unwrap(x.expression);
    return name === "update" && ts.isPropertyAccessExpression(callee) && isCipherObject(callee.expression, project, depth + 1);
  }
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return !!b && b.prefix.length === 0 && isCipherObject(b.init, project, depth + 1);
  }
  return false;
}

/** A name declared inside a function (a parameter or a local), as opposed to a module's variable or a global. */
function isLocal(id: ts.Identifier): boolean {
  const d = declarationOf(id);
  for (let cur: ts.Node | undefined = d ?? undefined; cur; cur = cur.parent) if (isFn(cur)) return true;
  return false;
}

/** May the write `target = ...` be ignored? Only when it changes a local name, or a fresh object made in this function. */
function isLocalWrite(target: ts.Expression): boolean {
  const t = unwrap(target);
  if (ts.isIdentifier(t)) return isLocal(t);
  let root: ts.Expression = t;
  while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) root = unwrap(root.expression);
  if (root === t || !ts.isIdentifier(root) || !isLocal(root)) return false;
  const b = boundTo(root);
  if (!b || b.prefix.length > 0) return false;
  const made = unwrap(b.init);
  const fresh = ts.isNewExpression(made) && ts.isIdentifier(made.expression) && declarationOf(made.expression) === null && INERT_CLASSES.test(made.expression.text);
  return ts.isObjectLiteralExpression(made) || ts.isArrayLiteralExpression(made) || fresh;
}

/** `parts[i]` on a local array or string: no getter of the project's is behind it. */
function isLocalIndex(n: ts.ElementAccessExpression): boolean {
  const object = unwrap(n.expression);
  return ts.isIdentifier(object) && isLocal(object);
}

/**
 * True when running the node changes nothing that lasts and sends nothing out: every call in it is on the
 * allow-list (reading the request, computing, building an answer, logging, the listed verifications) or is a
 * project function whose own body is inert. `accept` lets a caller take specific calls as given. The default
 * for anything not recognised is "not inert".
 */
function isInert(node: ts.Node, cx: Ctx, depth: number, accept?: (call: ts.CallExpression) => boolean): boolean {
  let ok = true;
  const getters = cx.project.gettersIn(cx.entry);
  const visit = (n: ts.Node): void => {
    if (!ok) return;
    if (ts.isTypeNode(n)) return;
    if (isFn(n) && n !== node) {
      // A function handed straight to a call may run now (`.map(fn)`, `.catch(fn)`); one stored in an object
      // or a variable is a definition, judged where it is called.
      if (!(ts.isCallExpression(n.parent) && n.parent.arguments.includes(n as ts.Expression))) return;
    }
    if (ts.isCallExpression(n)) {
      if (accept?.(n)) {
        // The call is taken as given, and with it the object it is made on; what it is handed is still read.
        n.arguments.forEach(visit);
        return;
      }
      if (!isInertCall(n, cx, depth)) ok = false;
    } else if (ts.isNewExpression(n)) {
      if (!isInertNew(n, cx)) ok = false;
    } else if (ts.isTaggedTemplateExpression(n) || ts.isDeleteExpression(n) || ts.isYieldExpression(n)) {
      ok = false;
    } else if ((ts.isForOfStatement(n) || ts.isForInStatement(n)) && !ts.isVariableDeclarationList(n.initializer)) {
      if (!isLocalWrite(n.initializer)) ok = false;
    } else if (ts.isPropertyAccessExpression(n) && getters.size > 0 && (getters.has("*") || getters.has(n.name.text))) {
      // Reading the property may run one of the project's getters.
      ok = false;
    } else if (ts.isElementAccessExpression(n) && getters.size > 0 && !ts.isStringLiteralLike(n.argumentExpression) && !ts.isNumericLiteral(n.argumentExpression) && !isLocalIndex(n)) {
      ok = false;
    } else if (ts.isBinaryExpression(n) && isAssignment(n.operatorToken.kind)) {
      if (!isLocalWrite(n.left)) ok = false;
    } else if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) && (n.operator === ts.SyntaxKind.PlusPlusToken || n.operator === ts.SyntaxKind.MinusMinusToken)) {
      if (!isLocalWrite(n.operand)) ok = false;
    }
    if (ok) ts.forEachChild(n, visit);
  };
  visit(node);
  return ok;
}

function isInertCall(call: ts.CallExpression, cx: Ctx, depth: number): boolean {
  const callee = unwrap(call.expression);
  // The project's own code is read, whatever it is called. Only what cannot be read is judged by the lists.
  const targets = cx.project.resolveCall(call, cx.entry);
  if (targets.length > 0) return targets.every((t) => isInertFn(t, cx, depth + 1));
  if (isLogging(call, cx.project) || isVerification(call, cx)) return true;
  const file = call.getSourceFile().fileName;
  if (ts.isIdentifier(callee)) {
    if (declarationOf(callee) !== null) return false; // a parameter or a local that could not be resolved
    if (isGlobal(callee, cx.project)) return COERCION_FUNCTIONS.has(callee.text) || GLOBAL_READS.has(callee.text);
    const imported = cx.project.packageImport(file, callee.text);
    if (!imported) return false;
    if (/^(?:node:)?crypto$/.test(imported.spec)) return CRYPTO_FUNCTIONS.has(imported.name);
    if (imported.spec === "next/headers") return imported.name === "cookies" || imported.name === "headers";
    // A Supabase client being made. What is done with it is a separate call.
    return /^@supabase\//.test(imported.spec) && SUPABASE_CLIENT.test(imported.name);
  }
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return false;
  const name = callee.name.text;
  const object = unwrap(callee.expression);
  const objectText = object.getText().replace(/\s+/g, "");
  const statics = STATIC_READS[objectText];
  if (statics) return outerRoot(object, cx.project) && (statics === "any" || statics.has(name));
  if (ts.isIdentifier(object) && declarationOf(object) === null) {
    const pkg = cx.project.packageImport(file, object.text);
    if (pkg) {
      if (/^(?:node:)?crypto$/.test(pkg.spec)) return CRYPTO_FUNCTIONS.has(name);
      return pkg.spec === "next/server" && pkg.name === "NextResponse" && (STATIC_READS.NextResponse as Set<string>).has(name);
    }
  }
  if (CIPHER_METHODS.has(name)) return isCipherObject(object, cx.project);
  if (LOOKUP_METHODS.has(name)) {
    // What came with the request: `req.headers.get(...)`, `cookies().get(...)`, `url.searchParams.get(...)`.
    let root = object;
    while (ts.isPropertyAccessExpression(root) || ts.isCallExpression(root)) root = unwrap(root.expression);
    if (!ts.isIdentifier(root)) return false;
    const fromNext = declarationOf(root) === null && cx.project.packageImport(file, root.text)?.spec === "next/headers";
    if (REQUEST_DATA.test(objectText)) return fromNext || isLocal(root);
    const b = ts.isIdentifier(object) ? boundTo(object) : null;
    return !!b && isLocal(root) && REQUEST_DATA_SOURCE.test(b.init.getText());
  }
  const listed = READ_METHODS.has(name) || NO_ARGUMENT_READS.has(name) || CALLBACK_METHODS.has(name) || PROMISE_METHODS.has(name) || name === "replace" || name === "replaceAll";
  // These are methods of strings, arrays, promises and request bodies. They mean that only on a value that is
  // data, and only when the project has no method of its own by that name that does something else.
  if (!listed || !isDataReceiver(object, cx) || !ownMethodsInert(name, cx, depth)) return false;
  const written = (a: ts.Expression | undefined): boolean => !!a && (ts.isArrowFunction(a) || ts.isFunctionExpression(a));
  // A function written in place is read with the rest; one passed by name (`.then(save)`) is not followed.
  if (CALLBACK_METHODS.has(name)) return written(call.arguments[0]);
  if (PROMISE_METHODS.has(name)) return call.arguments.length > 0 && call.arguments.every(written);
  // `req.json()` reads the request; `res.json(data)` is something else.
  if (NO_ARGUMENT_READS.has(name)) return call.arguments.length === 0;
  if (name === "replace" || name === "replaceAll") {
    const first = call.arguments[0];
    return call.arguments.length === 2 && (ts.isRegularExpressionLiteral(first) || ts.isStringLiteralLike(first));
  }
  return true;
}

function isInertFn(fn: Fn, cx: Ctx, depth: number): boolean {
  const memo = cx.project.inertMemo.get(fn);
  if (memo !== undefined) return memo;
  if (!fn.body || fn.asteriskToken) return false;
  if (depth > MAX_HOPS || cx.project.inertActive.has(fn)) {
    cx.project.cuts++;
    return false;
  }
  const cuts = cx.project.cuts;
  cx.project.inertActive.add(fn);
  // A parameter's default value runs with the call.
  const result = fn.parameters.every((p) => isInert(p, cx, depth)) && isInert(fn.body, cx, depth);
  cx.project.inertActive.delete(fn);
  if (result || cuts === cx.project.cuts) cx.project.inertMemo.set(fn, result);
  return result;
}

// --- The walk -------------------------------------------------------------------------------------------

/**
 * Walks a function's statements in order, carrying one fact: is every request that reaches this point
 * verified ("gated")? Ungated code has to be inert and its returns have to fit what is being proven; gated
 * code is free. A point becomes gated
 *
 *   after an `if` whose every way through is either gated or leaves: `if (!who) return ...` (the test is
 *     only false for the verified, the branch leaves), `if (t.ok) { ... } else { return ... }`;
 *   inside the branch of an `if` that only the verified reach: `if (who) { work }`;
 *   after a statement that calls, unconditionally, something that throws unless the request is verified;
 *   after a `try` only when its block ends gated AND its catch leaves: a catch that carries on receives
 *     whatever threw before the gate, including the guard's own refusal.
 *
 * A loop body, a `switch` clause and the code after them start ungated.
 */
class Walk {
  fails = new Set<Empty>();
  /** A proven test or a throwing check was met: without one there is nothing to speak of. */
  used = false;

  constructor(
    private cx: Ctx,
    private fn: Fn,
    private sense: Sense,
    private path: string[],
    private depth: number,
  ) {}

  private inert(node: ts.Node | undefined): void {
    if (node && !isInert(node, this.cx, 0)) throw new Unproven();
  }

  seq(statements: readonly ts.Statement[], gated: boolean): boolean {
    let g = gated;
    for (const s of statements) g = this.stmt(s, g);
    return g;
  }

  stmt(s: ts.Statement, gated: boolean): boolean {
    if (gated) return true;
    if (ts.isBlock(s)) return this.seq(s.statements, false);
    if (ts.isFunctionDeclaration(s) || ts.isEmptyStatement(s) || ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s)) return false;
    if (ts.isIfStatement(s)) {
      this.inert(s.expression);
      const yes = yesMeansVerified(s.expression, this.cx, this.depth);
      const no = noMeansVerified(s.expression, this.cx, this.depth);
      if (yes || no) this.used = true;
      const afterThen = this.stmt(s.thenStatement, yes);
      const afterElse = s.elseStatement ? this.stmt(s.elseStatement, no) : no;
      return afterThen && afterElse;
    }
    if (ts.isTryStatement(s)) {
      const afterTry = this.seq(s.tryBlock.statements, false);
      const afterCatch = s.catchClause ? this.seq(s.catchClause.block.statements, false) : true;
      const afterFinally = s.finallyBlock ? this.seq(s.finallyBlock.statements, false) : false;
      return afterFinally || (afterTry && afterCatch);
    }
    if (ts.isReturnStatement(s)) {
      this.inert(s.expression);
      if (s.expression && this.asserts(s.expression)) return true;
      this.ungatedReturn(s.expression);
      return true; // nothing runs past it
    }
    if (ts.isThrowStatement(s)) {
      this.inert(s.expression);
      return true;
    }
    if (ts.isVariableStatement(s) || ts.isExpressionStatement(s)) {
      this.inert(s);
      return this.asserts(s);
    }
    if (ts.isForStatement(s)) {
      this.inert(s.initializer);
      this.inert(s.condition);
      this.inert(s.incrementor);
      this.stmt(s.statement, false);
      return false;
    }
    if (ts.isForOfStatement(s) || ts.isForInStatement(s) || ts.isWhileStatement(s) || ts.isDoStatement(s)) {
      // `for (settings.owner of [sent]) {}` is an assignment.
      if ((ts.isForOfStatement(s) || ts.isForInStatement(s)) && !ts.isVariableDeclarationList(s.initializer) && !isLocalWrite(s.initializer)) throw new Unproven();
      this.inert(s.expression);
      this.stmt(s.statement, false);
      return false;
    }
    if (ts.isSwitchStatement(s)) {
      this.inert(s.expression);
      for (const clause of s.caseBlock.clauses) {
        if (ts.isCaseClause(clause)) this.inert(clause.expression);
        this.seq(clause.statements, false);
      }
      return false;
    }
    if (ts.isLabeledStatement(s)) {
      this.stmt(s.statement, false);
      return false;
    }
    if (ts.isBreakStatement(s) || ts.isContinueStatement(s)) return false;
    throw new Unproven();
  }

  /** What an unverified request may be handed back, by what is being proven. */
  private ungatedReturn(e: ts.Expression | undefined): void {
    if (this.sense === "handler") {
      // What everyone is answered is built from the request, literals and what a helper handed back. A value
      // kept by a module (a cache, a list of keys) does not go out to a caller nobody checked.
      if (e) {
        each(e, (n) => {
          if (!ts.isIdentifier(n) || isPropertyName(n) || isLocal(n) || isGlobal(n, this.cx.project)) return;
          if (declarationOf(n) === null && this.cx.project.packageImport(n.getSourceFile().fileName, n.text)) return;
          if (ts.isCallExpression(n.parent) && unwrap(n.parent.expression) === n) return; // a call: read by the inert check
          throw new Unproven();
        });
      }
      return;
    }
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

  /**
   * Does the statement call, on every way through it, something that throws unless the request is verified?
   * Not behind `&&`, `||`, `??` or `?:`, not inside a function written there, and not with a `.catch()` or
   * `.then()` hung on it, which can turn the refusal into an answer.
   */
  private asserts(node: ts.Node): boolean {
    let found = false;
    // Only positions that are evaluated every time the statement runs are looked at: the statement's own
    // expression, what a variable is set from, a call's callee and arguments, the object of a property read.
    // Not a default value, the right of `&&` `||` `??` `??=`, a `?:` arm, anything behind `?.`, or a
    // function written there.
    const visit = (n: ts.Node | undefined): void => {
      if (!n || found) return;
      if (ts.isExpressionStatement(n) || ts.isReturnStatement(n) || ts.isAwaitExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n) || ts.isAsExpression(n) || ts.isVoidExpression(n)) return visit(n.expression);
      if (ts.isVariableStatement(n)) return n.declarationList.declarations.forEach((d) => visit(d.initializer));
      if (ts.isArrayLiteralExpression(n)) return n.elements.forEach(visit);
      if ((n.flags & ts.NodeFlags.OptionalChain) !== 0) return;
      if (ts.isPropertyAccessExpression(n)) return visit(n.expression);
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) return visit(n.right);
      if (!ts.isCallExpression(n)) return;
      const callee = unwrap(n.expression);
      if (ts.isPropertyAccessExpression(callee) && /^(?:catch|then|finally)$/.test(callee.name.text)) return;
      if (this.isAssertCall(n)) {
        found = true;
        return;
      }
      visit(n.expression);
      n.arguments.forEach(visit);
    };
    visit(node);
    if (found) this.used = true;
    return found;
  }

  private isAssertCall(call: ts.CallExpression): boolean {
    let top: ts.Node = call;
    while (ts.isParenthesizedExpression(top.parent)) top = top.parent;
    const awaited = ts.isAwaitExpression(top.parent);
    const callee = unwrap(call.expression);
    // Authenticated decryption: `final()` throws unless the tag set on the decipher checks out.
    if (ts.isPropertyAccessExpression(callee) && callee.name.text === "final" && ts.isIdentifier(callee.expression)) {
      const decipher = callee.expression;
      const b = boundTo(decipher);
      const made = b && b.prefix.length === 0 ? unwrap(b.init) : null;
      if (!made || !ts.isCallExpression(made) || !nodeCrypto(made, "createDecipheriv", this.cx.project)) return false;
      if (!made.arguments[1] || !secretDerived(made.arguments[1], this.cx)) return false;
      const decl = declarationOf(decipher);
      let tagged = false;
      if (this.fn.body) {
        each(this.fn.body, (n) => {
          if (!ts.isCallExpression(n) || n.getStart() >= call.getStart()) return;
          const c = unwrap(n.expression);
          if (ts.isPropertyAccessExpression(c) && c.name.text === "setAuthTag" && ts.isIdentifier(c.expression) && declarationOf(c.expression) === decl) tagged = true;
        });
      }
      return tagged;
    }
    const targets = this.cx.project.resolveCall(call, this.cx.entry);
    if (targets.length === 0) {
      const p = platformCheck(call, this.cx);
      return !!p && p.kind === "asserts" && (!p.awaited || awaited);
    }
    return targets.every((t) => (!isAsync(t) || awaited) && inFrame(this.cx, call, t, () => proveFn(t, "asserts", [], this.cx, this.depth + 1)) !== null);
  }
}

/**
 * Proves one thing about a project function by walking its body (see Walk): that its answer at `path` is
 * truthy only for a verified request, empty only for one, or that it returns at all only for one. On the
 * way, everything the function does for an unverified request has to be inert: a helper that writes and
 * then checks is not a guard.
 */
function proveFn(fn: Fn, sense: Sense, path: string[], cx: Ctx, depth: number): Proof | null {
  const key = `${sense}\u0000${path.join("\u0000")}`;
  const memo = cx.project.proofMemo.get(fn)?.get(key);
  if (memo !== undefined) return memo;
  // Calling a generator runs none of its body. A parameter's default value runs with the call.
  if (!fn.body || fn.asteriskToken || !fn.parameters.every((p) => isInert(p, cx, 0))) return null;
  if (depth > MAX_PROOF_DEPTH || cx.project.proofActive.has(fn)) {
    cx.project.cuts++;
    return null;
  }
  const cuts = cx.project.cuts;
  const sites = cx.project.siteDependent;
  cx.project.proofActive.add(fn);
  let result: Proof | null = null;
  try {
    if (!ts.isBlock(fn.body)) {
      // `const check = (req) => sameBytes(a, b)`: the body is the answer.
      if (sense === "truthy" && isInert(fn.body, cx, 0)) result = proveValue(fn.body, path, cx, depth, isAsync(fn));
      else if (sense === "empty" && isInert(fn.body, cx, 0) && proveEmptyMeansVerified(fn.body, path, cx, depth, isAsync(fn))) result = { fails: new Set() };
    } else {
      const walk = new Walk(cx, fn, sense, path, depth);
      const gatedAtEnd = walk.seq(fn.body.statements, false);
      // Running off the end answers `undefined`.
      if (sense === "truthy") result = { fails: gatedAtEnd ? walk.fails : new Set<Empty>([...walk.fails, "undefined"]) };
      // "asserts" and "empty" also need every way out to be gated: running off the end answers undefined.
      else if (gatedAtEnd) result = { fails: new Set() };
    }
  } catch (err) {
    if (!(err instanceof Unproven)) {
      cx.project.proofActive.delete(fn);
      throw err;
    }
    result = null;
  }
  cx.project.proofActive.delete(fn);
  // An answer that looked at the arguments of the call being followed holds for that call only.
  if (sites === cx.project.siteDependent && (result || cuts === cx.project.cuts)) {
    const byKey = cx.project.proofMemo.get(fn) ?? new Map<string, Proof | null>();
    byKey.set(key, result);
    cx.project.proofMemo.set(fn, byKey);
  }
  return result;
}

/**
 * The handler is gated by a verification: walked from the top, everything it does for a request that has
 * not passed a proven check is inert, and at least one proven check is there.
 */
function verifiedRequest(handler: Fn, cx: Ctx): boolean {
  if (!handler.body || !ts.isBlock(handler.body)) return false;
  if (handler.asteriskToken || !handler.parameters.every((p) => isInert(p, cx, 0))) return false;
  const walk = new Walk(cx, handler, "handler", [], 0);
  try {
    walk.seq(handler.body.statements, false);
  } catch (err) {
    if (!(err instanceof Unproven)) throw err;
    return false;
  }
  return walk.used;
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

/** The call hashes the value, or compares it in constant time. */
function hashesValue(call: ts.CallExpression, t: Taint): boolean {
  const name = calleeName(call);
  const callee = unwrap(call.expression);
  const receiver = ts.isPropertyAccessExpression(callee) ? callee.expression.getText() : "";
  const hashing = (name === "update" && /\bcreateH(?:ash|mac)\s*\(/.test(receiver)) || (name === "digest" && /\bsubtle$/.test(receiver));
  const comparing = name === "timingSafeEqual";
  return (hashing || comparing) && call.arguments.some((a) => carries(a, t, true));
}

/**
 * What becomes of a URL token: "hashed" when it is hashed (or compared in constant time) and the raw value
 * goes nowhere else, "raw" when the value itself is handed to something that can keep or look up by it,
 * "unused" when neither. A secret link is looked up by its hash. A route that hashes its `[id]` for a log
 * line and then deletes the row by the id itself is using a plain id, however many hashes sit beside it.
 */
function tokenUse(fn: Fn, t: Taint, project: Project, entry: string, hops: number, seen: Set<Fn>): "hashed" | "raw" | "unused" {
  seen.add(fn);
  spread(fn, t, false);
  if (!fn.body) return "unused";
  let hashed = false;
  for (const call of callsIn([fn.body])) {
    if (isCoercion(call) || isLogging(call, project)) continue;
    if (hashesValue(call, t)) {
      hashed = true;
      continue;
    }
    // A call handed the token (or its hash) whose answer is thrown away finds nothing: it stores.
    if (call.arguments.some((a) => carries(a, t, true))) {
      let top: ts.Node = call;
      while (ts.isAwaitExpression(top.parent) || ts.isParenthesizedExpression(top.parent) || ts.isVoidExpression(top.parent)) top = top.parent;
      if (ts.isExpressionStatement(top.parent)) return "raw";
    }
    if (!callCarries(call, t)) continue;
    const targets = project.resolveCall(call, entry);
    if (targets.length === 0) {
      if (onlyLooks(call, project)) continue;
      return "raw";
    }
    if (hops <= 0) return "raw";
    for (const target of targets) {
      if (seen.has(target)) continue;
      const next = intoCallee(call, target, t);
      if (!next) continue;
      const use = tokenUse(target, next, project, entry, hops - 1, seen);
      if (use === "raw") return "raw";
      if (use === "hashed") hashed = true;
    }
  }
  // A statement the value is written into (sql`... ${id}`) or an object built from it has it too.
  let elsewhere = false;
  each(fn.body, (n) => {
    if (ts.isTaggedTemplateExpression(n) && carries(n.template, t, false)) elsewhere = true;
    if (ts.isNewExpression(n) && !ANSWERS.test(n.expression.getText()) && (n.arguments ?? []).some((a) => carries(a, t, false))) elsewhere = true;
  });
  if (elsewhere) return "raw";
  return hashed ? "hashed" : "unused";
}

// What goes back to the caller: a response, the address of a redirect, an error. A token written into one of
// these returns to whoever sent it; nothing is found or changed by it.
const ANSWERS = /^(?:Response|NextResponse|URL|URLSearchParams|Headers|\w*Error)$/;

/**
 * A call that looks at the value and keeps nothing of it: a pattern test, a byte copy, a serialisation.
 * Decided by what is called, not by the method's name: `/^\w+$/.test(id)` looks, `query.match({ id })`
 * and `db.exec(sql)` use.
 */
function onlyLooks(call: ts.CallExpression, project: Project): boolean {
  const callee = unwrap(call.expression);
  if (!ts.isPropertyAccessExpression(callee)) return false;
  const name = callee.name.text;
  const object = unwrap(callee.expression);
  if (name === "test" || name === "exec") {
    const value = ts.isIdentifier(object) ? (initializerOf(object) ?? project.constant(call.getSourceFile().fileName, object.text)?.value) : object;
    return !!value && ts.isRegularExpressionLiteral(unwrap(value));
  }
  if (ANSWERS.test(object.getText())) return true;
  return (name === "from" && object.getText() === "Buffer") || (name === "stringify" && object.getText() === "JSON");
}

/** No state is read or kept: no await, no `this`, and no name from outside the function except the language's own. */
function isPure(fn: Fn): boolean {
  let pure = true;
  const walk = (n: ts.Node): void => {
    if (!pure || ts.isTypeNode(n)) return;
    if (ts.isAwaitExpression(n) || n.kind === ts.SyntaxKind.ThisKeyword) pure = false;
    else if (ts.isIdentifier(n) && !isPropertyName(n)) {
      const d = declarationOf(n);
      const inside = d !== null && d.getStart() >= fn.getStart() && d.getEnd() <= fn.getEnd();
      if (!inside && !PURE_GLOBALS.has(n.text)) pure = false;
    }
    ts.forEachChild(n, walk);
  };
  if (fn.body) walk(fn.body);
  return pure;
}

/**
 * The `if` in a function that refuses a visitor who went over a limit: a count kept for this visitor is
 * compared with a number (or a limiter's yes/no is answered 429) and the branch turns the request away.
 * Null when there is none, or when the function does anything that lasts before it other than keeping the
 * count: a form that stores the lead and then counts the visitor has limited nothing.
 */
function limitingIf(fn: Fn, t: Taint, project: Project, entry: string): ts.IfStatement | null {
  if (!fn.body) return null;
  const counts = new Set<ts.Node>();
  const countVars = new Set<ts.Identifier>();
  for (const call of callsIn([fn.body])) {
    if (isCoercion(call) || !call.arguments.some((a) => carries(a, t, true))) continue;
    // A count is kept somewhere. A function that only reshapes the address (`parseIp(ip)`) keeps nothing,
    // so a test of what it returns is a format check, not a limit.
    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every(isPure)) continue;
    // Nor does a call that only reads (`BLOCKED.indexOf(ip)`, `Buffer.byteLength(ip)`): a blocklist or a
    // length check is not a limit.
    if (isInertCall(call, { project, entry }, 0)) continue;
    counts.add(call);
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
  let limit: ts.IfStatement | null = null;
  each(fn.body, (n) => {
    if (limit || !ts.isIfStatement(n) || !ifRefuses(n)) return;
    let limited = false;
    each(n.expression, (c) => {
      if (!ts.isBinaryExpression(c)) return;
      const op = c.operatorToken.kind;
      const relational =
        op === ts.SyntaxKind.GreaterThanToken || op === ts.SyntaxKind.GreaterThanEqualsToken || op === ts.SyntaxKind.LessThanToken || op === ts.SyntaxKind.LessThanEqualsToken;
      if (relational && (holdsCount(c.left) || holdsCount(c.right))) limited = true;
    });
    // A limiter library answers yes/no instead of a number: `if (!success) return 429`.
    if (!limited && holdsCount(n.expression) && /\b429\b/.test(n.getText())) limited = true;
    if (limited) limit = n;
  });
  const found = limit as ts.IfStatement | null;
  if (!found) return null;
  const from = found.getStart();
  return isInert(fn.body, { project, entry }, 0, (call) => counts.has(call) || call.getStart() >= from) ? found : null;
}

/** A count kept for this visitor is compared with a limit, and going over is refused. */
const visitorLimit: Sink = {
  throughCalls: false,
  hit: (fn, t, project, entry) => limitingIf(fn, t, project, entry) !== null,
};

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

/**
 * Does the function, or anything it calls within `hops`, use a module-level value whose declaration contains
 * `what`? A client built once at the top of a file (`const admin = createClient(url, SERVICE_ROLE_KEY)`) is
 * in no function's text, here or in the file it is imported from.
 */
function usesModuleValue(what: RegExp, fn: Fn, project: Project, entry: string, hops: number, seen = new Set<Fn>()): boolean {
  if (seen.has(fn) || !fn.body) return false;
  seen.add(fn);
  const file = fn.getSourceFile().fileName;
  const names = new Set<string>();
  each(fn.body, (n) => {
    if (!ts.isIdentifier(n) || isPropertyName(n) || names.has(n.text)) return;
    const d = declarationOf(n);
    if (d === null || ts.isSourceFile(statementOf(d)?.parent ?? d)) names.add(n.text);
  });
  for (const name of names) {
    const d = project.topVariable(file, name);
    if (!d) continue;
    if (what.test(d.getText())) return true;
    if (d.initializer && callsIn([d.initializer]).some((c) => project.resolveCall(c, entry).some((t) => withinReach(what, t, project, entry, 1)))) return true;
  }
  if (hops <= 0) return false;
  return callsIn([fn.body]).some((call) => project.resolveCall(call, entry).some((t) => usesModuleValue(what, t, project, entry, hops - 1, seen)));
}

export type HandlerGuard = "verified-request" | "link-token" | "visitor-limit";

/**
 * How a mutation handler is protected when the protection is not written in the route file itself, or
 * null when none can be shown.
 *
 *  verified-request  leaving the handler early depends on a signature check, a sealed value or a session
 *                    read, reached through the project's own helpers, before the handler does anything
 *                    that lasts.
 *  link-token        a URL segment is hashed (or compared in constant time) and its raw value is handed to
 *                    nothing else: the link is the permission. A plain id never qualifies, hashed or not.
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

    const cx: Ctx = { project, entry };
    if (verifiedRequest(handler, cx)) return "verified-request";

    // For the two shapes below the guard is inside the call the value is handed to. Whatever else the
    // handler does is outside it, so all of that has to be inert: a route that stores what it was sent and
    // then looks up the link, or counts the visitor, is open.
    const params = urlParams(handler);
    if ((params.whole.size || params.members.size) && handler.body && tokenUse(handler, params, project, entry, MAX_HOPS, new Set()) === "hashed") {
      const keyed = (call: ts.CallExpression): boolean => callCarries(call, params) || call.arguments.some((a) => carries(a, params, true));
      if (isInert(handler.body, cx, 0, keyed)) return "link-token";
    }

    const visitor = visitorAddress(handler, project, entry);
    if (visitor.nodes.size) {
      const walked = new Set<Fn>();
      if (reaches(handler, visitor, visitorLimit, project, entry, MAX_HOPS, walked)) {
        // A limit is not permission to write past row security. When the handler, or a helper within
        // two calls of it, writes to tables or calls auth.admin, and a service-role client is within the
        // same reach, the route stays reported.
        const writes = [...walked].some((f) => DATA_WRITE.test(f.getText())) || withinReach(DATA_WRITE, handler, project, entry, 2);
        const privileged = writes && (SERVICE_ROLE.test(sf.text) || withinReach(SERVICE_ROLE, handler, project, entry, 2) || usesModuleValue(SERVICE_ROLE, handler, project, entry, 2));
        // The limit protects what is handed the visitor's key, and what comes after a refusal the handler
        // itself makes on the count. Nothing else may last.
        const own = limitingIf(handler, visitor, project, entry);
        const after = own && own.parent === handler.body && alwaysLeaves(own.thenStatement) ? own.getEnd() : null;
        const behindLimit = (call: ts.CallExpression): boolean => visitor.nodes.has(call) || callCarries(call, visitor) || (after !== null && call.getStart() >= after);
        if (!privileged && handler.body && isInert(handler.body, cx, 0, behindLimit)) return "visitor-limit";
      }
    }
    return null;
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

/**
 * A value handed to the function, read as it stands or only reshaped: `sent`, `input.token`, `String(sent)`,
 * `sent.trim()`, or a `const` set to one. Not something worked out (`secret + body`) or read from elsewhere.
 */
function plainValue(e: ts.Expression, depth = 0): boolean {
  const v = unwrap(e);
  if (ts.isIdentifier(v)) {
    const d = declarationOf(v);
    if (!d || isReassigned(d)) return false;
    let holder: ts.Node = d.parent;
    while (ts.isBindingElement(holder) || ts.isObjectBindingPattern(holder)) holder = holder.parent;
    if (ts.isParameter(holder)) return true;
    const b = boundTo(v);
    return !!b && depth < 3 && plainValue(b.init, depth + 1);
  }
  if (ts.isPropertyAccessExpression(v)) return plainValue(v.expression, depth);
  if (!ts.isCallExpression(v) || !isCoercion(v)) return false;
  const callee = unwrap(v.expression);
  return ts.isPropertyAccessExpression(callee) ? v.arguments.length === 0 && plainValue(callee.expression, depth) : v.arguments.length === 1 && plainValue(v.arguments[0], depth);
}

/**
 * The value an unkeyed hash is taken of, for exactly `createHash(...).update(x).digest(...)` with one plain
 * `x`. Null for anything else: a keyed MAC (`createHmac`) is what a signature is checked against, and a hash
 * over a value joined with something (`update(secret + body)`) is a MAC by another name.
 */
function hashedValue(e: ts.Expression, project: Project): ts.Expression | null {
  const x = unwrap(e);
  if (!ts.isCallExpression(x) || calleeName(x) !== "digest") return null;
  const digest = unwrap(x.expression);
  const update = ts.isPropertyAccessExpression(digest) ? unwrap(digest.expression) : null;
  if (!update || !ts.isCallExpression(update) || calleeName(update) !== "update" || update.arguments.length < 1) return null;
  const updateCallee = unwrap(update.expression);
  const made = ts.isPropertyAccessExpression(updateCallee) ? unwrap(updateCallee.expression) : null;
  if (!made || !ts.isCallExpression(made) || !nodeCrypto(made, "createHash", project)) return null;
  return plainValue(update.arguments[0]) ? unwrap(update.arguments[0]) : null;
}

/** `const sha = (s) => createHash("sha256").update(s).digest("hex")`: the function's answer is the hash of its first argument. */
function returnsHashOfArgument(fn: Fn, project: Project): boolean {
  const first = fn.parameters[0];
  if (!fn.body || !first || !ts.isIdentifier(first.name)) return false;
  let returned: ts.Expression | undefined;
  if (!ts.isBlock(fn.body)) returned = fn.body;
  else if (fn.body.statements.length === 1 && ts.isReturnStatement(fn.body.statements[0])) returned = fn.body.statements[0].expression;
  const hashed = returned ? hashedValue(returned, project) : null;
  return !!hashed && ts.isIdentifier(hashed) && declarationOf(hashed) === first.name;
}

/** The name a function is called by: its own, or that of the variable or property that holds it. */
function nameOfFn(fn: Fn): { name: string; method: boolean } | null {
  if (ts.isFunctionDeclaration(fn)) return fn.name ? { name: fn.name.text, method: false } : null;
  if (ts.isMethodDeclaration(fn)) return ts.isIdentifier(fn.name) ? { name: fn.name.text, method: true } : null;
  const holder = fn.parent;
  if (ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name)) return { name: holder.name.text, method: false };
  if ((ts.isPropertyAssignment(holder) || ts.isPropertyDeclaration(holder)) && ts.isIdentifier(holder.name)) return { name: holder.name.text, method: true };
  return null;
}

/**
 * Is the expression proven to be an unkeyed hash of a value? By what it is, never by what it is called:
 *
 *   the hash written out                 createHash("sha256").update(sent).digest("hex")
 *   a project helper that is exactly it  sha(sent)
 *   a variable set once from one         const h = sha(sent)
 *   a parameter                          only when the project calls the function somewhere and EVERY call
 *                                        found in `files` fills that parameter with a proven hash
 */
function provenHash(e: ts.Expression, project: Project, files: string[], depth = 0): boolean {
  if (depth > 3) return false;
  const x = unwrap(e);
  if (hashedValue(x, project)) return true;
  if (ts.isCallExpression(x)) {
    const callee = unwrap(x.expression);
    if (!ts.isIdentifier(callee) || x.arguments.length !== 1 || !plainValue(x.arguments[0])) return false;
    const fns = project.resolveCall(x, x.getSourceFile().fileName);
    return fns.length === 1 && returnsHashOfArgument(fns[0], project);
  }
  if (!ts.isIdentifier(x)) return false;
  const b = boundTo(x);
  if (b) return b.prefix.length === 0 && provenHash(b.init, project, files, depth + 1);
  const d = declarationOf(x);
  const param = d?.parent;
  if (!d || !param || !ts.isParameter(param) || param.name !== d || param.dotDotDotToken || param.initializer || !isFn(param.parent) || isReassigned(d)) return false;
  const fn = param.parent;
  const named = nameOfFn(fn);
  if (!named) return false;
  const index = fn.parameters.indexOf(param);
  // Every place the name appears is looked at. A direct call has to hand over a proven hash; anything else
  // (the function passed along, renamed on import, pulled out of its object, reached through `.call`) is a
  // way to call it that cannot be followed, and one unknown caller is enough.
  let sites = 0;
  for (const file of files) {
    if (!(project.text(resolve(file)) ?? "").includes(named.name)) continue;
    const sf = project.source(file);
    if (!sf) return false;
    let ok = true;
    each(sf, (n) => {
      if (!ok) return;
      if (ts.isStringLiteralLike(n) && n.text === named.name && !ts.isImportDeclaration(n.parent)) ok = false;
      if (!ts.isIdentifier(n) || n.text !== named.name) return;
      if (n.getSourceFile() === fn.getSourceFile() && n.getStart() >= fn.getStart() && n.getEnd() <= fn.getEnd()) return; // inside the function itself
      const parent = n.parent;
      if (isFn(parent) || ((ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)) && parent.name === n && parent.initializer && unwrap(parent.initializer) === fn)) return; // its declaration
      for (let up: ts.Node | undefined = parent; up && !ts.isStatement(up); up = up.parent) if (ts.isTypeNode(up)) return;
      if ((ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)) && !parent.propertyName) return;
      const callee = ts.isPropertyAccessExpression(parent) && parent.name === n ? parent : n;
      let outer: ts.Node = callee;
      while (ts.isParenthesizedExpression(outer.parent) || ts.isNonNullExpression(outer.parent)) outer = outer.parent;
      const call = outer.parent;
      if (!ts.isCallExpression(call) || call.expression !== outer) {
        ok = false;
        return;
      }
      // A call of something else that shares the name is not a call of this function.
      // A call of something else that shares the name is not a call of this function. A method is taken
      // to be reached by any `x.name(...)`; a function only by a call that resolves to it.
      const reaches = named.method ? callee !== n : project.resolveCall(call, sf.fileName).includes(fn);
      if (!reaches) {
        if (callee === n && project.resolveCall(call, sf.fileName).length === 0) ok = false;
        return;
      }
      sites++;
      const arg = call.arguments[index];
      if (!arg || call.arguments.slice(0, index + 1).some(ts.isSpreadElement) || !provenHash(arg, project, files, depth + 1)) ok = false;
    });
    if (!ok) return false;
  }
  return sites > 0;
}

/**
 * True when an equality on this line finds a stored record by the hash of what the caller sent: one side is
 * a field of the stored row being iterated (`for (const s of rows) if (s.tokenHash === h)`,
 * `rows.find((r) => r.tokenHash === h)`) and the other side is PROVEN to be an unkeyed hash (see provenHash).
 * That is what a database index does, and its timing says nothing about the caller's secret.
 *
 * It fails closed. A field, variable, header or row that is merely named like a hash proves nothing
 * (`k.tokenHash === sent` is reported); so does a `.digest(` somewhere in the expression: a computed HMAC
 * matched with the signature sent (`s.signature === expected`) is a verification. Rows made on the spot
 * from the request, the iterated value itself (`sigs.some((sig) => sig === expected)`) and `some`/`every`
 * (a yes/no about the value compared) are never lookups.
 */
export function isRecordLookup(project: Project, file: string, line: number, mentions: RegExp, files: string[] = []): boolean {
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
    if (equality) equalities.push(n);
  });
  if (!equalities.some((b) => mentions.test(b.getText()))) return false;

  // Stored rows: a field of the object, a parameter, a module's own collection, or what an awaited read
  // handed back. A local list worked out from the request (`header.split(",").map(...)`) holds what the
  // caller sent, and matching it with anything is a decision about the caller.
  const stored = (rows: ts.Expression): boolean => {
    let r = unwrap(rows);
    while (ts.isCallExpression(r) && /^(?:values|entries)$/.test(calleeName(r))) {
      const callee = unwrap(r.expression);
      if (!ts.isPropertyAccessExpression(callee)) return false;
      r = unwrap(callee.expression);
    }
    let root = r;
    while (ts.isPropertyAccessExpression(root)) root = unwrap(root.expression);
    if (root.kind === ts.SyntaxKind.ThisKeyword) return true;
    if (!ts.isIdentifier(root)) return false;
    const d = declarationOf(root);
    if (!d) return false;
    if (ts.isParameter(d.parent) || !isLocal(root)) return true;
    const b = boundTo(root);
    // What an awaited read of the store handed back; not what was read from the request.
    return !!b && ts.isAwaitExpression(stripParens(b.init)) && !/\b(?:req|request)\b|\.(?:json|text|formData)\s*\(/.test(b.init.getText());
  };
  const iterated = (side: ts.Expression): boolean => {
    const s = unwrap(side);
    if (!ts.isPropertyAccessExpression(s) || !ts.isIdentifier(s.expression)) return false;
    const row = s.expression.text;
    for (let cur: ts.Node = s; cur.parent; cur = cur.parent) {
      const p = cur.parent;
      if ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && ts.isVariableDeclarationList(p.initializer)) {
        if (p.initializer.declarations.some((d) => bindingNames(d.name).includes(row))) return stored(p.expression);
      }
      if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && p.parameters.some((x) => bindingNames(x.name).includes(row))) {
        const call = p.parent;
        const receiver = ts.isCallExpression(call) ? unwrap(call.expression) : null;
        if (!receiver || !ts.isPropertyAccessExpression(receiver) || !stored(receiver.expression)) return false;
        // `find` and `filter` hand back the row. `some` and `every` hand back yes or no, which is a decision
        // about the value being compared, so they are never a lookup.
        return ts.isCallExpression(call) && call.arguments.includes(p) && /^(?:find|findLast|findIndex|findLastIndex|filter)$/.test(calleeName(call));
      }
    }
    return false;
  };
  const byKey = (row: ts.Expression, other: ts.Expression): boolean => iterated(row) && provenHash(other, project, files);
  // Every comparison on the line has to be such a lookup, or a test against something written in the code
  // (`r.kind === "log"`): a second comparison of two values (`given === adminPass`) keeps the line reported.
  const fixed = (x: ts.Expression): boolean => {
    const v = unwrap(x);
    return ts.isStringLiteralLike(v) || ts.isNumericLiteral(v) || v.kind === ts.SyntaxKind.TrueKeyword || v.kind === ts.SyntaxKind.FalseKeyword || v.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(v) && v.text === "undefined");
  };
  return equalities.every((b) => byKey(b.left, b.right) || byKey(b.right, b.left) || fixed(b.left) || fixed(b.right));
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
