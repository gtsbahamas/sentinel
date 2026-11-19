import re
p='src/layers/rules/handler-analysis.ts'
s=open(p).read()
def rep(old,new,n=1):
    global s
    assert s.count(old)==n, (s.count(old), old[:90])
    s=s.replace(old,new)
def refn(name,new):
    """replace a top-level function (signature to closing brace)"""
    global s
    m=re.search(r'^(?:export )?function '+re.escape(name)+r'[(<]', s, re.M)
    assert m, name
    j=s.index("\n}\n", m.start())+3
    s=s[:m.start()]+new.strip("\n")+"\n"+s[j:]

# ---------------- Project: packages, getters, frames
rep("""  /** The import behind a local name when it comes from a package, not from one of the project's own files. */
  packageImport(file: string, local: string): { spec: string; name: string } | null {
    const imported = this.importOf(file, local);
    if (!imported || !/^(?:node:)?(?:@[\\w.-]+\\/)?[\\w.-]+(?:\\/|$)/.test(imported.spec)) return null;
    return this.resolveModule(file, imported.spec) === null ? imported : null;
  }
""","""  /**
   * The import behind a local name when it is shown to come from a package: a Node built-in, or a package
   * the project's package.json lists. An import that merely fails to resolve (`#internal/log`, a path
   * mapping this does not know) is not a package; it is code that could not be read.
   */
  packageImport(file: string, local: string): { spec: string; name: string } | null {
    const imported = this.importOf(file, local);
    if (!imported || this.resolveModule(file, imported.spec) !== null) return null;
    if (/^(?:node:)?(?:crypto|buffer|util|url)$/.test(imported.spec)) return imported;
    const m = /^(@[\\w.-]+\\/[\\w.-]+|[\\w.-]+)(?:\\/|$)/.exec(imported.spec);
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
      if (!/\\bget\\s|defineProperty|Proxy/.test(this.text(file) ?? "")) continue;
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
""")
rep("  private aliases: Array<{ prefix: string; suffix: string; targets: string[] }> | null = null;\n",
"""  private aliases: Array<{ prefix: string; suffix: string; targets: string[] }> | null = null;
  private deps: Set<string> | null = null;
  private getters = new Map<string, Set<string>>();
  /** The call being followed into a helper, innermost first: where a helper's parameters get their values. */
  frame: Frame | null = null;
  /** Counts answers that depended on a call site's arguments: those are not kept per function. */
  siteDependent = 0;
""")
rep("type Fn = ts.FunctionDeclaration | ts.MethodDeclaration | ts.ArrowFunction | ts.FunctionExpression;\n",
"""type Fn = ts.FunctionDeclaration | ts.MethodDeclaration | ts.ArrowFunction | ts.FunctionExpression;

interface Frame {
  call: ts.CallExpression;
  target: Fn;
  parent: Frame | null;
}
""")
rep("""      const m = cls?.members.find((x): x is ts.MethodDeclaration => ts.isMethodDeclaration(x) && !!x.body && ts.isIdentifier(x.name) && x.name.text === name);
      return m ? [m] : [];""","""      const named = cls?.members.filter((x) => propertyKey(x.name) === name) ?? [];
      const m = named.length === 1 ? named[0] : undefined;
      return m && ts.isMethodDeclaration(m) && m.body && !m.asteriskToken ? [m] : [];""")
rep("""      if (imported && !this.resolveModule(file, imported.spec)) return []; // a package's object""",
    """      if (imported && !this.resolveModule(file, imported.spec)) return []; // a package's object, or code that could not be read""")

# ---------------- globals
rep("""function isLogging(call: ts.CallExpression, project: Project): boolean {""","""/** A name nothing in the file declares or imports: the language's or the platform's own. */
function isGlobal(id: ts.Identifier, project: Project): boolean {
  return declarationOf(id) === null && project.importOf(id.getSourceFile().fileName, id.text) === null;
}

function isLogging(call: ts.CallExpression, project: Project): boolean {""")
rep("""  if (root.text === "console") return declarationOf(root) === null;
  if (!/^(?:logger|log)$/i.test(root.text)) return false;
  // A logger from a package. The project's own `log` is read like any other of its functions.
  const file = call.getSourceFile().fileName;
  const imported = project.importOf(file, root.text);
  return imported !== null && project.resolveModule(file, imported.spec) === null;""",
"""  if (root.text === "console") return isGlobal(root, project);
  if (!/^(?:logger|log)$/i.test(root.text) || declarationOf(root) !== null) return false;
  // A logger from a package. The project's own `log` is read like any other of its functions.
  return project.packageImport(call.getSourceFile().fileName, root.text) !== null;""")

refn("nodeCrypto","""
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
""")
rep("""  const imported = cx.project.importOf(file, x.text);
  if (!imported) return false;
  if (cx.project.resolveModule(file, imported.spec) === null) return pkg.test(imported.spec) && (!exportName || exportName.test(imported.name));
  const top""","""  const fromPackage = cx.project.packageImport(file, x.text);
  if (fromPackage) return pkg.test(fromPackage.spec) && (!exportName || exportName.test(fromPackage.name));
  const top""")

# ---------------- secrets
rep("""const SUPABASE_CLIENT = /^create\\w*Client$/;""","""const SUPABASE_CLIENT = /^create\\w*Client$/;

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
}""")

# platformCheck body edits
rep("""    if (!nodeCrypto(call, name, cx.project) || call.arguments.length !== 2 || settledText(call.arguments[0]) === settledText(call.arguments[1])) return null;
    return value([], ["false"], false);""","""    if (!nodeCrypto(call, name, cx.project) || call.arguments.length !== 2 || settledText(call.arguments[0]) === settledText(call.arguments[1])) return null;
    // One side has to rest on a secret the server holds.
    if (!call.arguments.some((a) => secretDerived(a, cx))) return null;
    return value([], ["false"], false);""")
rep("""    if (!ts.isPropertyAccessExpression(callee) || !madeBy(callee.expression, /^stripe$/, null, cx)) return null;""",
    """    if (!ts.isPropertyAccessExpression(callee) || !madeBy(callee.expression, /^stripe$/, null, cx)) return null;
    if (!call.arguments[2] || !secretDerived(call.arguments[2], cx)) return null;""")
rep("""outerRoot(object)) return value([], ["false"], true);""","""outerRoot(object, cx.project)) {
      return call.arguments[1] && secretDerived(call.arguments[1], cx) ? value([], ["false"], true) : null;
    }""")
rep("""  if (!ts.isIdentifier(rootId) || !AUTH_CALLS.has(name)) return null;
  const spec = cx.project.importOf(call.getSourceFile().fileName, rootId.text)?.spec;
  if (!spec || !AUTH_PACKAGES.test(spec)) return null;
  const callback = call.arguments.some((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a));""",
"""  if (!ts.isIdentifier(rootId) || !AUTH_CALLS.has(name) || declarationOf(rootId) !== null) return null;
  const spec = cx.project.packageImport(call.getSourceFile().fileName, rootId.text)?.spec;
  if (!spec || !AUTH_PACKAGES.test(spec)) return null;
  const args = call.arguments;
  const keyed = (i: number): boolean => !!args[i] && secretDerived(args[i], cx);
  const receiverKeyed = ts.isPropertyAccessExpression(callee) && secretDerived(callee.expression, cx);""")
rep("""      return /^twilio/.test(spec) ? value([], ["false"], false) : null;
    case "jwtVerify":
      return /^jose/.test(spec) ? { kind: "asserts", awaited: true } : null;
    case "verify":
      if (/^(?:jsonwebtoken|svix)/.test(spec)) return callback ? null : { kind: "asserts", awaited: false };
      return /^@octokit\\/webhooks/.test(spec) ? value([], ["false"], true) : null;""",
"""      return /^twilio/.test(spec) && keyed(0) ? value([], ["false"], false) : null;
    case "jwtVerify":
      return /^jose/.test(spec) && args.length <= 3 && keyed(1) ? { kind: "asserts", awaited: true } : null;
    case "verify":
      // jsonwebtoken hands a failure to a callback, when given one, instead of throwing: the callback is the
      // third or fourth argument, written out or passed by name.
      if (/^jsonwebtoken/.test(spec)) return keyed(1) && (args.length === 2 || (args.length === 3 && ts.isObjectLiteralExpression(unwrap(args[2])))) ? { kind: "asserts", awaited: false } : null;
      if (/^svix/.test(spec)) return receiverKeyed && args.length === 2 ? { kind: "asserts", awaited: false } : null;
      return /^@octokit\\/webhooks/.test(spec) && receiverKeyed ? value([], ["false"], true) : null;""")

# ---------------- boundTo / isReassigned
rep("""  if (!ts.isVariableDeclaration(d) || !d.initializer || !ts.isVariableDeclarationList(d.parent)) return null;
  if ((d.parent.flags & ts.NodeFlags.Const) === 0 && isReassigned(decl)) return null;
  return { init: d.initializer, prefix };""","""  if (!ts.isVariableDeclaration(d) || !d.initializer || !ts.isVariableDeclarationList(d.parent)) return null;
  // A `var` can be declared twice and is the whole function's; only `let` and `const` are followed. Even a
  // `const` stops holding what it was set from once a field of it is written (`t.ok = true`).
  if ((d.parent.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0 || isReassigned(decl)) return null;
  return { init: d.initializer, prefix };""")
refn("isReassigned","""
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
""")
rep("""function isAssignment(kind: ts.SyntaxKind): boolean {""","""const reassigned = new WeakMap<ts.Identifier, boolean>();

function isAssignment(kind: ts.SyntaxKind): boolean {""")

# ---------------- proveValue object literal, proveCall frames
rep("""    if (path.length === 0 || x.properties.some((p) => !ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p))) return null;""",
    """    // A spread, a method, a getter or a computed key can put anything in any field.
    if (path.length === 0 || x.properties.some((p) => (!ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p)) || propertyKey(p.name) === null)) return null;""")
rep("""    if (!p) return x.properties.every((q) => propertyKey(q.name) !== null) ? { fails: new Set<Empty>([path.length > 1 ? "other" : "undefined"]) } : null;""",
    """    if (!p) return { fails: new Set<Empty>([path.length > 1 ? "other" : "undefined"]) };""")
rep("""  if (ts.isIdentifier(callee) && callee.text === "Boolean" && declarationOf(callee) === null && call.arguments.length === 1 && path.length === 0) {""",
    """  if (ts.isIdentifier(callee) && callee.text === "Boolean" && isGlobal(callee, cx.project) && call.arguments.length === 1 && path.length === 0) {""")
rep("""    const p = proveFn(t, "truthy", path, cx, depth + 1);
    if (!p) return null;""","""    const p = inFrame(cx, call, t, () => proveFn(t, "truthy", path, cx, depth + 1));
    if (!p) return null;""")
rep("""  return targets.length > 0 && targets.every((t) => (!isAsync(t) || awaited) && proveFn(t, "empty", path, cx, depth + 1) !== null);""",
    """  return targets.length > 0 && targets.every((t) => (!isAsync(t) || awaited) && inFrame(cx, x, t, () => proveFn(t, "empty", path, cx, depth + 1)) !== null);""")
rep("""    return targets.every((t) => (!isAsync(t) || awaited) && proveFn(t, "asserts", [], this.cx, this.depth + 1) !== null);""",
    """    return targets.every((t) => (!isAsync(t) || awaited) && inFrame(this.cx, call, t, () => proveFn(t, "asserts", [], this.cx, this.depth + 1)) !== null);""")
rep("""      if (!made || !ts.isCallExpression(made) || !nodeCrypto(made, "createDecipheriv", this.cx.project)) return false;""",
    """      if (!made || !ts.isCallExpression(made) || !nodeCrypto(made, "createDecipheriv", this.cx.project)) return false;
      if (!made.arguments[1] || !secretDerived(made.arguments[1], this.cx)) return false;""")

# ---------------- inert
rep("const INERT_CLASSES = /^(?:Response|NextResponse|URL|URLSearchParams|Headers|FormData|TextEncoder|TextDecoder|Date|Map|Set|RegExp|Uint8Array|\\w*Error)$/;",
"""const INERT_CLASSES = /^(?:Response|URL|URLSearchParams|Headers|FormData|TextEncoder|TextDecoder|Date|Map|Set|RegExp|Uint8Array|(?:Type|Range|Syntax|Reference|Eval|URI|Aggregate)?Error)$/;

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
  if (isGlobal(name, cx.project)) return INERT_CLASSES.test(name.text);
  if (declarationOf(name) === null) {
    const pkg = cx.project.packageImport(file, name.text);
    if (pkg) return pkg.spec === "next/server" && pkg.name === "NextResponse";
  }
  const cls = classNamed(cx.project, file, name.text, 3);
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
}""")
refn("outerRoot","""
function outerRoot(e: ts.Expression, project: Project): boolean {
  let root = unwrap(e);
  while (ts.isPropertyAccessExpression(root)) root = unwrap(root.expression);
  return ts.isIdentifier(root) && isGlobal(root, project);
}
""")
rep("""    } else if (ts.isNewExpression(n)) {
      if (!INERT_CLASSES.test(n.expression.getText()) && !ts.isThrowStatement(n.parent)) ok = false;
    } else if (ts.isTaggedTemplateExpression(n) || ts.isDeleteExpression(n)) {
      ok = false;""","""    } else if (ts.isNewExpression(n)) {
      if (!isInertNew(n, cx)) ok = false;
    } else if (ts.isTaggedTemplateExpression(n) || ts.isDeleteExpression(n) || ts.isYieldExpression(n)) {
      ok = false;
    } else if ((ts.isForOfStatement(n) || ts.isForInStatement(n)) && !ts.isVariableDeclarationList(n.initializer)) {
      if (!isLocalWrite(n.initializer)) ok = false;
    } else if (ts.isPropertyAccessExpression(n) && getters.size > 0 && (getters.has("*") || getters.has(n.name.text))) {
      // Reading the property may run one of the project's getters.
      ok = false;
    } else if (ts.isElementAccessExpression(n) && getters.size > 0 && !ts.isStringLiteralLike(n.argumentExpression) && !ts.isNumericLiteral(n.argumentExpression) && !isLocalIndex(n)) {
      ok = false;""")
rep("""  let ok = true;
  const visit = (n: ts.Node): void => {
    if (!ok) return;
    if (ts.isTypeNode(n)) return;""","""  let ok = true;
  const getters = cx.project.gettersIn(cx.entry);
  const visit = (n: ts.Node): void => {
    if (!ok) return;
    if (ts.isTypeNode(n)) return;""")
rep("""/**
 * True when running the node changes nothing that lasts""","""/** `parts[i]` on a local array or string: no getter of the project's is behind it. */
function isLocalIndex(n: ts.ElementAccessExpression): boolean {
  const object = unwrap(n.expression);
  return ts.isIdentifier(object) && isLocal(object);
}

/**
 * True when running the node changes nothing that lasts""")
rep("""  return ts.isObjectLiteralExpression(made) || ts.isArrayLiteralExpression(made) || (ts.isNewExpression(made) && INERT_CLASSES.test(made.expression.getText()));""",
    """  const fresh = ts.isNewExpression(made) && ts.isIdentifier(made.expression) && declarationOf(made.expression) === null && INERT_CLASSES.test(made.expression.text);
  return ts.isObjectLiteralExpression(made) || ts.isArrayLiteralExpression(made) || fresh;""")

refn("isInertCall","""
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
    return /^@supabase\\//.test(imported.spec) && SUPABASE_CLIENT.test(imported.name);
  }
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return false;
  const name = callee.name.text;
  const object = unwrap(callee.expression);
  const objectText = object.getText().replace(/\\s+/g, "");
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
""")
refn("isInertFn","""
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
""")

# ---------------- Walk.asserts: only where the call is sure to run
a=s.index("  private asserts(node: ts.Node): boolean {")
b=s.index("  private isAssertCall(")
s=s[:a]+"""  private asserts(node: ts.Node): boolean {
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

"""+s[b:]

# ungated handler return: nothing of the module's goes back to everyone
rep("""  private ungatedReturn(e: ts.Expression | undefined): void {
    if (this.sense === "handler") return;""","""  private ungatedReturn(e: ts.Expression | undefined): void {
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
    }""")

# proveFn: generators, parameter defaults, site-dependent answers
rep("""  if (!fn.body) return null;
  if (depth > MAX_PROOF_DEPTH || cx.project.proofActive.has(fn)) {
    cx.project.cuts++;
    return null;
  }
  const cuts = cx.project.cuts;
  cx.project.proofActive.add(fn);""","""  // Calling a generator runs none of its body. A parameter's default value runs with the call.
  if (!fn.body || fn.asteriskToken || !fn.parameters.every((p) => isInert(p, cx, 0))) return null;
  if (depth > MAX_PROOF_DEPTH || cx.project.proofActive.has(fn)) {
    cx.project.cuts++;
    return null;
  }
  const cuts = cx.project.cuts;
  const sites = cx.project.siteDependent;
  cx.project.proofActive.add(fn);""")
rep("""  cx.project.proofActive.delete(fn);
  if (result || cuts === cx.project.cuts) {""","""  cx.project.proofActive.delete(fn);
  // An answer that looked at the arguments of the call being followed holds for that call only.
  if (sites === cx.project.siteDependent && (result || cuts === cx.project.cuts)) {""")
rep("""  if (handler.parameters.some((p) => p.initializer && !isInert(p.initializer, cx, 0))) return false;""",
    """  if (handler.asteriskToken || !handler.parameters.every((p) => isInert(p, cx, 0))) return false;""")

# ---------------- visitor limit: a count is kept somewhere
rep("""    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every(isPure)) continue;
    counts.add(call);""","""    const targets = project.resolveCall(call, entry);
    if (targets.length > 0 && targets.every(isPure)) continue;
    // Nor does a call that only reads (`BLOCKED.indexOf(ip)`, `Buffer.byteLength(ip)`): a blocklist or a
    // length check is not a limit.
    if (isInertCall(call, { project, entry }, 0)) continue;
    counts.add(call);""")

# ---------------- link token: the hash has to be used for something whose answer is kept
rep("""    if (isCoercion(call) || isLogging(call, project)) continue;
    if (hashesValue(call, t)) {
      hashed = true;
      continue;
    }""","""    if (isCoercion(call) || isLogging(call, project)) continue;
    if (hashesValue(call, t)) {
      hashed = true;
      continue;
    }
    // A call handed the token (or its hash) whose answer is thrown away finds nothing: it stores.
    if (call.arguments.some((a) => carries(a, t, true))) {
      let top: ts.Node = call;
      while (ts.isAwaitExpression(top.parent) || ts.isParenthesizedExpression(top.parent) || ts.isVoidExpression(top.parent)) top = top.parent;
      if (ts.isExpressionStatement(top.parent)) return "raw";
    }""")
open(p,'w').write(s)
