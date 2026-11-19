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
  if ((call.flags & ts.NodeFlags.OptionalChain) !== 0 || !call.arguments.every((a) => isQuiet(a, fn, cx, depth))) return false;
  if (isNextHeaders(call, cx) || isClient(call, cx) || sessionRead(call, cx)) return true;
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

