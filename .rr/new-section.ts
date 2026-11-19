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

function isLogging(call: ts.CallExpression, project: Project): boolean {
  let root: ts.Expression = unwrap(call.expression);
  while (ts.isPropertyAccessExpression(root) || ts.isCallExpression(root)) root = unwrap(root.expression);
  if (!ts.isIdentifier(root)) return false;
  // `console` is the platform's; a `logger` counts only when it is imported, not when it is a local name
  // for something else (`const log = ledger`).
  if (root.text === "console") return declarationOf(root) === null;
  return /^(?:logger|log)$/i.test(root.text) && project.importOf(call.getSourceFile().fileName, root.text) !== null;
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

const MAX_PROOF_DEPTH = 6;

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

type PlatformCheck = { kind: "value"; path: string[]; fails: Empty[]; awaited: boolean } | { kind: "asserts"; awaited: boolean };

/**
 * The library calls that decide whether a request is genuine, with how each one says no: which field of its
 * answer is empty for an unverified request, or that it throws. Only these are taken on trust.
 */
function platformCheck(call: ts.CallExpression, cx: Ctx): PlatformCheck | null {
  const callee = unwrap(call.expression);
  const name = calleeName(call);
  const value = (path: string[], fails: Empty[], awaited: boolean): PlatformCheck => ({ kind: "value", path, fails, awaited });
  if (name === "timingSafeEqual") {
    // Comparing a value with itself answers yes for everyone.
    if (call.arguments.length !== 2 || settledText(call.arguments[0]) === settledText(call.arguments[1])) return null;
    return value([], ["false"], false);
  }
  if (name === "constructEvent") return { kind: "asserts", awaited: false };
  if (name === "constructEventAsync") return { kind: "asserts", awaited: true };
  if (ts.isPropertyAccessExpression(callee)) {
    const object = callee.expression.getText();
    if (name === "verify" && /\bsubtle$/.test(object)) return value([], ["false"], true);
    if (/\bauth$/.test(object)) {
      if (name === "getUser") return value(["data", "user"], ["null"], true);
      if (name === "getSession") return value(["data", "session"], ["null"], true);
      if (name === "getClaims") return value(["data"], ["null"], true);
    }
  }
  let rootId: ts.Expression = callee;
  while (ts.isPropertyAccessExpression(rootId) || ts.isCallExpression(rootId)) rootId = unwrap(rootId.expression);
  if (!ts.isIdentifier(rootId) || !AUTH_CALLS.has(name)) return null;
  const spec = cx.project.importOf(call.getSourceFile().fileName, rootId.text)?.spec;
  if (!spec || !AUTH_PACKAGES.test(spec)) return null;
  const callback = call.arguments.some((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a));
  switch (name) {
    case "validateRequest":
    case "validateRequestWithBody":
      return /^twilio/.test(spec) ? value([], ["false"], false) : null;
    case "jwtVerify":
      return /^jose/.test(spec) ? { kind: "asserts", awaited: true } : null;
    case "verify":
      if (/^(?:jsonwebtoken|svix)/.test(spec)) return callback ? null : { kind: "asserts", awaited: false };
      return /^@octokit\/webhooks/.test(spec) ? value([], ["false"], true) : null;
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
  if ((d.parent.flags & ts.NodeFlags.Const) === 0 && isReassigned(decl)) return null;
  return { init: d.initializer, prefix };
}

function isAssignment(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

/** A `let` that is written to anywhere after its declaration no longer holds what it was set from. */
function isReassigned(decl: ts.Identifier): boolean {
  let scope: ts.Node = decl;
  while (scope.parent && !isFn(scope) && !ts.isSourceFile(scope)) scope = scope.parent;
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
  });
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
function proveValue(e: ts.Expression, path: string[], cx: Ctx, depth: number, awaitedHint = false): Proof | null {
  if (depth > MAX_PROOF_DEPTH) return null;
  let x = e;
  let awaited = awaitedHint;
  for (;;) {
    if (ts.isAwaitExpression(x)) awaited = true;
    else if (!(ts.isParenthesizedExpression(x) || ts.isNonNullExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x) || ts.isTypeAssertionExpression(x))) break;
    x = x.expression;
  }
  const empty = emptyLiteral(x);
  // An empty literal is never truthy, so the claim holds of it whatever the path.
  if (empty) return { fails: new Set([path.length ? "other" : empty]) };
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return b ? proveValue(b.init, [...b.prefix, ...path], cx, depth + 1) : null;
  }
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name)) return proveValue(x.expression, [x.name.text, ...path], cx, depth + 1);
  if (ts.isElementAccessExpression(x) && ts.isStringLiteralLike(x.argumentExpression)) return proveValue(x.expression, [x.argumentExpression.text, ...path], cx, depth + 1);
  if (ts.isObjectLiteralExpression(x)) {
    // `{ ok: false, res }` asked for `ok`. As a whole an object is always truthy, so it proves nothing.
    if (path.length === 0 || x.properties.some((p) => !ts.isPropertyAssignment(p) && !ts.isShorthandPropertyAssignment(p))) return null;
    const p = x.properties.find((q) => propertyKey(q.name) === path[0]);
    if (!p) return x.properties.every((q) => propertyKey(q.name) !== null) ? { fails: new Set<Empty>([path.length > 1 ? "other" : "undefined"]) } : null;
    return proveValue(ts.isPropertyAssignment(p) ? p.initializer : (p as ts.ShorthandPropertyAssignment).name, path.slice(1), cx, depth + 1);
  }
  if (ts.isCallExpression(x)) return proveCall(x, awaited, path, cx, depth);
  if (path.length > 0) return null;
  if (ts.isConditionalExpression(x)) {
    const a = proveValue(x.whenTrue, [], cx, depth + 1);
    const b = a && proveValue(x.whenFalse, [], cx, depth + 1);
    return a && b ? union(a, b) : null;
  }
  if (ts.isBinaryExpression(x)) {
    const op = x.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      const a = proveValue(x.left, [], cx, depth + 1);
      const b = proveValue(x.right, [], cx, depth + 1);
      if (a && b) return union(a, b);
      // Unverified means the proven side was empty. With the left proven the result IS the left; with only
      // the right proven the left may have stopped it at any empty value.
      if (a) return a;
      return b ? union(b, { fails: new Set<Empty>(["other"]) }) : null;
    }
    if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) {
      const a = proveValue(x.left, [], cx, depth + 1);
      const b = a && proveValue(x.right, [], cx, depth + 1);
      return a && b ? union(a, b) : null;
    }
  }
  // `!x`, `x === true`, `x != null`: a yes/no that says yes only for the verified.
  if (ts.isPrefixUnaryExpression(x) || ts.isBinaryExpression(x)) return yesMeansVerified(x, cx, depth + 1) ? { fails: new Set<Empty>(["false"]) } : null;
  return null;
}

function proveCall(call: ts.CallExpression, awaited: boolean, path: string[], cx: Ctx, depth: number): Proof | null {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee) && callee.text === "Boolean" && declarationOf(callee) === null && call.arguments.length === 1 && path.length === 0) {
    return proveValue(call.arguments[0], [], cx, depth + 1) ? { fails: new Set<Empty>(["false"]) } : null;
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
    const p = proveFn(t, "truthy", path, cx, depth + 1);
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
  if (ts.isNewExpression(x) || ts.isObjectLiteralExpression(x) || ts.isArrayLiteralExpression(x)) return true;
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
  if (depth > MAX_PROOF_DEPTH) return false;
  let x = e;
  let awaited = awaitedHint;
  for (;;) {
    if (ts.isAwaitExpression(x)) awaited = true;
    else if (!(ts.isParenthesizedExpression(x) || ts.isNonNullExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x) || ts.isTypeAssertionExpression(x))) break;
    x = x.expression;
  }
  if (neverEmpty(x, path)) return true;
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return !!b && proveEmptyMeansVerified(b.init, [...b.prefix, ...path], cx, depth + 1);
  }
  if (ts.isPropertyAccessExpression(x) && ts.isIdentifier(x.name)) return proveEmptyMeansVerified(x.expression, [x.name.text, ...path], cx, depth + 1);
  if (!ts.isCallExpression(x)) return false;
  const targets = cx.project.resolveCall(x, cx.entry);
  return targets.length > 0 && targets.every((t) => (!isAsync(t) || awaited) && proveFn(t, "empty", path, cx, depth + 1) !== null);
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
  if (depth > MAX_PROOF_DEPTH) return false;
  const e = stripParens(c);
  if (ts.isPrefixUnaryExpression(e)) return e.operator === ts.SyntaxKind.ExclamationToken && noMeansVerified(e.operand, cx, depth + 1);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) return yesMeansVerified(e.left, cx, depth + 1) || yesMeansVerified(e.right, cx, depth + 1);
    if (op === ts.SyntaxKind.BarBarToken) return yesMeansVerified(e.left, cx, depth + 1) && yesMeansVerified(e.right, cx, depth + 1);
    const cmp = comparison(e);
    if (!cmp) return false;
    const p = proveValue(cmp.value, [], cx, depth + 1);
    if (!p) return false;
    // `x === true` is true only for a truthy x. `x !== false` is true for everything but false, so it is
    // true only for the verified when false is all a failed check ever leaves.
    if (cmp.literal === "true") return cmp.equal && cmp.strict;
    return !cmp.equal && subset(p.fails, covered(cmp.literal, cmp.strict));
  }
  return proveValue(e, [], cx, depth + 1) !== null;
}

/** True when the condition can only be FALSE for a verified request: the test a refusal hangs on. */
function noMeansVerified(c: ts.Expression, cx: Ctx, depth: number): boolean {
  if (depth > MAX_PROOF_DEPTH) return false;
  const e = stripParens(c);
  if (ts.isPrefixUnaryExpression(e)) return e.operator === ts.SyntaxKind.ExclamationToken && yesMeansVerified(e.operand, cx, depth + 1);
  if (ts.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    // Every part of an `&&` has to turn the unverified away by itself: the other part can say no first.
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) return noMeansVerified(e.left, cx, depth + 1) && noMeansVerified(e.right, cx, depth + 1);
    if (op === ts.SyntaxKind.BarBarToken) {
      if (noMeansVerified(e.left, cx, depth + 1) || noMeansVerified(e.right, cx, depth + 1)) return true;
      return coveredTogether(e, cx, depth);
    }
    const cmp = comparison(e);
    if (!cmp) return false;
    const p = proveValue(cmp.value, [], cx, depth + 1);
    if (!p) return false;
    if (cmp.literal === "true") return !cmp.equal && cmp.strict;
    return cmp.equal && subset(p.fails, covered(cmp.literal, cmp.strict));
  }
  return proveEmptyMeansVerified(e, [], cx, depth + 1);
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
    const p = proveValue(value, [], cx, depth + 1);
    if (p && subset(p.fails, covers)) return true;
  }
  return false;
}

// --- Inert code: the allow-list ------------------------------------------------------------------------

// Methods that read a string, an array, a buffer or a date and change nothing.
const READ_METHODS = new Set(
  (
    "includes indexOf lastIndexOf slice concat join trim trimStart trimEnd toLowerCase toUpperCase toString toFixed normalize " +
    "padStart padEnd startsWith endsWith split replace replaceAll match matchAll test substring charAt charCodeAt localeCompare " +
    "repeat at flat keys values entries subarray toISOString getTime valueOf " +
    "json text formData arrayBuffer blob clone then catch finally parse safeParse parseAsync safeParseAsync"
  ).split(" "),
);
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
const INERT_CLASSES = /^(?:Response|NextResponse|URL|URLSearchParams|Headers|FormData|TextEncoder|TextDecoder|Date|Map|Set|RegExp|Uint8Array|\w*Error)$/;

/** The root name of `a.b.c` when nothing in the file's functions declares it: a global or an import. */
function outerRoot(e: ts.Expression): boolean {
  let root = unwrap(e);
  while (ts.isPropertyAccessExpression(root)) root = unwrap(root.expression);
  if (!ts.isIdentifier(root)) return false;
  const d = declarationOf(root);
  return d === null;
}

/** A hash, MAC or cipher object: `createHash(...)`, a chain of `.update()` on one, or a variable set from one. */
function isCipherObject(e: ts.Expression, depth = 0): boolean {
  const x = unwrap(e);
  if (depth > 4) return false;
  if (ts.isCallExpression(x)) {
    const name = calleeName(x);
    if (CIPHER_MAKERS.has(name)) return true;
    const callee = unwrap(x.expression);
    return name === "update" && ts.isPropertyAccessExpression(callee) && isCipherObject(callee.expression, depth + 1);
  }
  if (ts.isIdentifier(x)) {
    const b = boundTo(x);
    return !!b && b.prefix.length === 0 && isCipherObject(b.init, depth + 1);
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
  return ts.isObjectLiteralExpression(made) || ts.isArrayLiteralExpression(made) || (ts.isNewExpression(made) && INERT_CLASSES.test(made.expression.getText()));
}

/**
 * True when running the node changes nothing that lasts and sends nothing out: every call in it is on the
 * allow-list (reading the request, computing, building an answer, logging, the listed verifications) or is a
 * project function whose own body is inert. `accept` lets a caller take specific calls as given. The default
 * for anything not recognised is "not inert".
 */
function isInert(node: ts.Node, cx: Ctx, depth: number, accept?: (call: ts.CallExpression) => boolean): boolean {
  let ok = true;
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
      if (!INERT_CLASSES.test(n.expression.getText()) && !ts.isThrowStatement(n.parent)) ok = false;
    } else if (ts.isTaggedTemplateExpression(n) || ts.isDeleteExpression(n)) {
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
  if (isLogging(call, cx.project) || isVerification(call, cx)) return true;
  const callee = unwrap(call.expression);
  const targets = cx.project.resolveCall(call, cx.entry);
  if (targets.length > 0) return targets.every((t) => isInertFn(t, cx, depth + 1));
  if (ts.isIdentifier(callee)) {
    if (declarationOf(callee) !== null) return false; // a parameter or a local that could not be resolved
    if (COERCION_FUNCTIONS.has(callee.text) || GLOBAL_READS.has(callee.text)) return true;
    const imported = cx.project.importOf(call.getSourceFile().fileName, callee.text);
    if (!imported) return false;
    if (/^(?:node:)?crypto$/.test(imported.spec)) return CRYPTO_FUNCTIONS.has(imported.name);
    if (imported.spec === "next/headers") return imported.name === "cookies" || imported.name === "headers";
    // A Supabase client being made. What is done with it is a separate call.
    return /^@supabase\//.test(imported.spec) && /^create\w*Client$/.test(imported.name);
  }
  if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.name)) return false;
  const name = callee.name.text;
  const object = unwrap(callee.expression);
  const objectText = object.getText().replace(/\s+/g, "");
  const statics = STATIC_READS[objectText];
  if (statics && outerRoot(object)) return statics === "any" || statics.has(name);
  if (CIPHER_METHODS.has(name) && isCipherObject(object)) return true;
  if (CIPHER_METHODS.has(name)) return false;
  if (LOOKUP_METHODS.has(name)) {
    if (REQUEST_DATA.test(objectText)) return true;
    const b = ts.isIdentifier(object) ? boundTo(object) : null;
    return !!b && REQUEST_DATA_SOURCE.test(b.init.getText());
  }
  if (CALLBACK_METHODS.has(name)) return call.arguments.length > 0 && (ts.isArrowFunction(call.arguments[0]) || ts.isFunctionExpression(call.arguments[0]));
  return READ_METHODS.has(name);
}

function isInertFn(fn: Fn, cx: Ctx, depth: number): boolean {
  const memo = cx.project.inertMemo.get(fn);
  if (memo !== undefined) return memo;
  if (!fn.body || depth > MAX_HOPS || cx.project.inertActive.has(fn)) return false;
  cx.project.inertActive.add(fn);
  const result = isInert(fn.body, cx, depth);
  cx.project.inertActive.delete(fn);
  // A "no" reached while part of a cycle or the depth limit cut the walk short is not final.
  if (result || (cx.project.inertActive.size === 0 && depth === 0)) cx.project.inertMemo.set(fn, result);
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
    if (this.sense === "handler") return;
    if (this.sense === "asserts") throw new Unproven();
    if (this.sense === "empty") {
      if (!e || !proveEmptyMeansVerified(e, this.path, this.cx, this.depth + 1, isAsync(this.fn))) throw new Unproven();
      return;
    }
    if (!e) {
      this.fails.add("undefined");
      return;
    }
    const p = proveValue(e, this.path, this.cx, this.depth + 1, isAsync(this.fn));
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
    const visit = (n: ts.Node): void => {
      if (found || isFn(n)) return;
      if (ts.isConditionalExpression(n)) return visit(n.condition);
      if (ts.isBinaryExpression(n)) {
        const op = n.operatorToken.kind;
        if (op === ts.SyntaxKind.AmpersandAmpersandToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) return visit(n.left);
      }
      if (ts.isCallExpression(n)) {
        if (n.questionDotToken) return;
        const callee = unwrap(n.expression);
        if (ts.isPropertyAccessExpression(callee) && /^(?:catch|then|finally)$/.test(callee.name.text)) return;
        if (this.isAssertCall(n)) {
          found = true;
          return;
        }
      }
      ts.forEachChild(n, visit);
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
      if (!made || !ts.isCallExpression(made) || calleeName(made) !== "createDecipheriv") return false;
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
    return targets.every((t) => (!isAsync(t) || awaited) && proveFn(t, "asserts", [], this.cx, this.depth + 1) !== null);
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
  if (!fn.body || depth > MAX_PROOF_DEPTH || cx.project.proofActive.has(fn)) return null;
  cx.project.proofActive.add(fn);
  let result: Proof | null = null;
  try {
    if (!ts.isBlock(fn.body)) {
      // `const check = (req) => sameBytes(a, b)`: the body is the answer.
      if (sense === "truthy" && isInert(fn.body, cx, 0)) result = proveValue(fn.body, path, cx, depth + 1, isAsync(fn));
      else if (sense === "empty" && isInert(fn.body, cx, 0) && proveEmptyMeansVerified(fn.body, path, cx, depth + 1, isAsync(fn))) result = { fails: new Set() };
    } else {
      const walk = new Walk(cx, fn, sense, path, depth);
      const gatedAtEnd = walk.seq(fn.body.statements, false);
      // Running off the end answers `undefined`.
      if (sense === "truthy") result = { fails: gatedAtEnd ? walk.fails : new Set<Empty>([...walk.fails, "undefined"]) };
      else if (sense === "asserts") result = gatedAtEnd && walk.used ? { fails: new Set() } : null;
      else if (sense === "empty") result = gatedAtEnd && walk.used ? { fails: new Set() } : null;
    }
  } catch (err) {
    if (!(err instanceof Unproven)) throw err;
    result = null;
  }
  cx.project.proofActive.delete(fn);
  // A "no" reached while part of a cycle or the depth limit cut the proof short is not final.
  if (result || (cx.project.proofActive.size === 0 && depth === 0)) {
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
  const walk = new Walk(cx, handler, "handler", [], 0);
  try {
    walk.seq(handler.body.statements, false);
  } catch (err) {
    if (!(err instanceof Unproven)) throw err;
    return false;
  }
  return walk.used;
}

