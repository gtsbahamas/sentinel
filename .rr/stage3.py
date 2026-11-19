import re
p='src/layers/rules/handler-analysis.ts'
s=open(p).read()
def rep(old,new,n=1):
    global s
    assert s.count(old)==n, (s.count(old), old[:90])
    s=s.replace(old,new)
def refn(name,new):
    global s
    m=re.search(r'^(?:export )?function '+re.escape(name)+r'[(<]', s, re.M)
    assert m, name
    j=s.index("\n}\n", m.start())+3
    s=s[:m.start()]+new.strip("\n")+"\n"+s[j:]

rep("/** A value read as it stands, or only reshaped: `sent`, `input.token`, `String(sent)`, `sent.trim()`. */",
    "/**\n * A value handed to the function, read as it stands or only reshaped: `sent`, `input.token`, `String(sent)`,\n * `sent.trim()`, or a `const` set to one. Not something worked out (`secret + body`) or read from elsewhere.\n */")
refn("plainValue","""
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
""")
refn("provenHash","""
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
      if (!named.method && !project.resolveCall(call, sf.fileName).includes(fn)) {
        if (callee === n && declarationOf(n) === null && project.lookup(sf.fileName, n.text) === null) ok = false;
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
""")
rep("""    if (equality && mentions.test(n.getText())) equalities.push(n);
  });
  if (equalities.length === 0) return false;
""","""    if (equality) equalities.push(n);
  });
  if (!equalities.some((b) => mentions.test(b.getText()))) return false;
""")
rep("""    return !!b && ts.isAwaitExpression(stripParens(b.init));
  };""","""    // What an awaited read of the store handed back; not what was read from the request.
    return !!b && ts.isAwaitExpression(stripParens(b.init)) && !/\\b(?:req|request)\\b|\\.(?:json|text|formData)\\s*\\(/.test(b.init.getText());
  };""")
rep("""  const byKey = (row: ts.Expression, other: ts.Expression): boolean => iterated(row) && provenHash(other, project, files);
  return equalities.every((b) => byKey(b.left, b.right) || byKey(b.right, b.left));""",
"""  const byKey = (row: ts.Expression, other: ts.Expression): boolean => iterated(row) && provenHash(other, project, files);
  // Every comparison on the line has to be such a lookup, or a test against something written in the code
  // (`r.kind === "log"`): a second comparison of two values (`given === adminPass`) keeps the line reported.
  const fixed = (x: ts.Expression): boolean => {
    const v = unwrap(x);
    return ts.isStringLiteralLike(v) || ts.isNumericLiteral(v) || v.kind === ts.SyntaxKind.TrueKeyword || v.kind === ts.SyntaxKind.FalseKeyword || v.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(v) && v.text === "undefined");
  };
  return equalities.every((b) => byKey(b.left, b.right) || byKey(b.right, b.left) || fixed(b.left) || fixed(b.right));""")
open(p,'w').write(s)
