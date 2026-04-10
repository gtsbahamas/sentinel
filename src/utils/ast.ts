import ts from "typescript";

export function parseSource(fileName: string, source: string): ts.SourceFile {
  return ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    fileName.endsWith(".tsx") || fileName.endsWith(".jsx")
      ? ts.ScriptKind.TSX
      : ts.ScriptKind.TS,
  );
}

export function walkAst(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => walkAst(child, callback));
}

export function findIdentifierUsages(sf: ts.SourceFile, name: string): ts.Node[] {
  const usages: ts.Node[] = [];
  walkAst(sf, (node) => {
    if (ts.isIdentifier(node) && node.text === name) {
      usages.push(node);
    }
  });
  return usages;
}

export function findImportsFrom(sf: ts.SourceFile, moduleName: string): string[] {
  const imports: string[] = [];
  walkAst(sf, (node) => {
    if (ts.isImportDeclaration(node)) {
      const mod = node.moduleSpecifier;
      if (ts.isStringLiteral(mod) && mod.text === moduleName) {
        const clause = node.importClause;
        if (clause?.name) imports.push(clause.name.text);
        if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            imports.push(element.name.text);
          }
        }
      }
    }
  });
  return imports;
}

export function findStringLiterals(sf: ts.SourceFile): string[] {
  const literals: string[] = [];
  walkAst(sf, (node) => {
    if (ts.isStringLiteral(node)) literals.push(node.text);
    if (ts.isNoSubstitutionTemplateLiteral(node)) literals.push(node.text);
  });
  return literals;
}

export function getLineNumber(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

export function getColumnNumber(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart()).character + 1;
}
