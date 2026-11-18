// Is this file test code? Decided by what the file contains, not by where it lives: it imports a test
// framework, or it is written as describe/it/test blocks with expect. Test code runs against throwaway
// data on a developer's machine or in CI; no visitor's input reaches it, so rules about what an attacker
// can send do not apply to it.
const TEST_FRAMEWORK =
  /(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)["'](?:vitest|jest|@jest\/globals|mocha|chai|node:test|bun:test|ava|tap|@playwright\/test|cypress|supertest|@testing-library\/[\w-]+)["']/;
const TEST_BLOCK = /^\s*(?:describe|it|test)(?:\.\w+)?\s*\(\s*["'`]/m;
const EXPECTATION = /\b(?:expect|assert)\s*[.(]/;

export function isTestCode(source: string): boolean {
  return TEST_FRAMEWORK.test(source) || (TEST_BLOCK.test(source) && EXPECTATION.test(source));
}
