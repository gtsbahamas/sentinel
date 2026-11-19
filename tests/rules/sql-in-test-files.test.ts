import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { dirname, join, relative } from "path";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { inputInjectionRules } from "../../src/layers/rules/domains/input-injection.js";
import { isTestFile } from "../../src/utils/test-code.js";
import { emptyModel } from "./helpers.js";

const SQL = "await db.query(`SELECT * FROM users WHERE name = '${name}'`);\n";
const TEST_BODY = `import { describe, it, expect } from "vitest";\ndescribe("users", () => { it("reads", async () => {\n${SQL}expect(1).toBe(1); }); });\n`;
const CHAI_ROUTE = `import { assert } from "chai";\nexport async function POST(req: Request) {\n  const { name } = await req.json();\n  assert(name, "name");\n${SQL}  return Response.json({});\n}\n`;

// Files where a real problem must stay reported.
const MUST_ALARM: Record<string, string> = {
  // The hole in the replaced change: a live route that imports a test library.
  "src/app/api/users/route.ts": CHAI_ROUTE,
  // Written like a test, named like production code.
  "src/lib/report.ts": TEST_BODY,
  "src/lib/plain.ts": SQL,
  // In the Pages Router every file under pages/ is served, whatever it is called.
  "pages/api/users.test.ts": CHAI_ROUTE,
  "src/pages/api/__tests__/users.ts": CHAI_ROUTE,
  "pages/users.test.tsx": CHAI_ROUTE,
  "src/pages/__tests__/users.tsx": CHAI_ROUTE,
  // Nothing under an API route tree is waved through on its name.
  "src/app/api/users/__tests__/users.test.ts": TEST_BODY,
  "app/api/orders.spec.ts": TEST_BODY,
  // Other places a framework serves files from by location.
  "api/users.test.ts": CHAI_ROUTE,
  "app/routes/users.test.tsx": CHAI_ROUTE,
  "netlify/functions/users.test.ts": CHAI_ROUTE,
  // A route handler is live wherever it sits.
  "src/app/orders/__tests__/route.ts": CHAI_ROUTE,
  // No route.* file is test code, whatever else its name says.
  "src/app/orders/route.test.ts": CHAI_ROUTE,
  "src/lib/route.spec.ts": CHAI_ROUTE,
  "src/app/billing/__tests__/route.test.tsx": CHAI_ROUTE,
  // Letter case does not make a served folder or a route file into test code: on a filesystem that
  // ignores case the framework serves these all the same.
  "web/Pages/users.test.tsx": CHAI_ROUTE,
  "server/API/users.spec.ts": CHAI_ROUTE,
  "src/app/invoices/__tests__/Route.ts": CHAI_ROUTE,
  // A name that only resembles the convention.
  "src/lib/test.ts": SQL,
  "src/lib/latest.spec-sheet.ts": SQL,
  "src/test/handler.ts": SQL,
  "src/lib/contest.tests/run.ts": SQL,
};

// Ordinary test files, which no visitor's input reaches.
const MUST_NOT_ALARM: Record<string, string> = {
  "src/lib/users.test.ts": TEST_BODY,
  "src/lib/users.spec.ts": TEST_BODY,
  "src/lib/users.db.test.tsx": TEST_BODY,
  "src/lib/__tests__/users.ts": TEST_BODY,
  "test/db/rls.test.js": TEST_BODY,
  "src/components/Table.spec.jsx": TEST_BODY,
};

let root: string;
let outer: string;
let reported: Set<string>;

beforeAll(async () => {
  // The project itself sits inside a folder called __tests__: where the project lives says nothing
  // about its files.
  outer = mkdtempSync(join(tmpdir(), "sentinel-sql-tests-"));
  root = join(outer, "__tests__", "project.test");
  for (const [file, body] of Object.entries({ ...MUST_ALARM, ...MUST_NOT_ALARM })) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), body);
  }
  resetRegistry();
  registerRules(inputInjectionRules);
  const base = emptyModel();
  const findings = await runRules(emptyModel({ meta: { ...base.meta, path: root } }));
  reported = new Set(
    findings.filter((f) => f.ruleId === "INPUT-003").map((f) => relative(root, f.evidence[0].file).split("\\").join("/")),
  );
});

afterAll(() => rmSync(outer, { recursive: true, force: true }));

describe("INPUT-003 and test files", () => {
  for (const file of Object.keys(MUST_ALARM)) {
    it(`still reports SQL built from a template in ${file}`, () => {
      expect(reported.has(file)).toBe(true);
    });
  }
  for (const file of Object.keys(MUST_NOT_ALARM)) {
    it(`does not report the test file ${file}`, () => {
      expect(reported.has(file)).toBe(false);
    });
  }
});

describe("isTestFile", () => {
  it("is decided by the path alone", () => {
    for (const file of Object.keys(MUST_ALARM)) expect(isTestFile(file), file).toBe(false);
    for (const file of Object.keys(MUST_NOT_ALARM)) expect(isTestFile(file), file).toBe(true);
  });
  it("reads Windows separators the same way", () => {
    expect(isTestFile("src\\lib\\users.test.ts")).toBe(true);
    expect(isTestFile("src\\app\\api\\users\\users.test.ts")).toBe(false);
  });
  it("ignores letter case in a served folder or a route file name", () => {
    for (const file of ["Pages/users.test.tsx", "src/Api/users.test.ts", "app/ROUTES/users.spec.ts", "netlify/Functions/__tests__/users.ts"]) {
      expect(isTestFile(file), file).toBe(false);
    }
    for (const file of ["src/lib/Route.test.ts", "src/lib/__tests__/ROUTE.tsx", "src/lib/Route.spec.mjs"]) {
      expect(isTestFile(file), file).toBe(false);
    }
  });
  it("still asks for the usual spelling of a test file name or folder", () => {
    expect(isTestFile("src/lib/users.TEST.ts")).toBe(false);
    expect(isTestFile("src/lib/__Tests__/users.ts")).toBe(false);
  });
  it("does not take a longer name beginning with route for a route file", () => {
    expect(isTestFile("src/lib/router.test.ts")).toBe(true);
    expect(isTestFile("src/lib/routes.spec.ts")).toBe(true);
  });
  it("needs the test suffix at the very end of the name", () => {
    expect(isTestFile("src/lib/db.test.ts.bak.ts")).toBe(false);
    expect(isTestFile("src/lib/db.spec.js.old.js")).toBe(false);
  });
  it("needs a folder named exactly __tests__", () => {
    expect(isTestFile("src/my__tests__/db.ts")).toBe(false);
    expect(isTestFile("src/__tests__old/db.ts")).toBe(false);
  });
});
