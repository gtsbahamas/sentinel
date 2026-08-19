import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { loggingMonitoringRules } from "../../src/layers/rules/domains/logging-monitoring.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { emptyModel, makeEndpoint, makeDep, stagedFixture } from "./helpers.js";
import type { SecurityRule } from "../../src/layers/rules/registry.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = stagedFixture("vulnerable-nextjs");

function ruleById(id: string): SecurityRule {
  const rule = loggingMonitoringRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

/** Create a temp project directory. Caller must rmSync. */
function makeTempProject(): string {
  return mkdtempSync(join(tmpdir(), "logmon-test-"));
}

function writeFile(root: string, relPath: string, contents: string) {
  const abs = join(root, relPath);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, contents);
  return abs;
}

describe("logging-monitoring rules", () => {
  it("flags sensitive value in log (LOG-001)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags console.log in API route (LOG-002)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags auth route without structured logger (LOG-009)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-009").length).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // LOG-003: Stack trace returned in API response
  // --------------------------------------------------------------------------
  describe("LOG-003", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags handler returning error.stack", async () => {
      const file = writeFile(
        root,
        "route.ts",
        `export async function POST() {
  try { doWork(); } catch (error) {
    return NextResponse.json({ error: error.stack }, { status: 500 });
  }
}`,
      );
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [makeEndpoint({ path: "/api/x", file })],
      });
      const findings = await ruleById("LOG-003").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].evidence[0].file).toBe(file);
    });

    it("does not flag handler that returns only a generic message", async () => {
      const file = writeFile(
        root,
        "route.ts",
        `export async function POST() {
  try { doWork(); } catch (error) {
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}`,
      );
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [makeEndpoint({ path: "/api/x", file })],
      });
      const findings = await ruleById("LOG-003").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-004: Admin operation without audit log
  // --------------------------------------------------------------------------
  describe("LOG-004", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags supabase.auth.admin.deleteUser without audit", async () => {
      writeFile(
        root,
        "admin.ts",
        `await supabase.auth.admin.deleteUser(userId);\nreturn ok;`,
      );
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-004").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag when an audit call is present in the same file", async () => {
      writeFile(
        root,
        "admin.ts",
        `await supabase.auth.admin.deleteUser(userId);\naudit({ action: "delete", userId });`,
      );
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-004").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-005: Unhandled promise rejection in route handler
  // --------------------------------------------------------------------------
  describe("LOG-005", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags async handler without try/catch or .catch()", async () => {
      const file = writeFile(
        root,
        "route.ts",
        `export async function POST() {
  const data = await db.query("select 1");
  return NextResponse.json(data);
}`,
      );
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [makeEndpoint({ path: "/api/x", file })],
      });
      const findings = await ruleById("LOG-005").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag handler that uses .catch() chain", async () => {
      const file = writeFile(
        root,
        "route.ts",
        `export async function POST() {
  const data = await db.query("select 1").catch((e) => captureException(e));
  return NextResponse.json(data);
}`,
      );
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [makeEndpoint({ path: "/api/x", file })],
      });
      const findings = await ruleById("LOG-005").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag handler wrapped in try/catch", async () => {
      const file = writeFile(
        root,
        "route.ts",
        `export async function POST() {
  try {
    const data = await db.query("select 1");
    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json({ error: "failed" }, { status: 500 });
  }
}`,
      );
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        endpoints: [makeEndpoint({ path: "/api/x", file })],
      });
      const findings = await ruleById("LOG-005").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-006: No error boundary in React tree
  // --------------------------------------------------------------------------
  describe("LOG-006", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags project with no error boundary", async () => {
      writeFile(root, "app/page.tsx", `export default function Page() { return <div/>; }`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-006").check(model);
      expect(findings.length).toBe(1);
    });

    it("does not flag project with app/error.tsx", async () => {
      writeFile(root, "app/error.tsx", `export default function Err() { return <div/>; }`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-006").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag project using react-error-boundary dependency", async () => {
      writeFile(root, "app/page.tsx", `export default function Page() { return <div/>; }`);
      const model = emptyModel({
        meta: { ...emptyModel().meta, path: root },
        dependencies: [makeDep("react-error-boundary", "^4.0.0")],
      });
      const findings = await ruleById("LOG-006").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag project with custom componentDidCatch boundary", async () => {
      writeFile(
        root,
        "components/Boundary.tsx",
        `export class Boundary extends React.Component {
  componentDidCatch(error, info) { console.error(error); }
  render() { return this.props.children; }
}`,
      );
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-006").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-007: PII logged in plaintext
  // --------------------------------------------------------------------------
  describe("LOG-007", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags console.log with email variable", async () => {
      writeFile(root, "foo.ts", `console.log("sent to", email);`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-007").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag benign log without PII terms", async () => {
      writeFile(root, "foo.ts", `console.log("request received");`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-007").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-008: Empty catch block
  // --------------------------------------------------------------------------
  describe("LOG-008", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags truly empty catch block", async () => {
      writeFile(root, "foo.ts", `try { doWork(); } catch (e) {}`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-008").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag catch block with intentional silencing comment", async () => {
      // The current regex requires literally `{ }`; a comment breaks the match.
      writeFile(
        root,
        "foo.ts",
        `try { doWork(); } catch (e) { /* intentional: optional feature */ }`,
      );
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-008").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag catch with logger call", async () => {
      writeFile(root, "foo.ts", `try { doWork(); } catch (e) { logger.error(e); }`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-008").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // LOG-010: Debug flag forced on
  // --------------------------------------------------------------------------
  describe("LOG-010", () => {
    let root: string;
    beforeEach(() => (root = makeTempProject()));
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it("flags hardcoded NODE_ENV=development assignment", async () => {
      writeFile(root, "config.ts", `process.env.NODE_ENV = 'development';`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-010").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("flags process.env.DEBUG = true", async () => {
      writeFile(root, "config.ts", `process.env.DEBUG = true;`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-010").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag `debug` npm package pattern (DEBUG read, not hardcoded)", async () => {
      writeFile(
        root,
        "config.ts",
        `const namespace = process.env.DEBUG || "";\nconst debug = require("debug")(namespace);`,
      );
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-010").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag NODE_ENV read-only usage", async () => {
      writeFile(root, "config.ts", `if (process.env.NODE_ENV === 'development') { /* ... */ }`);
      const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
      const findings = await ruleById("LOG-010").check(model);
      expect(findings.length).toBe(0);
    });
  });
});
