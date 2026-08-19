import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { apiSecurityRules } from "../../src/layers/rules/domains/api-security.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { emptyModel, makeEndpoint, stagedFixture } from "./helpers.js";
import type { SecurityRule } from "../../src/layers/rules/registry.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = stagedFixture("vulnerable-nextjs");

function ruleById(id: string): SecurityRule {
  const rule = apiSecurityRules.find((r) => r.id === id);
  if (!rule) throw new Error(`rule ${id} not found`);
  return rule;
}

/** Create a tmp project dir with the given files (relative path → contents). */
function makeTmpProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "api-sec-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

describe("api-security rules (fixture-based)", () => {
  it("flags auth endpoint without rate limit (API-002)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags mass assignment via body spread (API-003)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-003").length).toBeGreaterThanOrEqual(1);
  });

  it("flags unbounded GET list (API-004)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-004").length).toBeGreaterThanOrEqual(1);
  });
});

describe("API-001 CORS wildcard with credentials", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags wildcard + credentials in the same file", async () => {
    dir = makeTmpProject({
      "middleware.ts": [
        "export function middleware() {",
        "  const headers = new Headers();",
        "  headers.set('Access-Control-Allow-Origin', '*');",
        "  headers.set('Access-Control-Allow-Credentials', 'true');",
        "  return headers;",
        "}",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-001").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag wildcard-only CORS without credentials", async () => {
    dir = makeTmpProject({
      "cors.ts": "const h = { 'Access-Control-Allow-Origin': '*' };\n",
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-001").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-005 HTTP method not restricted", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags API route with default export and no method check", async () => {
    dir = makeTmpProject({
      "pages/api/foo.ts": [
        "export default function handler(req, res) {",
        "  res.json({ ok: true });",
        "}",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-005").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag App Router route.ts with named method exports", async () => {
    dir = makeTmpProject({
      "app/api/bar/route.ts": [
        "export async function GET(req) { return Response.json({ ok: true }); }",
        "export async function POST(req) { return Response.json({ ok: true }); }",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-005").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-006 GraphQL introspection in production", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags apollo server with introspection: true", async () => {
    dir = makeTmpProject({
      "server.ts": [
        "import { ApolloServer } from '@apollo/server';",
        "const server = new ApolloServer({",
        "  typeDefs,",
        "  resolvers,",
        "  introspection: true,",
        "});",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-006").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag env-gated introspection", async () => {
    dir = makeTmpProject({
      "server.ts": [
        "import { ApolloServer } from '@apollo/server';",
        "const server = new ApolloServer({",
        "  introspection: process.env.NODE_ENV !== 'production',",
        "});",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-006").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-007 HTTP method override", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags methodOverride middleware usage", async () => {
    dir = makeTmpProject({
      "app.ts": [
        "import methodOverride from 'method-override';",
        "app.use(methodOverride('X-HTTP-Method-Override'));",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-007").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag unrelated variables named _method", async () => {
    dir = makeTmpProject({
      "util.ts": "const _method = 'GET';\nexport { _method };\n",
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-007").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-008 CSRF missing on cookie-auth route", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  // @supabase/ssr sets SameSite=Lax on its auth cookies, which is already a
  // CSRF control. Routes using it are skipped deliberately (v0.1.3 FP pass),
  // so the positive case here is a hand-rolled cookie session instead.
  it("flags POST endpoint reading a hand-rolled session cookie without CSRF", async () => {
    dir = makeTmpProject({
      "app/api/update/route.ts": [
        "import { cookies } from 'next/headers';",
        "export async function POST(req) {",
        "  const session = cookies().get('sess')?.value;",
        "  await db.from('items').update({ name: 'x' }).eq('id', 1);",
        "  return Response.json({ ok: true, session });",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/update/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/update", method: "POST", file: endpointFile })],
    });
    const findings = await ruleById("API-008").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a route whose cookies come from @supabase/ssr", async () => {
    dir = makeTmpProject({
      "app/api/update/route.ts": [
        "import { createServerClient } from '@supabase/ssr';",
        "import { cookies } from 'next/headers';",
        "export async function POST(req) {",
        "  const supabase = createServerClient(url, key, { cookies: () => cookies() });",
        "  await supabase.from('items').update({ name: 'x' }).eq('id', 1);",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/update/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/update", method: "POST", file: endpointFile })],
    });
    expect(await ruleById("API-008").check(model)).toEqual([]);
  });

  it("does not flag endpoint with SameSite=Strict cookie", async () => {
    dir = makeTmpProject({
      "app/api/update/route.ts": [
        "import { cookies } from 'next/headers';",
        "export async function POST(req) {",
        "  cookies().set('sess', '1', { sameSite: 'strict' });",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/update/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/update", method: "POST", file: endpointFile })],
    });
    const findings = await ruleById("API-008").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-009 Raw error returned to client", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags NextResponse.json(error) without .message", async () => {
    dir = makeTmpProject({
      "app/api/bad/route.ts": [
        "import { NextResponse } from 'next/server';",
        "export async function GET() {",
        "  try { throw new Error('boom'); }",
        "  catch (error) { return NextResponse.json(error, { status: 500 }); }",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/bad/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/bad", method: "GET", file: endpointFile })],
    });
    const findings = await ruleById("API-009").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("flags Response.json(err) pattern too", async () => {
    dir = makeTmpProject({
      "app/api/bad/route.ts": [
        "export async function GET() {",
        "  try { doWork(); }",
        "  catch (err) { return Response.json(err); }",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/bad/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/bad", method: "GET", file: endpointFile })],
    });
    const findings = await ruleById("API-009").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag sanitized error.message responses", async () => {
    dir = makeTmpProject({
      "app/api/ok/route.ts": [
        "import { NextResponse } from 'next/server';",
        "export async function GET() {",
        "  try { doWork(); }",
        "  catch (error) { return NextResponse.json({ error: error.message }, { status: 500 }); }",
        "}",
      ].join("\n"),
    });
    const endpointFile = join(dir, "app/api/ok/route.ts");
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: dir },
      endpoints: [makeEndpoint({ path: "/api/ok", method: "GET", file: endpointFile })],
    });
    const findings = await ruleById("API-009").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});

describe("API-010 Dynamic import from user input", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("flags require(req.body.module)", async () => {
    dir = makeTmpProject({
      "src/handler.ts": [
        "export default function h(req, res) {",
        "  const mod = require(req.body.module);",
        "  res.json(mod);",
        "}",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-010").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBeGreaterThanOrEqual(1);
  });

  it("does not flag dynamic imports inside test files", async () => {
    dir = makeTmpProject({
      "src/foo.test.ts": [
        "test('loads', async () => {",
        "  const mod = await import(req.body.module);",
        "  expect(mod).toBeDefined();",
        "});",
      ].join("\n"),
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await ruleById("API-010").check(model);
    expect(Array.isArray(findings) ? findings.length : 0).toBe(0);
  });
});
