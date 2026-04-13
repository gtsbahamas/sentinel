import { describe, it, expect } from "vitest";
import { log005Fixer } from "../../../../src/layers/fix/deterministic/log-005.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: "test-finding-log-005",
    ruleId: "LOG-005",
    domain: "logging-monitoring",
    severity: "medium",
    confidence: "confirmed",
    title: "Unhandled error in route handler",
    description: "Async route handler has no try/catch",
    impact: "Unhandled errors may expose stack traces or crash the server",
    evidence: [{ file: "app/api/users/route.ts", line: 3 }],
    remediation: "Wrap handler body in try/catch and return a 500 response on error",
    references: [],
    layer: "rules",
    ...overrides,
  };
}

describe("log005Fixer", () => {
  it("has correct ruleId and type", () => {
    expect(log005Fixer.ruleId).toBe("LOG-005");
    expect(log005Fixer.type).toBe("deterministic");
  });

  it("wraps a simple GET handler body in try/catch", () => {
    const content = [
      `export async function GET(request: Request) {`,
      `  const data = await fetch("https://example.com/api");`,
      `  return Response.json(data);`,
      `}`,
    ].join("\n");

    const result = log005Fixer.apply!(content, makeFinding());

    expect(result).not.toBeNull();
    expect(result).toContain("try {");
    expect(result).toContain("} catch (error) {");
    expect(result).toContain(`console.error(\`GET handler failed:\`, error);`);
    expect(result).toContain(`return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });`);
  });

  it("wraps a POST handler body in try/catch", () => {
    const content = [
      `export async function POST(request: Request) {`,
      `  const body = await request.json();`,
      `  return Response.json({ ok: true });`,
      `}`,
    ].join("\n");

    const result = log005Fixer.apply!(content, makeFinding());

    expect(result).not.toBeNull();
    expect(result).toContain("try {");
    expect(result).toContain("} catch (error) {");
    expect(result).toContain(`console.error(\`POST handler failed:\`, error);`);
  });

  it("skips handler that already has try/catch", () => {
    const content = [
      `export async function GET(request: Request) {`,
      `  try {`,
      `    const data = await fetch("https://example.com/api");`,
      `    return Response.json(data);`,
      `  } catch (error) {`,
      `    return new Response("error", { status: 500 });`,
      `  }`,
      `}`,
    ].join("\n");

    const result = log005Fixer.apply!(content, makeFinding());

    expect(result).toBeNull();
  });

  it("is idempotent — second run returns null", () => {
    const content = [
      `export async function GET(request: Request) {`,
      `  const data = await fetch("https://example.com/api");`,
      `  return Response.json(data);`,
      `}`,
    ].join("\n");

    const first = log005Fixer.apply!(content, makeFinding())!;
    expect(first).not.toBeNull();

    const second = log005Fixer.apply!(first, makeFinding());
    expect(second).toBeNull();
  });
});
