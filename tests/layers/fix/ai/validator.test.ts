import { describe, it, expect } from "vitest";
import { validateAIResponse } from "../../../../src/layers/fix/ai/validator.js";

describe("validateAIResponse", () => {
  const original = `import { z } from "zod";

export const schema = z.object({ name: z.string() });

export async function POST(req: Request) {
  const body = await req.json();
  return Response.json({ ok: true });
}
`;

  it("accepts a valid patch that preserves exports and length", () => {
    const patched = `import { z } from "zod";

export const schema = z.object({ name: z.string() });

export async function POST(req: Request) {
  const body = await req.json();
  const parsed = schema.parse(body);
  return Response.json({ ok: true });
}
`;
    const result = validateAIResponse(original, patched);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("rejects an empty response", () => {
    const result = validateAIResponse(original, "");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("empty");
  });

  it("rejects a whitespace-only response", () => {
    const result = validateAIResponse(original, "   \n  ");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("empty");
  });

  it("rejects a truncated response (less than 50% of original length)", () => {
    const truncated = original.slice(0, Math.floor(original.length * 0.3));
    const result = validateAIResponse(original, truncated);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("truncated");
  });

  it("accepts a response that is at least 50% of original length (boundary)", () => {
    // Build content that is exactly 50% of original length
    // original.length = 197, so we need >= 98.5 => 99 chars
    const minLen = Math.ceil(original.length * 0.5);
    // Pad with spaces to hit the minimum length threshold
    const paddedContent = original.slice(0, minLen) + " ".repeat(Math.max(0, minLen - original.slice(0, minLen).length));
    // It may fail due to missing exports, but NOT due to truncation
    const result = validateAIResponse(original, paddedContent);
    expect(result.reason).not.toContain("truncated");
  });

  it("rejects if an export from original is missing in patched", () => {
    const patchedMissingExport = `import { z } from "zod";

// POST export removed accidentally
async function POST(req: Request) {
  return Response.json({ ok: true });
}
`;
    const result = validateAIResponse(original, patchedMissingExport);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("POST");
  });

  it("rejects if multiple exports are missing", () => {
    // Build patched content that is long enough (>50% of original) but lacks exports
    const patchedNoExports = `// File has been stripped of its exports accidentally.
// This comment is here to pad the content to ensure the length check passes.
// Padding: ${"x".repeat(original.length)}
async function POST(req: Request) {
  return Response.json({ ok: true });
}
`;
    const result = validateAIResponse(original, patchedNoExports);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("POST");
    expect(result.reason).toContain("schema");
  });

  it("accepts when original has no named exports (edge case)", () => {
    const noExportOriginal = `// utility file
function helper() { return 1; }
`;
    const noExportPatched = `// utility file — fixed
function helper() { return 1; }
// rate limit added
`;
    const result = validateAIResponse(noExportOriginal, noExportPatched);
    expect(result.valid).toBe(true);
  });
});
