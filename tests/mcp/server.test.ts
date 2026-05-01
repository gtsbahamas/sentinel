import { describe, it, expect } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  ListToolsResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createMcpServer } from "../../src/mcp/server.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

/**
 * Wire createMcpServer() to an in-memory client/server transport pair so we
 * can dispatch real MCP requests without spawning a subprocess. This is the
 * SDK's own recommended pattern for unit tests.
 */
async function connectClientToServer() {
  const server = createMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client(
    { name: "test-client", version: "0.0.0" },
    { capabilities: {} },
  );
  await client.connect(clientTransport);
  return { server, client };
}

describe("createMcpServer", () => {
  it("registers exactly one tool named scan_project", async () => {
    const { client } = await connectClientToServer();
    const result = await client.request({ method: "tools/list" }, ListToolsResultSchema);
    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe("scan_project");
  });

  it("declares path as a required input on scan_project", async () => {
    const { client } = await connectClientToServer();
    const result = await client.request({ method: "tools/list" }, ListToolsResultSchema);
    const tool = result.tools[0];
    expect(tool.inputSchema).toBeDefined();
    const schema = tool.inputSchema as {
      type: string;
      properties: Record<string, unknown>;
      required: string[];
    };
    expect(schema.type).toBe("object");
    expect(schema.properties.path).toBeDefined();
    expect(schema.required).toContain("path");
  });

  it("returns an error result when path does not exist", async () => {
    const { client } = await connectClientToServer();
    const result = await client.request(
      {
        method: "tools/call",
        params: {
          name: "scan_project",
          arguments: { path: "/definitely/does/not/exist/abc123" },
        },
      },
      CallToolResultSchema,
    );
    expect(result.isError).toBe(true);
    expect(Array.isArray(result.content)).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/Path does not exist/);
  });

  it("returns a JSON-shaped report when called against a fixture project", async () => {
    const { client } = await connectClientToServer();
    const result = await client.request(
      {
        method: "tools/call",
        params: {
          name: "scan_project",
          arguments: { path: fixturePath, format: "json" },
        },
      },
      CallToolResultSchema,
    );
    expect(result.isError).toBeFalsy();
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    // Should be parseable JSON matching formatJson() shape.
    const parsed = JSON.parse(text);
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("project");
    expect(Array.isArray(parsed.findings)).toBe(true);
  }, 60000);
});
