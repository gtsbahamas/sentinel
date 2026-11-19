import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { formatJson } from "../src/output/json.js";
import { formatTerminal } from "../src/output/terminal.js";
import { formatHtml } from "../src/output/html.js";
import { formatJsonDiff, diffFindings } from "../src/commands/diff.js";
import { createMcpServer } from "../src/mcp/server.js";
import type { ProjectModel } from "../src/model/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")) as {
  version: string;
};

const model: ProjectModel = {
  meta: {
    name: "test",
    path: "/tmp",
    stack: "nextjs-supabase",
    packageManager: "npm",
    language: "typescript",
    framework: "nextjs-app",
    deployTarget: null,
  },
  routes: [],
  endpoints: [],
  fileUploads: [],
  authFlows: [],
  dataModels: [],
  dependencies: [],
  envVars: [],
  staticAssets: [],
  findings: [],
};

describe("every printed version is package.json's", () => {
  it("JSON report", () => {
    const parsed = JSON.parse(formatJson(model, [], { recon_ms: 1, rules_ms: 1 }));
    expect(parsed.version).toBe(pkg.version);
  });

  it("terminal header", () => {
    expect(formatTerminal(model, [])).toContain(`SENTINEL v${pkg.version} `);
  });

  it("HTML footer", () => {
    expect(formatHtml(model, [], { recon_ms: 1, rules_ms: 1 })).toContain(`Sentinel v${pkg.version} `);
  });

  it("JSON diff", () => {
    const parsed = JSON.parse(formatJsonDiff(diffFindings([], [])));
    expect(parsed.version).toBe(pkg.version);
  });

  it("MCP server handshake", async () => {
    const server = createMcpServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    await client.connect(clientTransport);
    expect(client.getServerVersion()?.version).toBe(pkg.version);
  });
});
