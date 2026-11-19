/**
 * `sentinel mcp` — runs Sentinel as a Model Context Protocol server over
 * stdio so IDEs (Claude Code, Cursor, VS Code) can invoke the scanner as a
 * tool.
 *
 * Stdout discipline: stdout is the MCP transport channel. NEVER write to
 * stdout from this command. Status messages go to stderr.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer } from "../mcp/server.js";

export async function runMcp(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();

  // Status logs go to stderr — stdout is the protocol channel.
  process.stderr.write("shipsafe-sentinel MCP server starting on stdio...\n");

  await server.connect(transport);

  process.stderr.write("shipsafe-sentinel MCP server connected.\n");

  // server.connect() resolves once the transport is wired. The process stays
  // alive on the transport's stdin reader. Ctrl+C / SIGTERM from the IDE
  // closes stdin and the process exits naturally.
}
