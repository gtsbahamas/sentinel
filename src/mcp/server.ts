/**
 * MCP server exposing Sentinel's scanner to IDEs (Claude Code, Cursor, VS Code)
 * over stdio transport.
 *
 * Currently exposes ONE tool: `scan_project`. Future tools (intentionally
 * deferred):
 *   TODO(mcp): scan_diff       — diff two scan reports
 *   TODO(mcp): explain_finding — expand a single finding with deeper context
 *   TODO(mcp): fix             — apply automated fixes (wraps `runFixCommand`)
 *
 * Stdout discipline: this module MUST NOT write anything to process.stdout.
 * Stdout is the MCP transport channel. Any console.log / process.stdout.write
 * (including from downstream code we call into) breaks the protocol. We
 * intercept stdout while invoking runScan() — see invokeScan() below.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { runScan, type ScanOptions } from "../commands/scan.js";

interface ScanProjectArgs {
  path: string;
  format?: "json" | "terminal";
  failOn?: string;
}

const SCAN_PROJECT_INPUT_SCHEMA = {
  type: "object",
  properties: {
    path: {
      type: "string",
      description:
        "Absolute or relative filesystem path to the project to scan (must exist locally).",
    },
    format: {
      type: "string",
      enum: ["json", "terminal"],
      description:
        "Output format. Defaults to 'json' for structured consumption by the IDE/agent. 'terminal' returns the colored CLI report as plain text.",
      default: "json",
    },
    failOn: {
      type: "string",
      enum: ["critical", "high", "medium", "low", "info"],
      description:
        "Severity threshold for the tool's `isError` flag. Findings at or above this level mark the result as an error. Does not affect the report content.",
    },
  },
  required: ["path"],
  additionalProperties: false,
} as const;

function isScanProjectArgs(value: unknown): value is ScanProjectArgs {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.path !== "string" || v.path.length === 0) return false;
  if (
    v.format !== undefined &&
    v.format !== "json" &&
    v.format !== "terminal"
  ) {
    return false;
  }
  if (v.failOn !== undefined && typeof v.failOn !== "string") return false;
  return true;
}

/**
 * Run the scanner with stdout fully intercepted. runScan() writes either the
 * JSON body or terminal report to stdout in normal CLI use; in MCP mode that
 * would corrupt the transport. We redirect process.stdout.write into a buffer
 * for the duration of the call. process.stderr is left alone — stderr is
 * fine to use under stdio transport.
 *
 * Returns the captured stdout AND the runScan exit code.
 */
async function invokeScanCaptured(
  options: ScanOptions,
): Promise<{ stdout: string; exitCode: number }> {
  const buffer: string[] = [];
  const originalWrite = process.stdout.write.bind(process.stdout);

  // Replace stdout.write with a capture function. Returns true to satisfy the
  // Writable contract. We don't need to handle the encoding/callback overloads
  // perfectly — runScan only uses the (string) form.
  process.stdout.write = ((chunk: unknown): boolean => {
    if (typeof chunk === "string") {
      buffer.push(chunk);
    } else if (chunk instanceof Uint8Array) {
      buffer.push(Buffer.from(chunk).toString("utf-8"));
    }
    return true;
  }) as typeof process.stdout.write;

  try {
    const exitCode = await runScan(options);
    return { stdout: buffer.join(""), exitCode };
  } finally {
    process.stdout.write = originalWrite;
  }
}

async function runScanProject(
  args: ScanProjectArgs,
): Promise<{ content: { type: "text"; text: string }[]; isError?: boolean }> {
  if (!existsSync(args.path)) {
    return {
      content: [
        {
          type: "text",
          text: `Path does not exist: ${args.path}`,
        },
      ],
      isError: true,
    };
  }

  const format = args.format ?? "json";

  // For JSON mode we route to a temp file so the report body never touches
  // stdout (even our captured buffer would just discard it). For terminal
  // mode we capture stdout directly and return that as text.
  if (format === "json") {
    const tmpDir = mkdtempSync(join(tmpdir(), "sentinel-mcp-"));
    const reportPath = join(tmpDir, "scan.json");
    try {
      const scanOptions: ScanOptions = {
        path: args.path,
        format: "json",
        outFile: reportPath,
        failOn: args.failOn as ScanOptions["failOn"],
      };
      const { exitCode } = await invokeScanCaptured(scanOptions);

      let body: string;
      try {
        body = readFileSync(reportPath, "utf-8");
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [
            { type: "text", text: `Scan completed but report file unreadable: ${msg}` },
          ],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: body }],
        // exitCode 1 means the failOn threshold was hit — that's a "scan
        // succeeded with blocking findings" result, not a tool error. We only
        // set isError when failOn was explicitly requested AND the threshold
        // tripped, signaling the agent that the action would fail in CI.
        isError: args.failOn ? exitCode !== 0 : false,
      };
    } finally {
      try {
        rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  }

  // Terminal format: capture stdout and return the colored report as text.
  const scanOptions: ScanOptions = {
    path: args.path,
    format: "terminal",
    failOn: args.failOn as ScanOptions["failOn"],
  };
  const { stdout, exitCode } = await invokeScanCaptured(scanOptions);
  return {
    content: [{ type: "text", text: stdout }],
    isError: args.failOn ? exitCode !== 0 : false,
  };
}

/**
 * Build a configured MCP `Server` instance. Caller is responsible for
 * connecting it to a transport (e.g. StdioServerTransport).
 *
 * Tools registered:
 *  - scan_project: invokes runScan(), returns JSON report or terminal output.
 */
export function createMcpServer(): Server {
  const server = new Server(
    {
      name: "shipsafe-sentinel",
      version: "0.1.1",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "scan_project",
          description:
            "Run Sentinel's full security scan (Recon + Rules) against a local project path. Returns the JSON scan report by default — same shape `sentinel scan --format json` emits. Use this to surface security findings to the developer in their IDE.",
          inputSchema: SCAN_PROJECT_INPUT_SCHEMA,
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== "scan_project") {
      return {
        content: [{ type: "text", text: `Unknown tool: ${request.params.name}` }],
        isError: true,
      };
    }
    const rawArgs = request.params.arguments;
    if (!isScanProjectArgs(rawArgs)) {
      return {
        content: [
          {
            type: "text",
            text: "Invalid arguments for scan_project. Required: { path: string }. Optional: { format?: 'json' | 'terminal', failOn?: 'critical' | 'high' | 'medium' | 'low' | 'info' }.",
          },
        ],
        isError: true,
      };
    }
    try {
      return await runScanProject(rawArgs);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error && err.stack ? `\n${err.stack}` : "";
      return {
        content: [{ type: "text", text: `Scan failed: ${msg}${stack}` }],
        isError: true,
      };
    }
  });

  return server;
}
