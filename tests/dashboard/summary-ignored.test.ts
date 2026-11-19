import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { runInNewContext } from "vm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const client = join(__dirname, "..", "..", "src", "dashboard", "client");
const sidebar = readFileSync(join(client, "sidebar.js"), "utf-8");
const appSource = readFileSync(join(client, "app.js"), "utf-8");
// app.js without its boot step (lane building and the websocket).
const app = appSource.slice(0, appSource.indexOf("// ---- Boot ----"));

function fakeDocument() {
  const elements: Record<string, { innerHTML: string; scrollTop: number }> = {
    detailContent: { innerHTML: "", scrollTop: 0 },
  };
  const document = {
    getElementById: (id: string) => elements[id] ?? null,
    querySelectorAll: () => [],
    createElement: () => {
      let text = "";
      return {
        set textContent(value: string) {
          text = value;
        },
        get innerHTML() {
          return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        },
      };
    },
  };
  return { document, elements };
}

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// The summary panel, rendered with the smallest document the sidebar touches.
function renderSummary(ignored: unknown[]): string {
  const { document, elements } = fakeDocument();
  const state = {
    nodes: [],
    findings: [{ severity: "high", title: "kept one" }],
    isConverge: false,
    ignored,
  };
  runInNewContext(`${sidebar}\nrenderSummary();`, { document, state, SEVERITY_RANK });
  return elements.detailContent.innerHTML;
}

describe("dashboard summary: findings the config ignores", () => {
  it("are listed with their file, apart from the severity cards", () => {
    const html = renderSummary([
      { id: "IG-1", severity: "critical", title: "Weak <hash>", file: "/p/tools/hash.ts", line: 2 },
    ]);
    expect(html).toContain("Ignored by .sentinelrc.json (1)");
    const tail = html.slice(html.indexOf("Ignored by .sentinelrc.json"));
    expect(tail).toContain("Weak &lt;hash&gt;");
    expect(tail).toContain("/p/tools/hash.ts:2");
    // The critical card counts kept findings only.
    expect(html).toMatch(/<div class="metric-value">0<\/div><div class="metric-label">Critical instances/);
  });

  it("show no such section when there are none", () => {
    expect(renderSummary([])).not.toContain("Ignored by .sentinelrc.json");
  });

  it("are taken from scan:complete, in a converge round too, and shown on the summary", () => {
    const { document, elements } = fakeDocument();
    runInNewContext(
      `${sidebar}\n${app}\n` +
        // A converge round's scan:complete returns early; the list must already be kept.
        `state.isConverge = true;
        handleScanComplete({ summary: { ignored: [{ id: "IG-2", severity: "high", title: "From the event", file: "tools/a.ts" }] } });
        state.isConverge = false;
        renderSummary();`,
      { document, SEVERITY_RANK },
    );
    expect(elements.detailContent.innerHTML).toContain("Ignored by .sentinelrc.json (1)");
    expect(elements.detailContent.innerHTML).toContain("tools/a.ts");
  });
});
