import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { runInNewContext } from "vm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sidebar = readFileSync(join(__dirname, "..", "..", "src", "dashboard", "client", "sidebar.js"), "utf-8");

// The summary panel, rendered with the smallest document the sidebar touches.
function renderSummary(ignored: unknown[]): string {
  const elements: Record<string, { innerHTML: string; scrollTop: number }> = {
    detailContent: { innerHTML: "", scrollTop: 0 },
  };
  const document = {
    getElementById: (id: string) => elements[id] ?? null,
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
  const state = {
    nodes: [],
    findings: [{ severity: "high", title: "kept one" }],
    isConverge: false,
    ignored,
  };
  runInNewContext(`${sidebar}\nrenderSummary();`, {
    document,
    state,
    SEVERITY_RANK: { critical: 4, high: 3, medium: 2, low: 1, info: 0 },
  });
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
});
