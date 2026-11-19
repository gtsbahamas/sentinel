import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { runInNewContext } from "vm";

// A severity comes from a report (`sentinel fix --from` reads any JSON file),
// so the dashboard must never write it into the page as markup.

const __dirname = dirname(fileURLToPath(import.meta.url));
const sidebar = readFileSync(join(__dirname, "..", "..", "src", "dashboard", "client", "sidebar.js"), "utf-8");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_COLOR = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)" };
const HOSTILE = 'x" onmouseover="alert(1)"><img src=x onerror=alert(2)>';

function render(call: string, state: unknown, node?: unknown): string {
  const elements: Record<string, { innerHTML: string; scrollTop: number; querySelector?: () => null }> = {
    detailContent: { innerHTML: "", scrollTop: 0, querySelector: () => null },
  };
  const document = {
    getElementById: (id: string) => elements[id] ?? null,
    querySelectorAll: () => [],
    // textContent -> innerHTML the way a browser does it: quotes are left alone.
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
  runInNewContext(`${sidebar}\n${call}`, { document, state, node, SEVERITY_RANK, SEV_COLOR });
  return elements.detailContent.innerHTML;
}

function expectSafe(html: string) {
  expect(html).not.toContain("<img");
  // Quotes in text are harmless; a handler inside a tag is not.
  expect(html).not.toMatch(/<[^>]*onmouseover/);
  for (const [cls] of html.matchAll(/class="sev-tag[^"]*"/g)) {
    expect(cls).toMatch(/^class="sev-tag(?: (?:critical|high|medium|low|info))?"$/);
  }
}

const hostileGroup = { title: "Weak hash", severity: HOSTILE, instances: [{ file: "src/a.ts", line: 3 }] };

describe("dashboard: a severity is never written into the page as markup", () => {
  it("summary, ignored-findings list", () => {
    const html = render("renderSummary();", {
      nodes: [],
      findings: [],
      isConverge: false,
      ignored: [{ id: "IG-1", severity: HOSTILE, title: "Weak hash", file: "tools/a.ts", line: 2 }],
    });
    expect(html).toContain("Ignored by .sentinelrc.json (1)");
    expect(html).toContain("&lt;img");
    expectSafe(html);
  });

  it("summary, vulnerability classes list", () => {
    const html = render("renderSummary();", {
      nodes: [{ id: "n1", findingGroups: [hostileGroup] }],
      findings: [],
      isConverge: false,
      ignored: [],
    });
    expect(html).toContain("Weak hash");
    expectSafe(html);
  });

  it("node detail, its risk tag and each vulnerability card", () => {
    const html = render(
      "renderNodeDetail(node);",
      { nodes: [], findings: [], isConverge: false, ignored: [] },
      { id: "n1", lane: "api", maxSeverity: HOSTILE, findingGroups: [hostileGroup], data: { file: "src/a.ts" } },
    );
    expect(html).toContain("Weak hash");
    expectSafe(html);
  });

  it("a known severity keeps its colour class and label", () => {
    const html = render("renderSummary();", {
      nodes: [],
      findings: [],
      isConverge: false,
      ignored: [{ id: "IG-2", severity: "critical", title: "Weak hash", file: "tools/a.ts" }],
    });
    expect(html).toContain('<span class="sev-tag critical">critical</span>');
  });
});
