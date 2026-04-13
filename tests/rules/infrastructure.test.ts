import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { infrastructureRules } from "../../src/layers/rules/domains/infrastructure.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { emptyModel, emptyInfra } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

/** Get a rule by id. */
function getRule(id: string) {
  const rule = infrastructureRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

/** Create a temp directory with source files for walkSourceFiles-based rules. */
function makeTempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "infra-test-"));
  // walkSourceFiles needs a package.json or it just globs ts/js files
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "test" }));
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name);
    const parent = dirname(full);
    mkdirSync(parent, { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

describe("infrastructure rules", () => {
  // ── INFRA-001 (existing fixture test) ──
  it("flags missing Content-Security-Policy (INFRA-001)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-001").length).toBe(1);
  });

  // ── INFRA-002 ──
  describe("INFRA-002: HSTS missing", () => {
    it("flags when HSTS missing and deployTarget is null", async () => {
      const model = emptyModel({
        meta: {
          name: "test",
          path: "/tmp/test",
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
        infra: emptyInfra({ securityHeaders: {} }),
      });
      const findings = await getRule("INFRA-002").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("INFRA-002");
    });

    it("flags when HSTS missing and deployTarget is vercel", async () => {
      const model = emptyModel({
        meta: {
          name: "test",
          path: "/tmp/test",
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: "vercel",
        },
        infra: emptyInfra({ securityHeaders: {} }),
      });
      const findings = await getRule("INFRA-002").check(model);
      expect(findings.length).toBe(1);
    });

    it("does not flag when HSTS is set", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          securityHeaders: {
            "strict-transport-security": [
              { file: "next.config.mjs", value: "max-age=63072000; includeSubDomains; preload" },
            ],
          },
        }),
      });
      const findings = await getRule("INFRA-002").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // ── INFRA-003 (existing fixture test) ──
  it("flags missing X-Frame-Options (INFRA-003)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-003").length).toBe(1);
  });

  // ── INFRA-004 ──
  describe("INFRA-004: Wildcard CORS", () => {
    it("flags Access-Control-Allow-Origin: *", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          securityHeaders: {
            "access-control-allow-origin": [
              { file: "next.config.mjs", value: "*" },
            ],
          },
        }),
      });
      const findings = await getRule("INFRA-004").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("INFRA-004");
    });

    it("does not flag specific origin", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          securityHeaders: {
            "access-control-allow-origin": [
              { file: "next.config.mjs", value: "https://example.com" },
            ],
          },
        }),
      });
      const findings = await getRule("INFRA-004").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // ── INFRA-005 ──
  describe("INFRA-005: Cookies without Secure", () => {
    it("flags cookie set without secure: true", async () => {
      const dir = makeTempProject({
        "src/auth.ts": `
export function login(res) {
  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
  });
}
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-005").check(model);
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].ruleId).toBe("INFRA-005");
    });

    it("does not flag when secure: true is nearby", async () => {
      const dir = makeTempProject({
        "src/auth.ts": `
export function login(res) {
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
}
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-005").check(model);
      expect(findings.length).toBe(0);
    });

    it("skips cookie-setting lines inside comments", async () => {
      const dir = makeTempProject({
        "src/auth.ts": `
// res.cookie("session", token)
/* response.cookies.set("x", "y") */
export function noop() {}
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-005").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // ── INFRA-006 ──
  describe("INFRA-006: HTTP URL in source", () => {
    it("flags plain http:// URL in source code", async () => {
      const dir = makeTempProject({
        "src/api.ts": `
const API_URL = "http://example.com/api";
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-006").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("INFRA-006");
    });

    it("does not flag http://localhost", async () => {
      const dir = makeTempProject({
        "src/api.ts": `
const DEV_URL = "http://localhost:3000/api";
const LOOPBACK = "http://127.0.0.1:8080/api";
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-006").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag comment lines", async () => {
      const dir = makeTempProject({
        "src/api.ts": `
// const API_URL = "http://example.com/api";
 * See http://example.com/docs for details
`,
      });
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-006").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // ── INFRA-007 ──
  describe("INFRA-007: Next.js image wildcard", () => {
    it("flags wildcard hostname in remotePatterns", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          nextConfig: {
            file: "next.config.mjs",
            source: `
module.exports = {
  images: {
    remotePatterns: [{ hostname: "**" }],
  },
};
`,
          },
        }),
      });
      const findings = await getRule("INFRA-007").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("INFRA-007");
    });

    it("does not flag explicit hostname", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          nextConfig: {
            file: "next.config.mjs",
            source: `
module.exports = {
  images: {
    remotePatterns: [{ hostname: "cdn.example.com" }],
  },
};
`,
          },
        }),
      });
      const findings = await getRule("INFRA-007").check(model);
      expect(findings.length).toBe(0);
    });

    it("flags domains: ['*']", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          nextConfig: {
            file: "next.config.mjs",
            source: `
module.exports = {
  images: {
    domains: ["*"],
  },
};
`,
          },
        }),
      });
      const findings = await getRule("INFRA-007").check(model);
      expect(findings.length).toBe(1);
    });
  });

  // ── INFRA-008 ──
  describe("INFRA-008: .env committed", () => {
    it("flags .env file not in gitignore", async () => {
      const dir = makeTempProject({});
      writeFileSync(join(dir, ".env"), "SECRET=abc123");
      writeFileSync(join(dir, ".gitignore"), "node_modules\n");
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-008").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("critical");
    });

    it("does not flag .env when gitignored", async () => {
      const dir = makeTempProject({});
      writeFileSync(join(dir, ".env"), "SECRET=abc123");
      writeFileSync(join(dir, ".gitignore"), ".env\nnode_modules\n");
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-008").check(model);
      expect(findings.length).toBe(0);
    });

    it("does not flag .env when .env* glob is in gitignore", async () => {
      const dir = makeTempProject({});
      writeFileSync(join(dir, ".env"), "SECRET=abc123");
      writeFileSync(join(dir, ".env.local"), "LOCAL_SECRET=xyz");
      writeFileSync(join(dir, ".gitignore"), ".env*\nnode_modules\n");
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-008").check(model);
      expect(findings.length).toBe(0);
    });

    it("ignores gitignore comment lines", async () => {
      const dir = makeTempProject({});
      writeFileSync(join(dir, ".env"), "SECRET=abc123");
      // The .env line is commented out, so .env should NOT be considered ignored
      writeFileSync(join(dir, ".gitignore"), "# .env\nnode_modules\n");
      const model = emptyModel({
        meta: {
          name: "test",
          path: dir,
          stack: "nextjs-supabase",
          packageManager: "npm",
          language: "typescript",
          framework: "nextjs-app",
          deployTarget: null,
        },
      });
      const findings = await getRule("INFRA-008").check(model);
      expect(findings.length).toBe(1);
    });
  });

  // ── INFRA-009 ──
  describe("INFRA-009: Referrer-Policy", () => {
    it("flags missing Referrer-Policy", async () => {
      const model = emptyModel({
        infra: emptyInfra({ securityHeaders: {} }),
      });
      const findings = await getRule("INFRA-009").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("INFRA-009");
    });

    it("flags permissive unsafe-url policy", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          securityHeaders: {
            "referrer-policy": [
              { file: "next.config.mjs", value: "unsafe-url" },
            ],
          },
        }),
      });
      const findings = await getRule("INFRA-009").check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain("Permissive");
    });

    it("does not flag strict-origin-when-cross-origin", async () => {
      const model = emptyModel({
        infra: emptyInfra({
          securityHeaders: {
            "referrer-policy": [
              { file: "next.config.mjs", value: "strict-origin-when-cross-origin" },
            ],
          },
        }),
      });
      const findings = await getRule("INFRA-009").check(model);
      expect(findings.length).toBe(0);
    });
  });

  // ── INFRA-010 (existing fixture test) ──
  it("flags Supabase email confirmations disabled (INFRA-010)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-010").length).toBe(1);
  });
});
