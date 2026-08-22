import { describe, it, expect, afterAll } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { cryptographyRules } from "../../src/layers/rules/domains/cryptography.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { emptyModel, stagedFixture } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = stagedFixture("vulnerable-nextjs");

/** Spin up a temp project dir with one source file. */
function makeTmpProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "crypto-rule-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

const tmpDirs: string[] = [];
function tmp(files: Record<string, string>): string {
  const d = makeTmpProject(files);
  tmpDirs.push(d);
  return d;
}

afterAll(() => {
  for (const d of tmpDirs) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch { /* best-effort */ }
  }
});

function findRule(id: string) {
  const r = cryptographyRules.find((r) => r.id === id);
  if (!r) throw new Error(`rule ${id} not found`);
  return r;
}

describe("cryptography rules (fixture-based)", () => {
  it("flags Math.random in security context (CRYPTO-001)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags MD5 used for passwords (CRYPTO-002)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags ECB mode (CRYPTO-004)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-004").length).toBeGreaterThanOrEqual(1);
  });

  it("flags hardcoded HMAC key (CRYPTO-006)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-006").length).toBeGreaterThanOrEqual(1);
  });

  it("flags deprecated createCipher (CRYPTO-009)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-009").length).toBeGreaterThanOrEqual(1);
  });
});

describe("CRYPTO-003 bcrypt rounds", () => {
  it("flags bcrypt.hash with 8 rounds", async () => {
    const dir = tmp({
      "src/auth.ts": `
        import bcrypt from "bcrypt";
        export async function hashPw(pw: string) {
          return bcrypt.hash(pw, 8);
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-003").check(model);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].evidence[0].file).toContain("auth.ts");
  });

  it("does not flag bcrypt.hash with 12 rounds", async () => {
    const dir = tmp({
      "src/auth.ts": `
        import bcrypt from "bcrypt";
        export async function hashPw(pw: string) {
          return bcrypt.hash(pw, 12);
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-003").check(model);
    expect(findings.length).toBe(0);
  });
});

describe("CRYPTO-005 static/zero IV", () => {
  it("flags Buffer.alloc(16) as IV", async () => {
    const dir = tmp({
      "src/enc.ts": `
        import crypto from "crypto";
        const key = crypto.randomBytes(32);
        const iv = Buffer.alloc(16);
        crypto.createCipheriv("aes-256-gcm", key, Buffer.alloc(16));
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-005").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("flags new Uint8Array(16) as IV", async () => {
    const dir = tmp({
      "src/enc.ts": `
        import crypto from "crypto";
        const key = crypto.randomBytes(32);
        crypto.createCipheriv("aes-256-gcm", key, new Uint8Array(16));
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-005").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag random IV", async () => {
    const dir = tmp({
      "src/enc.ts": `
        import crypto from "crypto";
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        crypto.createCipheriv("aes-256-gcm", key, iv);
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-005").check(model);
    expect(findings.length).toBe(0);
  });
});

describe("CRYPTO-007 insecure TLS", () => {
  it("flags rejectUnauthorized: false", async () => {
    const dir = tmp({
      "src/client.ts": `
        import https from "https";
        const agent = new https.Agent({ rejectUnauthorized: false });
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-007").check(model);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
  });

  it("flags minVersion TLSv1.0", async () => {
    const dir = tmp({
      "src/client.ts": `
        const opts = { minVersion: "TLSv1.0" };
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-007").check(model);
    expect(findings.length).toBe(1);
  });

  it("does not flag rejectUnauthorized: true", async () => {
    const dir = tmp({
      "src/client.ts": `
        const agent = new https.Agent({ rejectUnauthorized: true });
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-007").check(model);
    expect(findings.length).toBe(0);
  });

  it("excludes test files", async () => {
    const dir = tmp({
      "src/client.test.ts": `
        const agent = new https.Agent({ rejectUnauthorized: false });
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-007").check(model);
    expect(findings.length).toBe(0);
  });
});

describe("CRYPTO-008 non-constant-time comparison", () => {
  it("flags hmac == expected", async () => {
    const dir = tmp({
      "src/verify.ts": `
        import crypto from "crypto";
        export function verify(body: string, sig: string, secret: string) {
          const hmac = crypto.createHmac("sha256", secret).update(body).digest("hex");
          if (hmac === sig) return true;
          return false;
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-008").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe("high");
  });

  it("flags reversed form: expected !== signature", async () => {
    const dir = tmp({
      "src/verify.ts": `
        import crypto from "crypto";
        export function verify(received: string, signature: string) {
          if (received !== signature) throw new Error("bad hmac");
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-008").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag when timingSafeEqual is used on that line", async () => {
    const dir = tmp({
      "src/verify.ts": `
        import crypto from "crypto";
        export function verify(a: Buffer, b: Buffer) {
          return crypto.timingSafeEqual(a, b);
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-008").check(model);
    expect(findings.length).toBe(0);
  });
});

describe("CRYPTO-010 plaintext password storage", () => {
  it("flags insert with raw password variable", async () => {
    const dir = tmp({
      "src/signup.ts": `
        export async function signup(email: string, password: string) {
          await supabase.from("users").insert({ email: email, password: password });
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-010").check(model);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not flag insert with bcrypt-hashed password", async () => {
    const dir = tmp({
      "src/signup.ts": `
        import bcrypt from "bcrypt";
        export async function signup(email: string, password: string) {
          const hashed = await bcrypt.hash(password, 12);
          await supabase.from("users").insert({ email: email, password: hashed });
        }
      `,
    });
    const model = emptyModel({ meta: { ...emptyModel().meta, path: dir } });
    const findings = await findRule("CRYPTO-010").check(model);
    // The insert line has `password: hashed` — "hashed" does not contain
    // bcrypt/argon2/scrypt/hash/pbkdf2 as a substring... wait, it contains "hash".
    expect(findings.length).toBe(0);
  });
});
