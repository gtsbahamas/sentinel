import { describe, it, expect, afterAll } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { businessLogicRules } from "../../src/layers/rules/domains/business-logic.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import { emptyModel, makeEndpoint } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

/** Get a single rule by ID from the exported array. */
function getRule(id: string) {
  const rule = businessLogicRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

/** Create a temp dir with a source file under src/. Returns { root, filePath }. */
function makeTempProject(fileName: string, content: string) {
  const root = mkdtempSync(join(tmpdir(), "biz-test-"));
  const dir = join(root, "src");
  mkdirSync(dir, { recursive: true });
  const filePath = join(dir, fileName);
  writeFileSync(filePath, content);
  return { root, filePath };
}

// Track temp dirs for cleanup
const tempDirs: string[] = [];
afterAll(() => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
});

describe("business-logic rules", () => {
  // ─── Existing fixture-based tests ───

  it("flags distinct login errors (BIZ-001)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags signup accepting role from body (BIZ-008)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-008").length).toBeGreaterThanOrEqual(1);
  });

  it("flags signup without captcha (BIZ-010)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-010").length).toBeGreaterThanOrEqual(1);
  });

  // ─── BIZ-002: Password reset token stored in plaintext ───

  it("BIZ-002 flags plaintext reset token insert", async () => {
    const { root, filePath } = makeTempProject(
      "reset.ts",
      `
      const token = crypto.randomUUID();
      await supabase.from("password_resets").insert({ reset_token: token, user_id: userId });
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-002").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-002");
  });

  it("BIZ-002 skips when token is hashed", async () => {
    const { root } = makeTempProject(
      "reset.ts",
      `
      import { createHash } from "crypto";
      const hashed = createHash("sha256").update(token).digest("hex");
      await supabase.from("password_resets").insert({ reset_token: hashed, user_id: userId });
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-002").check(model);
    expect(findings.length).toBe(0);
  });

  // ─── BIZ-003: Race condition on balance/credit ───

  it("BIZ-003 flags read-then-write on balance", async () => {
    const { root } = makeTempProject(
      "billing.ts",
      `
      const { data } = await supabase.from("wallets").select("balance").eq("id", userId).single();
      const oldBalance = data.balance;
      await supabase.from("wallets").update({ balance: oldBalance - amount }).eq("id", userId);
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-003").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-003");
  });

  it("BIZ-003 skips when file uses transaction", async () => {
    const { root } = makeTempProject(
      "billing.ts",
      `
      await db.transaction(async (tx) => {
        const { data } = await tx.from("wallets").select("balance").eq("id", userId).single();
        await tx.from("wallets").update({ balance: data.balance - amount }).eq("id", userId);
      });
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-003").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-003 skips when file uses FOR UPDATE lock", async () => {
    const { root } = makeTempProject(
      "billing.ts",
      `
      const { data } = await sql\`SELECT balance FROM wallets WHERE id = \${userId} FOR UPDATE\`;
      await supabase.from("wallets").select("balance").eq("id", userId).single();
      await supabase.from("wallets").update({ balance: data.balance - amount }).eq("id", userId);
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-003").check(model);
    expect(findings.length).toBe(0);
  });

  // ─── BIZ-004: OTP without attempt limit ───

  it("BIZ-004 flags OTP route without attempt limit", async () => {
    const { root, filePath } = makeTempProject(
      "verify-otp.ts",
      `
      export async function POST(req: Request) {
        const { otp } = await req.json();
        const { data } = await supabase.from("otp_codes").select("*").eq("code", otp).single();
        if (!data) return Response.json({ error: "Invalid OTP" }, { status: 400 });
        return Response.json({ success: true });
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/verify-code", file: filePath })],
    });
    const findings = await getRule("BIZ-004").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-004");
  });

  it("BIZ-004 skips when attempt limit present", async () => {
    const { root, filePath } = makeTempProject(
      "verify-otp.ts",
      `
      export async function POST(req: Request) {
        const { otp } = await req.json();
        const attempts = await getAttemptCount(userId);
        if (attempts >= 5) return Response.json({ error: "Locked out" }, { status: 429 });
        // verify...
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/otp/verify", file: filePath })],
    });
    const findings = await getRule("BIZ-004").check(model);
    expect(findings.length).toBe(0);
  });

  // ─── BIZ-005: Coupon without redemption tracking ───

  it("BIZ-005 flags coupon query without used tracking", async () => {
    const { root } = makeTempProject(
      "apply-coupon.ts",
      `
      const { data: coupon } = await supabase.from("coupons").select("*").eq("code", code).single();
      if (!coupon) return Response.json({ error: "Invalid coupon" });
      const discounted = total - coupon.amount;
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-005").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-005");
  });

  it("BIZ-005 skips when coupon marked as used", async () => {
    const { root } = makeTempProject(
      "apply-coupon.ts",
      `
      const { data: coupon } = await supabase.from("coupons").select("*").eq("code", code).single();
      if (!coupon) return Response.json({ error: "Invalid coupon" });
      await supabase.from("coupons").update({ used: true, redeemed_at: new Date() }).eq("id", coupon.id);
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-005").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-005 flags voucher table variant", async () => {
    const { root } = makeTempProject(
      "redeem.ts",
      `
      const { data } = await supabase.from("vouchers").select("*").eq("code", input).single();
      await applyDiscount(data.amount);
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-005").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // ─── BIZ-006: Negative quantity on money endpoint ───

  it("BIZ-006 flags amount read without positivity check", async () => {
    const { root } = makeTempProject(
      "charge.ts",
      `
      export async function POST(req: Request) {
        const body = await req.json();
        const amount = body.amount;
        await chargeCard(userId, amount);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-006").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-006");
  });

  it("BIZ-006 skips when .positive() is used", async () => {
    const { root } = makeTempProject(
      "charge.ts",
      `
      const schema = z.object({ amount: z.number().positive() });
      export async function POST(req: Request) {
        const body = await req.json();
        const amount = body.amount;
        await chargeCard(userId, amount);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-006").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-006 skips when .nonnegative() is used", async () => {
    const { root } = makeTempProject(
      "charge.ts",
      `
      const schema = z.object({ amount: z.number().nonnegative() });
      export async function POST(req: Request) {
        const body = await req.json();
        const amount = body.amount;
        await chargeCard(userId, amount);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-006").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-006 skips when > 0 check present", async () => {
    const { root } = makeTempProject(
      "charge.ts",
      `
      export async function POST(req: Request) {
        const body = await req.json();
        const amount = body.amount;
        if (amount > 0) await chargeCard(userId, amount);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({ meta: { ...emptyModel().meta, path: root } });
    const findings = await getRule("BIZ-006").check(model);
    expect(findings.length).toBe(0);
  });

  // ─── BIZ-007: Missing email verification before login ───

  it("BIZ-007 flags login without email verification check", async () => {
    const { root, filePath } = makeTempProject(
      "login.ts",
      `
      export async function POST(req: Request) {
        const { email, password } = await req.json();
        const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (!user || !bcrypt.compareSync(password, user.hash)) {
          return Response.json({ error: "Invalid credentials" });
        }
        const token = jwt.sign({ id: user.id }, SECRET);
        return Response.json({ token });
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/login", file: filePath })],
    });
    const findings = await getRule("BIZ-007").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-007");
  });

  it("BIZ-007 skips when email_confirmed_at is checked", async () => {
    const { root, filePath } = makeTempProject(
      "login.ts",
      `
      export async function POST(req: Request) {
        const { email, password } = await req.json();
        const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (!user.email_confirmed_at) return Response.json({ error: "Verify email first" });
        // ... authenticate
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/login", file: filePath })],
    });
    const findings = await getRule("BIZ-007").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-007 skips when supabase.auth.signInWith is used", async () => {
    const { root, filePath } = makeTempProject(
      "login.ts",
      `
      export async function POST(req: Request) {
        const { email, password } = await req.json();
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        return Response.json(data);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/signin", file: filePath })],
    });
    const findings = await getRule("BIZ-007").check(model);
    expect(findings.length).toBe(0);
  });

  // ─── BIZ-009: Password change without current password ───

  it("BIZ-009 flags password change without current password", async () => {
    const { root, filePath } = makeTempProject(
      "change-pw.ts",
      `
      export async function POST(req: Request) {
        const { newPassword } = await req.json();
        await supabase.auth.updateUser({ password: newPassword });
        return Response.json({ success: true });
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/change-password", file: filePath })],
    });
    const findings = await getRule("BIZ-009").check(model);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe("BIZ-009");
  });

  it("BIZ-009 skips when currentPassword is required", async () => {
    const { root, filePath } = makeTempProject(
      "change-pw.ts",
      `
      export async function POST(req: Request) {
        const { currentPassword, newPassword } = await req.json();
        const valid = await bcrypt.compare(currentPassword, user.hash);
        if (!valid) return Response.json({ error: "Wrong password" });
        await supabase.auth.updateUser({ password: newPassword });
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/change-password", file: filePath })],
    });
    const findings = await getRule("BIZ-009").check(model);
    expect(findings.length).toBe(0);
  });

  it("BIZ-009 skips reset-password routes with reset token", async () => {
    const { root, filePath } = makeTempProject(
      "reset-pw.ts",
      `
      export async function POST(req: Request) {
        const { resetToken, newPassword } = await req.json();
        const record = await db.query("SELECT * FROM resets WHERE reset_token = $1", [resetToken]);
        if (!record) return Response.json({ error: "Invalid token" });
        await updatePassword(record.user_id, newPassword);
      }
      `,
    );
    tempDirs.push(root);
    const model = emptyModel({
      meta: { ...emptyModel().meta, path: root },
      endpoints: [makeEndpoint({ path: "/api/reset-password", file: filePath })],
    });
    const findings = await getRule("BIZ-009").check(model);
    expect(findings.length).toBe(0);
  });
});
