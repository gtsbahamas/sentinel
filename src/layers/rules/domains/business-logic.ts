import fg from "fast-glob";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  impact: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "business-logic",
    severity,
    confidence: "high",
    title,
    description,
    impact,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

async function walkSourceFiles(model: ProjectModel): Promise<Array<{ file: string; source: string }>> {
  const files = await fg(["**/*.{ts,tsx,js,jsx,mjs,cjs}"], {
    cwd: model.meta.path,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/.next/**",
      "**/dist/**",
      "**/out/**",
      "**/build/**",
      "**/public/**",
      "**/widget-build/**",
      "**/.claude/worktrees/**",
    ],
  });
  return Promise.all(files.map(async (file) => ({ file, source: await safeReadFile(file) })));
}

export const businessLogicRules: SecurityRule[] = [
  {
    id: "BIZ-001",
    domain: "business-logic",
    title: "Login error reveals whether account exists",
    description: "Handler returns different error for 'user not found' vs 'wrong password'",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-204" },
    async check(model) {
      const findings: Finding[] = [];
      const loginRoutes = model.endpoints.filter((e) => /login|signin/i.test(e.path));
      const userNotFoundRe = /(user\s*(not\s*found|does[n']?t\s*exist)|no\s*such\s*user|unknown\s*user|email\s*not\s*found)/i;
      const wrongPasswordRe = /(wrong|invalid|incorrect)\s*(password|credentials)/i;
      for (const endpoint of loginRoutes) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (!userNotFoundRe.test(source) || !wrongPasswordRe.test(source)) continue;
        findings.push(
          mkFinding(
            "BIZ-001",
            "medium",
            `${endpoint.path} distinguishes "user not found" from "wrong password"`,
            "Different error messages enable username enumeration.",
            "Your login form reveals whether an email address has an account by showing different error messages. An attacker can enumerate valid accounts before attempting to break in.",
            "Always return the same generic error for any authentication failure: 'Invalid credentials'.",
            [{ file: endpoint.file }],
            { cwe: "CWE-204" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-002",
    domain: "business-logic",
    title: "Password reset token stored in plaintext",
    description: "Reset token inserted into DB without a hash",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-256" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /(reset_token|password_reset|passwordResetToken)[\s\S]{0,80}\.(insert|upsert|update)/;
      for (const { file, source } of files) {
        if (!re.test(source)) continue;
        if (/createHash|bcrypt|argon2|scrypt/i.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/reset_token|password_reset|passwordResetToken/i.test(line)) return;
          findings.push(
            mkFinding(
              "BIZ-002",
              "high",
              "Password reset token stored without hashing",
              "If the DB leaks, every reset token is usable. Hash tokens the same way you hash passwords.",
              "Your app stores password reset tokens in the database without hashing them. If your database is compromised, an attacker can use these tokens to reset any user's password.",
              "Store `sha256(token)` in DB. When validating, hash the incoming token and compare.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-256" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "BIZ-003",
    domain: "business-logic",
    title: "Race condition on balance/credit operation",
    description: "Read-then-write on a numeric field without a DB-level atomic update",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-362" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Pattern: .select('balance') ... .update({ balance: oldBalance - amount })
      const re = /\.select\s*\(\s*["']\s*(balance|credit|tokens|usage|quota|count)\s*["']\s*\)[\s\S]{0,400}\.update\s*\(\s*\{\s*\1\s*:/;
      for (const { file, source } of files) {
        const m = source.match(re);
        if (!m) continue;
        // Skip if the file uses transactions or row-level locks — these are
        // legitimate concurrency controls that prevent the race.
        if (/\b(BEGIN|COMMIT|\.transaction\s*\(|FOR\s+UPDATE|SERIALIZABLE|advisory_lock)\b/i.test(source)) continue;
        const idx = source.slice(0, source.indexOf(m[0])).split("\n").length;
        findings.push(
          mkFinding(
            "BIZ-003",
            "high",
            "Read-then-write race on a numeric field",
            "Two concurrent requests can each read the same starting balance and write their own decrement, losing one of the updates.",
            "Your app reads a balance, modifies it in code, then writes it back. Two simultaneous requests can both read the same balance and write back independently, allowing an attacker to spend the same credits twice.",
            "Use an atomic SQL expression: `update table set balance = balance - $1 where id = $2 and balance >= $1`.",
            [{ file, line: idx, snippet: m[0].slice(0, 120) }],
            { cwe: "CWE-362" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-004",
    domain: "business-logic",
    title: "OTP verification without attempt limit",
    description: "OTP compared without a per-account attempt counter",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-307" },
    async check(model) {
      const findings: Finding[] = [];
      const otpRoutes = model.endpoints.filter((e) => /otp|verify-code|mfa/i.test(e.path));
      for (const endpoint of otpRoutes) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        const hasAttemptLimit = /attempts|tries|attempt_count|rate|ratelimit|lockout/i.test(source);
        if (hasAttemptLimit) continue;
        findings.push(
          mkFinding(
            "BIZ-004",
            "high",
            `${endpoint.path} has no OTP attempt limit`,
            "A 6-digit OTP is brute-forceable in ~500k attempts without a limit.",
            "Your OTP verification has no attempt limit. An attacker can try all possible codes in rapid succession, cracking a 6-digit OTP in minutes through brute force.",
            "Track attempt count per account, lock after 5 failures, rotate the OTP on lockout.",
            [{ file: endpoint.file }],
            { cwe: "CWE-307" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-005",
    domain: "business-logic",
    title: "Discount or coupon code without uniqueness check",
    description: "Coupon applied without marking as used or checking prior redemptions",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-840" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const couponUse = /coupon|discount|promo|voucher|gift_?card/i;
      for (const { file, source } of files) {
        if (!couponUse.test(source)) continue;
        // If the file touches coupons but never marks one used or limits attempts, flag it.
        if (/used\s*:\s*true|redemptions|redeem_count|.(update|upsert)\s*\(.*(used|redeemed)/i.test(source)) continue;
        if (!/\.from\s*\(\s*["']?(coupon|discount|promo|voucher|gift_?card)/i.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/\.from\s*\(\s*["']?(coupon|discount|promo|voucher|gift_?card)/i.test(line)) return;
          findings.push(
            mkFinding(
              "BIZ-005",
              "medium",
              "Coupon code used without redemption tracking",
              "Without marking a coupon used, the same code can be redeemed repeatedly by one account.",
              "Your discount code system does not check if a code has already been used. An attacker can apply the same coupon repeatedly to get unlimited discounts.",
              "Update the coupon row to `used = true` (or increment redemptions) in the same transaction as the order insert.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-840" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "BIZ-006",
    domain: "business-logic",
    title: "Negative quantity accepted on money-moving endpoint",
    description: "No non-negative check on amount/price/quantity",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-840" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Look for endpoints that read `amount` or `quantity` from the body and
      // do NOT validate it > 0 or use a zod .positive() / .min() call.
      const reads = /\b(amount|quantity|qty|price|value)\b\s*[:=]\s*(body|data|input|payload)\.\1/;
      for (const { file, source } of files) {
        if (!reads.test(source)) continue;
        if (/\.positive\s*\(|\.nonnegative\s*\(|\.gte?\s*\(\s*[1-9]|\.min\s*\(\s*[1-9]|>\s*0\b|>=\s*1\b|Math\.max\s*\(\s*[1-9]/.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!reads.test(line)) return;
          findings.push(
            mkFinding(
              "BIZ-006",
              "high",
              "Money/quantity field read without positivity check",
              "A negative amount can convert a payment into a credit, draining balances.",
              "Your payment endpoint accepts negative quantities without validation. An attacker can submit a negative amount to reverse a charge, effectively stealing money from your platform.",
              "Validate with Zod: `z.number().positive()`. Reject non-finite and negative values explicitly.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-840" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "BIZ-007",
    domain: "business-logic",
    title: "Missing email verification before login",
    description: "Login handler does not check email_confirmed_at",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-287" },
    async check(model) {
      const findings: Finding[] = [];
      const loginRoutes = model.endpoints.filter((e) => /login|signin|authenticate/i.test(e.path));
      for (const endpoint of loginRoutes) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (/email_confirmed_at|emailVerified|isVerified|verified/.test(source)) continue;
        // Skip if it delegates entirely to supabase.auth.signInWith* (Supabase
        // enforces verification itself based on the project setting).
        if (/supabase\.auth\.signInWith/.test(source)) continue;
        findings.push(
          mkFinding(
            "BIZ-007",
            "medium",
            `${endpoint.path} does not check email verification`,
            "Unverified accounts let attackers squat on other people's emails and receive their password reset tokens.",
            "Your app allows login without checking email verification. An attacker can sign up with someone else's email address and immediately access features that should require email ownership proof.",
            "Check `user.email_confirmed_at` before issuing a session.",
            [{ file: endpoint.file }],
            { cwe: "CWE-287" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-008",
    domain: "business-logic",
    title: "Signup allows arbitrary role",
    description: "Signup handler accepts a role/plan field from the request body",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-269", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const signupRoutes = model.endpoints.filter((e) => /signup|register/i.test(e.path));
      // Match either `role: body.role` (object literal shorthand) or
      // `const role = body.role`. Comments are stripped first so that files
      // with `// role: body.role` hints don't trigger.
      const stripComments = (s: string) =>
        s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
      const propertyStyle = /\b(role|plan|tier|isAdmin)\b\s*:\s*(body|data|input|payload)\.\b(role|plan|tier|isAdmin)\b/i;
      const assignmentStyle = /(role|plan|tier|isAdmin)\s*=\s*(body|data|input|payload)\.\b(role|plan|tier|isAdmin)\b/i;
      for (const endpoint of signupRoutes) {
        const raw = await safeReadFile(endpoint.file).catch(() => "");
        const source = stripComments(raw);
        if (!propertyStyle.test(source) && !assignmentStyle.test(source)) continue;
        findings.push(
          mkFinding(
            "BIZ-008",
            "critical",
            `${endpoint.path} accepts role from signup body`,
            "Letting the client pick its own role on signup is a direct privilege escalation primitive.",
            "Your signup endpoint accepts a role or plan tier from the request body. An attacker can set themselves as admin or premium during registration without paying or being authorized.",
            "Hard-code role to 'user' at signup. Restrict elevation to an admin-only endpoint.",
            [{ file: endpoint.file }],
            { cwe: "CWE-269", owasp: "A01:2021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-009",
    domain: "business-logic",
    title: "Password change without current password",
    description: "Change-password route does not require the current password",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-620" },
    async check(model) {
      const findings: Finding[] = [];
      const routes = model.endpoints.filter((e) => /change-password|update-password|reset-password/i.test(e.path));
      for (const endpoint of routes) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        // Skip reset flows (token-based).
        if (/reset_token|resetToken/.test(source)) continue;
        if (/currentPassword|oldPassword|old_password|existingPassword/.test(source)) continue;
        findings.push(
          mkFinding(
            "BIZ-009",
            "high",
            `${endpoint.path} changes password without verifying current one`,
            "Session hijacks, CSRF, and stolen cookies can all change a user's password without the attacker knowing it. Requiring the current password blocks that class of attack.",
            "Your password change endpoint does not require the current password. An attacker who gains temporary access to a session, like through an unattended browser, can lock the real user out permanently.",
            "Require the current password. Verify it with bcrypt.compare before updating.",
            [{ file: endpoint.file }],
            { cwe: "CWE-620" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "BIZ-010",
    domain: "business-logic",
    title: "Public registration without bot protection",
    description: "Signup endpoint has no captcha, hCaptcha, or turnstile",
    severity: "low",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-799" },
    async check(model) {
      const findings: Finding[] = [];
      const signupRoutes = model.endpoints.filter((e) => /signup|register/i.test(e.path));
      // Only skip on real bot-protection usage — actual imports or verify calls,
      // not any mention of "captcha" (comments often reference it for other reasons).
      const stripComments = (s: string) =>
        s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
      const realBotProtection = /(from\s+["'][^"']*(hcaptcha|turnstile|recaptcha|cloudflare\/turnstile)[^"']*["']|verifyCaptcha|verifyTurnstile|verifyHcaptcha|siteverify|captcha\.verify|hcaptcha\.verify|turnstile\.verify|H-captcha-response|cf-turnstile-response)/i;
      for (const endpoint of signupRoutes) {
        const raw = await safeReadFile(endpoint.file).catch(() => "");
        const source = stripComments(raw);
        if (realBotProtection.test(source)) continue;
        findings.push(
          mkFinding(
            "BIZ-010",
            "low",
            `${endpoint.path} has no bot protection`,
            "Open signups get abused by bots for spam, fake accounts, and quota exhaustion.",
            "Your signup endpoint has no bot protection. An attacker can create thousands of accounts programmatically for spam, abuse free tiers, or overwhelm your system.",
            "Add hCaptcha, Cloudflare Turnstile, or an equivalent invisible challenge to the signup flow.",
            [{ file: endpoint.file }],
            { cwe: "CWE-799" },
          ),
        );
      }
      return findings;
    },
  },
];
