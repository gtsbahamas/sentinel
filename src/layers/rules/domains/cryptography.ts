import fg from "fast-glob";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "cryptography",
    severity,
    confidence: "high",
    title,
    description,
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
      "**/test/**",
      "**/tests/**",
      "**/__tests__/**",
      "**/*.test.*",
      "**/*.spec.*",
    ],
  });
  return Promise.all(files.map(async (file) => ({ file, source: await safeReadFile(file) })));
}

// Certain patterns look like crypto but are actually benign (e.g.
// `Math.random()` used for a React key). The rules below attempt to
// distinguish a security-sensitive use by the surrounding context.
const SECURITY_CONTEXT_WORDS = /\b(token|password|secret|nonce|salt|csrf|session|auth|otp|reset|key|iv)\b/i;

export const cryptographyRules: SecurityRule[] = [
  {
    id: "CRYPTO-001",
    domain: "cryptography",
    title: "Math.random() used in a security context",
    description: "Math.random() is predictable and must not be used for tokens, IDs, or secrets",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-338" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/Math\.random\s*\(/.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/Math\.random\s*\(/.test(line)) return;
          // Look one line back and one line forward for a security word.
          const window = [lines[idx - 1] ?? "", line, lines[idx + 1] ?? ""].join(" ");
          if (!SECURITY_CONTEXT_WORDS.test(window)) return;
          findings.push(
            mkFinding(
              "CRYPTO-001",
              "critical",
              "Math.random() in a security-sensitive context",
              "Math.random() is a PRNG, not a CSPRNG. Predicting its output is straightforward.",
              "Use crypto.randomBytes(), crypto.randomUUID(), or the Web Crypto API's crypto.getRandomValues().",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-338" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-002",
    domain: "cryptography",
    title: "MD5 or SHA-1 used for passwords or signatures",
    description: "Weak hash algorithms used where collision resistance matters",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-327" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const hashCallRe = /createHash\s*\(\s*["'](md5|sha1)["']/i;
      for (const { file, source } of files) {
        const hasPasswordContext = /\bpassword|\bhash_password|\bverifyPassword|signature|\bsign\b/i.test(source);
        if (!hasPasswordContext && !hashCallRe.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(/createHash\s*\(\s*["'](md5|sha1)["']/i);
          if (!m) return;
          findings.push(
            mkFinding(
              "CRYPTO-002",
              "critical",
              `${m[1].toUpperCase()} used as a hash function`,
              `${m[1].toUpperCase()} is broken for collision resistance and must not be used for passwords or digital signatures.`,
              "Use bcrypt/argon2 for passwords. Use SHA-256 (or better) for signatures.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-327" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-003",
    domain: "cryptography",
    title: "bcrypt rounds below 10",
    description: "bcrypt.hash() called with < 10 salt rounds",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-916" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /bcrypt(?:js)?\.(?:hash|hashSync|genSalt|genSaltSync)\s*\([^,]*,\s*(\d+)/;
      for (const { file, source } of files) {
        if (!/bcrypt/.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(re);
          if (!m) return;
          const rounds = parseInt(m[1], 10);
          if (rounds >= 10) return;
          findings.push(
            mkFinding(
              "CRYPTO-003",
              "high",
              `bcrypt with ${rounds} rounds is too fast`,
              "Modern GPUs can brute-force bcrypt hashes with low round counts in hours.",
              "Use at least 12 rounds. Benchmark your hardware and target ~250ms per hash.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-916" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-004",
    domain: "cryptography",
    title: "ECB mode used for encryption",
    description: "createCipheriv called with an -ecb cipher suite",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-327" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /createCipheriv\s*\(\s*["']([^"']*-ecb)["']/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(re);
          if (!m) return;
          findings.push(
            mkFinding(
              "CRYPTO-004",
              "critical",
              `${m[1]} uses ECB mode`,
              "ECB leaks plaintext patterns. Identical blocks produce identical ciphertext.",
              "Use AES-GCM or ChaCha20-Poly1305 with a random 96-bit nonce and authentication tag.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-327" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-005",
    domain: "cryptography",
    title: "Hardcoded or zero IV",
    description: "createCipheriv or createDecipheriv uses a static IV",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-329" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Look for createCipheriv/createDecipheriv where the third arg is a
      // Buffer.alloc, Buffer.from("const"), or a literal array of zeros.
      const re = /create(?:De)?Cipheriv\s*\([^,]+,\s*[^,]+,\s*(Buffer\.alloc\s*\(\s*\d+\s*\)|Buffer\.from\s*\(\s*["'][^"']*["']|new\s+Uint8Array\s*\(\s*\d+\s*\)|["'][A-Fa-f0-9]{16,}["'])/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(re);
          if (!m) return;
          findings.push(
            mkFinding(
              "CRYPTO-005",
              "critical",
              "Static/hardcoded IV used",
              "Reusing an IV with the same key destroys the confidentiality guarantees of most block cipher modes.",
              "Generate a fresh IV per encryption with crypto.randomBytes(). Prepend the IV to the ciphertext before storing.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-329" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-006",
    domain: "cryptography",
    title: "Hardcoded cryptographic key in source",
    description: "createCipher/Hmac/Sign called with a literal string key",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /(createCipheriv|createHmac|createSign)\s*\([^,]+,\s*["']([^"']{4,})["']/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(re);
          if (!m) return;
          findings.push(
            mkFinding(
              "CRYPTO-006",
              "critical",
              `${m[1]} called with hardcoded key`,
              "Literal keys in source code are committed to git and recoverable from the build output.",
              "Read the key from a secret store (env var, AWS Secrets Manager, Vault, etc.).",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-798" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-007",
    domain: "cryptography",
    title: "Insecure TLS configuration",
    description: "rejectUnauthorized: false or TLS < 1.2 forced",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-295" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|minVersion\s*:\s*["']TLSv1(?:\.0|\.1)?["']/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!re.test(line)) return;
          findings.push(
            mkFinding(
              "CRYPTO-007",
              "high",
              "Insecure TLS settings",
              "Disabling certificate verification or enabling TLS 1.0/1.1 exposes the connection to MITM attacks.",
              "Keep rejectUnauthorized default. Set minVersion to TLSv1.2 or TLSv1.3.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-295" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-008",
    domain: "cryptography",
    title: "Naive string comparison on secrets",
    description: "HMAC or token compared with == instead of timingSafeEqual",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-208" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Match: <secret-ish identifier> (==|===|!=|!==) <something>, OR the
      // reverse form: <something> (==|===|!=|!==) <secret-ish identifier>.
      const reLeft = /\b(hmac|signature|token|mac|digest|sig)\w*\s*(===|!==|==|!=)\s*\S/i;
      const reRight = /\S\s*(===|!==|==|!=)\s*\b(hmac|signature|token|mac|digest|sig)\w*/i;
      for (const { file, source } of files) {
        if (!/hmac|signature|token|digest|\bmac\b/i.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          // Per-line: if this line already uses timingSafeEqual, it's fine.
          if (/timingSafeEqual/.test(line)) return;
          if (!reLeft.test(line) && !reRight.test(line)) return;
          findings.push(
            mkFinding(
              "CRYPTO-008",
              "high",
              "Secret compared with non-constant-time equality",
              "String comparison short-circuits on first mismatch, leaking information via timing.",
              "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) for secret comparison.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-208" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-009",
    domain: "cryptography",
    title: "Deprecated crypto.createCipher used",
    description: "createCipher (without -iv) derives a weak key from the password",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-326" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Match both `crypto.createCipher(` and a bare `createCipher(` from
      // a `import { createCipher } from "crypto"` style import. Must not
      // match createCipheriv.
      const callRe = /(?:\bcrypto\.|\b)createCipher\s*\(/;
      const ivRe = /createCipheriv/;
      for (const { file, source } of files) {
        // Only consider files that import from node's crypto module to
        // avoid false hits on unrelated libraries.
        const usesNodeCrypto = /from\s+["']crypto["']|require\s*\(\s*["']crypto["']\s*\)/.test(source);
        if (!usesNodeCrypto) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!callRe.test(line)) return;
          if (ivRe.test(line)) return;
          findings.push(
            mkFinding(
              "CRYPTO-009",
              "high",
              "Deprecated crypto.createCipher",
              "createCipher() uses EVP_BytesToKey which produces weak keys and has been deprecated since Node 10.",
              "Switch to crypto.createCipheriv with a properly derived key and random IV.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-326" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "CRYPTO-010",
    domain: "cryptography",
    title: "Plaintext password storage",
    description: "User password written to DB without a hash call",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-256", owasp: "A02:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Look for insert/upsert/update on a users/accounts table with a raw
      // `password:` field that isn't obviously hashed.
      const insertRe = /\.(insert|upsert|update)\s*\(\s*\{[^}]*password\s*:\s*([^,}\n]+)/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(insertRe);
          if (!m) return;
          const value = m[2];
          if (/bcrypt|argon2|scrypt|hash|pbkdf2/i.test(value)) return;
          findings.push(
            mkFinding(
              "CRYPTO-010",
              "critical",
              "Plaintext password written to database",
              "Storing passwords in plaintext means any database leak compromises every user account.",
              "Hash passwords with bcrypt/argon2 before insertion. Never store the plaintext.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-256", owasp: "A02:2021" },
            ),
          );
        });
      }
      return findings;
    },
  },
];
