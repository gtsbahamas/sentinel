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
    domain: "cryptography",
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
    impact: "Your app generates security tokens using Math.random(), which produces predictable sequences. An attacker can observe their own tokens, reverse-engineer the pattern, and predict tokens issued to other users, letting them hijack sessions or bypass verification flows.",
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
              "Your app generates security tokens using Math.random(), which produces predictable sequences. An attacker can observe their own tokens, reverse-engineer the pattern, and predict tokens issued to other users, letting them hijack sessions or bypass verification flows.",
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
    impact: "Your app hashes sensitive data with MD5 or SHA-1, both of which have known collision attacks. An attacker can forge a value that produces the same hash, bypassing signature checks or password verification.",
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
              "Your app hashes sensitive data with MD5 or SHA-1, both of which have known collision attacks. An attacker can forge a value that produces the same hash, bypassing signature checks or password verification.",
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
    impact: "Your app uses bcrypt with too few rounds, making password hashes fast to crack. An attacker who obtains your database can brute-force passwords in hours instead of years.",
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
              "Your app uses bcrypt with too few rounds, making password hashes fast to crack. An attacker who obtains your database can brute-force passwords in hours instead of years.",
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
    impact: "Your app encrypts data using ECB mode, which encrypts identical blocks to identical ciphertext. An attacker can detect patterns in encrypted data, like repeated values, without decrypting anything.",
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
              "Your app encrypts data using ECB mode, which encrypts identical blocks to identical ciphertext. An attacker can detect patterns in encrypted data, like repeated values, without decrypting anything.",
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
    impact: "Your app reuses the same initialization vector for encryption. An attacker who captures multiple encrypted messages can XOR them together to recover plaintext without knowing the key.",
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
              "Your app reuses the same initialization vector for encryption. An attacker who captures multiple encrypted messages can XOR them together to recover plaintext without knowing the key.",
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
    impact: "Your app has a cryptographic key hardcoded in source code. Anyone who reads your code, including through a leaked repo or decompiled bundle, has the key to decrypt all your data.",
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
              "Your app has a cryptographic key hardcoded in source code. Anyone who reads your code, including through a leaked repo or decompiled bundle, has the key to decrypt all your data.",
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
    impact: "Your app disables TLS certificate verification or forces an old TLS version. An attacker on the same network can intercept encrypted traffic using a forged certificate.",
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
              "Your app disables TLS certificate verification or forces an old TLS version. An attacker on the same network can intercept encrypted traffic using a forged certificate.",
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
    impact: "Your app compares secrets using normal string comparison, which leaks timing information. An attacker can guess a token character by character by measuring response times, bypassing HMAC or signature verification.",
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
              "Your app compares secrets using normal string comparison, which leaks timing information. An attacker can guess a token character by character by measuring response times, bypassing HMAC or signature verification.",
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
    impact: "Your app uses the deprecated createCipher function, which derives a weak key from a password. An attacker can recover the encryption key faster than a brute-force attack on the password itself.",
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
              "Your app uses the deprecated createCipher function, which derives a weak key from a password. An attacker can recover the encryption key faster than a brute-force attack on the password itself.",
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
    impact: "Your app stores passwords in the database without hashing them. If your database is compromised, every user's password is immediately exposed in readable form.",
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
              "Your app stores passwords in the database without hashing them. If your database is compromised, every user's password is immediately exposed in readable form.",
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
