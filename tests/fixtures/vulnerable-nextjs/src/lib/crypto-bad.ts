// Intentionally vulnerable fixture for cryptography domain rules.
import { createHash, createCipher, createCipheriv, createHmac } from "crypto";

// VULN CRYPTO-001: Math.random for a security token.
export function makeToken(): string {
  const token = Math.random().toString(36).slice(2);
  return token;
}

// VULN CRYPTO-002: MD5 used for password hashing.
export function hashPassword(password: string): string {
  return createHash("md5").update(password).digest("hex");
}

// VULN CRYPTO-003: bcrypt with low rounds — simulated via a string comment
// because the fixture does not install bcrypt. The rule scans text.
const bcryptRoundsExample = `bcrypt.hash(password, 4)`;
void bcryptRoundsExample;

// VULN CRYPTO-004: ECB mode.
export function encryptEcb(key: Buffer, plaintext: string): Buffer {
  const cipher = createCipheriv("aes-128-ecb", key, Buffer.alloc(0));
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
}

// VULN CRYPTO-005: Static IV.
export function encryptStaticIv(key: Buffer, plaintext: string): Buffer {
  const iv = Buffer.alloc(16);
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
}

// VULN CRYPTO-006: Hardcoded HMAC key.
export function signHardcoded(message: string): string {
  return createHmac("sha256", "hardcoded-secret-key").update(message).digest("hex");
}

// VULN CRYPTO-007: Insecure TLS.
export const badTls = {
  rejectUnauthorized: false,
};

// VULN CRYPTO-008: Naive HMAC comparison.
export function verifySignatureNaive(expected: string, provided: string): boolean {
  const signature = provided;
  return signature === expected;
}

// VULN CRYPTO-009: Deprecated createCipher.
export function encryptLegacy(password: string, plaintext: string): Buffer {
  const cipher = createCipher("aes-128-cbc", password);
  return Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
}
