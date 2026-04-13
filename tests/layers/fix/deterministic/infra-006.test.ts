import { describe, it, expect } from "vitest";
import { infra006Fixer } from "../../../../src/layers/fix/deterministic/infra-006.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(evidenceFile: string): Finding {
  return {
    id: "test-finding-infra-006",
    ruleId: "INFRA-006",
    domain: "infrastructure",
    severity: "medium",
    confidence: "confirmed",
    title: "Missing Security Headers",
    description: "Security headers are not configured",
    impact: "Missing security headers increase attack surface",
    evidence: [{ file: evidenceFile }],
    remediation: "Add security headers to next.config",
    references: [],
    layer: "rules",
  };
}

const NEXT_CONFIG_WITHOUT_HEADERS = `/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
`;

const NEXT_CONFIG_WITH_EXISTING_HEADERS = `/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
    ];
  },
};

export default nextConfig;
`;

describe("infra006Fixer", () => {
  it("has correct ruleId and type", () => {
    expect(infra006Fixer.ruleId).toBe("INFRA-006");
    expect(infra006Fixer.type).toBe("deterministic");
  });

  it("adds headers() to next.config.mjs without existing headers", () => {
    const finding = makeFinding("next.config.mjs");
    const result = infra006Fixer.apply!(NEXT_CONFIG_WITHOUT_HEADERS, finding);

    expect(result).not.toBeNull();
    expect(result).toContain("async headers()");
    expect(result).toContain("X-Content-Type-Options");
    expect(result).toContain("nosniff");
    expect(result).toContain("X-Frame-Options");
    expect(result).toContain("DENY");
    expect(result).toContain("Referrer-Policy");
    expect(result).toContain("strict-origin-when-cross-origin");
    expect(result).toContain("Permissions-Policy");
    expect(result).toContain("camera=(), microphone=(), geolocation=()");
    expect(result).toContain("X-DNS-Prefetch-Control");
    expect(result).toContain("on");
  });

  it("adds headers() to next.config.js without existing headers", () => {
    const finding = makeFinding("next.config.js");
    const result = infra006Fixer.apply!(NEXT_CONFIG_WITHOUT_HEADERS, finding);

    expect(result).not.toBeNull();
    expect(result).toContain("async headers()");
    expect(result).toContain("X-Content-Type-Options");
  });

  it("adds headers() to next.config.ts without existing headers", () => {
    const finding = makeFinding("next.config.ts");
    const result = infra006Fixer.apply!(NEXT_CONFIG_WITHOUT_HEADERS, finding);

    expect(result).not.toBeNull();
    expect(result).toContain("async headers()");
  });

  it("returns null for non-config files", () => {
    const finding = makeFinding("src/app/page.tsx");
    const result = infra006Fixer.apply!(NEXT_CONFIG_WITHOUT_HEADERS, finding);

    expect(result).toBeNull();
  });

  it("returns null when X-Content-Type-Options already present", () => {
    const finding = makeFinding("next.config.mjs");
    const result = infra006Fixer.apply!(NEXT_CONFIG_WITH_EXISTING_HEADERS, finding);

    expect(result).toBeNull();
  });

  it("is idempotent — second run returns null", () => {
    const finding = makeFinding("next.config.mjs");
    const first = infra006Fixer.apply!(NEXT_CONFIG_WITHOUT_HEADERS, finding)!;
    const second = infra006Fixer.apply!(first, finding);

    expect(second).toBeNull();
  });
});
