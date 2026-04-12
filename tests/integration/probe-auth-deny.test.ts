import { describe, it, expect } from "vitest";
import { resolveAuthorization } from "../../src/layers/probe/authorization.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProbeConfig, ProbeAuthorizationEntry } from "../../src/model/types.js";

const config: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "passive",
  targetUrl: "http://localhost:3000",
};

describe("resolveAuthorization integration", () => {
  it("denies access to deny-listed hosts (google.com → denied-deny-list)", () => {
    const result = resolveAuthorization({
      targetUrl: "https://google.com/search",
      requestedLevel: "passive",
      config: { ...config, allowPublicHosts: true },
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-deny-list");
  });

  it("denies access to RFC1918 without --internal-network (192.168.1.1 → denied-internal)", () => {
    const result = resolveAuthorization({
      targetUrl: "http://192.168.1.1/admin",
      requestedLevel: "passive",
      config: { ...config, allowInternalNetwork: false },
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-internal");
  });

  it("denies access to public hosts without --allow-public (my-staging.example.com → denied-public)", () => {
    const result = resolveAuthorization({
      targetUrl: "https://my-staging.example.com",
      requestedLevel: "passive",
      config: { ...config, allowPublicHosts: false },
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-public");
  });

  it("returns needs-prompt for intrusive even with existing authorization", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "standard",
      grantedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      scopeNote: "granted for testing",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "intrusive",
      config,
      existingEntries: [entry],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("needs-prompt");
  });

  it("grants access for localhost with valid authorization", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "passive",
      grantedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      scopeNote: "local dev",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config,
      existingEntries: [entry],
      authorizeFlagPresent: false,
    });
    expect(result.state).toBe("granted");
    expect(result.entry).toBe(entry);
  });

  it("detects expired authorization (expiresAt in the past → expired)", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "passive",
      grantedAt: "2025-01-01T00:00:00Z",
      expiresAt: "2025-01-31T00:00:00Z",
      scopeNote: "old grant",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config,
      existingEntries: [entry],
      authorizeFlagPresent: false,
    });
    expect(result.state).toBe("expired");
  });
});
