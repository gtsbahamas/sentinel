import { describe, it, expect } from "vitest";
import {
  resolveAuthorization,
  parseTargetOrigin,
  buildAuthorizationEntry,
} from "../../../src/layers/probe/authorization.js";
import { PROBE_CONFIG_DEFAULTS } from "../../../src/layers/probe/schema.js";
import type { ProbeConfig, ProbeAuthorizationEntry } from "../../../src/model/types.js";

function makeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return { ...PROBE_CONFIG_DEFAULTS, enabled: true, targetUrl: null, ...overrides };
}

describe("parseTargetOrigin", () => {
  it("extracts scheme + host", () => {
    expect(parseTargetOrigin("https://example.com/path")).toBe("https://example.com");
  });

  it("preserves port", () => {
    expect(parseTargetOrigin("http://localhost:3000/api")).toBe("http://localhost:3000");
  });

  it("handles https without port", () => {
    expect(parseTargetOrigin("https://staging.app.com")).toBe("https://staging.app.com");
  });
});

describe("resolveAuthorization", () => {
  it("denies deny-listed hosts", () => {
    const result = resolveAuthorization({
      targetUrl: "https://google.com",
      requestedLevel: "passive",
      config: makeConfig({ allowPublicHosts: true }),
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-deny-list");
  });

  it("denies public hosts without --allow-public", () => {
    const result = resolveAuthorization({
      targetUrl: "https://my-app.com",
      requestedLevel: "passive",
      config: makeConfig({ allowPublicHosts: false }),
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-public");
  });

  it("allows public hosts with --allow-public", () => {
    const result = resolveAuthorization({
      targetUrl: "https://my-app.com",
      requestedLevel: "passive",
      config: makeConfig({ allowPublicHosts: true }),
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("needs-prompt");
  });

  it("denies RFC1918 without --internal-network", () => {
    const result = resolveAuthorization({
      targetUrl: "http://192.168.1.100:3000",
      requestedLevel: "passive",
      config: makeConfig({ allowInternalNetwork: false }),
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("denied-internal");
  });

  it("allows localhost without any special flags", () => {
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config: makeConfig(),
      existingEntries: [],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("needs-prompt");
  });

  it("grants when valid entry exists", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "passive",
      grantedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      scopeNote: "test",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000/api",
      requestedLevel: "passive",
      config: makeConfig(),
      existingEntries: [entry],
      authorizeFlagPresent: false,
    });
    expect(result.state).toBe("granted");
    expect(result.entry).toBe(entry);
  });

  it("detects expired entries", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "passive",
      grantedAt: new Date(Date.now() - 86400000 * 60).toISOString(),
      expiresAt: new Date(Date.now() - 86400000).toISOString(),
      scopeNote: "old",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config: makeConfig(),
      existingEntries: [entry],
      authorizeFlagPresent: false,
    });
    expect(result.state).toBe("expired");
  });

  it("always prompts for intrusive level", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "standard",
      grantedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      scopeNote: "test",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "intrusive",
      config: makeConfig(),
      existingEntries: [entry],
      authorizeFlagPresent: true,
    });
    expect(result.state).toBe("needs-prompt");
    expect(result.reason).toContain("Intrusive");
  });

  it("standard entry covers passive request", () => {
    const entry: ProbeAuthorizationEntry = {
      targetOrigin: "http://localhost:3000",
      level: "standard",
      grantedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      scopeNote: "test",
    };
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config: makeConfig(),
      existingEntries: [entry],
      authorizeFlagPresent: false,
    });
    expect(result.state).toBe("granted");
  });
});

describe("buildAuthorizationEntry", () => {
  it("creates entry with 30-day default expiry", () => {
    const entry = buildAuthorizationEntry("http://localhost:3000", "passive", "test");
    expect(entry.targetOrigin).toBe("http://localhost:3000");
    expect(entry.level).toBe("passive");
    expect(entry.scopeNote).toBe("test");
    const expiresIn = new Date(entry.expiresAt).getTime() - new Date(entry.grantedAt).getTime();
    expect(expiresIn).toBeCloseTo(30 * 86400000, -3);
  });
});
