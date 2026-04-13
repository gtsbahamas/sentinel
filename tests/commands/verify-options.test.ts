import { describe, it, expect } from "vitest";
import { mergeVerifyConfig } from "../../src/commands/verify-options.js";
import { CONFIG_DEFAULTS, type SentinelConfig } from "../../src/config.js";

function cloneConfig(): SentinelConfig {
  return JSON.parse(JSON.stringify(CONFIG_DEFAULTS)) as SentinelConfig;
}

describe("mergeVerifyConfig", () => {
  it("uses defaults from config when options are empty", () => {
    const config = cloneConfig();
    const result = mergeVerifyConfig({}, config);
    expect(result.enabled).toBe(false);
    expect(result.model).toBe("claude-haiku-4-5");
    expect(result.maxCostUsd).toBe(1.0);
    expect(result.concurrency).toBe(4);
    expect(result.minSeverity).toBe("medium");
    expect(result.keepDismissed).toBe(false);
    expect(result.provider).toBe("anthropic");
  });

  it("--verify enables verification", () => {
    const result = mergeVerifyConfig({ verify: true }, cloneConfig());
    expect(result.enabled).toBe(true);
    expect(result.model).toBe("claude-haiku-4-5");
  });

  it("--verify-model overrides model", () => {
    const result = mergeVerifyConfig(
      { verifyModel: "claude-sonnet-4-6" },
      cloneConfig(),
    );
    expect(result.model).toBe("claude-sonnet-4-6");
  });

  it("--verify-max-cost overrides budget", () => {
    const result = mergeVerifyConfig({ verifyMaxCost: 5.5 }, cloneConfig());
    expect(result.maxCostUsd).toBe(5.5);
  });

  it("--verify-concurrency overrides concurrency", () => {
    const result = mergeVerifyConfig({ verifyConcurrency: 8 }, cloneConfig());
    expect(result.concurrency).toBe(8);
  });

  it("--verify-min-severity overrides threshold", () => {
    const result = mergeVerifyConfig(
      { verifyMinSeverity: "high" },
      cloneConfig(),
    );
    expect(result.minSeverity).toBe("high");
  });

  it("--no-dismiss sets keepDismissed to true", () => {
    const result = mergeVerifyConfig({ dismiss: false }, cloneConfig());
    expect(result.keepDismissed).toBe(true);
  });

  it("absent dismiss leaves keepDismissed at default", () => {
    const result = mergeVerifyConfig({}, cloneConfig());
    expect(result.keepDismissed).toBe(false);
  });

  it("dismiss=true does not force keepDismissed on", () => {
    const result = mergeVerifyConfig({ dismiss: true }, cloneConfig());
    expect(result.keepDismissed).toBe(false);
  });

  it("provider is inherited from config.ai.provider", () => {
    const config = cloneConfig();
    config.ai.provider = "openai";
    const result = mergeVerifyConfig({}, config);
    expect(result.provider).toBe("openai");
  });
});
