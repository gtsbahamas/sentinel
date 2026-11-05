import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/fixtures/**", "**/tests/layers/ai/live/**", "**/tests/live/**"],
    testTimeout: 30000,
  },
});
