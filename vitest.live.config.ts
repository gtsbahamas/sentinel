import { defineConfig } from "vitest/config";

// Live AI provider smoke tests. Excluded from the default test suite
// (see vitest.config.ts) because they spend real money and require API keys.
// Run with: npm run test:ai-live
export default defineConfig({
  test: {
    include: ["tests/layers/ai/live/**/*.test.ts"],
    exclude: ["tests/fixtures/**"],
    testTimeout: 180_000,
  },
});
