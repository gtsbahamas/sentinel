import { defineConfig } from "vitest/config";

// Real api.osv.dev lookups. Excluded from the default suite (see
// vitest.config.ts) because they need the network.
// Run with: npm run test:osv-live
export default defineConfig({
  test: {
    include: ["tests/live/osv/**/*.test.ts"],
    testTimeout: 60_000,
  },
});
