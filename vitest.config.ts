import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: "forks",
    fileParallelism: false,
  },
});
