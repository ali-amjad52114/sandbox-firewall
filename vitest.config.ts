import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: "forks",
    fileParallelism: false,
    // The Node guest runtime inside Wasmer sandboxes needs JSPI on the host.
    execArgv: ["--experimental-wasm-jspi"],
  },
});
