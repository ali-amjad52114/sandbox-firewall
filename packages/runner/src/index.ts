import type { Runner } from "@firewall/contract";
import { WasmerRunner, type WasmerRunnerOptions } from "./runner.js";

export { WasmerRunner } from "./runner.js";
export { findCanaries } from "./canary.js";
export { diff as diffSnapshots, snapshot as snapshotFs } from "./fsdiff.js";

/** Factory used by the gateway, console and eval CLI. */
export function createRunner(options: WasmerRunnerOptions = {}): Runner & { warm(): Promise<void> } {
  return new WasmerRunner({
    cacheDir: options.cacheDir ?? process.env.FIREWALL_CACHE_DIR,
    maxConcurrent: options.maxConcurrent ?? Number(process.env.FIREWALL_MAX_CONCURRENT ?? 4),
  });
}
