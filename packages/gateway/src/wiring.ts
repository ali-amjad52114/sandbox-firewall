import type { Runner, TraceStore } from "@firewall/contract";
import { MemoryTraceStore, MockRunner } from "@firewall/contract/mock";

export interface Wiring {
  runner: Runner & { warm?(langs?: string[]): Promise<void> };
  store: TraceStore;
}

/**
 * Picks the runner and trace store from the environment.
 *
 *   FIREWALL_RUNNER  "wasmer" (default) | "mock"
 *   FIREWALL_STORE   "sqlite" (default) | "memory"
 *   FIREWALL_DB      sqlite path, default data/traces.db
 */
export async function createWiring(env: NodeJS.ProcessEnv = process.env): Promise<Wiring> {
  const runnerName = env.FIREWALL_RUNNER ?? "wasmer";
  const storeName = env.FIREWALL_STORE ?? "sqlite";

  let runner: Wiring["runner"];
  if (runnerName === "mock") runner = new MockRunner();
  else if (runnerName === "wasmer") {
    const mod = await import("@firewall/runner");
    runner = mod.createRunner();
  } else throw new Error(`FIREWALL_RUNNER=${runnerName}: expected "wasmer" or "mock"`);

  let store: TraceStore;
  if (storeName === "memory") store = new MemoryTraceStore();
  else if (storeName === "sqlite") {
    const mod = await import("@firewall/store");
    store = mod.createStore("sqlite", { path: env.FIREWALL_DB ?? "data/traces.db" });
  } else throw new Error(`FIREWALL_STORE=${storeName}: expected "sqlite" or "memory"`);

  return { runner, store };
}
