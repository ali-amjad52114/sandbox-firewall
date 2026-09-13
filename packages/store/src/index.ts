import type { TraceStore } from "@firewall/contract";
import { MemoryTraceStore } from "@firewall/contract/mock";
import { SqliteTraceStore } from "./sqlite.js";

export { SqliteTraceStore } from "./sqlite.js";
export { MemoryTraceStore };

export type StoreKind = "memory" | "sqlite";

export const DEFAULT_SQLITE_PATH = "data/traces.db";

/** Build a TraceStore. "sqlite" defaults to data/traces.db relative to cwd. */
export function createStore(kind: StoreKind, opts: { path?: string } = {}): TraceStore {
  switch (kind) {
    case "memory":
      return new MemoryTraceStore();
    case "sqlite":
      return new SqliteTraceStore(opts.path ?? DEFAULT_SQLITE_PATH);
    default:
      throw new Error(`unknown store kind: ${String(kind)}`);
  }
}
