import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sampleTraces } from "@firewall/contract/mock";
import { SqliteTraceStore } from "./sqlite.js";
import { createStore } from "./index.js";

describe("SqliteTraceStore", () => {
  let store: SqliteTraceStore;
  const samples = sampleTraces();

  beforeEach(async () => {
    store = new SqliteTraceStore(":memory:");
    for (const t of samples) await store.put(t);
  });
  afterEach(async () => {
    await store.close();
  });

  it("round-trips every sample trace by id", async () => {
    for (const t of samples) {
      expect(await store.get(t.id)).toEqual(t);
    }
    expect(await store.get("nope")).toBeNull();
  });

  it("lists newest first", async () => {
    const all = await store.list();
    expect(all).toHaveLength(samples.length);
    const sorted = [...samples].sort((a, b) => b.startedAt - a.startedAt).map((t) => t.id);
    expect(all.map((t) => t.id)).toEqual(sorted);
  });

  it("filters by verdict", async () => {
    const blocked = await store.list({ verdict: "blocked" });
    expect(blocked.length).toBeGreaterThan(0);
    expect(blocked.every((t) => t.verdict === "blocked")).toBe(true);
    expect(blocked.map((t) => t.id)).toEqual(["run_sample_exfil"]);
  });

  it("filters by agent and since", async () => {
    expect(await store.list({ agent: "claude-code" })).toHaveLength(samples.length);
    expect(await store.list({ agent: "someone-else" })).toHaveLength(0);
    const oldest = Math.min(...samples.map((t) => t.startedAt));
    expect(await store.list({ since: oldest })).toHaveLength(samples.length - 1);
  });

  it("honours limit", async () => {
    expect(await store.list({ limit: 1 })).toHaveLength(1);
  });

  it("overwrites on put with the same id", async () => {
    const t = { ...samples[0], verdict: "blocked" as const };
    await store.put(t);
    expect((await store.get(t.id))?.verdict).toBe("blocked");
    expect(await store.list()).toHaveLength(samples.length);
    expect(store.count()).toBe(samples.length);
    expect((await store.list({ verdict: "blocked" })).map((x) => x.id).sort()).toEqual(
      ["run_sample_clean", "run_sample_exfil"].sort(),
    );
  });
});

describe("createStore", () => {
  it("builds a memory store", async () => {
    const s = createStore("memory");
    await s.put(sampleTraces()[0]);
    expect(await s.list()).toHaveLength(1);
  });
  it("builds an in-memory sqlite store when a path is given", async () => {
    const s = createStore("sqlite", { path: ":memory:" });
    expect(s).toBeInstanceOf(SqliteTraceStore);
    await s.close?.();
  });
});
