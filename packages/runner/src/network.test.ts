import { BroadcastChannel } from "node:worker_threads";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { NetworkEvent } from "@firewall/contract";
import { ensureNetworkPatched, FETCH_CHANNEL, registerBridge, setExclusiveContext, setExclusiveExecuting } from "./network.js";

/** Pretend to be a wrapper worker: post a check and wait for the verdict. */
function ask(channel: BroadcastChannel, host: string, port = 80): Promise<{ allowed: boolean; reason: string }> {
  const id = `t_${Math.random().toString(36).slice(2)}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no verdict")), 2000);
    const onmessage = (ev: unknown) => {
      const m = (ev as { data: { type: string; id: string; allowed: boolean; reason: string } }).data;
      if (m.type === "verdict" && m.id === id) {
        clearTimeout(timer);
        channel.removeEventListener("message", onmessage);
        resolve({ allowed: m.allowed, reason: m.reason });
      }
    };
    channel.addEventListener("message", onmessage);
    channel.postMessage({ type: "check", id, host, port, threadId: 99 });
  });
}

describe("host-fetch verdicts (main side)", () => {
  const worker = new BroadcastChannel(FETCH_CHANNEL);
  beforeAll(async () => {
    await ensureNetworkPatched();
  });
  afterAll(() => {
    setExclusiveContext(undefined);
    worker.close();
  });

  it("denies everything when no run owns the fetch path, except SDK hosts", async () => {
    setExclusiveContext(undefined);
    expect((await ask(worker, "example.com")).allowed).toBe(false);
    expect((await ask(worker, "registry.wasmer.io", 443)).allowed).toBe(true);
    expect((await ask(worker, "cdn.wasmer.io", 443)).allowed).toBe(true);
    expect((await ask(worker, "notwasmer.io", 443)).allowed).toBe(false);
  });

  it("records denied attempts on active socket-run contexts", async () => {
    const events: NetworkEvent[] = [];
    const unregister = registerBridge(424242, { allowHost: () => false, onEvent: (e) => events.push(e) });
    setExclusiveContext(undefined);
    await ask(worker, "attacker.example", 8080);
    unregister();
    expect(events).toEqual([expect.objectContaining({ kind: "connect", host: "attacker.example", port: 8080, allowed: false })]);
  });

  it("lets the exclusive run's policy decide only while it executes", async () => {
    const events: NetworkEvent[] = [];
    setExclusiveContext({ allowHost: (h) => h === "api.allowed.example", onEvent: (e) => events.push(e) });

    // Sandbox creation phase: SDK downloads go through, guest hosts do not.
    setExclusiveExecuting(false);
    expect((await ask(worker, "registry.wasmer.io", 443)).allowed).toBe(true);
    expect((await ask(worker, "api.allowed.example")).allowed).toBe(false);
    expect(events).toEqual([]);

    // Guest executing: policy decides, and wasmer.io is no longer special.
    setExclusiveExecuting(true);
    expect((await ask(worker, "api.allowed.example")).allowed).toBe(true);
    expect((await ask(worker, "evil.example")).allowed).toBe(false);
    expect((await ask(worker, "registry.wasmer.io", 443)).allowed).toBe(false);
    expect(events.map((e) => [e.host, e.allowed])).toEqual([
      ["api.allowed.example", true],
      ["evil.example", false],
      ["registry.wasmer.io", false],
    ]);
    setExclusiveContext(undefined);
  });
});
