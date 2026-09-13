/**
 * Host-side network interception.
 *
 * Two paths carry guest traffic out of a Wasmer sandbox on Node:
 *
 * 1. WASIX sockets. The Node entrypoint backs every guest DNS lookup and TCP
 *    connect with one `NodeNetworkBridge` per `Wasmer` client. Worker threads
 *    dispatch straight to the bridge object (not through globals), so the
 *    reliable hook is the prototype. We patch `resolve`, `connectTcp` and
 *    `listenTcp` once per process and route each call to the policy
 *    registered for that bridge id. Unregistered bridges are denied.
 *
 * 2. Host fetch. The SDK serves some guest HTTP (the Node guest's `fetch`)
 *    through the host's own `fetch` inside its worker threads. That never
 *    touches the bridge, and the SDK's `network: { mode: "disabled" }` does
 *    not gate it either. We point the SDK at our own worker entry
 *    (firewall-worker.mjs) which wraps `fetch` and asks this module, over a
 *    BroadcastChannel, whether the host is allowed. Workers are a
 *    process-wide pool with no run identity, so runs that can use this path
 *    hold an exclusive slot (see runner.ts) and the answer is attributed to
 *    that one run. With no exclusive run active the answer is always no.
 */
import { BroadcastChannel } from "node:worker_threads";
import type { NetworkEvent } from "@firewall/contract";

export interface NetworkContext {
  /** Decide whether the guest may resolve this hostname. */
  allowHost(host: string): boolean;
  /** Called for every observed attempt. */
  onEvent(event: NetworkEvent): void;
}

interface BridgeLike {
  id: number;
}

type BridgeModule = {
  NodeNetworkBridge: { prototype: Record<string, (...args: never[]) => unknown> };
  nodeNetworkBridge(id: number): BridgeLike;
};

type CoreModule = { setWorkerUrl(url: string): void };

export const FETCH_CHANNEL = "sandbox-firewall-fetch";
export const FIREWALL_WORKER_URL = new URL("./firewall-worker.mjs", import.meta.url).href;

const contexts = new Map<number, { ctx: NetworkContext; allowedIps: Set<string> }>();
let exclusive: NetworkContext | undefined;
let exclusiveExecuting = false;

/** Hosts the SDK itself talks to from its workers (registry queries, package downloads). */
const SDK_HOST = /(^|\.)wasmer\.io$/i;
let patched: Promise<BridgeModule> | undefined;
let coreModule: Promise<CoreModule> | undefined;
let fetchChannel: BroadcastChannel | undefined;

function sdkFile(relative: string): string {
  // Neither file is in the package's "exports" map, so resolve the public
  // node entrypoint and swap the path. Both resolve to the same module
  // instances the SDK itself uses, which is what makes the patches take.
  return import.meta.resolve("@wasmer/sdk/node").replace(/dist\/node\.js$/, relative);
}

export class NetworkBlockedError extends Error {
  constructor(
    public readonly host: string,
    public readonly kind: NetworkEvent["kind"],
  ) {
    super(`firewall: ${kind} ${host} refused by policy`);
  }
}

function stripPort(peer: string): { host: string; port?: number } {
  const m = peer.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
  if (!m) return { host: peer };
  return { host: m[1], port: m[2] ? Number(m[2]) : undefined };
}

/** Install the bridge interception and the fetch channel once. Safe to call repeatedly. */
export function ensureNetworkPatched(): Promise<BridgeModule> {
  patched ??= (async () => {
    const mod = (await import(sdkFile("dist/node-network.js"))) as BridgeModule;
    const proto = mod.NodeNetworkBridge.prototype;
    const origResolve = proto.resolve as (this: BridgeLike, host: string) => Promise<string[]>;
    const origConnect = proto.connectTcp as (this: BridgeLike, local: string, peer: string) => Promise<object>;

    proto.resolve = async function (this: BridgeLike, host: string): Promise<string[]> {
      const entry = contexts.get(this.id);
      const allowed = !!entry && entry.ctx.allowHost(host);
      entry?.ctx.onEvent({ kind: "resolve", host, allowed, at: Date.now() });
      if (!allowed) throw new NetworkBlockedError(host, "resolve");
      const ips = await origResolve.call(this, host);
      for (const ip of ips) entry!.allowedIps.add(ip);
      return ips;
    };

    proto.connectTcp = async function (this: BridgeLike, local: string, peer: string): Promise<object> {
      const entry = contexts.get(this.id);
      const { host, port } = stripPort(peer);
      // Only IPs that came back from an allowed resolve may be dialed. This
      // closes the "connect to a raw IP" bypass and keeps the allowlist about
      // hostnames, which is what humans write in policies.
      const allowed = !!entry && (entry.allowedIps.has(host) || entry.ctx.allowHost(host));
      entry?.ctx.onEvent({ kind: "connect", host, port, allowed, at: Date.now() });
      if (!allowed) throw new NetworkBlockedError(peer, "connect");
      return origConnect.call(this, local, peer);
    };

    proto.listenTcp = function (this: BridgeLike, address: string): object {
      const entry = contexts.get(this.id);
      // Guests never get to open listeners: nothing in the firewall needs it,
      // and a listener is the classic way to turn a sandbox into a relay.
      entry?.ctx.onEvent({ kind: "connect", host: `listen ${address}`, allowed: false, at: Date.now() });
      throw new NetworkBlockedError(address, "connect");
    };

    installFetchChannel();
    await installWorkerAdapter();
    return mod;
  })();
  return patched;
}

function installFetchChannel(): void {
  if (fetchChannel) return;
  fetchChannel = new BroadcastChannel(FETCH_CHANNEL);
  const debug = process.env.FIREWALL_DEBUG === "1" ? (...a: unknown[]) => console.error("[firewall-main]", ...a) : () => {};
  fetchChannel.onmessage = (event: unknown) => {
    const m = (event as { data?: { type?: string; id?: string; host?: string; port?: number } }).data;
    debug("channel message", JSON.stringify(m), "exclusive?", !!exclusive, "executing?", exclusiveExecuting);
    if (!m || m.type !== "check" || !m.id) return;
    const host = m.host ?? "(unknown)";
    let allowed = false;
    let reason = "no sandbox owns host fetch right now";
    if (exclusive && exclusiveExecuting) {
      // Guest code is running in the one run that owns the host-fetch path:
      // its policy decides, wasmer.io included.
      allowed = exclusive.allowHost(host);
      reason = allowed ? "" : "host not allowed by policy";
      exclusive.onEvent({ kind: "connect", host, port: m.port, allowed, at: Date.now() });
    } else if (SDK_HOST.test(host)) {
      // No guest is executing on this path, so a wasmer.io fetch is the SDK
      // loading packages for a sandbox being created. Let it through.
      allowed = true;
      reason = "";
    } else {
      for (const { ctx } of contexts.values()) ctx.onEvent({ kind: "connect", host, port: m.port, allowed: false, at: Date.now() });
    }
    debug("verdict", m.id, host, allowed, reason);
    fetchChannel!.postMessage({ type: "verdict", id: m.id, allowed, reason });
  };
  fetchChannel.unref();
}

/**
 * Route every SDK worker through our wrapper entry.
 *
 * The SDK spawns pool workers through `globalThis.Worker`, which it only
 * installs (as its `NodeWorkerAdapter`) when nothing is there yet, and it
 * spawns the first worker while the client is still initialising. So the
 * URL override alone comes too late for that worker. Installing our own
 * adapter subclass first, which swaps the URL in its constructor, catches
 * every worker; the `setWorkerUrl` override is kept as a second layer.
 */
export async function installWorkerAdapter(): Promise<void> {
  if (workerAdapterInstalled) return;
  workerAdapterInstalled = true;
  const { NodeWorkerAdapter } = (await import(sdkFile("dist/node-worker-adapter.js"))) as {
    NodeWorkerAdapter: new (url: string | URL, options?: unknown) => object;
  };
  class FirewallWorkerAdapter extends NodeWorkerAdapter {
    constructor(_url: string | URL, options?: unknown) {
      super(FIREWALL_WORKER_URL, options);
    }
  }
  Object.defineProperty(globalThis, "Worker", { configurable: true, value: FirewallWorkerAdapter });
}
let workerAdapterInstalled = false;

/** Second layer: the SDK-side worker URL. Only valid once the SDK wasm is initialised. */
export async function applyFirewallWorker(): Promise<void> {
  coreModule ??= import(sdkFile("pkg/wasmer_sdk_js.js")) as Promise<CoreModule>;
  (await coreModule).setWorkerUrl(FIREWALL_WORKER_URL);
}

/** Register the policy for a bridge id. Returns an unregister function. */
export function registerBridge(id: number, ctx: NetworkContext): () => void {
  contexts.set(id, { ctx, allowedIps: new Set() });
  return () => {
    contexts.delete(id);
  };
}

/** The one run allowed to use the host-fetch path right now. */
export function setExclusiveContext(ctx: NetworkContext | undefined): void {
  exclusive = ctx;
  exclusiveExecuting = false;
}

/** Mark whether the exclusive run's guest program is currently executing. */
export function setExclusiveExecuting(executing: boolean): void {
  exclusiveExecuting = executing;
}

/**
 * Bridge ids are allocated from a module-level counter starting at 1. Callers
 * create clients under a mutex, so every id above `after` that exists right
 * after the client initialised belongs to that client.
 */
export function discoverBridgeIds(mod: BridgeModule, after: number): number[] {
  const ids: number[] = [];
  for (let id = after + 1; id < after + 1000; id++) {
    try {
      mod.nodeNetworkBridge(id);
      ids.push(id);
    } catch {
      break;
    }
  }
  return ids;
}
