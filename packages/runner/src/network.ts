/**
 * Host-side network interception.
 *
 * The Node entrypoint of @wasmer/sdk backs every guest DNS lookup and TCP
 * connect with one `NodeNetworkBridge` per `Wasmer` client. Worker threads
 * dispatch straight to the bridge object (not through globals), so the only
 * reliable hook is the prototype. We patch `resolve`, `connectTcp` and
 * `listenTcp` once per process and route each call to the policy registered
 * for that bridge id. Unregistered bridges are denied: default deny.
 */
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

const contexts = new Map<number, { ctx: NetworkContext; allowedIps: Set<string> }>();
let patched: Promise<BridgeModule> | undefined;

async function loadBridgeModule(): Promise<BridgeModule> {
  // The module is not in the package's "exports" map, so resolve the public
  // node entrypoint and swap the file name. Both resolve to the same module
  // instance the SDK itself uses, which is what makes the patch take effect.
  const nodeEntry = import.meta.resolve("@wasmer/sdk/node");
  const url = nodeEntry.replace(/node\.js$/, "node-network.js");
  return (await import(url)) as BridgeModule;
}

export class NetworkBlockedError extends Error {
  constructor(public readonly host: string, public readonly kind: NetworkEvent["kind"]) {
    super(`firewall: ${kind} ${host} refused by policy`);
  }
}

function stripPort(peer: string): { host: string; port?: number } {
  const m = peer.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
  if (!m) return { host: peer };
  return { host: m[1], port: m[2] ? Number(m[2]) : undefined };
}

/** Install the interception once. Safe to call repeatedly. */
export function ensureNetworkPatched(): Promise<BridgeModule> {
  patched ??= (async () => {
    const mod = await loadBridgeModule();
    const proto = mod.NodeNetworkBridge.prototype;
    const origResolve = proto.resolve as (this: BridgeLike, host: string) => Promise<string[]>;
    const origConnect = proto.connectTcp as (this: BridgeLike, local: string, peer: string) => Promise<object>;
    const origListen = proto.listenTcp as (this: BridgeLike, address: string) => object;

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
    return mod;
  })();
  return patched;
}

/** Register the policy for a bridge id. Returns an unregister function. */
export function registerBridge(id: number, ctx: NetworkContext): () => void {
  contexts.set(id, { ctx, allowedIps: new Set() });
  return () => {
    contexts.delete(id);
  };
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
