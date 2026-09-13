// Replacement worker entry for @wasmer/sdk.
//
// The SDK serves guest HTTP (the Node guest's `fetch`, for one) through the
// host's own `fetch` inside its worker threads, which never touches the TCP
// bridge the runner intercepts. This wrapper runs first in every SDK worker,
// swaps `globalThis.fetch` for one that asks the runner (over a
// BroadcastChannel) whether the host is allowed, and only then loads the
// SDK's real worker script. Deny by default: no answer means no fetch.
import { BroadcastChannel, threadId } from "node:worker_threads";
import { randomUUID } from "node:crypto";
import diagnostics_channel from "node:diagnostics_channel";

export const CHANNEL_NAME = "sandbox-firewall-fetch";

const sdkWorkerUrl = import.meta.resolve("@wasmer/sdk/node").replace(/node\.js$/, "node-worker.js");

const DEBUG = process.env.FIREWALL_DEBUG === "1";
const debug = (...args) => { if (DEBUG) console.error(`[firewall-worker ${threadId}]`, ...args); };
debug("wrapper loaded; real fetch is", typeof globalThis.fetch);
if (DEBUG) diagnostics_channel.subscribe("undici:request:create", (m) => console.error(`[undici worker ${threadId}]`, m.request.origin, m.request.path));

const channel = new BroadcastChannel(CHANNEL_NAME);
const pending = new Map();
channel.onmessage = (event) => {
  const m = event.data;
  debug("channel message", JSON.stringify(m));
  if (m && m.type === "verdict" && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
};
channel.unref();

const realFetch = globalThis.fetch;

function targetOf(input) {
  try {
    if (typeof input === "string") return new URL(input);
    if (input instanceof URL) return input;
    if (input && typeof input.url === "string") return new URL(input.url);
  } catch {
    /* fall through */
  }
  return null;
}

globalThis.fetch = async function firewalledFetch(input, init) {
  const url = targetOf(input);
  const host = url ? url.hostname : "(unparseable)";
  const port = url ? (url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80) : undefined;
  const id = randomUUID();
  debug("fetch", host, port, "asking", id);
  const verdict = await askVerdict(id, host, port);
  debug("verdict", id, JSON.stringify(verdict));
  if (!verdict.allowed) {
    throw new TypeError(`fetch failed: firewall refused ${host}${verdict.reason ? ` (${verdict.reason})` : ""}`);
  }
  return realFetch.call(globalThis, input, init);
};

// Second, lower hook: undici's global dispatcher. Every request Node's
// fetch machinery makes in this thread goes through `dispatch`, however the
// caller obtained `fetch`. The SDK's guest HTTP reaches undici without
// touching `globalThis.fetch`, so this is the hook that actually matters.
const DISPATCHER = Symbol.for("undici.globalDispatcher.1");
async function installDispatcherGuard() {
  if (!globalThis[DISPATCHER]) {
    // Force undici to create its default Agent so we can wrap it. The
    // throwaway request goes to a closed local port and fails at once.
    await realFetch("http://127.0.0.1:1/").catch(() => {});
  }
  const real = globalThis[DISPATCHER];
  if (!real || typeof real.dispatch !== "function") {
    debug("no undici dispatcher to guard");
    return;
  }
  const guarded = new Proxy(real, {
    get(target, prop, receiver) {
      if (prop !== "dispatch") return Reflect.get(target, prop, receiver);
      return (opts, handler) => {
        let host = "(unknown)";
        let port;
        try {
          const origin = new URL(String(opts.origin));
          host = origin.hostname;
          port = origin.port ? Number(origin.port) : origin.protocol === "https:" ? 443 : 80;
        } catch {
          /* keep unknown */
        }
        const id = randomUUID();
        debug("dispatch", host, port, opts.path, "asking", id);
        askVerdict(id, host, port).then((verdict) => {
          debug("verdict", id, JSON.stringify(verdict));
          if (verdict.allowed) {
            try {
              target.dispatch(opts, handler);
            } catch (err) {
              handler.onError?.(err);
            }
          } else {
            const err = new TypeError(`firewall refused ${host}${verdict.reason ? ` (${verdict.reason})` : ""}`);
            err.code = "FIREWALL_REFUSED";
            handler.onError?.(err);
          }
        });
        return true;
      };
    },
  });
  globalThis[DISPATCHER] = guarded;
  debug("undici dispatcher guarded");
}

function askVerdict(id, host, port) {
  return new Promise((resolve) => {
    pending.set(id, resolve);
    channel.postMessage({ type: "check", id, host, port, threadId });
    const timer = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        resolve({ allowed: false, reason: "no answer from firewall" });
      }
    }, 5000);
    if (typeof timer.unref === "function") timer.unref();
  });
}

await installDispatcherGuard();
await import(sdkWorkerUrl);
