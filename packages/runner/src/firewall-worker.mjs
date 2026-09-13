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

export const CHANNEL_NAME = "sandbox-firewall-fetch";

const sdkWorkerUrl = import.meta.resolve("@wasmer/sdk/node").replace(/node\.js$/, "node-worker.js");

const DEBUG = process.env.FIREWALL_DEBUG === "1";
const debug = (...args) => { if (DEBUG) console.error(`[firewall-worker ${threadId}]`, ...args); };
debug("wrapper loaded; real fetch is", typeof globalThis.fetch);

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
  const verdict = await new Promise((resolve) => {
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
  debug("verdict", id, JSON.stringify(verdict));
  if (!verdict.allowed) {
    throw new TypeError(`fetch failed: firewall refused ${host}${verdict.reason ? ` (${verdict.reason})` : ""}`);
  }
  return realFetch.call(globalThis, input, init);
};

await import(sdkWorkerUrl);
