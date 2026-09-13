import { Wasmer, type Sandbox, type WasmerOptions } from "@wasmer/sdk/node";
import {
  deriveVerdict,
  LANGUAGE_PACKAGES,
  SEVERITY,
  type FsChange,
  type Language,
  type NetworkEvent,
  type Runner,
  type RunRequest,
  type Trace,
  type Violation,
} from "@firewall/contract";
import { hostAllowed, pathWritable, validate } from "@firewall/policy";
import { findCanaries } from "./canary.js";
import { diff, snapshot } from "./fsdiff.js";
import { applyFirewallWorker, discoverBridgeIds, ensureNetworkPatched, registerBridge, setExclusiveContext, setExclusiveExecuting, type NetworkContext } from "./network.js";

const RUNNER_VERSION = "0.1.0";

const ENTRY: Record<Language, { file: string; command: string }> = {
  python: { file: "main.py", command: "python" },
  node: { file: "main.js", command: "edgejs" },
  php: { file: "main.php", command: "php" },
};

export interface WasmerRunnerOptions {
  /** Directory for the SDK package cache. Defaults to .wasmer in cwd. */
  cacheDir?: string;
  /** Maximum concurrently running sandboxes. Each needs its own Wasmer client. */
  maxConcurrent?: number;
}

/**
 * One `Wasmer` client owns one network bridge, and the bridge is the unit we
 * can attribute network calls to. So a run leases a client, and clients are
 * pooled: the engine initialises once per process (about 6 s) and later
 * clients cost about a second, later sandboxes on a client about 2 ms.
 */
class ClientLease {
  constructor(
    public readonly wasmer: Wasmer,
    public readonly bridgeIds: number[],
  ) {}
  busy = false;
}

let maxSeenBridgeId = 0;
let clientInitChain: Promise<unknown> = Promise.resolve();

/** Same SDK client, but every worker it spawns runs our fetch-wrapping entry first. */
class FirewallWasmer extends Wasmer {
  protected static async initializeCore(options: WasmerOptions) {
    const client = await super.initializeCore(options);
    await applyFirewallWorker();
    return client;
  }
}

/**
 * Languages whose guest HTTP rides the host-fetch path. Those runs are
 * exclusive so the worker pool's fetch questions attribute to exactly one
 * trace. Python and PHP use WASIX sockets, which the bridge attributes
 * per client, so they run concurrently.
 */
const HOST_FETCH_LANGUAGES: ReadonlySet<Language> = new Set(["node"]);

/**
 * Readers (socket-only runs: python, php) share; a writer (a host-fetch run:
 * node) runs alone. Writer-preferring: once a writer is waiting, new readers
 * queue behind it, so a steady stream of readers cannot starve a node run.
 */
class RunSlots {
  private readers = 0;
  private writer = false;
  private waitingWriters = 0;
  private queue: (() => void)[] = [];
  async acquire(exclusive: boolean): Promise<void> {
    if (exclusive) {
      this.waitingWriters++;
      try {
        while (this.writer || this.readers > 0) await this.park();
        this.writer = true;
      } finally {
        this.waitingWriters--;
      }
    } else {
      while (this.writer || this.waitingWriters > 0) await this.park();
      this.readers++;
    }
  }
  release(exclusive: boolean): void {
    if (exclusive) this.writer = false;
    else this.readers--;
    const waiting = this.queue;
    this.queue = [];
    for (const wake of waiting) wake();
  }
  private park(): Promise<void> {
    return new Promise<void>((resolve) => this.queue.push(resolve));
  }
}
const slots = new RunSlots();

export class WasmerRunner implements Runner {
  private pool: ClientLease[] = [];
  private waiters: (() => void)[] = [];
  private readonly maxConcurrent: number;
  private closed = false;

  constructor(private readonly options: WasmerRunnerOptions = {}) {
    this.maxConcurrent = options.maxConcurrent ?? 4;
  }

  async run(req: RunRequest): Promise<Trace> {
    if (this.closed) throw new Error("runner is closed");
    validate(req.policy);
    const entry = ENTRY[req.language];
    if (!entry) throw new Error(`unsupported language: ${req.language}`);

    const startedAt = Date.now();
    const t0 = performance.now();
    const network: NetworkEvent[] = [];
    const violations: Violation[] = [];
    const egressLeaks: { name: string; encoding: string; where: string }[] = [];
    const exclusive = HOST_FETCH_LANGUAGES.has(req.language);
    const netContext: NetworkContext = {
      allowHost: (host: string) => hostAllowed(req.policy, host),
      onEvent: (e: NetworkEvent) => network.push(e),
      // Bytes the guest tries to send out. A hostname allowlist says nothing
      // about a secret hidden in a URL path, query string or POST body, so
      // this is where payload exfil to an ALLOWED host is caught.
      scanEgress: (text: string, where: string) => {
        for (const hit of findCanaries(text, req.policy.canaries)) egressLeaks.push({ name: hit.name, encoding: hit.encoding, where });
      },
    };

    // Everything that must be released is acquired inside the try so a failure
    // to lease a client or a bridge can never leak a slot and deadlock the
    // runner (the finally always runs).
    let lease: ClientLease | undefined;
    let unregister: Array<() => void> = [];
    let sandbox: Sandbox | undefined;
    let sandboxCreateMs = 0;
    let execMs = 0;
    let stdout = "";
    let stderr = "";
    let exitCode: number | null = null;
    let exitReason: Trace["exitReason"] = "error";
    let outputTruncated = false;
    let fsChanges: FsChange[] = [];
    await slots.acquire(exclusive);
    try {
      lease = await this.acquire();
      unregister = lease.bridgeIds.map((id) => registerBridge(id, netContext));
      if (exclusive) setExclusiveContext(netContext);
      const files: Record<string, string> = { ...(req.files ?? {}) };
      const useEntryFile = req.code.length > 0 || !(req.args?.length);
      if (useEntryFile) files[entry.file] = req.code;
      const env = { ...(req.policy.env ?? {}), ...req.policy.canaries };

      const tc = performance.now();
      sandbox = await lease.wasmer.sandboxes.create({
        packages: [LANGUAGE_PACKAGES[req.language], ...(req.policy.packages ?? [])],
        files,
        env,
        // Always "host" so every DNS and TCP attempt reaches our bridge patch.
        // The policy decides there; "off" means the patch refuses everything
        // and we still get to record what the guest tried.
        network: { mode: "host" },
      });
      sandboxCreateMs = performance.now() - tc;

      const before = await snapshot(sandbox.fs);
      const args = useEntryFile ? [entry.file, ...(req.args ?? [])] : [...(req.args ?? [])];
      const te = performance.now();
      if (exclusive) setExclusiveExecuting(true);
      const out = await sandbox.command(entry.command, args, { cwd: "/workspace" }).run({
        check: false,
        timeoutMs: req.policy.limits.wallMs,
        outputBytes: req.policy.limits.maxOutputBytes,
        stdin: req.stdin,
      });
      if (exclusive) setExclusiveExecuting(false);
      execMs = performance.now() - te;
      stdout = out.stdout.text();
      stderr = out.stderr.text();
      exitCode = out.exitCode;
      exitReason = out.reason;
      outputTruncated = out.stdout.truncated || out.stderr.truncated;

      const after = await snapshot(sandbox.fs);
      fsChanges = diff(before, after, (p) => pathWritable(req.policy, p));

      // Violations, in the order a reader wants them: leaks first, then
      // network, then fs, then limits.
      const now = Date.now();
      const hosts = network.map((e) => e.host);
      const canaryWhere: [string, string, { minChunk?: number }][] = [
        ["stdout", stdout, {}],
        ["stderr", stderr, {}],
        ["network", hosts.join("\n"), { minChunk: 12 }],
        // DNS exfil hides bytes in subdomain labels across several lookups;
        // reassembling the labels makes a split secret one contiguous string.
        ["network-labels", reassembleLabels(hosts), { minChunk: 8 }],
      ];
      for (const change of fsChanges) {
        // Scan written files for a handled secret. Padding a file past the cap
        // to hide the canary is a known residual (see README Limits); 16 MB is
        // far past any realistic "hide 40 bytes" and files never leave the box.
        if (change.op === "delete" || (change.bytes ?? 0) > 16 * 1024 * 1024) continue;
        try {
          const rel = change.path.replace(/^\/workspace\//, "");
          canaryWhere.push([`fs:${change.path}`, await sandbox.fs.readText(rel), {}]);
        } catch {
          /* binary or unreadable; skip */
        }
      }
      const leaked = new Set<string>();
      for (const [where, text, opts] of canaryWhere) {
        for (const hit of findCanaries(text, req.policy.canaries, opts)) {
          const key = `${hit.name}@${where}`;
          if (leaked.has(key)) continue;
          leaked.add(key);
          violations.push({
            kind: "canary.leaked",
            severity: SEVERITY["canary.leaked"],
            detail: `canary ${hit.name} observed in ${where} (${hit.encoding})`,
            at: now,
            where,
          });
        }
      }
      // Canaries seen in outbound request bytes during execution (scanEgress).
      for (const l of egressLeaks) {
        const key = `${l.name}@${l.where}`;
        if (leaked.has(key)) continue;
        leaked.add(key);
        violations.push({
          kind: "canary.leaked",
          severity: SEVERITY["canary.leaked"],
          detail: `canary ${l.name} observed in ${l.where} (${l.encoding})`,
          at: now,
          where: l.where,
        });
      }
      const blockedHosts = new Set<string>();
      for (const e of network) {
        if (e.allowed || blockedHosts.has(e.host)) continue;
        blockedHosts.add(e.host);
        violations.push({
          kind: "network.blocked",
          severity: SEVERITY["network.blocked"],
          detail: `${e.kind} ${e.host}${e.port ? ":" + e.port : ""} refused by policy ${req.policy.name}`,
          at: e.at,
          where: "network",
        });
      }
      for (const c of fsChanges) {
        if (c.allowed) continue;
        violations.push({
          kind: "fs.outside_writable",
          severity: SEVERITY["fs.outside_writable"],
          detail: `${c.op} ${c.path}${c.bytes !== undefined ? ` (${c.bytes} bytes)` : ""} outside writable paths`,
          at: now,
          where: `fs:${c.path}`,
        });
      }
      if (exitReason === "timeout") {
        violations.push({
          kind: "limit.wall",
          severity: SEVERITY["limit.wall"],
          detail: `killed after ${req.policy.limits.wallMs} ms wall-clock budget`,
          at: now,
          where: "limits",
        });
      }
      if (outputTruncated) {
        violations.push({
          kind: "limit.output",
          severity: SEVERITY["limit.output"],
          detail: `output truncated at ${req.policy.limits.maxOutputBytes} bytes`,
          at: now,
          where: "limits",
        });
      }
    } catch (err) {
      const e = err as Error & { code?: string };
      violations.push({
        kind: "runtime.error",
        severity: SEVERITY["runtime.error"],
        detail: `${e.code ?? "ERROR"}: ${e.message}`,
        at: Date.now(),
        where: "runner",
      });
      stderr = stderr || e.message;
    } finally {
      if (exclusive) setExclusiveContext(undefined);
      for (const u of unregister) u();
      if (sandbox) await sandbox.close().catch(() => {});
      if (lease) this.release(lease);
      slots.release(exclusive);
    }

    const endedAt = Date.now();
    return {
      id: req.id,
      request: req,
      startedAt,
      endedAt,
      exitCode,
      exitReason,
      stdout,
      stderr,
      outputTruncated,
      violations,
      network,
      fs: fsChanges,
      verdict: deriveVerdict(violations),
      timings: { sandboxCreateMs: round(sandboxCreateMs), execMs: round(execMs), totalMs: round(performance.now() - t0) },
      runner: { name: "wasmer", version: RUNNER_VERSION },
    };
  }

  /** Warm the engine and the language package caches so the first real run is fast. */
  async warm(languages: Language[] = ["python"]): Promise<void> {
    const lease = await this.acquire();
    try {
      for (const lang of languages) {
        const sb = await lease.wasmer.sandboxes.create({ packages: [LANGUAGE_PACKAGES[lang]] });
        await sb.close();
      }
    } finally {
      this.release(lease);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    const pool = this.pool;
    this.pool = [];
    await Promise.all(pool.map((l) => l.wasmer.close().catch(() => {})));
  }

  private async acquire(): Promise<ClientLease> {
    for (;;) {
      const free = this.pool.find((l) => !l.busy);
      if (free) {
        free.busy = true;
        return free;
      }
      if (this.pool.length < this.maxConcurrent) {
        const lease = await this.createLease();
        lease.busy = true;
        this.pool.push(lease);
        return lease;
      }
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }

  private release(lease: ClientLease): void {
    lease.busy = false;
    this.waiters.shift()?.();
  }

  private createLease(): Promise<ClientLease> {
    // Serialise client creation so bridge-id discovery is unambiguous.
    const next = clientInitChain.then(async () => {
      const mod = await ensureNetworkPatched();
      const wasmer = new FirewallWasmer({
        cache: this.options.cacheDir ? { directory: this.options.cacheDir } : undefined,
      });
      // The bridge is created lazily on the first sandbox. Create and drop a
      // trivial one so we can learn the id before any guest code runs.
      const probe = await wasmer.sandboxes.create({ network: { mode: "disabled" } });
      await probe.close();
      const ids = discoverBridgeIds(mod, maxSeenBridgeId);
      if (ids.length === 0) throw new Error("firewall: could not attribute a network bridge to the new Wasmer client");
      maxSeenBridgeId = Math.max(maxSeenBridgeId, ...ids);
      return new ClientLease(wasmer, ids);
    });
    clientInitChain = next.catch(() => {});
    return next;
  }
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}

/**
 * Concatenate the leftmost labels of every attempted hostname (dropping the
 * two rightmost, the registrable-ish domain). A secret split across DNS labels
 * and across multiple lookups reassembles into one contiguous string the
 * canary scanner can match.
 */
function reassembleLabels(hosts: string[]): string {
  const parts: string[] = [];
  for (const h of hosts) {
    const labels = h.split(".").filter(Boolean);
    if (labels.length <= 2) continue;
    parts.push(labels.slice(0, labels.length - 2).join(""));
  }
  return parts.join("");
}
