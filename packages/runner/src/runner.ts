import { Wasmer, type Sandbox } from "@wasmer/sdk/node";
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
import { discoverBridgeIds, ensureNetworkPatched, registerBridge } from "./network.js";

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
    const lease = await this.acquire();
    const unregister = lease.bridgeIds.map((id) =>
      registerBridge(id, {
        allowHost: (host) => hostAllowed(req.policy, host),
        onEvent: (e) => network.push(e),
      }),
    );

    let sandbox: Sandbox | undefined;
    let sandboxCreateMs = 0;
    let execMs = 0;
    let stdout = "";
    let stderr = "";
    let exitCode: number | null = null;
    let exitReason: Trace["exitReason"] = "error";
    let outputTruncated = false;
    let fsChanges: FsChange[] = [];
    try {
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
      const out = await sandbox.command(entry.command, args, { cwd: "/workspace" }).run({
        check: false,
        timeoutMs: req.policy.limits.wallMs,
        outputBytes: req.policy.limits.maxOutputBytes,
        stdin: req.stdin,
      });
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
      const canaryWhere: [string, string, { minChunk?: number }][] = [
        ["stdout", stdout, {}],
        ["stderr", stderr, {}],
        ["network", network.map((e) => e.host).join("\n"), { minChunk: 12 }],
      ];
      for (const change of fsChanges) {
        if (change.op === "delete" || (change.bytes ?? 0) > 1024 * 1024) continue;
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
      for (const u of unregister) u();
      if (sandbox) await sandbox.close().catch(() => {});
      this.release(lease);
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
      const wasmer = new Wasmer({
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
