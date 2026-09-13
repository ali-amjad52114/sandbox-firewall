/**
 * Shared contract for the sandbox firewall. Every package codes against these
 * types and nothing else. Add fields optionally; never rename or remove.
 */

/** Guest runtimes the runner can execute. */
export type Language = "python" | "node" | "php";

/** Wasmer registry packages used per language, pinned. */
export const LANGUAGE_PACKAGES: Record<Language, string> = {
  python: "python/python@=3.13.18",
  node: "wasmer/edgejs@=0.2.0",
  php: "php/php-32@=8.3.2102",
};

export interface NetworkPolicy {
  /** "off" disables the guest network entirely. "allowlist" enables it but only to listed hosts. */
  mode: "off" | "allowlist";
  /** Hostnames (exact match, case-insensitive) the guest may resolve and connect to. */
  allow?: string[];
}

export interface FsPolicy {
  /** Guest paths, relative to /workspace, the run may create or modify. Empty means nothing. */
  writable?: string[];
}

export interface Limits {
  /** Wall-clock budget for the whole run. Enforced by the SDK timeout. */
  wallMs: number;
  /** Cap on captured stdout+stderr bytes. Enforced by the SDK. */
  maxOutputBytes: number;
  /**
   * Memory budget in MB. NOT enforceable by @wasmer/sdk 0.13 (wasm32 caps the
   * guest at 4 GB). Recorded on the trace so the policy is honest about it.
   */
  memoryMb?: number;
}

export interface Policy {
  name: string;
  network: NetworkPolicy;
  fs: FsPolicy;
  limits: Limits;
  /** Fake secrets injected as env vars. If their value shows up in output or network payload, that's a leak. */
  canaries: Record<string, string>;
  /** Extra registry packages to install beyond the language runtime. */
  packages?: string[];
  /** Extra env passed to the guest. Canaries override these. */
  env?: Record<string, string>;
}

export interface RunRequest {
  id: string;
  language: Language;
  /** Program source. Written to /workspace/main.<ext> and executed. */
  code: string;
  args?: string[];
  stdin?: string;
  /** Extra files placed under /workspace before the run. */
  files?: Record<string, string>;
  policy: Policy;
  agent?: { name: string; sessionId?: string; tool?: string };
  createdAt?: number;
}

export type ViolationKind =
  | "network.blocked"
  | "canary.leaked"
  | "fs.outside_writable"
  | "limit.wall"
  | "limit.output"
  | "runtime.error";

export type Severity = "low" | "medium" | "high" | "critical";

export interface Violation {
  kind: ViolationKind;
  severity: Severity;
  detail: string;
  /** Epoch ms. */
  at: number;
  /** Where it was observed: e.g. "stdout", "network", "fs:/workspace/x". */
  where?: string;
}

export interface NetworkEvent {
  kind: "resolve" | "connect";
  host: string;
  port?: number;
  allowed: boolean;
  at: number;
}

export interface FsChange {
  /** Absolute guest path, e.g. /workspace/out.txt */
  path: string;
  op: "create" | "modify" | "delete";
  bytes?: number;
  allowed: boolean;
}

export type Verdict = "clean" | "suspicious" | "blocked";

export interface Trace {
  id: string;
  request: RunRequest;
  startedAt: number;
  endedAt: number;
  exitCode: number | null;
  exitReason: "exited" | "terminated" | "timeout" | "error";
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  violations: Violation[];
  network: NetworkEvent[];
  fs: FsChange[];
  verdict: Verdict;
  /** Runner-side timings for the demo. */
  timings: { sandboxCreateMs: number; execMs: number; totalMs: number };
  runner: { name: string; version: string };
}

export interface Runner {
  run(req: RunRequest): Promise<Trace>;
  close?(): Promise<void>;
}

export interface TraceQuery {
  verdict?: Verdict;
  agent?: string;
  limit?: number;
  /** Only traces started after this epoch ms. */
  since?: number;
}

export interface TraceStore {
  put(trace: Trace): Promise<void>;
  get(id: string): Promise<Trace | null>;
  list(query?: TraceQuery): Promise<Trace[]>;
  close?(): Promise<void>;
}

/** Verdict derivation shared by runner and mocks so everyone agrees. */
export function deriveVerdict(violations: Violation[]): Verdict {
  if (violations.some((v) => v.severity === "critical" || v.severity === "high")) return "blocked";
  if (violations.length > 0) return "suspicious";
  return "clean";
}

/** Severity table shared by runner and evals. */
export const SEVERITY: Record<ViolationKind, Severity> = {
  "network.blocked": "high",
  "canary.leaked": "critical",
  "fs.outside_writable": "medium",
  "limit.wall": "medium",
  "limit.output": "low",
  "runtime.error": "low",
};

export function newId(prefix = "run"): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now().toString(36)}_${rand}`;
}
