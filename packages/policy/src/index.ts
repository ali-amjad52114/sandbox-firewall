import { parse as parseYaml } from "yaml";
import type { Policy } from "@firewall/contract";

/**
 * Policy presets. Canary values are deliberately fake and unmistakable so a
 * leak is visible at a glance in a trace.
 */
const CANARIES = {
  AWS_SECRET_ACCESS_KEY: "AKIAFAKE0000CANARY42/firewall",
  OPENAI_API_KEY: "sk-canary-0000000000000000firewall",
  DATABASE_URL: "postgres://canary:canary-pw-firewall@db.internal:5432/prod",
};

export const PRESETS: Record<"strict" | "research" | "permissive", Policy> = {
  strict: {
    name: "strict",
    network: { mode: "off" },
    fs: { writable: ["out/"] },
    limits: { wallMs: 10_000, maxOutputBytes: 64 * 1024, memoryMb: 256 },
    canaries: CANARIES,
  },
  research: {
    name: "research",
    network: { mode: "allowlist", allow: ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "example.com"] },
    fs: { writable: ["out/", "tmp/"] },
    limits: { wallMs: 60_000, maxOutputBytes: 512 * 1024, memoryMb: 1024 },
    canaries: CANARIES,
  },
  permissive: {
    name: "permissive",
    network: { mode: "allowlist", allow: ["*"] },
    fs: { writable: ["/"] },
    limits: { wallMs: 120_000, maxOutputBytes: 4 * 1024 * 1024 },
    canaries: CANARIES,
  },
};

export type PresetName = keyof typeof PRESETS;

export function isPresetName(name: string): name is PresetName {
  return name in PRESETS;
}

/** Deep-clone a preset so callers can mutate safely. */
export function preset(name: PresetName): Policy {
  return structuredClone(PRESETS[name]);
}

export class PolicyError extends Error {}

/**
 * Parse a YAML (or JSON) policy document. Unknown keys are rejected so typos
 * cannot silently weaken a policy. `extends: <preset>` fills in defaults.
 *
 * Example:
 *   name: data-science
 *   extends: research
 *   network:
 *     mode: allowlist
 *     allow: [pypi.org]
 *   fs:
 *     writable: [out/]
 *   limits:
 *     wallMs: 30000
 */
export function parsePolicy(text: string): Policy {
  const raw = parseYaml(text) as unknown;
  if (!raw || typeof raw !== "object") throw new PolicyError("policy must be a mapping");
  return fromObject(raw as Record<string, unknown>);
}

export function fromObject(raw: Record<string, unknown>): Policy {
  const allowedKeys = new Set(["name", "extends", "network", "fs", "limits", "canaries", "packages", "env"]);
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.has(key)) throw new PolicyError(`unknown policy key: ${key}`);
  }
  const base: Policy = typeof raw.extends === "string" && isPresetName(raw.extends) ? preset(raw.extends) : preset("strict");
  if (raw.extends !== undefined && !(typeof raw.extends === "string" && isPresetName(raw.extends))) {
    throw new PolicyError(`unknown preset in extends: ${String(raw.extends)}`);
  }
  const out: Policy = { ...base };
  if (typeof raw.name === "string") out.name = raw.name;

  if (raw.network !== undefined) {
    const n = expectObject(raw.network, "network", ["mode", "allow"]);
    const mode = n.mode ?? base.network.mode;
    if (mode !== "off" && mode !== "allowlist") throw new PolicyError(`network.mode must be off or allowlist`);
    const allow = n.allow === undefined ? base.network.allow : expectStringArray(n.allow, "network.allow");
    out.network = mode === "off" ? { mode } : { mode, allow: (allow ?? []).map((h) => h.toLowerCase()) };
  }
  if (raw.fs !== undefined) {
    const f = expectObject(raw.fs, "fs", ["writable"]);
    out.fs = { writable: f.writable === undefined ? base.fs.writable : expectStringArray(f.writable, "fs.writable") };
  }
  if (raw.limits !== undefined) {
    const l = expectObject(raw.limits, "limits", ["wallMs", "maxOutputBytes", "memoryMb"]);
    out.limits = {
      wallMs: expectPositiveInt(l.wallMs ?? base.limits.wallMs, "limits.wallMs"),
      maxOutputBytes: expectPositiveInt(l.maxOutputBytes ?? base.limits.maxOutputBytes, "limits.maxOutputBytes"),
      memoryMb: l.memoryMb === undefined ? base.limits.memoryMb : expectPositiveInt(l.memoryMb, "limits.memoryMb"),
    };
  }
  if (raw.canaries !== undefined) out.canaries = expectStringMap(raw.canaries, "canaries");
  if (raw.packages !== undefined) out.packages = expectStringArray(raw.packages, "packages");
  if (raw.env !== undefined) out.env = expectStringMap(raw.env, "env");
  validate(out);
  return out;
}

/** Throws if the policy is internally inconsistent. */
export function validate(p: Policy): void {
  if (!p.name) throw new PolicyError("policy.name is required");
  if (p.network.mode === "allowlist" && !(p.network.allow ?? []).length)
    throw new PolicyError("network.mode allowlist requires at least one host (use '*' for any)");
  if (p.limits.wallMs > 10 * 60_000) throw new PolicyError("limits.wallMs above 10 minutes is not allowed");
  for (const [k, v] of Object.entries(p.canaries)) {
    if (v.length < 8) throw new PolicyError(`canary ${k} is too short to be detectable (min 8 chars)`);
  }
}

/** True when the policy permits resolving/connecting to this host. */
export function hostAllowed(p: Policy, host: string): boolean {
  if (p.network.mode !== "allowlist") return false;
  const h = host.toLowerCase();
  return (p.network.allow ?? []).some((rule) => {
    const r = rule.toLowerCase();
    if (r === "*") return true;
    if (r.startsWith("*.")) return h === r.slice(2) || h.endsWith(r.slice(1));
    return h === r;
  });
}

/** True when the policy permits writing to this absolute guest path. */
export function pathWritable(p: Policy, absPath: string): boolean {
  const norm = absPath.startsWith("/") ? absPath : `/workspace/${absPath}`;
  return (p.fs.writable ?? []).some((rule) => {
    const r = rule === "/" ? "/" : rule.startsWith("/") ? rule : `/workspace/${rule}`;
    if (r === "/") return true;
    if (r.endsWith("/")) return norm.startsWith(r);
    return norm === r;
  });
}

function expectObject(v: unknown, name: string, keys: string[]): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new PolicyError(`${name} must be a mapping`);
  for (const k of Object.keys(v)) if (!keys.includes(k)) throw new PolicyError(`unknown key ${name}.${k}`);
  return v as Record<string, unknown>;
}
function expectStringArray(v: unknown, name: string): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw new PolicyError(`${name} must be a list of strings`);
  return v;
}
function expectStringMap(v: unknown, name: string): Record<string, string> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new PolicyError(`${name} must be a mapping`);
  for (const [k, x] of Object.entries(v)) if (typeof x !== "string") throw new PolicyError(`${name}.${k} must be a string`);
  return v as Record<string, string>;
}
function expectPositiveInt(v: unknown, name: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new PolicyError(`${name} must be a positive integer`);
  return v;
}
