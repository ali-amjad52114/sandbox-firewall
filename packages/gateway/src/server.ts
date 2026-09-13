import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { newId, type Language, type Policy, type Runner, type RunRequest, type Trace, type TraceStore } from "@firewall/contract";
import { isPresetName, parsePolicy, PolicyError, preset, PRESETS } from "@firewall/policy";

export interface GatewayOptions {
  runner: Runner;
  store: TraceStore;
  defaultPolicy?: Policy;
  /** Tag written on every trace so the console can tell sessions apart. */
  sessionId?: string;
}

type ToolResult = {
  content: { type: "text"; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

const text = (t: string, isError = false): ToolResult => ({ content: [{ type: "text", text: t }], isError });

export function createServer(opts: GatewayOptions): McpServer {
  const { runner, store } = opts;
  const defaultPolicy = opts.defaultPolicy ?? preset("strict");
  const server = new McpServer({ name: "sandbox-firewall", version: "0.1.0" });

  const resolvePolicy = (p?: string): Policy => {
    if (!p) return structuredClone(defaultPolicy);
    const trimmed = p.trim();
    if (isPresetName(trimmed)) return preset(trimmed);
    return parsePolicy(trimmed);
  };

  const execute = async (req: Omit<RunRequest, "id" | "createdAt" | "agent"> & { tool: string }): Promise<ToolResult> => {
    const request: RunRequest = {
      id: newId(),
      language: req.language,
      code: req.code,
      args: req.args,
      stdin: req.stdin,
      files: req.files,
      policy: req.policy,
      agent: { name: "mcp", tool: req.tool, sessionId: opts.sessionId },
      createdAt: Date.now(),
    };
    const trace = await runner.run(request);
    await store.put(trace);
    return {
      content: [{ type: "text", text: formatReport(trace) }],
      structuredContent: {
        traceId: trace.id,
        verdict: trace.verdict,
        exitCode: trace.exitCode,
        exitReason: trace.exitReason,
        violations: trace.violations,
      },
      isError: trace.verdict === "blocked",
    };
  };

  const guarded = <A>(fn: (args: A) => Promise<ToolResult>) => async (args: A): Promise<ToolResult> => {
    try {
      return await fn(args);
    } catch (err) {
      if (err instanceof PolicyError) return text(`invalid policy: ${err.message}`, true);
      const e = err as Error;
      return text(`firewall error: ${e.message}`, true);
    }
  };

  const policyParam = z
    .string()
    .optional()
    .describe('Policy: a preset name ("strict" default, "research", "permissive") or a YAML/JSON policy document.');

  server.registerTool(
    "run_code",
    {
      title: "Run code in a sandbox",
      description:
        "Execute a program inside a fresh Wasmer WebAssembly sandbox under a policy. " +
        "Network is intercepted per host, filesystem writes are diffed, canary secrets are watched, and wall-clock/output limits apply. " +
        "A BLOCKED result means the code violated policy; do not retry it unchanged.",
      inputSchema: {
        language: z.enum(["python", "node", "php"]),
        code: z.string().describe("Program source. Written to /workspace/main.<ext> and executed with cwd /workspace."),
        args: z.array(z.string()).optional().describe("Extra argv. If code is empty, the interpreter is run with these args directly."),
        stdin: z.string().optional(),
        files: z.record(z.string(), z.string()).optional().describe("Extra files placed under /workspace before the run."),
        policy: policyParam,
      },
    },
    guarded(async (a) =>
      execute({ language: a.language as Language, code: a.code, args: a.args, stdin: a.stdin, files: a.files, policy: resolvePolicy(a.policy), tool: "run_code" }),
    ),
  );

  server.registerTool(
    "run_shell",
    {
      title: "Run a simple shell command",
      description:
        "Runs a minimal shell command inside the sandbox. This build has no bash guest, so only echo, cat <file>, ls [dir] and pwd are supported; " +
        "they are translated to Python and run through the same firewall. Use run_code for anything else.",
      inputSchema: { command: z.string(), policy: policyParam },
    },
    guarded(async (a) => {
      const py = translateShell(a.command);
      if (!py) return text("run_shell supports only echo, cat, ls, pwd in this build; use run_code with language python/node/php.", true);
      return execute({ language: "python", code: py, policy: resolvePolicy(a.policy), tool: "run_shell" });
    }),
  );

  server.registerTool(
    "install_package",
    {
      title: "Install a package inside the sandbox",
      description:
        "Installs a Python package with pip inside a sandbox run. Requires an allowlist policy that permits pypi.org and files.pythonhosted.org (the research preset does). " +
        "Node package installation is not supported in this build.",
      inputSchema: { name: z.string(), language: z.enum(["python", "node"]), policy: policyParam },
    },
    guarded(async (a) => {
      if (a.language === "node") return text("npm install inside the Node guest is not supported in this build.", true);
      return execute({ language: "python", code: "", args: ["-m", "pip", "install", a.name], policy: resolvePolicy(a.policy ?? "research"), tool: "install_package" });
    }),
  );

  server.registerTool(
    "get_trace",
    { title: "Get a trace", description: "Full trace JSON for a previous run.", inputSchema: { id: z.string() } },
    guarded(async (a) => {
      const t = await store.get(a.id);
      if (!t) return text(`trace not found: ${a.id}`, true);
      return text(JSON.stringify(t, null, 2));
    }),
  );

  server.registerTool(
    "list_traces",
    {
      title: "List traces",
      description: "Recent runs, newest first.",
      inputSchema: { verdict: z.enum(["clean", "suspicious", "blocked"]).optional(), limit: z.number().int().positive().max(200).optional() },
    },
    guarded(async (a) => {
      const rows = await store.list({ verdict: a.verdict, limit: a.limit ?? 20 });
      if (!rows.length) return text("(no traces)");
      return text(
        rows
          .map(
            (t) =>
              `${t.id} ${t.verdict} ${t.request.language} ${t.request.agent?.tool ?? "-"} ${new Date(t.startedAt).toISOString()} exit=${t.exitCode ?? "-"} violations=${t.violations.length}`,
          )
          .join("\n"),
      );
    }),
  );

  server.registerTool(
    "list_policies",
    { title: "List policy presets", description: "Names and one-line summaries of the built-in policy presets.", inputSchema: {} },
    guarded(async () =>
      text(
        Object.values(PRESETS)
          .map(
            (p) =>
              `${p.name}: network ${p.network.mode}${p.network.mode === "allowlist" ? ` allow=${(p.network.allow ?? []).join(",")}` : ""}, writable=${(p.fs.writable ?? []).join(",") || "(none)"}, wallMs=${p.limits.wallMs}, maxOutputBytes=${p.limits.maxOutputBytes}`,
          )
          .join("\n"),
      ),
    ),
  );

  return server;
}

/** Human-readable report for the calling agent. */
export function formatReport(t: Trace): string {
  const lines: string[] = [];
  if (t.verdict === "blocked") {
    const first = t.violations.find((v) => v.severity === "critical") ?? t.violations[0];
    lines.push(`BLOCKED by policy ${t.request.policy.name}: ${first?.detail ?? "policy violation"}`);
    lines.push("Do not retry this action; it violates the sandbox policy. Tell the user what was attempted.");
  } else {
    lines.push(`${t.verdict} | exit ${t.exitCode ?? "-"} (${t.exitReason}) | sandbox ${t.timings.sandboxCreateMs} ms, exec ${t.timings.execMs} ms | trace ${t.id}`);
  }
  lines.push("--- stdout ---", clip(t.stdout, 4000));
  lines.push("--- stderr ---", clip(t.stderr, 2000));
  lines.push("--- violations ---", t.violations.length ? t.violations.map((v) => `[${v.severity}] ${v.kind}: ${v.detail}`).join("\n") : "(none)");
  lines.push("--- network ---", t.network.length ? t.network.map((e) => `${e.kind} ${e.host}${e.port ? ":" + e.port : ""} ${e.allowed ? "allowed" : "BLOCKED"}`).join("\n") : "(none)");
  lines.push("--- fs ---", t.fs.length ? t.fs.map((c) => `${c.op} ${c.path}${c.bytes !== undefined ? ` (${c.bytes} bytes)` : ""} ${c.allowed ? "ok" : "OUTSIDE"}`).join("\n") : "(none)");
  if (t.verdict === "blocked") lines.push(`trace ${t.id}`);
  return lines.join("\n");
}

function clip(s: string, max: number): string {
  if (!s) return "(empty)";
  return s.length > max ? `${s.slice(0, max)}\n...[truncated ${s.length - max} chars]` : s;
}

/** Translate the handful of shell commands we support into Python. */
export function translateShell(command: string): string | null {
  const tokens = tokenize(command.trim());
  if (!tokens.length) return null;
  const [cmd, ...rest] = tokens;
  const q = (s: string) => JSON.stringify(s);
  switch (cmd) {
    case "echo":
      return `print(${q(rest.join(" "))})`;
    case "pwd":
      return "print('/workspace')";
    case "ls": {
      const dir = rest.find((t) => !t.startsWith("-")) ?? ".";
      return `import os\nfor n in sorted(os.listdir(${q(dir)})):\n    print(n)`;
    }
    case "cat":
      if (!rest.length) return null;
      return rest.map((f) => `print(open(${q(f)}).read(), end='')`).join("\n");
    default:
      return null;
  }
}

function tokenize(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}
