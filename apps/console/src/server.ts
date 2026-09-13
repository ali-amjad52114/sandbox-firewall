import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  newId,
  type Language,
  type Policy,
  type Runner,
  type RunRequest,
  type Trace,
  type TraceQuery,
  type TraceStore,
  type Verdict,
} from "@firewall/contract";
import { fromObject, isPresetName, preset, PolicyError } from "@firewall/policy";

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = join(HERE, "index.html");
const LANGUAGES: Language[] = ["python", "node", "php"];
const VERDICTS: Verdict[] = ["clean", "suspicious", "blocked"];
const MAX_BODY_BYTES = 1024 * 1024;
/** TraceStore has no "all" or "count" method; this is the practical ceiling for stats. */
const STATS_SCAN_LIMIT = 1_000_000;

export interface ConsoleOptions {
  store: TraceStore;
  runner?: Runner;
  port: number;
  host?: string;
}

export interface ConsoleServer {
  server: Server;
  port: number;
  url: string;
  close(): Promise<void>;
}

export interface TraceSummary {
  id: string;
  verdict: Verdict;
  language: Language;
  agent: string | null;
  tool: string | null;
  policy: string;
  startedAt: number;
  endedAt: number;
  exitCode: number | null;
  exitReason: Trace["exitReason"];
  violationCount: number;
  firstViolation: { kind: string; severity: string; detail: string } | null;
  timings: Trace["timings"];
}

export interface Stats {
  total: number;
  byVerdict: Record<Verdict, number>;
  last24h: number;
  avgExecMs: number;
  avgSandboxCreateMs: number;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function summarize(t: Trace): TraceSummary {
  const first = t.violations[0];
  return {
    id: t.id,
    verdict: t.verdict,
    language: t.request.language,
    agent: t.request.agent?.name ?? null,
    tool: t.request.agent?.tool ?? null,
    policy: t.request.policy?.name ?? "",
    startedAt: t.startedAt,
    endedAt: t.endedAt,
    exitCode: t.exitCode,
    exitReason: t.exitReason,
    violationCount: t.violations.length,
    firstViolation: first ? { kind: first.kind, severity: first.severity, detail: first.detail } : null,
    timings: t.timings,
  };
}

export function computeStats(traces: Trace[], now = Date.now()): Stats {
  const byVerdict: Record<Verdict, number> = { clean: 0, suspicious: 0, blocked: 0 };
  let exec = 0;
  let create = 0;
  let last24h = 0;
  const dayAgo = now - 24 * 60 * 60 * 1000;
  for (const t of traces) {
    byVerdict[t.verdict] = (byVerdict[t.verdict] ?? 0) + 1;
    exec += t.timings?.execMs ?? 0;
    create += t.timings?.sandboxCreateMs ?? 0;
    if (t.startedAt >= dayAgo) last24h++;
  }
  const n = traces.length;
  const round = (x: number) => Math.round(x * 100) / 100;
  return {
    total: n,
    byVerdict,
    last24h,
    avgExecMs: n ? round(exec / n) : 0,
    avgSandboxCreateMs: n ? round(create / n) : 0,
  };
}

function parseQuery(url: URL): TraceQuery {
  const q: TraceQuery = {};
  const verdict = url.searchParams.get("verdict");
  if (verdict) {
    if (!VERDICTS.includes(verdict as Verdict)) throw new HttpError(400, `verdict must be one of ${VERDICTS.join(", ")}`);
    q.verdict = verdict as Verdict;
  }
  const agent = url.searchParams.get("agent");
  if (agent) q.agent = agent;
  const limit = url.searchParams.get("limit");
  if (limit) {
    const n = Number(limit);
    if (!Number.isInteger(n) || n <= 0 || n > 1000) throw new HttpError(400, "limit must be an integer in 1..1000");
    q.limit = n;
  }
  const since = url.searchParams.get("since");
  if (since) {
    const n = Number(since);
    if (!Number.isFinite(n)) throw new HttpError(400, "since must be epoch ms");
    q.since = n;
  }
  return q;
}

function resolvePolicy(raw: unknown): Policy {
  if (typeof raw === "string") return isPresetName(raw) ? preset(raw) : preset("strict");
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    try {
      return fromObject(raw as Record<string, unknown>);
    } catch (err) {
      if (err instanceof PolicyError) throw new HttpError(400, `invalid policy: ${err.message}`);
      throw err;
    }
  }
  return preset("strict");
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "body too large");
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "body is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(400, "body must be a JSON object");
  return parsed as Record<string, unknown>;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
  });
  res.end(text);
}

export async function createConsoleServer(opts: ConsoleOptions): Promise<ConsoleServer> {
  const { store, runner } = opts;
  const host = opts.host ?? "127.0.0.1";

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const method = req.method ?? "GET";
    const path = url.pathname;

    if (method === "GET" && (path === "/" || path === "/index.html")) {
      // Read at request time so edits to index.html show without a restart.
      const html = await readFile(INDEX_HTML);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(html);
      return;
    }

    if (method === "GET" && path === "/api/traces") {
      const traces = await store.list(parseQuery(url));
      sendJson(res, 200, traces.map(summarize));
      return;
    }

    if (method === "GET" && path.startsWith("/api/traces/")) {
      const id = decodeURIComponent(path.slice("/api/traces/".length));
      const trace = id ? await store.get(id) : null;
      if (!trace) throw new HttpError(404, `no trace with id ${id}`);
      sendJson(res, 200, trace);
      return;
    }

    if (method === "GET" && path === "/api/stats") {
      const traces = await store.list({ limit: STATS_SCAN_LIMIT });
      sendJson(res, 200, computeStats(traces));
      return;
    }

    if (method === "POST" && path === "/api/run") {
      if (!runner) {
        throw new HttpError(501, "This console has no runner attached. Start it with a runner to execute code.");
      }
      const body = await readJsonBody(req);
      const language = body.language;
      if (typeof language !== "string" || !LANGUAGES.includes(language as Language)) {
        throw new HttpError(400, `language must be one of ${LANGUAGES.join(", ")}`);
      }
      if (typeof body.code !== "string" || !body.code.trim()) throw new HttpError(400, "code must be a non-empty string");
      const agentRaw = body.agent;
      const agent =
        agentRaw && typeof agentRaw === "object" && typeof (agentRaw as { name?: unknown }).name === "string"
          ? (agentRaw as RunRequest["agent"])
          : { name: "console", tool: "run_form" };
      const request: RunRequest = {
        id: newId(),
        language: language as Language,
        code: body.code,
        policy: resolvePolicy(body.policy),
        agent,
        createdAt: Date.now(),
      };
      if (typeof body.stdin === "string") request.stdin = body.stdin;
      if (Array.isArray(body.args) && body.args.every((a) => typeof a === "string")) request.args = body.args as string[];
      const trace = await runner.run(request);
      await store.put(trace);
      sendJson(res, 200, trace);
      return;
    }

    if (path.startsWith("/api/")) throw new HttpError(404, `no route ${method} ${path}`);
    throw new HttpError(404, "not found");
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof Error ? err.message : String(err);
      if (status >= 500 && status !== 501) console.error(`[console] ${req.method} ${req.url} -> ${status}: ${message}`);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      sendJson(res, status, { error: message, status });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  const displayHost = host === "0.0.0.0" || host === "::" ? "localhost" : host;
  return {
    server,
    port,
    url: `http://${displayHost}:${port}/`,
    async close() {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

/**
 * CLI entry: `tsx apps/console/src/server.ts`
 *   CONSOLE_PORT   default 4317
 *   CONSOLE_HOST   default 127.0.0.1
 *   CONSOLE_STORE  "sqlite" (default, path from CONSOLE_DB, default data/traces.db) or "memory" (seeded with sampleTraces())
 *   CONSOLE_SEED=1 seed sampleTraces() into whichever store
 *   CONSOLE_RUNNER "mock" attaches MockRunner so POST /api/run works; unset means 501
 */
async function main(): Promise<void> {
  const { createStore } = await import("@firewall/store");
  const { sampleTraces, MockRunner } = await import("@firewall/contract/mock");
  const port = Number(process.env.CONSOLE_PORT ?? 4317);
  const kind = process.env.CONSOLE_STORE === "memory" ? "memory" : "sqlite";
  const storePath = process.env.CONSOLE_DB ?? "data/traces.db";
  const store = createStore(kind, { path: storePath });
  const seed = kind === "memory" || process.env.CONSOLE_SEED === "1";
  if (seed) for (const t of sampleTraces()) await store.put(t);

  const runner: Runner | undefined = process.env.CONSOLE_RUNNER === "mock" ? new MockRunner() : undefined;

  const app = await createConsoleServer({ store, runner, port, host: process.env.CONSOLE_HOST });
  console.error(
    `[console] listening on ${app.url} (store=${kind}${kind === "sqlite" ? ":" + storePath : ""}` +
      `${seed ? ", seeded" : ""}, runner=${runner ? "mock" : "none"})`,
  );
  const shutdown = async () => {
    await app.close();
    await runner?.close?.();
    await store.close?.();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

const isMain = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return pathToFileURL(entry).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
