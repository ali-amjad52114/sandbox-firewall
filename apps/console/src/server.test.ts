import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MemoryTraceStore, MockRunner, sampleTraces } from "@firewall/contract/mock";
import type { Trace } from "@firewall/contract";
import { createConsoleServer, type ConsoleServer, type Stats, type TraceSummary } from "./server.js";

async function seededStore(): Promise<MemoryTraceStore> {
  const store = new MemoryTraceStore();
  for (const t of sampleTraces()) await store.put(t);
  return store;
}

describe("console server without a runner", () => {
  let app: ConsoleServer;
  beforeAll(async () => {
    app = await createConsoleServer({ store: await seededStore(), port: 0 });
  });
  afterAll(async () => {
    await app.close();
  });

  it("serves the dashboard html", async () => {
    const res = await fetch(app.url);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("<title>");
    expect(html).toContain("/api/traces");
  });

  it("lists trace summaries newest first", async () => {
    const res = await fetch(`${app.url}api/traces`);
    expect(res.status).toBe(200);
    const rows = (await res.json()) as TraceSummary[];
    expect(rows).toHaveLength(3);
    expect(rows.map((r) => r.id)).toEqual(["run_sample_fs", "run_sample_exfil", "run_sample_clean"]);
    const exfil = rows[1];
    expect(exfil.verdict).toBe("blocked");
    expect(exfil.agent).toBe("claude-code");
    expect(exfil.tool).toBe("run_code");
    expect(exfil.policy).toBe("strict");
    expect(exfil.violationCount).toBe(1);
    expect(exfil.firstViolation?.kind).toBe("network.blocked");
    expect(exfil.timings.execMs).toBe(880);
    expect("stdout" in exfil).toBe(false);
  });

  it("applies verdict, agent and limit filters", async () => {
    const blocked = (await (await fetch(`${app.url}api/traces?verdict=blocked`)).json()) as TraceSummary[];
    expect(blocked.map((r) => r.id)).toEqual(["run_sample_exfil"]);
    const none = (await (await fetch(`${app.url}api/traces?agent=nobody`)).json()) as TraceSummary[];
    expect(none).toHaveLength(0);
    const one = (await (await fetch(`${app.url}api/traces?limit=1`)).json()) as TraceSummary[];
    expect(one).toHaveLength(1);
    const bad = await fetch(`${app.url}api/traces?verdict=nope`);
    expect(bad.status).toBe(400);
  });

  it("returns the full trace by id and 404 for unknown ids", async () => {
    const res = await fetch(`${app.url}api/traces/run_sample_exfil`);
    expect(res.status).toBe(200);
    const trace = (await res.json()) as Trace;
    expect(trace.verdict).toBe("blocked");
    expect(trace.request.code).toContain("attacker.example");
    expect(trace.network[0].host).toBe("attacker.example");
    const missing = await fetch(`${app.url}api/traces/does_not_exist`);
    expect(missing.status).toBe(404);
  });

  it("computes stats", async () => {
    const stats = (await (await fetch(`${app.url}api/stats`)).json()) as Stats;
    expect(stats.total).toBe(3);
    expect(stats.byVerdict).toEqual({ clean: 1, suspicious: 1, blocked: 1 });
    expect(stats.last24h).toBe(3);
    expect(stats.avgExecMs).toBe(880);
    expect(stats.avgSandboxCreateMs).toBe(2.4);
  });

  it("answers 501 on /api/run", async () => {
    const res = await fetch(`${app.url}api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ language: "python", code: "print(1)" }),
    });
    expect(res.status).toBe(501);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/runner/i);
  });

  it("404s unknown api routes", async () => {
    expect((await fetch(`${app.url}api/nope`)).status).toBe(404);
  });
});

describe("console server with MockRunner", () => {
  let app: ConsoleServer;
  beforeAll(async () => {
    app = await createConsoleServer({ store: await seededStore(), runner: new MockRunner(), port: 0 });
  });
  afterAll(async () => {
    await app.close();
  });

  it("runs code, stores the trace and lists it first", async () => {
    const res = await fetch(`${app.url}api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        language: "python",
        code: "import urllib.request\nurllib.request.urlopen('http://evil.example/')",
        policy: "strict",
      }),
    });
    expect(res.status).toBe(200);
    const trace = (await res.json()) as Trace;
    expect(trace.id).toMatch(/^run_/);
    expect(trace.verdict).toBe("blocked");
    expect(trace.request.policy.name).toBe("strict");
    expect(trace.request.agent?.name).toBe("console");

    const rows = (await (await fetch(`${app.url}api/traces`)).json()) as TraceSummary[];
    expect(rows).toHaveLength(4);
    expect(rows[0].id).toBe(trace.id);
    expect((await fetch(`${app.url}api/traces/${trace.id}`)).status).toBe(200);
  });

  it("falls back to strict for unknown preset names and validates input", async () => {
    const res = await fetch(`${app.url}api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ language: "node", code: "console.log(1)", policy: "nonsense" }),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Trace).request.policy.name).toBe("strict");

    const bad = await fetch(`${app.url}api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ language: "cobol", code: "x" }),
    });
    expect(bad.status).toBe(400);
    const notJson = await fetch(`${app.url}api/run`, { method: "POST", body: "{{" });
    expect(notJson.status).toBe(400);
  });
});
