import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Trace, TraceQuery, TraceStore } from "@firewall/contract";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS traces (
  id TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  language TEXT NOT NULL,
  agent TEXT,
  policy TEXT,
  exit_code INTEGER,
  violation_count INTEGER NOT NULL DEFAULT 0,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS traces_started_at ON traces(started_at);
CREATE INDEX IF NOT EXISTS traces_verdict ON traces(verdict);
`;

const UPSERT = `
INSERT INTO traces (id, started_at, ended_at, verdict, language, agent, policy, exit_code, violation_count, json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  started_at = excluded.started_at,
  ended_at = excluded.ended_at,
  verdict = excluded.verdict,
  language = excluded.language,
  agent = excluded.agent,
  policy = excluded.policy,
  exit_code = excluded.exit_code,
  violation_count = excluded.violation_count,
  json = excluded.json
`;

/**
 * SQLite-backed TraceStore using Node's built-in node:sqlite. Indexed columns
 * are denormalised from the trace for querying; the full trace lives in `json`.
 */
export class SqliteTraceStore implements TraceStore {
  private readonly db: DatabaseSync;

  constructor(readonly path: string = ":memory:") {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  async put(trace: Trace): Promise<void> {
    this.db
      .prepare(UPSERT)
      .run(
        trace.id,
        trace.startedAt,
        trace.endedAt,
        trace.verdict,
        trace.request.language,
        trace.request.agent?.name ?? null,
        trace.request.policy?.name ?? null,
        trace.exitCode,
        trace.violations.length,
        JSON.stringify(trace),
      );
  }

  async get(id: string): Promise<Trace | null> {
    const row = this.db.prepare("SELECT json FROM traces WHERE id = ?").get(id) as { json: string } | undefined;
    return row ? (JSON.parse(row.json) as Trace) : null;
  }

  async list(query: TraceQuery = {}): Promise<Trace[]> {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (query.verdict) {
      where.push("verdict = ?");
      params.push(query.verdict);
    }
    if (query.agent) {
      where.push("agent = ?");
      params.push(query.agent);
    }
    if (query.since) {
      where.push("started_at > ?");
      params.push(query.since);
    }
    const limit = Math.max(1, Math.floor(query.limit ?? 50));
    const sql =
      "SELECT json FROM traces" +
      (where.length ? " WHERE " + where.join(" AND ") : "") +
      " ORDER BY started_at DESC, id DESC LIMIT ?";
    params.push(limit);
    const rows = this.db.prepare(sql).all(...params) as { json: string }[];
    return rows.map((r) => JSON.parse(r.json) as Trace);
  }

  /** Number of stored traces (not part of TraceStore; handy for stats). */
  count(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM traces").get() as { n: number };
    return Number(row.n);
  }

  async close(): Promise<void> {
    this.db.close();
  }
}
