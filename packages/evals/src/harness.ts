import { newId, type Runner, type RunRequest, type Trace, type Verdict } from "@firewall/contract";
import type { Scenario } from "./corpus.js";

export interface EvalResult {
  name: string;
  pass: boolean;
  verdict: Verdict | null;
  expectedVerdict: Verdict;
  /** mustContain kinds that were expected but not present in the trace. */
  missing: string[];
  /** mustNotContain kinds that were present in the trace. */
  unexpected: string[];
  exitReason: Trace["exitReason"] | null;
  ms: number;
  trace: Trace | null;
  /** First failing check, in words. Empty when the scenario passed. */
  reason: string;
  skipped?: boolean;
}

export interface RunEvalsOptions {
  offline?: boolean;
  concurrency?: number;
}

function toRequest(s: Scenario): RunRequest {
  return {
    id: newId("eval"),
    language: s.language,
    code: s.code,
    files: Object.keys(s.files).length ? s.files : undefined,
    policy: s.policy,
    agent: { name: "evals", tool: "corpus" },
    createdAt: Date.now(),
  };
}

/** Evaluate a single scenario against a produced trace. */
function evaluate(s: Scenario, trace: Trace, ms: number): EvalResult {
  const kinds = new Set(trace.violations.map((v) => v.kind));
  const missing = s.expected.mustContain.filter((k) => !kinds.has(k as never));
  const unexpected = s.expected.mustNotContain.filter((k) => kinds.has(k as never));

  const checks: Array<[boolean, string]> = [];
  checks.push([
    trace.verdict === s.expected.verdict,
    `verdict ${trace.verdict} did not match expected ${s.expected.verdict}`,
  ]);
  checks.push([missing.length === 0, `missing required violations: ${missing.join(", ")}`]);
  checks.push([unexpected.length === 0, `unexpected violations present: ${unexpected.join(", ")}`]);
  if (s.expected.exitReason !== undefined) {
    checks.push([
      trace.exitReason === s.expected.exitReason,
      `exitReason ${trace.exitReason} did not match expected ${s.expected.exitReason}`,
    ]);
  }
  // The MockRunner fabricates stdout ("mock output" / "env: <canary>") and
  // cannot reproduce a scenario's real stdout, so stdout-content assertions only
  // apply to a real runner.
  if (trace.runner.name !== "mock") {
    for (const needle of s.expected.stdoutIncludes ?? []) {
      checks.push([trace.stdout.includes(needle), `stdout did not include "${needle}"`]);
    }
  }

  const failed = checks.find(([ok]) => !ok);
  return {
    name: s.name,
    pass: !failed,
    verdict: trace.verdict,
    expectedVerdict: s.expected.verdict,
    missing,
    unexpected,
    exitReason: trace.exitReason,
    ms,
    trace,
    reason: failed ? failed[1] : "",
  };
}

/** Run every scenario through the runner with bounded concurrency. */
export async function runEvals(
  runner: Runner,
  scenarios: Scenario[],
  opts: RunEvalsOptions = {},
): Promise<EvalResult[]> {
  const offline = opts.offline ?? false;
  const concurrency = Math.max(1, opts.concurrency ?? 2);
  const results: EvalResult[] = new Array(scenarios.length);

  let next = 0;
  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= scenarios.length) return;
      const s = scenarios[i];
      if (offline && s.expected.requiresNetwork) {
        results[i] = {
          name: s.name,
          pass: true,
          verdict: null,
          expectedVerdict: s.expected.verdict,
          missing: [],
          unexpected: [],
          exitReason: null,
          ms: 0,
          trace: null,
          reason: "skipped: offline",
          skipped: true,
        };
        continue;
      }
      const started = Date.now();
      try {
        const trace = await runner.run(toRequest(s));
        results[i] = evaluate(s, trace, Date.now() - started);
      } catch (e) {
        results[i] = {
          name: s.name,
          pass: false,
          verdict: null,
          expectedVerdict: s.expected.verdict,
          missing: [],
          unexpected: [],
          exitReason: null,
          ms: Date.now() - started,
          trace: null,
          reason: `runner threw: ${e instanceof Error ? e.message : String(e)}`,
        };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, scenarios.length || 1) }, () => worker());
  await Promise.all(workers);
  return results;
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

/** ASCII summary table: name | expected | got | result | ms | reason. */
export function formatTable(results: EvalResult[]): string {
  const header = ["name", "expected", "got", "result", "ms", "reason"];
  const rows = results.map((r) => [
    r.name,
    r.expectedVerdict,
    r.skipped ? "-" : String(r.verdict ?? "-"),
    r.skipped ? "SKIP" : r.pass ? "PASS" : "FAIL",
    r.skipped ? "-" : String(r.ms),
    r.reason,
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i].length)));
  const line = (cols: string[]) => cols.map((c, i) => pad(c, widths[i])).join(" | ");
  const sep = widths.map((w) => "-".repeat(w)).join("-+-");

  const passed = results.filter((r) => r.pass && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const total = results.filter((r) => !r.skipped).length;

  return [
    line(header),
    sep,
    ...rows.map(line),
    "",
    `${passed}/${total} passed (${skipped} skipped)`,
  ].join("\n");
}

/** Markdown table variant, for writing to a file. */
export function toMarkdown(results: EvalResult[]): string {
  const header = ["name", "expected", "got", "result", "ms", "reason"];
  const rows = results.map((r) => [
    r.name,
    r.expectedVerdict,
    r.skipped ? "-" : String(r.verdict ?? "-"),
    r.skipped ? "SKIP" : r.pass ? "PASS" : "FAIL",
    r.skipped ? "-" : String(r.ms),
    (r.reason || "").replace(/\|/g, "\\|"),
  ]);
  const passed = results.filter((r) => r.pass && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const total = results.filter((r) => !r.skipped).length;

  return [
    "| " + header.join(" | ") + " |",
    "| " + header.map(() => "---").join(" | ") + " |",
    ...rows.map((row) => "| " + row.join(" | ") + " |"),
    "",
    `**${passed}/${total} passed (${skipped} skipped)**`,
  ].join("\n");
}
