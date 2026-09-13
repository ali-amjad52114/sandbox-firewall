// Run the whole firewall end to end, serially. Wasmer engine warm-ups
// contend, so every step that spins a sandbox runs one at a time.
//
//   node scripts/e2e.mjs
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

const NODE = process.execPath;
const JSPI = ["--experimental-wasm-jspi", "--import", "tsx"];
const results = [];
const logDir = "C:/Users/aliam/AppData/Local/Temp/claude/C--AI-Projects-wasmer/183ad27c-33a2-46f7-87c1-483a0de91bc7/scratchpad/e2e";
mkdirSync(logDir, { recursive: true });

function header(n, title) {
  console.log(`\n${"=".repeat(72)}\n[${n}] ${title}\n${"=".repeat(72)}`);
}
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`  -> ${ok ? "PASS" : "FAIL"} ${name}${detail ? " | " + detail : ""}`);
}
function runSync(name, args, { env = {}, timeout = 300000, tail = 12 } = {}) {
  const r = spawnSync(NODE, args, { env: { ...process.env, ...env }, encoding: "utf8", timeout, maxBuffer: 64 * 1024 * 1024 });
  const out = (r.stdout ?? "") + (r.stderr ?? "");
  writeFileSync(`${logDir}/${name}.log`, out);
  const lines = out.split(/\r?\n/).filter((l) => l && !/^\s+at |napi-callback/.test(l));
  console.log(lines.slice(-tail).join("\n"));
  return { code: r.status, out, lines };
}
async function waitFor(url, ms) {
  const deadline = performance.now() + ms;
  while (performance.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 1. Toolchain
header(1, "Toolchain");
const ver = spawnSync(NODE, ["--version"], { encoding: "utf8" });
record("node runtime", ver.status === 0, ver.stdout.trim());

// 2. Typecheck
header(2, "Typecheck (tsc -p tsconfig.json)");
{
  const r = runSync("typecheck", ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]);
  record("typecheck", r.code === 0, r.code === 0 ? "no type errors" : "type errors");
}

// 3. Full test suite with real sandboxes
header(3, "Full test suite (vitest, FIREWALL_TEST_ONLINE=1)");
{
  const r = runSync("vitest", ["node_modules/vitest/vitest.mjs", "run"], { env: { FIREWALL_TEST_ONLINE: "1" }, timeout: 420000, tail: 8 });
  const m = r.out.match(/Tests\s+(\d+)\s+passed(?:\s*\|\s*(\d+)\s+failed)?/);
  const failed = m && m[2] ? Number(m[2]) : 0;
  record("test suite", r.code === 0 && failed === 0, m ? m[0] : "no summary line");
}

// 4. Corpus through the real runner
header(4, "Attack corpus (evals --runner wasmer)");
{
  const r = runSync("corpus", [...JSPI, "packages/evals/src/cli.ts", "--runner", "wasmer", "--md", "data/last-eval.md"], { timeout: 420000, tail: 14 });
  const m = r.out.match(/(\d+)\/(\d+) passed/);
  const all = m && m[1] === m[2];
  record("corpus", all, m ? m[0] : "no summary");
}

// 5. Gateway over stdio, three languages + exfil block
header(5, "Gateway MCP smoke (stdio, real runner)");
{
  const r = runSync("gateway", ["scripts/smoke-gateway.mjs"], { env: { FIREWALL_STORE: "memory" }, timeout: 300000, tail: 8 });
  const blocked = /exfil isError: true/.test(r.out);
  const langs = /node says 2/.test(r.out) && /php says 42/.test(r.out);
  record("gateway smoke", r.code === 0 && blocked && langs, blocked ? "exfil blocked, 3 languages ran" : "unexpected");
}

// 6. Demo beats: real leak vs firewalled block, against a live collector
header(6, "Demo beats (attacker collector, unsandboxed leak vs firewalled block)");
{
  const attacker = spawn(NODE, ["scripts/attacker-server.mjs"], { env: { ...process.env, ATTACKER_PORT: "9999" } });
  let atk = "";
  attacker.stdout.on("data", (d) => (atk += d));
  attacker.stderr.on("data", (d) => (atk += d));
  await sleep(1200);
  const un = runSync("demo-unsandboxed", ["scripts/demo-unsandboxed.mjs"], { tail: 3 });
  await sleep(500);
  const hitsAfterHost = (atk.match(/RECEIVED POST \/collect/g) || []).length;
  const leaked = /key=AKIAFAKE/.test(atk);
  record("beat 1: host run leaks the key", leaked && hitsAfterHost >= 1, `collector received ${hitsAfterHost} POST(s)`);

  const fw = runSync("demo-firewalled", ["scripts/demo-firewalled.mjs"], { env: { FIREWALL_STORE: "memory" }, timeout: 300000, tail: 6 });
  await sleep(500);
  const hitsAfterFw = (atk.match(/RECEIVED POST \/collect/g) || []).length;
  const blocked = /isError=true/.test(fw.out) && /BLOCKED/.test(fw.out);
  record("beat 3: firewalled run is blocked", blocked && hitsAfterFw === hitsAfterHost, `collector still at ${hitsAfterFw} POST(s)`);
  attacker.kill("SIGKILL");
}

// 7. Console API with the real runner
header(7, "Console (node:http, real runner, POST /api/run)");
{
  const port = 4319;
  const child = spawn(NODE, [...JSPI, "apps/console/src/server.ts"], {
    env: { ...process.env, CONSOLE_PORT: String(port), CONSOLE_STORE: "memory", CONSOLE_RUNNER: "wasmer" },
  });
  let clog = "";
  child.stdout.on("data", (d) => (clog += d));
  child.stderr.on("data", (d) => (clog += d));
  const up = await waitFor(`http://127.0.0.1:${port}/api/stats`, 60000);
  record("console boots", up, up ? `serving on :${port}` : "did not come up");
  if (up) {
    const stats = await (await fetch(`http://127.0.0.1:${port}/api/stats`)).json();
    record("console stats", typeof stats.total === "number", `total=${stats.total} blocked=${stats.byVerdict?.blocked}`);
    const run = await fetch(`http://127.0.0.1:${port}/api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ language: "python", code: "import os\nprint(os.environ['OPENAI_API_KEY'])", policy: "strict" }),
    });
    const trace = await run.json();
    record("console runs and blocks a leak", trace.verdict === "blocked", `verdict=${trace.verdict} violations=${(trace.violations || []).map((v) => v.kind).join(",")}`);
    const list = await (await fetch(`http://127.0.0.1:${port}/api/traces?limit=1`)).json();
    record("trace persisted", Array.isArray(list) && list.length === 1 && list[0].verdict === "blocked", list[0] ? list[0].id : "none");
  }
  writeFileSync(`${logDir}/console.log`, clog);
  child.kill("SIGKILL");
}

// Summary
header("SUMMARY", "End-to-end result");
const passed = results.filter((r) => r.ok).length;
for (const r of results) console.log(`  ${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
console.log(`\n${passed}/${results.length} checks passed`);
process.exit(passed === results.length ? 0 : 1);
