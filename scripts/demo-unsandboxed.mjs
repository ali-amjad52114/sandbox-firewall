// Demo beat 1: what happens today. The same exfil program an injected page
// asks an agent to run, executed with a plain host interpreter. The "secret"
// is the firewall canary so nothing real is at risk. Start
// scripts/attacker-server.mjs first and watch it receive the key.
//
// Demo beat 3 runs the identical program through the firewall:
//   node scripts/demo-firewalled.mjs
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export const PROGRAM = readFileSync(new URL("../corpus/demo-exfil.py", import.meta.url), "utf8");

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, "/")}`) {
  const env = { ...process.env, AWS_SECRET_ACCESS_KEY: "AKIAFAKE0000CANARY42/firewall" };
  console.log("--- running corpus/demo-exfil.py with the HOST python, no sandbox ---");
  const r = spawnSync(process.platform === "win32" ? "python" : "python3", ["-c", PROGRAM], { env, encoding: "utf8" });
  process.stdout.write(r.stdout);
  process.stderr.write(r.stderr);
  console.log(`--- exit ${r.status}. Check the attacker terminal. ---`);
}
