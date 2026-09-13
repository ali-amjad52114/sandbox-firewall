// Demo beat 3: the same program, through the firewall. Spawns the MCP
// gateway over stdio exactly as Claude Code would and calls run_code.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { readFileSync } from "node:fs";

const program = readFileSync(new URL("../corpus/demo-exfil.py", import.meta.url), "utf8");
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["--experimental-wasm-jspi", "--import", "tsx", "packages/gateway/src/index.ts"],
  env: { ...process.env, FIREWALL_RUNNER: "wasmer", FIREWALL_STORE: process.env.FIREWALL_STORE ?? "sqlite", FIREWALL_SESSION: "demo" },
  stderr: "pipe",
});
transport.stderr?.on("data", (d) => process.stderr.write("[gateway] " + d));
const client = new Client({ name: "demo", version: "0" });
await client.connect(transport);
console.log("--- running corpus/demo-exfil.py through the firewall (policy: strict) ---");
const t0 = performance.now();
const r = await client.callTool({ name: "run_code", arguments: { language: "python", code: program } });
console.log(r.content[0].text);
console.log(`--- isError=${r.isError} in ${(performance.now() - t0).toFixed(0)} ms. Check the attacker terminal: nothing arrived. ---`);
await client.close();
