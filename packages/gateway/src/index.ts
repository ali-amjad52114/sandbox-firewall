#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { isPresetName, preset } from "@firewall/policy";
import { createServer } from "./server.js";
import { createWiring } from "./wiring.js";

const log = (...args: unknown[]) => console.error("[sandbox-firewall]", ...args);

async function main(): Promise<void> {
  const wiring = await createWiring();
  const presetName = process.env.FIREWALL_DEFAULT_POLICY ?? "strict";
  if (!isPresetName(presetName)) throw new Error(`FIREWALL_DEFAULT_POLICY=${presetName} is not a preset`);
  const server = createServer({
    runner: wiring.runner,
    store: wiring.store,
    defaultPolicy: preset(presetName),
    sessionId: process.env.FIREWALL_SESSION,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(`ready: runner=${process.env.FIREWALL_RUNNER ?? "wasmer"} store=${process.env.FIREWALL_STORE ?? "sqlite"} policy=${presetName}`);

  if (wiring.runner.warm) {
    wiring.runner
      .warm(["python"])
      .then(() => log("engine warm"))
      .catch((e: Error) => log("warm failed:", e.message));
  }

  const shutdown = async () => {
    log("shutting down");
    await wiring.runner.close?.().catch(() => {});
    await wiring.store.close?.().catch(() => {});
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  process.stdin.on("close", shutdown);
}

main().catch((e: Error) => {
  log("fatal:", e.message);
  process.exit(1);
});
