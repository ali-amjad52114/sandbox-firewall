import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { MockRunner } from "@firewall/contract/mock";
import type { Runner } from "@firewall/contract";
import { loadCorpus } from "./corpus.js";
import { runEvals, formatTable, toMarkdown } from "./harness.js";

interface Args {
  runner: "mock" | "wasmer";
  offline: boolean;
  only?: string;
  json?: string;
  md?: string;
  concurrency: number;
  corpus: string;
}

function parseArgs(argv: string[]): Args {
  const here = dirname(fileURLToPath(import.meta.url));
  const defaultCorpus = resolve(here, "..", "..", "..", "corpus");
  const args: Args = {
    runner: "mock",
    offline: false,
    concurrency: 2,
    corpus: defaultCorpus,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--runner": {
        const v = argv[++i];
        if (v !== "mock" && v !== "wasmer") {
          console.error(`--runner must be mock or wasmer, got: ${v}`);
          process.exit(2);
        }
        args.runner = v;
        break;
      }
      case "--offline":
        args.offline = true;
        break;
      case "--only":
        args.only = argv[++i];
        break;
      case "--json":
        args.json = argv[++i];
        break;
      case "--md":
        args.md = argv[++i];
        break;
      case "--concurrency":
        args.concurrency = Math.max(1, parseInt(argv[++i], 10) || 2);
        break;
      case "--corpus":
        args.corpus = resolve(argv[++i]);
        break;
      default:
        console.error(`unknown argument: ${a}`);
        process.exit(2);
    }
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  let runner: Runner;
  if (args.runner === "wasmer") {
    try {
      const mod = await import("@firewall/runner");
      const wasmer = mod.createRunner();
      // Real createRunner() returns Runner & { warm(): Promise<void> }. Warm the
      // guest runtimes up front so the first scenario is not charged the cold start.
      if (typeof wasmer.warm === "function") await wasmer.warm();
      runner = wasmer;
    } catch (e) {
      console.error(
        `failed to load the wasmer runner (@firewall/runner): ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
      console.error("build/link packages/runner, or run with --runner mock.");
      process.exit(2);
      return;
    }
  } else {
    runner = new MockRunner();
  }

  let scenarios = loadCorpus(args.corpus);
  if (args.only) scenarios = scenarios.filter((s) => s.name.includes(args.only!));
  if (scenarios.length === 0) {
    console.error(`no scenarios matched (corpus=${args.corpus}${args.only ? `, only=${args.only}` : ""})`);
    process.exit(2);
  }

  const results = await runEvals(runner, scenarios, {
    offline: args.offline,
    concurrency: args.concurrency,
  });

  console.log(formatTable(results));

  if (args.json) {
    writeFileSync(args.json, JSON.stringify(results, null, 2));
    console.log(`wrote ${args.json}`);
  }
  if (args.md) {
    writeFileSync(args.md, toMarkdown(results));
    console.log(`wrote ${args.md}`);
  }

  await runner.close?.();

  const failed = results.some((r) => !r.pass && !r.skipped);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
