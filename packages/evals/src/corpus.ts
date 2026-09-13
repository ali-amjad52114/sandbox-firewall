import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { parsePolicy } from "@firewall/policy";
import type { Language, Policy } from "@firewall/contract";

/** The kinds of expectation the harness checks against a produced trace. */
export interface Expected {
  verdict: "clean" | "suspicious" | "blocked";
  mustContain: string[];
  mustNotContain: string[];
  mayContain: string[];
  exitReason?: "exited" | "terminated" | "timeout" | "error";
  stdoutIncludes?: string[];
  requiresNetwork?: boolean;
  notes: string;
}

export interface Scenario {
  name: string;
  dir: string;
  language: Language;
  code: string;
  files: Record<string, string>;
  policy: Policy;
  expected: Expected;
}

const PROGRAM_FILES: Record<string, Language> = {
  "main.py": "python",
  "main.js": "node",
  "main.php": "php",
};

/**
 * Load every scenario folder under `dir`. A folder is a scenario when it
 * contains both a program file (main.py|main.js|main.php) and an expected.json.
 * Folders without expected.json (e.g. the injected-page demo) are skipped.
 */
export function loadCorpus(dir = "corpus"): Scenario[] {
  const root = resolve(dir);
  if (!existsSync(root)) throw new Error(`corpus directory not found: ${root}`);

  const scenarios: Scenario[] = [];
  const entries = readdirSync(root).sort();
  for (const name of entries) {
    const sdir = join(root, name);
    if (!statSync(sdir).isDirectory()) continue;

    const expectedPath = join(sdir, "expected.json");
    if (!existsSync(expectedPath)) continue;

    const program = Object.keys(PROGRAM_FILES).find((f) => existsSync(join(sdir, f)));
    if (!program) continue;

    const language = PROGRAM_FILES[program];
    const code = readFileSync(join(sdir, program), "utf8");
    const expected = JSON.parse(readFileSync(expectedPath, "utf8")) as Expected;

    const policyPath = join(sdir, "policy.yaml");
    if (!existsSync(policyPath)) throw new Error(`scenario ${name} is missing policy.yaml`);
    const policy = parsePolicy(readFileSync(policyPath, "utf8"));

    const files: Record<string, string> = {};
    const manifestPath = join(sdir, "files.json");
    if (existsSync(manifestPath)) {
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, string>;
      for (const [guestName, rel] of Object.entries(manifest)) {
        files[guestName] = readFileSync(join(sdir, rel), "utf8");
      }
    }

    scenarios.push({ name, dir: sdir, language, code, files, policy, expected });
  }
  return scenarios;
}
