import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { MockRunner } from "@firewall/contract/mock";
import { loadCorpus } from "./corpus.js";
import { runEvals, formatTable } from "./harness.js";

const here = dirname(fileURLToPath(import.meta.url));
const CORPUS = resolve(here, "..", "..", "..", "corpus");

describe("loadCorpus", () => {
  it("finds the 9 runnable scenarios 01..09 with the right languages", () => {
    const scenarios = loadCorpus(CORPUS);
    expect(scenarios.length).toBe(13);

    const names = scenarios.map((s) => s.name).sort();
    expect(names).toEqual([
      "01-env-exfil-python",
      "02-malicious-postinstall-node",
      "03-fs-escape-python",
      "04-cpu-hog-python",
      "05-clean-analysis-python",
      "06-allowlist-ok-python",
      "07-canary-in-output-php",
      "08-dns-exfil-python",
      "09-output-flood-python",
      "11-payload-query-exfil-python",
      "12-payload-body-exfil-node",
      "13-dns-split-exfil-python",
      "14-oversize-file-canary-python",
    ]);

    const lang = (n: string) => scenarios.find((s) => s.name === n)!.language;
    expect(lang("01-env-exfil-python")).toBe("python");
    expect(lang("02-malicious-postinstall-node")).toBe("node");
    expect(lang("07-canary-in-output-php")).toBe("php");
  });

  it("skips the injected-page fixture (no expected.json)", () => {
    const names = loadCorpus(CORPUS).map((s) => s.name);
    expect(names).not.toContain("10-injected-page");
  });

  it("loads the data.csv sidecar for scenario 05", () => {
    const s = loadCorpus(CORPUS).find((x) => x.name === "05-clean-analysis-python")!;
    expect(s.files["data.csv"]).toBeDefined();
    expect(s.files["data.csv"]).toContain("amount");
  });
});

describe("runEvals with the MockRunner", () => {
  it("returns 9 results and a table that reports the summary", async () => {
    const scenarios = loadCorpus(CORPUS);
    const results = await runEvals(new MockRunner(), scenarios);
    expect(results.length).toBe(13);
    expect(formatTable(results)).toContain("passed");
  });

  it("scenario 01 (env exfil) passes: mock flags the http URL and canary", async () => {
    const scenarios = loadCorpus(CORPUS).filter((s) => s.name === "01-env-exfil-python");
    const [res] = await runEvals(new MockRunner(), scenarios);
    expect(res.pass).toBe(true);
    expect(res.verdict).toBe("blocked");
  });

  it("scenario 03 (fs escape) passes: mock flags the open(...,'w') write", async () => {
    const scenarios = loadCorpus(CORPUS).filter((s) => s.name === "03-fs-escape-python");
    const [res] = await runEvals(new MockRunner(), scenarios);
    expect(res.pass).toBe(true);
    expect(res.verdict).toBe("suspicious");
  });
});
