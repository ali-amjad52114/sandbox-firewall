import { describe, expect, it } from "vitest";
import { hostAllowed, parsePolicy, pathWritable, preset, PolicyError } from "./index.js";

describe("policy", () => {
  it("parses yaml with extends", () => {
    const p = parsePolicy(`name: ds\nextends: research\nnetwork:\n  mode: allowlist\n  allow: [PyPI.org]\nlimits:\n  wallMs: 5000\n`);
    expect(p.name).toBe("ds");
    expect(p.network).toEqual({ mode: "allowlist", allow: ["pypi.org"] });
    expect(p.limits.wallMs).toBe(5000);
    expect(p.limits.maxOutputBytes).toBe(preset("research").limits.maxOutputBytes);
  });
  it("rejects unknown keys", () => {
    expect(() => parsePolicy("name: x\nnetwrok: {mode: off}")).toThrow(PolicyError);
    expect(() => parsePolicy("name: x\nnetwork: {mode: open}")).toThrow(PolicyError);
  });
  it("matches hosts with wildcards", () => {
    const p = preset("research");
    p.network = { mode: "allowlist", allow: ["*.npmjs.org", "example.com"] };
    expect(hostAllowed(p, "registry.npmjs.org")).toBe(true);
    expect(hostAllowed(p, "npmjs.org")).toBe(true);
    expect(hostAllowed(p, "EXAMPLE.com")).toBe(true);
    expect(hostAllowed(p, "evil.example.com")).toBe(false);
    expect(hostAllowed(preset("strict"), "example.com")).toBe(false);
    expect(hostAllowed(preset("permissive"), "anything.tld")).toBe(true);
  });
  it("matches writable paths", () => {
    const p = preset("strict");
    expect(pathWritable(p, "/workspace/out/a.txt")).toBe(true);
    expect(pathWritable(p, "out/a.txt")).toBe(true);
    expect(pathWritable(p, "/workspace/a.txt")).toBe(false);
    expect(pathWritable(preset("permissive"), "/workspace/anything")).toBe(true);
  });
});
