# Attaching an agent to the firewall

The gateway is an MCP server over stdio. Any MCP-capable agent can attach to
it; every tool call then runs inside a fresh Wasmer sandbox under a policy.

## Claude Code

The repo ships a `.mcp.json` at the root, so opening this directory in Claude
Code offers the `sandbox-firewall` server automatically:

```json
{
  "mcpServers": {
    "sandbox-firewall": {
      "command": "node",
      "args": ["--experimental-wasm-jspi", "--import", "tsx", "packages/gateway/src/index.ts"],
      "env": {
        "FIREWALL_RUNNER": "wasmer",
        "FIREWALL_STORE": "sqlite",
        "FIREWALL_DB": "data/traces.db",
        "FIREWALL_DEFAULT_POLICY": "strict"
      }
    }
  }
}
```

Or add it from any directory:

```bash
claude mcp add sandbox-firewall -e FIREWALL_RUNNER=wasmer -e FIREWALL_STORE=sqlite -- node --experimental-wasm-jspi --import tsx C:/AI/Projects/wasmer/packages/gateway/src/index.ts
```

The `--experimental-wasm-jspi` flag is required by the Node guest runtime
(edgejs) and Node refuses it inside `NODE_OPTIONS`, so the server must be
launched with `node` directly rather than through `npx tsx`.

## Any other MCP client

Spawn the same command over stdio. Only stderr carries logs; stdout is the
protocol channel.

## Tools

| Tool | Parameters | What it does |
| --- | --- | --- |
| `run_code` | `language` (python, node, php), `code`, `args?`, `stdin?`, `files?`, `policy?` | Runs the program in a fresh sandbox and returns a report plus a trace id. |
| `run_shell` | `command`, `policy?` | Only `echo`, `cat`, `ls`, `pwd`; translated to Python. No bash guest exists in this SDK build. |
| `install_package` | `name`, `language` (python), `policy?` | `pip install` inside a run. Needs an allowlist policy such as `research`. |
| `get_trace` | `id` | Full trace JSON. |
| `list_traces` | `verdict?`, `limit?` | Recent runs. |
| `list_policies` | none | Preset summaries. |

## The `policy` parameter

Either a preset name or a YAML document:

```yaml
name: data-science
extends: research
network:
  mode: allowlist
  allow: [pypi.org, files.pythonhosted.org]
fs:
  writable: [out/]
limits:
  wallMs: 30000
  maxOutputBytes: 65536
```

Presets:

- `strict` (default): network off, only `out/` writable, 10 s, 64 KB output.
- `research`: allowlist for pypi.org, files.pythonhosted.org, registry.npmjs.org, example.com; `out/` and `tmp/` writable; 60 s.
- `permissive`: any host, whole workspace writable, 120 s.

Unknown keys are rejected so a typo cannot silently weaken a policy.

## What a blocked result looks like

The tool result has `isError: true` and starts with a line the agent cannot
misread:

```
BLOCKED by policy strict: canary AWS_SECRET_ACCESS_KEY observed in network (urlencoded)
Do not retry this action; it violates the sandbox policy. Tell the user what was attempted.
--- stdout ---
attempt failed: <urlopen error firewall: resolve exfil.attacker.example refused by policy>
--- stderr ---
(empty)
--- violations ---
[critical] canary.leaked: canary AWS_SECRET_ACCESS_KEY observed in network (urlencoded)
[high] network.blocked: resolve exfil.attacker.example refused by policy strict
--- network ---
resolve exfil.attacker.example BLOCKED
--- fs ---
(none)
trace run_mfj2k1_8a7b6c5d
```

`structuredContent` carries the same facts as JSON: `traceId`, `verdict`,
`exitCode`, `exitReason`, `violations`.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `FIREWALL_RUNNER` | `wasmer` | `wasmer` or `mock` |
| `FIREWALL_STORE` | `sqlite` | `sqlite` or `memory` |
| `FIREWALL_DB` | `data/traces.db` | SQLite path |
| `FIREWALL_DEFAULT_POLICY` | `strict` | Preset used when a call omits `policy` |
| `FIREWALL_SESSION` | unset | Tag written on every trace |
| `FIREWALL_CACHE_DIR` | `.wasmer` | Wasmer package cache |
| `FIREWALL_MAX_CONCURRENT` | `4` | Sandboxes running at once |
