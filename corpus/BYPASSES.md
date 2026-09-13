# Bypasses found and fixed during the build

Each entry: what the red team tried, what it proved, what changed.

| # | Attempt | Result before | Fix |
| --- | --- | --- | --- |
| 1 | Connect to a raw IP (`socket.connect(("93.184.216.34", 80))`) to skip the hostname allowlist | Bridge saw only an IP, no policy match possible | `connectTcp` only admits IPs returned by an allowed `resolve`; raw IPs are refused and recorded |
| 2 | Open a listener inside the sandbox to turn it into a relay | `listenTcp` reached Node's `net.createServer` | `listenTcp` always refused and recorded as a blocked event |
| 3 | Node guest `fetch()` to any host under the strict policy | **Succeeded with no trace event.** The SDK serves guest HTTP through the host's own `fetch` inside its worker threads, bypassing the socket bridge. `network: { mode: "disabled" }` does not gate it either. | The runner points the SDK at a wrapper worker (`firewall-worker.mjs`) that wraps `fetch` and asks the runner for a verdict over a BroadcastChannel; deny by default. Node runs hold an exclusive slot so the verdict attributes to exactly one trace. |
| 4 | Exfiltrate the canary as base64 chunks in DNS labels (`<chunk>.dns.attacker.example`) | Resolve was refused, but the leak itself was not called out | Canary scan covers attempted hostnames with 12-char chunk matching across raw, base64, base64url, hex and URL encodings |
| 5 | Write the environment to a dotfile (`.npmrc-backup`) instead of printing it | Only the write outside `out/` was flagged | Written files under 1 MB are scanned for canaries, so the dotfile is a critical `canary.leaked`, not a medium fs violation |

Open items the firewall cannot close in `@wasmer/sdk` 0.13:

- No memory limit. `limits.memoryMb` is recorded, not enforced.
- The filesystem diff sees `/workspace` only.
- A guest that finds another host-served capability (beyond `fetch`) would need the same treatment as item 3. The wrapper worker is the place to add it.
