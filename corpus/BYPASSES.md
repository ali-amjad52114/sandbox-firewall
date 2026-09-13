# Bypasses found and fixed during the build

Each entry: what the red team tried, what it proved, what changed.

| # | Attempt | Result before | Fix |
| --- | --- | --- | --- |
| 1 | Connect to a raw IP (`socket.connect(("93.184.216.34", 80))`) to skip the hostname allowlist | Bridge saw only an IP, no policy match possible | `connectTcp` only admits IPs returned by an allowed `resolve`; raw IPs are refused and recorded |
| 2 | Open a listener inside the sandbox to turn it into a relay | `listenTcp` reached Node's `net.createServer` | `listenTcp` always refused and recorded as a blocked event |
| 3 | Node guest `fetch()` to any host under the strict policy | **Succeeded with no trace event.** The SDK serves guest HTTP through the host's own `fetch` inside its worker threads, bypassing the socket bridge. `network: { mode: "disabled" }` does not gate it either. | The runner installs its own `Worker` adapter so every SDK worker boots through `firewall-worker.mjs`, which guards undici's global dispatcher (the layer under `fetch`, which the SDK reaches without touching `globalThis.fetch`) and asks the runner for a verdict over a BroadcastChannel; deny by default. Node runs hold an exclusive slot so the verdict attributes to exactly one trace. |
| 4 | Exfiltrate the canary as base64 chunks in DNS labels (`<chunk>.dns.attacker.example`) | Resolve was refused, but the leak itself was not called out | Canary scan covers attempted hostnames with 12-char chunk matching across raw, base64, base64url, hex and URL encodings |
| 5 | Write the environment to a dotfile (`.npmrc-backup`) instead of printing it | Only the write outside `out/` was flagged | Written files under 1 MB are scanned for canaries, so the dotfile is a critical `canary.leaked`, not a medium fs violation |

Round 2 — found by the adversarial audit workflow (6 static finders + 3 red-team agents, each finding verified by independent skeptics), then confirmed by running against the real runner:

| # | Attempt | Result before | Fix |
| --- | --- | --- | --- |
| 6 | Exfil the canary in a URL query / POST body / any request payload to a policy-**allowed** host (permissive allows `*`; research allows example.com). Verified: under `research`, a Python program sent the AWS key in the query to example.com, the request succeeded, verdict `clean`. | **Leaked with no violation.** The canary scan only read attempted hostnames; `NetworkEvent` had no path/body, so a secret anywhere but the hostname left undetected. This is the exfil channel that matters most. | The network context now exposes `scanEgress`. WASIX `socketWrite` bytes (Python, PHP) and the Node fetch request line, headers, string/Buffer body **and streamed body** (teed through the undici dispatcher guard) are scanned for canaries. A hit is a critical `canary.leaked` regardless of whether the host is allowed. Corpus 11, 12. |
| 7 | Split the canary into sub-12-char DNS labels across several `gethostbyname` lookups under permissive. | **Leaked.** The 12-char hostname-chunk matcher, sampling every 6 chars, never lined up with the labels. | The runner reassembles the leftmost labels of every attempted hostname (across lookups) into one string and scans it. Hosts are recorded even when resolution fails, so this needs no live DNS. Corpus 13. |
| 8 | base32-encode the canary (case-insensitive, hostname-legal) for DNS exfil. | Missed: the scanner knew raw/base64/base64url/hex/urlencoded, not base32. | Added base32 (RFC 4648, no padding) to the encoding set. |
| 9 | Pad a written file just past 1 MB to skip the canary scan (`out/leak.bin`, secret at offset 0). | **Leaked** (verdict `clean`): files over 1 MB were skipped. | Scan cap raised from 1 MB to 16 MB. Corpus 14. (Written files never leave the sandbox, so this is a tripwire, not an exfil channel — see Limits.) |
| 10 | Fail to release a run slot when client/bridge leasing throws (before the `try`), deadlocking the whole runner. | Real liveness bug: one reachable fault permanently wedged every future run. | Slot and lease acquisition moved inside the `try`; the `finally` always releases. The reader/writer lock is now writer-preferring so a stream of Python/PHP runs cannot starve a Node run. |

Open items the firewall cannot close in `@wasmer/sdk` 0.13:

- No memory limit. `limits.memoryMb` is recorded, not enforced.
- The filesystem diff sees `/workspace` only. Writes to `/tmp` or outside the workspace are invisible to the diff, but they also never leave the sandbox and are destroyed on close, so they are not an exfil channel.
- Written files are canary-scanned only up to 16 MB; a secret hidden past that in a single file is not scanned. Files never leave the sandbox, so this is a tripwire gap, not a leak.
- A canary reversed or put through an encoding the scanner does not know (e.g. a custom cipher) can pass the stdout/stderr tripwire. stdout is returned to the calling agent, not sent outward, so this is best-effort, not an exfil boundary. The network and file channels cover the encodings an exfil tool actually uses (raw, base64/url, hex, base32, urlencoded, plus DNS-label reassembly).
- A guest that finds another host-served capability (beyond `fetch`) would need the same treatment as item 3. The wrapper worker is the place to add it.
