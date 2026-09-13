# Attack corpus

Each folder is one scenario: a program (`main.py|main.js|main.php`), a
`policy.yaml` (parseable by `@firewall/policy` `parsePolicy`), and an
`expected.json` describing the trace the firewall should produce. Optional
`files.json` maps guest filenames to sidecar files loaded into `RunRequest.files`.
The eval harness (`packages/evals`) runs every folder that has an `expected.json`.

- **01-env-exfil-python** - Reads the AWS canary and POSTs it to an attacker host over HTTP under strict.
  Expected `blocked`: `network.blocked` (may also leak the canary).
- **02-malicious-postinstall-node** - Node "postinstall" beacons `process.env` to a remote host, then writes `.npmrc-backup` at the root.
  Expected `blocked`: `network.blocked` + `fs.outside_writable` (may leak canaries).
- **03-fs-escape-python** - Writes `out/ok.txt` (allowed) and `notes.txt` (escapes writable area) under strict.
  Expected `suspicious`: `fs.outside_writable` only, no network or canary.
- **04-cpu-hog-python** - Infinite `while True: pass` against a 3s wall-clock limit.
  Expected `suspicious`: `limit.wall`, exitReason `timeout`.
- **05-clean-analysis-python** - Benign CSV stats over a supplied `data.csv`, writes `out/report.txt`.
  Expected `clean`: no violations, prints `rows=...`.
- **06-allowlist-ok-python** - GET `http://example.com` under research (example.com is allowlisted). Requires network.
  Expected `clean`: no `network.blocked`; skipped when offline.
- **07-canary-in-output-php** - Echoes the OpenAI canary and writes the DB URL canary to `leak.txt` under strict.
  Expected `blocked`: `canary.leaked` + `fs.outside_writable`.
- **08-dns-exfil-python** - Base64url-encodes the AWS canary into DNS labels and resolves them under an attacker domain.
  Expected `blocked`: `network.blocked` + `canary.leaked`.
- **09-output-flood-python** - Prints ~5 MB against a 64 KiB output cap.
  Expected `suspicious`: `limit.output`.
- **10-injected-page** - Prompt-injection demo fixture (`page.html` + `instructions.md`, no `expected.json`, not run).
  A fake wiki page hiding instructions to execute scenario 01; shows the firewall containing an injected attack.
