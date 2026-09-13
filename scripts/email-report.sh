#!/bin/sh
# email-report.sh - mail the latest eval report produced by the eval cron job.
#
# Runs on Wasmer Edge as a scheduled job (see app.yaml, job "email-eval-report").
# Reads data/last-eval.md (written by the "run-evals" job) and pipes an RFC 5322
# message into `sendmail -t`, the sendmail-compatible binary Wasmer provides
# when the app has `enable_email: true` (registry package sendmail/sendmail).
#
# POSIX sh only: the Edge job runs under wasmer/bash, and the script is also
# usable locally with any sendmail-compatible MTA for testing.
#
# Env (all optional):
#   REPORT_TO     recipient address           (default: ops@example.com)
#   REPORT_FROM   envelope/From address       (default: firewall@example.com)
#   REPORT_PATH   path to the markdown report (default: data/last-eval.md)
#   SENDMAIL      sendmail binary             (default: sendmail)

set -eu

REPORT_TO="${REPORT_TO:-ops@example.com}"
REPORT_FROM="${REPORT_FROM:-firewall@example.com}"
REPORT_PATH="${REPORT_PATH:-data/last-eval.md}"
SENDMAIL="${SENDMAIL:-sendmail}"

# `date -u` exists in wasmer/coreutils; fall back to a fixed string if not.
STAMP="$(date -u +%Y-%m-%dT%H:%MZ 2>/dev/null || echo unknown-time)"

if [ ! -s "$REPORT_PATH" ]; then
  # Still send a mail so a missing report is noticed, not silently dropped.
  SUBJECT="[sandbox-firewall] eval report MISSING at $STAMP"
  BODY="No report found at $REPORT_PATH. The run-evals job may have failed."
else
  # Subject carries the headline pass line if the report has one, e.g.
  # "Pass: 41/44". The grep is best-effort; a report without it still sends.
  HEADLINE="$(grep -m1 -i -E '^(\*\*)?pass' "$REPORT_PATH" 2>/dev/null | tr -d '*' || true)"
  SUBJECT="[sandbox-firewall] eval report $STAMP ${HEADLINE:+- $HEADLINE}"
  BODY="$(cat "$REPORT_PATH")"
fi

# -t reads To:/From:/Subject: from the headers below.
# -f sets the envelope sender explicitly (per Wasmer's email docs).
printf '%s\n' \
  "To: $REPORT_TO" \
  "From: $REPORT_FROM" \
  "Subject: $SUBJECT" \
  "MIME-Version: 1.0" \
  "Content-Type: text/plain; charset=utf-8" \
  "" \
  "$BODY" \
| "$SENDMAIL" -f "$REPORT_FROM" -t

echo "email-report: sent '$SUBJECT' to $REPORT_TO"
