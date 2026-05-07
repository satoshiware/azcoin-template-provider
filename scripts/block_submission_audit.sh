#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Extract accepted AZCoin Template Provider submitblock records from journald.

Reads lines containing event="submitblock_result" and accepted=true only.
Outputs observed journal time plus template_id and block_hash parsed from logs.
For operational auditing only — not payout or accounting truth. Do not use
coinbase_output_count from logs as payout truth.

Run on the Template Provider / AZCoin Core host (journal for
azcoin-template-provider.service only). The SV2 pool may run elsewhere. This
tool does not read or require local pool-sv2.service, pool journald, sv2-apps,
pool config files, or pool binaries on this machine.

Usage:
  scripts/block_submission_audit.sh [--unit <systemd-unit>] [--lines N] [--since STR] [--jsonl]
  scripts/block_submission_audit.sh -h | --help

Options:
  --unit <systemd-unit>   systemd journal unit (default: azcoin-template-provider.service)
  --lines N               journal tail line count with -n (default: 2000; ignored if --since)
  --since STR             journalctl --since expression (exclusive of -n)
  --jsonl                 one JSON object per accepted record (no jq/python)
  -h, --help              show this help

Examples:
  scripts/block_submission_audit.sh
  scripts/block_submission_audit.sh --lines 5000
  scripts/block_submission_audit.sh --since "2026-05-07 00:00:00"
  scripts/block_submission_audit.sh --since "today" --jsonl
EOF
}

UNIT="azcoin-template-provider.service"
LINES="2000"
SINCE=""
FORMAT="text"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      UNIT="${2:-}"
      shift 2
      ;;
    --lines)
      LINES="${2:-}"
      shift 2
      ;;
    --since)
      SINCE="${2:-}"
      shift 2
      ;;
    --jsonl)
      FORMAT="jsonl"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

[[ -n "$UNIT" ]] || {
  printf '%s\n' '--unit requires a value' >&2
  exit 2
}

if [[ "$LINES" != *[!0-9]* ]] && [[ -n "${LINES// }" ]]; then
  :
else
  printf '%s\n' '--lines requires a positive integer' >&2
  exit 2
fi

if [[ -z "$SINCE" ]]; then
  if [[ "$LINES" -lt 1 ]]; then
    printf '%s\n' '--lines must be >= 1' >&2
    exit 2
  fi
  J_CMD=(journalctl -u "$UNIT" -n "$LINES" --no-pager -l)
else
  J_CMD=(journalctl -u "$UNIT" --since "$SINCE" --no-pager -l)
fi

sudo "${J_CMD[@]}" | awk -v FORMAT="$FORMAT" '
function json_escape(str, _out, _i, _ch) {
  _out = ""
  for (_i = 1; _i <= length(str); _i++) {
    _ch = substr(str, _i, 1)
    if (_ch == "\\")       { _out = _out "\\\\"; continue }
    if (_ch == "\"")       { _out = _out "\\\""; continue }
    if (_ch == "\n")       { _out = _out "\\n";  continue }
    if (_ch == "\r")       { _out = _out "\\r";  continue }
    if (_ch == "\t")       { _out = _out "\\t";  continue }
    _out = _out _ch
  }
  return _out
}

function extract_tid(line, _m, _p, _tail, _buf, _j, _c) {
  _m = "template_id="
  _p = index(line, _m)
  if (!_p) return ""
  _tail = substr(line, _p + length(_m))
  _buf = ""
  for (_j = 1; _j <= length(_tail); _j++) {
    _c = substr(_tail, _j, 1)
    if (_c ~ /[0-9]/) _buf = _buf _c
    else break
  }
  return _buf
}

$0 ~ /event="submitblock_result"/ && $0 ~ /accepted=true/ {
  ot = $1 " " $2 " " $3
  tid = extract_tid($0)

  hmark = "block_hash=Some(\""
  hp = index($0, hmark)
  bh = ""
  if (hp > 0) {
    rest = substr($0, hp + length(hmark))
    for (j = 1; j <= length(rest); j++) {
      c = substr(rest, j, 1)
      if (c == "\"") break
      bh = bh c
    }
  }

  if (tid == "" || bh == "") next

  n++
  if (FORMAT == "jsonl") {
    jot = json_escape(ot)
    jbh = json_escape(bh)
    printf "{\"observed_time\":\"%s\",\"template_id\":%s,\"block_hash\":\"%s\",\"accepted\":true}\n", jot, tid, jbh
  } else {
    printf "observed_time=%s template_id=%s block_hash=%s\n", ot, tid, bh
  }
}

END {
  if (n == 0) print "no accepted submitblock records found" > "/dev/stderr"
}
'
