#!/usr/bin/env bash
# Usage: ./cacheck.sh HOST [PORT]
# Prints one row per IP and certificate. Exit code: 0 pass, 1 warn, 2 fail, 3 request failed.
set -euo pipefail
host=${1:?usage: cacheck.sh HOST [PORT]}
port=${2:-0}
api="${CACHECK_URL:-https://this-server}/api/check"

body=$(jq -n --arg host "$host" --argjson port "$port" '{host: $host, port: $port}')
out=$(curl -sS -w '\n%{http_code}' -H 'Content-Type: application/json' -d "$body" "$api") || exit 3
code=${out##*$'\n'}
resp=${out%$'\n'*}
if [[ $code != 200 ]]; then
  echo "HTTP $code: $(jq -r '.error' <<<"$resp" 2>/dev/null || echo "$resp")" >&2
  exit 3
fi

# The overall result is the worst IP result, or the consistency check if it warns or fails.
overall=$(jq -r '[.results[].overall, (.consistency.status // empty | select(. == "warn" or . == "fail"))]
  | map({"pass": 0, "info": 1, "warn": 2, "fail": 3}[.] // 0) | max
  | ["pass", "info", "warn", "fail"][.]' <<<"$resp")

jq -r --arg overall "$overall" '
  def problems: [.checks[]? | select(.status == "warn" or .status == "fail") | "\(.id) (\(.status))"] | join(", ");
  ( [["IP", "KEY", "TLS", "RESULT", "PROBLEMS"]]
    + [ .results[] as $r
        | ( [$r.ip, ($r.keyType // "-"), ($r.tls.version // "-"),
             ($r.analysis.overall // $r.overall), ($r.error // $r.denyReason // ($r.analysis | problems))] ),
          ( $r.alternate // empty
            | [$r.ip, .keyType, .tls.version, .overall, (.analysis | problems)] ) ]
  ) as $rows
  | [range(0; 4) as $i | $rows | map(.[$i] | length) | max] as $width
  | ( $rows[] | [range(0; 4) as $i | .[$i] + " " * ($width[$i] - (.[$i] | length) + 2)] + [.[4]] | add ),
    "",
    ( .consistency // empty | "Consistency: \(.status). \(.detail)" ),
    "Overall: \($overall)"
' <<<"$resp"

case $overall in
  fail) exit 2 ;;
  warn) exit 1 ;;
esac
