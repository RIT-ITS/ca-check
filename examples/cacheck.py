#!/usr/bin/env python3
"""Usage: ./cacheck.py HOST [PORT]

Prints one row per IP and certificate. Exit code: 0 pass, 1 warn, 2 fail, 3 request failed.
Needs Python 3.8 or later and nothing outside the standard library.
"""
import json
import os
import sys
import urllib.error
import urllib.request

RANK = {"pass": 0, "info": 1, "warn": 2, "fail": 3}


def problems(analysis):
    return ", ".join(
        f"{c['id']} ({c['status']})"
        for c in (analysis or {}).get("checks", [])
        if c["status"] in ("warn", "fail")
    )


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    server = os.environ.get("CACHECK_URL", "https://this-server")
    body = {"host": sys.argv[1], "port": int(sys.argv[2]) if len(sys.argv) > 2 else 0}
    req = urllib.request.Request(
        f"{server}/api/check",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "cacheck-example"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e).get("error", "")
        except ValueError:
            msg = e.reason
        print(f"HTTP {e.code}: {msg}", file=sys.stderr)
        sys.exit(3)
    except urllib.error.URLError as e:
        print(f"Request failed: {e.reason}", file=sys.stderr)
        sys.exit(3)

    rows = [("IP", "KEY", "TLS", "RESULT", "PROBLEMS")]
    for r in data["results"]:
        analysis = r.get("analysis")
        rows.append((
            r["ip"],
            r.get("keyType") or "-",
            (r.get("tls") or {}).get("version", "-"),
            analysis["overall"] if analysis else r["overall"],
            problems(analysis) if analysis else r.get("error") or r.get("denyReason") or "",
        ))
        if alt := r.get("alternate"):
            rows.append((r["ip"], alt["keyType"], alt["tls"]["version"], alt["overall"], problems(alt["analysis"])))

    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    for row in rows:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)) + "  " + row[4])

    statuses = [r["overall"] for r in data["results"]]
    if consistency := data.get("consistency"):
        if consistency["status"] in ("warn", "fail"):
            statuses.append(consistency["status"])
        print(f"\nConsistency: {consistency['status']}. {consistency['detail']}")
    overall = max(statuses, key=lambda s: RANK.get(s, 0))
    print(f"Overall: {overall}")
    sys.exit({"warn": 1, "fail": 2}.get(overall, 0))


if __name__ == "__main__":
    main()
