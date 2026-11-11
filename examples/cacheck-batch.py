#!/usr/bin/env python3
"""Usage: ./cacheck-batch.py HOSTS_FILE > results.csv   (HOSTS_FILE "-" reads stdin)

Checks each host in turn and writes CSV to stdout, one row per IP and certificate.
Each line of HOSTS_FILE is "host", "host:port" or "host:port starttls"; blank lines
and lines starting with # are skipped. On 429 or 503 the script waits for the
Retry-After seconds and tries the same host again, so it stays within the rate limit.
Progress goes to stderr. Set CACHECK_URL to the server's address first.

Exit code: worst result over all hosts: 0 pass, 1 warn, 2 fail, 3 a request failed.
Needs Python 3.8 or later and nothing outside the standard library.
"""
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request

RANK = {"pass": 0, "info": 0, "warn": 1, "fail": 2, "error": 3}
COLUMNS = ["host", "port", "ip", "key_type", "tls_version", "result", "problems", "consistency", "checked_at", "error"]
MAX_503_TRIES = 5


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def problems(analysis):
    return ", ".join(
        f"{c['id']} ({c['status']})"
        for c in (analysis or {}).get("checks", [])
        if c["status"] in ("warn", "fail")
    )


def parse_line(line):
    """Returns (host, port, starttls) or None for blank and comment lines."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    parts = line.split()
    target, starttls = parts[0], (parts[1] if len(parts) > 1 else "")
    host, port = target, 0
    # host:port, but leave bare IPv6 addresses alone; use [v6]:port for a port.
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif target.count(":") == 1:
        host, p = target.split(":")
        port = int(p)
    return host, port, starttls


def check(server, host, port, starttls):
    """Returns (response dict, None) or (None, error message)."""
    body = {"host": host, "port": port}
    if starttls:
        body["starttls"] = starttls
    tries_503 = 0
    while True:
        req = urllib.request.Request(
            f"{server}/api/check",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "cacheck-batch-example"},
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                return json.load(resp), None
        except urllib.error.HTTPError as e:
            try:
                msg = json.load(e).get("error", "")
            except ValueError:
                msg = e.reason
            if e.code in (429, 503):
                if e.code == 503:
                    tries_503 += 1
                    if tries_503 >= MAX_503_TRIES:
                        return None, f"HTTP 503: {msg}"
                try:
                    wait = max(int(e.headers.get("Retry-After", "")), 1)
                except ValueError:
                    wait = 60
                log(f"  HTTP {e.code}, waiting {wait}s")
                time.sleep(wait)
                continue
            return None, f"HTTP {e.code}: {msg}"
        except urllib.error.URLError as e:
            return None, f"Request failed: {e.reason}"
        except TimeoutError:
            return None, "Request failed: timed out"


def rows_for(host, port, data):
    consistency = data.get("consistency") or {}
    cons = consistency.get("status", "")
    base = {"host": data.get("host", host), "port": data.get("port", port),
            "consistency": cons, "checked_at": data.get("checkedAt", "")}
    rows = []
    for r in data.get("results", []):
        analysis = r.get("analysis")
        rows.append({**base, "ip": r["ip"], "key_type": r.get("keyType", ""),
                     "tls_version": (r.get("tls") or {}).get("version", ""),
                     "result": analysis["overall"] if analysis else r["overall"],
                     "problems": problems(analysis),
                     "error": r.get("error") or r.get("denyReason") or ""})
        if alt := r.get("alternate"):
            rows.append({**base, "ip": r["ip"], "key_type": alt["keyType"],
                         "tls_version": alt["tls"]["version"], "result": alt["overall"],
                         "problems": problems(alt["analysis"]), "error": ""})
    statuses = [r["overall"] for r in data.get("results", [])]
    if cons in ("warn", "fail"):
        statuses.append(cons)
    return rows, statuses


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    server = os.environ.get("CACHECK_URL", "").rstrip("/")
    if not server:
        log("Set CACHECK_URL to the server's address, for example https://cacheck.example.edu")
        sys.exit(3)
    src = sys.stdin if sys.argv[1] == "-" else open(sys.argv[1], encoding="utf-8")
    with src:
        targets = [t for t in map(parse_line, src) if t]

    out = csv.DictWriter(sys.stdout, fieldnames=COLUMNS)
    out.writeheader()
    worst = 0
    for i, (host, port, starttls) in enumerate(targets, 1):
        log(f"[{i}/{len(targets)}] {host}" + (f":{port}" if port else "") + (f" {starttls}" if starttls else ""))
        data, err = check(server, host, port, starttls)
        if err:
            log(f"  {err}")
            out.writerow({"host": host, "port": port or "", "result": "error", "error": err})
            worst = max(worst, RANK["error"])
        else:
            rows, statuses = rows_for(host, port, data)
            out.writerows(rows)
            worst = max([worst] + [RANK.get(s, 0) for s in statuses])
        sys.stdout.flush()
    sys.exit(worst)


if __name__ == "__main__":
    main()
