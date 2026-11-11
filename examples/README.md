# API example scripts

Each script checks one host with `POST /api/check` and prints a table with one row per IP address and certificate. A server with both an RSA and an ECDSA certificate gets a row for each. The table lists the checks that warned or failed. The script then prints the consistency check and an overall result: the worst IP result, or the consistency result if it warns or fails.

| Script | Needs |
|---|---|
| `cacheck.sh` | bash, `curl` and `jq` |
| `cacheck.ps1` | PowerShell 7 (`pwsh`) |
| `cacheck.py` | Python 3.8 or later; standard library only |

Set `CACHECK_URL` to the server's address, then run `./cacheck.sh HOST [PORT]`:

```
$ CACHECK_URL=https://cacheck.example.edu ./cacheck.sh expired.badssl.com
IP              KEY  TLS      RESULT  PROBLEMS
104.154.89.105  rsa  TLS 1.2  fail    validity (fail), extra_certs (warn)

Consistency: info. Only one IP was tested.
Overall: fail
```

Exit codes: `0` pass, `1` warn, `2` fail, `3` the request failed.

The API help page (`/help`) shows the same scripts with that server's address filled in. `web/examples_test.go` fails if the two copies differ.

## Batch

`cacheck-batch.py` (Python 3.8 or later, standard library only) checks a list of hosts one at a time and writes CSV to stdout, one row per IP address and certificate. Each line of the list is `host`, `host:port` or `host:port starttls`; blank lines and `#` comments are skipped. Progress goes to stderr. Unlike the single-host scripts it has no default server: it stops at once if `CACHECK_URL` is not set.

```
$ CACHECK_URL=https://cacheck.example.edu ./cacheck-batch.py hosts.txt > results.csv
[1/3] example.com
[2/3] expired.badssl.com
  HTTP 429, waiting 6s
[3/3] smtp.gmail.com:587
```

Columns: `host, port, ip, key_type, tls_version, result, problems, consistency, checked_at, error`. A host that can't be checked at all (it doesn't resolve, for example) gets one row with `result` set to `error`.

On `429` the script waits for the `Retry-After` seconds and tries the same host again, so it never goes over the server's rate limit. That also sets the speed: at the default 10 checks a minute, 100 hosts take at least 10 minutes, more if they have many IP addresses. The exit code is the worst result over all hosts, with the same exit codes. This script is not on the help page.
