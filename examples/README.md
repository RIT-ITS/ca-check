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
