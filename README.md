# CA Chain Check

A small web service that connects to `host:port` with TLS and SNI, accepts whatever certificate chain the server presents **without validating it**, and reports what is wrong with it:

- **Root trust:** whether each root program (Apple, Chrome, Microsoft and Mozilla) trusts at least one path. The check passes when every store in `REQUIRED_TRUST_STORES` (default: all four) does, warns when only some do, and fails when none do. Different stores can be satisfied by different paths, for example through a cross-sign. The data comes from three public CCADB reports: per-store status (`CCADB_STORES_URL`), Mozilla's roots with the Websites trust bit (`MOZILLA_ROOTS_URL`) and Microsoft's root report with PEM (`MICROSOFT_ROOTS_URL`). A root counts for Mozilla with the Websites bit, for Apple with `serverAuth`, for Microsoft with the Server Authentication EKU, and for Chrome when included. Microsoft `NotBefore` roots show as "limited". The data refreshes every 24 hours (`TRUSTSTORE_REFRESH`), with embedded copies as fallback (`make refresh-roots`). If any download fails, the previous data is kept and the download is retried after 1 minute, doubling after each failure up to 1 hour (never longer than `TRUSTSTORE_REFRESH`), with up to 10% jitter; after a success it returns to the normal interval. `GET /api/config` reports `refreshFailing` and `nextAttempt`, and the page footer says when the data may be out of date. If the server has no data at all (no usable embedded copy and no successful download), `POST /api/check` answers 503 with `Retry-After` instead of reporting every chain as untrusted, and the page explains that checks are unavailable. The interface names the stores only where it lists them, and explains in a tooltip that Mozilla's list is used well beyond Firefox.
- **Order:** whether each certificate is immediately followed by its issuer. This is checked by signature, not just by name.
- **Validity:** whether each certificate is expired, not yet valid, or expiring soon.
- **Extra certificates:** certs unrelated to the leaf, duplicates, and cross-signs that are only on paths that do not reach the trust store.
- **Pending distrust:** CA fingerprints you flag in config as scheduled to lose trust.
- **Revocation:** whether the issuer's OCSP responder or CRL says a certificate on the best path is revoked. CRLs must be signed by the issuer, and out-of-date answers count as "could not check". Because the URLs come from the certificate, every fetch follows the target policy below: http or https on ports 80 and 443 only, each resolved address and each redirect checked, size and time limited. Answers are cached until the issuer's next update, for at most an hour. Turn off with `CHECK_REVOCATION=false` (Helm: `config.checkRevocation`); `REVOCATION_TIMEOUT` (default 5s) limits each fetch.
- **OCSP stapling:** if the server staples an OCSP response, whether it is signed by the leaf's issuer, current and says "good". A revoked staple fails; an unusable one warns, or fails when the leaf has the Must-Staple (TLS Feature) extension. No staple fails only for Must-Staple certificates.
- **Hostname:** whether the leaf certificate matches the host.
- **RSA and ECDSA certificates:** many servers have one of each and send whichever the client supports. After the normal handshake, each IP gets a second TLS 1.2 ClientHello offering only the other key type's cipher suites. TLS 1.2 sends certificates unencrypted, so the probe reads them and stops without finishing the handshake. It builds this hello itself because some servers, Google's among them, reject Go's TLS 1.2 hello when it offers only RSA suites. If the server sends a different certificate, both chains are analyzed and the page has a switch between them; the IP's result is the worse of the two. A server that only allows TLS 1.3 can't be asked this way, and the result says so. Turn off with `CHECK_ALT_KEY_TYPE=false` (Helm: `config.checkAltKeyType`).
- **Cloudflare Radar:** each CA certificate's details link to its [Cloudflare Radar](https://radar.cloudflare.com/certificate-transparency) page (`/certificate-transparency/ca/<SHA-256>`) for more detail on the CA.
- **Every chain path:** found by searching issuers by name and verified signature, including cross-signs. All paths are drawn as a Mermaid diagram.

**STARTTLS:** on ports 21 (FTP), 25 and 587 (SMTP), 110 (POP3), 143 (IMAP), 389 (LDAP) and 5432 (PostgreSQL), the check tries TLS first and, if the handshake fails, reconnects and tries STARTTLS for that protocol. The API's `starttls` field (`smtp`, `imap`, `pop3`, `ftp`, `ldap`, `postgres`) forces STARTTLS on any port, and `none` turns the fallback off. The web page has no control for this; it reads an optional `starttls` URL parameter instead.

When a hostname resolves to several IPs, every IP is tested and shown in its own tab, along with a consistency verdict ("IPs serve different chains").

Set `DISABLE_IPV6=true` (Helm: `config.disableIPv6`) on hosts without IPv6 connectivity. With it set, AAAA records are never requested, IPv6 entries in `DNS_OVERRIDES` are skipped and listed as not tested, and an IPv6 literal or connect IP is refused with a clear message.

## Quick start

```sh
make test
make run              # http://127.0.0.1:8080 (reads .env if present)
```

## API

`POST /api/check`

```json
{"host": "example.com", "port": 443, "connectIPs": ["203.0.113.10"]}
```

`starttls` is optional (see above). `connectIPs` is optional and works like `curl --resolve`: the server connects to those IPs but still sends the hostname as SNI. The response has one entry in `results[]` per IP, each with its TLS info, chain analysis and Mermaid source.

`GET /api/config` returns the UI flags. `GET /healthz` is the liveness check. The page at `/help` documents the API for users, with examples. `examples/` has bash, PowerShell and Python scripts that print a summary table; the help page shows the same scripts, and a test fails if they differ. `/swagger` is an interactive Swagger UI reference built from `web/openapi.json` (OpenAPI 3.0.3); a test fails if the spec and the Go types drift apart. Swagger UI is vendored in `web/vendor/swagger-ui` (`make refresh-swagger`), so no outside scripts are loaded.

## Target access policy

Every resolved or overridden IP is checked in order:

1. **`TARGET_DENY_CIDRS`:** never testable, by anyone. The defaults cover cloud metadata, link-local, multicast and unspecified addresses.
2. **Private ranges** (RFC1918, loopback, CGNAT, ULA, plus `PRIVATE_TARGET_EXTRA_CIDRS`): testable only by clients whose IP is in `PRIVATE_TARGET_CLIENT_CIDRS`. That list is empty by default, which means nobody.
3. **Everything else:** allowed.

Each dial goes to the exact IP that was checked, so DNS rebinding can't redirect a probe.

## DNS overrides (testing servers inside a cluster)

These are applied in priority order:

1. **Per request,** with `connectIPs`. Turn it off with `ALLOW_REQUEST_IP_OVERRIDE=false`, or limit it to certain clients with `IP_OVERRIDE_CLIENT_CIDRS`.
2. **Static,** with `DNS_OVERRIDES=api.internal=10.0.0.5,10.0.0.6;*.svc.cluster.local=10.96.0.10`. In Helm, use the `dnsOverrides:` map instead.
3. **Custom resolver,** with `DNS_SERVERS=10.96.0.10:53`.

Overridden IPs still go through the target policy. To reach in-cluster services, add the cluster CIDRs to `PRIVATE_TARGET_CLIENT_CIDRS` for the clients that need it.

## Rate limiting

- Each client IP gets a token bucket (`RATE_LIMIT_RPM`, `RATE_LIMIT_BURST`). A check costs 1 token, plus 1 more for every 4 target IPs.
- Over the limit, the API returns `429` with a `Retry-After` header.
- `MAX_CONCURRENT_PROBES` caps the number of handshakes running at once.
- The client IP is the rightmost `X-Forwarded-For` hop that is not one of the `TRUSTED_PROXIES`. Set that variable to your Traefik or ingress CIDR, or every request will look like it comes from the proxy.
- If a proxy hides the real client address (for example rootless Podman with Traefik, where every request appears to come from Traefik), set `CLIENT_IP_HEADER`, for example `CF-Connecting-IP` behind a Cloudflare tunnel. It's honored only when the request comes from a `TRUSTED_PROXIES` address. `TRAEFIK_RATELIMIT_HEADER` (or `traefik.middleware.sourceHeader` in Helm) groups the Traefik limit by the same header.
- The limit is kept in memory **per replica**. Compose and Helm can also add a Traefik `ratelimit` middleware as a shared layer in front of the app.

## Pending loss of trust

```sh
PENDING_DISTRUST='E6:2A:...:59|2027-01-15|Example CA distrusted for TLS;0123abcd...|2027-06-01'
PENDING_DISTRUST_FILE=/etc/ca-chain-check/pending-distrust.yaml   # - {fingerprint, date, note}
```

Fingerprints are SHA-256. Colons and letter case don't matter. Entries from the variable and the file are merged.

In Helm, set `pendingDistrust:` in your values. It's rendered into the ConfigMap and mounted as the file, and pods restart automatically when it changes.

## Theming

The shared default palette is a navy header band, snow-white report sheets, a teal action colour and a yellow rule under the band. To use your own institution's colours, set `THEME_COLORS` in your local `.env` (which git ignores) or `theme:` in your Helm values. Brand colours then live only in your deployment's config, not in the shared code.

```sh
THEME_COLORS="accent=0b6e4f accent-hover=0f8a63 bar=102a20 bar-edge=c9a227 dark.bar=08160f"
```

- Write the pairs as `token=hex`, separated by spaces or `;`. The `#` is optional, since some `.env` parsers treat it as the start of a comment. Anything that isn't a known token or a hex colour stops the server at startup.
- The server turns these pairs into `/theme.css`, which loads after `styles.css`. It also draws the favicon in the `bar` and `bar-edge` colours.
- **Tokens:**
  - **Action:** `accent` (primary button, selected tab, focus ring), `accent-ink` (text on the accent) and `accent-hover`.
  - **Header band:** `bar`, `bar-ink`, `bar-muted`, `bar-field`, `bar-line`, `bar-line-hover`, `bar-placeholder`, `bar-error`, and `bar-edge` (the 3px rule under the band).
  - **Report:** `ground`, `sheet`, `sheet-alt`, `ink`, `muted`, `rule`, `rule-strong` and `link`.
- **Dark mode:** a plain value for `bar`, `bar-field`, `ground`, `sheet`, `sheet-alt`, `ink`, `muted`, `rule`, `rule-strong` or `link` applies in light mode only. Add a `dark.` version (for example `dark.bar=0a0a0a`) to set the dark-mode value. Every other token applies to both modes.
- Status colours (pass, warn, fail, note) can't be themed, because they carry meaning and are tuned for contrast.
- Keep `accent` at 3:1 or more against `sheet` and `bar` so the focus ring stays visible, and keep `accent-ink` at 4.5:1 or more on `accent`.

## Local deployment (Podman Compose + Traefik)

```sh
cp .env.example .env    # set APP_HOST, TRAEFIK_NETWORK, TRAEFIK_ENTRYPOINT, TRAEFIK_CERTRESOLVER
podman compose up -d --build --force-recreate   # podman-compose keeps the old container without --force-recreate
```

The app joins the external Traefik network and publishes no ports itself. Traefik picks up the router, service, health check and rate-limit middleware from the labels.

## Production (Helm)

```sh
helm upgrade --install ca-chain-check deploy/helm/ca-chain-check \
  --set image.repository=registry.example.com/ca-chain-check --set image.tag=0.1.0 \
  --set traefik.ingressRoute.enabled=true --set traefik.ingressRoute.host=chain-check.example.com \
  --set traefik.middleware.enabled=true
```

All app settings are under `config.*`. The chart can also create:

- a standard `Ingress`
- a Traefik `IngressRoute` and `Middleware`
- a HorizontalPodAutoscaler and a PodDisruptionBudget
- a NetworkPolicy that limits egress to DNS and the TLS ports you list

Site-specific values (image registry, hosts, pull secrets) can go in `deploy/helm/values.local.yaml`, which git ignores. Pass it with `-f deploy/helm/values.local.yaml`.

## CI (GitLab)

`.gitlab-ci.yml` runs `go vet` and `go test` on every push and merge request. On the default branch it builds the image with rootless Buildah and pushes it to the project's container registry twice, as `:latest` and as `:<short commit SHA>`. To deploy `:latest`, set `image.pullPolicy=Always` and run `kubectl rollout restart deployment/ca-chain-check` after each push. To pin a release, set `image.tag` to the SHA instead.

## Maintenance

- `make refresh-roots` updates the embedded CCADB snapshots in `assets/` (`mozilla-roots.pem`, `root-stores.csv`, `microsoft-roots.csv`) and records the download date in `assets/roots-date.txt`, which the page shows for the built-in copy.
- `make refresh-mermaid` updates the vendored `web/vendor/mermaid.min.js`.
- `make refresh-swagger` updates the vendored Swagger UI in `web/vendor/swagger-ui/` (version in `SWAGGER_UI_VERSION`).
