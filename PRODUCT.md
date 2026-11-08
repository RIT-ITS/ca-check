# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Primary:** the owner's internal team and organization (institutional context; the code is shared with other schools, each applying its own colours locally). They check TLS chains on servers they run, before and after certificate rollouts, while debugging client trust errors, and when auditing.
- **Secondary:** the public. The tool is on the public internet, so visitors can be anywhere from PKI experts to people who only know "the browser says the certificate is wrong". The verdict has to make sense to both.

## Product Purpose

CA Chain Check connects to a host and port over TLS with SNI. It accepts whatever chain the server presents, without trust-validating it, and says what is wrong with that chain:

- whether it reaches a root in the trust store (by default Mozilla's CCADB roots; the interface says "trust store" and never names the source)
- whether the certificates are in issuance order
- whether any certificate is expired or not yet valid
- whether the server sends CAs it doesn't need
- whether any CA on the path is flagged as pending loss of trust
- whether the leaf matches the hostname

Success means a user knows within seconds whether the chain is right and, if it isn't, exactly which certificate to fix and how.

## Positioning

- **Fast and focused:** a verdict on the chain only, in seconds. It is not a full TLS grade covering ciphers and protocols.
- **Every path shown:** issuance paths and cross-signs are drawn as a diagram, not flattened into one list.
- **Internal targets:** it can test hosts other tools can't reach, such as servers inside a cluster or on a LAN. This uses DNS overrides, per-request connect IPs, and private targets for allowlisted clients.
- **Distrust planning:** it flags CAs that are scheduled to lose trust, so teams can migrate before the deadline.
- **Per-IP results:** every IP behind a hostname is tested separately, which catches the one misconfigured node behind a load balancer.

## Operating Context

- People use it during an incident or a certificate rollout, often next to a terminal running `openssl s_client`, and they copy PEMs and fingerprints out of it.
- Results get shared with colleagues and in tickets.
- Internal hosts are checked through the deployment's DNS overrides and private-target allowlist.
- It is deployed behind Traefik and a Cloudflare tunnel. Public visitors are rate-limited per client IP.

## Capabilities and Constraints

- **Interface:** a single-page web UI served by a Go binary from embedded static files. The frontend is plain HTML, CSS and JS with no build step. Mermaid 11 is vendored locally because there is no CDN at runtime.
- **CSP:** `default-src 'self'`, no inline scripts. `style-src` allows `'unsafe-inline'` only because Mermaid puts `<style>` in its SVG. Fonts and assets must be self-hosted.
- **API:** `POST /api/check {host, port, connectIPs?}` returns per-IP results, each with checks, the chain as sent, Mozilla store roots, paths and Mermaid source. `GET /api/config` returns UI flags (whether IP override is allowed, the trust store info).
- **Terminology:** leaf, intermediate, root, issuer, subject, chain as sent, path, cross-sign, trust store (default source Mozilla CCADB), pending distrust, SNI, fingerprint (SHA-256).
- **Check statuses:** pass, info, warn, fail.
- **Undecided:** shareable result links. The UI already pre-fills the form from `?host=&port=` but doesn't run the check automatically.

## Brand Commitments

- No logo or brand assets exist. The name is "CA Chain Check".
- Because of the institutional context, the presentation should stay professional and neutral, credible to an organization's IT staff, with no novelty personality.

## Evidence on Hand

- There is real product output only: live results against public hosts such as example.com and the badssl.com variants.
- There are no users, testimonials, metrics or endorsements. Don't invent any.

## Product Principles

1. **Verdict first, evidence one step away.** The answer is visible straight away, and every claim can be traced to the exact certificate and field behind it.
2. **Name the fix.** Each problem says which certificate, at which position, and what to change.
3. **Faithful to the wire.** Show the chain exactly as the server sent it. Analysis is added on top and never reorders or hides what was received.
4. **Expert-grade but readable.** Use full fingerprints, DNs and PEMs, and copy them losslessly, but phrase verdicts so a non-expert can act on them.
5. **Safe by default.** Target policy and rate limits are part of the product, not afterthoughts.

## Accessibility & Inclusion

- WCAG 2.2 AA is required (institutional context).
- Status must never rely on color alone.
- The page must be usable by keyboard, including the tabs, fold-outs and copy buttons.
- It must work at phone width.
- It must respect reduced motion.
