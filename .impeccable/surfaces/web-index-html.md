---
version: 1
slug: "web-index-html"
primary_target: "web/index.html"
related_targets: ["web/app.js","web/styles.css"]
---

# CA Chain Check: check page

## Scope

- **Surface:** the single check page (`web/index.html`, `web/app.js`, `web/styles.css`).
- **Mode:** Operate.
- **Audience:** the owner's org and team (institutional), plus the public.
- **Job:** enter host and port, then get a verdict and the fix within seconds, with full certificate evidence one step away.

## Constraints

- **User-pinned:** colours used subtly, and themeable per deployment through THEME_COLORS so no institution's brand lives in the shared code. The default palette is inspired by a snowy mountain-town cartoon: night-navy band, snow ground, teal accent, yellow band rule. The accent is never a status colour. The interface calls the root store "the trust store".
- **Avoid:** marketing feel, a hacker or terminal costume, a generic SaaS card grid, and lost density.
- **Unchanged:** the API, the behaviour, the per-IP tabs, the expandable certificate details, the Mermaid paths, and the CSP (self-hosted assets only).

## Direction contract

**THESIS:** The check result reads like a clinical lab report. An interpretation box states the verdict and the fix, a result table lists each test against its expected value with flags in their own column, and the certificates are the specimens. This replaces the category default of a summary banner over a grid of soft cards.

**OWN-WORLD:**
- **Surfaces:** navy header band with a 3px yellow rule. Pale snow ground, and white report sheets with 1px cool-gray hairline rules.
- **Type:** Public Sans (institutional, self-hosted) for all text, with tabular figures. System mono only for machine identifiers: fingerprints, PEM, serials, key IDs, OIDs, IP addresses, SNI and the hostname field, and cipher names.
- **Status:** a flag column carries FAIL, WARN or NOTE as words plus a shape, tinted red, ochre or slate. The accent is reserved for the primary action, the selected tab and focus.

**STORY:** The visitor submits a host. They read the interpretation (the verdict plus the exact fix), scan the result table for flags, open a certificate row only when they need the evidence, and copy what they need into a ticket.

**FIRST VIEWPORT:**
- A dark header band holds the name and an inline host/port form, with the accent-coloured Check button at right.
- Below it is the report header: the host:port title, plus a metadata strip with IP, TLS, cipher, SNI and checked-at time.
- The IP tabs come next, then the Interpretation box, and then the result table (Test | Result | Expected | Flag) at full width.
- Signature move: the validity reference-range graph. Each certificate's validity is a bar on one shared time axis with today marked.

**FORM:** Lab Report, rank 1 of 7 (IMPECCABLE'S PICK). seed:baa6fdf6dd645e76.

Kept from the declined challengers:
- State restyles the row, never the grid.
- Red is reserved for findings that need a change.
- Validity is drawn to scale.
- Colour is quarantined to the flags, the graph and the diagram.
- One type family on a fixed scale.

**FINISH:** unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
