---
name: CA Chain Check
description: A TLS chain verdict laid out as a clinical lab report, in a themeable navy, snow and teal default palette.
colors:
  accent: "#138c9c"
  accent-ink: "#000000"
  accent-hover: "#1aa5b8"
  bar: "#1b2a41"
  bar-ink: "#ffffff"
  bar-muted: "#b9c6d3"
  bar-field: "#24364f"
  bar-line: "#4a5f80"
  bar-line-hover: "#7488a6"
  bar-placeholder: "#93a3b8"
  bar-error: "#ffb4ab"
  bar-edge: "#f2c230"
  ground: "#edf1f5"
  sheet: "#ffffff"
  sheet-alt: "#f5f7fa"
  ink: "#16202b"
  muted: "#4f5b68"
  rule: "#d5dce3"
  rule-strong: "#9fadbb"
  fail: "#b3261e"
  fail-bg: "#fbeceb"
  warn: "#8a5a00"
  warn-bg: "#fbf3e0"
  note: "#35577a"
  note-bg: "#ebf1f6"
  pass: "#2c6a3d"
  pass-bg: "#e9f3ec"
  plate: "#ffffff"
  plate-ink: "#16202b"
  plate-muted: "#4f5b68"
  diagram-node: "#f3f5f7"
  diagram-node-stroke: "#7d8a99"
typography:
  display:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.015em"
    fontFeature: "tnum"
  headline:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  title:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.5
    fontFeature: "tnum"
  body:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  body-sm:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.5
    fontFeature: "tnum"
  flag:
    fontFamily: "IBM Plex Sans, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "0.04em"
    fontFeature: "tnum"
  mono:
    fontFamily: "ui-monospace, SF Mono, Cascadia Mono, JetBrains Mono, Menlo, Consolas, monospace"
    fontSize: "0.92em"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  hair: "1px"
  key: "2px"
  control: "3px"
  sheet: "4px"
spacing:
  s1: "4px"
  s2: "8px"
  s3: "12px"
  s4: "16px"
  s5: "24px"
  s6: "32px"
  s7: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "0 24px"
    height: "40px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
    textColor: "{colors.accent-ink}"
  button-quiet:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "4px 10px"
  input-bar:
    backgroundColor: "{colors.bar-field}"
    textColor: "{colors.bar-ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "40px"
  header-band:
    backgroundColor: "{colors.bar}"
    textColor: "{colors.bar-ink}"
    padding: "16px"
  report-sheet:
    backgroundColor: "{colors.sheet}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sheet}"
    padding: "24px"
  tab:
    textColor: "{colors.muted}"
    typography: "{typography.mono}"
    padding: "12px 12px 9px"
  tab-selected:
    textColor: "{colors.ink}"
  flag-fail:
    textColor: "{colors.fail}"
    typography: "{typography.flag}"
  flag-warn:
    textColor: "{colors.warn}"
    typography: "{typography.flag}"
  flag-note:
    textColor: "{colors.note}"
    typography: "{typography.flag}"
  flag-pass:
    textColor: "{colors.pass}"
    typography: "{typography.flag}"
  interpretation:
    backgroundColor: "{colors.sheet-alt}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "16px 24px"
  interpretation-fail:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.fail}"
  interpretation-warn:
    backgroundColor: "{colors.warn-bg}"
    textColor: "{colors.warn}"
  interpretation-pass:
    backgroundColor: "{colors.pass-bg}"
    textColor: "{colors.pass}"
  result-row-fail:
    backgroundColor: "{colors.fail-bg}"
    padding: "12px"
  result-row-warn:
    backgroundColor: "{colors.warn-bg}"
    padding: "12px"
  validity-bar:
    backgroundColor: "{colors.ink}"
    rounded: "{rounded.hair}"
    height: "10px"
  diagram-plate:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "16px"
---

# Design System: CA Chain Check

## Overview

**Creative North Star: "The Lab Report"**

The check result reads like a clinical lab report rendered as a working tool. A night-navy header band carries the instrument (host, port, the teal Check button); below it a white report sheet sits on a pale snow ground, ruled with 1px gray hairlines. The verdict lives in an interpretation box, the tests sit in a result table with their expected values and a flag column, and the certificates are the specimens, folded into rows that open on demand.

Density is the point. This is an Operate-mode surface used mid-incident beside a terminal, so type is compact (15px body on a fixed scale), figures are tabular, and machine identifiers stay in system mono so they copy losslessly. Colour is used subtly: navy, white and cool grays carry the page, the accent appears only where the user acts or focuses, and a thin yellow rule closes the header band. The default palette nods to a snowy mountain town: night sky, snow, and a teal knit hat with a yellow pom-pom. Every non-status colour is a token that a deployment can override locally with THEME_COLORS (see README, Theming), so an institution can apply its own brand without changing the shared code. Status colour is quarantined to flags, the validity graph and the paths diagram.

The page follows the OS colour scheme. In dark, the ground and sheet go charcoal and status inks lighten, but the diagram plate stays a light gray so the diagram palette reads true.

**Key Characteristics:**
- Navy header band closed by a 3px yellow rule (bar-edge).
- White sheets, 1px hairlines, no shadows; depth is ruled, not lifted.
- One family (IBM Plex Sans, self-hosted) on a fixed scale with tabular numerals; system mono for machine identifiers only.
- Status as word plus shape (Fail, Warn, Note, Pass with authored 16px icons), tinted red, ochre, slate or green.
- Validity drawn to scale on one shared axis with an ink today line.

## Colors

A navy-and-snow palette with one teal signal, a yellow band rule and four muted status inks. All non-status tokens are themeable per deployment.

### Primary
- **Hat Teal** (accent): the primary action (Check chain), the selected tab's underline, focus rings, link hover underline, text selection (30% mix) and the loading meter. Text on it is pure black (accent-ink); hover lightens to accent-hover. It is never a status colour.
- **Pom-pom Yellow** (bar-edge): the 3px rule under the header band and the favicon's base stripe. Nothing else.

### Neutral
- **Night Navy** (bar): the header band. Darkens further in dark scheme (#0e1726).
- **Band White / Band Gray** (bar-ink, bar-muted): header text and header labels.
- **Band Field / Band Line** (bar-field, bar-line, bar-line-hover, bar-placeholder): header input fill, stroke, hover stroke and placeholder. **Band Error** (bar-error): form errors on the band.
- **Snow Ground** (ground): page background behind the sheets.
- **Sheet White** (sheet) and **Sheet Tint** (sheet-alt): report sheet, and the neutral interpretation box, open certificate row, row hover and PEM well.
- **Ink** (ink): body text, links, validity bars, the today line.
- **Muted Gray** (muted): secondary text, column headers, dates, issuers.
- **Hairline** (rule) and **Strong Hairline** (rule-strong): row dividers and sheet borders; table header underlines and quiet button strokes.

### Status
- **Fail Red** (fail / fail-bg): findings that need a change.
- **Warn Ochre** (warn / warn-bg): expiring soon, pending distrust, alternate paths.
- **Note Slate** (note / note-bg): informational notes.
- **Pass Green** (pass / pass-bg): passing checks and trusted paths.

Dark-scheme overrides (styles.css, `prefers-color-scheme: dark`): bar #0e1726, bar-field #18263a, ground #10151b, sheet #181f27, sheet-alt #1e2630, ink #e8edf2, muted #a5b1bd, rule #2d3742, rule-strong #4b5866, fail #ff8a7f on #3a1714, warn #e7b65a on #33270f, note #9cc1e6 on #16263a, pass #7fcf94 on #142a1b, plate #dfe5ea.

### Diagram palette
The Mermaid paths diagram (the diagramStyles table in internal/analyze/analyze.go) reuses the light status pairs on its light plate. Pass green and fail red have nearly the same luminance, so no state relies on colour: every node names its state in words, and each style has its own border or fill pattern.
- **Trusted path:** pass-bg/pass, 3px solid border.
- **Trusted root, not sent:** pass-bg/pass, 3px border dashed 6 4.
- **Pending distrust / not needed:** warn-bg/warn, 2px border dotted 2 3.
- **Expired / unrelated:** fail-bg/fail, 1.5px border, fill hatched at 45 degrees (fail stripes at 35% opacity, drawn after render by app.js), matching the validity graph's hatching.
- **Missing issuer:** transparent, fail text, 1.5px border dashed 6 4.
- **Other:** diagram-node/diagram-node-stroke, 1.5px solid.
- **Links:** trusted 3px pass; other 1.5px; to a missing issuer dashed.

The key under the diagram draws the same borders and hatching. The design was checked under simulated protanopia, deuteranopia, tritanopia and greyscale.

### Named Rules
**The Signal Rule.** The accent marks action, selection and focus only. If the accent is telling the user something about the chain, it is wrong. Local themes must keep it off the status hues.

**The Red Means Change Rule.** Red is reserved for findings that need a change. Informational output is slate; nothing decorative is red.

**The Quarantine Rule.** Colour lives only in flags, the validity graph and the diagram. Everything else is the band, the accent and neutrals.

**The Word-and-Shape Rule.** Status never relies on colour alone: every status carries its word (Fail, Warn, Note, Pass) and a shape (octagon-x, triangle, circle-i, check), and expired validity bars are hatched.

## Typography

**Body Font:** IBM Plex Sans (self-hosted woff2, weights 400, 600 and 700, Latin and Latin Extended; SIL OFL 1.1), with system-ui fallback
**Mono Font:** system mono stack (ui-monospace, SF Mono, Cascadia Mono, JetBrains Mono, Menlo, Consolas)

**Character:** One sober institutional sans for every word, with tabular figures throughout so dates, ports and positions align in columns. Mono is a data type, not a voice.

### Hierarchy
- **Display** (700, 1.75rem, 1.2): the report title (host:port).
- **Headline** (700, 1.375rem, 1.3): the interpretation verdict and the empty-state title.
- **Title** (700, 1.125rem): section headings, notice headings and the brand name.
- **Body** (400, 0.9375rem, 1.5): default text; fix lists capped at 80ch, notices at 70 to 72ch.
- **Body Small** (400, 0.8125rem): tables, certificate rows, key-value lists, metadata values.
- **Label** (600, 0.75rem): field labels, column headers, metadata terms, tags, axis ticks.
- **Flag** (700, 0.75rem, 0.04em, uppercase): status flags only.
- **Mono** (0.92em of context): fingerprints, PEM, serials, key IDs, OIDs, IPs, SNI, the host field, cipher names and the IP tabs.

### Named Rules
**The One Family Rule.** IBM Plex Sans on the fixed xs to 2xl tokens; no ad hoc sizes, no second display face.

**The Machine Mono Rule.** Mono only for strings a user would paste into a terminal or ticket.

## Layout

A single centred column (max 1180px, 16px side padding). The header band is a two-column grid (brand at 180 to 240px, then the probe form); the report is one sheet with a head, IP tabs and tabbed panels whose sections are separated by 32px. Spacing follows a 4px-based scale (4, 8, 12, 16, 24, 32, 48), with 24px as the default sheet and panel inset. The metadata strip is an auto-fit grid of 160px-minimum cells divided by hairlines.

At 860px and below the header stacks, certificate rows reflow into a position/subject/chevron grid with issuer, expiry and flags beneath, and the validity graph drops its side columns. At 640px and below the probe row wraps, insets drop to 16px, and the result table becomes stacked cards with an "Expected:" prefix.

Print hides the form, tabs and controls, shows every panel, and page-breaks between IPs.

### Named Rules
**The Fixed Grid Rule.** State restyles a row's tint and mark, never the grid. A failing row keeps its columns, widths and position; only its background and flag change.

## Elevation & Depth

Flat. There are no shadows; depth is conveyed by the ground-to-sheet value step, 1px hairlines, the strong hairline under table headers, and the sheet-alt tint for open or hovered rows. The metadata strip uses 1px inset box-shadows purely to draw shared hairlines between grid cells, not to lift anything.

### Named Rules
**The Ruled-Not-Lifted Rule.** If a surface needs separating, draw a hairline or step the tint. Never cast a shadow.

## Shapes

Nearly square. Controls, tables, the interpretation box and the plate use a 3px radius; the sheet uses 4px; legend keys 2px; validity bars 1px. Borders are 1px hairlines, with 1.5px strokes reserved for graph marks (today line, hatched and dashed bars, legend keys) and a 3px underline for the selected tab and the header rule. Icons are an authored 16px set on a 16px grid, 1.75 stroke, round caps and joins, inheriting currentColor.

## Components

### Buttons
- **Primary:** accent fill, accent-ink 700 text, 40px tall, 24px horizontal padding, 3px radius. Hover lightens to accent-hover; focus ring switches to white on the dark band; disabled drops to 65% opacity with a progress cursor. One per page.
- **Quiet:** sheet fill, strong hairline stroke, ink label text, 4px 10px padding, with an inline icon (Copy PEM). Hover darkens the stroke to ink.

### Inputs / Fields
- **Style:** on the dark band only: band-field fill, band-line stroke, 3px radius, 40px tall, mono text, labels above in Label type in band gray.
- **Focus:** 2px accent ring at 0 offset plus an accent stroke. Hover lifts the stroke to a lighter gray.
- **Error:** a pale red line below the form (bar-error on the band), announced as an alert.

### Navigation (IP tabs)
- Mono, Body Small, muted; each tab carries its status icon (labelled) plus the IP. Selected tab is ink, 600, with a 3px accent underline overlapping the strip's hairline. Scrolls horizontally when there are many IPs.

### Flags
- Word plus authored icon, Flag type, tinted by status. They sit in their own column in the result table and paths table, and inline as smaller 600-weight tags in certificate rows.

### Interpretation box
- Strong-hairline box on sheet-alt, 16px 24px padding, 3px radius. A fail, warn or pass state tints the fill to the status background and the stroke to a 40 to 45% status mix; the verdict sits in Headline type with a 22px icon, followed by a numbered fix list.

### Result table
- Columns Test | Result | Expected | Flag. Header row in Label type over a strong hairline; rows divided by hairlines. Fail and warn rows tint their cells to fail-bg or warn-bg and nothing else.

### Certificate rows
- Disclosure rows on a shared six-column grid (position, subject, issuer, expiry, flags, chevron), 48px minimum height. Hover and open states use sheet-alt; the chevron rotates 90 degrees over 160ms. The body is a key-value list and a scrollable PEM well (max 260px) with a Copy PEM button.

### Validity Range Graph (signature)
- Each certificate's validity is a bar drawn to scale on one shared time axis, with labels left and dates right. Bars are 10px ink at 82% opacity; trust-store roots not sent are dashed outlines; expiring-soon bars are solid warn; expired and not-yet-valid bars are hatched fail (135 degrees, 3px stripes) with a 1.5px fail stroke, so the state survives without colour. Bars running off the axis fade out on the clipped side. Short bars get a 10px minimum width (3px floor otherwise). A 1.5px ink today line crosses every row, labelled in bold ink on the axis.

### Paths Diagram Plate
- The Mermaid diagram sits on a light plate (plate token; #dfe5ea in dark) with plate-ink and plate-muted captions. The diagram reads top-down from roots to the leaf (edges labelled "issued"), a key listing only the styles the diagram uses (36 by 22px swatches drawn with the same border and hatching, plus a name and one line of meaning), and a paths table beneath listing route and terminal flag.

### Loading
- A 120 by 3px track with an accent segment sweeping over 1.1s; a 260ms rise reveals results. Both stop under reduced motion.

## Do's and Don'ts

### Do:
- **Do** keep the accent to the primary action, selected tab, focus ring and selection, and bar-edge to the header rule.
- **Do** keep brand colours in local config (THEME_COLORS), never in the shared stylesheet.
- **Do** call the root store "the trust store" in the interface, without naming its source.
- **Do** pair every status colour with its word and its icon shape; hatch expired bars.
- **Do** draw validity to scale on one shared axis with an ink today line.
- **Do** use the xs to 2xl type tokens and the 4px spacing scale; keep tabular numerals on.
- **Do** keep the diagram plate light in both schemes so the diagram palette stays true.
- **Do** meet WCAG 2.2 AA: text at 4.5:1, focus visible, keyboard-operable tabs, fold-outs and copy buttons, reduced motion respected.

### Don't:
- **Don't** use the accent as a status colour.
- **Don't** use red for anything that does not need a change.
- **Don't** let state change a row's grid, column widths or position; restyle tint and mark only.
- **Don't** put colour outside the flags, the validity graph and the diagram.
- **Don't** add kicker or eyebrow labels above headings.
- **Don't** add shadows, soft cards or a second type family.
