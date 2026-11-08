"use strict";
(() => {
  const $ = (sel) => document.querySelector(sel);
  const form = $("#check-form");
  const hostEl = $("#host");
  const portEl = $("#port");
  const ipsEl = $("#connect-ips");
  const submitEl = $("#submit");
  const errEl = $("#form-error");
  const results = $("#results");
  let diagramSeq = 0;

  const dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  function initMermaid() {
    if (window.mermaid) {
      window.mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: dark ? "dark" : "default",
        flowchart: { htmlLabels: true, curve: "basis" } });
    }
  }

  // ---------- DOM helper ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const pill = (status, text) => h("span", { class: `pill ${status}` }, text || status);

  const STATUS_WORD = { pass: "Pass", info: "Info", warn: "Warn", fail: "Fail" };
  const SOURCE_WORD = {
    dns: "DNS", config_override: "server DNS override", request_override: "your IP override", ip_literal: "IP literal",
  };

  // ---------- config ----------
  fetch("api/config").then((r) => r.json()).then((cfg) => {
    if (cfg.ipOverrideAllowed) $("#advanced").hidden = false;
    renderStoreInfo(cfg.trustStore);
  }).catch(() => { $("#store-info").textContent = ""; });

  function renderStoreInfo(ts) {
    if (!ts) return;
    const when = ts.loadedAt ? new Date(ts.loadedAt).toLocaleString() : "unknown";
    const src = ts.source && ts.source.startsWith("http") ? "CCADB (live)" : ts.source;
    $("#store-info").textContent = `Mozilla trust store: ${ts.count} roots · source: ${src} · loaded ${when}`;
  }

  // ---------- input ----------
  hostEl.addEventListener("input", () => {
    // Split a pasted host:port or URL.
    let v = hostEl.value.trim();
    const m = v.match(/^(?:https?:\/\/)?(\[[0-9a-fA-F:.]+\]|[^\/:\s]+):(\d{1,5})(?:\/.*)?$/);
    if (m) { hostEl.value = m[1].replace(/^\[|\]$/g, ""); portEl.value = m[2]; }
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    errEl.hidden = true;
    const host = hostEl.value.trim();
    const port = Number(portEl.value || 443);
    if (!host) return showFormError("Enter a hostname.");
    if (!Number.isInteger(port) || port < 1 || port > 65535) return showFormError("Port must be 1–65535.");
    const body = { host, port };
    const ips = (ipsEl.value || "").split(/[\s,]+/).filter(Boolean);
    if (ips.length && !$("#advanced").hidden) body.connectIPs = ips;

    submitEl.disabled = true;
    results.replaceChildren(h("div", { class: "notice" }, h("span", { class: "spinner" }), `Connecting to ${host}:${port}…`));
    try {
      const resp = await fetch("api/check", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        results.replaceChildren(h("div", { class: "banner fail" },
          h("h2", {}, resp.status === 429 ? "Slow down" : "Request failed"),
          h("p", {}, data.error || `HTTP ${resp.status}`)));
        return;
      }
      renderStoreInfo(data.trustStore);
      await render(data);
    } catch (e) {
      results.replaceChildren(h("div", { class: "banner fail" }, h("h2", {}, "Network error"), h("p", {}, String(e))));
    } finally {
      submitEl.disabled = false;
    }
  });

  function showFormError(msg) { errEl.textContent = msg; errEl.hidden = false; }

  // ---------- rendering ----------
  async function render(data) {
    const out = [];
    const r = data.resolution || {};
    const cons = data.consistency || {};
    out.push(h("div", { class: `banner ${cons.status || "info"}` },
      h("h2", {}, `${data.host}:${data.port}`),
      h("p", {}, `Resolved via ${SOURCE_WORD[r.source] || r.source}: `, h("span", { class: "mono" }, (r.ips || []).join(", ") || "none")),
      r.skipped && r.skipped.length ? h("p", {}, `Not tested (limit reached): `, h("span", { class: "mono" }, r.skipped.join(", "))) : null,
      h("p", {}, cons.detail || "")));

    const list = data.results || [];
    const tabs = h("div", { class: "tabs", role: "tablist" });
    const panels = [];
    list.forEach((res, i) => {
      const id = `panel-${i}`;
      const tab = h("button", { class: "tab", type: "button", role: "tab", "aria-controls": id, "aria-selected": i === 0 ? "true" : "false",
        onclick: () => select(i) }, h("span", { class: `dot ${res.overall || "info"}`, title: STATUS_WORD[res.overall] || "" }), res.ip);
      tabs.append(tab);
      const panel = h("div", { id, role: "tabpanel" });
      panel.hidden = i !== 0;
      panels.push({ tab, panel, res, rendered: false });
    });
    if (list.length > 1) out.push(tabs);
    out.push(...panels.map((p) => p.panel));
    results.replaceChildren(...out);

    async function select(i) {
      panels.forEach((p, j) => { p.tab.setAttribute("aria-selected", i === j ? "true" : "false"); p.panel.hidden = i !== j; });
      const p = panels[i];
      if (!p.rendered) { p.rendered = true; await renderIP(p.panel, p.res, data.host); }
    }
    if (panels.length) await select(0);
  }

  async function renderIP(panel, res, host) {
    if (res.denyReason) {
      panel.append(h("div", { class: "notice" }, h("strong", {}, "Not tested. "), res.denyReason));
      return;
    }
    if (res.error) {
      panel.append(h("div", { class: "notice" }, h("strong", {}, "Connection failed. "), res.error));
      return;
    }
    const a = res.analysis;
    const t = res.tls || {};
    panel.append(h("div", { class: "tls-meta" },
      h("span", {}, "IP ", h("b", { class: "mono" }, res.ip)),
      h("span", {}, "Protocol ", h("b", {}, t.version)),
      h("span", {}, "Cipher ", h("b", { class: "mono" }, t.cipherSuite)),
      t.alpn ? h("span", {}, "ALPN ", h("b", {}, t.alpn)) : null,
      h("span", {}, "SNI ", h("b", { class: "mono" }, t.sni || "(none — IP literal)")),
      h("span", {}, "Handshake ", h("b", {}, `${t.handshakeMs} ms`))));

    // Checks
    panel.append(h("div", { class: "checks" }, a.checks.map((c) => h("div", { class: `check ${c.status}` },
      h("h3", {}, pill(c.status, STATUS_WORD[c.status]), c.title),
      h("p", {}, c.detail),
      c.items && c.items.length ? h("ul", {}, c.items.map((it) => h("li", {}, it))) : null))));

    // Chain as presented
    const byId = {};
    for (const c of [...a.chain, ...(a.storeRoots || [])]) if (!byId[c.id]) byId[c.id] = c;
    panel.append(h("h2", { class: "section" }, `Chain as sent (${a.chain.length} certificate${a.chain.length === 1 ? "" : "s"})`));
    panel.append(h("div", { class: "certs" }, a.chain.map((c) => certCard(c))));
    if (a.storeRoots && a.storeRoots.length) {
      panel.append(h("h2", { class: "section" }, "Roots from the Mozilla store (not sent by the server)"));
      panel.append(h("div", { class: "certs" }, a.storeRoots.map((c) => certCard(c))));
    }

    // Diagram + paths
    panel.append(h("h2", { class: "section" }, `Chain paths (${a.paths.length})`));
    const diag = h("div", { class: "diagram" }, "Rendering diagram…");
    panel.append(diag);
    panel.append(h("div", { class: "legend" },
      legend("#1a7f37", "#dcfce7", "On a trusted path"), legend("#1a7f37", "#dcfce7", "Mozilla root not sent", true),
      legend("#b45309", "#fef3c7", "Pending distrust / alternate path"), legend("#b91c1c", "#fee2e2", "Expired / unrelated"),
      legend("#64748b", "#eef2f7", "Other")));
    panel.append(h("ol", { class: "paths" }, a.paths.map((p) => pathItem(p, byId))));

    try {
      if (!window.mermaid) throw new Error("Mermaid failed to load");
      initMermaid();
      const { svg } = await window.mermaid.render(`chain-diagram-${++diagramSeq}`, a.mermaid);
      diag.innerHTML = svg; // produced by Mermaid with securityLevel "strict"
    } catch (e) {
      diag.replaceChildren(h("p", {}, `Diagram unavailable: ${e.message || e}`), h("pre", { class: "pem" }, a.mermaid));
    }
  }

  function legend(stroke, fill, text, dashed) {
    const i = h("i");
    i.style.borderColor = stroke; i.style.background = fill;
    if (dashed) i.style.borderStyle = "dashed";
    return h("span", {}, i, text);
  }

  function pathItem(p, byId) {
    const parts = [];
    p.nodes.forEach((id, i) => {
      if (i) parts.push(h("span", { class: "arrow", "aria-hidden": "true" }, "→"));
      const c = byId[id];
      parts.push(h("span", {}, c ? (c.index >= 0 ? `#${c.index} ` : "") + c.subjectCN : id));
    });
    if (p.terminal === "incomplete") {
      parts.push(h("span", { class: "arrow" }, "→"), h("span", {}, `missing: ${p.missingIssuer}`));
    }
    const term = { mozilla_root: ["pass", "Mozilla root"], untrusted_root: ["fail", "Untrusted root"], incomplete: ["fail", "Incomplete"] }[p.terminal];
    return h("li", { class: p.best ? "best" : "" },
      p.best ? pill("pass", "Best") : null,
      pill(term[0], term[1]),
      !p.timeValid ? pill("fail", "Validity problem") : null,
      p.pendingDistrust ? pill("warn", "Pending distrust") : null,
      ...parts);
  }

  function fmtDate(s) { return s ? new Date(s).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : ""; }

  function certCard(c) {
    const badges = [];
    if (c.index === 0) badges.push(pill("neutral", "Leaf"));
    else if (c.isCA) badges.push(pill("neutral", c.selfSigned ? "Root CA" : "Intermediate CA"));
    if (c.inMozilla) badges.push(pill("pass", "Mozilla root"));
    else if (c.selfSigned) badges.push(pill("fail", "Untrusted self-signed"));
    if (c.onTrustedPath) badges.push(pill("pass", "Trusted path"));
    const vs = { valid: ["pass", "Valid"], expired: ["fail", "Expired"], not_yet_valid: ["fail", "Not yet valid"],
      expiring_soon: ["warn", `Expires in ${c.daysRemaining}d`] }[c.status];
    badges.push(pill(vs[0], vs[1]));
    if (c.extraneous === "unrelated") badges.push(pill("fail", "Unrelated CA"));
    if (c.extraneous === "duplicate") badges.push(pill("warn", `Duplicate of #${c.duplicateOf}`));
    if (c.extraneous === "alternate_path") badges.push(pill("warn", "Not needed for Mozilla"));
    if (c.pendingDistrust) badges.push(pill("warn", "Pending distrust"));

    const rows = [
      ["Subject", c.subject], ["Issuer", c.issuer], ["Serial", c.serial, true],
      ["Not before", fmtDate(c.notBefore)], ["Not after", `${fmtDate(c.notAfter)} (${c.daysRemaining} days)`],
      ["Public key", `${c.keyAlgorithm}${c.keySize ? ` ${c.keySize}-bit` : ""}`], ["Signature", c.signatureAlgorithm],
      ["SHA-256", c.sha256, true], ["SHA-1", c.sha1, true],
      ["Subject Key ID", c.subjectKeyId, true], ["Authority Key ID", c.authorityKeyId, true],
      ["CA", c.isCA ? `yes${c.maxPathLen !== undefined && c.maxPathLen !== null ? `, path length ≤ ${c.maxPathLen}` : ""}` : "no"],
      ["DNS names", (c.dnsNames || []).join(", ")], ["IP addresses", (c.ipAddresses || []).join(", ")],
      ["Emails", (c.emails || []).join(", ")], ["URIs", (c.uris || []).join(", ")],
      ["Key usage", (c.keyUsage || []).join(", ")], ["Extended key usage", (c.extKeyUsage || []).join(", ")],
      ["Policies", (c.policies || []).join(", "), true],
      ["OCSP", (c.ocspServers || []).join(", ")], ["CA issuers", (c.issuingUrls || []).join(", ")],
      ["CRL", (c.crlDistributionPoints || []).join(", ")],
    ];
    if (c.pendingDistrust) {
      const pd = c.pendingDistrust;
      rows.unshift(["Pending distrust", [pd.date, pd.note].filter(Boolean).join(" — ") || "flagged"]);
    }
    const dl = h("dl", { class: "kv" });
    for (const [k, v, mono] of rows) {
      if (!v) continue;
      dl.append(h("dt", {}, k), h("dd", { class: mono ? "mono" : "" }, v));
    }
    const copyBtn = h("button", { class: "ghost", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(c.pem); copyBtn.textContent = "Copied"; }
      catch { copyBtn.textContent = "Copy failed"; }
      setTimeout(() => { copyBtn.textContent = "Copy PEM"; }, 1500);
    } }, "Copy PEM");

    return h("details", { class: "cert" },
      h("summary", {},
        h("span", { class: "pos", title: c.index >= 0 ? `Position ${c.index} as sent` : "From Mozilla store" }, c.index >= 0 ? `#${c.index}` : "store"),
        h("span", { class: "cert-subject" }, c.subjectCN),
        h("span", { class: "cert-issuer" }, "Issued by ", c.issuerCN),
        h("span", { class: "badges" }, badges)),
      h("div", { class: "cert-body" }, dl,
        h("div", { class: "pem-head" }, h("strong", {}, "PEM"), copyBtn),
        h("pre", { class: "pem" }, c.pem)));
  }

  const params = new URLSearchParams(location.search);
  if (params.get("host")) {
    hostEl.value = params.get("host");
    if (params.get("port")) portEl.value = params.get("port");
  }
})();
