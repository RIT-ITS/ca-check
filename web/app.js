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
  let mermaidReady = false;
  let viewSeq = 0;
  // Versioned URL of the diagram library, set on this script's tag by the server.
  const MERMAID_SRC = (document.currentScript && document.currentScript.dataset.mermaid) || "vendor/mermaid.min.js";

  // The diagram library is large, so it loads when the first check starts,
  // not with the page.
  let mermaidLoading = null;
  function loadMermaid() {
    if (window.mermaid) return Promise.resolve();
    if (!mermaidLoading) {
      mermaidLoading = new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = MERMAID_SRC;
        s.onload = () => resolve();
        s.onerror = () => { mermaidLoading = null; reject(new Error("the diagram library did not load")); };
        document.head.append(s);
      });
    }
    return mermaidLoading;
  }

  // Short messages for screen readers (WCAG 4.1.3). Clearing first makes a
  // repeated message ("Copied") announce again.
  const announceEl = document.getElementById("announce");
  function announce(msg) {
    if (!announceEl) return;
    announceEl.textContent = "";
    setTimeout(() => { announceEl.textContent = msg; }, 60);
  }

  // Give every id inside a rendered view a unique prefix and update the
  // references to them, so several IP panels (and RSA/ECDSA views) never
  // share heading ids.
  function scopeIds(root, prefix) {
    const map = new Map();
    root.querySelectorAll("[id]").forEach((el) => {
      const id = `${prefix}-${el.id}`;
      map.set(el.id, id);
      el.id = id;
    });
    for (const attr of ["aria-labelledby", "aria-describedby", "aria-controls", "for"]) {
      root.querySelectorAll(`[${attr}]`).forEach((el) => {
        el.setAttribute(attr, el.getAttribute(attr).split(/\s+/).map((v) => map.get(v) || v).join(" "));
      });
    }
  }

  // Phone layouts restyle tables as stacked blocks; explicit roles keep
  // their row and column structure for screen readers.
  function tableRoles(table) {
    table.setAttribute("role", "table");
    table.querySelectorAll("thead, tbody").forEach((g) => g.setAttribute("role", "rowgroup"));
    table.querySelectorAll("tr").forEach((r) => r.setAttribute("role", "row"));
    table.querySelectorAll("th").forEach((c) => c.setAttribute("role", c.getAttribute("scope") === "row" ? "rowheader" : "columnheader"));
    table.querySelectorAll("td").forEach((c) => c.setAttribute("role", "cell"));
    return table;
  }

  // ---------- DOM helpers ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "style") el.setAttribute("style", v);
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  // Authored icon set: 16px grid, 1.75 stroke.
  const ICON_PATHS = {
    pass: ["M3.5 8.5l3 3 6-7"],
    fail: ["M5.2 1.5h5.6l3.7 3.7v5.6l-3.7 3.7H5.2L1.5 10.8V5.2z", "M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4"],
    warn: ["M8 1.8l6.6 11.7H1.4z", "M8 6.2v3.3", "M8 11.6v.1"],
    info: ["M8 1.6a6.4 6.4 0 1 1 0 12.8A6.4 6.4 0 0 1 8 1.6z", "M8 7.2v4", "M8 4.8v.1"],
    copy: ["M5.5 5.5h7v8h-7z", "M3.5 10.5v-8h7"],
    chev: ["M6 3.5l4.5 4.5L6 12.5"],
  };
  const NS = "http://www.w3.org/2000/svg";
  function icon(name, label) {
    const s = document.createElementNS(NS, "svg");
    s.setAttribute("class", "i");
    s.setAttribute("viewBox", "0 0 16 16");
    if (label) { s.setAttribute("role", "img"); s.setAttribute("aria-label", label); }
    else s.setAttribute("aria-hidden", "true");
    for (const d of ICON_PATHS[name]) {
      const p = document.createElementNS(NS, "path");
      p.setAttribute("d", d);
      s.append(p);
    }
    return s;
  }

  const FLAG_WORD = { pass: "Pass", info: "Note", warn: "Warn", fail: "Fail" };
  const flag = (status) => h("span", { class: `flag ${status}` }, icon(status), FLAG_WORD[status] || status);

  const SOURCE_WORD = {
    dns: "DNS", config_override: "server DNS override", request_override: "your IP override", ip_literal: "IP literal",
  };

  // What each test expects, phrased as a reference value.
  const EXPECTED = {
    mozilla_root: "Every trust store checked trusts at least one path",
    order: "Leaf first, each certificate followed by its issuer",
    validity: "Every certificate on the path is currently valid",
    extra_certs: "Only the leaf and the intermediates it needs",
    root_sent: "Root not sent (clients already have it)",
    pending_distrust: "No CA on the path is scheduled to lose trust",
    revocation: "No certificate on the path is revoked (OCSP or CRL)",
    ocsp_stapling: "Stapled response is valid, or none is required",
    hostname: "Leaf certificate covers the hostname",
  };

  // ---------- trust stores ----------
  const STORES = ["apple", "chrome", "microsoft", "mozilla"];
  const STORE_LABEL = { apple: "Apple", chrome: "Chrome", microsoft: "Microsoft", mozilla: "Mozilla" };
  // Why each store matters, for stores whose reach isn't obvious from the name.
  const STORE_TIP = {
    mozilla: "Mozilla's list is not only for Firefox. Most Linux distributions, and tools such as Python (certifi), Node.js and curl's CA bundle, use it as their list of trusted roots.",
  };
  // A store name, with its explanation as a tooltip that also works with the
  // keyboard and screen readers.
  function storeName(store) {
    const label = STORE_LABEL[store] || store;
    const tip = STORE_TIP[store];
    if (!tip) return label;
    return h("span", { class: "tip", tabindex: "0", "data-tip": tip }, label, h("span", { class: "sr" }, ` (${tip})`));
  }
  // Text that starts with a store name ("Mozilla: no trusted path") gets the
  // name's tooltip.
  function storeText(text) {
    const m = /^(Apple|Chrome|Microsoft|Mozilla)\b/.exec(text);
    if (!m) return text;
    return [storeName(m[1].toLowerCase()), text.slice(m[1].length)];
  }
  const STORE_WORD = { trusted: "trusted", limited: "limited", untrusted: "not trusted", absent: "not included" };
  // items: [{store, status, required}] with status trusted | limited | untrusted | absent.
  function storeList(items) {
    return h("ul", { class: "stores" }, items.map((s) => {
      const st = s.status === "trusted" ? "pass" : s.status === "limited" ? "warn"
        : s.status === "untrusted" && s.required !== false ? "fail" : "neutral";
      return h("li", { class: `tag ${st}` }, st !== "neutral" ? icon(st) : null,
        storeName(s.store), h("span", { class: "store-word" }, STORE_WORD[s.status] + (s.required === false ? " (not required)" : "")));
    }));
  }

  // ---------- config ----------
  fetch("api/config").then((r) => r.json()).then((cfg) => {
    if (cfg.ipOverrideAllowed) $("#advanced").hidden = false;
    renderStoreInfo(cfg.trustStore);
    // Only on the start page; a check result already explains itself.
    if (cfg.trustStore && !cfg.trustStore.count && !results.querySelector(".panel, .notice")) {
      results.prepend(h("div", { class: "sheet notice warn no-data" },
        h("h2", {}, "Checks are unavailable for now"),
        h("p", {}, "This server has no trust store data yet, so it cannot tell whether a chain is trusted. "
          + "It downloads the data from CCADB and retries automatically"
          + (cfg.trustStore.nextAttempt ? `; the next try is at ${fmtDateTime(cfg.trustStore.nextAttempt)}` : "")
          + ". Reload this page in a few minutes.")));
    }
  }).catch(() => { $("#store-info").textContent = ""; });

  function renderStoreInfo(ts) {
    if (!ts) return;
    const el = $("#store-info");
    const retry = ts.nextAttempt ? ` Next try ${fmtDateTime(ts.nextAttempt)}.` : "";
    if (!ts.count) {
      el.replaceChildren(`No trust store data loaded. The download from CCADB failed and is retried automatically.${retry}`);
      return;
    }
    const known = ts.loadedAt && !ts.loadedAt.startsWith("0001");
    const loaded = ts.source && !ts.source.startsWith("embedded")
      ? `Downloaded ${known ? fmtDateTime(ts.loadedAt) : "at an unknown time"}.`
      : `Built-in copy${known ? ` from ${ts.loadedAt.slice(0, 10)}` : ""}.`;
    const failing = ts.refreshFailing ? ` The latest download from CCADB failed, so this data may be out of date.${retry}` : "";
    const counts = ts.stores || {};
    const parts = [];
    STORES.filter((s) => counts[s]).forEach((s, i, all) => {
      parts.push(storeName(s), ` ${counts[s]}`, i < all.length - 1 ? ", " : "");
    });
    el.replaceChildren(...(parts.length
      ? ["Trust stores: ", ...parts, " roots. ", loaded + failing]
      : [`Trust store: ${ts.count} roots. `, loaded + failing]));
  }

  // ---------- input ----------
  hostEl.addEventListener("input", () => {
    const v = hostEl.value.trim();
    const m = v.match(/^(?:https?:\/\/)?(\[[0-9a-fA-F:.]+\]|[^\/:\s]+):(\d{1,5})(?:\/.*)?$/);
    if (m) { hostEl.value = m[1].replace(/^\[|\]$/g, ""); portEl.value = m[2]; }
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    errEl.hidden = true;
    const host = hostEl.value.trim();
    const port = Number(portEl.value || 443);
    if (!host) return showFormError("Enter a hostname or IP address to check.");
    if (!Number.isInteger(port) || port < 1 || port > 65535) return showFormError("Port must be a whole number from 1 to 65535.");
    const body = { host, port };
    if (starttls) body.starttls = starttls;
    const ips = (ipsEl.value || "").split(/[\s,]+/).filter(Boolean);
    if (ips.length && !$("#advanced").hidden) body.connectIPs = ips;

    submitEl.disabled = true;
    loadMermaid().catch(() => {}); // in parallel with the check; drawing reports a failure
    announce(`Checking ${host}:${port}…`);
    results.setAttribute("aria-busy", "true");
    results.replaceChildren(h("div", { class: "sheet" },
      h("div", { class: "loading" }, h("span", { class: "meterbar", "aria-hidden": "true" }), `Connecting to ${host}:${port} and reading its chain…`)));
    try {
      const resp = await fetch("api/check", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        const retry = resp.headers.get("Retry-After");
        results.replaceChildren(h("div", { class: "sheet notice fail reveal" },
          h("h2", {}, resp.status === 429 ? "Too many checks from your address" : "The check could not run"),
          h("p", {}, resp.status === 429
            ? `Wait ${retry || "a few"} seconds, then try again.`
            : (data.error || `The server answered HTTP ${resp.status}.`))));
        announce(resp.status === 429 ? `Too many checks. Wait ${retry || "a few"} seconds, then try again.` : `The check could not run. ${data.error || ""}`);
        return;
      }
      renderStoreInfo(data.trustStore);
      const url = new URL(location.href);
      url.searchParams.set("host", host);
      url.searchParams.set("port", String(port));
      if (starttls) url.searchParams.set("starttls", starttls); else url.searchParams.delete("starttls");
      saveHistory(url, data);
      await render(data);
      announce(finishedText(data));
    } catch (e) {
      results.replaceChildren(h("div", { class: "sheet notice fail reveal" },
        h("h2", {}, "Could not reach CA Chain Check"), h("p", {}, `Check your connection and try again. (${e.message || e})`)));
      announce("Could not reach CA Chain Check. Check your connection and try again.");
    } finally {
      submitEl.disabled = false;
      results.removeAttribute("aria-busy");
    }
  });

  // One sentence summing up a finished check, for the status announcement.
  function finishedText(data) {
    const list = data.results || [];
    const tested = list.filter((r) => r.analysis);
    let overall = "";
    for (const r of list) overall = worse(overall, r.overall || "info");
    const word = !tested.length ? "no chain could be read"
      : overall === "fail" ? "the chain is broken" : overall === "warn" ? "the chain works, with warnings" : "the chain is correct";
    const n = list.length;
    return `Check finished for ${data.host}:${data.port}: ${word}. ${n} address${n === 1 ? "" : "es"} tested. Results follow.`;
  }
  function worse(a, b) {
    const rank = { "": -1, pass: 0, info: 1, warn: 2, fail: 3 };
    return (rank[b] ?? 0) > (rank[a] ?? -1) ? b : a;
  }

  function showFormError(msg) { errEl.textContent = msg; errEl.hidden = false; hostEl.focus(); }

  // ---------- formatting ----------
  const fmtDate = (s) => (s ? new Date(s).toISOString().slice(0, 10) : "");
  function fmtDateTime(s) {
    const d = new Date(s);
    return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
  }
  function fmtDays(n) {
    if (n < 0) return `expired ${-n} day${n === -1 ? "" : "s"} ago`;
    if (n < 730) return `${n} day${n === 1 ? "" : "s"} left`;
    return `${(n / 365).toFixed(1)} years left`;
  }
  const certLabel = (c) => (c.index >= 0 ? `#${c.index} ${c.subjectCN}` : `${c.subjectCN} (trust store)`);

  // ---------- empty state ----------
  function renderIntro() {
    const rows = Object.entries(EXPECTED).filter(([id]) => id !== "root_sent");
    const titles = {
      mozilla_root: "Chains to a trusted root", order: "Certificates in issuance order",
      validity: "Validity periods", extra_certs: "No unnecessary certificates",
      pending_distrust: "No CAs pending loss of trust", revocation: "Not revoked", ocsp_stapling: "OCSP stapling", hostname: "Hostname match",
    };
    results.replaceChildren(h("div", { class: "sheet intro" },
      h("h1", {}, "Check the certificate chain a server sends"),
      h("p", {}, "Enter a host above. CA Chain Check connects to it (with SNI), reads the certificate chain it sends without trusting it, and runs the tests below. Anything that fails comes with a fix. Each IP address behind the name is tested on its own."),
      tableRoles(h("table", { class: "results" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Test"), h("th", { scope: "col" }, "Expected"))),
        h("tbody", {}, rows.map(([id, exp]) => h("tr", {},
          h("td", { class: "test" }, titles[id]), h("td", { class: "expected", style: "width:auto" }, exp))))))));
  }

  // ---------- rendering ----------
  async function render(data) {
    const r = data.resolution || {};
    const cons = data.consistency || {};
    const list = data.results || [];
    const sheet = h("div", { class: "sheet reveal" });

    const first = list.find((x) => x.tls) || {};
    const head = h("div", { class: "report-head" },
      h("h1", {}, `${data.host}:${data.port}`),
      h("p", { class: "resolution" },
        `${list.length} address${list.length === 1 ? "" : "es"} from ${SOURCE_WORD[r.source] || r.source}`,
        r.skipped && r.skipped.length ? `, ${r.skipped.length} not tested (limit reached)` : "",
        r.droppedIPv6 && r.droppedIPv6.length ? `, ${r.droppedIPv6.length} IPv6 not tested (IPv6 is off on this server)` : r.ipv4Only ? ", IPv4 only" : "",
        cons.detail && list.length > 1 ? `. ${cons.detail}` : "."),
      h("dl", { class: "meta" },
        metaItem("Checked", fmtDateTime(data.checkedAt)),
        metaItem("Trust store", data.trustStore ? `${data.trustStore.count} roots` : "unknown"),
        first.tls ? metaItem("SNI", first.tls.sni || "none (IP literal)", true, true) : null,
        list.length > 1 ? metaItem("Across IPs", cons.status === "warn" ? "Different chains" : cons.status === "pass" ? "Identical chains" : "Not comparable") : null));
    sheet.append(head);

    const tabs = h("div", { class: "tabs", role: "tablist", "aria-label": "Tested IP addresses" });
    const panels = [];
    list.forEach((res, i) => {
      const id = `panel-${i}`;
      const st = res.overall || "info";
      const tab = h("button", {
        class: "tab", type: "button", role: "tab", id: `tab-${i}`, "aria-controls": id,
        "aria-selected": i === 0 ? "true" : "false", tabindex: i === 0 ? "0" : "-1",
        onclick: () => select(i),
        onkeydown: (e) => {
          const k = e.key;
          if (k !== "ArrowRight" && k !== "ArrowLeft" && k !== "Home" && k !== "End") return;
          e.preventDefault();
          const n = k === "Home" ? 0 : k === "End" ? panels.length - 1 : (i + (k === "ArrowRight" ? 1 : -1) + panels.length) % panels.length;
          select(n); panels[n].tab.focus();
        },
      }, h("span", { class: `flag ${st}` }, icon(st, FLAG_WORD[st])), res.ip);
      tabs.append(tab);
      const panel = h("div", { id, role: "tabpanel", "aria-labelledby": `tab-${i}`, class: "panel" });
      panel.hidden = i !== 0;
      panels.push({ tab, panel, res, rendered: false });
    });
    if (list.length > 1) sheet.append(tabs);
    panels.forEach((p) => sheet.append(p.panel));
    results.replaceChildren(sheet);

    async function select(i) {
      panels.forEach((p, j) => {
        p.tab.setAttribute("aria-selected", i === j ? "true" : "false");
        p.tab.tabIndex = i === j ? 0 : -1;
        p.panel.hidden = i !== j;
      });
      const p = panels[i];
      if (!p.rendered) { p.rendered = true; await renderIP(p.panel, p.res, data.host); }
    }
    if (panels.length) await select(0);
  }

  function metaItem(label, value, mono, wide) {
    return h("div", { class: wide ? "wide" : "" }, h("dt", {}, label), h("dd", { class: mono ? "mono" : "" }, value));
  }

  function stapleWord(s) {
    if (!s || !s.present) return s && s.mustStaple ? "None (required)" : "None";
    return { good: "Good", revoked: "Revoked", unknown: "Unknown to responder", error: "Not usable" }[s.status] || s.status;
  }

  const KEY_NAME = { rsa: "RSA", ecdsa: "ECDSA", other: "Other" };

  async function renderIP(panel, res, host) {
    if (res.denyReason) {
      panel.append(notice("info", "This address was not tested", res.denyReason));
      return;
    }
    if (res.error) {
      panel.append(notice("fail", "Could not complete a TLS handshake", res.error));
      return;
    }
    const views = [{ keyType: res.keyType, tls: res.tls, analysis: res.analysis }];
    if (res.alternate) views.push({ keyType: res.alternate.keyType, tls: res.alternate.tls, analysis: res.alternate.analysis });
    if (views.length === 1) {
      await renderView(panel, res, views[0], host, false);
      return;
    }
    // Two certificates: a switch between them, each rendered when first shown.
    const bodies = views.map(() => h("div", {}));
    const done = [];
    const btns = views.map((v, i) => {
      const st = v.analysis.overall || "info";
      return h("button", { type: "button", class: "seg", "aria-pressed": i === 0 ? "true" : "false", onclick: () => show(i) },
        h("span", { class: `flag ${st}` }, icon(st, FLAG_WORD[st])), `${KEY_NAME[v.keyType] || v.keyType} certificate`);
    });
    async function show(i) {
      btns.forEach((b, j) => b.setAttribute("aria-pressed", i === j ? "true" : "false"));
      bodies.forEach((b, j) => { b.hidden = i !== j; });
      if (!done[i]) { done[i] = true; await renderView(bodies[i], res, views[i], host, true); }
    }
    panel.append(h("div", { class: "keytypes" },
      h("p", {}, "This server has two certificates. Each client gets the one that matches what it supports."),
      h("div", { class: "seg-group", role: "group", "aria-label": "Certificate to show" }, btns)), ...bodies);
    await show(0);
  }

  async function renderView(panel, res, v, host, two) {
    const a = v.analysis;
    const t = v.tls || {};
    const byId = {};
    for (const c of [...a.chain, ...(a.storeRoots || [])]) if (!byId[c.id]) byId[c.id] = c;
    const kt = KEY_NAME[v.keyType] || v.keyType;
    const onlyOne = !two && /^The server has only/.test(res.keyTypeNote || "");

    panel.append(h("dl", { class: "meta" },
      metaItem("IP address", res.ip, true), metaItem("Protocol", t.version),
      metaItem("Cipher suite", t.cipherSuite, true, true), metaItem("ALPN", t.alpn || "none"),
      metaItem("Handshake", `${t.handshakeMs} ms`),
      v.keyType ? metaItem("Key type", onlyOne ? `${kt} only` : kt) : null,
      metaItem("OCSP staple", stapleWord(a.staple)),
      t.starttls ? metaItem("STARTTLS", protoName(t.starttls)) : null));
    if (!two && res.keyTypeNote && !onlyOne) panel.append(h("p", { class: "keynote" }, res.keyTypeNote));

    const view = h("div", {},
      interpretation(a, host, t.starttls, two ? kt : ""), resultTable(a), validitySection(a), chainSection(a));
    const pathsSec = pathsSection(a, byId);
    view.append(pathsSec.el);
    scopeIds(view, `v${++viewSeq}`);
    panel.append(view);
    await pathsSec.draw();
  }

  function notice(status, title, text) {
    return h("div", { class: `interp ${status === "info" ? "" : status}` },
      h("p", { class: "verdict" }, icon(status), title), h("p", { style: "margin:8px 0 0" }, text));
  }

  // ---------- interpretation: verdict + fixes ----------
  function interpretation(a, host, viaStartTLS, keyLabel) {
    const checks = Object.fromEntries(a.checks.map((c) => [c.id, c]));
    const fixes = [];
    const add = (status, text, items) => fixes.push({ status, text, items });

    const mr = checks.mozilla_root;
    if (mr && mr.status === "fail") {
      if (/self-signed root/.test(mr.detail)) add("fail", "Get a certificate from a publicly trusted CA, or install your private root on every client that connects.");
      else add("fail", "Configure the server to send the missing intermediate certificate after the leaf.", mr.items);
    } else if (mr && mr.status === "warn") {
      add("warn", "Some trust stores don't trust this chain, so clients that use them will reject it. Use a CA whose root is in every store:", mr.items);
    }
    const ord = checks.order;
    if (ord && ord.status !== "pass") add(ord.status, "Reorder the chain file so each certificate is followed by its issuer:", ord.items);
    const val = checks.validity;
    if (val && val.status !== "pass") {
      // Certificates off the best path are covered by the "remove" fix, not renewal.
      const onPath = (val.items || []).filter((it) => !/not on the best path/.test(it));
      const exItems = (checks.extra_certs && checks.extra_certs.items) || [];
      // Items read "<certificate>: <problem>"; the problem text never contains ": ".
      const certOf = (s) => s.slice(0, s.lastIndexOf(": "));
      const offPath = (val.items || []).filter((it) => /not on the best path/.test(it) && !exItems.some((e) => certOf(e) === certOf(it)));
      const items = [...onPath, ...offPath];
      if (items.length) add(onPath.length ? val.status : "warn", val.status === "fail" && onPath.length ? "Renew or replace the out-of-date certificate:" : "Plan renewal:", items);
    }
    const ex = checks.extra_certs;
    if (ex && ex.status !== "pass") add(ex.status, "Remove these certificates from the chain file:", ex.items);
    const rv = checks.revocation;
    if (rv && rv.status === "fail") add("fail", "Replace the revoked certificate. Clients that check revocation will reject it:", rv.items);
    const os = checks.ocsp_stapling;
    if (os && os.status !== "pass") {
      if (a.staple && a.staple.status === "revoked") add("fail", "The stapled OCSP response says the certificate is revoked. Replace the certificate.");
      else if (a.staple && a.staple.present) add(os.status, "Fix OCSP stapling so the server sends a current response for this certificate, or turn stapling off if the certificate doesn't require it.");
      else add(os.status, "Turn on OCSP stapling. The certificate requires it (Must-Staple).");
    }
    const pd = checks.pending_distrust;
    if (pd && pd.status !== "pass") add(pd.status, "Switch to a certificate whose chain doesn't include these CAs:", pd.items);
    const hn = checks.hostname;
    if (hn && hn.status === "fail") add("fail", `Reissue the certificate with ${host} in its subject alternative names.`);
    const rs = checks.root_sent;
    if (rs) add("info", "Optional: drop the root from the chain file to shorten the handshake.", rs.items);

    const fails = fixes.filter((f) => f.status === "fail").length;
    const warns = fixes.filter((f) => f.status === "warn").length;
    let verdict;
    if (a.overall === "fail") verdict = `Chain is broken: ${fails} required fix${fails === 1 ? "" : "es"}`;
    else if (a.overall === "warn") verdict = `Chain works, with ${warns} warning${warns === 1 ? "" : "s"}`;
    else verdict = "Chain is correct";
    const st = a.overall === "info" ? "pass" : a.overall;

    fixes.sort((x, y) => ({ fail: 0, warn: 1, info: 2 })[x.status] - ({ fail: 0, warn: 1, info: 2 })[y.status]);
    const copyLabel = h("span", {}, "Copy summary");
    const copyBtn = h("button", { class: "btn-quiet", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(summaryText(a, host, viaStartTLS, verdict, fixes, keyLabel)); copyLabel.textContent = "Copied"; announce("Summary copied"); }
      catch { copyLabel.textContent = "Copy failed"; announce("Copy failed"); }
      setTimeout(() => { copyLabel.textContent = "Copy summary"; }, 1600);
    } }, icon("copy"), copyLabel);
    return h("section", { class: `interp ${st}`, "aria-labelledby": "interp-h" },
      h("div", { class: "interp-top" },
        h("h2", { class: "verdict", id: "interp-h" }, icon(st), h("span", { class: "sr" }, "Interpretation: "), verdict),
        copyBtn),
      fixes.length
        ? h("ol", { class: "fixes" }, fixes.map((f) => h("li", {},
          h("span", { class: `flag ${f.status}`, style: "margin-right:8px" }, icon(f.status), FLAG_WORD[f.status]), f.text,
          f.items && f.items.length ? h("ul", {}, f.items.map((it) => h("li", {}, storeText(it)))) : null)))
        : h("p", { style: "margin:8px 0 0" }, "Every test passed. Nothing needs to change."));
  }

  function summaryText(a, host, viaStartTLS, verdict, fixes, keyLabel) {
    const lines = [`CA Chain Check: ${host}`, `Verdict: ${verdict}`];
    if (keyLabel) lines.splice(1, 0, `Certificate: ${keyLabel}`);
    if (viaStartTLS) lines.splice(1, 0, `Connection: STARTTLS (${protoName(viaStartTLS)})`);
    if (fixes.length) {
      lines.push("", "Fixes:");
      fixes.forEach((f, i) => {
        lines.push(`${i + 1}. [${FLAG_WORD[f.status].toUpperCase()}] ${f.text}`);
        (f.items || []).forEach((it) => lines.push(`   - ${it}`));
      });
    }
    lines.push("", "Results:");
    a.checks.forEach((c) => lines.push(`- [${FLAG_WORD[c.status].toUpperCase()}] ${c.title}: ${c.detail}`));
    lines.push("", "Chain as sent:");
    a.chain.forEach((c) => lines.push(`#${c.index} ${c.subjectCN} (issuer: ${c.issuerCN}; expires ${fmtDate(c.notAfter)}; sha256 ${c.sha256})`));
    return lines.join("\n");
  }

  // ---------- result table ----------
  function resultTable(a) {
    return h("section", { "aria-labelledby": "res-h" },
      h("h2", { class: "sec", id: "res-h" }, "Results"),
      tableRoles(h("table", { class: "results" },
        h("thead", {}, h("tr", {},
          h("th", { scope: "col" }, "Test"), h("th", { scope: "col" }, "Result"),
          h("th", { scope: "col" }, "Expected"), h("th", { scope: "col" }, "Flag"))),
        h("tbody", {}, a.checks.map((c) => h("tr", { class: c.status },
          h("td", { class: "test" }, c.title),
          h("td", { class: "result" }, c.detail,
            // The store list below says the same as the warning's items.
            c.items && c.items.length && !(c.id === "mozilla_root" && c.status === "warn") ? h("ul", {}, c.items.map((it) => h("li", {}, storeText(it)))) : null,
            c.id === "mozilla_root" && a.trustStores && a.trustStores.length && c.status !== "fail" ? storeList(a.trustStores) : null),
          h("td", { class: "expected" }, EXPECTED[c.id] || ""),
          h("td", { class: "flagcell" }, flag(c.status))))))));
  }

  // ---------- validity reference-range graph ----------
  function validitySection(a) {
    const certs = [];
    const seen = new Set();
    for (const c of [...a.chain, ...(a.storeRoots || [])]) {
      if (seen.has(c.id)) continue;
      seen.add(c.id);
      certs.push(c);
    }
    const now = Date.now();
    const YEAR = 365.25 * 864e5;
    let lo = Math.min(...certs.map((c) => +new Date(c.notBefore)), now);
    let hi = Math.max(...certs.map((c) => +new Date(c.notAfter)), now);
    lo = Math.max(lo, now - 12 * YEAR);
    hi = Math.min(hi, now + 12 * YEAR);
    if (hi - lo < 120 * 864e5) { lo = now - 60 * 864e5; hi = now + 60 * 864e5; }
    const pct = (t) => ((Math.min(Math.max(t, lo), hi) - lo) / (hi - lo)) * 100;

    const rows = certs.map((c) => {
      const nb = +new Date(c.notBefore), na = +new Date(c.notAfter);
      const left = pct(nb), width = Math.max(pct(na) - left, 0.8);
      const short = pct(na) - left < 1.5;
      const cls = ["bar-v", c.status, c.index < 0 ? "store" : "", short ? "short" : "", !short && nb < lo ? "cut-l" : "", !short && na > hi ? "cut-r" : ""].join(" ");
      const dateCls = c.status === "expired" || c.status === "not_yet_valid" ? "fail" : c.status === "expiring_soon" ? "warn" : "";
      return h("div", { class: "range-row" },
        h("div", { class: "range-label", title: c.subject }, h("span", { class: "pos" }, c.index >= 0 ? `#${c.index}` : "list"), c.subjectCN),
        h("div", { class: "track", "aria-hidden": "true" },
          h("div", { class: cls, style: `left:${left}%;width:${width}%` }),
          h("div", { class: "today", style: `left:${pct(now)}%` })),
        h("div", { class: `range-dates ${dateCls}` },
          `${fmtDate(c.notBefore)} → ${fmtDate(c.notAfter)} `, h("br"), h("b", {}, fmtDays(c.daysRemaining))));
    });

    // Year ticks
    const axis = h("div", { class: "axis", "aria-hidden": "true" });
    const y0 = new Date(lo).getUTCFullYear() + 1, y1 = new Date(hi).getUTCFullYear();
    const span = y1 - y0;
    const step = span > 16 ? 4 : span > 8 ? 2 : 1;
    const todayPct = pct(now);
    for (let y = y0; y <= y1; y += step) {
      const p = pct(Date.UTC(y, 0, 1));
      if (Math.abs(p - todayPct) > 7 && p > 2 && p < 98) axis.append(h("span", { style: `left:${p}%` }, String(y)));
    }
    if (hi - lo < 2 * YEAR) {
      // short range: label months instead
      axis.replaceChildren();
    }
    axis.append(h("span", { class: "today-l", style: `left:${todayPct}%` }, "Today"));

    return h("section", { "aria-labelledby": "val-h" },
      h("h2", { class: "sec", id: "val-h" }, "Validity"),
      h("div", { class: "range" }, rows, axis));
  }

  // ---------- chain as sent ----------
  function chainSection(a) {
    const sec = h("section", { "aria-labelledby": "chain-h" },
      h("h2", { class: "sec", id: "chain-h" }, "Chain as sent",
        h("small", {}, "in the order the server sent them")),
      h("div", { class: "certs" }, certHead(), a.chain.map(certRow)));
    if (a.storeRoots && a.storeRoots.length) {
      sec.append(h("h2", { class: "sec", style: "margin-top:24px" }, "Roots from the trust store", h("small", {}, "not sent by the server, used to complete a path")),
        h("div", { class: "certs" }, certHead(), a.storeRoots.map(certRow)));
    }
    return sec;
  }

  function certHead() {
    return h("div", { class: "cert-head", "aria-hidden": "true" },
      h("span", {}, "#"), h("span", {}, "Subject"), h("span", {}, "Issued by"), h("span", {}, "Expires"), h("span", {}, "Notes"), h("span"));
  }

  // ---------- revocation ----------
  const isRevoked = (c) => !!c.revocation && [c.revocation.ocsp, c.revocation.crl].some((s) => s && s.status === "revoked");
  function revSourceText(s) {
    if (s.status === "good") return "not revoked";
    if (s.status === "revoked") return `REVOKED${s.revokedAt ? ` on ${fmtDate(s.revokedAt)}` : ""}${s.reason ? ` (${s.reason})` : ""}`;
    if (s.status === "unknown") return "responder doesn't know this certificate";
    return `could not check (${s.error || "error"})`;
  }
  function revocationText(r) {
    if (!r) return "";
    const parts = [];
    if (r.ocsp) parts.push(`OCSP: ${revSourceText(r.ocsp)}`);
    if (r.crl) parts.push(`CRL: ${revSourceText(r.crl)}${r.crl.nextUpdate && r.crl.status === "good" ? `, list valid until ${fmtDate(r.crl.nextUpdate)}` : ""}`);
    return parts.length ? parts.join(". ") : "No OCSP responder or CRL named";
  }

  function certRow(c) {
    const tags = [];
    const tag = (st, text) => tags.push(h("span", { class: `tag ${st}` }, st !== "neutral" ? icon(st === "neutral" ? "info" : st) : null, text));
    if (c.index === 0) tag("neutral", "Leaf");
    else if (c.isCA) tag("neutral", c.selfSigned ? "Root" : "Intermediate");
    if (c.inMozilla) tag("pass", "Trusted root");
    else if (c.selfSigned) tag("fail", "Untrusted root");
    if (c.onTrustedPath && !c.inMozilla) tag("pass", "On a trusted path");
    if (c.status === "expired") tag("fail", "Expired");
    if (c.status === "not_yet_valid") tag("fail", "Not yet valid");
    if (c.status === "expiring_soon") tag("warn", "Expiring soon");
    if (c.extraneous === "unrelated") tag("fail", "Unrelated");
    if (c.extraneous === "duplicate") tag("warn", `Duplicate of #${c.duplicateOf}`);
    if (c.extraneous === "alternate_path") tag("warn", "Not needed for trust");
    if (c.pendingDistrust) tag("warn", "Pending distrust");
    if (isRevoked(c)) tag("fail", "Revoked");

    const expCls = c.status === "expired" || c.status === "not_yet_valid" ? "fail" : c.status === "expiring_soon" ? "warn" : "";
    const rows = [
      ["Subject", c.subject], ["Issuer", c.issuer], ["Serial", c.serial, true],
      ["Not before", fmtDateTime(c.notBefore)], ["Not after", `${fmtDateTime(c.notAfter)} (${fmtDays(c.daysRemaining)})`],
      ["Public key", `${c.keyAlgorithm}${c.keySize ? `, ${c.keySize}-bit` : ""}`], ["Signature", c.signatureAlgorithm],
      ["SHA-256", c.sha256, true], ["SHA-1", c.sha1, true],
      // Radar has a page per CA certificate (keyed by SHA-256) showing which
      // root stores include it. Leaf certificates have no page.
      ["Root stores", c.isCA ? h("div", {},
        c.stores ? storeList(STORES.map((s) => ({ store: s, status: c.stores[s] === "trusted" ? "trusted" : c.stores[s] === "limited" ? "limited" : "absent" }))) : null,
        h("a", { href: `https://radar.cloudflare.com/certificate-transparency/ca/${c.sha256.toUpperCase()}`, target: "_blank", rel: "noopener noreferrer" },
          "Check on Cloudflare Radar", h("span", { class: "sr" }, " (opens in a new tab)"))) : null],
      ["Subject key ID", c.subjectKeyId, true], ["Authority key ID", c.authorityKeyId, true],
      ["CA", c.isCA ? `Yes${c.maxPathLen !== undefined && c.maxPathLen !== null ? `, path length ≤ ${c.maxPathLen}` : ""}` : "No"],
      ["DNS names", (c.dnsNames || []).join(", ")], ["IP addresses", (c.ipAddresses || []).join(", ")],
      ["Emails", (c.emails || []).join(", ")], ["URIs", (c.uris || []).join(", ")],
      ["Key usage", (c.keyUsage || []).join(", ")], ["Extended key usage", (c.extKeyUsage || []).join(", ")],
      ["Policies", (c.policies || []).join(", "), true],
      ["Revocation", revocationText(c.revocation)],
      ["OCSP URL", (c.ocspServers || []).join(", ")], ["CA issuers", (c.issuingUrls || []).join(", ")],
      ["CRL URL", (c.crlDistributionPoints || []).join(", ")],
    ];
    if (c.pendingDistrust) {
      const pd = c.pendingDistrust;
      rows.unshift(["Pending distrust", [pd.date, pd.note].filter(Boolean).join(", ") || "Flagged"]);
    }
    const dl = h("dl", { class: "kv" });
    for (const [k, v, mono] of rows) {
      if (!v) continue;
      dl.append(h("dt", {}, k), h("dd", { class: mono ? "mono" : "" }, v));
    }
    const copyLabel = h("span", {}, "Copy PEM");
    const copyBtn = h("button", { class: "btn-quiet", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(c.pem); copyLabel.textContent = "Copied"; announce("PEM copied"); }
      catch { copyLabel.textContent = "Copy failed. Select the text instead"; announce("Copy failed. Select the text instead."); }
      setTimeout(() => { copyLabel.textContent = "Copy PEM"; }, 1600);
    } }, icon("copy"), copyLabel);

    return h("details", { class: "cert" },
      h("summary", {},
        h("span", { class: "c-pos", title: c.index >= 0 ? null : "Not sent by the server" }, c.index >= 0 ? `#${c.index}` : "n/a"),
        h("span", { class: "c-subj" }, c.subjectCN),
        h("span", { class: "c-iss" }, h("span", { class: "sr" }, "Issued by "), c.issuerCN),
        h("span", { class: `c-exp ${expCls}` }, h("span", { class: "sr" }, "Expires "), h("b", {}, fmtDate(c.notAfter))),
        h("span", { class: "c-flags" }, tags),
        h("span", { class: "chev" }, icon("chev"))),
      h("div", { class: "cert-body" }, dl,
        h("div", { class: "pem-head" }, h("span", {}, "PEM"), copyBtn),
        h("pre", { class: "pem", tabindex: "0" }, c.pem)));
  }

  // ---------- paths ----------
  function pathsSection(a, byId) {
    const fig = h("figure", { class: "plate" }, h("div", { class: "diagram" }, "Drawing paths…"), diagramKey(a.diagramKey));
    const TERM = { mozilla_root: ["pass", "Trusted root"], untrusted_root: ["fail", "Untrusted root"], incomplete: ["fail", "Incomplete"] };
    const table = tableRoles(h("table", { class: "paths" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Ends at"), h("th", { scope: "col" }, "Route"), h("th", { scope: "col" }, "Notes"))),
      h("tbody", {}, a.paths.map((p) => {
        const parts = [];
        p.nodes.forEach((id, i) => {
          if (i) parts.push(h("span", { class: "arrow", "aria-hidden": "true" }, "→"), h("span", { class: "sr" }, " issued by "));
          const c = byId[id];
          parts.push(c ? (c.index >= 0 ? `#${c.index} ${c.subjectCN}` : `${c.subjectCN} (trust store)`) : id);
        });
        if (p.terminal === "incomplete") parts.push(h("span", { class: "arrow", "aria-hidden": "true" }, "→"), h("span", { class: "sr" }, " issued by "), `missing: ${p.missingIssuer}`);
        const [st, word] = TERM[p.terminal];
        const notes = [];
        if (p.best) notes.push(h("span", { class: "tag pass" }, "Best path"));
        if (p.stores && p.stores.length) {
          const names = [];
          p.stores.forEach((s, i) => names.push(i ? ", " : "", storeName(s)));
          notes.push(h("span", { class: "tag neutral" }, "Trusted by ", ...names));
        }
        if (!p.timeValid) notes.push(h("span", { class: "tag fail" }, icon("fail"), "Validity problem"));
        if (p.pendingDistrust) notes.push(h("span", { class: "tag warn" }, icon("warn"), "Pending distrust"));
        return h("tr", {}, h("td", { class: "ends" }, flagWord(st, word)), h("td", { class: "route" }, parts), h("td", { class: "notes" }, h("span", { class: "c-flags" }, notes)));
      }))));
    const el = h("section", { "aria-labelledby": "paths-h" },
      h("h2", { class: "sec", id: "paths-h" }, "Paths", h("small", {}, `${a.paths.length} found, including cross-signs. Roots are at the top, the leaf at the bottom.`)),
      fig, table);
    return {
      el,
      draw: async () => {
        const slot = fig.querySelector(".diagram");
        try {
          await loadMermaid();
          if (!mermaidReady) {
            window.mermaid.initialize({
              startOnLoad: false, securityLevel: "strict", theme: "base",
              themeVariables: { fontFamily: "IBM Plex Sans, system-ui, sans-serif", fontSize: "14px", lineColor: "#7d8a99", primaryTextColor: "#16202b", edgeLabelBackground: getComputedStyle(document.documentElement).getPropertyValue("--plate").trim() || "#ffffff" },
              flowchart: { htmlLabels: true, curve: "basis", nodeSpacing: 36, rankSpacing: 44 },
            });
            mermaidReady = true;
          }
          const svgId = `chain-diagram-${++diagramSeq}`;
          const { svg } = await window.mermaid.render(svgId, a.mermaid);
          slot.innerHTML = svg; // produced by Mermaid with securityLevel "strict"
          uniqueSvgIds(slot.firstElementChild, svgId);
          slot.firstElementChild?.setAttribute("aria-label", "Certificate issuance paths diagram");
          slot.firstElementChild?.setAttribute("role", "img");
          if (slot.firstElementChild) hatchDiagram(slot.firstElementChild, a.diagramKey);
        } catch (e) {
          slot.replaceChildren(h("p", {}, `Diagram unavailable: ${e.message || e}. The table below lists every path.`));
        }
      },
    };
  }

  // Mermaid names edges L_<from>_<to>_<n> in every diagram, so two diagrams
  // on one page share ids. Prefix those with the diagram's own id and update
  // any references to them.
  function uniqueSvgIds(svg, prefix) {
    if (!svg) return;
    const map = new Map();
    svg.querySelectorAll("[id]").forEach((el) => {
      if (el === svg || el.id.startsWith(prefix)) return;
      const id = `${prefix}-${el.id}`;
      map.set(el.id, id);
      el.id = id;
    });
    if (!map.size) return;
    const fix = (v) => v.replace(/url\(#([^)]+)\)/g, (m, id) => (map.has(id) ? `url(#${map.get(id)})` : m))
      .replace(/^#(.+)$/, (m, id) => (map.has(id) ? `#${map.get(id)}` : m));
    svg.querySelectorAll("*").forEach((el) => {
      for (const attr of ["href", "xlink:href", "marker-start", "marker-end", "clip-path", "fill", "mask", "filter"]) {
        const v = el.getAttribute(attr);
        if (v && v.includes("#")) el.setAttribute(attr, fix(v));
      }
    });
  }

  function flagWord(st, word) { return h("span", { class: `flag ${st}` }, icon(st), word); }
  // What each diagram style means. The server sends only the styles this
  // diagram uses, with their colours, so the key always matches the drawing.
  const KEY_TEXT = {
    trusted: ["On a trusted path", "Sent by the server, on a path to a trusted root."],
    store: ["Trusted root, not sent", "From the trust store. Servers usually don't send the root, so this is normal."],
    other: ["Not on a trusted path", "Sent by the server, but no path from it reaches a trusted root."],
    pending: ["Pending distrust", "Scheduled to lose trust. Plan to replace it."],
    alternate: ["Not needed", "Only on a path that doesn't reach a trusted root. It may be an old cross-sign kept for older clients."],
    invalid: ["Expired or not yet valid", "Outside its validity dates, so clients reject it."],
    revoked: ["Revoked", "Its issuer says it is revoked (OCSP or CRL). Clients that check will reject it."],
    unrelated: ["Unrelated", "Not on any path from this site's certificate. Remove it."],
    missing: ["Missing issuer", "Not sent by the server and not in the trust store, so the path stops here. Its arrow is dashed."],
    link: ["Issued", "Points from the issuer down to the certificate it signed."],
    "trusted-link": ["Trusted link", "On a path to a trusted root."],
  };
  function diagramKey(entries) {
    const items = (entries || []).filter((e) => KEY_TEXT[e.id]).map((e) => {
      const [name, desc] = KEY_TEXT[e.id];
      return h("li", {}, keySwatch(e), h("span", {}, h("b", {}, name), h("span", {}, desc)));
    });
    if (!items.length) return null;
    return h("figcaption", {}, h("h3", {}, "Key"), h("ul", { class: "key" }, items));
  }
  // Diagonal stripes over a node's fill, so problem nodes differ from the
  // rest by pattern as well as colour (the validity graph hatches the same way).
  let hatchSeq = 0;
  function hatchPattern(id, e) {
    const mk = (tag, attrs) => {
      const n = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
      return n;
    };
    const defs = mk("defs", {});
    const pat = mk("pattern", { id, patternUnits: "userSpaceOnUse", width: 6, height: 6, patternTransform: "rotate(45)" });
    pat.append(mk("rect", { width: 6, height: 6, fill: e.fill }), mk("line", { x1: 0, y1: 0, x2: 0, y2: 6, stroke: e.stroke, "stroke-width": 2, "stroke-opacity": 0.35 }));
    defs.append(pat);
    return defs;
  }
  function hatchDiagram(svg, entries) {
    const seen = new Set();
    for (const e of entries || []) {
      if (e.kind !== "node" || !e.hatch || !e.class || seen.has(e.class)) continue;
      seen.add(e.class);
      const id = `${svg.id}-hatch-${e.class}`;
      svg.prepend(hatchPattern(id, e));
      for (const g of svg.querySelectorAll(`g.node.${CSS.escape(e.class)}`)) {
        for (const shape of g.querySelectorAll(":scope > rect, :scope > path, :scope > polygon")) shape.style.setProperty("fill", `url(#${id})`, "important");
      }
    }
  }
  function keySwatch(e) {
    const s = document.createElementNS(NS, "svg");
    s.setAttribute("viewBox", "0 0 36 22");
    s.setAttribute("aria-hidden", "true");
    const el = (tag, attrs) => {
      const n = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
      s.append(n);
    };
    const dash = e.dash ? { "stroke-dasharray": e.dash } : {};
    if (e.kind === "link") {
      // A short vertical arrow, matching the diagram's top-down links.
      el("line", { x1: 18, y1: 2, x2: 18, y2: 15, stroke: e.stroke, "stroke-width": e.width, ...dash });
      el("path", { d: "M13 14l5 6 5-6z", fill: e.stroke });
    } else {
      let fill = e.fill;
      if (e.hatch) {
        const id = `key-hatch-${++hatchSeq}`;
        s.append(hatchPattern(id, e));
        fill = `url(#${id})`;
      }
      el("rect", { x: 1.5, y: 2.5, width: 33, height: 17, rx: 2, fill, stroke: e.stroke, "stroke-width": e.width, ...dash });
      el("path", { d: "M8 9h20M11 14h14", stroke: e.text, "stroke-width": 1.5, "stroke-linecap": "round", opacity: 0.55 });
    }
    return s;
  }

  const PROTO_NAMES = { smtp: "SMTP", imap: "IMAP", pop3: "POP3", ftp: "FTP", ldap: "LDAP", postgres: "PostgreSQL", mysql: "MySQL" };
  const protoName = (p) => PROTO_NAMES[p] || p.toUpperCase();

  // ---------- history ----------
  // Each check gets its own history entry holding its results, so Back and
  // Forward show earlier checks again without re-running them. A link that
  // only carries host/port fills in the form and does not run a check.
  function saveHistory(url, data) {
    const state = { data };
    const title = `${url.searchParams.get("host")}:${url.searchParams.get("port")} | CA Chain Check`;
    const same = url.href === location.href; // re-checking the same target: update, don't stack
    try {
      if (same) history.replaceState(state, "", url); else history.pushState(state, "", url);
    } catch {
      // The browser may refuse a large state; keep the entry, drop the stored results.
      if (same) history.replaceState(null, "", url); else history.pushState(null, "", url);
    }
    document.title = title;
  }

  function loadFromURL() {
    const params = new URLSearchParams(location.search);
    hostEl.value = params.get("host") || "";
    portEl.value = params.get("port") || "443";
    starttls = (params.get("starttls") || "").toLowerCase();
  }

  window.addEventListener("popstate", (ev) => {
    loadFromURL();
    const data = ev.state && ev.state.data;
    if (data) {
      document.title = `${hostEl.value}:${portEl.value} | CA Chain Check`;
      renderStoreInfo(data.trustStore);
      render(data).then(() => announce(`Showing an earlier check. ${finishedText(data).replace(/^Check finished for /, "")}`));
    } else {
      document.title = "CA Chain Check";
      renderIntro();
    }
  });

  // ---------- boot ----------
  // starttls is a URL-only option (no form control): a protocol name, or
  // "none" for TLS only. Without it the server picks by port.
  let starttls = "";
  loadFromURL();
  if (history.state && history.state.data) {
    // Reloaded or restored page: show the stored result again.
    document.title = `${hostEl.value}:${portEl.value} | CA Chain Check`;
    render(history.state.data);
  } else {
    renderIntro();
  }
})();
