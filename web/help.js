// Help page: show this server's address in the examples, add copy buttons
// to the example scripts, and mark the current section in the side list.
"use strict";
for (const el of document.querySelectorAll("[data-origin]")) el.textContent = location.origin;

const announce = (msg) => {
  const el = document.getElementById("announce");
  el.textContent = "";
  setTimeout(() => { el.textContent = msg; }, 50);
};

for (const pre of document.querySelectorAll("pre[data-copy]")) {
  const name = pre.dataset.copy;
  const head = document.createElement("div");
  head.className = "code-head";
  const label = document.createElement("code");
  label.textContent = name;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn-quiet";
  btn.textContent = "Copy";
  btn.setAttribute("aria-label", `Copy ${name}`);
  let timer;
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent.replace(/\n?$/, "\n"));
      btn.textContent = "Copied";
      announce(`${name} copied`);
    } catch {
      btn.textContent = "Copy failed";
      announce(`Could not copy ${name}. Select the text and copy it instead.`);
    }
    clearTimeout(timer);
    timer = setTimeout(() => { btn.textContent = "Copy"; }, 2000);
  });
  head.append(label, btn);
  pre.before(head);
}

// Mark the section nearest the top of the screen as current.
const links = [...document.querySelectorAll(".doc-nav a[href^='#']")];
const targets = links.map((a) => document.getElementById(a.hash.slice(1))).filter(Boolean);
const wide = matchMedia("(min-width: 961px)"); // the side list only follows the page when it is beside it
const markCurrent = () => {
  if (!wide.matches) {
    for (const a of links) a.removeAttribute("aria-current");
    return;
  }
  let current = targets[0];
  for (const t of targets) if (t.getBoundingClientRect().top <= 120) current = t;
  if (innerHeight + scrollY >= document.documentElement.scrollHeight - 2) current = targets[targets.length - 1];
  for (const a of links) {
    if (a.hash === `#${current.id}`) a.setAttribute("aria-current", "true");
    else a.removeAttribute("aria-current");
  }
};
let queued = false;
addEventListener("scroll", () => {
  if (queued) return;
  queued = true;
  requestAnimationFrame(() => { queued = false; markCurrent(); });
}, { passive: true });
wide.addEventListener("change", markCurrent);
markCurrent();
