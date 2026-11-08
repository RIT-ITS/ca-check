// Show this server's own address in the help page examples.
"use strict";
for (const el of document.querySelectorAll("[data-origin]")) el.textContent = location.origin;
