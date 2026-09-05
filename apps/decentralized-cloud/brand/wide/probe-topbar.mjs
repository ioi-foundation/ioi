#!/usr/bin/env node
// MEASURE THE TOPBAR, rather than guess at it again.
//
// The gate reports a collision at 1520px — a nav button on top of the status text —
// inside a viewport with zero horizontal scroll. I have now changed the CSS twice on a
// theory about which box is failing to shrink, and the collision is still there, which
// means the theory is wrong and the next change would be a third guess.
//
// This prints the actual boxes: what each element's rect is, which of them overlap,
// and by how much. A cross-check that disagrees with your arithmetic is usually your
// arithmetic.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "../..");
const PORT = Number(process.env.IOI_DC_PROBE_PORT || 4193);

const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
  env: { ...process.env, IOI_DC_PORT: String(PORT) },
  stdio: ["ignore", "pipe", "pipe"],
});
let booted = false;
server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
for (let i = 0; i < 80 && !booted; i++) await new Promise((r) => setTimeout(r, 100));
if (!booted) { server.kill("SIGTERM"); throw new Error("the face server did not start"); }

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch();
try {
  for (const w of [1520, 1440, 1180]) {
    const page = await browser.newPage({ viewport: { width: w, height: 900 }, deviceScaleFactor: 1 });
    await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "networkidle" });
    await page.waitForTimeout(600);
    const m = await page.evaluate(() => {
      const box = (sel) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        return {
          sel, x: Math.round(r.x), right: Math.round(r.right), w: Math.round(r.width),
          scrollW: el.scrollWidth, clientW: el.clientWidth,
          flex: `${cs.flexGrow} ${cs.flexShrink} ${cs.flexBasis}`, overflowX: cs.overflowX,
        };
      };
      const navButtons = [...document.querySelectorAll(".nav button")].map((b) => {
        const r = b.getBoundingClientRect();
        return { text: b.textContent.trim(), x: Math.round(r.x), right: Math.round(r.right) };
      });
      const status = document.querySelector(".topbar-status")?.getBoundingClientRect();
      return {
        boxes: [".topbar", ".topbar-left", ".lockup", ".nav", ".topbar-status"].map(box),
        navButtons,
        statusX: status ? Math.round(status.x) : null,
        bodyScroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });
    console.log(`\n── ${w}px · body horizontal scroll ${m.bodyScroll}px ──`);
    for (const b of m.boxes) {
      if (!b) continue;
      console.log(`  ${b.sel.padEnd(16)} x ${String(b.x).padStart(5)} → ${String(b.right).padStart(5)}  w ${String(b.w).padStart(4)}  scrollW ${String(b.scrollW).padStart(4)} clientW ${String(b.clientW).padStart(4)}  flex ${b.flex}  overflow-x ${b.overflowX}`);
    }
    const last = m.navButtons[m.navButtons.length - 1];
    if (last && m.statusX !== null) {
      const overlap = last.right - m.statusX;
      console.log(`  last nav button "${last.text}" ends at ${last.right}; status starts at ${m.statusX} → ${overlap > 0 ? `OVERLAP ${overlap}px` : `clear by ${-overlap}px`}`);
    }
    await page.close();
  }
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
