#!/usr/bin/env node
// CONSOLE CAPTURE — the "before" and "after" instrument for every console iteration.
//
// One run photographs every registered surface at the five console widths (390, 768,
// 1180, 1440, 1920) plus a reduced-motion pass at 1440, into
// .artifacts/console/<iteration>/. Each capture waits for THAT surface's own content
// by selector, and burns the state it caught — LOADED after Nms, or STILL WAITING —
// into the image, because a picture that does not say which state it captured is
// read as the loaded page (standing-practice §1). A surface that never arrived exits
// non-zero so a waiting page cannot be scored as the product.
//
//   ITER=001-shell PORT=4240 node scripts/console-capture.mjs
//   SURFACES=home,catalog  — restrict to some surfaces
//   WIDTHS=390,1440        — restrict widths
//
// It also writes an index.json beside the images: per capture, the surface, width,
// reduced-motion flag, wait observed, arrived flag, document height, and the horizontal
// overflow measured — so the audit can cite a number from the run rather than a memory
// of one.
import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES } from "../src/logic/surfaces.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const port = process.env.PORT || "4240";
const iter = process.env.ITER;
if (!iter) {
  console.error("ITER=<iteration-name> is required (e.g. ITER=000-baseline)");
  process.exit(2);
}
const outDir = path.join(APP, ".artifacts", "console", iter);
mkdirSync(outDir, { recursive: true });

const WIDTHS = (process.env.WIDTHS || "390,768,1180,1440,1920").split(",").map(Number);
const only = process.env.SURFACES ? process.env.SURFACES.split(",") : null;

// What "this surface's content has arrived" means, by name. A surface not listed
// here waits for its <h1>, which every surface renders synchronously, and the index
// says so — a synchronous wait is not evidence the read landed.
const ARRIVAL = {
  catalog: ".t-catalog .trow",
  candidates: ".t-quotes .trow, .panel.flag",
  sources: ".t-sources .trow",
  placement: ".t-decision .trow",
  receipts: ".t-receipts .trow",
  // The budget <option> the daemon's read fills in. Waited for as ATTACHED, below:
  // Playwright's default wait is for visibility, and an <option> inside a <select> is
  // never "visible" to it, so the baseline run timed out five times on a form that
  // was fully rendered — labelled STILL WAITING, correctly, over a loaded page.
  job: "select.field-box option:nth-child(2)",
  redundancy: ".t-postures .trow",
  api: ".t-api .trow",
  spend: ".t-pairs .trow",
  iam: ".t-leases .trow",
  supply: ".t-supply .trow",
  settings: ".t-pairs .trow",
};

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});

const index = [];
const passes = [
  ...WIDTHS.map((w) => ({ width: w, reduced: false })),
  { width: 1440, reduced: true },
];

for (const s of SURFACES) {
  if (only && !only.includes(s.id)) continue;
  for (const p of passes) {
    const ctx = await browser.newContext({
      viewport: { width: p.width, height: p.width < 700 ? 844 : 900 },
      reducedMotion: p.reduced ? "reduce" : "no-preference",
    });
    const page = await ctx.newPage();
    await page.goto(`http://127.0.0.1:${port}/#/${s.id}`, { waitUntil: "domcontentloaded" });
    const sel = ARRIVAL[s.id] || "h1";
    const t0 = Date.now();
    const arrived = await page.waitForSelector(sel, { timeout: 90000, state: "attached" }).then(() => true).catch(() => false);
    const waited = Date.now() - t0;
    // Let a landed read paint and any one-second dial tick settle.
    await page.waitForTimeout(400);
    const m = await page.evaluate(() => ({
      docHeight: document.documentElement.scrollHeight,
      overflowX: document.documentElement.scrollWidth - window.innerWidth,
      h1: document.querySelector("h1")?.textContent?.trim() || null,
      current: document.querySelector('[aria-current="page"]')?.textContent?.trim() || null,
    }));
    await page.evaluate(({ arrived, waited, sel, reduced }) => {
      const bar = document.createElement("div");
      bar.textContent = (arrived
        ? `LOADED — "${sel}" present after ${waited}ms`
        : `STILL WAITING — "${sel}" never appeared in ${waited}ms. THIS IS NOT THE LOADED PAGE.`)
        + (reduced ? " · prefers-reduced-motion: reduce" : "");
      bar.setAttribute("style",
        "position:static;display:block;width:100%;padding:6px 10px;box-sizing:border-box;" +
        "font:12px ui-monospace,monospace;color:#fff;" +
        `background:${arrived ? "#397554" : "#e40014"};`);
      document.body.appendChild(bar);
    }, { arrived, waited, sel, reduced: p.reduced });
    const name = `${s.id}-${p.width}${p.reduced ? "-reduced" : ""}.png`;
    await page.screenshot({ path: path.join(outDir, name), fullPage: true });
    index.push({ surface: s.id, width: p.width, reduced: p.reduced, arrived, waited, selector: sel, ...m, file: name });
    console.log(`${arrived ? "LOADED " : "WAITING"} ${name.padEnd(34)} ${String(waited).padStart(6)}ms  h=${m.docHeight}  overflowX=${m.overflowX}`);
    if (!arrived) process.exitCode = 2;
    await ctx.close();
  }
}
await browser.close();
writeFileSync(path.join(outDir, "index.json"), JSON.stringify({ iteration: iter, at: new Date().toISOString(), captures: index }, null, 2));
console.log(`wrote ${index.length} captures to ${outDir}`);
