#!/usr/bin/env node
// THE CONTACT SHEET — seven surfaces, three widths, one image, meant to be OPENED.
//
// A blind reviewer's closing sentence on round one:
//
//   "this surface has been *verified* far more than it has been *looked at*, and its
//    verification reads source as text, which is why a `className` pointing at a rule
//    that does not exist survives a green gate."
//
// They measured twenty text-on-text overlaps at 1440 and 1180 — the two widths I had
// been screenshotting and calling fine — a submit button rendering as a raw browser
// default, thirteen table rows whose first column said "—", and a Basis column that
// became one character per line at 390px. Every one was invisible to every assertion I
// had and obvious in the first two seconds of looking.
//
// So looking becomes a step with an artifact, rather than a habit I can believe I
// performed. This writes ONE sheet with every surface at every width, and the run is
// not green until a person has opened it and written a line per surface.
//
// It is deliberately not an assertion. A picture cannot be asserted about — that is
// the entire point of the reviewer's sentence — so this produces the thing a human
// must look at and refuses to pretend that producing it is the same as looking.
//
// Usage: node apps/decentralized-cloud/scripts/contact-sheet.mjs

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES } from "../src/logic/surfaces.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const OUT = path.join(APP, "brand/.artifacts/contact");
const PORT = Number(process.env.IOI_DC_SHEET_PORT || 4205);
const WIDTHS = [1440, 1180, 390];

mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) rmSync(path.join(OUT, f), { force: true });

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
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});

const cells = [];
try {
  for (const w of WIDTHS) {
    const page = await browser.newPage({ viewport: { width: w, height: 900 }, deviceScaleFactor: 1 });
    for (const s of SURFACES) {
      await page.goto(`http://127.0.0.1:${PORT}/#/${s.id}`, { waitUntil: "networkidle" });
      // The slow reads are part of what is being looked at. A shot taken during the
      // wait is a picture of the waiting state — a real state, and not the one this
      // sheet is for.
      await page.waitForTimeout(s.id === "candidates" || s.id === "sources" ? 6000 : 1500);
      const buf = await page.screenshot();
      cells.push({ w, id: s.id, label: s.label, url: `data:image/png;base64,${buf.toString("base64")}` });
    }
    await page.close();
  }

  // One page, every cell, grouped by width and labelled. Each is shown at a third of
  // its true size so twenty-one viewports fit somewhere a person will actually scroll
  // through — and each links to its own full-size capture, because a defect spotted in
  // the thumbnail has to be confirmable at full size.
  const page = await browser.newPage({ viewport: { width: 1700, height: 1200 }, deviceScaleFactor: 1 });
  const groups = WIDTHS.map((w) => {
    const row = cells
      .filter((c) => c.w === w)
      .map((c) => `<figure><img src="${c.url}" width="${Math.round(w / 3)}"><figcaption>${c.label} · ${w}px</figcaption></figure>`)
      .join("");
    return `<section><h2>${w}px</h2><div class="row">${row}</div></section>`;
  }).join("");
  await page.setContent(
    `<style>body{margin:0;background:#fff;font:13px ui-monospace,monospace;color:#333;padding:20px;}` +
    `h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#666;margin:26px 0 10px;}` +
    `.row{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;}` +
    `figure{margin:0;}img{display:block;border:1px solid #ddd;}` +
    `figcaption{margin-top:6px;font-size:11px;color:#666;}</style>` +
    `<h1 style="font-size:15px;">decentralized.cloud — every surface, every width</h1>` +
    `<p style="max-width:80ch;color:#666;">Producing this sheet is not looking at it. ` +
    `The run is green when someone has opened it and written a line per surface.</p>` +
    groups
  );
  const sheet = path.join(OUT, "contact-sheet.png");
  await page.screenshot({ path: sheet, fullPage: true });
  await page.close();

  writeFileSync(
    path.join(OUT, "cells.json"),
    JSON.stringify({ at: new Date().toISOString(), widths: WIDTHS, surfaces: SURFACES.map((s) => s.id) }, null, 2)
  );
  console.log(`contact sheet: ${sheet}`);
  console.log(`${cells.length} cells — ${SURFACES.length} surfaces x ${WIDTHS.length} widths`);
  console.log("");
  console.log("THIS RUN IS NOT GREEN UNTIL THE SHEET HAS BEEN OPENED AND A LINE WRITTEN");
  console.log("PER SURFACE. Producing the picture is not the same as looking at it, and");
  console.log("the whole reason this step exists is that I could not tell the difference.");
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
