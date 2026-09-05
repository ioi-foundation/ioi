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

// What "this surface has arrived" means, per surface. Named here rather than guessed
// at with a timeout, because a timeout is a guess about the daemon and this sheet is
// the thing people form their opinion of the product from.
// `job` has no read to wait for — its content is a form, present immediately.
const CONTENT_OF = {
  catalog: ".t-catalog .trow",
  candidates: ".t-quotes .trow",
  sources: ".t-sources .trow",
  placement: ".t-decision .trow",
  redundancy: ".t-postures .trow",
  receipts: ".t-receipts .trow",
  api: ".t-api .trow",
  job: null,
};
// FAIL CLOSED. An unlisted surface used to get `undefined`, skip the wait, and be
// photographed mid-load with nothing saying so — which is how three cold readers came
// to judge blank pages that were never blank. Every registered surface must be named
// here, with a selector or an explicit null.
for (const s of SURFACES) {
  if (!(s.id in CONTENT_OF)) throw new Error(`CONTENT_OF has no entry for surface "${s.id}" — add a selector or an explicit null`);
}

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

      // ── THE SHEET WAITED 1.5s FOR READS THAT TAKE UP TO 61 ─────────────────
      //
      // The comment that used to sit here said, correctly, that "a shot taken during
      // the wait is a picture of the waiting state — a real state, and not the one this
      // sheet is for". Directly underneath it was `waitForTimeout(1500)`, which
      // guaranteed exactly that shot for Sources, Placement and Receipts on every run.
      //
      // THREE COLD READERS JUDGED THIS PRODUCT THROUGH THIS SHEET. All three reported
      // three of seven surfaces as blank pages, and I relayed those blanks upward as
      // product findings and wrote contact-sheet lines describing them. They were an
      // artifact of this line. The product renders those surfaces; the instrument
      // photographed them before they arrived.
      //
      // That is the vacuous-pass defect exactly — measuring a loading page and
      // reporting the result as if it described the loaded one — committed inside the
      // instrument built to catch what the assertions miss. The gate learned this two
      // commits ago. The sheet had not, and the sheet is the thing people LOOK at.
      //
      // Each surface now waits for ITS OWN CONTENT with a ceiling above the slowest
      // measured read, and a cell that never arrives is LABELLED rather than presented
      // as a picture of the product.
      const want = CONTENT_OF[s.id];
      let arrived = true;
      if (want) {
        arrived = await page.waitForSelector(want, { timeout: 90_000 })
          .then(() => true).catch(() => false);
      }
      await page.waitForTimeout(400);
      // FULL PAGE, NOT THE VIEWPORT.
      //
      // Every cell was a 900px-tall viewport shot, so every surface was cut off at the
      // fold — and four cold readers in a row reported the consequences as PRODUCT
      // defects: "the two writes are not in the table" (they are, below 900px), "there
      // is no submit button visible anywhere" (there is), "the counts sum to 13 sources
      // and the capture is cut off after four and a half rows, so I cannot check the
      // header against its own table on any width".
      //
      // That last sentence is the cost stated exactly: the instrument made every
      // count-versus-table check impossible, and then readers correctly reported that
      // they could not verify the counts. THREE separate framings of one defect — a
      // fixed wait, an unreadable scale, a cropped frame — all of them the sheet being
      // built for producing rather than for reading.
      const buf = await page.screenshot({ fullPage: true });
      cells.push({
        w, id: s.id, label: s.label, arrived,
        url: `data:image/png;base64,${buf.toString("base64")}`,
      });
      if (!arrived) {
        console.log(`  !! ${s.id} @ ${w}px — content did not arrive within 90s; this cell is a WAITING page`);
      }
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
      // A cell whose content never arrived is MARKED, in the caption, in words. An
      // unmarked waiting page is indistinguishable from a page that renders nothing —
      // which is the exact confusion three cold readers reported back, and they were
      // reading the instrument, not the product.
      .map((c) => {
        const cap = c.arrived === false
          ? `${c.label} · ${w}px — <b>STILL WAITING at capture; this is not the loaded page</b>`
          : `${c.label} · ${w}px`;
        return `<figure${c.arrived === false ? ' class="waiting"' : ""}>` +
          `<img src="${c.url}" width="${Math.round(w / 3)}">` +
          `<figcaption>${cap}</figcaption></figure>`;
      })
      .join("");
    return `<section><h2>${w}px</h2><div class="row">${row}</div></section>`;
  }).join("");
  await page.setContent(
    `<style>body{margin:0;background:#fff;font:13px ui-monospace,monospace;color:#333;padding:20px;}` +
    `h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#666;margin:26px 0 10px;}` +
    `.row{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;}` +
    `figure{margin:0;}img{display:block;border:1px solid #ddd;}` +
    `figcaption{margin-top:6px;font-size:11px;color:#666;}` +
    `figure.waiting img{border:2px solid #e40014;}figure.waiting figcaption{color:#e40014;}</style>` +
    `<h1 style="font-size:15px;">decentralized.cloud — every surface, every width</h1>` +
    `<p style="max-width:80ch;color:#666;">Producing this sheet is not looking at it. ` +
    `The run is green when someone has opened it and written a line per surface.</p>` +
    groups
  );
  const sheet = path.join(OUT, "contact-sheet.png");
  await page.screenshot({ path: sheet, fullPage: true });
  await page.close();

  // ── EVERY CELL ALSO WRITTEN FULL SIZE ────────────────────────────────────
  //
  // A cold reader, on the sheet itself: "at 1700x2227 for 21 browser screenshots, most
  // body text on this sheet is at or past the limit of legibility. I had to crop and
  // upscale roughly a dozen regions to read it, and I still failed on at least two
  // digits. A contact sheet that cannot be read by looking at it does not enforce the
  // rule printed at the top of it."
  //
  // That is the same criticism as the 1500ms wait, aimed at a different property of the
  // same instrument: the sheet was optimised for being PRODUCED rather than for being
  // read. The thumbnail grid is still the thing you scan; these are what you open when
  // the thumbnail shows you something you cannot resolve. Same scaling scar as the mark
  // rounds, where delivery downsampling once manufactured a finding about a Z.
  for (const c of cells) {
    const file = path.join(OUT, `${c.id}-${c.w}${c.arrived === false ? "-WAITING" : ""}.png`);
    writeFileSync(file, Buffer.from(c.url.split(",")[1], "base64"));
  }

  writeFileSync(
    path.join(OUT, "cells.json"),
    JSON.stringify({
      at: new Date().toISOString(),
      widths: WIDTHS,
      surfaces: SURFACES.map((s) => s.id),
      // The state of every capture, machine-readable, so a later reader can tell which
      // cells were the loaded page without squinting at a caption.
      captures: cells.map((c) => ({ surface: c.id, width: c.w, loaded: c.arrived !== false })),
    }, null, 2)
  );
  console.log(`contact sheet: ${sheet}`);
  console.log(`full-size cells: ${OUT}/<surface>-<width>.png`);
  console.log(`${cells.length} cells — ${SURFACES.length} surfaces x ${WIDTHS.length} widths`);
  console.log("");
  console.log("THIS RUN IS NOT GREEN UNTIL THE SHEET HAS BEEN OPENED AND A LINE WRITTEN");
  console.log("PER SURFACE. Producing the picture is not the same as looking at it, and");
  console.log("the whole reason this step exists is that I could not tell the difference.");
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
