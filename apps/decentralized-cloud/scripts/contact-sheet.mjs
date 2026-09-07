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

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES } from "../src/logic/surfaces.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const OUT = path.join(APP, "brand/.artifacts/contact");
const PORT = Number(process.env.IOI_DC_SHEET_PORT || 4205);
const WIDTHS = [1440, 1180, 390];
// The phone width, and the band height its unscaled crops are written in. 760 is a
// readable slice at true size without being so tall that delivery scales it again.
const NARROW = 390;
const BAND = 760;

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
  spend: ".t-budgets .trow",
  iam: ".t-leases .trow",
  supply: ".t-supply .trow",
  settings: ".t-pairs .trow",
  home: ".t-health .trow",
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

// PROVENANCE, MEASURED AT CAPTURE TIME — a sheet that cannot say which build it
// photographed is not evidence.
//
// This script does NOT build; it serves whatever is in dist/. That is deliberate — the
// sheet is for looking at, and rebuilding under it would change what is on screen
// mid-shoot. But it means the bytes it photographs are whoever's build landed there last,
// and a run of this script was straddled by a peer session's rebuild five seconds after it
// started: half the cells were one commit's bytes and half another's, with nothing in the
// images saying so. That sheet was voided. A mixed sheet is not a result to interpret, it
// is no result — and it is indistinguishable by eye from a clean one.
//
// So the run REFUSES to start against a dirty tree, records the commit, and fingerprints
// the served bundle before and after the shoot. If the fingerprint moves, somebody rebuilt
// underneath and the whole sheet is declared void rather than published.
const git = (args) => spawnSync("git", args, { cwd: APP, encoding: "utf8" }).stdout.trim();
const COMMIT = git(["rev-parse", "--short", "HEAD"]);
const DIRTY = git(["status", "--porcelain", "--", "src", "public", "index.html"]);
if (DIRTY) {
  console.log("REFUSING TO SHOOT — the surface tree has uncommitted changes:");
  console.log(DIRTY.split("\n").map((l) => `  ${l}`).join("\n"));
  console.log("A sheet shot over a dirty tree cannot name what it photographed. Commit or stash first.");
  process.exit(1);
}

const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
  // PINNED, not inherited: an ambient IOI_DC_DIST would point this shoot at a different
  // build than the one this run names in its own output.
  env: { ...process.env, IOI_DC_PORT: String(PORT), IOI_DC_DIST: path.join(APP, "dist") },
  stdio: ["ignore", "pipe", "pipe"],
});
let booted = false;
server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
for (let i = 0; i < 600 && !booted; i++) await new Promise((r) => setTimeout(r, 100));
if (!booted) { server.kill("SIGTERM"); throw new Error("the face server did not start within 60s"); }

const fingerprint = async () => {
  const t = await (await fetch(`http://127.0.0.1:${PORT}/assets/face.js`)).text();
  return `${t.length}:${createHash("sha256").update(t).digest("hex").slice(0, 12)}`;
};
const FP_BEFORE = await fingerprint();
console.log(`shooting ${COMMIT} — served bundle ${FP_BEFORE}`);

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
      // `domcontentloaded`, NOT `networkidle`.
      //
      // networkidle waits for the network to go quiet, and this surface's network never
      // does: the catalog read runs ~30s and Candidates polls every 30s, so on a page
      // whose default surface reads sources, goto's own 30s timeout expired before the
      // first quiet moment and the sheet crashed outright.
      //
      // It was also the wrong signal all along. What this sheet needs to know is "has
      // THIS surface's content arrived", and the selector wait below answers exactly
      // that, by name, with a 90s ceiling and a NOT-MEASURED label when it does not.
      // networkidle was a proxy for that question that happened to work while the
      // default surface was cheap.
      await page.goto(`http://127.0.0.1:${PORT}/#/${s.id}`, { waitUntil: "domcontentloaded" });

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
      // THE WAIT IS RECORDED, NOT JUST ENDURED. Standing practice §1 says a capture
      // states the wait it observed; this file said so in a comment and wrote only a
      // boolean. An instrument reader asked for the number and found it absent.
      const t0 = Date.now();
      if (want) {
        arrived = await page.waitForSelector(want, { timeout: 90_000 })
          .then(() => true).catch(() => false);
      }
      const waitedMs = Date.now() - t0;
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
        w, id: s.id, label: s.label, arrived, waitedMs,
        url: `data:image/png;base64,${buf.toString("base64")}`,
      });
      if (!arrived) {
        console.log(`  !! ${s.id} @ ${w}px — content did not arrive within 90s; this cell is a WAITING page`);
      }

      // ── THE PHONE WIDTH IS ALSO WRITTEN IN UNSCALED BANDS ──────────────────
      //
      // A full-page 390px capture is about 390x4600, and it downsamples ~2.3x on the
      // way to whoever is reading it. Two real defects were invisible in exactly that
      // image and legible the moment it was cropped unscaled: a daemon label clipped
      // off the left edge, and a state chip wrapping to four lines into a distorted
      // pill.
      //
      // This is the same class of instrument error as a magnified glyph plate — the
      // one that manufactured a mark finding twice in this programme — so the phone
      // width gets the same discipline the mark plate gets: nothing scaled, look at
      // the pixels that ship.
      // EVERY WIDTH, NOT ONLY THE PHONE. Receipts at 1440 is 6,800px tall; delivered
      // whole it arrives at ~0.29 scale and an instrument reader called it illegible and
      // cropped it by hand to read it at all. The bands are the reading copy for every
      // cell whose height would force a scale-down; a short page writes one band.
      {
        const full = await page.evaluate(() => document.documentElement.scrollHeight);
        for (let y = 0, n = 0; y < full; y += BAND, n += 1) {
          const h = Math.min(BAND, full - y);
          if (h < 40) break;                       // a sliver at the end carries nothing
          const band = await page.screenshot({
            fullPage: true, clip: { x: 0, y, width: w, height: h },
          });
          writeFileSync(path.join(OUT, `${s.id}-${w}-band${n}.png`), band);
        }
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
          ? `${c.label} · ${w}px — <b>STILL WAITING after ${(c.waitedMs / 1000).toFixed(1)}s; this is not the loaded page</b>`
          : `${c.label} · ${w}px · loaded after ${(c.waitedMs / 1000).toFixed(1)}s`;
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
      captures: cells.map((c) => ({
        surface: c.id, width: c.w, loaded: c.arrived !== false,
        // The wait the capture observed before its content arrived (or the 90s ceiling
        // when it did not), in milliseconds — the number §1 promises.
        waited_ms: c.waitedMs,
      })),
    }, null, 2)
  );
  // THE SAME BUNDLE AT THE END AS AT THE START, or none of this is one build.
  const fpAfter = await fingerprint();
  if (fpAfter !== FP_BEFORE) {
    console.log("");
    console.log(`SHEET VOID — the served bundle changed under the shoot: ${FP_BEFORE} -> ${fpAfter}.`);
    console.log("Someone rebuilt while this was running. Some cells are one build and some are");
    console.log("another, and nothing in the images says which. This is not a mixed result to be");
    console.log("read with care; it is no result. Re-shoot from a quiet tree.");
    process.exit(1);
  }
  console.log(`contact sheet: ${sheet}`);
  console.log(`shot from ${COMMIT}, served bundle ${FP_BEFORE} unchanged across the shoot`);
  console.log(`full-size cells: ${OUT}/<surface>-<width>.png`);
  console.log(`unscaled ${BAND}px bands at every width: ${OUT}/<surface>-<width>-band<n>.png`);
  console.log(`${cells.length} cells — ${SURFACES.length} surfaces x ${WIDTHS.length} widths`);
  console.log("");
  console.log("THIS RUN IS NOT GREEN UNTIL THE SHEET HAS BEEN OPENED AND A LINE WRITTEN");
  console.log("PER SURFACE. Producing the picture is not the same as looking at it, and");
  console.log("the whole reason this step exists is that I could not tell the difference.");
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
