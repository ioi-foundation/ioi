#!/usr/bin/env node
// PICTURES OF THE PORTED SURFACE, from the running server.
//
// The gate measures overflow, collisions, table semantics and served bytes, and every
// one of those was green on a build whose tables had no scroll container because I
// had invented a class name the stylesheet does not define. The overflow probe caught
// that one. It would not have caught a table that renders but reads as nonsense, a
// panel that lost its heading, or a surface that paints nothing at all — and five
// defects in this programme's history passed every number and were plain in a
// screenshot.
//
// Usage: node apps/decentralized-cloud/brand/wide/shot-surfaces.mjs

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "../..");
const OUT = path.join(HERE, "../.artifacts/surfaces");
mkdirSync(OUT, { recursive: true });
const PORT = Number(process.env.IOI_DC_SHOT_PORT || 4192);

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
try {
  for (const [w, h] of [[1520, 900], [1280, 900], [390, 900]]) {
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    for (const surface of ["candidates", "sources", "job", "receipts", "api"]) {
      await page.goto(`http://127.0.0.1:${PORT}/#/${surface}`, { waitUntil: "networkidle" });
      // The reads are slow by design and the surface says so while it waits; a shot
      // taken during the wait would be a picture of the waiting state, which is a real
      // state but not the one being reviewed here.
      await page.waitForTimeout(2500);
      await page.screenshot({ path: path.join(OUT, `${surface}-${w}px.png`), fullPage: w > 400 });
    }
    await page.close();
  }
  console.log(`wrote ten shots of the ported surface to ${OUT}`);
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
