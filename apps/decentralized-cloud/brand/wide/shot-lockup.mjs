#!/usr/bin/env node
// A picture of the SHIPPED lockup, taken from the running server.
//
// Not of a re-composition of it — of the bytes the server sends. The drawn I's CSS
// width is set independently of its viewBox, and an SVG box narrower than its viewBox
// shrinks the glyph to fit and centres it in the slack. That failure is silent, it
// passes every assertion in the face gate, and it is invisible to anything except
// looking at the picture.

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "../..");
const OUT = path.join(HERE, "../.artifacts/shipped");
mkdirSync(OUT, { recursive: true });
const PORT = Number(process.env.IOI_DC_SHOT_PORT || 4191);

const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
  env: { ...process.env, IOI_DC_PORT: String(PORT) },
  stdio: ["ignore", "pipe", "pipe"],
});
let booted = false;
server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
for (let i = 0; i < 60 && !booted; i++) await new Promise((r) => setTimeout(r, 100));
if (!booted) { server.kill("SIGTERM"); throw new Error("the face server did not start"); }

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 700 }, deviceScaleFactor: 1 });
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  const lock = page.locator(".lockup");
  await lock.screenshot({ path: path.join(OUT, "lockup-shipped-22px.png") });

  // The same lockup at the sizes the identity actually has to survive, driven by the
  // page's own CSS rather than by a re-composition: the wordmark's font-size is set
  // inline on the element, so this changes exactly what a narrow viewport would.
  for (const px of [16, 13]) {
    await page.evaluate((size) => {
      document.querySelector(".wordmark").style.fontSize = `${size}px`;
    }, px);
    await lock.screenshot({ path: path.join(OUT, `lockup-shipped-${px}px.png`) });
  }
  console.log(`wrote three shots of the SERVED lockup to ${OUT}`);
} finally {
  await browser.close();
  server.kill("SIGTERM");
}
