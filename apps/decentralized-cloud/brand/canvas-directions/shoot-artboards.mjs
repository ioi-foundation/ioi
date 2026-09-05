#!/usr/bin/env node
// Render each artboard to a PNG so cold readers can judge the DESIGN rather than the
// canvas chrome. A .dc.html is a canvas component: its styles live in <helmet> and its
// body in <x-dc>, both of which the canvas runtime unwraps at render time. This does
// the same unwrapping so the file can be shot standalone.
//
// deviceScaleFactor 2 here, deliberately and unlike the mark plate: these are 1440px
// layouts being judged on composition and type, not glyphs being judged at true 16px,
// and a reader looking at a downsampled 1440 layout is judging a blur. The mark plate's
// rule — never magnify, never downsample — is about what is being MEASURED, not a
// blanket setting.
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "shots");
mkdirSync(OUT, { recursive: true });

const unwrap = (src) => {
  const helmet = (src.match(/<helmet>([\s\S]*?)<\/helmet>/) || [, ""])[1];
  const body = (src.match(/<x-dc>([\s\S]*?)<\/x-dc>/) || [, ""])[1].replace(/<helmet>[\s\S]*?<\/helmet>/, "");
  const bodyStyle = (src.match(/body\s*\{([^}]*)\}/) || [, ""])[1];
  return `<!doctype html><meta charset="utf-8">${helmet}<style>html,body{${bodyStyle}}</style>${body}`;
};

const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const files = readdirSync(HERE).filter((f) => f.endsWith(".dc.html")).sort();
for (const f of files) {
  const tmp = path.join(OUT, f.replace(".dc.html", ".render.html"));
  writeFileSync(tmp, unwrap(readFileSync(path.join(HERE, f), "utf8")));
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await page.goto("file://" + tmp, { waitUntil: "networkidle" });
  // WAIT FOR THE WEBFONTS, explicitly. `networkidle` plus a fixed pause shot the first
  // pass before Archivo arrived, so every headline rendered in a fallback serif — and
  // a reader judging that is judging a direction I did not specify. Same class as the
  // contact sheet photographing a loading page: the instrument showed something other
  // than the artifact, and the fixed wait was the tell.
  const fontsReady = await page.evaluate(() => document.fonts.ready.then(() => document.fonts.status));
  if (fontsReady !== "loaded") console.log(`  !! ${f}: fonts ${fontsReady}`);
  await page.waitForTimeout(400);
  const out = path.join(OUT, f.replace(".dc.html", ".png"));
  await page.screenshot({ path: out, fullPage: true });
  await page.close();
  console.log("wrote", path.basename(out));
}
await browser.close();
