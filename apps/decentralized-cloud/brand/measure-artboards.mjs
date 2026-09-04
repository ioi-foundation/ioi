#!/usr/bin/env node
// Renders every built artboard at the exact frame size canvas.json declares for it,
// measures overflow, and writes a PNG per artboard.
//
// A design canvas frame neither scales nor crops: content wider or taller than the
// declared w/h is CLIPPED, silently. The first review of this identity found five
// artboards clipping — including the wordmark losing its last letter — because the
// frames were sized by arithmetic instead of by rendering. This exists so that
// cannot happen again: nothing is published until this prints OK for every frame.
//
// Usage: node apps/decentralized-cloud/brand/measure-artboards.mjs

import { readFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// `--set <name>` measures a sibling built set (see build-artboards.mjs).
const setArg = process.argv.indexOf("--set");
const SET = setArg > -1 ? process.argv[setArg + 1] : null;
const CANVAS = SET ? path.join(HERE, `${SET}-canvas`) : path.join(HERE, "canvas");
const SHOTS = SET ? path.join(HERE, ".artifacts", SET) : path.join(HERE, ".artifacts");

// Playwright lives in the primary checkout; this worktree carries no node_modules.
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const manifest = JSON.parse(readFileSync(path.join(CANVAS, "canvas.json"), "utf8"));
mkdirSync(SHOTS, { recursive: true });

const browser = await chromium.launch();
let failures = 0;

for (const ab of manifest.artboards) {
  const page = await browser.newPage({ viewport: { width: ab.w, height: ab.h } });
  await page.goto(`file://${path.join(CANVAS, ab.file)}`);
  // The canvas runtime blocks these out; a bare browser needs telling.
  await page.addStyleTag({ content: "x-dc { display: block; } helmet { display: none; }" });
  await page.waitForTimeout(400); // let the inlined faces settle before measuring

  // scrollHeight saturates at the viewport, so an artboard with room to spare and one
  // that exactly fills its frame look identical. Measure the real ink bottom instead.
  const m = await page.evaluate(() => {
    let bottom = 0, right = 0;
    for (const el of document.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      if (r.width || r.height) { bottom = Math.max(bottom, r.bottom); right = Math.max(right, r.right); }
    }
    return { w: Math.ceil(right), h: Math.ceil(bottom) };
  });

  await page.screenshot({ path: path.join(SHOTS, `${ab.file.replace(/\.dc\.html$/, "")}.png`), fullPage: true });
  await page.close();

  const dw = m.w - ab.w;
  const dh = m.h - ab.h;
  const bad = dw > 0 || dh > 0;
  if (bad) failures += 1;
  const slack = bad ? `OVERFLOW +${Math.max(dw, 0)}w +${Math.max(dh, 0)}h` : `ok (${-dw}w ${-dh}h spare)`;
  console.log(`  ${bad ? "CLIP" : "OK  "}  ${ab.file.padEnd(22)} frame ${ab.w}x${ab.h}  content ${m.w}x${m.h}  ${slack}`);
}

await browser.close();
console.log(`\n${manifest.artboards.length - failures}/${manifest.artboards.length} artboards fit their frame`);
console.log(`screenshots: ${path.relative(process.cwd(), SHOTS)}`);
process.exit(failures ? 1 : 0);
