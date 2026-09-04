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
  //
  // Overflow is only half of it: two reviews caught elements COLLIDING inside a frame,
  // which no overflow measurement can see — a chip overrunning its grid column into the
  // prose beside it stays comfortably within the artboard. So leaf boxes are checked
  // pairwise too. Only leaves, and only siblings that are not positioned on purpose,
  // so a deliberately stacked layer is not reported as a fault.
  const m = await page.evaluate(() => {
    let bottom = 0, right = 0;
    const leaves = [];
    for (const el of document.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      if (r.width || r.height) { bottom = Math.max(bottom, r.bottom); right = Math.max(right, r.right); }
      // "Leaf" means carries its own text, NOT childless: a chip holds a dot span
      // beside its label, and the first version of this check skipped exactly the
      // element whose overrun it was written to catch.
      const ownsText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (ownsText && r.width > 1 && r.height > 1) {
        const cs = getComputedStyle(el);
        if (cs.position === "static" && cs.visibility !== "hidden" && (el.textContent || "").trim()) {
          // An inline element that wraps reports ONE union box covering every line it
          // touches, which overlaps its own siblings by construction. Compare the
          // per-line fragments instead, or the check reports prose as a collision.
          leaves.push({
            el,
            rects: [...el.getClientRects()].filter((q) => q.width > 1 && q.height > 1),
            text: (el.textContent || "").trim().slice(0, 28),
          });
        }
      }
    }

    const collisions = [];
    for (let i = 0; i < leaves.length; i++) {
      for (let j = i + 1; j < leaves.length; j++) {
        const a = leaves[i], b = leaves[j];
        if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
        for (const ra of a.rects) {
          for (const rb of b.rects) {
            const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
            const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
            // A couple of pixels is antialiasing and line-box slack; more than that on
            // both axes is two things sitting on top of each other.
            if (ox > 3 && oy > 3) {
              collisions.push(`"${a.text}" over "${b.text}" (${Math.round(ox)}x${Math.round(oy)}px)`);
            }
          }
        }
      }
    }
    return { w: Math.ceil(right), h: Math.ceil(bottom), collisions: collisions.slice(0, 4), collisionCount: collisions.length };
  });

  await page.screenshot({ path: path.join(SHOTS, `${ab.file.replace(/\.dc\.html$/, "")}.png`), fullPage: true });
  await page.close();

  const dw = m.w - ab.w;
  const dh = m.h - ab.h;
  const clipped = dw > 0 || dh > 0;
  const collided = m.collisionCount > 0;
  if (clipped || collided) failures += 1;
  const slack = clipped ? `OVERFLOW +${Math.max(dw, 0)}w +${Math.max(dh, 0)}h` : `ok (${-dw}w ${-dh}h spare)`;
  const label = clipped ? "CLIP" : collided ? "OVER" : "OK  ";
  console.log(`  ${label}  ${ab.file.padEnd(22)} frame ${ab.w}x${ab.h}  content ${m.w}x${m.h}  ${slack}`);
  if (collided) {
    console.log(`        ${m.collisionCount} overlapping pair${m.collisionCount === 1 ? "" : "s"}:`);
    for (const c of m.collisions) console.log(`          ${c}`);
  }
}

await browser.close();
console.log(`\n${manifest.artboards.length - failures}/${manifest.artboards.length} artboards fit their frame with nothing colliding`);
console.log(`screenshots: ${path.relative(process.cwd(), SHOTS)}`);
process.exit(failures ? 1 : 0);
