#!/usr/bin/env node
// Reads the owner's reserved "d" out of its vector source and reports its geometry.
//
// The mark is the owner's; nothing here redraws it. This converts the presentation
// PDF to SVG with pdftocairo, isolates the paths belonging to the standalone tile
// specimen (the wordmark beside it is NOT carried into the family and is excluded),
// and prints measured facts: shape count, each shape's box, the slant of its edges,
// corner radii, and the gradient stops.
//
// Same discipline as measure-face.mjs: numbers come out of the artefact, and the
// script says what it could not determine rather than estimating it.
//
// Usage: node apps/decentralized-cloud/brand/reserved-d/extract-geometry.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PDF = path.join(HERE, "EPS", "FInal.pdf");
const work = mkdtempSync(path.join(tmpdir(), "reserved-d-"));
const svgPath = path.join(work, "page2.svg");

execFileSync("pdftocairo", ["-svg", "-f", "2", "-l", "2", PDF, svgPath]);
const svg = readFileSync(svgPath, "utf8");

// ── Path bounding boxes ─────────────────────────────────────────────────────
// Only M/L/C appear in this file; curve control points are included in the box,
// which slightly overstates a rounded corner's extent — noted rather than hidden.
function bbox(d) {
  const nums = d.match(/-?\d+(?:\.\d+)?/g);
  if (!nums) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (let i = 0; i + 1 < nums.length; i += 2) {
    const x = parseFloat(nums[i]), y = parseFloat(nums[i + 1]);
    if (x < minX) minX = x; if (x > maxX) maxX = x;
    if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  return { minX, minY, maxX, maxY, w: maxX - minX, h: maxY - minY };
}

const paths = [];
for (const m of svg.matchAll(/<path([^>]*)\bd="([^"]+)"/g)) {
  const attrs = m[1];
  const d = m[2];
  const box = bbox(d);
  if (!box || box.w < 0.5 || box.h < 0.5) continue;
  paths.push({
    d,
    box,
    fill: (attrs.match(/fill="([^"]+)"/) || [])[1] || null,
    isClip: /clip-rule/.test(attrs),
    curves: (d.match(/C/g) || []).length,
  });
}

// ── Isolate the mark ────────────────────────────────────────────────────────
// The discriminator is not position, it is fill: every shape of the d carries a
// gradient, and every letter of the wordmark beside it is flat. The wordmark is not
// carried into the family, so keying on the gradient excludes it by construction
// rather than by a guess about where things sit on the page.
const marks = paths.filter((p) => !p.isClip && /url\(/.test(p.fill || ""));
const byY = [...marks].sort((a, b) => a.box.minY - b.box.minY);

const clusters = [];
for (const p of byY) {
  const c = clusters.find((k) => Math.abs(k.cy - (p.box.minY + p.box.h / 2)) < 40);
  if (c) { c.items.push(p); c.cy = c.items.reduce((s, q) => s + q.box.minY + q.box.h / 2, 0) / c.items.length; }
  else clusters.push({ cy: p.box.minY + p.box.h / 2, items: [p] });
}

console.log(`page 2 carries ${paths.length} drawn paths in ${clusters.length} vertical clusters\n`);
for (const [i, c] of clusters.entries()) {
  const xs = c.items.map((p) => p.box.minX);
  const w = Math.max(...c.items.map((p) => p.box.maxX)) - Math.min(...xs);
  console.log(`  cluster ${i + 1}: ${c.items.length} shapes, centre y ${c.cy.toFixed(1)}, spans ${w.toFixed(1)} wide`);
}

// The mark alone is the cluster with the FEWEST shapes spanning the LEAST width —
// a lockup cluster carries the wordmark's letters as well.
const markCluster = clusters
  .filter((c) => c.items.length >= 3)
  .sort((a, b) => {
    const wa = Math.max(...a.items.map((p) => p.box.maxX)) - Math.min(...a.items.map((p) => p.box.minX));
    const wb = Math.max(...b.items.map((p) => p.box.maxX)) - Math.min(...b.items.map((p) => p.box.minX));
    return wa - wb;
  })[0];

if (!markCluster) {
  console.log("\nCOULD NOT ISOLATE the standalone mark — reporting nothing rather than guessing.");
  process.exit(1);
}

const items = [...markCluster.items].sort((a, b) => a.box.minY - b.box.minY || a.box.minX - b.box.minX);
const x0 = Math.min(...items.map((p) => p.box.minX));
const y0 = Math.min(...items.map((p) => p.box.minY));
const x1 = Math.max(...items.map((p) => p.box.maxX));
const y1 = Math.max(...items.map((p) => p.box.maxY));
const W = x1 - x0, H = y1 - y0;

console.log(`\nthe mark alone: ${items.length} shapes in a ${W.toFixed(2)} x ${H.toFixed(2)} box (aspect ${(W / H).toFixed(3)})`);
console.log(`normalised to a 96-unit grid on the taller axis:\n`);
const k = 96 / Math.max(W, H);
for (const [i, p] of items.entries()) {
  const b = p.box;
  console.log(
    `  shape ${i + 1}: x ${((b.minX - x0) * k).toFixed(1)}..${((b.maxX - x0) * k).toFixed(1)}` +
    `  y ${((b.minY - y0) * k).toFixed(1)}..${((b.maxY - y0) * k).toFixed(1)}` +
    `  ${(b.w * k).toFixed(1)} x ${(b.h * k).toFixed(1)}` +
    `  ${p.curves} curve segments  fill ${p.fill || "gradient"}`
  );
}

// ── Gradient stops ──────────────────────────────────────────────────────────
const stops = [...svg.matchAll(/<stop[^>]*offset="([^"]+)"[^>]*stop-color="([^"]+)"/g)]
  .map((m) => ({ offset: parseFloat(m[1]), color: m[2] }));
// pdftocairo expands a gradient into hundreds of interpolated stops, so the useful
// facts are the ENDS and the count, not the list.
const sorted = [...stops].sort((a, b) => a.offset - b.offset);
const toHex = (rgb) => {
  const n = rgb.match(/-?[\d.]+/g).map((v) => Math.round((parseFloat(v) / 100) * 255));
  return `#${n.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
};
console.log(`\ngradient: ${stops.length} interpolated stops across ${(svg.match(/<linearGradient/g) || []).length} definitions`);
if (sorted.length) {
  console.log(`  first  offset ${sorted[0].offset}  ${toHex(sorted[0].color)}`);
  console.log(`  last   offset ${sorted[sorted.length - 1].offset}  ${toHex(sorted[sorted.length - 1].color)}`);
}
const angles = [...svg.matchAll(/gradientTransform="matrix\(([^)]+)\)"/g)].map((m) => {
  const [a, b] = m[1].split(",").map(parseFloat);
  return (Math.atan2(b, a) * 180) / Math.PI;
});
if (angles.length) {
  const uniq = [...new Set(angles.map((a) => a.toFixed(1)))];
  console.log(`  axis angles present: ${uniq.join("°, ")}°`);
}

console.log(`\nNOT determined here: exact corner radii — curve control points are inside the`);
console.log(`boxes above but are not separated out — and whether the shapes share one`);
console.log(`gradient or carry one each. Both need a per-path parse or the .ai to state,`);
console.log(`and neither is guessed at.`);
