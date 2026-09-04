#!/usr/bin/env node
// Per-path parse of the owner's reserved d: corner radii per shape, and whether the
// three shapes share one gradient or carry one each.
//
// extract-geometry.mjs reports boxes and refuses to state radii. This goes the next
// step and reads the path commands themselves. Where a value still cannot be read
// out of the source it is reported as not determinable rather than estimated — a
// derived form may then choose its own radius, but it has to say that it chose.
//
// Usage: node apps/decentralized-cloud/brand/reserved-d/parse-shapes.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PDF = path.join(HERE, "EPS", "FInal.pdf");
const work = mkdtempSync(path.join(tmpdir(), "reserved-d-shapes-"));
const svgPath = path.join(work, "page2.svg");
execFileSync("pdftocairo", ["-svg", "-f", "2", "-l", "2", PDF, svgPath]);
const svg = readFileSync(svgPath, "utf8");

// ── The mark's shapes: gradient-filled, as established ──────────────────────
//
// The gradient path is only the PAINT: each is a bare quadrilateral (M, three L, Z)
// with square corners. The rounded silhouette lives in the clipPath the paint is
// drawn through, so the radii have to be read there. Reading the fill path alone
// reports "no curves" and would have concluded the mark has square corners, which
// the artwork plainly contradicts.
const clipOf = new Map();
for (const g of svg.matchAll(/<g clip-path="url\(#([^)]+)\)">\s*<path[^>]*fill="url\(#([^)"]+)\)"/g)) {
  clipOf.set(g[2], g[1]);
}
const clipPaths = new Map();
for (const c of svg.matchAll(/<clipPath id="([^"]+)">\s*<path([^>]*)\bd="([^"]+)"/g)) {
  clipPaths.set(c[1], c[3]);
}

const shapes = [];
for (const m of svg.matchAll(/<path([^>]*)\bd="([^"]+)"/g)) {
  const fill = (m[1].match(/fill="([^"]+)"/) || [])[1] || "";
  if (!/url\(/.test(fill) || /clip-rule/.test(m[1])) continue;
  const ref = (fill.match(/#([^)"]+)/) || [])[1];
  shapes.push({ fill, d: m[2], ref, clipId: clipOf.get(ref) || null, clipD: clipPaths.get(clipOf.get(ref)) || null });
}

// Three copies of the mark sit on the page; take the tightest vertical cluster.
const boxOf = (d) => {
  const n = d.match(/-?\d+(?:\.\d+)?/g).map(Number);
  let a = Infinity, b = Infinity, c = -Infinity, e = -Infinity;
  for (let i = 0; i + 1 < n.length; i += 2) {
    a = Math.min(a, n[i]); c = Math.max(c, n[i]);
    b = Math.min(b, n[i + 1]); e = Math.max(e, n[i + 1]);
  }
  return { x0: a, y0: b, x1: c, y1: e };
};
for (const s of shapes) s.box = boxOf(s.d);
const clusters = [];
for (const s of [...shapes].sort((p, q) => p.box.y0 - q.box.y0)) {
  const cy = (s.box.y0 + s.box.y1) / 2;
  const k = clusters.find((c) => Math.abs(c.cy - cy) < 60);
  if (k) { k.items.push(s); k.cy = k.items.reduce((t, i) => t + (i.box.y0 + i.box.y1) / 2, 0) / k.items.length; }
  else clusters.push({ cy, items: [s] });
}
const mark = clusters.filter((c) => c.items.length === 3)[0];
if (!mark) {
  console.log("COULD NOT ISOLATE a three-shape copy of the mark — reporting nothing.");
  process.exit(1);
}

// ── Command census and corner geometry ──────────────────────────────────────
//
// The VISIBLE shape is the clip, not the paint: each gradient quad is deliberately
// oversized and cut down by a rounded clipPath. So the clip box is the geometry, and
// normalising off the paint would describe shapes larger than anything on the page.
for (const s of mark.items) {
  s.visible = s.clipD ? boxOf(s.clipD) : s.box;
}
const y0all = Math.min(...mark.items.map((s) => s.visible.y0));
const y1all = Math.max(...mark.items.map((s) => s.visible.y1));
const x0all = Math.min(...mark.items.map((s) => s.visible.x0));
const x1all = Math.max(...mark.items.map((s) => s.visible.x1));
const H = y1all - y0all;
const k96 = 96 / H;
console.log(
  `visible mark box ${((x1all - x0all) * k96).toFixed(1)} x 96.0 units ` +
  `(aspect ${((x1all - x0all) / H).toFixed(3)}), normalised on the taller axis\n`
);

console.log(`the mark: ${mark.items.length} gradient-filled shapes\n`);
for (const [i, s] of mark.items.entries()) {
  const cmds = s.d.match(/[MLCZmlcz]/g) || [];
  const census = cmds.reduce((acc, c) => ((acc[c] = (acc[c] || 0) + 1), acc), {});
  const w = (s.visible.x1 - s.visible.x0) * k96;
  const h = (s.visible.y1 - s.visible.y0) * k96;

  // Radii come from the CLIP, not the paint. A rounded corner is emitted as one C
  // between two straight runs; for a circular quarter-turn the chord between its
  // endpoints is r·√2, so r ≈ chord / √2.
  const source = s.clipD || s.d;
  const segs = [...source.matchAll(/C\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)/g)];
  const chords = [];
  let prevEnd = null;
  for (const g of source.matchAll(/([MLC])((?:\s*-?[\d.]+)+)/g)) {
    const n = g[2].trim().split(/\s+/).map(Number);
    if (g[1] === "C") {
      const end = [n[4], n[5]];
      if (prevEnd) chords.push(Math.hypot(end[0] - prevEnd[0], end[1] - prevEnd[1]) * k96);
      prevEnd = end;
    } else {
      prevEnd = [n[n.length - 2], n[n.length - 1]];
    }
  }

  console.log(`  shape ${i + 1}  ${w.toFixed(1)} x ${h.toFixed(1)} units on a 96 grid`);
  console.log(`     paint path commands: ${Object.entries(census).map(([c, n]) => `${c}x${n}`).join(" ") || "none parsed"}`);
  console.log(`     gradient: ${s.ref}`);
  // A clip can be a loose bounding region rather than the true silhouette. If its
  // box is materially larger than the paint's, its curves describe something else
  // and the radii below would be measuring the wrong object.
  let clipNote = "NO CLIP FOUND — the paint path is the silhouette";
  if (s.clipD) {
    const cb = boxOf(s.clipD);
    const dw = ((cb.x1 - cb.x0) - (s.box.x1 - s.box.x0)) * k96;
    const dh = ((cb.y1 - cb.y0) - (s.box.y1 - s.box.y0)) * k96;
    const tight = Math.abs(dw) < 4 && Math.abs(dh) < 4;
    clipNote = dw < 0 || dh < 0
      ? `clip ${s.clipId} — the cutter; the gradient quad behind it is ${(-dw).toFixed(1)} x ${(-dh).toFixed(1)} units larger and is never seen`
      : `clip ${s.clipId} — LARGER than the paint, so it is a bounding region and its curves describe something else; radii below are suspect`;
  }
  console.log(`     silhouette: ${clipNote}`);
  if (chords.length) {
    const radii = chords.map((c) => c / Math.SQRT2).sort((a, b) => a - b);
    console.log(`     ${chords.length} curve segments; implied corner radii ` +
      `${radii[0].toFixed(2)}..${radii[radii.length - 1].toFixed(2)} units ` +
      `(median ${radii[Math.floor(radii.length / 2)].toFixed(2)})`);
  } else {
    console.log(`     NO curve segments in the path — corners are not rounded in this`);
    console.log(`     rendering, so a radius is NOT DETERMINABLE from this source.`);
  }
}

// ── Gradient: shared or per shape ───────────────────────────────────────────
const refs = mark.items.map((s) => s.ref);
console.log(`\ngradient definitions referenced: ${[...new Set(refs)].length} for ${refs.length} shapes`);
const stopsOf = (id) => {
  const block = svg.match(new RegExp(`<linearGradient id="${id}"[\\s\\S]*?</linearGradient>`));
  if (!block) return null;
  const st = [...block[0].matchAll(/offset="([^"]+)"[^>]*stop-color="rgb\(([^)]+)\)"/g)]
    .map((m) => ({ o: parseFloat(m[1]), c: m[2] }));
  if (!st.length) return null;
  const hex = (rgb) => "#" + rgb.split(",").map((v) => Math.round((parseFloat(v) / 100) * 255).toString(16).padStart(2, "0")).join("");
  const tr = block[0].match(/gradientTransform="matrix\(([^)]+)\)"/);
  const ang = tr ? (Math.atan2(parseFloat(tr[1].split(",")[1]), parseFloat(tr[1].split(",")[0])) * 180) / Math.PI : null;
  return { n: st.length, from: hex(st[0].c), to: hex(st[st.length - 1].c), angle: ang };
};
for (const [i, r] of refs.entries()) {
  const g = stopsOf(r);
  console.log(g
    ? `  shape ${i + 1}: ${r} — ${g.n} stops, ${g.from} → ${g.to}, axis ${g.angle.toFixed(1)}°`
    : `  shape ${i + 1}: ${r} — could not read its stops`);
}
// ── Flat-token derivation ───────────────────────────────────────────────────
// A flat form cannot flatten "the" gradient, because there is no single ramp. Each
// shape gets the midpoint of its OWN ramp, and the sweep survives as three steps.
// Whether those midpoints already exist as tokens is a fact, not a preference.
const tokensCss = readFileSync(
  path.join(HERE, "../../../..", "packages/design-system/tokens/colors.css"), "utf8"
);
const tokens = [...tokensCss.matchAll(/(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})/g)]
  .map((m) => ({ name: m[1], hex: m[2].toLowerCase() }));
const rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
const mid = (a, b) => {
  const [ra, ga, ba] = rgb(a), [rb, gb, bb] = rgb(b);
  return "#" + [(ra + rb) / 2, (ga + gb) / 2, (ba + bb) / 2]
    .map((v) => Math.round(v).toString(16).padStart(2, "0")).join("");
};
const nearest = (hex) => {
  const [r, g, b] = rgb(hex);
  let best = null;
  for (const t of tokens) {
    const [tr, tg, tb] = rgb(t.hex);
    const d = Math.hypot(r - tr, g - tg, b - tb);
    if (!best || d < best.d) best = { ...t, d };
  }
  return best;
};

console.log(`\nflat-token derivation — midpoint of each shape's own ramp:`);
const snaps = [];
for (const [i, r] of refs.entries()) {
  const g = stopsOf(r);
  if (!g) continue;
  const m = mid(g.from, g.to);
  const n = nearest(m);
  snaps.push(n.name);
  console.log(
    `  shape ${i + 1}: ${g.from} → ${g.to}  midpoint ${m}  ` +
    `nearest token ${n.name} ${n.hex} at distance ${n.d.toFixed(0)}/441` +
    `${n.d > 60 ? "  — TOO FAR; this needs a named token, not a snap" : "  — close enough to snap"}`
  );
}
// Snapping is only viable if the three stay three. If two shapes land on one token
// the sweep collapses, and the flat form stops carrying the thing it exists to carry.
const distinct = new Set(snaps).size;
console.log(
  distinct === snaps.length
    ? `\n  snapping keeps ${distinct} distinct steps — viable.`
    : `\n  snapping collapses ${snaps.length} shapes onto ${distinct} token${distinct === 1 ? "" : "s"}: the`
      + `\n  three-step sweep would become ${distinct}, so the flat form needs three NAMED tokens`
      + `\n  citing their source ramps rather than a snap to what already exists.`
);

// ── Emit the silhouettes, normalised ────────────────────────────────────────
// `--emit` prints the three clip paths translated and scaled onto a 96-unit grid so
// a board can draw the owner's geometry rather than an approximation of it. The
// numbers are the source's own; nothing here redraws a curve.
if (process.argv.includes("--emit")) {
  const scale = 96 / (y1all - y0all);
  const W = (x1all - x0all) * scale;
  console.log(`\n── reserved d, normalised to 96 units tall (${W.toFixed(2)} wide) ──`);
  console.log(`   translate by (${(-x0all).toFixed(3)}, ${(-y0all).toFixed(3)}) then scale ${scale.toFixed(5)}`);
  for (const [i, s] of mark.items.entries()) {
    const d = (s.clipD || s.d)
      .replace(/(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)/g, (_, a, b) =>
        `${((parseFloat(a) - x0all) * scale).toFixed(2)} ${((parseFloat(b) - y0all) * scale).toFixed(2)}`);
    console.log(`\n  shape ${i + 1} (${s.ref}):`);
    console.log(`  ${d.trim()}`);
  }
}

const ends = refs.map((r) => { const g = stopsOf(r); return g ? `${g.from}→${g.to}` : "?"; });
console.log(
  [...new Set(ends)].length === 1
    ? `\nAll three run the same ramp ${ends[0]} under different transforms: one gradient, three placements.`
    : `\nThe three do NOT share a ramp — they are ${[...new Set(ends)].length} distinct gradients.`
);
