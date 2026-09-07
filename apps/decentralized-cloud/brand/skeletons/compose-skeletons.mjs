#!/usr/bin/env node
// Skeleton-stage harness for the new-mark phase.
//
// Renders every skeleton in `skeletons.mjs` at 16px, 24px and a 96px reference, in
// ONE INK on white, and measures three things about each. It writes the plates a
// cold reader is shown, and it refuses rather than printing a plausible number.
//
// What it measures, and why each exists:
//
//   1. INK PRESENCE (fail-closed). A render with no ink, or with the whole frame
//      inked, is not a measurement of a drawing — it is a broken render. Every
//      other number below would be describing nothing, so the run refuses.
//   2. SEPARATION. Each skeleton claims its parts stay apart at product size. The
//      probe scans one true-device-pixel line, at a coordinate DERIVED FROM THE
//      SKELETON'S OWN GEOMETRY rather than guessed at a fraction of the tile, and
//      counts runs of ink. Parameters — the ink threshold, the channel, the scan
//      axis and the scan line — are printed with the result, not implied by this
//      source.
//   3. CUE SEPARATION. A sibling is isolated by DIFFERENCING it against the same
//      skeleton drawn without any cue, because measuring the whole drawing pulls
//      in ink that is identical between siblings and compresses them together.
//      The measured minimum separation is then cross-checked against the closed
//      form implied by `cueCentres` in `skeletons.mjs`. A measurement that
//      disagrees with the arithmetic in the file is rejected as broken.
//
// The connected-region count is STRUCK by the phase brief and is not used here.
//
// Three positive controls run first. A probe that cannot fail on its own finding
// is not a probe, so each is handed exactly the defect it exists to catch and the
// run aborts unless the probe reports it.
//
// Usage: node apps/decentralized-cloud/brand/skeletons/compose-skeletons.mjs [--plates]

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
// `--set r2` measures the round-two skeletons. Round one stays on disk unchanged so
// its plates and its verdicts remain the record of what was killed and why.
const setArg = process.argv.indexOf("--set");
const SET = setArg > -1 ? process.argv[setArg + 1] : null;
const { SKELETONS, SIBLINGS, GRID, INK, GROUND, svg, scanAt } =
  await import(SET ? `./skeletons-${SET}.mjs` : "./skeletons.mjs");

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts", SET ? `skeletons-${SET}` : "skeletons");
const SIZES = [16, 24, 96];
const PRODUCT_SIZES = [16, 24];

// ── Stated parameters ───────────────────────────────────────────────────────
// Printed beside every result. The monogram phase's struck control chose its
// threshold after seeing which value returned the wanted answer; these are fixed
// here, once, and every number below is reported against them.
const CHANNEL = "mean of R,G,B";
const INK_AT = 200;        // luminance below this is ink present, on a white ground
const SOLID = 14;          // the ink's own luminance, for reporting coverage
const DIFF_AT = 8;         // per-pixel channel difference that counts as "changed"
const MIN_VISIBLE_PX = 1;  // a separation below one device pixel is one nobody sees

const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 800 }, deviceScaleFactor: 1 });
mkdirSync(OUT, { recursive: true });

// ── Rendering ───────────────────────────────────────────────────────────────
// Each drawing is rendered alone on a white page so nothing bleeds in from a
// neighbour, and screenshotted at true device pixels.
async function shoot(markup, size) {
  await page.setContent(
    `<style>body{margin:0;background:${GROUND};}</style>` +
    `<div id="stage" style="width:${size}px;height:${size}px;">${markup}</div>`
  );
  const buf = await page.locator("#stage").screenshot();
  return `data:image/png;base64,${buf.toString("base64")}`;
}

// The DIFFERENCING base. For rounds one and two the shape with no cue was simply
// draw(null); from round three the outline event is the identity, so draw(null) is
// the neutral SIBLING and a skeleton supplies a separate event-free base. Using the
// neutral sibling as its own base makes that sibling difference to nothing, drops it
// from the set, and reports a working cue as 0.00px — which is what it did.
const baseSvg = (sk, size) => sk.baseDraw
  ? `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
    sk.baseDraw().replace(/INK/g, INK) + `</svg>`
  : svg(sk, size, null);

const pixels = (dataUrl) => page.evaluate(async (u) => {
  const im = new Image(); im.src = u; await im.decode();
  const c = document.createElement("canvas");
  c.width = im.width; c.height = im.height;
  c.getContext("2d").drawImage(im, 0, 0);
  return { w: im.width, h: im.height, d: [...c.getContext("2d").getImageData(0, 0, im.width, im.height).data] };
}, dataUrl);

const lum = (d, p) => (d[p * 4] + d[p * 4 + 1] + d[p * 4 + 2]) / 3;

// 1 ── ink presence, fail-closed
function presence(im) {
  let on = 0;
  for (let p = 0; p < im.w * im.h; p++) if (lum(im.d, p) < INK_AT) on += 1;
  const frac = on / (im.w * im.h);
  return { on, frac, ok: on > 0 && frac < 0.98 };
}

// 2 ── separation along one scanned line
function separation(im, axis, atFrac) {
  const across = axis === "x" ? im.w : im.h;
  const line = Math.min((axis === "x" ? im.h : im.w) - 1,
                        Math.max(0, Math.round(atFrac * (axis === "x" ? im.h : im.w))));
  const runs = []; let run = null;
  for (let i = 0; i < across; i++) {
    const p = axis === "x" ? line * im.w + i : i * im.w + line;
    const L = lum(im.d, p);
    if (L < INK_AT) {
      const cov = Math.round(((255 - L) / (255 - SOLID)) * 100);
      if (!run) run = { a: i, b: i, peak: cov }; else { run.b = i; run.peak = Math.max(run.peak, cov); }
    } else if (run) { runs.push(run); run = null; }
  }
  if (run) runs.push(run);
  const gaps = runs.slice(1).map((r, k) => r.a - runs[k].b - 1);
  return { line, runs, gaps };
}

// 3 ── cue centre, isolated by differencing against the cue-less base
function cueCentre(imA, imB) {
  let sx = 0, sy = 0, wt = 0;
  for (let y = 0; y < imA.h; y++) for (let x = 0; x < imA.w; x++) {
    const p = y * imA.w + x;
    const diff = Math.abs(lum(imA.d, p) - lum(imB.d, p));
    if (diff > DIFF_AT) { sx += x * diff; sy += y * diff; wt += diff; }
  }
  return wt ? { x: sx / wt, y: sy / wt, wt } : null;
}

// 4 ── the top-edge profile, and how much of it survives
// Round one's survivor died on a fault no probe here could see: both readers said
// the taper that made it interesting flattens at 16px into a plain rectangle. That
// is measurable, so it is now measured. For each column, find the topmost inked row;
// the profile is that series. The RISE is the difference between its ends, in device
// pixels, and it is cross-checked against the rise the geometry declares.
function topProfile(im) {
  const tops = [];
  for (let x = 0; x < im.w; x++) {
    let top = null;
    for (let y = 0; y < im.h; y++) if (lum(im.d, y * im.w + x) < INK_AT) { top = y; break; }
    if (top !== null) tops.push({ x, top });
  }
  if (tops.length < 3) return null;
  // Ends are averaged over the outer eighth so one antialiased column cannot set the
  // answer; a single-column read is what makes a 1px measurement look like a slope.
  const k = Math.max(1, Math.round(tops.length / 8));
  const avg = (a) => a.reduce((s, p) => s + p.top, 0) / a.length;
  const left = avg(tops.slice(0, k)), right = avg(tops.slice(-k));
  return { rise: left - right, left, right, cols: tops.length, k };
}

// 5 ── silhouette distinctness
// Round two produced four candidates that two readers independently called the same
// drawing: a dark mass with one small interior subtraction, and at 16px a subtraction
// is one to three device pixels. So the silhouettes are compared directly, with every
// counter CLOSED. Intersection over union of the two ink masks, at 16px: 1.0 is the
// same raster, 0 is no shared ink at all. A pair above the threshold means the two
// marks differ only in what they contain, not in what they are.
const IOU_AT = 0.80;
function inkMask(im) {
  const m = new Uint8Array(im.w * im.h);
  for (let p = 0; p < im.w * im.h; p++) m[p] = lum(im.d, p) < INK_AT ? 1 : 0;
  return m;
}
function iou(a, b) {
  let inter = 0, union = 0;
  for (let p = 0; p < a.length; p++) { if (a[p] && b[p]) inter++; if (a[p] || b[p]) union++; }
  return union ? inter / union : 0;
}

const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
const minPairwise = (pts) => {
  let m = Infinity;
  for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) m = Math.min(m, dist(pts[i], pts[j]));
  return m;
};

// ── Positive controls ───────────────────────────────────────────────────────
// Each probe is handed the exact defect it exists to catch. If it reports the
// drawing as sound, the probe is not a probe and this run is worthless.
console.log(`parameters: channel ${CHANNEL}; ink at luminance < ${INK_AT}; solid ink ${SOLID};`);
console.log(`            diff threshold ${DIFF_AT}; visible-separation floor ${MIN_VISIBLE_PX}px; deviceScaleFactor 1\n`);
console.log("positive controls — each probe is given the defect it exists to catch:");

let controlsOk = true;
const control = (what, passed, detail) => {
  if (!passed) controlsOk = false;
  console.log(`  ${passed ? "CAUGHT " : "MISSED "} ${what}${detail ? `  (${detail})` : ""}`);
};

// (a) fail-closed: an empty frame must be refused, not measured.
{
  const im = await pixels(await shoot(`<svg width="24" height="24"><rect width="24" height="24" fill="${GROUND}"/></svg>`, 24));
  const p = presence(im);
  control("empty frame refused by the presence probe", !p.ok, `${p.on} ink px`);
}
// (b) fusion: three bars drawn with NO gap must read as one run, not three.
{
  const fused = `<svg width="24" height="24" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    [0, 1, 2].map((i) => `<rect x="10" y="${12 + i * 16}" width="46" height="16" fill="${INK}"/>`).join("") + `</svg>`;
  const s = separation(await pixels(await shoot(fused, 24)), "y", 18 / GRID);
  control("gapless bars reported as ONE run by the separation probe", s.runs.length === 1, `${s.runs.length} runs`);
}
// (c) a cue that does not move: three "siblings" drawn identically must measure
//     zero separation and be reported not distinguishable.
{
  const same = `<svg width="24" height="24" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    `<circle cx="48" cy="48" r="20" fill="${INK}"/></svg>`;
  const base = `<svg width="24" height="24" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/></svg>`;
  const b = await pixels(await shoot(base, 24));
  const cs = [];
  for (let i = 0; i < 3; i++) cs.push(cueCentre(await pixels(await shoot(same, 24)), b));
  const sep = minPairwise(cs);
  control("identical siblings reported as NOT distinguishable", sep < MIN_VISIBLE_PX, `min separation ${sep.toFixed(2)}px`);
}

// (d) faintness: a wall thin enough that antialiasing spreads it across less than
//     half a device pixel row must be reported as FAINT, not counted as a sound run.
//     At 16px one grid unit is 1/6 of a device pixel, so a 2.4-unit wall covers 0.4
//     of a row and should measure ~40% — inside the faint band by construction.
//     (A 0.9-unit wall was tried first and measured as ABSENT, not faint: the probe
//     found no runs at all. That is a stronger refusal but a different one, and a
//     control has to plant the defect it names.)
{
  const hairline = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    `<rect x="10" y="20" width="30" height="2.4" fill="${INK}"/>` +
    `<rect x="60" y="20" width="30" height="2.4" fill="${INK}"/></svg>`;
  const s = separation(await pixels(await shoot(hairline, 16)), "x", 20.5 / GRID);
  const peaks = s.runs.map((r) => r.peak);
  control("hairline walls reported as faint, not as sound runs",
    s.runs.length > 0 && peaks.every((p) => p < 55), `peak coverage ${peaks.join("/") || "none"}%`);
}
// (e) over-count: a drawing that makes MORE runs than it claims must be reported
//     miscounted. A >= comparison passes it, which is the defect this replaces.
{
  const four = `<svg width="24" height="24" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    [8, 32, 56, 80].map((x) => `<rect x="${x}" y="40" width="8" height="16" fill="${INK}"/>`).join("") + `</svg>`;
  const s = separation(await pixels(await shoot(four, 24)), "x", 48 / GRID);
  control("four runs rejected against a claim of two", s.runs.length !== 2, `${s.runs.length} runs against a claim of 2`);
}

// (f) the slant probe must find a slope that is there, and must NOT find one that
//     is not. A flat-topped rectangle scoring a rise would make every taper look
//     safe; a 24-unit taper going unmeasured would make every taper look doomed.
{
  const flat = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    `<rect x="8" y="30" width="80" height="40" fill="${INK}"/></svg>`;
  const p = topProfile(await pixels(await shoot(flat, 16)));
  control("flat top edge reported as NO rise", p !== null && Math.abs(p.rise) < 0.5, `rise ${p ? p.rise.toFixed(2) : "n/a"}px`);

  const sloped = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/>` +
    `<polygon points="8,54 88,6 88,86 8,86" fill="${INK}"/></svg>`;
  const q = topProfile(await pixels(await shoot(sloped, 16)));
  const want = 48 * 16 / GRID;   // a declared 48-unit rise is 8 device px at 16px
  control("a 48-unit taper measured against its closed form",
    q !== null && Math.abs(q.rise - want) <= Math.max(0.75, want * 0.2),
    `measured ${q ? q.rise.toFixed(2) : "n/a"}px, closed form ${want.toFixed(2)}px`);
}

// (g) the silhouette probe must catch a pair that is the same shape, and must NOT
//     flag a pair that is genuinely different. A probe that only fires makes every
//     set look derivative; one that never fires makes every set look distinct.
{
  const disc = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/><circle cx="48" cy="48" r="40" fill="${INK}"/></svg>`;
  const discToo = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/><circle cx="48" cy="48" r="40" fill="${INK}"/><circle cx="48" cy="48" r="7" fill="${GROUND}"/></svg>`;
  const bar = `<svg width="16" height="16" viewBox="0 0 96 96"><rect width="96" height="96" fill="${GROUND}"/><rect x="8" y="40" width="80" height="16" fill="${INK}"/></svg>`;
  const mDisc = inkMask(await pixels(await shoot(disc, 16)));
  const mDiscToo = inkMask(await pixels(await shoot(discToo, 16)));
  const mBar = inkMask(await pixels(await shoot(bar, 16)));
  const same = iou(mDisc, mDiscToo), diff = iou(mDisc, mBar);
  control("two discs differing only by a punched counter flagged as one silhouette", same >= IOU_AT, `IoU ${same.toFixed(3)}`);
  control("a disc and a bar NOT flagged as one silhouette", diff < IOU_AT, `IoU ${diff.toFixed(3)}`);
}

if (!controlsOk) {
  console.error("\nABORTING: a probe failed to report the defect it exists to catch. Nothing below would mean anything.");
  await browser.close();
  process.exit(2);
}

// ── The skeletons ───────────────────────────────────────────────────────────
const verdicts = [];
for (const sk of SKELETONS) {
  // A GHOST is a retired shape carried in only so the silhouette comparison can see
  // it. It is not measured, not scored, not plated and never shown to a reader — it
  // exists so a later round cannot quietly re-draw a silhouette an earlier round
  // already killed.
  if (sk.ghost) { console.log(`\n·· ${sk.name} — ghost, silhouette comparison only`); continue; }
  console.log(`\n── ${sk.name}  (${sk.id}, ${sk.origin})`);
  console.log(`   ${sk.thesis}`);

  if (sk.hook) console.log(`   hook: ${sk.hook}`);
  const row = { id: sk.id, name: sk.name, hook: sk.hook || null, sizes: {} };
  let refused = false, crossCheckFailed = false;

  for (const size of SIZES) {
    const baseUrl = await shoot(svg(sk, size, null), size);
    const base = await pixels(baseUrl);
    const p = presence(base);
    if (!p.ok) {
      console.error(`   REFUSING at ${size}px: ${p.on} ink pixels over ${(p.frac * 100).toFixed(1)}% of frame — not a drawing.`);
      refused = true;
      continue;
    }

    // separation, on the base unless the claim only exists once a cue is drawn
    const sib = sk.separationOn;
    const target = sib ? await pixels(await shoot(svg(sk, size, sib), size)) : base;
    const s = separation(target, sk.separation.axis, scanAt(sk, sib));
    const wanted = sk.separation.runs;
    // EXACTLY the claimed number of runs. A >= comparison lets a drawing that makes
    // four runs pass a claim of two, which is a label claiming more than the
    // assertion checks — it did exactly that for the isometric slabs.
    const counted = s.runs.length === wanted && s.gaps.every((g) => g >= 1);
    // A run present but pale is a wall that is half there. 16px antialiasing is where
    // an outline dies, and a binary SEPARATED/FUSED verdict hides it, so a run below
    // this floor is reported as faint and counts against the skeleton at product size.
    const FAINT_AT = 55;
    const faint = s.runs.filter((r) => r.peak < FAINT_AT);
    const held = counted && faint.length === 0;
    if (!held && PRODUCT_SIZES.includes(size)) refused = true;

    console.log(
      `   ${String(size).padStart(2)}px  ink ${(p.frac * 100).toFixed(1)}% of frame  ·  ` +
      `scan ${sk.separation.axis === "x" ? "row" : "column"} ${s.line} of ${sk.separation.axis === "x" ? target.h : target.w}: ` +
      `${s.runs.length} run${s.runs.length === 1 ? "" : "s"} (claimed ${wanted}) ` +
      (s.gaps.length ? `gap${s.gaps.length > 1 ? "s" : ""} ${s.gaps.join(",")}px ` : "no gap ") +
      `coverage ${s.runs.map((r) => r.peak + "%").join("/") || "—"}  ` +
      `${held ? "SEPARATED" : counted ? `FAINT (${faint.length} run${faint.length === 1 ? "" : "s"} under ${FAINT_AT}%)` : "MISCOUNTED"}`
    );
    row.sizes[size] = { ink: p.frac, runs: s.runs.length, wanted, gaps: s.gaps, held };
  }

  // cue separation + closed-form cross-check, at product sizes only
  for (const size of PRODUCT_SIZES) {
    // An APERTURE cue does not move, it opens: the differencing centre sits in the
    // same place for all three siblings and a position probe would report zero and
    // call the cue dead. What varies is the width of the gap, so that is what is
    // measured — from the same scan the separation probe uses.
    if (sk.cueIs === "aperture") {
      const widths = [];
      for (const k of SIBLINGS) {
        const im = await pixels(await shoot(svg(sk, size, k), size));
        const s = separation(im, sk.separation.axis, scanAt(sk, k));
        widths.push(s.gaps.length ? Math.max(...s.gaps) : 0);
      }
      const sorted = [...widths].sort((a, b) => a - b);
      const measured = Math.min(...sorted.slice(1).map((v, i) => v - sorted[i]));
      const declared = Math.min(...SIBLINGS.map((k, i) => i === 0 ? Infinity
        : Math.abs(sk.apertures[SIBLINGS[i]] - sk.apertures[SIBLINGS[i - 1]])));
      const expected = declared * size / GRID;
      const agrees = Math.abs(measured - expected) <= Math.max(1, expected * 0.4);
      if (!agrees) crossCheckFailed = true;
      console.log(
        `   ${String(size).padStart(2)}px  cue (aperture): gaps ${widths.join("/")}px  smallest step ${measured.toFixed(2)}px  ` +
        `closed form ${expected.toFixed(2)}px  ${agrees ? "agree" : "DISAGREE — measurement rejected"}  ` +
        `${measured >= MIN_VISIBLE_PX ? "DISTINGUISHABLE" : "not distinguishable"}`
      );
      row.sizes[size] = { ...row.sizes[size], cue: measured, cueExpected: expected, agrees, distinguishable: measured >= MIN_VISIBLE_PX };
      continue;
    }
    const base = await pixels(await shoot(baseSvg(sk, size), size));
    const centres = [];
    for (const k of SIBLINGS) {
      const c = cueCentre(await pixels(await shoot(svg(sk, size, k), size)), base);
      if (c) centres.push(c);
    }
    const measured = centres.length === SIBLINGS.length ? minPairwise(centres) : 0;
    // Closed form: the smallest distance between the declared cue centres, in grid
    // units, scaled to this render. It comes from `cueCentres` in skeletons.mjs —
    // the same constants draw() uses — so a disagreement is a broken probe.
    const declared = minPairwise(SIBLINGS.map((k) => ({ x: sk.cueCentres[k][0], y: sk.cueCentres[k][1] })));
    const expected = declared * size / GRID;
    const agrees = Math.abs(measured - expected) <= Math.max(0.5, expected * 0.25);
    if (!agrees) crossCheckFailed = true;
    const distinguishable = centres.length === SIBLINGS.length && measured >= MIN_VISIBLE_PX;
    console.log(
      `   ${String(size).padStart(2)}px  cue: measured ${measured.toFixed(2)}px  closed form ${expected.toFixed(2)}px  ` +
      `${agrees ? "agree" : "DISAGREE — measurement rejected"}  ` +
      `${distinguishable ? "DISTINGUISHABLE" : "not distinguishable"}`
    );
    row.sizes[size] = { ...row.sizes[size], cue: measured, cueExpected: expected, agrees, distinguishable };
  }

  // Does the silhouette's own slope survive product size? Declared in grid units by
  // the skeleton; measured off the rendered top-ink profile; the two are compared.
  // A rise under one device pixel is a slope nobody sees, whatever the drawing says.
  // `topRise: null` means the shape makes NO claim about a top edge — a curved
  // outline has no straight rise to declare. The profile is still reported, as
  // information, but nothing is failed against a number that was never claimed.
  let slantDead = false;
  if (sk.topRise === null) {
    for (const size of PRODUCT_SIZES) {
      const p = topProfile(await pixels(await shoot(svg(sk, size, sk.separationOn || "cloud"), size)));
      console.log(`   ${String(size).padStart(2)}px  top edge: measured rise ${(p ? p.rise : 0).toFixed(2)}px  no claim declared — not checked`);
    }
  } else if (typeof sk.topRise === "number") {
    for (const size of PRODUCT_SIZES) {
      const p = topProfile(await pixels(await shoot(svg(sk, size, sk.separationOn || "cloud"), size)));
      const expected = sk.topRise * size / GRID;
      const measured = p ? p.rise : 0;
      const agrees = Math.abs(measured - expected) <= Math.max(0.75, Math.abs(expected) * 0.25);
      if (!agrees) crossCheckFailed = true;
      const visible = Math.abs(measured) >= MIN_VISIBLE_PX;
      if (sk.topRise !== 0 && !visible) slantDead = true;
      console.log(
        `   ${String(size).padStart(2)}px  top edge: measured rise ${measured.toFixed(2)}px  ` +
        `closed form ${expected.toFixed(2)}px  ${agrees ? "agree" : "DISAGREE — measurement rejected"}  ` +
        `${sk.topRise === 0 ? "flat by declaration" : visible ? "SLANT HOLDS" : "SLANT FLATTENS"}`
      );
      row.sizes[size] = { ...row.sizes[size], rise: measured, riseExpected: expected };
    }
  }

  row.verdict = crossCheckFailed ? "measurement-rejected"
    : refused ? "fails-at-product-size"
    : slantDead ? "silhouette-flattens-at-product-size"
    : "survives-measurement";
  console.log(`   → ${row.verdict}`);
  for (const h of sk.hazards) console.log(`     hazard: ${h}`);
  verdicts.push(row);
}

// ── Are these five marks, or one mark five times? ───────────────────────────
// Every silhouette, counters closed, compared with every other at 16px.
const sils = [];
for (const sk of SKELETONS) {
  const markup = sk.silhouetteDraw ? sk.silhouetteDraw() : sk.draw(sk.neutral || null);
  const body = `<svg width="16" height="16" viewBox="0 0 ${GRID} ${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
    markup.replace(/INK/g, INK) + `</svg>`;
  sils.push({ sk, mask: inkMask(await pixels(await shoot(body, 16))), body });
}
if (sils.length > 1) {
  console.log(`\nsilhouette distinctness — every counter closed, compared at 16px (IoU, flagged at ${IOU_AT}):`);
  const flagged = new Set();
  for (let i = 0; i < sils.length; i++) for (let j = i + 1; j < sils.length; j++) {
    const v = iou(sils[i].mask, sils[j].mask);
    const bad = v >= IOU_AT;
    if (bad) { flagged.add(sils[i].sk.id); flagged.add(sils[j].sk.id); }
    console.log(`  ${v.toFixed(3)}  ${sils[i].sk.name} / ${sils[j].sk.name}${bad ? "  — SAME SILHOUETTE" : ""}`);
  }
  for (const v of verdicts) {
    if (flagged.has(v.id)) {
      v.silhouette = "shared";
      if (v.verdict === "survives-measurement") v.verdict = "silhouette-not-its-own";
    } else v.silhouette = "distinct";
  }
}

// ── Plates for the cold reader ──────────────────────────────────────────────
// One PNG per skeleton per product size, named by a letter rather than by the
// concept, so the reader is shown a drawing and not a description of it.
if (process.argv.includes("--plates")) {
  // Round one's plates are A-E. A later set gets its own letters so a reader who has
  // seen one round cannot carry a verdict across on the strength of a shared label —
  // and so a six-skeleton set does not silently write a file called "undefined",
  // which is what a five-letter alphabet did the first time this ran.
  // Each round gets its own letters. A reader who has seen an earlier round must not
  // be able to carry a verdict across on a shared label, and a five-letter alphabet
  // against six skeletons silently wrote a file called "undefined" the first time.
  const ALPHABETS = { "": "ABCDE", r2: "PQRSTUVW", r3: "GHJKLMN", r4: "1234567" };
  const letters = ALPHABETS[SET || ""];
  if (!letters) {
    console.error(`REFUSING to plate: set "${SET}" has no letters of its own, and reusing another round's would let a reader carry a verdict across.`);
    await browser.close();
    process.exit(2);
  }
  if (SKELETONS.length > letters.length) {
    console.error(`REFUSING to plate: ${SKELETONS.length} skeletons against ${letters.length} letters.`);
    await browser.close();
    process.exit(2);
  }
  // The mark a reader is shown is a SIBLING, not the differencing base. The base is
  // an instrument — the same drawing with the cue removed so the cue can be isolated
  // — and for three of these five it is the concept with its idea taken out: the
  // grid with nothing spent, the wedge with nothing punched, the lanes with none
  // chosen. The first plating run showed the base and would have asked a cold reader
  // to name a drawing nobody is proposing.
  const PLATE_SIB = "cloud";
  for (const [i, sk] of SKELETONS.entries()) {
    if (sk.ghost) continue;
    for (const size of [16, 24, 96]) {
      // Plated at 8x nearest-neighbour so a 16px drawing can be LOOKED at without
      // resampling it into something smoother than it is. The pixels are the 16px
      // pixels; only the display is enlarged.
      const scale = size === 96 ? 2 : 8;
      const markup =
        `<div style="background:${GROUND};padding:24px;display:inline-block;">` +
        `<div style="width:${size * scale}px;height:${size * scale}px;image-rendering:pixelated;` +
        `background-image:url('${await shoot(svg(sk, size, PLATE_SIB), size)}');background-size:100% 100%;"></div></div>`;
      await page.setContent(`<style>body{margin:0;background:${GROUND};}</style>${markup}`);
      const buf = await page.locator("div").first().screenshot();
      writeFileSync(path.join(OUT, `${letters[i]}-${size}px.png`), buf);
    }
    // and the three siblings side by side at 24px, for the lockup-cue question
    const trio = SIBLINGS.map((k) =>
      `<div style="width:192px;height:192px;image-rendering:pixelated;background-size:100% 100%;` +
      `background-image:url('PLACE-${k}');"></div>`).join("");
    let filled = trio;
    for (const k of SIBLINGS) filled = filled.replace(`PLACE-${k}`, await shoot(svg(sk, 24, k), 24));
    await page.setContent(`<style>body{margin:0;background:${GROUND};}</style>` +
      `<div style="display:flex;gap:24px;padding:24px;background:${GROUND};">${filled}</div>`);
    writeFileSync(path.join(OUT, `${letters[i]}-siblings-24px.png`), await page.locator("div").first().screenshot());
  }
  // ── Lockups ───────────────────────────────────────────────────────────────
  // A mark that passes alone and fails beside its name has not passed. The wordmark
  // is IOI Display, unicase, with the period DRAWN and medial — there is no U+002E
  // in the lockup. The face is inlined as a data: URI and the run REFUSES if it did
  // not load, because a lockup measured in a fallback face is a lockup nobody drew.
  const IOI = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");
  const WM = await import("../wordmark/wordmark.mjs");
  // The wordmark comes from brand/wordmark/wordmark.mjs and from nowhere else. A
  // previous version of this file carried its own copy of the Z path and the period's
  // metrics "matching index.html" — and that is exactly the arrangement that let the
  // shipped Z be fixed while the plated one stayed broken, voiding a round's lockup
  // half. Two copies and a comment saying they must agree is not one source.
  //
  // Two lockup forms are plated, per ioi-e1's ruling. The single line sets the mark
  // at one EM as a floor rather than at 1.25-1.35 of the cap, because two rounds of
  // readers independently worked out that a cap-locked mark against an 18-letter name
  // is arithmetically ~5% of the lockup — "you could double every one of these marks
  // and they'd still read as a bullet point". The STACKED form breaks the name over
  // two lines with the period LEADING line two, and stands the mark at the full
  // two-line height.
  const lockupSingle = (markMarkup, typePx) => {
    const markPx = typePx * WM.SINGLE_LINE_MARK_EM;
    return `<div class="lk" style="display:flex;align-items:center;gap:${Math.round(typePx * 0.45)}px;` +
      `background:${GROUND};padding:${Math.round(typePx)}px;width:max-content;">` +
      `<svg class="lk-mark" width="${markPx}" height="${markPx}" viewBox="0 0 ${GRID} ${GRID}">${markMarkup.replace(/INK/g, INK)}</svg>` +
      `<div class="lk-word">${WM.wordmarkSingle(typePx, INK)}</div></div>`;
  };
  const lockupStacked = (markMarkup, typePx) => {
    // Two lines of cap plus the leading between them.
    const markPx = typePx * (WM.CAP / WM.UPM) * 2 + typePx * 0.14;
    return `<div class="lk" style="display:flex;align-items:center;gap:${Math.round(typePx * 0.45)}px;` +
      `background:${GROUND};padding:${Math.round(typePx)}px;width:max-content;">` +
      `<svg class="lk-mark" width="${markPx.toFixed(2)}" height="${markPx.toFixed(2)}" viewBox="0 0 ${GRID} ${GRID}">${markMarkup.replace(/INK/g, INK)}</svg>` +
      `<div class="lk-word">${WM.wordmarkStacked(typePx, INK)}</div></div>`;
  };
  for (const [i, sk] of SKELETONS.entries()) {
    if (sk.ghost) continue;
    const mark = sk.draw(PLATE_SIB).replace(/INK/g, INK);
    const rows =
      lockupSingle(mark, 22) + lockupSingle(mark, 11) +
      lockupStacked(mark, 22) + lockupStacked(mark, 11);
    await page.setContent(
      `<style>@font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${IOI}) format("truetype");}` +
      `body{margin:0;background:${GROUND};}#warm{font-family:"IOI Display";font-size:20px;position:absolute;left:-9999px;}</style>` +
      `<div id="warm">decentralized</div>` +
      `<div id="pair" style="display:flex;flex-direction:column;gap:14px;padding:18px;background:${GROUND};width:max-content;">${rows}</div>`);
    await page.waitForFunction(() => document.fonts.ready.then(() => true));
    await page.evaluate(() => document.fonts.load('22px "IOI Display"'));
    await page.waitForTimeout(250);
    if (!(await page.evaluate(() => document.fonts.check('22px "IOI Display"')))) {
      console.error("REFUSING to plate lockups: IOI Display did not load; every lockup would show a fallback face.");
      await browser.close();
      process.exit(2);
    }
    writeFileSync(path.join(OUT, `${letters[i]}-lockup.png`), await page.locator("#pair").screenshot());

    // BALANCE BY MASS, not by cap ratio. The cap rule said 1.29x and readers said the
    // mark was a speck; a ratio against the CAP says nothing about a name 19 caps
    // long. This measures the ink each side actually puts on the page, by screenshot,
    // so "the mark holds its own" becomes a number rather than an opinion.
    const inkArea = async (sel) => {
      const buf = await page.locator(sel).first().screenshot();
      const im = await pixels(`data:image/png;base64,${buf.toString("base64")}`);
      let on = 0;
      for (let p = 0; p < im.w * im.h; p++) if (lum(im.d, p) < INK_AT) on += 1;
      return on;
    };
    const massOf = async (form) => {
      const idx = form === "single" ? 0 : 2;   // rows: single 22, single 11, stacked 22, stacked 11
      const markInk = await inkArea(`.lk:nth-of-type(${idx + 1}) .lk-mark`);
      const wordInk = await inkArea(`.lk:nth-of-type(${idx + 1}) .lk-word`);
      return { markInk, wordInk, share: wordInk ? markInk / (markInk + wordInk) : 0 };
    };
    const single = await massOf("single"), stacked = await massOf("stacked");
    console.log(
      `   lockup mass at 22px — single: mark ${single.markInk} px of ink vs word ${single.wordInk}, ` +
      `mark is ${(single.share * 100).toFixed(1)}% of the pair · ` +
      `stacked: ${(stacked.share * 100).toFixed(1)}%`);
  }
  // The silhouettes as judged: counters closed, at 96px so a reader can see the shape
  // the 16px comparison was actually made on.
  for (const [i, s] of sils.entries()) {
    await page.setContent(`<style>body{margin:0;background:${GROUND};}</style>` +
      `<div style="padding:24px;background:${GROUND};width:max-content;">` +
      s.body.replace('width="16" height="16"', 'width="96" height="96"') + `</div>`);
    writeFileSync(path.join(OUT, `${letters[i]}-silhouette.png`), await page.locator("div").first().screenshot());
  }
  writeFileSync(path.join(OUT, "measurements.json"), JSON.stringify(verdicts, null, 2));
  console.log(`\nplates: ${path.relative(process.cwd(), OUT)}  (${letters.slice(0, SKELETONS.length).split("").join(", ")} — deliberately unnamed)`);
}

await browser.close();
const dead = verdicts.filter((v) => v.verdict !== "survives-measurement");
console.log(`\n${verdicts.length - dead.length}/${verdicts.length} skeletons survive measurement at 16px and 24px`);
for (const d of dead) console.log(`  DEAD  ${d.name}: ${d.verdict}`);
console.log(`\nMeasurement is not the whole gate: the control test, the one-drawing test and`);
console.log(`the lockup-cue test are a cold reader's, and a skeleton can survive here and die there.`);
process.exit(0);
