// THE MARK — one source, framework-free.
//
// decentralized.cloud's identity, per the owner's brand page (Brand Identity.dc.html,
// 2026-09-06, confirmed 2026-09-07 as the current mark over the three-lobe file that
// preceded it): a CLOUD that opens into a NETWORK. The hero treatment is the hover
// cloud — the owner's cloud-hover.html, served at /brand/hover.html — and the static
// mark is that same cloud with a three-node network knocked out of its right side as
// true transparency, so the network takes the colour of whatever sits behind it.
//
// EVERY NUMBER HERE IS READ OFF THE OWNER'S FILE, not chosen: the cloud is the four
// circles and the rect cloud-hover.html draws (C = [[188,264,66],[268,198,82],
// [338,160,96],[488,250,82]], R = 188..488 × 198..330), translated so the silhouette's
// bounding box starts at 0,0 — it spans x 122..570 and y 64..332 in that file, so the
// mark's box is 448 × 268. The network cut is placed inside the right lobes where the
// hover opens. The wordmark's layout is unchanged from the designer's lockup: two
// lines of IOI Display, measured in a browser.
//
// This module is imported by three consumers that must agree and cannot see each
// other: the shipped shell (src/components/Lockup.jsx), the asset builder
// (build-assets.mjs writes every downloadable SVG from these constants), and the face
// gate (which asserts the served bytes carry these exact paths). A drawing copied
// into any of them would be a second source.

// ── Colour ──────────────────────────────────────────────────────────────────
// Registered in packages/design-system/tokens/colors.css under the same names; the
// palette gate refuses any hex on the face that is not there. The gradient runs
// bottom-left to top-right ACROSS THE WHOLE CLOUD (userSpaceOnUse over the mark's
// box), which is the brand page's rule: one ramp, infrastructure indigo to network
// cyan.
export const MARK_INDIGO = "#3f3dfa";       // --color-dc-mark-indigo
export const MARK_CYAN = "#41dbf9";         // --color-dc-mark-cyan
export const SUBSTRATE_NAVY = "#000c26";    // --color-dc-substrate-navy
export const INTERIOR_INDIGO = "#0e2250";   // --color-dc-interior-indigo
export const WHITE = "#ffffff";
export const BLACK = "#000000";
// The dot's gradient, on its own box.
export const GRADIENT = { x1: 0, y1: 1, x2: 1, y2: 0, from: MARK_INDIGO, to: MARK_CYAN };

// ── The cloud ───────────────────────────────────────────────────────────────
export const MARK_WIDTH = 448;
export const MARK_HEIGHT = 268;
export const MARK_BOX = `0 0 ${MARK_WIDTH} ${MARK_HEIGHT}`;
// The owner's four circles and rect, translated by (-122, -64).
export const CLOUD_CIRCLES = [
  [66, 200, 66],
  [146, 134, 82],
  [216, 96, 96],
  [366, 186, 82],
];
export const CLOUD_RECT = { x: 66, y: 134, w: 300, h: 132 };
// The mark's gradient, over its own box, bottom-left to top-right.
export const MARK_GRADIENT = { x1: 0, y1: MARK_HEIGHT, x2: MARK_WIDTH, y2: 0, from: MARK_INDIGO, to: MARK_CYAN };

// Each circle as a path of two arcs, and the rect as a path, so the shell, the
// assets and the gate all carry the same five strings and the union of the five is
// the silhouette. A space follows every command letter, because the face gate scans
// served bytes for milestone identifiers of the form M\d\d.\d and a bare "M12.3"
// would read as one.
// WRITTEN AS LITERALS, not computed from CLOUD_CIRCLES: the bundle does not fold
// constants, and the face gate anchors on these exact strings in the SERVED bytes —
// a computed array shipped the template and the gate reported 0 of 5 paths served.
// `circlePath` below regenerates them from the circles, and the builder's --check
// refuses to run if the two disagree.
export const MARK_PATHS = [
  "M 0 200 A 66 66 0 1 0 132 200 A 66 66 0 1 0 0 200 Z",
  "M 64 134 A 82 82 0 1 0 228 134 A 82 82 0 1 0 64 134 Z",
  "M 120 96 A 96 96 0 1 0 312 96 A 96 96 0 1 0 120 96 Z",
  "M 284 186 A 82 82 0 1 0 448 186 A 82 82 0 1 0 284 186 Z",
  "M 66 134 H 366 V 266 H 66 Z",
];
export const circlePath = ([cx, cy, r]) =>
  `M ${cx - r} ${cy} A ${r} ${r} 0 1 0 ${cx + r} ${cy} A ${r} ${r} 0 1 0 ${cx - r} ${cy} Z`;
export const derivedMarkPaths = () => [
  ...CLOUD_CIRCLES.map(circlePath),
  `M ${CLOUD_RECT.x} ${CLOUD_RECT.y} H ${CLOUD_RECT.x + CLOUD_RECT.w} V ${CLOUD_RECT.y + CLOUD_RECT.h} H ${CLOUD_RECT.x} Z`,
];

// ── The animated mark — the owner's "cloud to network", pure SVG, no WebGL ─────
// Geometry and timing from the owner's SVG animation (brand/mark/source/
// mark-animated.html), translated into the mark's units by (-122, -64). The cloud
// is clipped at a seam; the right of the seam dissolves into a pixel field that
// feeds a network of squares; then the seam sweeps right, the cloud reabsorbs the
// network, and it returns. One loop is ANIM.duration seconds. The header plays it;
// under reduced motion the static cut mark stands instead.
export const ANIM = {
  duration: 11,
  seam: 166,           // EDGE_X — where the cloud is cut while the network stands
  full: 360,           // FULL_X — how far the seam sweeps when the cloud reabsorbs
  times: { build: 0.2, buildDur: 1.4, live: 2.0, sweep: 6.0, sweepEnd: 8.3, recede: 9.3, recedeEnd: 10.5 },
  // 7 hubs, then 4 satellites nearest the seam; d = build order, from x.
  nodes: [
    { x: 270, y: 54, s: 24 }, { x: 328, y: 78, s: 24 }, { x: 276, y: 146, s: 26 }, { x: 334, y: 148, s: 24 },
    { x: 278, y: 236, s: 24 }, { x: 330, y: 248, s: 24 }, { x: 356, y: 198, s: 24 },
    { x: 238, y: 74, s: 11 }, { x: 240, y: 140, s: 11 }, { x: 236, y: 198, s: 11 }, { x: 240, y: 254, s: 11 },
  ],
  buildFrom: 236, buildSpan: 120,
  edges: [
    [7, 0, true], [8, 2, true], [9, 2, true], [10, 4, true],
    [0, 1], [0, 2], [1, 2], [1, 3], [2, 3], [2, 4], [3, 5], [4, 5], [3, 6], [5, 6],
  ],
  // The pixel lattice: 8-unit grid from the seam rightwards, thinning with distance.
  pixels: { x0: 162, x1: 250, y0: -4, y1: 272, step: 8, span: 88 },
  // Fibres from each satellite back into the field: three per satellite.
  fibres: { x0: 196, xSpread: 22, dy: 14, jitter: 8, c1: 14, c2: 16 },
  seed: 23,
  // Signal pulses that ride the built network while it is live.
  signals: [
    { dur: 1.8, begin: 0, path: "M 270 54 L 328 78 L 334 148 L 356 198" },
    { dur: 1.9, begin: 0.7, path: "M 278 236 L 330 248 L 356 198 L 334 148 L 276 146" },
    { dur: 1.5, begin: 1.2, path: "M 276 146 L 270 54 L 328 78" },
  ],
  // The owner's file lit the pulses in a pale blue that is not a token; they ride in
  // identity white, which is.
  pulse: WHITE,
};

// Is a point inside the cloud silhouette — the same four circles and rect.
export const inCloud = (x, y) =>
  CLOUD_CIRCLES.some(([cx, cy, r]) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r) ||
  (x >= CLOUD_RECT.x && x <= CLOUD_RECT.x + CLOUD_RECT.w && y >= CLOUD_RECT.y && y <= CLOUD_RECT.y + CLOUD_RECT.h);

// ── The network cut ─────────────────────────────────────────────────────────
// Three nodes of the network the hover opens, knocked out of the right lobes as true
// transparency, joined by three edges. Node side 40 on a 268-tall mark: at the header's
// 42px the nodes are 6px and the edges 1.2px; at 16px the cut closes and the glyph
// reads as the cloud, which is the honest floor and is stated on the brand page.
export const CUT_NODES = [
  { x: 258, y: 66, s: 40 },
  { x: 364, y: 182, s: 40 },
  { x: 270, y: 232, s: 40 },
];
export const CUT_EDGES = [[0, 1], [1, 2], [0, 2]];
export const CUT_EDGE_WIDTH = 8;
export const CUT_NODE_RADIUS = 8;

// ── The lockup's proportions — the owner's rules ─────────────────────────────
// "Mark height is 2.65× the wordmark block height. Gap between mark and wordmark is
// 7.5% of the mark's width. Never restyle these relationships." The wordmark block
// is 67.188 units tall (CLOUD's baseline to the top of DECENTRALIZED); the mark is
// scaled to 2.65 of that and the wordmark is centred on the mark's height.
export const BLOCK = 67.188;
export const MARK_TO_BLOCK = 2.65;
export const GAP_OF_MARK_WIDTH = 0.075;
export const LOCKUP_MARK_HEIGHT = +(BLOCK * MARK_TO_BLOCK).toFixed(3);          // 178.048
export const LOCKUP_MARK_SCALE = +(LOCKUP_MARK_HEIGHT / MARK_HEIGHT).toFixed(5); // 0.66436
export const LOCKUP_MARK_WIDTH = +(MARK_WIDTH * LOCKUP_MARK_SCALE).toFixed(3);   // 297.633
export const LOCKUP_GAP = +(LOCKUP_MARK_WIDTH * GAP_OF_MARK_WIDTH).toFixed(3);    // 22.322

// ── The wordmark's layout, measured ──────────────────────────────────────────
// Caps only: IOI Display is unicase, so cap height IS the line's ink height. The
// face declares capHeight 700/1000, so font-size = cap / 0.7. These coordinates are
// the designer's lockup's, in which the wordmark's ink starts at x 149.84; the lockup
// builder translates the block to sit LOCKUP_GAP after the mark.
export const WORDMARK_X = 149.84;           // ink left of both lines and of the dot
export const TOP_CAP = 22.072;              // DECENTRALIZED, y 0..22.072
export const BOTTOM_CAP = 38;               // CLOUD, y 29.188..67.188
export const BOTTOM_TOP = 29.188;
export const TOP_FONT_SIZE = TOP_CAP / 0.7;       // 31.531 units
export const BOTTOM_FONT_SIZE = BOTTOM_CAP / 0.7; // 54.286 units
export const WORDMARK_WIDTH = 409.206;      // ink, both lines: x 149.84..559.046

// Where the wordmark block sits in the full lockup: after the mark and its gap,
// centred on the mark's height.
export const LOCKUP_WORDMARK_X = +(LOCKUP_MARK_WIDTH + LOCKUP_GAP).toFixed(3);          // 319.955
export const LOCKUP_WORDMARK_Y = +((LOCKUP_MARK_HEIGHT - BLOCK) / 2).toFixed(3);         // 55.43
export const LOCKUP_WIDTH = +(LOCKUP_WORDMARK_X + WORDMARK_WIDTH).toFixed(3);            // 729.161
export const LOCKUP_HEIGHT = LOCKUP_MARK_HEIGHT;

// CLOUD is TRACKED: the ink gap between every pair of its letters is 23.56 units,
// and the dot stands exactly one such gap before the C — it is spaced as a sixth
// letter, not as punctuation. DECENTRALIZED runs at the face's natural fit.
export const CLOUD_INK_GAP = 23.56;
export const CLOUD_LETTER_INK = [          // x ranges of C L O U D, for the record
  [181, 236.589], [260.149, 314.435], [337.995, 397.166], [420.726, 479.897], [503.457, 559.046],
];

// THE DOT. A rounded square, 7.6 units on a 38 cap (0.2 of the cap; 0.14 of the
// CLOUD font size), corner radius a quarter of its side, standing ON THE BASELINE
// with its left edge on the wordmark's left edge. It carries the cloud gradient,
// always — it is the one place the mark's colour enters the type.
export const DOT = { x: 149.84, y: 59.588, size: 7.6, radius: 1.9 };
export const DOT_PATH =
  "M 151.74 67.188L 155.54 67.188C 156.59 67.188 157.44 66.337 157.44 65.288L 157.44 61.488C 157.44 60.439 156.59 59.588 155.54 59.588L 151.74 59.588C 150.691 59.588 149.84 60.439 149.84 61.488L 149.84 65.288C 149.84 66.337 150.691 67.188 151.74 67.188Z";

// ── Setting the wordmark as LIVE TEXT (the shell) ────────────────────────────
// The shell sets the name in IOI.ttf rather than from the outlines, per the owner's
// ruling, inside an SVG so the BASELINE is what is positioned — HTML line boxes place
// text by ascender metrics, and this face's hhea (750/-200) and Windows (700/450)
// tables disagree by 0.15em, so an HTML stack would sit 2–3px differently per
// platform. SVG text is placed at its baseline on every platform.
//
// x is the ink's left minus the face's side bearing (32/1000 em, from its own
// tables); textLength is the ink width plus both bearings, so the run is fitted to
// the outlined lockup's width exactly rather than trusting the browser's shaping
// to land within a unit of it — `lengthAdjust="spacing"` moves letters, never
// distorts glyphs.
export const FACE_SIDE_BEARING = 0.032;
export const TEXT_TOP = {
  x: +(WORDMARK_X - FACE_SIDE_BEARING * TOP_FONT_SIZE).toFixed(3),
  y: TOP_CAP,
  fontSize: +TOP_FONT_SIZE.toFixed(3),
  length: +(WORDMARK_WIDTH + 2 * FACE_SIDE_BEARING * TOP_FONT_SIZE).toFixed(3),
};
export const TEXT_BOTTOM = {
  x: +(CLOUD_LETTER_INK[0][0] - FACE_SIDE_BEARING * BOTTOM_FONT_SIZE).toFixed(3),
  y: BLOCK,
  fontSize: +BOTTOM_FONT_SIZE.toFixed(3),
  length: +(CLOUD_LETTER_INK[4][1] - CLOUD_LETTER_INK[0][0] + 2 * FACE_SIDE_BEARING * BOTTOM_FONT_SIZE).toFixed(3),
};
export const WORDMARK_BOX = `${WORDMARK_X} 0 ${WORDMARK_WIDTH} ${BLOCK}`;

// ── The app icon ─────────────────────────────────────────────────────────────
// A white tile, corner radius 14% of its side, with the mark's ink at 69% of the
// tile's width, centred — the designer's tile numbers, kept.
export const ICON = (() => {
  const tile = 139.208, radius = 19.457, inkFraction = 0.69;
  const scale = +((tile * inkFraction) / MARK_WIDTH).toFixed(5);
  const w = MARK_WIDTH * scale, h = MARK_HEIGHT * scale;
  return { tile, radius, scale, x: +((tile - w) / 2).toFixed(3), y: +((tile - h) / 2).toFixed(3) };
})();

// ── SVG builders ─────────────────────────────────────────────────────────────
// `fill` is "gradient" or a single colour; the gradient is emitted once per SVG
// under `id`, so two marks on one page do not collide. The cut is a mask with the
// same id suffixed `-cut`, in the mark's own units, so it travels with any transform
// the mark is placed under.
export const gradientDefs = (id = "dc-mark-g") =>
  `<linearGradient id="${id}" x1="${GRADIENT.x1}" y1="${GRADIENT.y1}" x2="${GRADIENT.x2}" y2="${GRADIENT.y2}">` +
  `<stop offset="0" stop-color="${GRADIENT.from}"/><stop offset="1" stop-color="${GRADIENT.to}"/></linearGradient>`;

export const markGradientDefs = (id = "dc-mark-g") =>
  `<linearGradient id="${id}" gradientUnits="userSpaceOnUse" x1="${MARK_GRADIENT.x1}" y1="${MARK_GRADIENT.y1}" x2="${MARK_GRADIENT.x2}" y2="${MARK_GRADIENT.y2}">` +
  `<stop offset="0" stop-color="${MARK_GRADIENT.from}"/><stop offset="1" stop-color="${MARK_GRADIENT.to}"/></linearGradient>`;

export const cutShapes = (ink = "#000") =>
  CUT_EDGES.map(([a, b]) =>
    `<line x1="${CUT_NODES[a].x}" y1="${CUT_NODES[a].y}" x2="${CUT_NODES[b].x}" y2="${CUT_NODES[b].y}" stroke="${ink}" stroke-width="${CUT_EDGE_WIDTH}"/>`).join("") +
  CUT_NODES.map((n) =>
    `<rect x="${n.x - n.s / 2}" y="${n.y - n.s / 2}" width="${n.s}" height="${n.s}" rx="${CUT_NODE_RADIUS}" fill="${ink}"/>`).join("");

export const cutMaskDefs = (id = "dc-mark-g") =>
  `<mask id="${id}-cut" maskUnits="userSpaceOnUse" x="0" y="0" width="${MARK_WIDTH}" height="${MARK_HEIGHT}">` +
  `<rect width="${MARK_WIDTH}" height="${MARK_HEIGHT}" fill="#fff"/>${cutShapes("#000")}</mask>`;

const paint = (fill, id) => (fill === "gradient" ? `url(#${id})` : fill);

// The cloud with the network knocked out. Defs (gradient + mask) must be emitted by
// the caller under the same id.
export const markPaths = (fill = "gradient", id = "dc-mark-g") =>
  `<g fill="${paint(fill, id)}" mask="url(#${id}-cut)">${MARK_PATHS.map((d) => `<path d="${d}"/>`).join("")}</g>`;

export const markDefs = (fill, id) => (fill === "gradient" ? markGradientDefs(id) : "") + cutMaskDefs(id);

export const markSvg = ({ fill = "gradient", id = "dc-mark-g", attrs = "" } = {}) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${MARK_BOX}" role="img" aria-label="decentralized.cloud mark"${attrs}>` +
  `<defs>${markDefs(fill, id)}</defs>` + markPaths(fill, id) + `</svg>`;

// The reduction glyph: the same mark, fitted to a square tile on its long axis and
// centred on the short. Below 32px the cut closes and it reads as the cloud.
export const glyphSvg = ({ fill = "gradient", id = "dc-glyph-g", size = 96 } = {}) => {
  const pad = 4;
  const scale = (size - 2 * pad) / MARK_WIDTH;
  const dy = (size - MARK_HEIGHT * scale) / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="decentralized.cloud">` +
    `<defs>${markDefs(fill, id)}</defs>` +
    `<g transform="translate(${pad} ${dy.toFixed(3)}) scale(${scale.toFixed(5)})">${markPaths(fill, id)}</g></svg>`;
};

export const appIconSvg = ({ id = "dc-icon-g", tile = WHITE } = {}) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${ICON.tile} ${ICON.tile}" role="img" aria-label="decentralized.cloud">` +
  `<defs>${markDefs("gradient", id)}</defs>` +
  `<rect width="${ICON.tile}" height="${ICON.tile}" rx="${ICON.radius}" fill="${tile}"/>` +
  `<g transform="translate(${ICON.x} ${ICON.y}) scale(${ICON.scale})">${markPaths("gradient", id)}</g></svg>`;
