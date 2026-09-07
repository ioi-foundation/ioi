// THE MARK — one source, framework-free.
//
// decentralized.cloud's identity, from the designer's file source/FInal-CLOUD-v3.svg
// (2026-09-06). Three lobes of a cloud, each a rounded slab leaning right, carrying
// the cloud gradient; a two-line wordmark set in IOI Display — DECENTRALIZED small
// above, a gradient dot and CLOUD large below. Every number here is READ OFF THAT
// FILE, not chosen: the lobes are its paths verbatim, and the layout constants are
// the bounding boxes measured in a browser (getBBox) on the light lockup.
//
// This module is imported by three consumers that must agree and cannot see each
// other: the shipped shell (src/components/Lockup.jsx draws the lobes from
// MARK_PATHS), the asset builder (build-assets.mjs writes every downloadable SVG
// from the same constants), and the face gate (which asserts the served bytes carry
// these exact paths). A drawing copied into any of them would be a second source,
// and two copies of a thing that must agree are two sources and a wish — the fault
// the wordmark's one-source module was built to remove.

// ── Colour ──────────────────────────────────────────────────────────────────
// Registered in packages/design-system/tokens/colors.css under the same names; the
// palette gate refuses any hex on the face that is not there. The gradient runs
// bottom-left to top-right on EACH lobe's own box (objectBoundingBox on a fill set
// on the group is resolved per painted element), which is why every lobe lightens
// toward its upper right independently — that is the source file's behaviour and
// it is kept, not corrected.
export const MARK_INDIGO = "#3f3dfa";       // --color-dc-mark-indigo
export const MARK_CYAN = "#41dbf9";         // --color-dc-mark-cyan
export const SUBSTRATE_NAVY = "#000c26";    // --color-dc-substrate-navy
export const INTERIOR_INDIGO = "#0e2250";   // --color-dc-interior-indigo
export const WHITE = "#ffffff";
export const BLACK = "#000000";
export const GRADIENT = { x1: 0, y1: 1, x2: 1, y2: 0, from: MARK_INDIGO, to: MARK_CYAN };

// ── The lobes ───────────────────────────────────────────────────────────────
// In the lockup's own units: the block is 67.188 tall (the mark's full height and
// the wordmark's, baseline to the top of DECENTRALIZED). Ink spans x 1.406..128.765.
// The coordinates are the source's; the one change is a space after every command
// letter, because the face gate scans served bytes for milestone identifiers of the
// form M\d\d.\d and "M36.473" read as one. Same path, one spelling, everywhere.
export const MARK_PATHS = [
  "M 1.497 54.71C 0.67 61.602 5.586 67.188 12.478 67.188L 31.674 67.188L 34.957 39.833C 36.007 31.086 29.767 23.996 21.02 23.996L 21.02 23.996C 12.274 23.996 4.332 31.086 3.283 39.833Z",
  "M 36.473 67.188L 84.465 67.188L 89.648 23.996C 91.238 10.743 81.784 0 68.532 0L 68.532 0C 55.279 0 43.247 10.743 41.657 23.996Z",
  "M 89.264 67.188L 112.3 67.188C 119.191 67.188 125.448 61.602 126.275 54.71L 128.636 35.034C 129.813 25.227 122.817 17.277 113.01 17.277L 113.01 17.277C 103.203 17.277 94.299 25.227 93.123 35.034Z",
];
export const BLOCK = 67.188;                // the lockup's unit: mark height = wordmark height
export const MARK_WIDTH = 130;              // viewBox width; ink ends at 128.765
export const MARK_BOX = `0 0 ${MARK_WIDTH} ${BLOCK}`;

// ── The wordmark's layout, measured ──────────────────────────────────────────
// Caps only: IOI Display is unicase, so cap height IS the line's ink height. The
// face declares capHeight 700/1000, so font-size = cap / 0.7.
export const WORDMARK_X = 149.84;           // ink left of both lines and of the dot
export const TOP_CAP = 22.072;              // DECENTRALIZED, y 0..22.072
export const BOTTOM_CAP = 38;               // CLOUD, y 29.188..67.188
export const BOTTOM_TOP = 29.188;
export const TOP_FONT_SIZE = TOP_CAP / 0.7;       // 31.531 units
export const BOTTOM_FONT_SIZE = BOTTOM_CAP / 0.7; // 54.286 units
export const WORDMARK_WIDTH = 409.206;      // ink, both lines: x 149.84..559.046
export const MARK_TO_WORDMARK = WORDMARK_X - MARK_WIDTH; // 19.84 units of clear

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

export const LOCKUP_WIDTH = WORDMARK_X + WORDMARK_WIDTH; // 559.046; height is BLOCK

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
// A white tile, corner radius 14% of its side, with the mark at 0.7545 scale — its
// ink is 69% of the tile's width — centred on the tile. Those are the source file's
// numbers (139.208 tile, rx 19.457, mark translated to 19.49, 44.257).
export const ICON = { tile: 139.208, radius: 19.457, scale: 0.7545, x: 19.49, y: 44.257 };

// ── Reduction glyph ──────────────────────────────────────────────────────────
// Below 48px the three lobes' separating gaps (4.8 units, under half a device pixel
// at 16px) turn to mud, so the glyph is the lobes CLOSED into one silhouette — the
// same paths, stroked in their own fill to bridge the gaps — with a three-node
// network cut out of it as true transparency: three squares of the network motif
// joined by two edges, so whatever sits behind the icon shows through as the
// network. Nodes are placed one per lobe, on the lobes' own centrelines.
export const GLYPH_STROKE = 7;              // closes the 4.8-unit gaps with margin
export const GLYPH_NODES = [
  { x: 21, y: 47, s: 13 },                  // left lobe
  { x: 66, y: 27, s: 13 },                  // centre lobe, the tallest
  { x: 110, y: 46, s: 13 },                 // right lobe
];
export const GLYPH_EDGES = [[0, 1], [1, 2]];
export const GLYPH_EDGE_WIDTH = 4.5;

// ── SVG builders ─────────────────────────────────────────────────────────────
// `fill` is "gradient" or a single colour; the gradient is emitted once per SVG
// under `id`, so two marks on one page do not collide.
export const gradientDefs = (id = "dc-mark-g") =>
  `<linearGradient id="${id}" x1="${GRADIENT.x1}" y1="${GRADIENT.y1}" x2="${GRADIENT.x2}" y2="${GRADIENT.y2}">` +
  `<stop offset="0" stop-color="${GRADIENT.from}"/><stop offset="1" stop-color="${GRADIENT.to}"/></linearGradient>`;

const paint = (fill, id) => (fill === "gradient" ? `url(#${id})` : fill);

export const markPaths = (fill = "gradient", id = "dc-mark-g") =>
  `<g fill="${paint(fill, id)}">${MARK_PATHS.map((d) => `<path d="${d}"/>`).join("")}</g>`;

export const markSvg = ({ fill = "gradient", id = "dc-mark-g", attrs = "" } = {}) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${MARK_BOX}" role="img" aria-label="decentralized.cloud mark"${attrs}>` +
  (fill === "gradient" ? `<defs>${gradientDefs(id)}</defs>` : "") + markPaths(fill, id) + `</svg>`;

export const glyphSvg = ({ fill = "gradient", id = "dc-glyph-g", size = 96 } = {}) => {
  // The cloud fills a square tile edge to edge on its long axis, centred on the short.
  // The pad clears the closing stroke's outer half, so no lobe is clipped by the tile.
  const pad = 4 + GLYPH_STROKE / 2;
  const scale = (size - 2 * pad) / MARK_WIDTH;
  const dy = (size - BLOCK * scale) / 2;
  const nodes = GLYPH_NODES.map((n) =>
    `<rect x="${n.x - n.s / 2}" y="${n.y - n.s / 2}" width="${n.s}" height="${n.s}" rx="${(n.s * 0.25).toFixed(2)}" fill="#000"/>`).join("");
  const edges = GLYPH_EDGES.map(([a, b]) =>
    `<line x1="${GLYPH_NODES[a].x}" y1="${GLYPH_NODES[a].y}" x2="${GLYPH_NODES[b].x}" y2="${GLYPH_NODES[b].y}" stroke="#000" stroke-width="${GLYPH_EDGE_WIDTH}"/>`).join("");
  const body = MARK_PATHS.map((d) => `<path d="${d}"/>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="decentralized.cloud">` +
    `<defs>${fill === "gradient" ? gradientDefs(id) : ""}` +
    `<mask id="${id}-cut"><rect width="${size}" height="${size}" fill="#fff"/>` +
    `<g transform="translate(${pad} ${dy.toFixed(3)}) scale(${scale.toFixed(5)})">${edges}${nodes}</g></mask></defs>` +
    `<g mask="url(#${id}-cut)" transform="translate(${pad} ${dy.toFixed(3)}) scale(${scale.toFixed(5)})">` +
    `<g fill="${paint(fill, id)}" stroke="${paint(fill, id)}" stroke-width="${GLYPH_STROKE}" stroke-linejoin="round">${body}</g></g></svg>`;
};

export const appIconSvg = ({ id = "dc-icon-g", tile = WHITE } = {}) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${ICON.tile} ${ICON.tile}" role="img" aria-label="decentralized.cloud">` +
  `<defs>${gradientDefs(id)}</defs>` +
  `<rect width="${ICON.tile}" height="${ICON.tile}" rx="${ICON.radius}" fill="${tile}"/>` +
  `<g transform="translate(${ICON.x} ${ICON.y}) scale(${ICON.scale})">${markPaths("gradient", id)}</g></svg>`;
