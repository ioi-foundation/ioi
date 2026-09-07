// THE MARK — one source, framework-free.
//
// decentralized.cloud's identity is the owner's, delivered complete on 2026-09-07 as
// brand/mark/source/brand-identity-standalone.html — a bundled page whose assets are
// decoded verbatim into brand/mark/source/: the dark and light lockups, the mark in
// full colour and in two monos, the reduction glyph, the wordmark, the animated SVG
// mark (the "replica engine"), the WebGL hero and the brand page itself. Those files
// ARE the brand. Nothing here redraws them: public/brand/ is a byte-for-byte copy
// that build-assets.mjs makes and --check verifies, and this module exports only the
// numbers the shell and the face gate need to agree with those files.
//
// THE MARK is a cloud — three circles and a flat base — with a stepped block cut out
// of its right lobe, the cut's walls in interior indigo, and a cyan network of eight
// nodes standing inside it. THE ANIMATED MARK sinks the blocks of a grid across the
// cloud's face to open that cut where the pointer is, and the network builds inside.
// THE WORDMARK is DECENTRALIZED over CLOUD in IOI Display with a gradient dot before
// CLOUD, set 2.65× smaller than the mark with a gap of 7.5% of the mark's width.

// ── Colour ──────────────────────────────────────────────────────────────────
// Registered in packages/design-system/tokens/colors.css under the same names.
export const MARK_INDIGO = "#3f3dfa";       // --color-dc-mark-indigo
export const MARK_CYAN = "#41dbf9";         // --color-dc-mark-cyan, the network
export const SUBSTRATE_NAVY = "#000c26";    // --color-dc-substrate-navy
export const INTERIOR_INDIGO = "#0e2250";   // --color-dc-interior-indigo, the cut's walls
export const WHITE = "#ffffff";
export const BLACK = "#000000";
// The cut's bevel faces in the static mark, as the owner's file paints them.
export const CUT_FACES = { lit: "#2b4fb0", side: "#23409a", shade: "#1b2f72", deep: "#101f4e" };
export const GRADIENT = { x1: 0, y1: 1, x2: 1, y2: 0, from: MARK_INDIGO, to: MARK_CYAN };

// ── The static mark, from mark-dark.svg ─────────────────────────────────────
export const MARK_BOX = "-2 -4 210 125";
export const MARK_WIDTH = 210;
export const MARK_HEIGHT = 125;
// The cloud silhouette: three circles and the base, one path, verbatim from the file.
// The face gate asserts this exact string is in the served bytes, and build-assets
// refuses to run if the file on disk no longer carries it.
export const CLOUD_PATH =
  "M 72 87 A 36.00 36.00 0 1 0 0 87 A 36.00 36.00 0 1 0 72 87 Z M 126 61 A 46.00 46.00 0 1 0 34 61 A 46.00 46.00 0 1 0 126 61 Z M 202 69 A 60.00 60.00 0 1 0 82 69 A 60.00 60.00 0 1 0 202 69 Z M 13.37 115 L 180.52 115 L 180.52 80 L 13.37 80 Z";
export const MARK_PATHS = [CLOUD_PATH];
// The cut, as the polygon the file masks out of the cloud.
export const CUT_POLYGON =
  "98.5,93.5 117.5,93.5 136.5,93.5 155.5,93.5 174.5,93.5 193.5,93.5 193.5,74.5 193.5,55.5 174.5,55.5 174.5,36.5 155.5,36.5 155.5,17.5 136.5,17.5 117.5,17.5 117.5,36.5 98.5,36.5 98.5,55.5 98.5,74.5";
// The network's eight nodes (7.2 square, radius 1.2) inside the cut, top-left corners.
export const NET_NODES = [
  [127.15, 19.86], [158.2, 20.27], [142.0, 42.59], [168.46, 51.33],
  [126.34, 66.69], [154.15, 70.62], [139.3, 97.12], [166.3, 99.35],
];
export const NET_NODE_SIZE = 7.2;

// ── The lockup, from lockup-dark.svg ────────────────────────────────────────
// The wordmark group sits at this transform inside the mark's box: 0.6458 is the
// scale that makes the mark 2.65× the wordmark block, and 120.24 puts the wordmark's
// ink one gap of 7.5% of the mark's width after the cloud.
export const LOCKUP_BOX = "-2 -4 489.2520215633423 125";
export const LOCKUP_WORDMARK_TRANSFORM = "translate(120.24 35.80) scale(0.6458)";
export const MARK_TO_BLOCK = 2.65;
export const GAP_OF_MARK_WIDTH = 0.075;

// ── The wordmark's layout, measured on the outlines ──────────────────────────
// The shell sets the name as LIVE TEXT in IOI Display (owner ruling 2026-09-05)
// inside an SVG so each line is placed by its baseline; the numbers are the ink
// boxes of the outlined wordmark the owner's lockups carry (wordmark.svg, whose
// box is x 147..562, y -8..76 around the same ink).
export const BLOCK = 67.188;                // CLOUD's baseline to the top of DECENTRALIZED
export const WORDMARK_X = 149.84;           // ink left of both lines and of the dot
export const TOP_CAP = 22.072;              // DECENTRALIZED, y 0..22.072
export const BOTTOM_CAP = 38;               // CLOUD, y 29.188..67.188
export const BOTTOM_TOP = 29.188;
export const TOP_FONT_SIZE = TOP_CAP / 0.7;       // capHeight 700/1000
export const BOTTOM_FONT_SIZE = BOTTOM_CAP / 0.7;
export const WORDMARK_WIDTH = 409.206;      // ink, both lines: x 149.84..559.046
export const CLOUD_LETTER_INK = [
  [181, 236.589], [260.149, 314.435], [337.995, 397.166], [420.726, 479.897], [503.457, 559.046],
];
// THE DOT: a rounded square carrying the gradient, on the baseline before CLOUD. The
// owner's lockup scales the outlined dot 1.38× about its centre (154.64, 63.388):
// 7.6 units becomes 10.488, which is what the live-text shell draws.
export const DOT = { x: 149.84, y: 59.588, size: 7.6, radius: 1.9 };
export const DOT_SCALE = 1.38;
export const DOT_CENTRE = { x: 154.64, y: 63.388 };
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

// ── The animated mark — the owner's replica engine, its constants verbatim ─────
// World units: the cloud spans x -1.055..0.955; the camera sits at z 2.8 looking at
// the face; the extrusion is 0.34 deep; a grid of 0.19 blocks across the face sinks
// where the cut is. The header draws this with src/components/AnimatedMark.jsx.
export const ANIM = {
  circles: [[-0.70, -0.02, 0.36], [-0.26, 0.24, 0.46], [0.36, 0.16, 0.60]],
  flatY: -0.30, xMin: -1.055, xMax: 0.955,
  depth: 0.34, blockDepth: 0.14, sink: 0.16,
  pitch: 0.19, x0: -0.93, y0: -0.18, inset: 0.14,
  camZ: 2.8, camY: 0.18, fov: 45,
  u: 0.27, halfWidth: 0.52, defaultCut: 0.45, nodeZOffset: 0.04,
  nodes: [[-0.75, 0.06], [0.4, 0.04], [-0.2, 0.32], [0.78, 0.36], [-0.78, 0.58], [0.25, 0.62], [-0.3, 0.92], [0.7, 0.94]],
  edges: [[0, 1], [0, 2], [1, 2], [1, 3], [2, 3], [2, 4], [2, 5], [3, 5], [4, 5], [4, 6], [5, 6], [5, 7], [6, 7]],
  // The lit-face gradient, sampled from the WebGL hero render — the owner's stops.
  gradientStops: [
    [0, "rgb(49,56,187)"], [0.164, "rgb(49,82,187)"], [0.278, "rgb(50,100,187)"], [0.413, "rgb(50,116,187)"],
    [0.599, "rgb(50,136,187)"], [0.678, "rgb(50,140,187)"], [0.775, "rgb(51,151,187)"], [0.84, "rgb(51,156,186)"], [1, "rgb(51,156,186)"],
  ],
  slices: 9, sideSlices: 4, samples: 160,
  nodeSize: 0.072, pulsePeriod: 3.4,
};

// ── The files ────────────────────────────────────────────────────────────────
// What public/brand/ holds, each a verbatim copy of the same-named source file.
export const BRAND_FILES = [
  "lockup-dark.svg", "lockup-light.svg", "mark-dark.svg", "mark-light.svg",
  "mark-mono-white.svg", "mark-mono-navy.svg", "glyph.svg", "wordmark.svg",
  "mark-animated.html", "hero-3d.html", "three-d-stage.js",
];
// The favicon is the reduction glyph under the name browsers look for.
export const FAVICON_SOURCE = "glyph.svg";
