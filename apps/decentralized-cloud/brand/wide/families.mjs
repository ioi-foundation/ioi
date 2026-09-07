// WIDE GENERATION — the candidate families.
//
// The previous phase drew five marks a round, by hand, and closed at its cap after
// four rounds with zero passes. Twenty drawings is not a search; it is twenty
// guesses. This module replaces the drawing step with a parameter sweep, so a round
// puts HUNDREDS of shapes in front of the cheap filter (16px, one ink, "name it in
// one word") and only survivors are ever crafted.
//
// Every family below is built against the findings the previous phase paid for, and
// each finding is a CONSTRAINT IN THE GEOMETRY here, not a note:
//
//   R1  Few, large, regular, centred, symmetric elements is the vocabulary system
//       icons are drawn in. => no candidate is mirror-symmetric about either axis,
//       and no family centres its event.
//   R2  At 16px an interior event is 1-3 device pixels, so the identity lives in the
//       OUTLINE. => every family's first event is an outline event. A counter is
//       only ever a family's SECOND event.
//   R3  A silhouette that is somebody else's. => the renderer scores every candidate
//       against the retired ghosts and against every other candidate, and against
//       the TYPE it sits beside (the probe the last phase named and never built).
//   R4  A tilt with nothing level in it reads as a misaligned asset. => every canted
//       family carries one true horizontal at the base, level with the type's
//       baseline. That is the one construction fix readers confirmed as "a decision".
//
// Angles: cardinal edges (0/45/90) are avoided except for that one base horizontal.
// The grid is 96 units and the product size is 16px, so ONE device pixel is 6 grid
// units. Any event smaller than ~12 units is invisible at product size and the
// sweeps below do not generate one.

export const GRID = 96;
export const INK = "#0d0f12";
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;
const pts = (ps) => ps.map(([x, y]) => `${R2(x)},${R2(y)}`).join(" ");

// A body plus zero or more subtractions, as one masked rect. Using a mask rather
// than fill-rule keeps every family composable: a counter, a kerf and a bite are the
// same operation, so a candidate can carry two events of different kinds without a
// second code path.
function masked(id, bodyMarkup, holesMarkup) {
  if (!holesMarkup) return bodyMarkup;
  const mid = `m-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    bodyMarkup.replace(/fill="INK"/g, 'fill="white"') +
    holesMarkup +
    `</mask></defs>` +
    `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>`
  );
}

const polygon = (ps) => `<polygon points="${pts(ps)}" fill="INK"></polygon>`;

// ── A · the canted mass with a counter ──────────────────────────────────────
// The direction the phase ruled: a counter in a mass whose container is nameable as
// nothing. Its named fault is that the container reads as a luggage tag, so the
// sweep moves the four vertices, bows one edge and moves the counter, and the cheap
// filter reads back what each one is called.
function familyA() {
  const out = [];
  const BASE = 84, TOP = 12;
  const cants = [
    { k: "lean-l", tl: 20, tr: 8, bl: 8, br: 90 },
    { k: "lean-r", tl: 8, tr: 22, bl: 14, br: 88 },
    { k: "lean-s", tl: 14, tr: 14, bl: 6, br: 84 },
  ];
  const bows = [0, 10, 20];
  const bowEdges = ["left", "right", "top"];
  const counters = [
    { k: "hi-l", cx: 36, cy: 36 },
    { k: "lo-r", cx: 62, cy: 60 },
    { k: "hi-r", cx: 64, cy: 34 },
  ];
  for (const c of cants) {
    for (const bow of bows) {
      for (const be of bowEdges) {
        for (const ct of counters) {
          // Four corners: top-left, top-right, base-right, base-left. The base is the
          // one true horizontal; the two top corners sit at different heights so no
          // edge is level with another and none lands on a cardinal angle.
          const P = [
            [c.bl + 4, TOP + c.tl],
            [c.br - 4, TOP + c.tr],
            [c.br, BASE],
            [c.bl, BASE],
          ];
          // The bow is a quadratic control point pushed off the chosen edge's midpoint
          // along its normal; bow 0 leaves the edge straight.
          const bowed = (a, b) => {
            const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
            const dx = b[0] - a[0], dy = b[1] - a[1];
            const len = Math.hypot(dx, dy) || 1;
            return `Q ${R2(mx - (dy / len) * bow)} ${R2(my + (dx / len) * bow)} ${R2(b[0])} ${R2(b[1])}`;
          };
          const seg = (which, a, b) =>
            bow > 0 && be === which ? bowed(a, b) : `L ${R2(b[0])} ${R2(b[1])}`;
          const body =
            `<path d="M ${R2(P[0][0])} ${R2(P[0][1])} ` +
            `${seg("top", P[0], P[1])} ` +
            `${seg("right", P[1], P[2])} ` +
            `L ${R2(P[3][0])} ${R2(P[3][1])} ` +   // the base: always straight, always level
            `${seg("left", P[3], P[0])} Z" fill="INK"></path>`;
          const id = `A-${c.k}-b${bow}${bow ? be[0] : ""}-${ct.k}`;
          out.push({
            id, family: "A canted mass + counter",
            thesis: "a counter in a canted mass with one bowed edge and one true horizontal base",
            draw: () => masked(id, body, `<circle cx="${ct.cx}" cy="${ct.cy}" r="14" fill="black"></circle>`),
            silhouette: () => body,
          });
        }
      }
    }
  }
  return out;
}

// ── B · the kerf ────────────────────────────────────────────────────────────
// One mass cut clean through by a straight kerf at a non-cardinal angle, offset from
// centre so the two pieces have different mass. The event is a full-width outline
// event, not an interior one, so it survives 16px by construction. The idea it is
// near is routing: one thing arriving at two.
function familyB() {
  const out = [];
  const bodies = [
    { k: "quad", ps: [[10, 20], [88, 10], [90, 84], [8, 84]] },
    { k: "trap", ps: [[18, 14], [86, 24], [88, 84], [10, 84]] },
  ];
  for (const b of bodies) {
    for (const ang of [18, 32, 54]) {          // degrees off vertical; never 0 or 45
      for (const off of [-18, -6, 14]) {       // how far the kerf misses the centre
        for (const w of [8, 13]) {
          const rad = (ang * Math.PI) / 180;
          const cx = 48 + off, cy = 48;
          const dx = Math.sin(rad) * 90, dy = Math.cos(rad) * 90;
          const nx = (Math.cos(rad) * w) / 2, ny = (-Math.sin(rad) * w) / 2;
          const kerf = polygon([
            [cx - dx + nx, cy - dy + ny], [cx + dx + nx, cy + dy + ny],
            [cx + dx - nx, cy + dy - ny], [cx - dx - nx, cy - dy - ny],
          ]).replace('fill="INK"', 'fill="black"');
          const id = `B-${b.k}-a${ang}-o${off}-w${w}`;
          const body = polygon(b.ps);
          out.push({
            id, family: "B kerf-split mass",
            thesis: "one mass cut through by an off-centre kerf at a non-cardinal angle",
            draw: () => masked(id, body, kerf),
            silhouette: () => body,
          });
        }
      }
    }
  }
  return out;
}

// ── C · strata ──────────────────────────────────────────────────────────────
// Three bars of unequal length with sheared ends and unequal gaps. The hazard is
// explicit and this family exists to be killed if the readers name it: an align-left
// or menu button is exactly three bars, so everything here that makes it NOT that —
// the shear, the unequal lengths, the ragged left edge — has to carry the whole
// shape, and if it cannot, the cheap filter says so in one word.
function familyC() {
  const out = [];
  const shears = [10, 20, 30];
  const lens = [
    { k: "wide-top", l: [86, 58, 40] },
    { k: "wide-mid", l: [52, 88, 36] },
    { k: "wide-bot", l: [40, 62, 90] },
  ];
  const starts = [
    { k: "flush", s: [8, 8, 8] },
    { k: "step", s: [8, 20, 32] },
    { k: "zig", s: [8, 30, 14] },
  ];
  for (const sh of shears) {
    for (const L of lens) {
      for (const S of starts) {
        const ys = [18, 44, 70], h = 17;
        const bars = ys.map((y, i) => {
          const x0 = S.s[i], x1 = Math.min(94, S.s[i] + L.l[i]);
          return polygon([[x0 + sh, y], [x1, y], [x1 - sh, y + h], [x0, y + h]]);
        }).join("");
        const id = `C-s${sh}-${L.k}-${S.k}`;
        out.push({
          id, family: "C sheared strata",
          thesis: "three bars of unequal length with sheared ends and a ragged left edge",
          draw: () => bars,
          silhouette: () => bars,
        });
      }
    }
  }
  return out;
}

// ── D · the arc bite ────────────────────────────────────────────────────────
// A mass with a circular bite taken out of one edge by a circle whose centre is
// OUTSIDE the mass. A V-notch is a bookmark and a ticket; an arc is neither, and it
// is the one edge event the phase never tried.
function familyD() {
  const out = [];
  const body = polygon([[10, 16], [88, 8], [90, 84], [8, 84]]);
  const sites = [
    { k: "top", cx: 58, cy: 6 }, { k: "right", cx: 96, cy: 44 }, { k: "left", cx: 4, cy: 52 },
  ];
  for (const s of sites) {
    for (const r of [20, 28, 36]) {
      for (const push of [0, 8, 16]) {   // how far the biting circle is driven in
        const dirx = s.k === "right" ? -1 : s.k === "left" ? 1 : 0;
        const diry = s.k === "top" ? 1 : 0;
        const bite = `<circle cx="${s.cx + dirx * push}" cy="${s.cy + diry * push}" r="${r}" fill="black"></circle>`;
        const id = `D-${s.k}-r${r}-p${push}`;
        out.push({
          id, family: "D arc bite",
          thesis: "a mass bitten by a circle whose centre lies outside it",
          draw: () => masked(id, body, bite),
          silhouette: () => masked(id, body, bite),
        });
      }
    }
  }
  return out;
}

// ── E · the keyway ──────────────────────────────────────────────────────────
// One edge of the mass steps in and back out once, with both step faces cut at an
// angle so neither is vertical. Two events of different kinds on one body: the step,
// and the cant of the body itself.
function familyE() {
  const out = [];
  for (const edge of ["right", "top", "left"]) {
    for (const depth of [16, 24, 32]) {
      for (const at of [0.3, 0.5, 0.72]) {
        const L = 10, R = 90, T = 12, B = 84, skew = 9;
        let ps;
        if (edge === "right") {
          const y0 = T + (B - T) * at - 14, y1 = y0 + 28;
          ps = [[L + 6, T], [R, T + 6], [R, y0], [R - depth, y0 + skew], [R - depth, y1], [R, y1 + skew], [R, B], [L, B]];
        } else if (edge === "top") {
          const x0 = L + (R - L) * at - 14, x1 = x0 + 28;
          ps = [[L, T + 8], [x0, T + 4], [x0 + skew, T + depth], [x1, T + depth], [x1 + skew, T], [R, T + 10], [R - 2, B], [L, B]];
        } else {
          const y0 = T + (B - T) * at - 14, y1 = y0 + 28;
          ps = [[L + 4, T], [R, T + 8], [R - 2, B], [L, B], [L, y1 + skew], [L + depth, y1], [L + depth, y0 + skew], [L, y0]];
        }
        const id = `E-${edge}-d${depth}-a${String(at).replace(".", "")}`;
        const body = polygon(ps);
        out.push({
          id, family: "E keyway step",
          thesis: "one edge steps in and back out once, both step faces cut off-vertical",
          draw: () => body, silhouette: () => body,
        });
      }
    }
  }
  return out;
}

// ── F · the pair ────────────────────────────────────────────────────────────
// Two masses of deliberately unequal size on an implied line that is not level. The
// only family here whose subject is a RELATION rather than an object, which is what
// the product is: one request arriving at many venues.
function familyF() {
  const out = [];
  for (const ratio of [0.34, 0.52, 0.7]) {
    for (const ang of [14, 26, 40]) {
      for (const gap of [10, 16, 24]) {
        const big = 46, small = Math.round(big * ratio);
        const rad = (ang * Math.PI) / 180;
        const ax = 30, ay = 60;
        const bx = ax + Math.cos(rad) * (big / 2 + gap + small / 2) + 14;
        const by = ay - Math.sin(rad) * (big / 2 + gap + small / 2) - 6;
        const quad = (cx, cy, s, tilt) => {
          const t = (tilt * Math.PI) / 180, h = s / 2;
          const c = Math.cos(t), sn = Math.sin(t);
          return polygon([[-h, -h], [h, -h * 0.78], [h * 0.9, h], [-h, h]].map(([x, y]) =>
            [cx + x * c - y * sn, cy + x * sn + y * c]));
        };
        const id = `F-r${String(ratio).replace(".", "")}-a${ang}-g${gap}`;
        const m = quad(ax, ay, big, -8) + quad(bx, by, small, 12);
        out.push({
          id, family: "F unequal pair",
          thesis: "two masses of unequal size on an implied line that is not level",
          draw: () => m, silhouette: () => m,
        });
      }
    }
  }
  return out;
}

// ── G · notch and counter ───────────────────────────────────────────────────
// The pairing round four bet on — one outline event and one interior event, of
// different kinds — swept properly rather than drawn once.
function familyG() {
  const out = [];
  const L = 10, R = 90, T = 14, B = 84;
  for (const nEdge of ["right", "base", "top"]) {
    for (const nDepth of [18, 26, 34]) {
      for (const ct of [{ k: "hi", cx: 38, cy: 36 }, { k: "lo", cx: 58, cy: 62 }, { k: "mid", cx: 44, cy: 52 }]) {
        let ps;
        if (nEdge === "right") ps = [[L + 6, T], [R, T + 5], [R - nDepth, 48], [R, B - 4], [L, B]];
        else if (nEdge === "base") ps = [[L + 6, T], [R, T + 5], [R - 2, B], [56, B], [46, B - nDepth], [34, B], [L, B]];
        else ps = [[L + 4, T + 6], [40, T], [50, T + nDepth], [62, T + 2], [R, T + 8], [R - 2, B], [L, B]];
        const id = `G-${nEdge}-d${nDepth}-${ct.k}`;
        const body = polygon(ps);
        out.push({
          id, family: "G notch + counter",
          thesis: "one outline event and one interior event, of different kinds",
          draw: () => masked(id, body, `<circle cx="${ct.cx}" cy="${ct.cy}" r="13" fill="black"></circle>`),
          silhouette: () => body,
        });
      }
    }
  }
  return out;
}

// ── H and I · derived from the face's own outlines ──────────────────────────
// ioi-c0's ruling: widen by FAMILY, and add letterform-derived cuts and
// wordmark-fragment marks. Both families take their body from IOI Display's actual
// glyph outlines rather than from a drawing of one, so "derived from the wordmark"
// is a fact about the geometry and not a claim in a caption.
//
// The obvious hazard is the obvious one: a mark cut from a D that still reads as a D
// is a monogram, and the phase's own finding is that a mark absorbed into its own
// wordmark has stopped being a mark. That is precisely what the type probe measures,
// so this family is generated freely and the probe is allowed to kill most of it.
// If it kills all of it, that is a result about the idea, not a bug in the sweep.
import { createRequire } from "node:module";
const require_ = createRequire(import.meta.url);
const opentype = require_("/home/heathledger/Documents/ioi/repos/ioi/node_modules/opentype.js");
const FACE = opentype.loadSync(
  new URL("../../public/fonts/IOI.ttf", import.meta.url).pathname
);

// A glyph outline placed in the 96 grid: scaled uniformly so its cap fills 76 units
// and centred, which is the same box every other family draws into.
const CAP_UNITS = 76;
function glyphPath(ch) {
  const g = FACE.charToGlyph(ch);
  const p = g.getPath(0, 0, 700);
  const bb = p.getBoundingBox();
  const s = CAP_UNITS / (bb.y2 - bb.y1);
  const w = (bb.x2 - bb.x1) * s;
  const tx = (GRID - w) / 2 - bb.x1 * s;
  const ty = (GRID - CAP_UNITS) / 2 - bb.y1 * s;
  p.commands = p.commands.map((c) => {
    const o = { ...c };
    for (const [ax, ay] of [["x", "y"], ["x1", "y1"], ["x2", "y2"]]) {
      if (o[ax] !== undefined) o[ax] = o[ax] * s + tx;
      if (o[ay] !== undefined) o[ay] = o[ay] * s + ty;
    }
    return o;
  });
  return p.toPathData(2);
}

// Crop a body to a window: everything outside the window polygon is removed. Using a
// clip rather than four masking rectangles keeps a canted window canted.
function clipped(id, bodyMarkup, windowPts) {
  const cid = `c-${id}`;
  return (
    `<defs><clipPath id="${cid}" clipPathUnits="userSpaceOnUse">` +
    `<polygon points="${pts(windowPts)}"></polygon></clipPath></defs>` +
    `<g clip-path="url(#${cid})">${bodyMarkup}</g>`
  );
}

const GLYPHS_H = ["D", "C", "O", "U", "S"];

function familyH() {
  const out = [];
  for (const ch of GLYPHS_H) {
    const d = glyphPath(ch);
    const body = `<path d="${d}" fill="INK"></path>`;
    for (const amount of [16, 26, 36]) {
      // kerf: cut the letter through at a non-cardinal angle
      for (const ang of [22, 58]) {
        const rad = (ang * Math.PI) / 180;
        const dx = Math.sin(rad) * 90, dy = Math.cos(rad) * 90;
        const nx = (Math.cos(rad) * 11) / 2, ny = (-Math.sin(rad) * 11) / 2;
        const cx = 48, cy = 48 - amount + 20;
        const kerf = polygon([
          [cx - dx + nx, cy - dy + ny], [cx + dx + nx, cy + dy + ny],
          [cx + dx - nx, cy + dy - ny], [cx - dx - nx, cy - dy - ny],
        ]).replace('fill="INK"', 'fill="black"');
        const id = `H-${ch}-kerf${ang}-${amount}`;
        out.push({
          id, family: "H letterform cut",
          thesis: `the face's own ${ch}, cut through at ${ang} degrees off vertical`,
          draw: () => masked(id, body, kerf), silhouette: () => body,
        });
      }
      // arc bite out of the letter's outer edge
      const id2 = `H-${ch}-bite${amount}`;
      out.push({
        id: id2, family: "H letterform cut",
        thesis: `the face's own ${ch}, bitten by a circle centred outside it`,
        draw: () => masked(id2, body, `<circle cx="${94}" cy="${34 + amount}" r="${22 + amount / 2}" fill="black"></circle>`),
        silhouette: () => body,
      });
      // canted crop: the letter seen through a leaning window
      const id3 = `H-${ch}-crop${amount}`;
      out.push({
        id: id3, family: "H letterform cut",
        thesis: `the face's own ${ch} seen through a leaning window`,
        draw: () => clipped(id3, body, [[6, 10 + amount / 2], [90, 4], [90, 88], [6, 82 + amount / 2]]),
        silhouette: () => clipped(`${id3}-s`, body, [[6, 10 + amount / 2], [90, 4], [90, 88], [6, 82 + amount / 2]]),
      });
    }
  }
  return out;
}

function familyI() {
  const out = [];
  // A fragment of a letter, taken through a canted window that keeps a MINORITY of
  // the glyph. The bet is that a corner of the face's own drawing — a bowl terminal,
  // the elbow of the drawn Z — carries the wordmark's hand without being readable as
  // the letter it came from.
  const Z_PATH =
    "M 32 700 L 1033 700 L 1033 560 L 221 140 L 1033 140 L 1033 0 " +
    "L 32 0 L 32 140 L 844 560 L 32 560 Z";
  const zScaled = (() => {
    const s = CAP_UNITS / 700, w = 1065 * s;
    return `<g transform="translate(${R2((GRID - w) / 2)} ${R2((GRID - CAP_UNITS) / 2)}) scale(${R2(s)}) translate(0 700) scale(1 -1)">` +
      `<path d="${Z_PATH}" fill="INK"></path></g>`;
  })();
  const sources = [
    ...["D", "C", "O", "S"].map((ch) => ({ k: ch, body: `<path d="${glyphPath(ch)}" fill="INK"></path>` })),
    { k: "Zdrawn", body: zScaled },
  ];
  const windows = [
    { k: "tl", ps: [[4, 4], [58, 10], [50, 62], [4, 56]] },
    { k: "tr", ps: [[42, 6], [92, 4], [92, 58], [36, 64]] },
    { k: "bl", ps: [[4, 38], [56, 32], [62, 92], [4, 92]] },
    { k: "br", ps: [[38, 34], [92, 40], [92, 92], [44, 92]] },
  ];
  for (const s of sources) {
    for (const w of windows) {
      for (const lean of [0, 12]) {
        const ps = w.ps.map(([x, y]) => [x + (lean * (y - 48)) / 96, y]);
        const id = `I-${s.k}-${w.k}-l${lean}`;
        out.push({
          id, family: "I wordmark fragment",
          thesis: `a fragment of the face's own ${s.k}, taken through a ${w.k} window`,
          draw: () => clipped(id, s.body, ps),
          silhouette: () => clipped(`${id}-s`, s.body, ps),
        });
      }
    }
  }
  return out;
}

export const CANDIDATES = [
  ...familyA(), ...familyB(), ...familyC(),
  ...familyD(), ...familyE(), ...familyF(), ...familyG(),
  ...familyH(), ...familyI(),
];

// ── Ghosts ──────────────────────────────────────────────────────────────────
// Carried from the retired phase for the silhouette comparison ONLY: never plated,
// never shown to a reader, never scored. They exist so this round cannot spend a
// cold reader on a shape that is already dead.
export const GHOSTS = [
  { id: "ghost-wedge", draw: () => `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>` },
  { id: "ghost-disc", draw: () => `<circle cx="48" cy="48" r="42" fill="INK"></circle>` },
  {
    id: "ghost-canted-counter",
    draw: () =>
      `<defs><mask id="m-gcc" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<path d="M 18 22 L 84 10 Q 92 48 86 84 L 12 84 Z" fill="white"></path>` +
      `<circle cx="58" cy="44" r="14" fill="black"></circle></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m-gcc)"></rect>`,
  },
];

export const svgFor = (markup, size) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}" shape-rendering="auto">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK/g, INK) + `</svg>`;
