// The five skeletons, and nothing else about them.
//
// SMALL-SIZE-FIRST, per the new-mark phase brief: at this stage a concept is a
// drawing on a 96-unit grid in ONE INK on white. No tile, no colour, no gradient,
// no board. The monogram phase reached corner arcs within 0.04% of true circles on
// a shape that reads as a toolbar icon; that order is inverted here.
//
// Each skeleton declares, in the same object as its geometry:
//
//   separation — the claim that its parts stay apart, as an axis and a scan
//     coordinate DERIVED FROM ITS OWN GEOMETRY (a guessed scan row can miss the
//     feature entirely and report a fusion that is really a bad scan), plus the
//     number of runs of ink the drawing is claiming to have there.
//   cue — how a sibling is named, as an axis and a `step` in grid units. The step
//     is the closed form the measured separation is cross-checked against. A
//     measurement that disagrees with the arithmetic in this file is a broken
//     measurement, not a finding.
//   hazards — the stock shapes this drawing is near, written before it is drawn
//     rather than discovered by a reviewer later.
//
// The three siblings are the decentralized.* family: cloud, exchange, trade. The
// cue must be visible in the LOCKUP at product size, not only in a tile — that is
// the test the monogram failed, so `cueInLockup` is drawn and measured too.

export const GRID = 96;
export const INK = "#0a0e19";
export const GROUND = "#ffffff";
export const SIBLINGS = ["cloud", "exchange", "trade"];

// ── S1 · routed graph ───────────────────────────────────────────────────────
// Banked concept one. Nodes are venues, edges are routes, one lit edge is the
// chosen placement. Three destinations so the lit route has three states.
const S1 = () => {
  const src = { x: 17, y: 48, r: 11 };
  const dst = [{ x: 79, y: 17 }, { x: 79, y: 48 }, { x: 79, y: 79 }];
  const R = 9.5;
  const thin = 5, thick = 12;
  return {
    id: "routed-graph",
    name: "Routed graph",
    origin: "banked — concept one in the phase brief",
    thesis: "nodes are venues, edges are routes, the lit edge is the chosen placement",
    hazards: [
      "Structurally the Android/Material SHARE glyph: three nodes joined by edges. It must escape that read by geometry, not by colour.",
      "Google Cloud product-icon house style; a token swap on a Google-shaped mark is still a Google-shaped mark.",
    ],
    // The three destination nodes must stay three, so the scan is a COLUMN through
    // their shared centre x, and it is claiming three runs.
    separation: { axis: "y", at: dst[0].x / GRID, runs: 3, of: "the three destination nodes" },
    separationOn: null,
    // Which destination is lit names the sibling. The closed form has to describe
    // EVERYTHING that differs between a sibling and the base, and here that is not
    // just the enlarged node: the whole edge from the source thickens too, and it
    // crosses most of the frame. Declaring only the node centre made the probe
    // disagree with the file by 1.7px at 16px — the arithmetic was wrong, not the
    // measurement, and the cross-check is what said so. So the cue centre is the
    // area-weighted centroid of the widened edge (centroid at its midpoint) and
    // the grown node ring.
    cueCentres: Object.fromEntries(SIBLINGS.map((k, i) => {
      const d = dst[i];
      const len = Math.hypot(d.x - src.x, d.y - src.y);
      const wEdge = len * (thick - thin);                       // band added along the edge
      const wNode = Math.PI * ((R + 3) ** 2 - R ** 2);           // ring added at the node
      const mx = (src.x + d.x) / 2, my = (src.y + d.y) / 2;
      return [k, [
        (mx * wEdge + d.x * wNode) / (wEdge + wNode),
        (my * wEdge + d.y * wNode) / (wEdge + wNode),
      ]];
    })),
    draw: (sib) => {
      const lit = sib === null ? -1 : SIBLINGS.indexOf(sib);
      let s = "";
      dst.forEach((d, i) => {
        const w = i === lit ? thick : thin;
        s += `<line x1="${src.x}" y1="${src.y}" x2="${d.x}" y2="${d.y}" stroke="INK" stroke-width="${w}" stroke-linecap="round"></line>`;
      });
      s += `<circle cx="${src.x}" cy="${src.y}" r="${src.r}" fill="INK"></circle>`;
      dst.forEach((d, i) => {
        s += `<circle cx="${d.x}" cy="${d.y}" r="${i === lit ? R + 3 : R}" fill="INK"></circle>`;
      });
      return s;
    },
  };
};

// ── S2 · isometric blocks ───────────────────────────────────────────────────
// Banked concept two. Capacity as blocks: one large placement and one small.
const S2 = () => {
  // A flat isometric block: top rhombus + two side faces. In one ink the faces
  // cannot be told apart by tone, so the block is drawn as an OUTLINE mass with
  // its two interior edges knocked out. Whether those edges survive 16px is the
  // whole question, and it is measured rather than assumed.
  const iso = (cx, cy, w, h, d) => {
    const p = (x, y) => `${x.toFixed(2)},${y.toFixed(2)}`;
    const top = `${p(cx, cy - h / 2 - d)} ${p(cx + w / 2, cy - d)} ${p(cx, cy + h / 2 - d)} ${p(cx - w / 2, cy - d)}`;
    const body = `${p(cx - w / 2, cy - d)} ${p(cx, cy + h / 2 - d)} ${p(cx + w / 2, cy - d)} ${p(cx + w / 2, cy - d + d * 2)} ${p(cx, cy + h / 2 + d)} ${p(cx - w / 2, cy - d + d * 2)}`;
    return { top, body, cx, cy };
  };
  const big = iso(34, 46, 54, 40, 13);
  const small = iso(76, 62, 30, 22, 8);
  return {
    id: "isometric-blocks",
    name: "Isometric blocks",
    origin: "banked — concept two in the phase brief",
    thesis: "capacity as blocks; one large placement and one small",
    hazards: [
      "Google Cloud's isometric product-icon language nearly verbatim — two-tone blue slabs are Compute Engine and Cloud Build.",
      "Isometric geometry collapses at 16px, the size at which every concept in this programme has died.",
      "\"Cube = compute\" is the default hosting-logo shape.",
    ],
    // In one ink the slabs are OUTLINES, so a row across them cuts four walls, not
    // two shapes. The first version of this claimed two runs and the probe returned
    // four and was allowed to pass on a >= comparison: a label claiming more than
    // its assertion checks. The claim now says what the geometry actually makes.
    separation: { axis: "x", at: 0.56, runs: 4, of: "the two walls of the large slab and the two of the small cube" },
    separationOn: null,
    // Which block is lit names the sibling: large, small, or the third behind.
    cueCentres: { cloud: [big.cx, big.cy], exchange: [small.cx, small.cy], trade: [76, 30] },
    draw: (sib) => {
      const lit = sib === null ? -1 : SIBLINGS.indexOf(sib);
      const blocks = [big, small, iso(76, 30, 26, 19, 7)];
      return blocks.map((b, i) => {
        const on = i === lit;
        const fill = on ? "INK" : "none";
        const stroke = `stroke="INK" stroke-width="5" stroke-linejoin="round"`;
        return `<polygon points="${b.body}" fill="${fill}" ${stroke}></polygon>` +
               `<polygon points="${b.top}" fill="${fill}" ${stroke}></polygon>`;
      }).join("");
    },
  };
};

// ── S3 · the chosen lane ────────────────────────────────────────────────────
// Mine. Candidates are lanes; exactly one runs past the others. It is flat and
// orthogonal, so it is neither the share glyph nor an isometric cube, and it
// rhymes with the owner's reserved three-bar construction rather than discarding
// it — a continuity worth testing, not worth assuming.
const S3 = () => {
  const H = 16, GAP = 14, X = 10, SHORT = 46, LONG = 76;
  const ys = [0, 1, 2].map((i) => 12 + i * (H + GAP));
  return {
    id: "chosen-lane",
    name: "The chosen lane",
    origin: "mine",
    thesis: "candidates are lanes; exactly one runs past the others — the route that was taken",
    hazards: [
      "Three stacked bars is the HAMBURGER MENU, and unequal bars is the standard sort/filter control. This is the same class of failure the monogram made against the duplicate-layers glyph, and it is the first thing a cold reader will be asked.",
      "Bar stacks are also the generic 'list' and 'align-left' glyphs.",
      "Its continuity with the owner's reserved three-bar d is a hypothesis. If a reader does not see the relation, the continuity is not there.",
    ],
    // The three lanes must stay three: a COLUMN inside every bar's left end.
    separation: { axis: "y", at: (X + 8) / GRID, runs: 3, of: "the three lanes" },
    separationOn: null,
    // Which lane runs long names the sibling. What DIFFERS from the base is the
    // extension beyond SHORT, so the cue centre is the middle of that extension.
    cueCentres: Object.fromEntries(SIBLINGS.map((k, i) =>
      [k, [X + (SHORT + LONG) / 2, ys[i] + H / 2]])),
    draw: (sib) => {
      const lit = sib === null ? -1 : SIBLINGS.indexOf(sib);
      return ys.map((y, i) =>
        `<rect x="${X}" y="${y}" width="${i === lit ? LONG : SHORT}" height="${H}" rx="${H / 2}" fill="INK"></rect>`
      ).join("");
    },
  };
};

// ── S4 · the bitten grid ────────────────────────────────────────────────────
// Mine. A pool of capacity with exactly one cell spent. The mark is MASS with a
// hole in it, which is the construction most likely to survive one ink at 16px:
// a knockout in a solid field is the last thing to close up.
const S4 = () => {
  const CELL = 38, GUT = 10, X0 = 5, Y0 = 5;
  const at = (c, r) => ({ x: X0 + c * (CELL + GUT), y: Y0 + r * (CELL + GUT) });
  // Three of the four cells are the sibling slots: top-right, bottom-left, bottom-right.
  const bite = { cloud: [1, 0], exchange: [0, 1], trade: [1, 1] };
  return {
    id: "bitten-grid",
    name: "The bitten grid",
    origin: "mine",
    thesis: "a pool of capacity with exactly one cell spent; the hole is the placement",
    hazards: [
      "A 2x2 of squares is the stock DASHBOARD / grid / app-launcher glyph, and Google's own apps grid is its 3x3 sibling.",
      "One-square-different in a grid is also the standard 'select all / deselect' control state.",
      "The whole concept rests on the knockout being legible at 16px. If the gutters close, it is a filled square.",
    ],
    separation: { axis: "x", at: (Y0 + CELL / 2) / GRID, runs: 2, of: "the two columns across the top row" },
    separationOn: null,
    // What differs from the full grid is the missing cell, so the cue centre is
    // that cell's centre.
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => {
      const p = at(bite[k][0], bite[k][1]);
      return [k, [p.x + CELL / 2, p.y + CELL / 2]];
    })),
    draw: (sib) => {
      const b = sib === null ? null : bite[sib];
      let s = "";
      for (let r = 0; r < 2; r++) for (let c = 0; c < 2; c++) {
        if (b && b[0] === c && b[1] === r) continue;
        const p = at(c, r);
        s += `<rect x="${p.x}" y="${p.y}" width="${CELL}" height="${CELL}" rx="7" fill="INK"></rect>`;
      }
      return s;
    },
  };
};

// ── S5 · the wedge counter ──────────────────────────────────────────────────
// Mine. A wedge carries direction without drawing an arrowhead, and a single
// punched counter is the receipt the routing mints. Mass-heavy on purpose: the
// silhouette is one shape, so there is nothing to fuse.
const S5 = () => {
  const L = 8, R = 88, TOPL = 20, BOTL = 76, TOPR = 6, BOTR = 90;
  const slots = { cloud: 30, exchange: 48, trade: 66 };  // counter centre x
  const CR = 13;
  // Thickness at a given x, so the counter is placed where the wedge is thick
  // enough to hold it rather than where it looked right.
  const halfAt = (x) => {
    const t = (x - L) / (R - L);
    const top = TOPL + (TOPR - TOPL) * t, bot = BOTL + (BOTR - BOTL) * t;
    return { top, bot, mid: (top + bot) / 2, h: bot - top };
  };
  return {
    id: "wedge-counter",
    name: "The wedge counter",
    origin: "mine",
    thesis: "direction without an arrowhead, and one punched counter — the receipt the routing mints",
    hazards: [
      "A wedge is the PLAY, cursor and volume glyph; the direction it carries is the direction those controls carry.",
      "A knocked-out circle in a mass is the standard 'do not enter' and record-button family.",
      "Being one mass, it cannot fail the separation probe — which means the separation probe proves nothing about it. Its risk is DISTINCTIVENESS, and that is a reader's judgement, not a measurement.",
    ],
    // The claim here is the opposite of the others: the counter must stay a HOLE.
    // A row through the counter's centre must find TWO runs of ink with the hole
    // between them, or the punch has closed.
    separation: { axis: "x", at: null, runs: 2, of: "ink either side of the punched counter" },
    // Unlike the others, this claim is only true once a counter is punched: the
    // base is one mass. The probe therefore runs on a sibling, not on the base.
    separationOn: "exchange",
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [slots[k], halfAt(slots[k]).mid]])),
    slots, halfAt, CR,
    draw: (sib) => {
      const body = `<polygon points="${L},${TOPL} ${R},${TOPR} ${R},${BOTR} ${L},${BOTL}" fill="white"></polygon>`;
      const cx = sib === null ? null : slots[sib];
      const mask = cx === null ? "" :
        `<circle cx="${cx}" cy="${halfAt(cx).mid.toFixed(2)}" r="${CR}" fill="black"></circle>`;
      return `<defs><mask id="wedge-${sib || "base"}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect x="0" y="0" width="${GRID}" height="${GRID}" fill="black"></rect>${body}${mask}</mask></defs>` +
             `<rect x="0" y="0" width="${GRID}" height="${GRID}" fill="INK" mask="url(#wedge-${sib || "base"})"></rect>`;
    },
  };
};

export const SKELETONS = [S1(), S2(), S3(), S4(), S5()];

// S5's scan coordinate depends on which sibling is drawn, so it is resolved late.
export function scanAt(sk, sib) {
  if (sk.separation.at !== null) return sk.separation.at;
  return sk.halfAt(sk.slots[sib || "exchange"]).mid / GRID;
}

export function svg(sk, size, sib, { ink = INK, ground = GROUND } = {}) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
         `<rect x="0" y="0" width="${GRID}" height="${GRID}" fill="${ground}"></rect>` +
         sk.draw(sib === undefined ? null : sib).replace(/INK/g, ink) +
         `</svg>`;
}
