// WIDE GENERATION, ROUND FOUR — the interlock, built the way the reader described it.
//
// Round three tried to make the self-crossing out of TWO ARMS placed near each other,
// and the sheet showed why that was wrong even after its masking bug was fixed: two
// arms only cross if you position them so their limbs overlap, and nothing in the
// construction guaranteed that. Half the sheet severed instead of crossing. I did not
// spend readers on it.
//
// Re-reading what the reader actually said settles the construction:
//
//   "a square whose stroke breaks and doubles back on itself so the outline appears
//    to pass through its own corner — an interlock, not a gap"
//
// That is not two arms. It is ONE stroke, travelling around a rectangle for slightly
// MORE than one full circuit, so that its end runs back over its own beginning. The
// overlap is guaranteed by construction rather than by placement, which is exactly
// what round three lacked: you cannot fail to cross a path you are already on.
//
// The over/under is then cut where the two passes coincide — and it is cut by
// stroking the FRONT segment at a slightly greater width into the mask, so the gap
// follows the crossing wherever it happens to fall. Round three placed that hole at a
// guessed midpoint, which is how it landed in empty space and severed limb ends.
//
// AXES, each answering something a reader said rather than something easy to vary:
//   circuit   how far past one full lap the stroke runs. This IS the idea; below ~1.0
//             there is no crossing at all, and the low end is generated as the control
//             that proves the crossing is what a reader is responding to.
//   base      square, wide and tall. ioi-c0's ruling after round two: non-square bases,
//             so the sheet is not one shape wide.
//   w         stroke weight. One device pixel is six grid units at product size, so
//             this decides whether the crossing has room to happen at all.
//   start     which side the stroke begins on, which moves the crossing to a different
//             corner without tilting anything.
//   gap       how much clearance the front pass takes out of the back one.
//
// NOTHING IS TILTED. Both round-two readers called the cant a liability — "reads as
// 'this image is broken', not as a deliberate mark" — and it is gone from every
// family here.

export const GRID = 96;
export const INK = "#0d0f12";
export const INK2 = "#8f98a3";
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;

// A point at distance t along the perimeter of a rectangle, walking clockwise from
// the top-left corner. Everything below is expressed in perimeter distance, so a
// "circuit" is a number the construction can honour exactly rather than approximate.
function ring(x0, y0, w, h) {
  const segs = [
    { from: [x0, y0], to: [x0 + w, y0] },
    { from: [x0 + w, y0], to: [x0 + w, y0 + h] },
    { from: [x0 + w, y0 + h], to: [x0, y0 + h] },
    { from: [x0, y0 + h], to: [x0, y0] },
  ];
  const lens = segs.map((s) => Math.hypot(s.to[0] - s.from[0], s.to[1] - s.from[1]));
  const perim = lens.reduce((a, b) => a + b, 0);
  const at = (t) => {
    let u = ((t % perim) + perim) % perim;
    for (let i = 0; i < segs.length; i++) {
      if (u <= lens[i]) {
        const f = u / lens[i];
        return [
          segs[i].from[0] + (segs[i].to[0] - segs[i].from[0]) * f,
          segs[i].from[1] + (segs[i].to[1] - segs[i].from[1]) * f,
        ];
      }
      u -= lens[i];
    }
    return segs[0].from;
  };
  // The polyline between two perimeter distances, including every corner it passes
  // through. Sampling instead would round the corners off, and the corner is where
  // the whole event happens.
  const corners = [0, lens[0], lens[0] + lens[1], lens[0] + lens[1] + lens[2]];
  const between = (ta, tb) => {
    const out = [at(ta)];
    for (let k = 0; k * perim < tb + perim; k++) {
      for (const c of corners) {
        const t = c + k * perim;
        if (t > ta && t < tb) out.push(at(t));
      }
    }
    out.push(at(tb));
    return out;
  };
  return { perim, at, between };
}

const poly = (ps, w, stroke = "INK") =>
  `<path d="${ps.map(([x, y], i) => `${i ? "L" : "M"} ${R2(x)} ${R2(y)}`).join(" ")}" ` +
  `fill="none" stroke="${stroke}" stroke-width="${w}" stroke-linecap="butt" stroke-linejoin="miter"></path>`;

// ── The overshoot ───────────────────────────────────────────────────────────
// The spiral below was the first attempt and it FAILED, visibly, for a reason worth
// keeping written down: a stroke that travels more than one circuit of a ring
// RETRACES its own start, it does not cross it. All 198 cells rendered as a plain
// rectangular outline and 192 collapsed as duplicates of each other, which is the
// dedupe correctly reporting that a sweep had produced one drawing.
//
// "Passes through its own corner" is an OVERSHOOT. Build the rectangle as four bars
// and let one or two of them run PAST the corner they should have stopped at: where
// the overshooting bar crosses the one it should have met, there is a real crossing,
// guaranteed by construction, with a tail sticking out the far side. That is the
// shape the reader described, and unlike the spiral it cannot fail to cross.
function overshoot({ id, bw, bh, w, over, sides, gap, tone }) {
  const x0 = (GRID - bw) / 2, y0 = (GRID - bh) / 2, x1 = x0 + bw, y1 = y0 + bh;
  const h = w / 2;
  // Four bars, each drawn corner to corner. `over` extends a bar past its end corner.
  // The bars that overshoot are the ones named in `sides`, so the asymmetry is chosen
  // rather than incidental — a symmetric overshoot on all four is a hash mark, which
  // is a shape every reader has a ready name for.
  const bar = (a, b, ext) => {
    const dx = Math.sign(b[0] - a[0]), dy = Math.sign(b[1] - a[1]);
    return [[a[0], a[1]], [b[0] + dx * ext, b[1] + dy * ext]];
  };
  const defs = [
    { k: "top", a: [x0 - h, y0], b: [x1 + h, y0] },
    { k: "right", a: [x1, y0 - h], b: [x1, y1 + h] },
    { k: "bottom", a: [x1 + h, y1], b: [x0 - h, y1] },
    { k: "left", a: [x0, y1 + h], b: [x0, y0 - h] },
  ];
  const front = [], back = [];
  for (const d of defs) {
    const ext = sides.includes(d.k) ? over : 0;
    (ext ? front : back).push(bar(d.a, d.b, ext));
  }
  const draw = (ps, stroke, width) => poly(ps, width, stroke);
  const backMarkup = back.map((p) => draw(p, "INK", w)).join("");
  const frontMarkup = front.map((p) => draw(p, tone ? "INK2" : "INK", w)).join("");
  if (!front.length) return backMarkup;
  if (tone) return backMarkup + frontMarkup;
  const mid = `m4o-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    back.map((p) => draw(p, "white", w)).join("") +
    // The clearance follows the overshooting bars themselves, so the gap lands exactly
    // where the crossing is rather than at a point I guessed.
    front.map((p) => draw(p, "black", w + gap * 2)).join("") +
    `</mask></defs>` +
    `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>` +
    front.map((p) => draw(p, "INK", w)).join("")
  );
}

function spiral({ id, bw, bh, w, circuit, startFrac, gap, tone }) {
  const x0 = (GRID - bw) / 2, y0 = (GRID - bh) / 2;
  const r = ring(x0, y0, bw, bh);
  const t0 = r.perim * startFrac;
  const t1 = t0 + r.perim * circuit;
  // The front pass is the tail that has come back around onto the start. Its length is
  // exactly the overlap, so when circuit is 1.0 there is no front pass and no crossing.
  const overlap = Math.max(0, r.perim * (circuit - 1));
  if (overlap < w) {
    // No crossing: the control. Drawn as one plain stroke, and labelled as the control
    // rather than quietly dropped, because a round that only contains its hypothesis
    // cannot tell you the hypothesis is what a reader is answering.
    return poly(r.between(t0, t1), w);
  }
  const back = r.between(t0, t1 - overlap);
  const front = r.between(t1 - overlap, t1);
  if (tone) return poly(back, w) + poly(front, w, "INK2");
  const mid = `m4-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    poly(back, w, "white") +
    // The clearance is the FRONT pass stroked wider, in black, so the gap follows the
    // crossing exactly wherever it falls instead of being placed at a guessed point.
    poly(front, w + gap * 2, "black") +
    `</mask></defs>` +
    `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>` +
    poly(front, w)
  );
}

const CANDS = [];
const BASES = [
  { k: "square", bw: 62, bh: 62 },
  { k: "wide", bw: 74, bh: 48 },
  { k: "tall", bw: 48, bh: 74 },
];
// Which bars overshoot. One is the most asymmetric and the least nameable; two
// opposite is a pinwheel; two adjacent puts both crossings at one end. All four is
// deliberately absent: that is a hash mark, and every reader has a ready name for it.
const SIDE_SETS = [
  { k: "one", sides: ["top"] },
  { k: "one-r", sides: ["right"] },
  { k: "opp", sides: ["top", "bottom"] },
  { k: "adj", sides: ["top", "right"] },
];
for (const B of BASES) {
  for (const w of [13, 17, 22]) {
    for (const S of SIDE_SETS) {
      for (const over of [0, 9, 15, 22]) {
        for (const gap of [4, 7]) {
          if (over === 0 && gap !== 4) continue;   // the control has no gap to vary
          const id = `O-${B.k}-w${w}-${S.k}-o${over}-g${gap}`;
          const markup = overshoot({ id, bw: B.bw, bh: B.bh, w, over, sides: over ? S.sides : [], gap });
          CANDS.push({
            id,
            family: over === 0 ? "O closed frame, no crossing (control)" : "O the overshoot",
            thesis: over === 0
              ? `a ${B.k} frame with nothing overshooting — the control that says whether the crossing is what a reader answers to`
              : `a ${B.k} frame with ${S.sides.length} bar(s) running ${over} units past the corner, crossing what they should have met`,
            draw: () => markup,
          });
        }
      }
    }
  }
}
// Two-tone siblings: the over/under carried by the second tone instead of a cut. The
// one-ink cost is real — printed in one ink these collapse toward the closed frame,
// which is the control sitting on the same sheet — and the harness measures it.
for (const B of BASES) {
  for (const S of SIDE_SETS.slice(0, 3)) {
    for (const over of [15, 22]) {
      const id = `O-tone-${B.k}-${S.k}-o${over}`;
      const markup = overshoot({ id, bw: B.bw, bh: B.bh, w: 17, over, sides: S.sides, gap: 6, tone: true });
      CANDS.push({
        id, family: "O overshoot, two-tone",
        thesis: "the same crossing with the over/under carried by tone instead of a cut",
        draw: () => markup,
      });
    }
  }
}

export const CANDIDATES = CANDS;

// Every shape a reader has NAMED across both phases, carried so this round cannot
// spend a reader on something already dead.
export const GHOSTS = [
  { id: "ghost-wedge", draw: () => `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>` },
  { id: "ghost-disc", draw: () => `<circle cx="48" cy="48" r="42" fill="INK"></circle>` },
  {
    id: "ghost-broken-ring",
    draw: () => `<path d="M 78 30 A 34 34 0 1 1 60 18" fill="none" stroke="INK" stroke-width="18"></path>`,
  },
  {
    id: "ghost-square-outline",
    draw: () =>
      `<defs><mask id="m4-gs" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<rect x="12" y="12" width="72" height="72" fill="white"></rect>` +
      `<rect x="30" y="30" width="36" height="36" fill="black"></rect></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m4-gs)"></rect>`,
  },
];

export const svgFor = (markup, size, twoTone) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK2/g, twoTone ? INK2 : INK).replace(/\bINK\b/g, INK) +
  `</svg>`;
