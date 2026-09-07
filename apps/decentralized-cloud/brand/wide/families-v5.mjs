// WIDE GENERATION, ROUND FIVE — the BREACH, which is what the reader was looking at.
//
// Rounds three and four were built on the reader's WORDS and both failed. Reader L,
// on the only cells any reader has ever granted:
//
//   "46, 47, and 50 all have a square whose stroke breaks and doubles back on itself
//    so the outline appears to pass through its own corner — an interlock, not a gap."
//
// I read "interlock" and spent two rounds building interlocks: two arms crossing
// (round three, which severed instead of crossing), then one stroke running past a
// full circuit (round four, which retraces rather than crosses and produced 261
// duplicates of a plain rectangle). Neither went to a reader, because both were
// visibly wrong the moment I opened the sheet.
//
// Then I looked up what 46/47/50 actually WERE. They are `L-nest-*`: an outer quad
// with an inner quad knocked out of it, offset so far that the inner shape BREAKS
// THROUGH the outer edge. The closed frame is opened, and the ink that remains wraps
// around and doubles back — which is precisely the perception the reader reported.
//
// The reader described what they SAW. I treated the description as the construction,
// and they are not the same thing: "an interlock, not a gap" is a report about the
// percept, and the geometry that produced it is an off-centre knockout that breaches
// its own boundary. Two rounds spent on that mistake, and it is the same error this
// programme keeps paying for in a new costume — taking an account of a thing for the
// thing. The evidence for what a reader responded to is the ARTIFACT they were shown,
// and it was on disk the entire time.
//
// So this round sweeps the breach itself:
//   breach   how far the inner form pushes past the outer edge. 0 is a closed frame —
//            the control, and the whole question: does the reader's response survive
//            when the boundary is intact?
//   edge     which side is breached. The percept was "passes through its own corner",
//            so a corner breach is generated as well as an edge one.
//   ratio    the inner form's size, which sets how much ink is left to read as stroke.
//   tilt     0 and 9 degrees. Both round-two readers called the cant a liability, and
//            reader L then granted three tilted cells while saying they "survive
//            because they have a structural event beyond the tilt". That is a
//            hypothesis, not a finding, so this round puts the same breach on a level
//            base beside a canted one and lets a reader settle it.

export const GRID = 96;
export const INK = "#0d0f12";
export const INK2 = "#8f98a3";
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;
const pts = (ps) => ps.map(([x, y]) => `${R2(x)},${R2(y)}`).join(" ");

const rot = (ps, deg, cx = 48, cy = 48) => {
  const t = (deg * Math.PI) / 180, c = Math.cos(t), s = Math.sin(t);
  return ps.map(([x, y]) => [cx + (x - cx) * c - (y - cy) * s, cy + (x - cx) * s + (y - cy) * c]);
};

const quad = (cx, cy, w, h) => [
  [cx - w / 2, cy - h / 2], [cx + w / 2, cy - h / 2],
  [cx + w / 2, cy + h / 2], [cx - w / 2, cy + h / 2],
];

const EDGES = {
  top: [0, -1], right: [1, 0], bottom: [0, 1], left: [-1, 0],
  "corner-tr": [0.72, -0.72], "corner-bl": [-0.72, 0.72],
};

function breachMark({ id, ow, oh, ratio, edge, breach, tilt, tone }) {
  const [dx, dy] = EDGES[edge];
  const iw = ow * ratio, ih = oh * ratio;
  // The inner form is pushed along the edge normal until it clears the boundary by
  // `breach`. At breach 0 its far side sits exactly ON the boundary, so the frame is
  // still closed and the control is a genuine control rather than a different drawing.
  const push = [
    dx * ((ow - iw) / 2 + breach),
    dy * ((oh - ih) / 2 + breach),
  ];
  const outer = rot(quad(48, 48, ow, oh), tilt);
  const inner = rot(quad(48 + push[0], 48 + push[1], iw, ih), tilt);
  if (tone) {
    return `<polygon points="${pts(outer)}" fill="INK"></polygon>` +
      `<polygon points="${pts(inner)}" fill="INK2"></polygon>`;
  }
  const mid = `m5-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    `<polygon points="${pts(outer)}" fill="white"></polygon>` +
    `<polygon points="${pts(inner)}" fill="black"></polygon>` +
    `</mask></defs>` +
    `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>`
  );
}

const CANDS = [];
const BASES = [
  { k: "square", ow: 74, oh: 74 },
  { k: "wide", ow: 82, oh: 58 },
  { k: "tall", ow: 58, oh: 82 },
];
for (const B of BASES) {
  for (const ratio of [0.5, 0.62, 0.74]) {
    for (const edge of ["top", "right", "corner-tr", "corner-bl"]) {
      for (const breach of [0, 7, 15, 24]) {
        for (const tilt of [0, 9]) {
          const id = `B-${B.k}-r${String(ratio).replace(".", "")}-${edge}-b${breach}-t${tilt}`;
          const markup = breachMark({ id, ow: B.ow, oh: B.oh, ratio, edge, breach, tilt });
          CANDS.push({
            id,
            family: breach === 0 ? "B closed frame (control)" : "B the breach",
            thesis: breach === 0
              ? `a ${B.k} frame with the counter meeting the boundary but not crossing it — the control that says whether the breach is what the reader answered to`
              : `a ${B.k} frame whose counter breaks ${breach} units through its ${edge}, so the ink that remains wraps and doubles back`,
            draw: () => markup,
          });
        }
      }
    }
  }
}
// Two-tone siblings: the inner form present as a second tone rather than as a void.
// Printed in one ink these collapse into a plain filled quad — a large cost, measured
// and printed, not waved through.
for (const B of BASES) {
  for (const edge of ["top", "corner-tr"]) {
    for (const breach of [15, 24]) {
      const id = `B-tone-${B.k}-${edge}-b${breach}`;
      const markup = breachMark({ id, ow: B.ow, oh: B.oh, ratio: 0.62, edge, breach, tilt: 0, tone: true });
      CANDS.push({
        id, family: "B breach, two-tone",
        thesis: "the same breach with the inner form carried by tone instead of by a void",
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
    id: "ghost-pierced-square",
    draw: () =>
      `<defs><mask id="m5-gp" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<polygon points="12,20 86,12 90,84 8,84" fill="white"></polygon>` +
      `<circle cx="40" cy="40" r="16" fill="black"></circle></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m5-gp)"></rect>`,
  },
];

export const svgFor = (markup, size, twoTone) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK2/g, twoTone ? INK2 : INK).replace(/\bINK\b/g, INK) +
  `</svg>`;
