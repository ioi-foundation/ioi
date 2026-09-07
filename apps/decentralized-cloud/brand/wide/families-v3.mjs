// WIDE GENERATION, ROUND THREE — the interlock, sampled properly.
//
// Six rounds across two phases produced exactly one thing a cold reader granted, and
// round two produced it. Reader L, unprompted, on cells 46/47/50:
//
//   "46, 47, and 50 all have a square whose stroke breaks and doubles back on itself
//    so the outline appears to pass through its own corner — an interlock, not a gap.
//    That self-crossing is the one thing here I did not have a ready name for, and it
//    is the one thing that would make me look twice."
//
// That is a mechanism, not a preference, and it is the first one this program has
// been handed. "The one thing I did not have a ready name for" is the entire bar
// stated from the other side: every previous failure was a shape the reader COULD
// name — a letter, a digit, a spinner, a tag, a moon, a lump.
//
// It is one reader out of two. Reader K read the same cells as "square" and
// "bracket". So this round is not a coronation of the interlock; it is the round that
// finds out whether the interlock survives a second reader when it is drawn properly
// instead of incidentally. Three of 58 was a lucky corner of one family's parameter
// space, and the drawing was never designed for it.
//
// WHAT ROUND TWO ALSO SETTLED, and what is therefore banned here:
//   - TILT IS NOT CONTENT. Reader L: "a few degrees of rotation reads to me as 'this
//     image is broken / badly aligned', not as a deliberate mark." I have leaned on
//     the cant since round one on the strength of one line in the closed phase's
//     handoff. Nothing here is tilted for its own sake; where a form leans it is
//     because the interlock requires it.
//   - NO BROKEN RINGS. Both readers: loading spinner.
//   - NO THIN CRESCENTS. Both readers: two or three pixels wide, reads as an artifact.
//   - NO COUNTER-IN-A-MASS. Twelve cells, one sentence, in both readers' groupings.
//
// The whole round is one idea with its parameters swept, which is what round two's
// readers said the previous rounds were pretending not to be: "the space is one shape
// wide". This time that is deliberate and declared.

export const GRID = 96;
export const INK = "#0d0f12";
export const INK2 = "#8f98a3";
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;
const pts = (ps) => ps.map(([x, y]) => `${R2(x)},${R2(y)}`).join(" ");
const polygon = (ps, fill = "INK") => `<polygon points="${pts(ps)}" fill="${fill}"></polygon>`;

// An arm is a stroked polyline with ONE corner: it arrives along one heading, turns,
// and leaves along another. Drawing it as a stroke rather than as a hand-built
// polygon is what lets the corner be any angle — ioi-c0's ruling after round two was
// that the sheet must not be one shape wide, and a hard-coded right angle is one
// shape however many other numbers move.
//
//   at       where the corner sits. Moving it off the middle of the pair is the
//            "crossing placed off-corner" axis.
//   turn     the angle the arm turns through. 90 is a bracket; 60 and 120 are not,
//            and neither has a ready name.
//   inLen/outLen  the two limbs, deliberately unequal — a symmetric arm is the
//            vocabulary system icons are drawn in, which round one established and
//            round two confirmed.
function armPath(at, heading, turn, inLen, outLen, w) {
  const rad = (d) => (d * Math.PI) / 180;
  const p0 = [at[0] - Math.cos(rad(heading)) * inLen, at[1] - Math.sin(rad(heading)) * inLen];
  const p1 = [at[0] + Math.cos(rad(heading + turn)) * outLen, at[1] + Math.sin(rad(heading + turn)) * outLen];
  return `<path d="M ${R2(p0[0])} ${R2(p0[1])} L ${R2(at[0])} ${R2(at[1])} L ${R2(p1[0])} ${R2(p1[1])}" ` +
    `fill="none" stroke="INK" stroke-width="${w}" stroke-linecap="butt" stroke-linejoin="miter"></path>`;
}

// Two arms whose limbs pass through each other. `cross` is where the cut goes — the
// point at which one arm reads as being in front — and it is a POINT ON A LIMB, not
// the corner, so the over/under can sit anywhere along the crossing.
function interlock({ id, w, turn, inA, outA, inB, outB, cornerA, cornerB, headA, headB, cut }) {
  const a = armPath(cornerA, headA, turn, inA, outA, w);
  const b = armPath(cornerB, headB, -turn, inB, outB, w);
  if (!cut) return b + a;
  // THE CUT APPLIES TO THE BACK ARM ONLY, and then the front arm is drawn over the
  // result. The first version of this masked the WHOLE body, so the hole bit through
  // both arms and left floating squares — not an over/under but a shape with a chunk
  // missing. Every number passed; the sheet was plainly broken the moment I opened
  // it. An over/under is asymmetric by definition, so a symmetric operation could
  // never have produced one.
  const mx = (cornerA[0] + cornerB[0]) / 2, my = (cornerA[1] + cornerB[1]) / 2;
  const g = w / 2 + cut;
  const hole = polygon([[mx - g, my - g], [mx + g, my - g], [mx + g, my + g], [mx - g, my + g]], "black");
  const mid = `m3-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    b.replace(/stroke="INK2?"/g, 'stroke="white"') + hole +
    `</mask></defs>` +
    `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>` +
    a
  );
}

const CANDS = [];
// The axes, and why each is here rather than because it was easy to vary:
//   turn    60 / 90 / 120 — 90 is the bracket both readers could name. The other two
//           are the whole point of dropping the hard-coded right angle.
//   limbs   four unequal pairs. A symmetric arm is system-icon vocabulary.
//   offset  how far apart the two corners sit, which moves the crossing off-corner.
//   cut     0 (fused, the control) / 5 / 9.
// NOTHING here is tilted for its own sake. Both round-two readers called the cant a
// liability — "reads as 'this image is broken', not as a deliberate mark" — so the
// only angles in this round are the ones the crossing itself needs.
const LIMBS = [
  { k: "long-short", inA: 40, outA: 22, inB: 38, outB: 20 },
  { k: "short-long", inA: 20, outA: 40, inB: 22, outB: 38 },
  { k: "uneven", inA: 42, outA: 18, inB: 20, outB: 40 },
  { k: "even", inA: 32, outA: 32, inB: 32, outB: 32 },
];
for (const turn of [60, 90, 120]) {
  for (const L of LIMBS) {
    for (const offset of [0, 12, 22]) {
      for (const cut of [0, 5, 9]) {
        const id = `X-t${turn}-${L.k}-o${offset}-c${cut}`;
        const markup = interlock({
          id, w: 19, turn,
          inA: L.inA, outA: L.outA, inB: L.inB, outB: L.outB,
          cornerA: [48 - offset / 2, 48 - offset / 2],
          cornerB: [48 + offset / 2, 48 + offset / 2],
          headA: 0, headB: 180, cut,
        });
        CANDS.push({
          id,
          family: cut ? `X interlock, crossing cut` : `X interlock, fused (control)`,
          thesis: cut
            ? `two arms turning ${turn} degrees with unequal limbs, one passing in front by a ${cut}-unit cut`
            : `the same pair with no over/under — the control that says whether the cut is what does the work`,
          draw: () => markup,
        });
      }
    }
  }
}

// Stroke weight, swept separately rather than crossed with everything above: at 16px
// one device pixel is six grid units, so weight decides whether the crossing has room
// to happen at all, and crossing it with four other axes would just spend the sheet.
for (const w of [14, 24, 30]) {
  for (const turn of [60, 90, 120]) {
    const id = `X-w${w}-t${turn}`;
    const markup = interlock({
      id, w, turn, inA: 40, outA: 22, inB: 38, outB: 20,
      cornerA: [42, 42], cornerB: [54, 54], headA: 0, headB: 180, cut: 6,
    });
    CANDS.push({
      id, family: "X interlock, weight swept",
      thesis: `the crossing at stroke weight ${w} — ${(w / 6).toFixed(1)} device pixels at product size`,
      draw: () => markup,
    });
  }
}

// The two-tone siblings: the over/under carried by TONE rather than by a cut. Colour
// is a cost, not a disqualifier, and the cost is measured — printed in one ink these
// collapse into the fused control above, which is sitting on the same sheet.
for (const turn of [60, 90, 120]) {
  for (const L of LIMBS.slice(0, 3)) {
    const id = `X-tone-t${turn}-${L.k}`;
    const a = armPath([42, 42], 0, turn, L.inA, L.outA, 19);
    const b = armPath([54, 54], 180, -turn, L.inB, L.outB, 19).replace('stroke="INK"', 'stroke="INK2"');
    CANDS.push({
      id, family: "X interlock, two-tone",
      thesis: "the same crossing with the over/under carried by tone instead of a cut",
      draw: () => b + a,
    });
  }
}

export const CANDIDATES = CANDS;

// Ghosts: every shape a reader has NAMED across both phases. These are dead by human
// answer rather than by a number, and carrying them means this round cannot spend a
// reader on something already killed.
export const GHOSTS = [
  { id: "ghost-wedge", draw: () => `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>` },
  { id: "ghost-disc", draw: () => `<circle cx="48" cy="48" r="42" fill="INK"></circle>` },
  {
    id: "ghost-pierced-square",
    draw: () =>
      `<defs><mask id="m3-gp" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<polygon points="12,20 86,12 90,84 8,84" fill="white"></polygon>` +
      `<circle cx="40" cy="40" r="16" fill="black"></circle></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m3-gp)"></rect>`,
  },
  {
    id: "ghost-broken-ring",
    draw: () =>
      `<path d="M 78 30 A 34 34 0 1 1 60 18" fill="none" stroke="INK" stroke-width="18"></path>`,
  },
  {
    id: "ghost-square-outline",
    draw: () =>
      `<defs><mask id="m3-gs" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<rect x="12" y="12" width="72" height="72" fill="white"></rect>` +
      `<rect x="30" y="30" width="36" height="36" fill="black"></rect></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m3-gs)"></rect>`,
  },
];

export const svgFor = (markup, size, twoTone) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK2/g, twoTone ? INK2 : INK).replace(/\bINK\b/g, INK) +
  `</svg>`;
