// Round four — the last, by ioi-e1's cap.
//
// WHAT THREE ROUNDS ESTABLISHED, in the order they were learned:
//
//   R1  Few, large, regular, centred, symmetric elements is the vocabulary SYSTEM
//       ICONS are drawn in. Four skeletons drawn that way landed on four different
//       existing buttons — the share glyph, the align-left button, the apps grid —
//       named by two readers independently with confidence "certain".
//   R2  Banning that vocabulary was right and insufficient: "a mass with one small
//       interior subtraction" is a formula, not a principle, and both readers said
//       unprompted that four of six were the same drawing. THE PRINCIPLE: at 16px an
//       interior event is one to three device pixels, so the identity cannot live
//       there. It lives in the OUTLINE.
//   R3  Silhouette-led, judged as solid shapes with every counter closed. All five
//       failed. The probe killed the two-round incumbent on its own terms — closing
//       its counter left a shape 93.1% identical to a mark that never had one — and
//       a candidate whose hazards named the power symbol was named the power symbol.
//
// WHAT THE READERS ACTUALLY REWARDED, across all three rounds, is narrower than any
// of that: a COUNTER IN A MASS scored highest twice, and what failed both times was
// the CONTAINER — "megaphone", "speaker cone", "pennant", "flag", "lens cap". Nobody
// disliked the hole. They disliked the shape around it.
//
// So round four keeps the device the readers kept choosing and replaces the thing
// they kept rejecting. Every container here is built to be nameable as nothing:
//   - no orthogonal-only construction, and no edge at 0, 45 or 90 degrees where it
//     can be avoided — system glyphs live on those angles because that is what
//     survives being redrawn by a hundred hands;
//   - at least TWO edge events of DIFFERENT KINDS, since a single event is what made
//     round two a monoculture and a lone notch is what every ticket and tag icon has;
//   - and the silhouette is checked against ROUND THREE'S shapes as well as against
//     its own siblings, so this round cannot quietly re-draw something already dead.

import { SIBLINGS } from "./skeletons.mjs";
export { GRID, INK, GROUND, SIBLINGS, svg } from "./skeletons.mjs";
const GRID = 96;
const NEUTRAL = "exchange";

// ── M · the caret slab ──────────────────────────────────────────────────────
// Two edge events of different kinds on one body: a V bitten into the right edge,
// and a square tab protruding from the top left. A notch alone is a ticket; a tab
// alone is a folder; the pair is neither, and both survive as outline.
const M = () => {
  const TOP = 22, BOT = 84, L = 6, R = 90;
  const NOTCH = 26;                       // how deep the V cuts in from the right
  const TABW = 20, TABH = 12;
  const notches = { cloud: 40, exchange: 53, trade: 66 };   // the V's apex height
  const shape = (apexY, tab) =>
    `${L},${TOP + 8} ${L + TABW},${TOP + 8} ${L + TABW},${TOP} ${L + TABW + TABW},${TOP} ` +
    `${R},${TOP + 4} ${R - NOTCH},${apexY} ${R},${BOT} ${L},${BOT}` +
    (tab ? "" : "");
  return {
    id: "caret-slab", name: "The caret slab",
    origin: "mine, round four",
    thesis: "one body carrying two different kinds of edge event — a bite and a tab",
    hook: "the square tab on the top-left shoulder, which nothing else in the set has, sitting opposite a V bitten into the far edge",
    hazards: [
      "A V bitten into a right edge is the BOOKMARK / ribbon end, and a tab on a top edge is the FOLDER. Two clichés on one body may read as two clichés rather than as one shape — that is this round's central bet and a reader settles it, not me.",
      "The tab is 20x12 grid units: 3.3 x 2.0 device pixels at 16px. A hook that small is a hook antialiasing owns, and this one is on a corner where it has the least support.",
      "It is still a quadrilateral mass, which is what round three's failures were.",
    ],
    separation: { axis: "x", at: 0.5, runs: 1, of: "the mass, one piece by construction" },
    separationOn: null,
    // NO CLAIM. `topRise` compares the ends of the rendered top-ink profile, each
    // averaged over the outer eighth of the shape's columns. That equals a geometric
    // rise ONLY when the top edge is a single straight line across the full width.
    // Here it is not, so a declared number and the measurement answer different
    // questions and the disagreement is meaningless rather than informative — which
    // is what it reported. The profile is still printed, as information.
    topRise: null,
    // What differs between siblings is the triangle the V removes; its centroid is
    // the mean of the three vertices, per the closed-form rule this phase learned
    // the hard way three times.
    cueCentres: Object.fromEntries(SIBLINGS.map((k) =>
      [k, [(R + R + (R - NOTCH)) / 3, (TOP + 4 + BOT + notches[k]) / 3]])),
    neutral: NEUTRAL,
    draw: (sib) => `<polygon points="${shape(notches[sib === null ? NEUTRAL : sib], true)}" fill="INK"></polygon>`,
    baseDraw: () => `<polygon points="${L},${TOP + 8} ${L + TABW},${TOP + 8} ${L + TABW},${TOP} ${L + TABW + TABW},${TOP} ${R},${TOP + 4} ${R},${BOT} ${L},${BOT}" fill="INK"></polygon>`,
    silhouetteDraw: () => `<polygon points="${shape(notches[NEUTRAL], true)}" fill="INK"></polygon>`,
  };
};

// ── N · the crescent block ──────────────────────────────────────────────────
// A curved event on a straight body: a large disc bitten out of one long edge, big
// enough that what remains is a thick crescent standing on a flat base. A straight
// mass and a circular void are different KINDS of geometry, and the combination is
// what makes it hard to name — a rectangle is a rectangle and a circle is a circle,
// but a rectangle a circle has taken a large bite out of is neither.
const N = () => {
  const X0 = 6, X1 = 90, Y0 = 16, Y1 = 86, RAD = 30;
  const centres = { cloud: 34, exchange: 48, trade: 62 };
  return {
    id: "crescent-block", name: "The crescent block",
    origin: "mine, round four",
    thesis: "a straight mass and a circular void — two kinds of geometry, so it is neither of them",
    hook: "the size of the bite: it takes nearly half the body, so the mark reads as what is LEFT rather than as a rectangle with a dent",
    hazards: [
      "A large circular bite out of a rectangle is close to the 'eject a card' and 'battery' families, and the crescent that remains is a MOON, which is the stock dark-mode toggle.",
      "It is a rectangle underneath, and a rectangle is the outline round three proved is nobody's.",
      "The bite is r30 — 10 device pixels at 16px, the largest event in any round here. That is its best property and also why it may simply read as a hole rather than as a shape.",
    ],
    separation: { axis: "x", at: (Y0 + 6) / GRID, runs: 1, of: "the body above the bite, which the bite does not reach" },
    separationOn: NEUTRAL,
    topRise: 0,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [centres[k], Y1]])),
    neutral: NEUTRAL,
    draw: (sib) => {
      const cx = centres[sib === null ? NEUTRAL : sib];
      const id = `cb-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
             `<rect x="${X0}" y="${Y0}" width="${X1 - X0}" height="${Y1 - Y0}" rx="5" fill="white"></rect>` +
             `<circle cx="${cx}" cy="${Y1}" r="${RAD}" fill="black"></circle></mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
    baseDraw: () => `<rect x="${X0}" y="${Y0}" width="${X1 - X0}" height="${Y1 - Y0}" rx="5" fill="INK"></rect>`,
    silhouetteDraw: () => {
      const id = "cb-sil";
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
             `<rect x="${X0}" y="${Y0}" width="${X1 - X0}" height="${Y1 - Y0}" rx="5" fill="white"></rect>` +
             `<circle cx="${centres[NEUTRAL]}" cy="${Y1}" r="${RAD}" fill="black"></circle></mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

// ── O · the counter in a canted quad ────────────────────────────────────────
// The device the readers kept choosing — a counter in a mass — with the container
// they kept rejecting replaced. No two edges parallel, no edge on 0, 45 or 90
// degrees, and one side bowed so the outline is not all-straight either.
const O = () => {
  // THE TILT NEEDED AN ANCHOR. This mark was the only one in four rounds that both
  // readers passed on its own, and both then failed it in lockup for the same reason:
  // "everything else on the line is dead horizontal, so the mark looks knocked askew,
  // like a misaligned asset rather than a decision." A cant with nothing level in it
  // is indistinguishable from a mistake.
  //
  // So the container stays canted — that is the fingerprint, and it is the thing that
  // survives downscaling where a notch does not — and the mark is given ONE TRUE
  // HORIZONTAL for the eye to sit on: the bottom edge runs flat, level with the
  // type's baseline. Everything above it leans. A shape that is level where it meets
  // the line and canted everywhere else reads as drawn that way on purpose.
  const BASE_Y = 88;
  const P = [[10, 30], [72, 8], [90, 62], [26, BASE_Y]];
  const slots = { cloud: [40, 40], exchange: [52, 50], trade: [46, 64] };
  const CR = 14;
  const body = `M ${P[0][0]} ${P[0][1]} L ${P[1][0]} ${P[1][1]} L ${P[2][0]} ${P[2][1]} ` +
               `Q ${P[2][0] - 8} ${BASE_Y} ${72} ${BASE_Y} ` +   // curve down to the flat
               `L ${P[3][0]} ${BASE_Y} Z`;                        // the one true horizontal
  return {
    id: "canted-counter", name: "The counter in a canted quad",
    origin: "mine, round four — the device three rounds of readers kept choosing, in a container they have not rejected",
    thesis: "a counter in a mass, where the mass is nameable as nothing: no parallel edges, no cardinal angles, one bowed side",
    hook: "the counter sitting off-centre in a body that leans, with one side bowed and three straight — you cannot describe the container in one word, which is the point",
    hazards: [
      "'A shape with a hole in it' is what reader two said they would carry away from the round-two winner, and this is still a shape with a hole in it. If the container is merely unfamiliar rather than memorable, this fails exactly as that did.",
      "A canted quadrilateral with a counter is close to a camera APERTURE and to the 'tag' family, and a leaning body reads as italic — a slant nobody chose.",
      "The counter is r14 — 4.7 device pixels at 16px. That is the largest a counter has been in this phase and it is still small.",
    ],
    separation: { axis: "x", at: 0.5, runs: 2, of: "ink either side of the counter" },
    separationOn: NEUTRAL,
    // NO CLAIM. `topRise` compares the ends of the rendered top-ink profile, each
    // averaged over the outer eighth of the shape's columns. That equals a geometric
    // rise ONLY when the top edge is a single straight line across the full width.
    // Here it is not, so a declared number and the measurement answer different
    // questions and the disagreement is meaningless rather than informative — which
    // is what it reported. The profile is still printed, as information.
    topRise: null,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, slots[k]])),
    neutral: NEUTRAL,
    draw: (sib) => {
      const s = slots[sib === null ? NEUTRAL : sib];
      const id = `cc-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
             `<path d="${body}" fill="white"></path>` +
             `<circle cx="${s[0]}" cy="${s[1]}" r="${CR}" fill="black"></circle></mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
    baseDraw: () => `<path d="${body}" fill="INK"></path>`,
    silhouetteDraw: () => `<path d="${body}" fill="INK"></path>`,
  };
};

// ── P · the offset arch ─────────────────────────────────────────────────────
// A silhouette whose top edge is half a curve and half a square shoulder — the two
// halves of the outline are drawn by different rules, which is a thing almost no
// system glyph does, because a glyph has to be redrawable from a description.
const P = () => {
  const L = 12, R = 86, BASE = 84, SHOULDER = 44, PEAK = 12;
  const feet = { cloud: 30, exchange: 44, trade: 58 };    // where the base notch sits
  const NW = 16, NH = 18;
  const shape = (fx) =>
    `M ${L} ${BASE} L ${L} ${SHOULDER} ` +
    `Q ${L} ${PEAK} ${(L + R) / 2} ${PEAK} ` +      // curved half
    `L ${R} ${PEAK} L ${R} ${BASE} ` +               // square half
    `L ${fx + NW} ${BASE} L ${fx + NW} ${BASE - NH} L ${fx} ${BASE - NH} L ${fx} ${BASE} Z`;
  return {
    id: "offset-arch", name: "The offset arch",
    origin: "mine, round four",
    thesis: "an outline whose two halves are drawn by different rules — one curved shoulder, one square",
    hook: "the asymmetry of the top: it curves up on the left and stops square on the right, so it is an arch that only half happened",
    hazards: [
      "A half-arch on a base is a DOORWAY and a tombstone, and with a notch in the base it is close to the 'shopping bag' and 'archway' logo families.",
      "An arch is also very near a rounded rectangle at 16px: if the curve flattens, this is a rectangle with a notch, which is round two again.",
      "The base notch that names the sibling is 16x18 units — 2.7 x 3.0 device pixels at 16px.",
    ],
    separation: { axis: "x", at: (BASE - 4) / GRID, runs: 2, of: "the two feet either side of the base notch" },
    separationOn: NEUTRAL,
    // NO CLAIM. `topRise` compares the ends of the rendered top-ink profile, each
    // averaged over the outer eighth of the shape's columns. That equals a geometric
    // rise ONLY when the top edge is a single straight line across the full width.
    // Here it is not, so a declared number and the measurement answer different
    // questions and the disagreement is meaningless rather than informative — which
    // is what it reported. The profile is still printed, as information.
    topRise: null,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [feet[k] + NW / 2, BASE - NH / 2]])),
    neutral: NEUTRAL,
    draw: (sib) => `<path d="${shape(feet[sib === null ? NEUTRAL : sib])}" fill="INK"></path>`,
    baseDraw: () => `<path d="M ${L} ${BASE} L ${L} ${SHOULDER} Q ${L} ${PEAK} ${(L + R) / 2} ${PEAK} L ${R} ${PEAK} L ${R} ${BASE} Z" fill="INK"></path>`,
    silhouetteDraw: () => `<path d="${shape(feet[NEUTRAL])}" fill="INK"></path>`,
  };
};

// ── Ghosts ──────────────────────────────────────────────────────────────────
// Round three's shapes, carried in for the silhouette comparison ONLY. They are not
// scored, not plated and not shown to a reader; they exist so this round cannot
// quietly re-draw something already dead. The wedge is the one that matters: it
// survived two rounds and killed two of its own descendants at 0.931 and 0.802 IoU.
const ghost = (id, name, markup) => ({
  id, name, ghost: true,
  origin: "round three, retired — carried only for the silhouette comparison",
  thesis: "", hook: "", hazards: [],
  separation: { axis: "x", at: 0.5, runs: 1, of: "" }, separationOn: null, topRise: null,
  cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [48, 48]])),
  draw: () => markup, baseDraw: () => markup, silhouetteDraw: () => markup,
});

export const SKELETONS = [
  M(), N(), O(), P(),
  ghost("ghost-wedge", "the retired wedge",
    `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>`),
  ghost("ghost-disc", "the retired keyed disc",
    `<circle cx="48" cy="48" r="42" fill="INK"></circle>`),
];

export function scanAt(sk, sib) {
  return sk.separation.at;
}
