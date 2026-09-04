// Round two skeletons.
//
// WHAT ROUND ONE ESTABLISHED. Four of five skeletons died, and only one died on
// measurement. The other three were named as existing system controls by two cold
// readers independently, with confidence "certain": the share glyph, the align-left
// button, the apps grid. They were four different drawings and they landed on four
// different existing buttons, which is not four accidents.
//
// The thing they share is a VOCABULARY: a small number of LARGE, REGULAR, CENTRED,
// SYMMETRIC elements — circles joined by lines, stacked bars, a grid of squares,
// stacked cubes. That is the vocabulary system icons are drawn in, because it is the
// vocabulary that survives being drawn small by a hundred different people. Dodging
// one glyph at a time is how you find the next glyph. So round two bans the
// vocabulary instead:
//
//   BANNED — separated circles joined by strokes; stacks of parallel bars; grids of
//   equal cells; cubes, hexagons and isometric slabs; anything symmetric about the
//   vertical axis; anything assembled from more than two detached pieces.
//   REQUIRED — one connected irregular mass whose SILHOUETTE carries the identity,
//   because mass is what survives 16px and strokes are what die there.
//
// The one survivor, the wedge counter, is carried forward as the incumbent and gets
// no special treatment: both readers scored it 5/10 and both named the same fault
// unprompted — the slant that makes it interesting is what 16px deletes, leaving "a
// black rectangle with an off-centre white dot". Its taper was 14 grid units over
// 80, which is 2.33 device pixels of rise at 16px. That fault is now MEASURED rather
// than argued: every skeleton declares the rise of its own top edge, and the harness
// fits the rendered top-ink profile and cross-checks it.

import { SIBLINGS } from "./skeletons.mjs";
export { GRID, INK, GROUND, SIBLINGS, svg } from "./skeletons.mjs";
const GRID = 96;

// ── F · the wedge counter, corrected ────────────────────────────────────────
const F = () => {
  const L = 8, R = 88;
  // Taper deepened from 14 grid units of rise to 25: 4.17 device pixels at 16px
  // against the 2.33 that flattened. The counter is enlarged from r13 to r15 so it
  // reads as an aperture rather than as the dead pixel both readers saw.
  const TOPL = 28, BOTL = 68, TOPR = 3, BOTR = 93, CR = 15;
  const slots = { cloud: 32, exchange: 50, trade: 68 };
  const halfAt = (x) => {
    const t = (x - L) / (R - L);
    const top = TOPL + (TOPR - TOPL) * t, bot = BOTL + (BOTR - BOTL) * t;
    return { top, bot, mid: (top + bot) / 2, h: bot - top };
  };
  return {
    id: "wedge-counter-ii", name: "The wedge counter, corrected",
    origin: "round one's only survivor, carried forward with its named fault addressed",
    thesis: "direction without an arrowhead, and one punched counter — the receipt the routing mints",
    hook: "the taper — a mass that is nearly three times deeper at one end than the other, with the counter sitting in the thin end where there is least room for it",
    hazards: [
      "Round one's readers scored this 5/10 and neither could name a control for it — but reader two called the surviving 16px form 'closer to a lens cap than to anything I'd call a brand', and deepening the taper does not answer that.",
      "A knocked-out circle in a mass is the 'do not enter' and record-button family.",
      "Its risk is DISTINCTIVENESS, which no probe here measures. Being one mass, it cannot fail the separation probe, so that probe proves nothing about it.",
    ],
    separation: { axis: "x", at: null, runs: 2, of: "ink either side of the punched counter" },
    separationOn: "exchange",
    topRise: TOPL - TOPR,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [slots[k], halfAt(slots[k]).mid]])),
    slots, halfAt, CR,
    draw: (sib) => {
      const body = `<polygon points="${L},${TOPL} ${R},${TOPR} ${R},${BOTR} ${L},${BOTL}" fill="white"></polygon>`;
      const cx = sib === null ? null : slots[sib];
      const punch = cx === null ? "" : `<circle cx="${cx}" cy="${halfAt(cx).mid.toFixed(2)}" r="${CR}" fill="black"></circle>`;
      const id = `wc2-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${body}${punch}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

// ── G · the confluence ──────────────────────────────────────────────────────
// Many in, one out — the router's whole thesis — drawn as MASS rather than as nodes
// and edges. Round one proved that drawing a network as circles-and-lines produces
// the share glyph; this draws the same idea as one solid converging body.
const G = () => {
  const OUT = { x0: 62, x1: 90, y0: 38, y1: 58 };
  const inlets = [{ y: 6, h: 14 }, { y: 41, h: 14 }, { y: 76, h: 14 }];
  const FAT = 26;
  return {
    id: "confluence", name: "The confluence",
    origin: "mine, round two",
    thesis: "many in, one out, drawn as one solid body instead of as nodes and edges",
    hook: "the outlet — three arms of unequal weight collapsing into one blunt stub that is thicker than any of them",
    hazards: [
      "A converging body with a narrow outlet is the FUNNEL, which is the standard FILTER control. That is the same class of failure that killed three of round one, and it is the first thing to ask a cold reader.",
      "It is also the version-control 'merge' glyph, and the audio 'mixer' shape.",
      "The chosen-inlet cue is a thickness difference, and thickness differences are the first thing antialiasing eats at 16px.",
    ],
    // The three inlets must still be three where they leave the left edge.
    separation: { axis: "y", at: 8 / GRID, runs: 3, of: "the three inlets at the left edge" },
    separationOn: null,
    topRise: 6 - 38,   // negative: the top edge falls to the right
    cueCentres: Object.fromEntries(SIBLINGS.map((k, i) =>
      [k, [(6 + OUT.x0) / 2, inlets[i].y + inlets[i].h / 2]])),
    draw: (sib) => {
      const lit = sib === null ? -1 : SIBLINGS.indexOf(sib);
      const arms = inlets.map((n, i) => {
        const h = i === lit ? FAT : n.h;
        const y = n.y + n.h / 2 - h / 2;
        return `<polygon points="6,${y} 6,${y + h} ${OUT.x0},${OUT.y1} ${OUT.x0},${OUT.y0}" fill="INK"></polygon>`;
      }).join("");
      return arms + `<rect x="${OUT.x0}" y="${OUT.y0}" width="${OUT.x1 - OUT.x0}" height="${OUT.y1 - OUT.y0}" fill="INK"></rect>`;
    },
  };
};

// ── H · the terrace ─────────────────────────────────────────────────────────
// Capacity that steps, as ONE joined mass with unequal treads and unequal risers.
// The bar-chart glyph it is nearest to is made of SEPARATED bars of equal width;
// this is one silhouette, and the inequality is the point.
const H = () => {
  const steps = [{ x0: 6, x1: 34, y: 52 }, { x0: 34, x1: 58, y: 30 }, { x0: 58, x1: 90, y: 12 }];
  const FLOOR = 90, PUNCH = 13;
  return {
    id: "terrace", name: "The terrace",
    origin: "mine, round two",
    thesis: "capacity that steps — one mass, unequal treads, unequal risers",
    hook: "the unequal treads — 28, 24 and 32 wide over risers of 22 and 18, so no two steps are the same and it cannot be mistaken for a chart",
    hazards: [
      "A rising profile is the BAR CHART and the 'trending up' glyph, and rotated it is the signal-strength meter. It differs from all three by being one joined mass with unequal treads, and whether a reader sees that difference is a reader's call, not mine.",
      "It is also the 'stairs' pictogram and, filled, the generic analytics logo of the last decade.",
      "The riser between the second and third tread is 18 grid units — 3 device pixels at 16px. If the profile flattens the whole idea flattens with it.",
    ],
    separation: { axis: "y", at: 20 / GRID, runs: 1, of: "the mass, which is one piece by construction" },
    separationOn: null,
    topRise: steps[0].y - steps[2].y,
    cueCentres: Object.fromEntries(SIBLINGS.map((k, i) =>
      [k, [(steps[i].x0 + steps[i].x1) / 2, steps[i].y + (FLOOR - steps[i].y) / 2]])),
    draw: (sib) => {
      const pts = [`${steps[0].x0},${FLOOR}`];
      for (const s of steps) { pts.push(`${s.x0},${s.y}`, `${s.x1},${s.y}`); }
      pts.push(`${steps[2].x1},${FLOOR}`);
      const body = `<polygon points="${pts.join(" ")}" fill="white"></polygon>`;
      const i = sib === null ? -1 : SIBLINGS.indexOf(sib);
      const punch = i < 0 ? "" :
        `<rect x="${(steps[i].x0 + steps[i].x1) / 2 - PUNCH / 2}" ` +
        `y="${steps[i].y + (FLOOR - steps[i].y) / 2 - PUNCH / 2}" width="${PUNCH}" height="${PUNCH}" fill="black"></rect>`;
      const id = `tr-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${body}${punch}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

// ── I · the split mass ──────────────────────────────────────────────────────
// One block of capacity with a single route cut through it. The channel stops short
// of the far edge, so the mass stays one piece: a route THROUGH capacity, not a
// capacity cut in two.
const I = () => {
  const X0 = 6, X1 = 90, Y0 = 18, Y1 = 78, W = 12, SHORT = 12;
  const slots = { cloud: 26, exchange: 46, trade: 66 };
  const LEAN = 16;   // how far the channel leans right as it rises
  return {
    id: "split-mass", name: "The split mass",
    origin: "mine, round two",
    thesis: "one block of capacity with a single route cut through it, stopping short so the block stays whole",
    hook: "the blind channel — a cut that leans as it rises and stops before it gets out, so the block is scored but never severed",
    hazards: [
      "A mass with a gap in it is the POWER symbol's family, and a block split into two tones is the 'brightness/contrast' and 'compare/split view' control.",
      "A flat-topped rectangle has no silhouette of its own; everything here rests on the channel, and the channel is 12 grid units — 2 device pixels at 16px.",
      "It declares a top rise of ZERO on purpose. That is a real cost, not an oversight: it gives the probe nothing to find, and a mark whose outline is a rectangle is a mark whose outline is nobody's.",
    ],
    separation: { axis: "x", at: (Y1 - 8) / GRID, runs: 2, of: "the mass either side of the channel, scanned below where the channel ends" },
    separationOn: "exchange",
    topRise: 0,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [slots[k] + LEAN / 2, (Y0 + SHORT + Y1) / 2]])),
    draw: (sib) => {
      const body = `<rect x="${X0}" y="${Y0}" width="${X1 - X0}" height="${Y1 - Y0}" rx="6" fill="white"></rect>`;
      const cx = sib === null ? null : slots[sib];
      const cut = cx === null ? "" :
        `<polygon points="${cx},${Y1 + 4} ${cx + W},${Y1 + 4} ${cx + W + LEAN},${Y0 + SHORT} ${cx + LEAN},${Y0 + SHORT}" fill="black"></polygon>`;
      const id = `sm-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${body}${cut}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

// ── J · the ribbon ──────────────────────────────────────────────────────────
// One thick stroke that folds back on itself with unequal arms and stops just short
// of touching, so the near-miss encloses a counter without closing it. The interior
// event is the gap, not a hole: a shape that ALMOST closes is a thing a reader has
// to look at twice, which is the whole hook.
const J = () => {
  // The first cut of this drew the outline as a filled path AND stroked it at 17
  // units with a round join. A stroke inflates an outline by half its width on every
  // side, so a 17-unit stroke closed a 17-unit notch exactly: the hook was sealed
  // shut at every size, including 96px, and the aperture probe correctly reported
  // gaps of 0/0/1px. The fill alone carries the shape; there is no stroke.
  const path = (gap) =>
    `M 10 84 L 10 26 L 62 26 L 62 ${58 - gap / 2} L 30 ${58 - gap / 2} ` +
    `L 30 ${58 + gap / 2} L 86 ${58 + gap / 2} L 86 84 Z`;
  // Widened from 10/17/24 to 10/20/30: a 7-unit step is 1.17 device pixels at 16px,
  // which is inside the floor of what a reader can be asked to tell apart.
  const gaps = { cloud: 10, exchange: 20, trade: 30 };
  return {
    id: "ribbon", name: "The ribbon",
    origin: "mine, round two",
    thesis: "one route that folds back on itself and stops just short of closing",
    hook: "the near-miss — the point where the stroke folds back and almost, but not quite, meets itself",
    hazards: [
      "A folded stroke with unequal arms reads as a LETTER before it reads as a mark: S, Z, N and 2 are all in range, and round one's monogram died partly for reading as a 2.",
      "It is also close to the 'shuffle', 'redo' and route/zigzag glyphs, and to a chart line.",
      "The hook is a GAP of 10-24 grid units, which is 1.7-4.0 device pixels at 16px. A hook measured in single pixels is a hook antialiasing owns.",
    ],
    separation: { axis: "y", at: 46 / GRID, runs: 2, of: "the two arms either side of the fold" },
    separationOn: "exchange",
    // The top edge sits at y=26 across the upper arm and drops to the lower arm's
    // top at 58 + gap/2 on the right. For the sibling the slant probe renders
    // (exchange, gap 20) that is a fall of 42 grid units, not the zero first declared.
    topRise: -(58 + 20 / 2 - 26),
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [46, 58]])),
    cueIs: "aperture",   // the cue is the SIZE of the gap, not its position
    apertures: gaps,
    draw: (sib) => `<path d="${path(sib === null ? 20 : gaps[sib])}" fill="INK"></path>`,
  };
};

// ── K · the eroded block ────────────────────────────────────────────────────
// A block of capacity with unequal bites taken out of one edge — capacity drawn
// down, and a torn edge that no regular construction produces. The nearest familiar
// object is a ticket stub, which is what a receipt looks like, so the association it
// does carry is one the product would accept.
const K = () => {
  const X0 = 8, X1 = 84, Y0 = 14, Y1 = 82;
  const bites = [{ y: 30, r: 13 }, { y: 52, r: 8 }, { y: 70, r: 11 }];
  return {
    id: "eroded-block", name: "The eroded block",
    origin: "mine, round two",
    thesis: "a block of capacity with unequal bites out of one edge — capacity drawn down, and the torn edge of a receipt",
    hook: "the torn right edge: three bites of three different sizes, never a repeating scallop",
    hazards: [
      "A scalloped edge is the TICKET STUB and the perforated-coupon shape; if a reader names 'ticket' that is not fatal here, but if a reader names 'coupon' or 'voucher' it is a retail signal on an infrastructure product.",
      "Semicircular bites around an edge are also the COG and the gear-fragment, which is the stock 'settings' control.",
      "The smallest bite is r8 — 2.7 device pixels across at 16px. If the three bites stop reading as three different sizes the hook is gone and it is a rectangle with a wavy edge.",
    ],
    separation: { axis: "y", at: (X1 - 3) / GRID, runs: 4, of: "the four spans of ink left between the three bites along the bitten edge" },
    separationOn: null,
    topRise: 0,
    // The cue is which bite is deepened; centres are the three bite centres.
    cueCentres: Object.fromEntries(SIBLINGS.map((k, i) => [k, [X1, bites[i].y]])),
    draw: (sib) => {
      const lit = sib === null ? -1 : SIBLINGS.indexOf(sib);
      const body = `<rect x="${X0}" y="${Y0}" width="${X1 - X0}" height="${Y1 - Y0}" rx="4" fill="white"></rect>`;
      const cuts = bites.map((b, i) =>
        `<circle cx="${X1}" cy="${b.y}" r="${i === lit ? b.r + 6 : b.r}" fill="black"></circle>`).join("");
      const id = `eb-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${body}${cuts}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

export const SKELETONS = [F(), G(), H(), I(), J(), K()];

export function scanAt(sk, sib) {
  if (sk.separation.at !== null) return sk.separation.at;
  return sk.halfAt(sk.slots[sib || "exchange"]).mid / GRID;
}
