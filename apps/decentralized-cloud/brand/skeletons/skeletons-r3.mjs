// Round three skeletons — silhouette-led.
//
// WHAT ROUND TWO ESTABLISHED, against its author. Round one died of a vocabulary:
// few, large, regular, centred elements, which is how system icons are drawn. Round
// two banned that vocabulary and immediately built a second monoculture — a dark
// mass with one small interior subtraction — and both cold readers said so
// independently and unprompted. Reader one: "R, T and U are the same idea three
// times... at 16px those distinctions are one to three pixels, which is to say, at
// the size that matters they are the same drawing."
//
// The ban was right and insufficient, because a vocabulary was replaced with a
// formula rather than with a principle. The principle, derived from the one
// candidate that survived both rounds rather than from the failures:
//
//   AT 16px AN INTERIOR EVENT IS ONE TO THREE DEVICE PIXELS, SO THE IDENTITY
//   CANNOT LIVE THERE. IT HAS TO LIVE IN THE OUTLINE.
//
// So every skeleton here carries its distinguishing event ON ITS SILHOUETTE, and
// each is tested as a SOLID FILLED SHAPE with every counter closed before anything
// else is asked of it. If two candidates' filled silhouettes are largely the same
// raster, their interior events are doing all the work and both are refused.
//
// The incumbent is included and is expected to fail that test. Both round-two
// readers named its silhouette as something borrowed — "megaphone", "speaker cone",
// "pennant", "flag" — and reader two stated the cost against their own favourite:
// "the hole-in-a-wedge is the single most reused device in media/comms branding...
// its pass is a pass on structure, not on distinctiveness."

import { SIBLINGS } from "./skeletons.mjs";
export { GRID, INK, GROUND, SIBLINGS, svg } from "./skeletons.mjs";
const GRID = 96;

// Three different drawings are needed of each skeleton, and conflating any two of
// them breaks a probe:
//
//   draw(sib)        what a reader is shown, and what the presence and separation
//                    probes measure. draw(null) is the NEUTRAL setting, because for
//                    these skeletons the outline event IS the identity and a version
//                    without it is a shape nobody is proposing.
//   baseDraw()       the DIFFERENCING base, with the event absent entirely. The first
//                    cut of this round had draw(null) serving as the base, which made
//                    the base identical to the neutral sibling: that sibling
//                    differenced to nothing, only two of three centres came back, and
//                    the cue probe reported 0.00px for four of five skeletons. It read
//                    as four dead cues and was one wrong base.
//   silhouetteDraw() the shape with every counter CLOSED, which is what the
//                    distinctness probe judges.
const NEUTRAL = "exchange";

// ── V · the stepped wedge ───────────────────────────────────────────────────
// The direct answer to round two's finding: take the only candidate that survived
// two rounds and move its identity out of the counter and onto the outline. Same
// tapering mass, no hole at all, and a rectangular step cut into the top edge so the
// silhouette itself has a re-entrant corner — which almost no system glyph has.
const V = () => {
  const L = 8, R = 88, TOPL = 28, BOTL = 68, TOPR = 3, BOTR = 93;
  const topAt = (x) => TOPL + (TOPR - TOPL) * ((x - L) / (R - L));
  const botAt = (x) => BOTL + (BOTR - BOTL) * ((x - L) / (R - L));
  const STEP_W = 24, STEP_D = 20;
  const starts = { cloud: 34, exchange: 50, trade: 66 };
  const shape = (x0) => {
    const x1 = x0 + STEP_W;
    return `${L},${TOPL} ${x0},${topAt(x0).toFixed(2)} ${x0},${(topAt(x0) + STEP_D).toFixed(2)} ` +
           `${x1},${(topAt(x1) + STEP_D).toFixed(2)} ${x1},${topAt(x1).toFixed(2)} ${R},${TOPR} ` +
           `${R},${BOTR} ${L},${BOTL}`;
  };
  return {
    id: "stepped-wedge", name: "The stepped wedge",
    origin: "mine, round three — the incumbent's identity moved from its counter to its outline",
    thesis: "a tapering mass with a step cut out of its top edge: the event is in the silhouette, where 16px cannot delete it",
    hook: "the re-entrant corner — the outline turns back on itself once, which a wedge, a flag and a megaphone never do",
    hazards: [
      "It is still the round-two wedge underneath, and both readers named that silhouette as a megaphone or a pennant. A step in the top edge may not be enough to unname it — that is the whole question this round asks.",
      "A stepped top edge on a solid mass is close to a CHART and to the 'crop' glyph's corner.",
      "The step is 20 grid units deep: 3.33 device pixels at 16px. That is more than an interior counter gets, but it is not much.",
    ],
    separation: { axis: "y", at: 0.62, runs: 1, of: "the mass, one piece by construction" },
    separationOn: null,
    topRise: TOPL - TOPR,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) =>
      [k, [starts[k] + STEP_W / 2, topAt(starts[k] + STEP_W / 2) + STEP_D / 2]])),
    neutral: NEUTRAL,
    draw: (sib) => `<polygon points="${shape(sib === null ? starts[NEUTRAL] : starts[sib])}" fill="INK"></polygon>`,
    // No step at all: the plain taper, so differencing isolates the step.
    baseDraw: () => `<polygon points="${L},${TOPL} ${R},${TOPR} ${R},${BOTR} ${L},${BOTL}" fill="INK"></polygon>`,
    silhouetteDraw: () => `<polygon points="${shape(starts[NEUTRAL])}" fill="INK"></polygon>`,
  };
};

// ── W · the split wedge ─────────────────────────────────────────────────────
// One mass entering, two leaving — the routing fan, but cut INTO the silhouette
// rather than assembled from separate arms. Round two's confluence built the same
// idea out of arms and became an arrow; this builds it by subtraction from a solid.
const W = () => {
  const R = 88, TOPR = 6, BOTR = 90, L = 8, TOPL = 26, BOTL = 70;
  const apexes = { cloud: 32, exchange: 46, trade: 60 };
  const shape = (ax) => `${R},${TOPR} ${R},${BOTR} ${L},${BOTL} ${ax},${(TOPL + BOTL) / 2} ${L},${TOPL}`;
  return {
    id: "split-wedge", name: "The split wedge",
    origin: "mine, round three",
    thesis: "one mass in, two out — the fan cut into a solid rather than built from separate arms",
    hook: "the deep V bitten into the narrow end, which makes two prongs of unequal thickness out of one body",
    hazards: [
      "A forked narrow end is the FISH TAIL and the arrow FLETCHING, and a two-pronged solid is the tuning fork and the 'merge' glyph.",
      "It is a wedge again. If a reader names 'arrow' the round-two confluence failure has repeated with a different construction.",
      "The two prongs are 22 grid units thick at the tip — 3.7 device pixels at 16px — and if they fuse the mark is a plain wedge.",
    ],
    separation: { axis: "y", at: (L + 4) / GRID, runs: 2, of: "the two prongs at the narrow end" },
    separationOn: null,
    topRise: TOPL - TOPR,
    // The changed region is the TRIANGLE cut out of the narrow end — vertices at the
    // two left corners and the apex — so its centroid is the mean of those three, not
    // the midpoint of the cut. Declaring the feature's position instead of the changed
    // region's centroid is an error made three times in this phase now.
    cueCentres: Object.fromEntries(SIBLINGS.map((k) =>
      [k, [(L + L + apexes[k]) / 3, (TOPL + BOTL + (TOPL + BOTL) / 2) / 3]])),
    neutral: NEUTRAL,
    draw: (sib) => `<polygon points="${shape(sib === null ? apexes[NEUTRAL] : apexes[sib])}" fill="INK"></polygon>`,
    // No V: the unsplit wedge, so differencing isolates the cut.
    baseDraw: () => `<polygon points="${R},${TOPR} ${R},${BOTR} ${L},${BOTL} ${L},${TOPL}" fill="INK"></polygon>`,
    silhouetteDraw: () => `<polygon points="${shape(apexes[NEUTRAL])}" fill="INK"></polygon>`,
  };
};

// ── X · the asymmetric plectrum ─────────────────────────────────────────────
// Three corners, all different: one acute, two rounded to different radii, and three
// sides that are all slightly convex. No straight edge anywhere and no axis of
// symmetry, which between them rule out most of the glyph set — system icons are
// built from straight lines and mirror symmetry because that is what survives being
// redrawn by a hundred hands.
const X = () => {
  const clips = { cloud: 0, exchange: 1, trade: 2 };
  // Corners, and the small flat that clips one of them — the cue is which corner is
  // cut, which is an event on the outline rather than inside it.
  const corners = [[14, 82], [50, 10], [86, 58]];
  const CLIP = 14;
  const BOWS = [10, 6, 8];   // each side bows outward by a different amount
  const CENTRE = [50, 50];
  // The first cut of this built the path inside a forEach that emitted a stray `Q`
  // with no endpoint and closed a corner it had already left. It rendered 0.4% ink —
  // effectively nothing — at every size. It is written out plainly here instead: for
  // each corner, where the incoming edge ARRIVES and where the outgoing edge LEAVES;
  // an unclipped corner has those two at the same point, a clipped one has a flat
  // between them.
  const shape = (which) => {
    const lerp = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
    const arrive = [], leave = [];
    for (let i = 0; i < 3; i++) {
      const p = corners[i], prev = corners[(i + 2) % 3], next = corners[(i + 1) % 3];
      if (i === which) {
        arrive.push(lerp(p, prev, CLIP / Math.hypot(prev[0] - p[0], prev[1] - p[1])));
        leave.push(lerp(p, next, CLIP / Math.hypot(next[0] - p[0], next[1] - p[1])));
      } else { arrive.push(p); leave.push(p); }
    }
    let d = `M ${leave[0][0].toFixed(2)} ${leave[0][1].toFixed(2)} `;
    for (let i = 0; i < 3; i++) {
      const from = leave[i], to = arrive[(i + 1) % 3], bow = BOWS[i];
      // Control point: the edge's midpoint pushed directly away from the centre, so
      // the side bows outward rather than shearing.
      const mx = (from[0] + to[0]) / 2, my = (from[1] + to[1]) / 2;
      const dx = mx - CENTRE[0], dy = my - CENTRE[1], len = Math.hypot(dx, dy) || 1;
      d += `Q ${(mx + dx / len * bow).toFixed(2)} ${(my + dy / len * bow).toFixed(2)} ${to[0].toFixed(2)} ${to[1].toFixed(2)} `;
      const nx = (i + 1) % 3;
      if (nx === which) d += `L ${leave[nx][0].toFixed(2)} ${leave[nx][1].toFixed(2)} `;
    }
    return d + "Z";
  };
  return {
    id: "plectrum", name: "The asymmetric plectrum",
    origin: "mine, round three",
    thesis: "three unequal corners and three bowed sides — no straight edge and no axis of symmetry",
    hook: "the single sharp corner among two soft ones, and the fact that no two sides bow by the same amount",
    hazards: [
      "A rounded triangle is the GUITAR PICK, and pointed downward it is the SHIELD, which is the stock security-industry shape. Asymmetry is what is being asked to break both reads, and asymmetry is subtle.",
      "It is also close to the 'location pin' body and to a leaf.",
      "The clipped corner that names the sibling is 14 grid units — 2.3 device pixels at 16px — and a clip that small on a curved corner may not survive antialiasing.",
    ],
    separation: { axis: "x", at: 0.5, runs: 1, of: "the mass, one piece by construction" },
    separationOn: null,
    // No straight top edge exists here, so there is no rise to declare. The probe is
    // skipped rather than given a made-up number to agree with; a claim that does not
    // exist must not be manufactured so a check has something to pass.
    topRise: null,
    // The changed region is the TRIANGLE the clip removes — the corner and the two
    // points the clip cuts to — so its centroid is the mean of those three.
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => {
      const i = clips[k], p = corners[i], prev = corners[(i + 2) % 3], next = corners[(i + 1) % 3];
      const cut = (q) => {
        const t = CLIP / Math.hypot(q[0] - p[0], q[1] - p[1]);
        return [p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t];
      };
      const a = cut(prev), b = cut(next);
      return [k, [(p[0] + a[0] + b[0]) / 3, (p[1] + a[1] + b[1]) / 3]];
    })),
    neutral: NEUTRAL,
    draw: (sib) => `<path d="${shape(sib === null ? clips[NEUTRAL] : clips[sib])}" fill="INK"></path>`,
    // No corner clipped: differencing then isolates the clip.
    baseDraw: () => `<path d="${shape(-1)}" fill="INK"></path>`,
    silhouetteDraw: () => `<path d="${shape(clips[NEUTRAL])}" fill="INK"></path>`,
  };
};

// ── Y · the keyed disc ──────────────────────────────────────────────────────
// A circle is the least ownable outline there is, so this one is broken: a single
// narrow slot cut from the edge past the centre. The silhouette is a disc that
// cannot close, and where the slot points names the sibling.
const Y = () => {
  const CX = 48, CY = 48, RAD = 42, SLOT = 15;
  const angles = { cloud: -90, exchange: -20, trade: 50 };
  const shape = (deg) => {
    const a = deg * Math.PI / 180;
    const ux = Math.cos(a), uy = Math.sin(a), px = -uy, py = ux;
    const p = (t, s) => `${(CX + ux * t + px * s).toFixed(2)},${(CY + uy * t + py * s).toFixed(2)}`;
    return `<circle cx="${CX}" cy="${CY}" r="${RAD}" fill="white"></circle>` +
           `<polygon points="${p(RAD + 6, -SLOT / 2)} ${p(RAD + 6, SLOT / 2)} ${p(-8, SLOT / 2)} ${p(-8, -SLOT / 2)}" fill="black"></polygon>`;
  };
  return {
    id: "keyed-disc", name: "The keyed disc",
    origin: "mine, round three",
    thesis: "the least ownable outline there is, broken by one slot that cuts past its centre",
    hook: "the slot that overshoots the middle, so the disc is not a ring, not a pie and not a gauge — it is a disc that has been keyed",
    hazards: [
      "A circle with a wedge missing is the PIE CHART and Pac-Man; a circle with a gap is the 'power' symbol and the loading spinner, and the spinner already killed this product's first mark.",
      "A keyway in a disc is also the stock 'lock/key' and 'camera aperture' vocabulary.",
      "The slot is 15 grid units — 2.5 device pixels at 16px. If it closes, this is a filled circle, which is the most anonymous mark it is possible to draw.",
    ],
    separation: { axis: "x", at: 0.5, runs: 2, of: "ink either side of the slot where it crosses the centre" },
    separationOn: "cloud",
    topRise: 0,
    // The changed region is the SLOT, which runs from 8 units past the centre out to
    // 6 units beyond the rim. Its centroid sits at the midpoint of that span — t=20,
    // which is 0.476 of the radius, not the 0.7 first declared.
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => {
      const a = angles[k] * Math.PI / 180, t = ((RAD + 6) + (-8)) / 2;
      return [k, [CX + Math.cos(a) * t, CY + Math.sin(a) * t]];
    })),
    neutral: NEUTRAL,
    draw: (sib) => {
      const id = `kd-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${shape(angles[sib === null ? NEUTRAL : sib])}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
    // No slot: the plain disc, so differencing isolates where the slot was cut.
    baseDraw: () => `<circle cx="${CX}" cy="${CY}" r="${RAD}" fill="INK"></circle>`,
    silhouetteDraw: () => {
      const id = "kd-sil";
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${shape(angles[NEUTRAL])}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
  };
};

// ── Z · the incumbent ───────────────────────────────────────────────────────
// The wedge counter as it stands, carried in unmarked so the round has a control and
// so the silhouette probe is applied to it on the same terms as the rest. Its
// silhouette FILLS the counter, which is the point: if closing the hole leaves a
// shape indistinguishable from a plain wedge, then the hole was the whole mark.
const Z = () => {
  const L = 8, R = 88, TOPL = 28, BOTL = 68, TOPR = 3, BOTR = 93, CR = 15;
  const slots = { cloud: 32, exchange: 50, trade: 68 };
  const halfAt = (x) => {
    const t = (x - L) / (R - L);
    const top = TOPL + (TOPR - TOPL) * t, bot = BOTL + (BOTR - BOTL) * t;
    return { top, bot, mid: (top + bot) / 2, h: bot - top };
  };
  const body = `<polygon points="${L},${TOPL} ${R},${TOPR} ${R},${BOTR} ${L},${BOTL}" fill="white"></polygon>`;
  return {
    id: "wedge-counter-incumbent", name: "The wedge counter",
    origin: "the incumbent — the only candidate to survive rounds one and two",
    thesis: "direction without an arrowhead, and one punched counter",
    hook: "the circular void off-centre in the fat end of a solid wedge — the only counter in either round's set",
    hazards: [
      "Both round-two readers named its silhouette as borrowed: megaphone, speaker cone, pennant, flag.",
      "Reader two, against their own favourite: 'the hole-in-a-wedge is the single most reused device in media/comms branding... no two people will agree on what it depicts.'",
      "Its identity is an interior event, which is exactly what this round exists to test.",
    ],
    separation: { axis: "x", at: null, runs: 2, of: "ink either side of the punched counter" },
    separationOn: "exchange",
    topRise: TOPL - TOPR,
    cueCentres: Object.fromEntries(SIBLINGS.map((k) => [k, [slots[k], halfAt(slots[k]).mid]])),
    neutral: NEUTRAL, slots, halfAt,
    draw: (sib) => {
      const cx = sib === null ? null : slots[sib];
      const punch = cx === null ? "" : `<circle cx="${cx}" cy="${halfAt(cx).mid.toFixed(2)}" r="${CR}" fill="black"></circle>`;
      const id = `wci-${sib || "base"}`;
      return `<defs><mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
             `<rect width="${GRID}" height="${GRID}" fill="black"></rect>${body}${punch}</mask></defs>` +
             `<rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${id})"></rect>`;
    },
    // Counters CLOSED: this is the shape the silhouette probe judges.
    silhouetteDraw: () => `<polygon points="${L},${TOPL} ${R},${TOPR} ${R},${BOTR} ${L},${BOTL}" fill="INK"></polygon>`,
  };
};

export const SKELETONS = [V(), W(), X(), Y(), Z()];

export function scanAt(sk, sib) {
  if (sk.separation.at !== null) return sk.separation.at;
  return sk.halfAt(sk.slots[sib || "exchange"]).mid / GRID;
}
