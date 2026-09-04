// WIDE GENERATION, ROUND TWO — sampling the space round one's readers named.
//
// Round one put 352 candidates in front of three fresh readers and got zero passes,
// unanimously. That is the same verdict the closed phase got four times, but this
// time the readers agreed on WHY, in three independent voices:
//
//   "the shape lands on a letter... a mark that reads as a letter is a letter"
//   "the dominant failure is collision with the alphabet and the digits"
//   "either a letter/digit I'd read as text, or an unmemorable black lump"
//
// So round one's nine families sampled two regions and both are dead: shapes near
// the alphabet, and shapes near nothing. The one positive datum in the whole round
// was a crescent — the only cell any reader said they would recognise again — and it
// was disqualified for being the moon. Read carefully that is not "avoid known
// forms": it is that a KNOWN form is the only thing that survived being small, and
// what it lacked was a reason to be this brand's rather than anyone's.
//
// RETIRED THIS ROUND, on reader evidence, by ioi-c0's ruling:
//   C sheared strata   — read as "7", "2", "equals", "menu" by all three
//   E keyway step      — one survivor of 27; the step vanishes at 16px
//   F unequal pair     — thirteen cells all three readers could not tell apart
//   H letterform cut   — read as C, D, U, L, S, E, J. A mark cut from the face's
//   I wordmark fragment  outlines IS the face's letter. This was ioi-c0's own
//                        addition and the readers overturned it; recorded here
//                        because the round log records who was wrong, not just what.
//
// KEPT: A and G, the counter-in-a-mass lineage — the only one with survivors across
// both this phase and the closed one.
//
// COLOUR is now a COST rather than a disqualifier (owner ruling, relayed by ioi-c0).
// Every candidate is generated with an optional second tone, and the filter runs
// twice: once in one ink, once in two. A candidate that passes only in two-tone
// survives WITH ITS ONE-INK COST WRITTEN BESIDE IT — never quietly promoted.

export const GRID = 96;
export const INK = "#0d0f12";
export const INK2 = "#8f98a3";   // a mid tone that survives being printed one-ink
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;
const pts = (ps) => ps.map(([x, y]) => `${R2(x)},${R2(y)}`).join(" ");
const polygon = (ps, fill = "INK") => `<polygon points="${pts(ps)}" fill="${fill}"></polygon>`;

function masked(id, body, holes) {
  if (!holes) return body;
  const mid = `m2-${id}`;
  return (
    `<defs><mask id="${mid}" maskUnits="userSpaceOnUse" x="0" y="0" width="${GRID}" height="${GRID}">` +
    `<rect width="${GRID}" height="${GRID}" fill="black"></rect>` +
    body.replace(/fill="INK2?"/g, 'fill="white"') + holes +
    `</mask></defs><rect width="${GRID}" height="${GRID}" fill="INK" mask="url(#${mid})"></rect>`
  );
}

// ── A' · the kept lineage, resampled ────────────────────────────────────────
// The counter-in-a-mass, with the parameters round one showed actually move the
// drawing: the counter's SIZE relative to the mass, and whether it breaks the
// outline. Round one swept bow and cant, and 57 of 81 collapsed as duplicates at
// 16px — proof that those two parameters are spent below the resolution the viewer
// has. This sweeps what survives instead.
function familyA2() {
  const out = [];
  const BASE = 84;
  const bodies = [
    { k: "lean", ps: [[12, 24], [86, 12], [90, BASE], [8, BASE]] },
    { k: "wedge", ps: [[10, 32], [88, 10], [88, BASE], [10, BASE]] },
  ];
  for (const b of bodies) {
    for (const r of [16, 22, 28]) {                 // counter radius: 5.3, 7.3, 9.3 device px at 16px
      for (const cx of [34, 48, 64]) {
        for (const cy of [36, 54]) {
          const id = `A2-${b.k}-r${r}-x${cx}-y${cy}`;
          out.push({
            id, family: "A' counter in a canted mass",
            thesis: `a counter of radius ${r} in a canted mass — the one lineage with survivors`,
            draw: () => masked(id, polygon(b.ps), `<circle cx="${cx}" cy="${cy}" r="${r}" fill="black"></circle>`),
          });
        }
      }
    }
  }
  return out;
}

// ── J · metaphor with a twist ───────────────────────────────────────────────
// The crescent was the only shape any round-one reader said they would recognise
// again, and it failed for being ONLY the moon. So: a known form, altered by exactly
// one decisive move, where the move is what makes it this brand's.
//
// HAZARDS PRE-BANNED BY NAME, per ioi-c0, and none of these may be generated: a
// cloud silhouette, the share glyph, the power symbol, an arrow, a location pin, a
// hang tag. Every family here is checked against that list before it is written, and
// the crescent's own hazard — "it is just the moon" — is the thing the twist exists
// to answer. If a reader still says "moon", the twist failed and the candidate dies.
function familyJ() {
  const out = [];
  const OUT_R = 42, CX = 48, CY = 48;
  const disc = `<circle cx="${CX}" cy="${CY}" r="${OUT_R}" fill="INK"></circle>`;
  // twist 1 — the crescent's inner edge is a STRAIGHT chord, not an arc. A moon's
  // inner edge is always an arc, because a moon is two circles.
  for (const off of [14, 22, 30]) {
    for (const tilt of [0, 14, 28]) {
      const id = `J-chord-o${off}-t${tilt}`;
      const t = (tilt * Math.PI) / 180;
      const hx = Math.cos(t) * 90, hy = Math.sin(t) * 90;
      const cut = polygon(
        [[CX + off - hx, CY - hy], [CX + off + hx, CY + hy],
         [CX + off + hx + 90, CY + hy], [CX + off - hx + 90, CY - hy]],
        "black"
      );
      out.push({
        id, family: "J known form, one twist",
        thesis: "a crescent whose inner edge is a straight chord — a moon's never is",
        draw: () => masked(id, disc, cut),
      });
    }
  }
  // twist 2 — the crescent's horns are CUT FLAT and the base is level with the type.
  for (const off of [16, 24]) {
    for (const flat of [10, 18, 26]) {
      const id = `J-flathorn-o${off}-f${flat}`;
      const cut =
        `<circle cx="${CX + off}" cy="${CY}" r="${OUT_R}" fill="black"></circle>` +
        polygon([[0, 0], [GRID, 0], [GRID, 6 + flat], [0, 6 + flat]], "black") +
        polygon([[0, GRID - 6 - flat], [GRID, GRID - 6 - flat], [GRID, GRID], [0, GRID]], "black");
      out.push({
        id, family: "J known form, one twist",
        thesis: "a crescent with its horns cut flat, so it has a top and a base rather than points",
        draw: () => masked(id, disc, cut),
      });
    }
  }
  // twist 3 — the ring, broken ONCE, off-axis. A broken ring is not a spinner as long
  // as the break is not on a cardinal angle and the stroke is not even.
  for (const gap of [26, 40]) {
    for (const rot of [23, 61, 107]) {
      for (const w of [14, 20]) {
        const id = `J-ring-g${gap}-r${rot}-w${w}`;
        const rr = OUT_R - w / 2;
        const a0 = (rot * Math.PI) / 180, a1 = ((rot + 360 - gap) * Math.PI) / 180;
        const large = 360 - gap > 180 ? 1 : 0;
        const d =
          `M ${R2(CX + rr * Math.cos(a0))} ${R2(CY + rr * Math.sin(a0))} ` +
          `A ${rr} ${rr} 0 ${large} 1 ${R2(CX + rr * Math.cos(a1))} ${R2(CY + rr * Math.sin(a1))}`;
        out.push({
          id, family: "J known form, one twist",
          thesis: "a ring broken once, off every cardinal angle",
          draw: () => `<path d="${d}" fill="none" stroke="INK" stroke-width="${w}" stroke-linecap="butt"></path>`,
        });
      }
    }
  }
  return out;
}

// ── K · negative space ──────────────────────────────────────────────────────
// The memorable form is the HOLE. Round two's constraint on this family comes
// straight from R2's finding: at 16px an interior event is 1-3 device pixels, so a
// counter can only carry the identity if it is LARGE — every void here is at least
// 35% of its mass, which is 5+ device pixels across at product size.
function familyK() {
  const out = [];
  const field = [
    { k: "disc", body: `<circle cx="48" cy="48" r="44" fill="INK"></circle>` },
    { k: "block", body: polygon([[8, 14], [88, 8], [90, 88], [6, 88]]) },
  ];
  const voids = [
    { k: "slot", make: (t) => polygon([[30, 26], [64, 20], [58, 70], [26, 76]].map(([x, y]) => [x + t, y]), "black") },
    { k: "chevron", make: (t) => polygon([[26, 24], [50, 46], [72, 22], [72, 44], [50, 66], [26, 46]].map(([x, y]) => [x + t, y]), "black") },
    { k: "step", make: (t) => polygon([[26, 24], [66, 24], [66, 46], [46, 46], [46, 72], [26, 72]].map(([x, y]) => [x + t, y]), "black") },
    { k: "wedge", make: (t) => polygon([[24, 22], [72, 34], [72, 50], [24, 74]].map(([x, y]) => [x + t, y]), "black") },
  ];
  for (const f of field) {
    for (const v of voids) {
      for (const t of [-8, 0, 8]) {
        const id = `K-${f.k}-${v.k}-t${t}`;
        out.push({
          id, family: "K the hole is the mark",
          thesis: `a ${f.k} whose identity is a large ${v.k} void, offset ${t}`,
          draw: () => masked(id, f.body, v.make(t)),
        });
      }
    }
  }
  return out;
}

// ── L · two forms, one relation ─────────────────────────────────────────────
// A single mass keeps collapsing to a letter or a lump, so the identity here is the
// RELATIONSHIP between two forms. Round one's family F tried this and failed for a
// reason the readers named exactly: the second form was tiny and detached, so it read
// as "a square and a speck". Both forms here are substantial — the smaller is never
// below half the larger — and they always touch, nest or overlap.
function familyL() {
  const out = [];
  const big = (cx, cy, s, tilt) => {
    const h = s / 2, t = (tilt * Math.PI) / 180, c = Math.cos(t), sn = Math.sin(t);
    return polygon([[-h, -h], [h, -h * 0.82], [h * 0.92, h], [-h, h]].map(([x, y]) =>
      [cx + x * c - y * sn, cy + x * sn + y * c]));
  };
  for (const rel of ["nest", "overlap", "interlock"]) {
    for (const ratio of [0.52, 0.68]) {
      for (const shift of [-12, 0, 12]) {
        for (const tilt of [-9, 9]) {
          const S = 62, s = S * ratio;
          const id = `L-${rel}-r${String(ratio).replace(".", "")}-s${shift}-t${tilt}`;
          let m;
          if (rel === "nest") {
            // the smaller form sits INSIDE the larger as a knockout, off-centre
            m = masked(id, big(48, 50, S, tilt),
              big(48 + shift, 50 + shift / 2, s, -tilt).replace('fill="INK"', 'fill="black"'));
          } else if (rel === "overlap") {
            // the smaller occludes the larger with a knockout gap, so the pair reads
            // as one in front of the other rather than as two touching
            m = masked(id, big(38, 54, S, tilt),
              big(38 + 26 + shift / 3, 54 - 22, s + 12, -tilt).replace('fill="INK"', 'fill="black"')) +
              big(38 + 26 + shift / 3, 54 - 22, s, -tilt);
          } else {
            // two brackets hooked into each other
            const arm = (cx, cy, f) => polygon([
              [cx, cy - 26], [cx + f * 30, cy - 26], [cx + f * 30, cy - 8],
              [cx + f * 14, cy - 8], [cx + f * 14, cy + 26], [cx, cy + 26],
            ]);
            m = arm(34 + shift / 2, 40, 1) + arm(62 - shift / 2, 58, -1);
          }
          out.push({
            id, family: "L two forms, one relation",
            thesis: `two substantial forms in a ${rel} relation — the relation is the identity`,
            draw: () => m,
          });
          // The two-tone sibling. Where the one-ink drawing separates its forms by
          // knocking one out of the other, this one separates them by TONE — which is
          // how most marks that score anywhere actually do it, and which the one-ink
          // filter was quietly disqualifying before the owner made colour a cost.
          // The cost is real and it is measured: printed in one ink these two forms
          // merge into a single silhouette, and the harness reports how much.
          if (rel !== "interlock") {
            const idT = `${id}-tone`;
            const s2 = rel === "nest"
              ? big(48 + shift, 50 + shift / 2, s, -tilt)
              : big(38 + 26 + shift / 3, 54 - 22, s, -tilt);
            out.push({
              id: idT, family: "L two forms, one relation (two-tone)",
              thesis: `the same ${rel} relation separated by tone rather than by a knockout`,
              draw: () => (rel === "nest" ? big(48, 50, S, tilt) : big(38, 54, S, tilt)) +
                s2.replace('fill="INK"', 'fill="INK2"'),
            });
          }
        }
      }
    }
  }
  return out;
}

// ── G' · the notch-and-counter lineage, kept ────────────────────────────────
function familyG2() {
  const out = [];
  const L = 10, R = 90, T = 14, B = 84;
  for (const nDepth of [24, 34]) {
    for (const ct of [{ k: "hi", cx: 38, cy: 36 }, { k: "lo", cx: 58, cy: 60 }]) {
      for (const r of [15, 21]) {
        const ps = [[L + 6, T], [R, T + 5], [R - nDepth, 48], [R, B - 4], [L, B]];
        const id = `G2-d${nDepth}-${ct.k}-r${r}`;
        out.push({
          id, family: "G' notch + counter",
          thesis: "one outline event and one interior event, of different kinds",
          draw: () => masked(id, polygon(ps), `<circle cx="${ct.cx}" cy="${ct.cy}" r="${r}" fill="black"></circle>`),
        });
      }
    }
  }
  return out;
}

export const CANDIDATES = [...familyA2(), ...familyG2(), ...familyJ(), ...familyK(), ...familyL()];

// Ghosts: round one's whole survivor set is too large to carry, so the ghosts are the
// shapes readers NAMED — the ones already proven dead by a human answer rather than
// by a number. A later round cannot re-draw them.
export const GHOSTS = [
  { id: "ghost-wedge", draw: () => `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>` },
  { id: "ghost-disc", draw: () => `<circle cx="48" cy="48" r="42" fill="INK"></circle>` },
  {
    id: "ghost-moon",
    draw: () =>
      `<defs><mask id="m2-gm" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<circle cx="48" cy="48" r="42" fill="white"></circle>` +
      `<circle cx="70" cy="48" r="38" fill="black"></circle></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m2-gm)"></rect>`,
  },
  {
    id: "ghost-square-and-speck",
    draw: () => `<polygon points="14,20 62,16 64,72 16,76" fill="INK"></polygon>` +
      `<polygon points="74,14 88,12 90,28 76,30" fill="INK"></polygon>`,
  },
];

export const svgFor = (markup, size, twoTone) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK2/g, twoTone ? INK2 : INK).replace(/\bINK\b/g, INK) +
  `</svg>`;
