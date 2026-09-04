// WIDE GENERATION, ROUND SIX — across primitives, not within one.
//
// Round five's reader N wrote the diagnosis of the previous five rounds, unasked:
//
//   "The whole sheet is one vocabulary: right angles, one stroke weight, one bite.
//    There is no curve, no diagonal, no dot, no crossing stroke anywhere in 100 marks.
//    That is why so many collapse into 'a C' or 'a box' — you have removed every axis
//    on which a viewer could tell two of them apart. Variety inside a single primitive
//    is not variety."
//
// And: "Nothing here reads as cloud, network, distribution, or connection. If a theme
// was intended, it did not arrive; my first words were furniture and punctuation."
//
// That is correct and it indicts the SEARCH rather than any drawing. Each round
// narrowed onto the previous round's survivor, and the narrowing compounded until I
// was sampling one primitive — a rectilinear mass with a rectilinear subtraction — a
// hundred ways and calling it width. Nine readers have now said the same thing in
// five vocabularies.
//
// So this round deliberately does the opposite. Every family below introduces an axis
// no previous round had, and they are the four the reader named — curve, diagonal,
// dot, crossing stroke — plus one that answers the theme complaint.
//
// THE 16px FLOOR, applied to every family by construction rather than by hope: one
// device pixel is six grid units, so no stroke is thinner than 18 units (3px) and no
// element smaller than 20 units across. Round five's thin wrap-around limbs were one
// or two device pixels and both readers called them artifacts.
//
// HAZARDS BANNED BY NAME, cumulative across every round, none of which may be
// generated: cloud silhouette, share glyph, power symbol, arrow, location pin, hang
// tag, loading spinner, hash mark, checkbox, folder, floppy disk, and the letterforms
// C, L, U, D, O, S, Z and the digits 0, 2, 7.

export const GRID = 96;
export const INK = "#0d0f12";
export const INK2 = "#8f98a3";
export const GROUND = "#ffffff";

const R2 = (n) => Math.round(n * 100) / 100;
const rad = (d) => (d * Math.PI) / 180;
const pts = (ps) => ps.map(([x, y]) => `${R2(x)},${R2(y)}`).join(" ");
const stroke = (d, w, colour = "INK", cap = "butt") =>
  `<path d="${d}" fill="none" stroke="${colour}" stroke-width="${w}" ` +
  `stroke-linecap="${cap}" stroke-linejoin="miter"></path>`;

const CANDS = [];

// ── P · curve against straight ──────────────────────────────────────────────
// One mass whose boundary is genuinely part arc and part straight line — not a
// rounded rectangle, where the curve is a corner treatment, but a shape where a true
// arc of substantial radius meets flat edges at a visible junction. No previous round
// contained a curve at all.
for (const r of [30, 40, 50]) {
  for (const sweep of [110, 160, 215]) {
    for (const flat of ["base", "left", "both"]) {
      for (const start of [200, 265, 330]) {
        const cx = 48, cy = 48;
        const a0 = rad(start), a1 = rad(start + sweep);
        const p0 = [cx + r * Math.cos(a0), cy + r * Math.sin(a0)];
        const p1 = [cx + r * Math.cos(a1), cy + r * Math.sin(a1)];
        const large = sweep > 180 ? 1 : 0;
        // The arc, then closed by straight runs — so the silhouette carries one curve
        // and two or three hard edges, and the junction between them is the event.
        let d = `M ${R2(p0[0])} ${R2(p0[1])} A ${r} ${r} 0 ${large} 1 ${R2(p1[0])} ${R2(p1[1])}`;
        if (flat === "base") d += ` L ${R2(p1[0])} 84 L ${R2(p0[0])} 84 Z`;
        else if (flat === "left") d += ` L 12 ${R2(p1[1])} L 12 ${R2(p0[1])} Z`;
        else d += ` L ${R2(p1[0])} 84 L 12 84 L 12 ${R2(p0[1])} Z`;
        const id = `P-r${r}-s${sweep}-${flat}-a${start}`;
        CANDS.push({
          id, family: "P curve meeting straight",
          intent: "capacity — a volume with one soft face",
          thesis: `an arc of radius ${r} sweeping ${sweep} degrees, closed by flat edges — one true curve, which no previous round contained`,
          draw: () => `<path d="${d}" fill="INK"></path>`,
        });
      }
    }
  }
}

// ── Q · diagonal-led ────────────────────────────────────────────────────────
// A construction whose PRIMARY axis is a diagonal, as opposed to a rectilinear form
// rotated a few degrees. Both round-five readers were explicit that a small rotation
// reads as a defect — "the icon is crooked" — so nothing here is a tilt: the diagonal
// is the structure, at angles far from both cardinal and 45.
for (const ang of [28, 62, 118]) {
  for (const w of [20, 28]) {
    for (const bars of [2, 3]) {
      for (const spread of [22, 34]) {
        const parts = [];
        for (let i = 0; i < bars; i++) {
          // Unequal lengths by construction: a set of equal parallel bars is the
          // vocabulary round one was killed for.
          const len = 34 + i * 13;
          const off = (i - (bars - 1) / 2) * spread;
          const nx = Math.cos(rad(ang + 90)) * off, ny = Math.sin(rad(ang + 90)) * off;
          const dx = Math.cos(rad(ang)) * len / 2, dy = Math.sin(rad(ang)) * len / 2;
          parts.push(stroke(
            `M ${R2(48 + nx - dx)} ${R2(48 + ny - dy)} L ${R2(48 + nx + dx)} ${R2(48 + ny + dy)}`, w));
        }
        const id = `Q-a${ang}-w${w}-b${bars}-s${spread}`;
        CANDS.push({
          id, family: "Q diagonal-led",
          intent: "throughput — work moving on a line",
          thesis: `${bars} bars of unequal length on a ${ang}-degree axis — the diagonal is the structure, not a rotation`,
          draw: () => parts.join(""),
        });
      }
    }
  }
}

// ── R · a mass and a dot ────────────────────────────────────────────────────
// A separate disc, at a size that survives: 22 units is 3.7 device pixels at product
// size. Round one's family F failed because its second element was a speck; this one
// is never below a third of the mass, and it always touches or overlaps.
for (const dr of [12, 16, 20]) {
  for (const at of [[30, 30], [66, 32], [64, 66]]) {
    for (const shape of ["quad", "arc"]) {
      for (const overlap of [true, false]) {
        const body = shape === "quad"
          ? `<polygon points="16,22 78,22 78,80 16,80" fill="INK"></polygon>`
          : `<path d="M 16 80 L 16 46 A 31 31 0 0 1 78 46 L 78 80 Z" fill="INK"></path>`;
        const id = `R-d${dr}-${at[0]}x${at[1]}-${shape}-${overlap ? "knock" : "sit"}`;
        const dot = `<circle cx="${at[0]}" cy="${at[1]}" r="${dr}" fill="${overlap ? "black" : "INK"}"></circle>`;
        const markup = overlap
          ? `<defs><mask id="m6-${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
            `<rect width="96" height="96" fill="black"></rect>` +
            body.replace(/fill="INK"/, 'fill="white"') + dot +
            `</mask></defs><rect width="96" height="96" fill="INK" mask="url(#m6-${id})"></rect>`
          : body + dot;
        CANDS.push({
          id, family: "R mass and dot",
          intent: "a venue with one job placed in it",
          thesis: `a disc of radius ${dr} — ${(dr * 2 / 6).toFixed(1)} device pixels across at product size — ${overlap ? "knocked out of" : "sitting on"} a ${shape} mass`,
          draw: () => markup,
        });
      }
    }
  }
}

// ── S · crossing strokes ────────────────────────────────────────────────────
// Two strokes that actually cross, which round three set out to build and never
// achieved. Here the crossing is guaranteed: the two strokes are chords of the same
// frame through a shared interior point, so they cannot miss each other.
for (const a1 of [24, 55]) {
  for (const a2 of [104, 143]) {
    for (const w of [19, 26]) {
      for (const px of [40, 56]) {
        for (const cut of [0, 7]) {
          const L = 78;
          const s1 = `M ${R2(px - Math.cos(rad(a1)) * L / 2)} ${R2(48 - Math.sin(rad(a1)) * L / 2)} ` +
            `L ${R2(px + Math.cos(rad(a1)) * L / 2)} ${R2(48 + Math.sin(rad(a1)) * L / 2)}`;
          const s2 = `M ${R2(px - Math.cos(rad(a2)) * L / 2)} ${R2(48 - Math.sin(rad(a2)) * L / 2)} ` +
            `L ${R2(px + Math.cos(rad(a2)) * L / 2)} ${R2(48 + Math.sin(rad(a2)) * L / 2)}`;
          const id = `S-${a1}x${a2}-w${w}-p${px}-c${cut}`;
          const markup = cut
            ? `<defs><mask id="m6-${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
              `<rect width="96" height="96" fill="black"></rect>` +
              stroke(s1, w, "white") + stroke(s2, w + cut * 2, "black") +
              `</mask></defs><rect width="96" height="96" fill="INK" mask="url(#m6-${id})"></rect>` +
              stroke(s2, w)
            : stroke(s1, w) + stroke(s2, w);
          CANDS.push({
            id, family: cut ? "S crossing strokes, one in front" : "S crossing strokes, fused (control)",
            intent: "two routes meeting and one taking precedence",
            thesis: `two strokes at ${a1} and ${a2} degrees crossing off-centre${cut ? ", one passing in front" : " with no over/under — the control"}`,
            draw: () => markup,
          });
        }
      }
    }
  }
}

// ── T · many into one ───────────────────────────────────────────────────────
// The theme complaint answered directly: this is a router, and what a router does is
// take several arrivals and produce one departure. Several strokes converge and one
// leaves — unequal in count, never symmetric, no terminal nodes (nodes are what make
// the share glyph, which is banned by name).
for (const inN of [2, 3, 4]) {
  for (const spread of [30, 52]) {
    for (const w of [17, 23]) {
      for (const meet of [40, 56]) {
        const parts = [];
        for (let i = 0; i < inN; i++) {
          const a = 180 - spread / 2 + (inN === 1 ? 0 : (i * spread) / (inN - 1));
          parts.push(stroke(
            `M ${R2(meet + Math.cos(rad(a)) * 42)} ${R2(48 + Math.sin(rad(a)) * 42)} L ${meet} 48`, w));
        }
        parts.push(stroke(`M ${meet} 48 L 88 48`, w + 5));
        const id = `T-i${inN}-s${spread}-w${w}-m${meet}`;
        CANDS.push({
          id, family: "T many into one",
          intent: "many requests, one route out — what a router does",
          thesis: `${inN} strokes arriving and one leaving, the departure heavier — what the product actually does`,
          draw: () => parts.join(""),
        });
      }
    }
  }
}

export const CANDIDATES = CANDS;

// Everything a reader has NAMED across three phases, carried for the silhouette
// comparison only — never plated, never scored.
export const GHOSTS = [
  { id: "ghost-wedge", draw: () => `<polygon points="8,28 88,3 88,93 8,68" fill="INK"></polygon>` },
  { id: "ghost-disc", draw: () => `<circle cx="48" cy="48" r="42" fill="INK"></circle>` },
  {
    id: "ghost-broken-ring",
    draw: () => `<path d="M 78 30 A 34 34 0 1 1 60 18" fill="none" stroke="INK" stroke-width="18"></path>`,
  },
  {
    id: "ghost-checkbox",
    draw: () =>
      `<defs><mask id="m6-gc" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<rect x="14" y="14" width="68" height="68" fill="white"></rect>` +
      `<rect x="30" y="30" width="36" height="36" fill="black"></rect></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m6-gc)"></rect>`,
  },
  {
    id: "ghost-breach",
    draw: () =>
      `<defs><mask id="m6-gb" maskUnits="userSpaceOnUse" x="0" y="0" width="96" height="96">` +
      `<rect width="96" height="96" fill="black"></rect>` +
      `<rect x="11" y="11" width="74" height="74" fill="white"></rect>` +
      `<rect x="30" y="-8" width="46" height="46" fill="black"></rect></mask></defs>` +
      `<rect width="96" height="96" fill="INK" mask="url(#m6-gb)"></rect>`,
  },
];

export const svgFor = (markup, size, twoTone) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
  `<rect width="${GRID}" height="${GRID}" fill="${GROUND}"></rect>` +
  markup.replace(/INK2/g, twoTone ? INK2 : INK).replace(/\bINK\b/g, INK) +
  `</svg>`;
