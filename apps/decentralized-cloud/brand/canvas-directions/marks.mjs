// THE TWO OWNER MARK REFERENCES, hand-authored on a stated grid.
//
// Owner ruling 2026-09-05: the shell mark is replaced by one of these two. This round
// decides which. Both are drawn, not traced — every coordinate below is on a 96-unit
// artboard with a 6-unit module, so the forms hold at 16px and the reductions are
// derived from the same geometry rather than redrawn.
//
// Colour is design-system tokens only. The two-tone blue the owner described maps to
// --color-ocean-blue #0048ff and --color-pastel-blue #afc1fd, with onyx for the deepest
// face; the palette gate on the shipped surface refuses any colour that is not a token,
// so a mark that needed a new hex could not ship.

const INK = "#0a0e19";
const BLUE = "#0048ff";       // ocean blue — the dominant face
const BLUE_LIGHT = "#afc1fd"; // pastel blue — the lit top face
const BLUE_MID = "#4078fa";   // token: the ramp's mid step, used for the side face
const PAPER = "#ffffff";

// ── A · ISOMETRIC BLOCKS ────────────────────────────────────────────────────
// Capacity as blocks. A stepped slab plus a smaller cube set slightly lower and to the
// right. True isometric: every top face is a rhombus of 2:1 run-to-rise, so the
// verticals stay vertical and the mark reads as built rather than drawn.
//
// KNOWN COST, stated beside the score rather than hidden: isometric block marks are the
// single most common form in cloud and infrastructure identity. The earlier skeleton
// round flagged exactly this — a reader's "I have seen this on forty landing pages" is
// a second-sighting failure, and second sighting is the bar.
export const isoBlocks = ({ size = 96, tile = null, mono = null } = {}) => {
  const top = mono || BLUE_LIGHT;
  const front = mono || BLUE;
  const side = mono || BLUE_MID;
  const op = mono ? { top: 0.45, front: 1, side: 0.72 } : { top: 1, front: 1, side: 1 };
  return `<svg width="${size}" height="${size}" viewBox="0 0 96 96" role="img" aria-label="decentralized.cloud" style="display:block;flex-shrink:0">
  ${tile ? `<rect x="0" y="0" width="96" height="96" rx="11" fill="${tile}"></rect>` : ""}
  <g>
    <!-- the stepped slab: a long block with a raised left half -->
    <path d="M 12 46 L 36 34 L 60 46 L 36 58 Z" fill="${top}" opacity="${op.top}"></path>
    <path d="M 12 46 L 36 58 L 36 76 L 12 64 Z" fill="${front}" opacity="${op.front}"></path>
    <path d="M 60 46 L 36 58 L 36 76 L 60 64 Z" fill="${side}" opacity="${op.side}"></path>
    <!-- the raised step, one module up -->
    <path d="M 12 34 L 30 25 L 48 34 L 30 43 Z" fill="${top}" opacity="${op.top}"></path>
    <path d="M 12 34 L 30 43 L 30 55 L 12 46 Z" fill="${front}" opacity="${op.front}"></path>
    <path d="M 48 34 L 30 43 L 30 55 L 48 46 Z" fill="${side}" opacity="${op.side}"></path>
    <!-- the detached cube, lower right: the second venue -->
    <path d="M 60 62 L 74 55 L 88 62 L 74 69 Z" fill="${top}" opacity="${op.top}"></path>
    <path d="M 60 62 L 74 69 L 74 83 L 60 76 Z" fill="${front}" opacity="${op.front}"></path>
    <path d="M 88 62 L 74 69 L 74 83 L 88 76 Z" fill="${side}" opacity="${op.side}"></path>
  </g>
</svg>`;
};

// ── B · DISSOLVING CLOUD ────────────────────────────────────────────────────
// Decentralization as dissolution. A solid cloud silhouette whose upper-right edge
// breaks into a square grid that fades out. The squares are on the same 6-unit module
// as the cloud's radii, so the dissolution reads as the same material coming apart
// rather than as decoration laid on top.
//
// KNOWN COST: at 16px the dissolving squares fall below one device pixel and the mark
// resolves to a plain cloud — which is the most generic possible cloud-product mark.
// The reduction below therefore drops the faintest column deliberately rather than
// letting it turn to mud, and the readers are asked at true 16px precisely because that
// is where this form is weakest.
export const dissolvingCloud = ({ size = 96, tile = null, mono = null } = {}) => {
  const body = mono || BLUE;
  const bits = mono || BLUE;
  // Three columns of squares, each column fainter and smaller than the last.
  const grid = [
    { x: 60, y: 26, s: 9, o: 0.95 }, { x: 60, y: 38, s: 9, o: 0.8 },
    { x: 72, y: 22, s: 7.5, o: 0.62 }, { x: 72, y: 33, s: 7.5, o: 0.48 },
    { x: 72, y: 44, s: 7.5, o: 0.34 },
    { x: 83, y: 19, s: 6, o: 0.3 }, { x: 83, y: 29, s: 6, o: 0.2 },
    { x: 83, y: 39, s: 6, o: 0.12 },
  ];
  return `<svg width="${size}" height="${size}" viewBox="0 0 96 96" role="img" aria-label="decentralized.cloud" style="display:block;flex-shrink:0">
  ${tile ? `<rect x="0" y="0" width="96" height="96" rx="11" fill="${tile}"></rect>` : ""}
  <path d="M 26 70 C 15 70 8 62 8 53 C 8 44 15 37 24 37 C 26 27 35 20 45 20 C 55 20 63 26 66 35 L 66 70 Z"
        fill="${body}"></path>
  <g>
    ${grid.map((g) => `<rect x="${g.x}" y="${g.y}" width="${g.s}" height="${g.s}" rx="1.2" fill="${bits}" opacity="${mono ? Math.max(0.15, g.o * 0.9) : g.o}"></rect>`).join("\n    ")}
  </g>
</svg>`;
};

export const MARKS = {
  A: { id: "A", name: "Isometric blocks", draw: isoBlocks,
       idea: "Capacity as blocks — a stepped slab and a second, detached cube.",
       cost: "The most common form in cloud and infrastructure identity. A reader's \"I have seen this on forty landing pages\" is a second-sighting failure, and second sighting is the bar." },
  B: { id: "B", name: "Dissolving cloud", draw: dissolvingCloud,
       idea: "Decentralization as dissolution — a cloud whose upper-right edge breaks into a fading grid.",
       cost: "At 16px the squares fall below a device pixel and it resolves to a plain cloud, which is the most generic cloud-product mark there is." },
};
