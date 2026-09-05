import { CLOUD, CLOUD_GRID } from "../../brand/canvas-directions/marks.mjs";

// THE LOCKUP, under the owner's two rulings of 2026-09-05.
//
// THE MARK is the dissolving cloud — a solid cloud whose upper-right edge breaks into
// a fading grid — the owner's reference B, winner of a blind head-to-head over the
// isometric blocks. Its score ships with it and is not hidden: 51 of 100 against 36,
// three readers, and NOT a pass — "neither mark passes second-sighting; both are
// category pictures." Two drawing faults found by the scorer were fixed after that
// number, so 51 is the corrected drawing's floor. The geometry is IMPORTED from the
// one module that draws it for the brand plates, so the shell and the sheets cannot
// drift — the reason the wordmark constants are imported too.
//
// THE WORDMARK is set entirely in IOI Display, unaltered: ONE text run. The drawn I and
// the drawn Z that two reader rounds had granted are removed by the owner's ruling and
// archived with their evidence; the cost the owner chose — five readers across two
// rulings transcribed the face's Z as a 2 and its bare-stem I as a 1 at small sizes —
// is recorded on the identity sheet, not here. The only drawn element is the medial
// period, and only because the face carries no U+002E at all.
//
// SIZE: readers of the head-to-head said the mark wanted to be ~15% larger and aligned
// to cap height rather than to the box; the plates settled at 1.62x the cap. Same here.


// The mark's viewBox is the INK's bounding box on the 96-unit artboard — x 4..92,
// y 18..66 — not the artboard. The first build put the whole artboard in a
// cap-sized box and the cloud came out at 60% of it, a smudge beside the name.
const INK_BOX = "4 18 88 48";

// SIZES ARE IN EM, IN THE STYLESHEET, AND NOWHERE ELSE. The first build set the
// wordmark's font size inline from a `px` prop, which beat the narrow-width rule that
// steps the lockup down — so at 390 the name stayed at 22px and pushed the body 74px
// past the viewport. The dot's geometry (0.137em, 0.10em sides, raised 0.2815em) and
// the mark's 1.62x-cap height live in face.css in em; wordmark.mjs carries the same
// numbers for the brand plates. Nothing here re-states them.

export default function Lockup() {
  return (
    <div className="lockup">
      <svg
        className="mark"
        viewBox={INK_BOX}
        role="img"
        aria-label="decentralized.cloud"
      >
        <g className="mark-body">
          {CLOUD.map((s, i) =>
            s.r !== undefined
              ? <circle key={i} cx={s.cx} cy={s.cy} r={s.r} />
              : <rect key={i} x={s.x} y={s.y} width={s.w} height={s.h} />
          )}
        </g>
        <g className="mark-bits">
          {CLOUD_GRID.map((g, i) => (
            <rect key={i} x={g.x} y={g.y} width={g.s} height={g.s} rx="1" opacity={g.o} />
          ))}
        </g>
      </svg>
      <div className="wordmark" aria-hidden="true">
        <span>decentralized</span>
        <span className="dot" />
        <span>cloud</span>
      </div>
      {/* The accessible name is on the mark's <svg role="img" aria-label>, once. The
          wordmark is aria-hidden: a styled span pair plus a drawn dot would be read as
          fragments. */}
    </div>
  );
}
