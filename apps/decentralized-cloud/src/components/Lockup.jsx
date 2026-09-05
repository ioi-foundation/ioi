import { CAP, UPM, Z_PATH, Z_ADVANCE, DOT_DIAMETER_EM, DOT_SIDE_EM, DOT_RAISE_EM } from "../../brand/wordmark/wordmark.mjs";

// THE LOCKUP — and the port's one real improvement over the surface it replaces.
//
// The static shell carried the Z path as a literal, and brand/wordmark/wordmark.mjs
// claimed to be its one source while nothing enforced that. I added a gate that reads
// the SERVED BYTES and compares them to the module's constant, and mutation-tested it.
//
// This component does something the static shell could not: it IMPORTS the constant.
// Drift is now impossible rather than merely detected — there is no second copy to
// drift from. The served-bytes gate stays anyway, because it is the assertion that
// proves the thing a visitor receives carries the value, and a build step is exactly
// the kind of transform that can quietly drop one.
//
// THE Z IS DRAWN, and only here. IOI Display's own Z (gid 30; the face is unicase)
// has a curved upper-left terminal and reads as a numeral 2 — the brand's own name
// misspelled by its own typeface. Three fresh readers on narrow plates typed a digit
// for exactly one variant in a field of twenty, and it was the face's own. The
// adopted path differs from the previous override in one number: the diagonal is cut
// 1.7x the bar rather than 1.35x, elbow flush at the corners. The mechanism the
// readers named is a corner, not a terminal: "it is a bend versus a corner, and at
// 13px the bend wins."
//
// IOI.ttf is UNTOUCHED. It is the estate's brand face and other products set their
// wordmarks in it; whether the same misread exists there is the owner's call.
//
// The face carries no U+002E either, which is why the period has always had to be
// drawn — a mechanical necessity, not a style ruling.

export default function Lockup({ px = 22 }) {
  const capPx = (px * CAP) / UPM;
  const dotPx = px * DOT_DIAMETER_EM;
  return (
    <div className="lockup">
      <div className="wordmark" style={{ fontSize: `${px}px` }} aria-hidden="true">
        <span>decentrali</span>
        <svg
          className="wm-z"
          width={(capPx * Z_ADVANCE) / CAP}
          height={capPx}
          viewBox={`0 -${CAP} ${Z_ADVANCE} ${CAP}`}
          aria-hidden="true"
          focusable="false"
        >
          <g transform="scale(1,-1)">
            <path d={Z_PATH} fill="currentColor" />
          </g>
        </svg>
        <span>ed</span>
        <span
          className="dot"
          style={{
            width: `${dotPx.toFixed(2)}px`,
            height: `${dotPx.toFixed(2)}px`,
            margin: `0 ${(px * DOT_SIDE_EM).toFixed(2)}px`,
            top: `-${(px * DOT_RAISE_EM).toFixed(2)}px`,
          }}
        />
        <span>cloud</span>
      </div>
      {/* The accessible name lives here rather than on the decorative wordmark, so a
          screen reader is told the product's name once, in words, instead of being
          read a drawn glyph and a styled span. */}
      <span className="sr-only">decentralized.cloud</span>
    </div>
  );
}
