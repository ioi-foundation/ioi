import {
  CAP, UPM, Z_PATH, Z_ADVANCE, I_PATH, I_ADVANCE,
  DOT_DIAMETER_EM, DOT_SIDE_EM, DOT_RAISE_EM,
} from "../../brand/wordmark/wordmark.mjs";

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
      {/* THE MARK, carried across from the static shell unchanged.
          The mark hunt has since been capped — six rounds, ~1,300 candidates, thirteen
          fresh readers, zero granted by two — and this drawing is the owner's reserved
          form, shipped as identity v0 provisional. It is not mine to redraw and not
          mine to remove, and ioi-c0 ruled explicitly that it stays untouched pending an
          owner ruling on the naming question.
          I dropped it from the first version of this component — not by deciding to,
          but by writing a new lockup and not carrying it over. Removing the product's
          only mark by omission is still removing it, and the screenshot is what caught
          it: every gate was green, because no gate asserts the mark exists. */}
      <svg className="mark" width="31" height="31" viewBox="0 0 96 96" role="img" aria-label="decentralized.cloud">
        <defs>
          <mask id="cloud-cue" maskUnits="userSpaceOnUse" x="-20" y="-20" width="136" height="136">
            <rect x="-20" y="-20" width="136" height="136" fill="#ffffff" />
            <rect x="65.38" y="24.03" width="15" height="6.2" rx="3.1" fill="#000000" />
          </mask>
        </defs>
        <rect x="0" y="0" width="96" height="96" rx="11" fill="#0a0e19" />
        <g mask="url(#cloud-cue)">
          <g transform="translate(9.500 13.743) scale(0.71369)">
            <path d="M 41.44 0.00 C 38.66 0.00 36.33 2.13 36.09 4.90 L 34.09 27.84 L 79.17 27.84 L 75.70 67.48 L 103.42 67.48 L 107.83 17.16 C 108.63 7.94 101.36 0.00 92.10 0.00 Z" fill="#ffffff" />
            <path d="M 10.57 27.84 C 7.79 27.84 5.46 29.97 5.22 32.75 L 3.14 56.51 L 26.66 56.51 C 29.45 56.51 31.77 54.39 32.01 51.61 L 34.09 27.84 Z" fill="#ffffff" />
            <path d="M 17.71 68.00 C 8.93 68.07 1.66 74.86 0.97 83.61 L 0.00 96.00 L 73.47 96.00 L 75.71 67.47 Z" fill="#ffffff" />
          </g>
        </g>
      </svg>
      <div className="wordmark" style={{ fontSize: `${px}px` }} aria-hidden="true">
        {/* The run breaks HERE, before the I, because the I is drawn. I had this wrong
            in the first version of this component: I adopted the drawn I into the one
            source and into the static shell, and left the React lockup setting
            "decentrali" in the face — so the ported surface shipped the bare stem
            three readers had just rejected. The gate caught it, which is the whole
            reason the gate reads the served bytes rather than the module. */}
        <span>decentral</span>
        <svg
          className="wm-i"
          width={(capPx * I_ADVANCE) / CAP}
          height={capPx}
          viewBox={`0 -${CAP} ${I_ADVANCE} ${CAP}`}
          aria-hidden="true"
          focusable="false"
        >
          <g transform="scale(1,-1)">
            <path d={I_PATH} fill="currentColor" />
          </g>
        </svg>
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
      {/* The accessible name is on the MARK's <svg role="img" aria-label>, and nowhere
          else. The wordmark is aria-hidden because it is drawn glyphs and styled spans
          — a screen reader walking it would read the product's name as fragments. I
          briefly had an sr-only span here saying the name a second time, which would
          have announced it twice. */}
    </div>
  );
}
