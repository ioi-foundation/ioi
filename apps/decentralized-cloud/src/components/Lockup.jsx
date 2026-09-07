import { GRADIENT, WORDMARK_BOX, TEXT_TOP, TEXT_BOTTOM, DOT } from "../../brand/mark/mark.mjs";
import AnimatedMark from "./AnimatedMark.jsx";

// THE LOCKUP — the owner's animated primary lockup, from its one source.
//
// THE MARK is the owner's cloud whose face opens into a network, and in the header
// it MOVES: the owner ruled (2026-09-07) that the site header carries the animated
// version of the primary lockup, and AnimatedMark.jsx is the owner's replica engine
// drawn from brand/mark/mark.mjs — the module the asset check and the face gate read
// too. Under reduced motion it is the owner's static mark-dark.svg, verbatim. The
// three-lobe mark and the earlier cloud that preceded it are asserted ABSENT from
// the served bytes.
//
// THE WORDMARK is set entirely in IOI Display, unaltered, as live text — the owner's
// ruling of 2026-09-05 stands: one run per line, no drawn letters. Two lines,
// DECENTRALIZED small over CLOUD large, set INSIDE AN SVG so each line is placed by
// its baseline. The only drawn element is the dot — the face has no U+002E — and it
// is a brand device: a rounded square on the baseline carrying the gradient.
//
// SIZE is in em on .lockup in the stylesheet: 1em is the wordmark block height and
// the mark's height is a multiple of it declared there, with the reason.

const DotGradient = ({ id }) => (
  <linearGradient id={id} x1={GRADIENT.x1} y1={GRADIENT.y1} x2={GRADIENT.x2} y2={GRADIENT.y2}>
    <stop offset="0" stopColor={GRADIENT.from} />
    <stop offset="1" stopColor={GRADIENT.to} />
  </linearGradient>
);

export default function Lockup() {
  return (
    <div className="lockup">
      <AnimatedMark />
      {/* The accessible name is on the mark, once. The wordmark is aria-hidden: two
          text runs plus a drawn dot would be read as fragments. */}
      <svg className="wordmark" viewBox={WORDMARK_BOX} aria-hidden="true">
        <defs><DotGradient id="dc-dot-g" /></defs>
        <text
          className="wm-top"
          x={TEXT_TOP.x}
          y={TEXT_TOP.y}
          fontSize={TEXT_TOP.fontSize}
          textLength={TEXT_TOP.length}
          lengthAdjust="spacing"
        >
          decentralized
        </text>
        <rect
          className="dot"
          x={DOT.x}
          y={DOT.y}
          width={DOT.size}
          height={DOT.size}
          rx={DOT.radius}
          fill="url(#dc-dot-g)"
        />
        <text
          className="wm-bottom"
          x={TEXT_BOTTOM.x}
          y={TEXT_BOTTOM.y}
          fontSize={TEXT_BOTTOM.fontSize}
          textLength={TEXT_BOTTOM.length}
          lengthAdjust="spacing"
        >
          cloud
        </text>
      </svg>
    </div>
  );
}
