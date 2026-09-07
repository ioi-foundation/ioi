import {
  MARK_BOX, MARK_PATHS, GRADIENT, WORDMARK_BOX, TEXT_TOP, TEXT_BOTTOM, DOT,
} from "../../brand/mark/mark.mjs";

// THE LOCKUP — the designer's mark of 2026-09-06, from its one source.
//
// THE MARK is three lobes of a cloud, each a rounded slab leaning right, in the cloud
// gradient. Its geometry is IMPORTED from brand/mark/mark.mjs — the module the asset
// builder and the face gate read too — so the shell, the downloadable SVGs and the
// assertion cannot drift. It replaces the dissolving cloud (owner's reference B,
// scored 51/100, never a pass); that drawing stays in brand/canvas-directions/marks.mjs
// for the plates that judged it and is asserted ABSENT from the served bytes.
//
// THE WORDMARK is set entirely in IOI Display, unaltered, as live text — the owner's
// ruling of 2026-09-05 stands: one run per line, no drawn letters. The designer's file
// outlines the same face glyph for glyph, so the two agree by construction. It is two
// lines now, DECENTRALIZED small over CLOUD large, and it is set INSIDE AN SVG so each
// line is placed by its baseline: HTML line boxes place text by ascender metrics, and
// this face's tables put the baseline 0.15em apart between platforms. The only drawn
// element is the dot — the face has no U+002E — and it is a brand device: a rounded
// square on the baseline carrying the gradient, spaced before CLOUD as a sixth letter.
//
// SIZE is in em on .lockup in the stylesheet and nowhere else: 1em is the block
// height, both SVGs are sized from it, and the narrow-width rule steps the pair down
// as one object.

const Gradient = ({ id }) => (
  <linearGradient id={id} x1={GRADIENT.x1} y1={GRADIENT.y1} x2={GRADIENT.x2} y2={GRADIENT.y2}>
    <stop offset="0" stopColor={GRADIENT.from} />
    <stop offset="1" stopColor={GRADIENT.to} />
  </linearGradient>
);

export default function Lockup() {
  return (
    <div className="lockup">
      <svg className="mark" viewBox={MARK_BOX} role="img" aria-label="decentralized.cloud">
        <defs><Gradient id="dc-mark-g" /></defs>
        <g fill="url(#dc-mark-g)">
          {MARK_PATHS.map((d, i) => <path key={i} d={d} />)}
        </g>
      </svg>
      {/* The accessible name is on the mark, once. The wordmark is aria-hidden: two
          text runs plus a drawn dot would be read as fragments. */}
      <svg className="wordmark" viewBox={WORDMARK_BOX} aria-hidden="true">
        <defs><Gradient id="dc-dot-g" /></defs>
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
