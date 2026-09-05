import { Chip } from "./Bits.jsx";

// THE ROUTING, DRAWN. Four columns — sources asked, venues quoting, candidates in the
// latest sweep, one recommended — each a stack sized to its count, joined by bands.
//
// The columns are on a SQUARE-ROOT scale, and the legend says so. On a linear scale
// the single recommended placement is a four-pixel sliver beside a 48-candidate stack
// and a reader cannot see the one thing the drawing exists to point at; on a log scale
// thirteen and forty-eight look nearly the same height. Square root keeps the order
// and keeps the one visible. It is a drawing choice, and a drawing choice that changes
// what a number LOOKS like has to be printed beside the numbers.
//
// The drawing WIDENS in the middle, because the data does: two venues answer with
// forty-eight candidates. A strip that only ever narrowed would be a picture of a shape
// these numbers do not have.
//
// Colour: green is the live-evidence share of a column — a quoting source, a live
// priced candidate — and nothing else is green. Everything that did not make it is
// drawn in the ground's own grey, with its reason printed under the column.
//
// A stage whose body has not arrived is drawn as NOTHING with the word "asking" under
// it. An empty column a reader would take for zero is a false number.

const W = 1000, H = 200, COL = 26;
const XS = [40, 340, 640, 940 - COL];
const scale = (n, max) => (n > 0 && max > 0 ? Math.max(6, (H - 20) * Math.sqrt(n / max)) : 0);

// ONE MARK PER THING COUNTED. A column is a stack of `total` marks, the bottom `live`
// of them green, so thirteen sources are thirteen visible rows and forty-seven
// candidates are forty-seven — a stack a reader can count is a stack that cannot be
// faked, which is what makes this the product rather than a diagram of it. The stack's
// overall height is on the square-root scale above; the marks divide it.
function Column({ x, total, live, max, tone }) {
  if (total === null) return null;
  const h = scale(total, max);
  const n = Math.max(total, 1);
  const gap = total > 1 ? Math.min(1.5, h / n / 4) : 0;
  const unit = (h - gap * (n - 1)) / n;
  const cls = tone ? `rt-stage rt-${tone}` : "rt-stage";
  return (
    <g>
      {Array.from({ length: total }, (_, i) => {
        const y = H - (i + 1) * unit - i * gap;
        const isLive = live !== null && i < live;
        return <rect key={i} x={x} y={y} width={COL} height={unit} className={isLive ? "rt-live" : cls} />;
      })}
    </g>
  );
}

// A band from the LIVE share of one column to the WHOLE of the next: what passed on.
function Band({ from, to, fromH, toH }) {
  if (!fromH || !toH) return null;
  const x1 = from + COL, x2 = to;
  const y1 = H - fromH, y2 = H - toH;
  const d = `M ${x1} ${y1} C ${x1 + 120} ${y1}, ${x2 - 120} ${y2}, ${x2} ${y2} L ${x2} ${H} L ${x1} ${H} Z`;
  return <path d={d} className="rt-band" />;
}

export default function Routing({ sources, candidates, placement, figures }) {
  const counts = {
    sources: sources ? sources.asked : null,
    sourcesLive: sources ? sources.quoting.length : null,
    venues: candidates ? candidates.venues.length : null,
    inSweep: candidates ? candidates.inSweep : null,
    live: candidates ? candidates.live : null,
    placed: placement ? (placement.recommended ? 1 : 0) : null,
  };
  const max = Math.max(counts.sources || 0, counts.inSweep || 0, 1);
  const h = {
    s: counts.sources !== null ? scale(counts.sources, max) : 0,
    sLive: counts.sources !== null ? (scale(counts.sources, max) * (counts.sourcesLive || 0)) / Math.max(counts.sources, 1) : 0,
    v: counts.venues !== null ? scale(counts.venues, max) : 0,
    c: counts.inSweep !== null ? scale(counts.inSweep, max) : 0,
    cLive: counts.inSweep !== null ? (scale(counts.inSweep, max) * (counts.live || 0)) / Math.max(counts.inSweep, 1) : 0,
    p: counts.placed !== null ? scale(counts.placed, max) : 0,
  };

  return (
    <figure className="routing" aria-label="How the latest sweep was routed: sources asked, venues quoting, candidates, one recommended">
      <svg className="rt" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true" focusable="false">
        <Band from={XS[0]} to={XS[1]} fromH={h.sLive} toH={h.v} />
        <Band from={XS[1]} to={XS[2]} fromH={h.v} toH={h.c} />
        <Band from={XS[2]} to={XS[3]} fromH={h.cLive} toH={h.p} />
        <Column x={XS[0]} total={counts.sources} live={counts.sourcesLive} max={max} />
        <Column x={XS[1]} total={counts.venues} live={counts.venues} max={max} />
        <Column x={XS[2]} total={counts.inSweep} live={counts.live} max={max} />
        <Column x={XS[3]} total={counts.placed} live={null} max={max} tone="placed" />
        <line x1="0" y1={H - 0.5} x2={W} y2={H - 0.5} className="rt-base" />
      </svg>

      {/* The heads sit under their stacks at every width — four columns, always. The
          reasons beneath them need room to be read, so they go four-across on a desk
          and one-across on a phone, each prefixed with the set it belongs to. */}
      {/* The heads are the hero's four figures, from routing.mjs's headline() — each
          the TOTAL of the stack above it, under the same set name the population line
          uses, so a reader can reconcile this band with Candidates or Placement by
          name. */}
      <ol className="rt-heads" aria-label="The routing, in four numbers">
        {figures.map((f) => (
          <li key={f.key} className="rt-head">
            <div className="rt-n">{f.n === null ? "…" : f.n.toLocaleString("en-US")}</div>
            <div className="rt-set">{f.label}</div>
          </li>
        ))}
      </ol>
      <div className="rt-details">
        <div className="rt-cell">
          <div className="rt-set rt-set-repeat">sources asked</div>
          {sources ? (
            <ul className="rt-why">
              {sources.quoting.map((n) => <li key={n} className="rt-live-word">{n} · quoting</li>)}
              {sources.notQuoting.map((s) => <li key={s.name}>{s.name} · {s.why}</li>)}
            </ul>
          ) : <div className="rt-wait">asking the daemon — this read takes about half a minute</div>}
        </div>
        <div className="rt-cell">
          <div className="rt-set rt-set-repeat">venues quoting</div>
          {candidates ? (
            <ul className="rt-why">
              {candidates.venues.map((v) => (
                <li key={v} className="rt-live-word">{v} · {candidates.liveByVenue[v]} live</li>
              ))}
            </ul>
          ) : <div className="rt-wait">asking</div>}
        </div>
        <div className="rt-cell">
          <div className="rt-set rt-set-repeat">candidates in the latest sweep</div>
          {candidates ? (
            <ul className="rt-why">
              <li className="rt-live-word">{candidates.live} live-priced</li>
              {candidates.notLive.map((c) => <li key={c.name}>{c.name} · {c.why}</li>)}
            </ul>
          ) : <div className="rt-wait">asking</div>}
        </div>
        <div className="rt-cell">
          <div className="rt-set rt-set-repeat">placement recommended</div>
          {placement ? (
            placement.recommended ? (
              <div className="rt-rec">
                <div className="rt-rec-name">{placement.recommended.name}</div>
                <div className="rt-chips">
                  {placement.recommended.reasonCodes.map((c) => <Chip key={c} kind="muted">{c}</Chip>)}
                </div>
                <div className="rt-why-line">
                  of {placement.eligible ?? "…"} eligible across every sweep held
                  {placement.feeMinted === false ? " · no fee minted" : ""}
                </div>
              </div>
            ) : <div className="rt-wait">no candidate eligible — nothing chosen to fill the gap</div>
          ) : <div className="rt-wait">asking the daemon for its advisory</div>}
        </div>
      </div>
      <figcaption className="rt-caption mono">
        column height is on a square-root scale of the count, so the one recommended placement stays visible beside the candidate stack · green is live evidence and nothing else is
      </figcaption>
    </figure>
  );
}
