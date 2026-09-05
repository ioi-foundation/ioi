import { useMemo } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { stamp } from "../logic/classify.mjs";
import { sourcesStage, candidatesStage, placementStage, headline } from "../logic/routing.mjs";
import { hashForSurface } from "../logic/surfaces.mjs";
import Freshness from "./Freshness.jsx";
import Routing from "./Routing.jsx";

// THE HERO IS THE PRODUCT PERFORMING.
//
// Not a description of the router beside a stat box: the cheapest live quote the
// daemon holds right now, at display size, with its own observation window visibly
// running out beneath it; then the four figures a routing decision is made of; then the
// routing itself, drawn from those figures. Every number is the daemon's, read on this
// visit, and the one moving element on the page moves because a real window is closing.
//
// ONE FOCAL POINT. The price. The statement above it is set small on purpose — a
// second headline fighting the figure is the two-column hero the readers killed.
//
// THREE READS ARRIVE AT THREE SPEEDS — candidates in about a second, the advisory in a
// few, sources in half a minute — and the hero paints each part as it lands rather than
// waiting for the slowest. A figure that has not arrived says "…" and its column says
// "asking"; nothing is drawn at zero to fill the wait.

const price = (usd) => {
  // Four decimals, because these quotes are quoted in tenths of a cent and $0.01 would
  // round the cheapest of them to nothing. Split so the currency and the unit can be
  // set small beside a large figure without being separated from it.
  const s = usd.toFixed(4);
  return { whole: s.slice(0, s.indexOf(".")), frac: s.slice(s.indexOf(".")) };
};

export default function Hero() {
  const intent = intentRef();
  const cands = useSurfaceRead("candidates", `/api/candidates?intent_ref=${encodeURIComponent(intent)}&latest=true`);
  const sources = useSurfaceRead("sources", "/api/candidate-sources");
  const advisory = useSurfaceRead("placement", `/api/placement-advisory?intent_ref=${encodeURIComponent(intent)}`);

  const stages = useMemo(
    () => ({
      sources: sourcesStage(sources.data),
      candidates: candidatesStage(cands.data),
      placement: placementStage(advisory.data),
    }),
    [sources.data, cands.data, advisory.data]
  );
  const figures = headline(stages);
  const cheapest = stages.candidates?.cheapest || null;
  const anyStale = cands.stale || sources.stale || advisory.stale;

  return (
    <section className="hero" aria-labelledby="hero-statement">
      <h1 id="hero-statement" className="hero-statement">
        One request. Every venue asked. One placement, with a receipt.
      </h1>

      <div className="hero-focus">
        {cheapest ? (
          <>
            <div className="eyebrow hero-eyebrow">cheapest live quote right now</div>
            <p className="hero-price" aria-label={`${cheapest.quote.usd_per_hour.toFixed(4)} US dollars per GPU hour`}>
              <span className="hero-cur">$</span>
              <span className="hero-figure">
                {price(cheapest.quote.usd_per_hour).whole}
                <span className="hero-frac">{price(cheapest.quote.usd_per_hour).frac}</span>
              </span>
              <span className="hero-unit">/ GPU · hour</span>
            </p>
            <p className="hero-what">
              <span className="hero-venue">{cheapest.display_name || cheapest.provider_kind}</span>
              {cheapest.gpu?.vram_gb ? <span> · {cheapest.gpu.vram_gb} GB</span> : null}
              {cheapest.region ? <span> · {cheapest.region}</span> : null}
              <span className="hero-basis mono"> · {cheapest.quote.basis}</span>
            </p>
            <Freshness observedAt={cheapest.observed_at} expiresAt={cheapest.expires_at} size="hero" />
            <p className="hero-observed mono">
              observed {stamp(cheapest.observed_at)} · sweep {stages.candidates.batch}
              {anyStale ? " · a newer read is in flight" : ""}
            </p>
          </>
        ) : cands.phase === "first" ? (
          <>
            <div className="eyebrow hero-eyebrow">asking the daemon for the latest sweep</div>
            <p className="hero-price hero-price-waiting" aria-live="polite">
              <span className="hero-figure">…</span>
            </p>
            <p className="hero-what">The cheapest live quote will stand here, with the time it is still good for. Nothing is shown until the daemon answers.</p>
          </>
        ) : (
          <>
            <div className="eyebrow hero-eyebrow">no live quote in the latest sweep</div>
            <p className="hero-price hero-price-waiting"><span className="hero-figure">—</span></p>
            <p className="hero-what">No candidate passes the live rule right now, and no price has been invented to stand here.</p>
          </>
        )}
      </div>

      {/* The four figures ARE the drawing's column heads — one row of numbers, not
          two. The first build printed them as a separate row above the routing and the
          picture showed the same four numbers twice, ten lines apart. */}
      <Routing sources={stages.sources} candidates={stages.candidates} placement={stages.placement} figures={figures} />

      <div className="hero-doors">
        <a className="button hero-door" href={hashForSurface("job")}>Submit a job — dry run, nothing spent</a>
        <a className="hero-door-link" href={hashForSurface("candidates")}>All live prices →</a>
        <a className="hero-door-link" href={hashForSurface("placement")}>Why this placement →</a>
      </div>
    </section>
  );
}
