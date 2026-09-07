import { classify } from "./classify.mjs";
import { latestBatch, summarise } from "./batches.mjs";
import { SETS } from "./population.mjs";

// THE ROUTING, AS ONE DRAWING — the hero's single derivation. Framework-free.
//
// The product's whole claim fits in one line: some sources were asked, a few quoted,
// candidates came back, one was recommended, and every one of those numbers expires.
// A cold reader put it better than the surface ever had: "that is a NARROWING and it is
// DECAYING, and both are inherently visual." So the landing draws it — and this module
// is the one place the drawing's numbers come from, so the picture and the population
// line beneath it cannot disagree. Every count here is the same count the counting
// surfaces publish, under the same set name from population.mjs.
//
// IT IS NOT A FUNNEL, AND THE DRAWING MUST NOT PRETEND IT IS. 13 sources narrow to 2
// quoting venues, which then FAN OUT to 48 candidates, which narrow to one placement.
// A strip that only ever narrows would be a picture of a shape the numbers do not have.
// The stages carry their true counts and the renderer is expected to draw them at
// their true relative size, widening where the data widens.
//
// NOTHING IS INVENTED TO FILL A STAGE. A stage whose body has not arrived yet is
// `null` and the renderer says "asking" there, rather than drawing an empty band that
// a reader would take for zero.

// Why a source did not quote, in the daemon's own state word. The vocabulary is the
// daemon's `state` field, unparaphrased; the catalog module maps these to chip words,
// and this module deliberately does not, because a second mapping is a second spine.
const SOURCE_STATE_WORD = {
  live_quote_source: "quoting",
  available: "available, no price",
  storage_backends_engaged: "storage, no price",
  credential_preflight_only: "connected, no adapter",
  candidate_source_unavailable: "no source",
};

export function sourcesStage(sourcesBody) {
  const list = Array.isArray(sourcesBody?.sources) ? sourcesBody.sources : null;
  if (!list) return null;
  const quoting = list.filter((s) => s.state === "live_quote_source");
  const rest = list.filter((s) => s.state !== "live_quote_source");
  return {
    asked: list.length,
    quoting: quoting.map((s) => s.source),
    // Every source that did not quote, with the daemon's state word beside it.
    notQuoting: rest.map((s) => ({
      name: s.source,
      why: SOURCE_STATE_WORD[s.state] || s.state || "state absent",
    })),
  };
}

export function candidatesStage(candidatesBody) {
  const items = Array.isArray(candidatesBody?.candidates) ? candidatesBody.candidates : null;
  if (!items) return null;
  const { latest } = latestBatch(items);
  const { live, venues, cheapest } = summarise(latest.items);
  const considered =
    typeof candidatesBody?.selection?.considered === "number" ? candidatesBody.selection.considered : null;
  // Every candidate the live rule REFUSED, with the clause that refused it — the same
  // reason string Candidates renders in its "not live, and why" list.
  const notLive = latest.items
    .filter((c) => !classify(c).live)
    .map((c) => ({
      name: c.display_name || c.provider_kind || "unnamed candidate",
      venue: c.provider_kind || null,
      why: classify(c).reason,
    }));
  // Live count per venue, from the same live set — the number the routing prints
  // beside each quoting venue, so "2 venues quoting" is checkable from where it is made.
  const liveByVenue = {};
  for (const c of live) liveByVenue[c.provider_kind] = (liveByVenue[c.provider_kind] || 0) + 1;
  return {
    inSweep: latest.items.length,
    live: live.length,
    venues,
    liveByVenue,
    cheapest,
    notLive,
    held: considered,
    batch: latest.key,
    observed: latest.observed || null,
  };
}

export function placementStage(advisoryBody) {
  if (!advisoryBody || typeof advisoryBody !== "object") return null;
  const rec = advisoryBody.recommendation || null;
  return {
    recommended: rec
      ? {
          name: rec.display_name || rec.venue || "unnamed",
          venue: rec.venue || null,
          candidateRef: rec.candidate_ref || null,
          reasonCodes: Array.isArray(rec.reason_codes) ? rec.reason_codes : [],
        }
      : null,
    eligible: typeof advisoryBody.eligible === "number" ? advisoryBody.eligible : null,
    considered: typeof advisoryBody.considered === "number" ? advisoryBody.considered : null,
    feeMinted: advisoryBody.fee_object_minted ?? null,
    at: advisoryBody.at || null,
    ref: advisoryBody.advisory_ref || null,
  };
}

// The four figures the hero states, each with the SAME set name the population line
// uses — so a reader can put the hero beside Candidates or Placement and reconcile
// them by name. Null means "not read yet", never zero.
export function headline({ sources, candidates, placement }) {
  return [
    { key: "sources", n: sources ? sources.asked : null, label: SETS.sources },
    { key: "venues", n: candidates ? candidates.venues.length : null, label: SETS.venues },
    // The stack's TOTAL, not its live share: the drawing's third column is the whole
    // sweep with the live-priced part in green, and a head that named a different
    // number than the column it sat under would be two figures disagreeing on purpose.
    // The live count is printed in the column's detail, in the live colour.
    { key: "sweep", n: candidates ? candidates.inSweep : null, label: SETS.batch },
    { key: "placement", n: placement ? (placement.recommended ? 1 : 0) : null, label: "placement recommended" },
  ];
}
