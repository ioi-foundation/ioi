import { classify } from "./classify.mjs";

// THE LATEST BATCH, AND WHY THE OLDER EVIDENCE IS SET ASIDE RATHER THAN MIXED IN.
//
// A long-lived intent accumulates every sweep the daemon has ever run against it. If
// the surface simply rendered `candidates`, a quote taken four minutes ago would sit
// in the same table as one taken a fortnight ago, in the same type, under the same
// heading — and the page would become a place where prices go to be misread.
//
// So the page reads the LATEST BATCH and says how much older evidence it set aside.
// Framework-free, because the rule is not about rendering.

export function latestBatch(candidates) {
  const all = Array.isArray(candidates) ? candidates : [];
  const batches = new Map();
  for (const c of all) {
    const key = c.batch || "unbatched";
    const entry = batches.get(key) || { key, observed: "", items: [] };
    entry.items.push(c);
    if ((c.observed_at || "") > entry.observed) entry.observed = c.observed_at || "";
    batches.set(key, entry);
  }
  const ordered = [...batches.values()].sort((a, b) => (a.observed < b.observed ? 1 : -1));
  const latest = ordered[0] || { key: "none", observed: "", items: [] };
  return {
    latest,
    setAside: all.length - latest.items.length,
    batchCount: ordered.length,
  };
}

// The live set, the venues quoting it, and the cheapest — all derived from the ONE
// rule in classify.mjs. Nothing here re-implements liveness: a second definition of
// "live" on this surface is exactly the second spine the estate's structural law
// forbids, and it is how a simulator lane would eventually be counted toward a fee.
export function summarise(candidates) {
  const live = candidates.filter((c) => classify(c).live);
  const venues = [...new Set(live.map((c) => c.provider_kind))].sort();
  const cheapest = live.length
    ? live.reduce((a, b) => (a.quote.usd_per_hour <= b.quote.usd_per_hour ? a : b))
    : null;
  return { live, venues, cheapest };
}

// TWO VENUES IS THE LINE, and it is a line about what may be CLAIMED, not a display
// preference. A routing decision needs at least two venues to be a decision at all;
// with one, the intent can be priced but not routed, and no fee may be minted against
// it. The surface says which of those it is looking at, in words, every time.
export function venueVerdict({ live, venues }) {
  if (venues.length >= 2) {
    return {
      routable: true,
      heading: `${live.length} live quotes, across ${venues.length} venues`,
      body:
        `Two or more venues are quoting (${venues.join(", ")}), so this intent can be ` +
        "compared and routed, not merely priced.",
    };
  }
  return {
    routable: false,
    heading: `${live.length} live quote${live.length === 1 ? "" : "s"}, from ${venues.length === 1 ? "one venue" : "no venue"}`,
    body:
      "A routing decision needs at least two venues to be a decision at all. " +
      (venues.length === 1
        ? `Every quote below is real and every one of them is ${venues[0]}, so this intent can be priced but not routed, and no fee can be minted against it.`
        : "Nothing here is priced, and no price has been invented to fill the gap. " +
          "Quotes are good for about fifteen minutes, and taking a fresh one is a write " +
          "this surface does not perform — so an intent nobody has refreshed lately shows " +
          "its evidence expired rather than a price it cannot stand behind."),
  };
}
