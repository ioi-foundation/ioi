// ONE POPULATION, NAMED THE SAME WAY EVERYWHERE IT IS COUNTED.
//
// Four cold readers, independently, could not reconcile the numbers across surfaces:
//
//   "Placement says 4514 considered; Candidates says 45 live quotes; Sources counts 13
//    sources. Three different population sizes on three pages of the same product, with
//    no stated relationship between any pair."
//
//   "45 vs 47 vs 4514 … 4514 is a hundredfold larger than 45; 47 exceeds 45 by two.
//    Nothing says these count different things."
//
// They DO count different things, and every one of them is correct. That is precisely
// why it was damaging: a reader cannot tell an honest funnel from an inconsistency
// unless the funnel is drawn. Three true numbers with no stated relationship read as
// three claims that cannot all be true.
//
// The funnel, from the daemon's own bodies:
//
//   SOURCES asked ──▶ CANDIDATES held (every sweep ever) ──▶ the LATEST BATCH
//        ──▶ those that pass the LIVE rule ──▶ across N VENUES
//   and, separately, the advisory's own view: ELIGIBLE out of CONSIDERED.
//
// The rule this file enforces is not that the numbers agree — they should not, they
// measure different sets — but that WHEREVER A COUNT IS PUBLISHED, THE SET IT COUNTS IS
// NAMED IN THE SAME WORDS. A count is only honest if a reader can check it from where
// it is made, and they cannot check what they cannot name.

// The vocabulary. One noun per set, used by every surface, so two pages can be
// reconciled by reading them side by side rather than by trusting me.
// Each entry names the SET and its UNIT, because two of these numbers differ by unit
// rather than by set and a reader cannot see that from the digits. A reader:
// "Candidates says runpod: 21. Sources says runpod gpu_types_priced 39. The vast pair
// reconciles exactly — 24 and 24 — and the one that reconciles makes the one that does
// not look like an error rather than a difference in units."
// It is a difference in units: 21 live CANDIDATES for this intent's class, against 39
// catalog GPU TYPES the venue prices at all. Both true, neither comparable.
export const SETS = {
  sources: "sources asked",
  held: "candidates held, across every sweep",
  batch: "candidates in the latest sweep",
  live: "candidates live right now",
  venues: "venues quoting",
  considered: "candidates considered by the advisory",
  eligible: "candidates eligible for placement",
};

const n = (v) => (typeof v === "number" && Number.isFinite(v) ? v.toLocaleString("en-US") : null);

// One line, from whichever counts the calling surface actually has. Absent counts are
// OMITTED rather than rendered as zero or a dash — a surface that has not read the
// advisory must not imply it read it and found nothing.
export function populationLine(counts = {}) {
  const parts = [];
  if (n(counts.live) !== null) parts.push(`${n(counts.live)} ${SETS.live}`);
  if (n(counts.venues) !== null) parts.push(`${n(counts.venues)} ${SETS.venues}`);
  if (n(counts.batch) !== null) parts.push(`${n(counts.batch)} ${SETS.batch}`);
  if (n(counts.held) !== null) parts.push(`${n(counts.held)} ${SETS.held}`);
  if (n(counts.eligible) !== null) parts.push(`${n(counts.eligible)} ${SETS.eligible}`);
  if (n(counts.considered) !== null) parts.push(`${n(counts.considered)} ${SETS.considered}`);
  if (n(counts.sources) !== null) parts.push(`${n(counts.sources)} ${SETS.sources}`);
  return parts.join(" · ");
}

// The sentence that makes the funnel checkable. Rendered wherever a surface publishes a
// count that a reader could mistake for one of the others.
export const FUNNEL_NOTE =
  "These count different sets, narrowing left to right: every source asked, every " +
  "candidate ever swept for this intent, the latest sweep only, and the ones that pass " +
  "the live rule right now. The advisory counts its own two — eligible out of " +
  "considered — over every candidate held, not over the live ones. Counts on Sources " +
  "are in a different unit again: what a venue's catalog offers, not what it quoted " +
  "for this intent.";
