#!/usr/bin/env node
// M15.1 done-bar — decentralized.cloud live quoting.
//
// Proves the public face can be given real, evidence-bearing, expiring quotes from
// live provider adapters, and that a simulator candidate can never be mistaken for
// one. READ-ONLY: it opens a quoting intent and refreshes candidates. It never calls
// provider-ops, never leases anything, and never spends. The live Vast lifecycle
// harness (verify-hypervisor-vast-lifecycle.mjs with IOI_VAST_LIVE=1) is a SPEND
// harness and is deliberately not what this file does.
//
// PASS CONDITION: at least two distinct live VENUES, where a venue is a
// `provider_kind` that produced at least one candidate the daemon labelled
// live_evidence. One venue is a real, reportable PARTIAL — not a pass. The count of
// live candidates and the count of distinct `source` values are reported as separate
// labelled facts precisely so a large candidate count can never stand in for venue
// diversity.
//
// The live-vs-simulator label is mutation-tested below: the same classifier that
// admits real candidates is fed hand-built records with the label corrupted one way
// at a time, and every one of them must be refused. A classifier that cannot fail on
// its own finding is not a check.
//
// Usage: node apps/hypervisor/scripts/verify-decentralized-cloud-live-quotes.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REQUIRED_LIVE_VENUES = 2;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

// ── The classifier under test ────────────────────────────────────────────────
//
// A candidate counts as LIVE only if every one of these holds. Each rejection
// names itself, so a FAIL says which property was missing rather than "not live".
// `nowMs` is a parameter so expiry is testable without waiting fifteen minutes.
function classifyCandidate(c, nowMs) {
  if (!c || typeof c !== "object") return { live: false, reason: "not_a_candidate" };
  const labels = Array.isArray(c.eligibility_labels) ? c.eligibility_labels : [];
  if (labels.includes("simulated_control_plane")) return { live: false, reason: "simulated_control_plane" };
  if (c.evidence_mode !== "live_evidence") return { live: false, reason: `evidence_mode=${c.evidence_mode ?? "absent"}` };
  const q = c.quote;
  if (!q || typeof q !== "object") return { live: false, reason: "quote_absent" };
  if (q.evidence_mode !== "live_evidence") return { live: false, reason: `quote.evidence_mode=${q.evidence_mode ?? "absent"}` };
  if (typeof q.usd_per_hour !== "number" || !(q.usd_per_hour >= 0)) return { live: false, reason: "quote.usd_per_hour_absent" };
  if (!q.basis) return { live: false, reason: "quote.basis_absent" };
  if (!c.observed_at) return { live: false, reason: "observed_at_absent" };
  if (!c.expires_at) return { live: false, reason: "expires_at_absent" };
  const expires = Date.parse(c.expires_at);
  if (!Number.isFinite(expires)) return { live: false, reason: "expires_at_unparseable" };
  if (expires <= nowMs) return { live: false, reason: "expired" };
  if (typeof c.provider_kind !== "string" || !c.provider_kind) return { live: false, reason: "provider_kind_absent" };
  return { live: true, reason: "live_evidence" };
}

const liveVenues = (cands, nowMs) =>
  [...new Set(cands.filter((c) => classifyCandidate(c, nowMs).live).map((c) => c.provider_kind))].sort();

// ── Mutation battery on the label ────────────────────────────────────────────
//
// One well-formed live record, then that same record broken one way at a time. The
// positive control matters as much as the mutants: a classifier that refuses
// everything would pass a rejection-only battery while proving nothing.
const NOW = Date.parse("2026-01-01T12:00:00Z");
const WELL_FORMED = Object.freeze({
  provider_kind: "vast",
  source: "depin_market",
  evidence_mode: "live_evidence",
  placement_eligible: true,
  observed_at: "2026-01-01T11:55:00Z",
  expires_at: "2026-01-01T12:10:00Z",
  eligibility_labels: ["placement_eligible", "quote_live"],
  quote: { evidence_mode: "live_evidence", usd_per_hour: 0.25, basis: "vast offer dph_total (verbatim)" },
});
const mutate = (patch) => ({ ...WELL_FORMED, ...patch });

const MUTANTS = [
  ["a simulator lane wearing a live label is refused", mutate({ eligibility_labels: ["placement_eligible", "simulated_control_plane"] }), "simulated_control_plane"],
  ["a simulator evidence_mode is refused", mutate({ evidence_mode: "simulated" }), "evidence_mode=simulated"],
  ["a missing evidence_mode is refused", mutate({ evidence_mode: undefined }), "evidence_mode=absent"],
  ["a candidate with no quote is refused", mutate({ quote: undefined }), "quote_absent"],
  ["a live candidate carrying a simulated quote is refused", mutate({ quote: { ...WELL_FORMED.quote, evidence_mode: "simulated" } }), "quote.evidence_mode=simulated"],
  ["a quote with no price is refused", mutate({ quote: { ...WELL_FORMED.quote, usd_per_hour: undefined } }), "quote.usd_per_hour_absent"],
  ["a quote with no stated basis is refused", mutate({ quote: { ...WELL_FORMED.quote, basis: undefined } }), "quote.basis_absent"],
  ["a candidate with no observed_at is refused", mutate({ observed_at: undefined }), "observed_at_absent"],
  ["a candidate with no expires_at is refused", mutate({ expires_at: undefined }), "expires_at_absent"],
  ["an expired quote is refused however it is labelled", mutate({ expires_at: "2026-01-01T11:59:59Z" }), "expired"],
];

function runMutationBattery() {
  const control = classifyCandidate(WELL_FORMED, NOW);
  ok("mutation control: a well-formed live candidate is ADMITTED", control.live === true, control.reason);

  for (const [name, mutant, expectedReason] of MUTANTS) {
    const verdict = classifyCandidate(mutant, NOW);
    ok(`mutation: ${name}`, verdict.live === false && verdict.reason === expectedReason,
      `got live=${verdict.live} reason=${verdict.reason}`);
  }

  // The venue counter is the pass condition's arithmetic, so it gets its own anchor:
  // three candidates from one provider are one venue, not three.
  const threeOfOne = [WELL_FORMED, WELL_FORMED, WELL_FORMED];
  ok("mutation: three candidates from one provider_kind count as ONE venue",
    liveVenues(threeOfOne, NOW).length === 1, `got ${liveVenues(threeOfOne, NOW).length}`);
  const twoKinds = [WELL_FORMED, mutate({ provider_kind: "runpod", source: "direct_provider" })];
  ok("mutation: two provider_kinds count as TWO venues",
    liveVenues(twoKinds, NOW).length === 2, `got ${liveVenues(twoKinds, NOW).join(",")}`);
  const oneLiveOneSim = [WELL_FORMED, mutate({ provider_kind: "runpod", eligibility_labels: ["simulated_control_plane"] })];
  ok("mutation: a simulator venue never raises the venue count",
    liveVenues(oneLiveOneSim, NOW).length === 1, `got ${liveVenues(oneLiveOneSim, NOW).join(",")}`);
}

async function run() {
  runMutationBattery();

  // ── Sources: health, in the daemon's own words ────────────────────────────
  const sourcesRes = await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources");
  ok("candidate-sources answers", sourcesRes.status === 200, `HTTP ${sourcesRes.status}`);
  const sources = sourcesRes.j.sources || sourcesRes.j.candidate_sources || [];
  ok("candidate-sources enumerates sources", Array.isArray(sources) && sources.length > 0, `${sources.length} sources`);

  const unavailable = sources.filter((s) => s.state === "candidate_source_unavailable");
  ok("every unavailable source states a named reason rather than staying silent",
    unavailable.every((s) => typeof s.reason === "string" && s.reason.length > 0),
    `${unavailable.length} unavailable`);

  // ── Quoting: intent, then refresh. No mutation, no spend. ─────────────────
  const intentRes = await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime",
    resource_classes: ["compute.gpu_runtime"],
    gpu: { required: true },
  });
  const intentRef = intentRes.j.intent?.intent_ref;
  ok("a quoting intent opens", !!intentRef, `HTTP ${intentRes.status}`);
  if (!intentRef) return;

  const refreshRes = await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intentRef });
  ok("candidates refresh answers", refreshRes.status === 200, `HTTP ${refreshRes.status}`);
  const candidates = refreshRes.j.candidates || [];
  const now = Date.now();

  const live = candidates.filter((c) => classifyCandidate(c, now).live);
  const venues = liveVenues(candidates, now);
  const liveSources = [...new Set(live.map((c) => c.source))].sort();

  // Three separate counts, reported separately on purpose.
  ok(`FACT live candidates: ${live.length}`, true);
  ok(`FACT distinct live venues (provider_kind): ${venues.length} [${venues.join(", ") || "none"}]`, true);
  ok(`FACT distinct live sources (origin class): ${liveSources.length} [${liveSources.join(", ") || "none"}]`, true);

  // ── Evidence discipline on whatever came back ─────────────────────────────
  ok("no candidate labelled simulated_control_plane is counted live",
    !live.some((c) => (c.eligibility_labels || []).includes("simulated_control_plane")), "");
  ok("every live candidate carries observed_at, expires_at and a stated quote basis",
    live.every((c) => c.observed_at && c.expires_at && c.quote?.basis), `${live.length} live`);
  ok("every live quote is still inside its validity window",
    live.every((c) => Date.parse(c.expires_at) > now), "");
  ok("every live candidate carries a quote_ref its price can be traced to",
    live.every((c) => typeof c.quote?.quote_ref === "string" && c.quote.quote_ref.length > 0), "");
  const quoted = candidates.filter((c) => c.quote && typeof c.quote.usd_per_hour === "number");
  ok("no candidate carries a price without live evidence behind it",
    quoted.every((c) => classifyCandidate(c, now).live), `${quoted.length} priced`);

  // ── The pass condition ────────────────────────────────────────────────────
  ok(`at least ${REQUIRED_LIVE_VENUES} distinct live venues are quoting`,
    venues.length >= REQUIRED_LIVE_VENUES,
    `${venues.length} of ${REQUIRED_LIVE_VENUES} — [${venues.join(", ") || "none"}]`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`decentralized.cloud live quoting: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
