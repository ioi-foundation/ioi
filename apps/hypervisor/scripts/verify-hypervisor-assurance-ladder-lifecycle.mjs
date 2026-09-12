#!/usr/bin/env node
// check:assurance-ladder-lifecycle — M06.1, against an ISOLATED real daemon.
//
// THE ONE THING THIS GATE ADDS, and the reason it is a separate file. Two sibling gates already
// exist: `check:assurance-transition-receipt` proves the transition SEAM over an ontology-revision
// subject, and `check:verified-work-graph` proves the WorkResult resolver and the consumer
// PROJECTION. Neither drives the ladder past `accepted`, and the second says in its own header that
// it makes no claim the M06.1 progression exists. So this gate drives the PROGRESSION — all six
// members, `attested → evidenced → verified → accepted → adjudicated → settled`, one at a time, on
// a work object — and proves what only a full walk can: that every outcome class survives the whole
// climb, that a challenge resolution is claimable at exactly one rung, and that arriving at the top
// is not a verdict about the work underneath.
//
// It deliberately does NOT restate the sibling's consumer assertions (census shape, unreached-stage
// independence, contract-version downgrade, bound-version history). Re-asserting them here would be
// a second set of answers waiting to disagree with the first; they are cited, not copied.
//
// THE SUBJECT IS A NEGATIVE WORK RESULT ON PURPOSE. A ladder walked only over a success has not
// been shown to retain anything. This one climbs to `settled` over a WorkResult whose owner says
// `negative`, which is the exact place a consumer that read "settled" as "good" would be caught.
//
// REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the ladder afterwards and
// requires the transition count and head to be exactly what they were. A 4xx that still appended is
// the failure this shape exists to catch.
//
// "REACHING SETTLED GRANTS NOTHING" IS MEASURED. The authority-bearing families are read before the
// walk and after it and required to be byte-identical, rather than asserted from the nonclaim
// strings the record carries.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutate   plant named defects in the daemon's own source, rebuild, re-run this file against
//              each mutant, and require it to redden the ONE assertion it names. A mutant that
//              reddens something else is reported as a MISS, never quietly counted.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const LADDER_SOURCE = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/assurance_transition_routes.rs");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });

const STAGES = ["attested", "evidenced", "verified", "accepted", "adjudicated", "settled"];
// Frozen by canonical-enums.md. Transcribed here rather than read from the daemon: a gate that
// imported the producer's own list would agree with it by construction.
const OUTCOME_CLASSES = ["positive", "negative", "inconclusive", "invalid", "exploit", "superseded", "disputed", "no_fault"];
const NONCLAIMS = ["correctness", "acceptance", "settlement"];

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-assurance-ladder-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let daemonLog = "";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
}

const req = (method, p, body = null, { authenticated = true } = {}) => fetch(`${DAEMON}${p}`, {
  method,
  headers: {
    "content-type": "application/json",
    ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...(body === null ? {} : { body: JSON.stringify(body) }),
}).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, j: {} }));

const AT = "/v1/hypervisor/assurance-transitions";
const WR = "/v1/hypervisor/work-results";
const VWG = "/v1/hypervisor/verified-work-graph";
const code = (j) => j?.code ?? j?.error?.code ?? "";

const graphOf = async (subject) =>
  (await req("GET", `${VWG}?work_result_ref=${encodeURIComponent(subject)}`)).j?.verified_work_graph ?? null;

/// The ladder's observable state, so a refusal can be counted BY EFFECT rather than by its status.
const ladderState = async (subject) => {
  const graph = await graphOf(subject);
  return {
    count: graph?.transition_count ?? null,
    reached: graph?.reached_stage ?? null,
    head: graph?.transitions?.at(-1)?.content_hash ?? null,
  };
};

/// The exact stream head a successor must compare against, read from the ladder rather than
/// remembered, so a refusal assertion below fails for its OWN cause and not for a stale head.
const currentHead = async (subject) => {
  const { j } = await req("GET", `${AT}?subject_ref=${encodeURIComponent(subject)}`);
  const rows = j?.assurance_transitions ?? j?.transitions ?? [];
  return rows.at(-1)?.admission?.admission_head ?? null;
};

/// Authority-bearing families. Reaching `settled` must move none of them.
///
/// EVERY ONE OF THESE IS ASSERTED TO ANSWER 200 before the comparison is believed. A route that does
/// not exist answers 404 both times and compares equal, so a mistyped family would report "nothing
/// moved" while observing nothing at all — the same vacuity a comparison of two empty sets has.
/// `/v1/hypervisor/standing-leases` was in this list and is not a route (standing leases hang off
/// `/connectors/:id/standing-lease`), which is exactly how that was caught.
const AUTHORITY_FAMILIES = [
  "/v1/hypervisor/capability-leases",
  "/v1/hypervisor/connectors",
  "/v1/hypervisor/governance/approval-requests",
  "/v1/hypervisor/authority/grants",
  "/v1/hypervisor/authority/receipts",
];
const withoutResponseStamp = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const { at: _generatedAt, ...state } = body;
  return state;
};
const snapshotAuthority = async () => {
  const snapshot = {};
  const answered = [];
  for (const route of AUTHORITY_FAMILIES) {
    const { status, j } = await req("GET", route);
    if (status === 200) answered.push(route);
    snapshot[route] = `${status}:${JSON.stringify(withoutResponseStamp(j))}`;
  }
  snapshot.__answered = answered.join(",");
  return snapshot;
};

let transitionSeq = 0;
const transitionBody = (subject, { outcome, head, stage, extra = {} }) => {
  transitionSeq += 1;
  const body = {
    owner_ref: "org://local",
    idempotency_key: `ladder-${transitionSeq}-${stage}`,
    subject_ref: subject,
    outcome_class: outcome,
    evidence_refs: [`evidence://assurance-ladder/${stage}/${transitionSeq}`],
    does_not_assert: NONCLAIMS,
    valid_time: { starts_at: "2026-03-01T00:00:00Z", ends_at: null },
    // The stage is ASSERTED, never chosen: the daemon derives it from the ladder's own length, and
    // asserting it is how a caller learns it disagreed rather than silently landing elsewhere.
    to_stage: stage,
    ...extra,
  };
  if (head !== null) body.expected_head = head;
  return body;
};

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();

  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req("POST", "/v1/hypervisor/auth/bootstrap",
    { token, password: "assurance-ladder-v1", email: "assurance-ladder@ioi.local" }, { authenticated: false });
  SESSION = boot.j?.session_token ?? "";
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  // -- the subject: a REAL WorkResult its owner calls NEGATIVE ------------------
  const admitted = await req("POST", WR, {
    goal_ref: "goal://m061-ladder-lifecycle",
    result_profile: "research",
    outcome_class: "negative",
    status: "completed",
    claim_refs: ["evidence://m061-ladder-observation-1"],
    supporting_evidence_refs: ["artifact://m061-ladder-a1"],
  });
  const SUBJECT = admitted.j?.work_result?.work_result_id ?? "";
  ok("PRECONDITION: the ladder climbs over a REAL WorkResult its own owner admitted, and that owner calls the work NEGATIVE",
    admitted.status === 201 && SUBJECT.startsWith("work-result://") && admitted.j?.work_result?.outcome_class === "negative",
    `${admitted.status} ${SUBJECT}`);

  const authorityBefore = await snapshotAuthority();

  // -- the full progression, one member at a time -------------------------------
  //
  // Six outcome classes are carried up the ladder, one per rung, so the climb itself proves the
  // vocabulary survives every position rather than only the first.
  const climb = [
    { stage: "attested", outcome: "inconclusive" },
    { stage: "evidenced", outcome: "negative" },
    { stage: "verified", outcome: "exploit" },
    { stage: "accepted", outcome: "disputed" },
    // A REJECTED resolution is the only one that may carry `no_fault`: the daemon couples the typed
    // resolution to the outcome class so a SUSTAINED finding can never be recorded as a clean pass.
    // The upheld/rejected coupling is asserted in its own right below.
    { stage: "adjudicated", outcome: "no_fault", extra: {
      challenge_resolution: {
        verifier_challenge_id: "verifier-challenge://m061/ladder/1",
        resolution: "rejected",
        adjudicator_ref: "org://local",
        adjudicator_policy_ref: "policy://ioi/assurance/adjudication/v1",
        reviewer_lineage: [
          { reviewer_ref: "org://local", reviewed_at: "2026-03-02T00:00:00Z", review_decision: "rejected" },
        ],
      },
    } },
    { stage: "settled", outcome: "superseded" },
  ];
  let head = null;
  const rungs = [];
  for (const [index, rung] of climb.entries()) {
    const reply = await req("POST", AT, transitionBody(SUBJECT, { ...rung, head }));
    const record = reply.j?.assurance_transition ?? reply.j?.transition ?? null;
    rungs.push({ rung, status: reply.status, record, code: code(reply.j) });
    // The successor's compare-and-swap value is the STREAM head the route hands back, not the
    // record's own content hash — they are different numbers, and presenting the second is how a
    // climb silently stops at rung two.
    head = reply.j?.expected_head_for_successor ?? head;
    if (index === 0 && reply.status >= 400) break;
  }
  const landed = rungs.filter((r) => r.status === 201 || r.status === 200);
  ok("every member of the ladder is reachable in order: attested → evidenced → verified → accepted → adjudicated → settled",
    landed.length === STAGES.length
      && landed.every((r, i) => r.record?.to_stage === STAGES[i] && r.record?.to_stage_ordinal === i + 1),
    rungs.map((r) => (r.record ? `${r.record.to_stage}@${r.record.to_stage_ordinal}` : `${r.rung.stage}:${r.status} ${r.code}`)).join(" → "));

  const graph = await graphOf(SUBJECT);
  ok("the ladder reaches settled as SIX distinct transitions, each its own object with its own actor and evidence",
    graph?.reached_stage === "settled" && graph?.transition_count === 6
      && graph.transitions.every((t) => typeof t.actor_ref === "string" && t.actor_ref.startsWith("user://")
        && Array.isArray(t.evidence_refs) && t.evidence_refs.length > 0),
    `reached ${graph?.reached_stage} · ${graph?.transition_count} transitions`);
  ok("every stage row is reached independently and carries its own transition, so nothing about settlement is inferable from acceptance",
    (graph?.stages ?? []).length === 6
      && graph.stages.every((row, i) => row.stage === STAGES[i] && row.reached === true
        && typeof row.transition_ref === "string" && row.transition_ref.length > 0)
      && new Set(graph.stages.map((row) => row.transition_ref)).size === 6,
    (graph?.stages ?? []).map((s) => s.stage).join(","));

  // -- the six carried classes survive the whole climb, verbatim ----------------
  const carried = climb.map((r) => r.outcome);
  const census = graph?.outcome_class_census ?? {};
  ok("every outcome class carried up the ladder survives the whole climb, counted verbatim and never normalised toward positive",
    carried.every((outcome) => census[outcome] === 1) && (census.positive ?? 0) === 0,
    JSON.stringify(census));
  ok("the census still carries ALL EIGHT frozen members, including the ones with no rows",
    OUTCOME_CLASSES.every((outcome) => Object.prototype.hasOwnProperty.call(census, outcome)),
    `${Object.keys(census).length} members`);

  // -- a receipt is not a verdict (ACC-8 clause 3) ------------------------------
  ok("a ladder that reaches SETTLED does not rewrite the work: the owner's own outcome_class is still NEGATIVE",
    graph?.work_result_outcome_class === "negative",
    `work_result_outcome_class=${graph?.work_result_outcome_class}`);
  ok("the projection carries its authority and verdict nonclaims and the transition's own, explicitly",
    typeof graph?.authority_nonclaim === "string" && typeof graph?.verdict_nonclaim === "string"
      && graph?.transition_authority_nonclaim === "assurance_transition_grants_no_authority"
      && graph?.transition_verdict_nonclaim === "assurance_transition_is_not_a_verdict"
      && Array.isArray(graph?.does_not_assert) && graph.does_not_assert.length > 0,
    `${graph?.transition_verdict_nonclaim}`);
  ok("every transition on the ladder declares what it does not assert, at every rung including settled",
    (graph?.transitions ?? []).every((t) => Array.isArray(t.does_not_assert) && t.does_not_assert.length > 0),
    "");

  // MEASURED, not asserted from the nonclaim strings.
  const authorityAfter = await snapshotAuthority();
  const moved = AUTHORITY_FAMILIES.filter((route) => authorityBefore[route] !== authorityAfter[route]);
  ok("the authority comparison is not vacuous: every family it watches actually ANSWERED, before and after",
    authorityBefore.__answered === AUTHORITY_FAMILIES.join(",") && authorityAfter.__answered === AUTHORITY_FAMILIES.join(","),
    `answered ${authorityAfter.__answered.split(",").filter(Boolean).length}/${AUTHORITY_FAMILIES.length}`);
  ok("climbing to SETTLED grants nothing: no lease, connector, approval request, grant or authority receipt moved",
    moved.length === 0,
    moved.length ? `moved: ${moved.join(", ")}` : `${AUTHORITY_FAMILIES.length} authority families byte-identical`);

  // -- the ladder does not move backwards, and refusals are counted by effect ---
  const beforeRefusals = await ladderState(SUBJECT);
  const past = await req("POST", AT, transitionBody(SUBJECT, { stage: "settled", outcome: "positive", head: await currentHead(SUBJECT) }));
  const afterPast = await ladderState(SUBJECT);
  ok("the ladder has a TOP: a further transition on a settled subject refuses typed and nothing is appended",
    code(past.j) === "assurance_transition_ladder_exhausted"
      && afterPast.count === beforeRefusals.count && afterPast.head === beforeRefusals.head,
    `${code(past.j)} · count ${beforeRefusals.count}→${afterPast.count}`);

  // -- a challenge resolution is claimable at EXACTLY one rung ------------------
  const second = await req("POST", WR, {
    goal_ref: "goal://m061-ladder-skip",
    result_profile: "research",
    outcome_class: "positive",
    status: "completed",
    claim_refs: ["evidence://m061-skip-1"],
    supporting_evidence_refs: ["artifact://m061-skip-a1"],
  });
  const SKIP_SUBJECT = second.j?.work_result?.work_result_id ?? "";
  const skipAhead = await req("POST", AT, transitionBody(SKIP_SUBJECT, { stage: "verified", outcome: "positive", head: null }));
  const skipState = await ladderState(SKIP_SUBJECT);
  ok("a first transition asserting 'verified' refuses rather than skipping attested and evidenced, and no ladder is created",
    code(skipAhead.j) === "assurance_transition_stage_skip" && (skipState.count ?? 0) === 0,
    `${code(skipAhead.j)} · transitions ${skipState.count ?? 0}`);

  const earlyResolution = await req("POST", AT, transitionBody(SKIP_SUBJECT, {
    stage: "attested", outcome: "positive", head: null,
    extra: { challenge_resolution: { verifier_challenge_id: "verifier-challenge://m061/early/1", resolution: "upheld", adjudicator_ref: "policy://ioi/assurance/adjudicator", adjudicator_policy_ref: "policy://ioi/assurance/adjudication/v1" } },
  }));
  const earlyState = await ladderState(SKIP_SUBJECT);
  ok("a challenge resolution IS an adjudication: presented at 'attested' it refuses, and nothing is appended",
    code(earlyResolution.j) === "assurance_transition_challenge_resolution_outside_adjudication" && (earlyState.count ?? 0) === 0,
    `${code(earlyResolution.j)} · transitions ${earlyState.count ?? 0}`);

  // AN UPHELD CHALLENGE IS NOT A CLEAN PASS. The typed resolution and the outcome class are coupled,
  // so a sustained finding cannot be recorded as a positive step at the adjudication rung.
  // On a subject standing at `accepted`, so the refusal is the COUPLING and not an exhausted ladder.
  const third = await req("POST", WR, {
    goal_ref: "goal://m061-ladder-coupling",
    result_profile: "research",
    outcome_class: "positive",
    status: "completed",
    claim_refs: ["evidence://m061-coupling-1"],
    supporting_evidence_refs: ["artifact://m061-coupling-a1"],
  });
  const COUPLING_SUBJECT = third.j?.work_result?.work_result_id ?? "";
  let couplingHead = null;
  for (const stage of ["attested", "evidenced", "verified", "accepted"]) {
    const reply = await req("POST", AT, transitionBody(COUPLING_SUBJECT, { stage, outcome: "positive", head: couplingHead }));
    couplingHead = reply.j?.expected_head_for_successor ?? couplingHead;
  }
  const upheldAsClean = await req("POST", AT, transitionBody(COUPLING_SUBJECT, {
    stage: "adjudicated", outcome: "positive", head: couplingHead,
    extra: { challenge_resolution: { verifier_challenge_id: "verifier-challenge://m061/coupling/1", resolution: "upheld", adjudicator_ref: "org://local", adjudicator_policy_ref: "policy://ioi/assurance/adjudication/v1", reviewer_lineage: [{ reviewer_ref: "org://local", reviewed_at: "2026-03-02T00:00:00Z", review_decision: "upheld" }] } },
  }));
  ok("an UPHELD challenge cannot be recorded as a clean pass: the resolution and the outcome class are coupled",
    code(upheldAsClean.j) === "assurance_transition_resolution_outcome_disagreement",
    code(upheldAsClean.j));

  // Aimed at the SAME subject standing at `accepted`, so the reviewer rule is what refuses. Pointed
  // at a subject sitting at `attested` this passed on the outside-adjudication code instead and
  // proved nothing about reviewers — a refusal for the wrong reason is not evidence for this one.
  const unreviewed = await req("POST", AT, transitionBody(COUPLING_SUBJECT, {
    stage: "adjudicated", outcome: "positive", head: couplingHead,
    extra: { challenge_resolution: { verifier_challenge_id: "verifier-challenge://m061/unreviewed/1", resolution: "rejected", adjudicator_ref: "org://local", adjudicator_policy_ref: "policy://ioi/assurance/adjudication/v1", reviewer_lineage: [] } },
  }));
  const unreviewedState = await ladderState(COUPLING_SUBJECT);
  ok("an adjudication naming NO reviewer refuses by its own cause, and nothing is appended: a verdict nobody stands behind is not one",
    code(unreviewed.j) === "assurance_transition_resolution_reviewer_required" && unreviewedState.reached === "accepted",
    `${code(unreviewed.j)} · still at ${unreviewedState.reached}`);

  // AN UPHELD ADJUDICATION ACTUALLY LANDS, carrying `invalid` — the one member of ACC-8 clause 2's
  // named vocabulary the six-rung climb above has no room for. Proving only that `upheld` REFUSES a
  // clean pass would leave the sustaining path itself undriven.
  const upheldInvalid = await req("POST", AT, transitionBody(COUPLING_SUBJECT, {
    stage: "adjudicated", outcome: "invalid", head: couplingHead,
    extra: { challenge_resolution: { verifier_challenge_id: "verifier-challenge://m061/upheld/1", resolution: "upheld", adjudicator_ref: "org://local", adjudicator_policy_ref: "policy://ioi/assurance/adjudication/v1", reviewer_lineage: [{ reviewer_ref: "org://local", reviewed_at: "2026-03-03T00:00:00Z", review_decision: "upheld" }] } },
  }));
  const couplingGraph = await graphOf(COUPLING_SUBJECT);
  ok("an UPHELD challenge is admitted at the adjudication rung carrying 'invalid', and the sustained finding is retained verbatim",
    (upheldInvalid.status === 201 || upheldInvalid.status === 200)
      && couplingGraph?.reached_stage === "adjudicated"
      && (couplingGraph?.outcome_class_census?.invalid ?? 0) === 1,
    `${upheldInvalid.status} ${code(upheldInvalid.j)} · reached ${couplingGraph?.reached_stage}`);

  // ACC-8 clause 2's vocabulary, EXACTLY: inconclusive, invalid, exploit-finding, superseded,
  // disputed and no-fault. A ladder that only records successes has not recorded anything.
  const retained = ["inconclusive", "invalid", "exploit", "superseded", "disputed", "no_fault"];
  const across = (name) => (graph?.outcome_class_census?.[name] ?? 0) + (couplingGraph?.outcome_class_census?.[name] ?? 0);
  ok("every outcome class ACC-8 clause 2 names by hand is retained and queryable on a real ladder: inconclusive, invalid, exploit, superseded, disputed, no_fault",
    retained.every((name) => across(name) >= 1),
    retained.map((name) => `${name}=${across(name)}`).join(" "));

  const unknownOutcome = await req("POST", AT, transitionBody(SKIP_SUBJECT, { stage: "attested", outcome: "looks_fine", head: null }));
  const unknownState = await ladderState(SKIP_SUBJECT);
  ok("an outcome class outside the frozen vocabulary refuses by its own cause rather than being coerced to the nearest member, and nothing is appended",
    code(unknownOutcome.j) === "assurance_transition_outcome_class_invalid"
      && (unknownState.count === null || unknownState.count === 0),
    `${unknownOutcome.status} ${code(unknownOutcome.j)} · transitions ${unknownState.count ?? 0}`);

  // -- durable truth is read ACROSS a restart ----------------------------------
  const beforeRestart = JSON.stringify({
    stages: graph.stages.map((s) => [s.stage, s.reached, s.transition_ref, s.outcome_class]),
    census: graph.outcome_class_census,
    reached: graph.reached_stage,
  });
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const afterGraph = await graphOf(SUBJECT);
  const afterRestart = JSON.stringify({
    stages: (afterGraph?.stages ?? []).map((s) => [s.stage, s.reached, s.transition_ref, s.outcome_class]),
    census: afterGraph?.outcome_class_census,
    reached: afterGraph?.reached_stage,
  });
  ok("the whole progression — every rung, every outcome class, the reached stage — survives a daemon restart byte-identically",
    beforeRestart === afterRestart && afterGraph?.transition_count === 6,
    `${afterGraph?.reached_stage} · ${afterGraph?.transition_count} transitions`);
  ok("the negative and exploit rungs are still queryable after the restart — a negative result is not quietly lost on reload",
    (afterGraph?.outcome_class_census?.negative ?? 0) === 1 && (afterGraph?.outcome_class_census?.exploit ?? 0) === 1
      && afterGraph?.work_result_outcome_class === "negative",
    JSON.stringify(afterGraph?.outcome_class_census ?? {}));
}

const stop = () => {
  try { daemon?.kill("SIGKILL"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on("SIGINT", () => { stop(); process.exit(130); });
process.on("SIGTERM", () => { stop(); process.exit(143); });

// ------------------------------------------------------------------------------- mutation harness
//
// Each mutant names the ONE assertion it must redden. A mutant that reddens something else is a
// MISS, not a pass: it would mean this gate's green came from somewhere other than the property the
// mutant broke.
const MUTANTS = [
  {
    id: "the-ladder-accepts-the-stage-the-caller-asserts",
    file: LADDER_SOURCE,
    reddens: "a first transition asserting 'verified' refuses rather than skipping attested and evidenced, and no ladder is created",
    from: '    if let Some(asserted) = body.get("to_stage").and_then(Value::as_str) {\n        if asserted != to_stage {',
    to: '    if let Some(asserted) = body.get("to_stage").and_then(Value::as_str) {\n        if false && asserted != to_stage {',
  },
  {
    id: "a-challenge-resolution-is-claimable-at-any-rung",
    file: LADDER_SOURCE,
    reddens: "a challenge resolution IS an adjudication: presented at 'attested' it refuses, and nothing is appended",
    from: "    if to_stage != ADJUDICATED_STAGE {\n        return Err(refuse(",
    to: "    if false && to_stage != ADJUDICATED_STAGE {\n        return Err(refuse(",
  },
  {
    id: "non-positive-outcomes-normalised-on-the-way-into-the-census",
    file: LADDER_SOURCE,
    reddens: "every outcome class carried up the ladder survives the whole climb, counted verbatim and never normalised toward positive",
    from: '        let count = ladder\n            .iter()\n            .filter(|document| {\n                document.get("outcome_class").and_then(Value::as_str) == Some(*outcome)\n            })\n            .count();',
    to: '        let count = ladder\n            .iter()\n            .filter(|document| {\n                let raw = document.get("outcome_class").and_then(Value::as_str);\n                let seen = if raw == Some("inconclusive") { Some("positive") } else { raw };\n                seen == Some(*outcome)\n            })\n            .count();',
  },
];

async function mutate() {
  const originals = new Map();
  const report = [];
  const restore = () => {
    for (const [file, text] of originals) fs.writeFileSync(file, text);
  };
  process.on("exit", restore);
  process.on("SIGINT", () => { restore(); process.exit(130); });
  process.on("SIGTERM", () => { restore(); process.exit(143); });
  for (const mutant of MUTANTS) {
    if (!originals.has(mutant.file)) originals.set(mutant.file, fs.readFileSync(mutant.file, "utf8"));
    const source = originals.get(mutant.file);
    if (!source.includes(mutant.from)) {
      report.push({ id: mutant.id, verdict: "ANCHOR-LOST", detail: "the anchor text is not in the source; this mutant proves nothing" });
      continue;
    }
    fs.writeFileSync(mutant.file, source.replace(mutant.from, mutant.to));
    const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
      cwd: ROOT, encoding: "utf8", env: { ...process.env, CARGO_INCREMENTAL: "0" },
    });
    if (build.status !== 0) {
      restore();
      report.push({ id: mutant.id, verdict: "BUILD-FAILED", detail: (build.stderr || "").split("\n").filter((l) => l.startsWith("error")).slice(0, 2).join(" · ") });
      continue;
    }
    const run = spawnSync("node", [fileURLToPath(import.meta.url)], { cwd: APP, encoding: "utf8" });
    const lines = `${run.stdout}`.split("\n");
    const reddened = lines.filter((line) => line.startsWith("FAIL ")).map((line) => line.slice(5).split(" — ")[0]);
    const hit = reddened.includes(mutant.reddens);
    report.push({
      id: mutant.id,
      verdict: hit && reddened.length > 0 ? "CAUGHT" : reddened.length === 0 ? "SURVIVED" : "MISS",
      detail: hit ? `reddened its target (${reddened.length} assertion(s) red)` : reddened.length === 0 ? "the gate stayed green with the defect planted" : `reddened ${JSON.stringify(reddened.slice(0, 2))} instead`,
    });
    fs.writeFileSync(mutant.file, source);
  }
  restore();
  const rebuild = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, CARGO_INCREMENTAL: "0" },
  });
  for (const row of report) console.log(`${row.verdict === "CAUGHT" ? "PASS" : "FAIL"} mutant ${row.id} — ${row.verdict}: ${row.detail}`);
  const caught = report.filter((row) => row.verdict === "CAUGHT").length;
  console.log(`${caught === MUTANTS.length && rebuild.status === 0 ? "PASS" : "FAIL"} mutate:assurance-ladder-lifecycle — ${caught}/${MUTANTS.length} planted defects caught · source restored and rebuilt (${rebuild.status === 0 ? "clean" : "REBUILD FAILED"})`);
  process.exit(caught === MUTANTS.length && rebuild.status === 0 ? 0 : 1);
}

if (process.argv.includes("--mutate")) {
  mutate();
} else {
  run()
    .catch((error) => ok("the lifecycle ran to completion", false, String(error?.message || error)))
    .finally(() => {
      stop();
      for (const result of results) {
        console.log(`${result.pass ? "PASS" : "FAIL"} ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
      }
      const failed = results.filter((result) => !result.pass).length;
      console.log(`${failed ? "FAIL" : "PASS"} check:assurance-ladder-lifecycle — ${results.length - failed}/${results.length} assertions · M06.1 · the ladder climbs to settled and settles nothing about the work`);
      process.exit(failed ? 1 : 0);
    });
}
