// Tests for the M04.8 commit-path profiler's ATTRIBUTION, not its plumbing.
//
// The defect class this guards against is a profile that reports plausible
// numbers attributed to the wrong phase. A parser that quietly folds durable
// store time into "consensus" still produces a full-looking artifact, and no
// amount of downstream reading would catch it. So the tests below plant a
// synthetic delay in ONE source field and require that exactly one named phase
// moves — and then re-run the SAME expectation against a delay planted
// elsewhere and require that expectation to go red. An attribution assertion
// that cannot fail is not an attribution assertion.
//
// Nothing here asserts a latency bound. The profiler enforces none by design.

import assert from "node:assert/strict";
import test from "node:test";

import {
  BENCH_CANONICAL_TX_CONTRACT,
  BENCH_IAVL_CONTRACT,
  BENCH_ORDERING_CONTRACT,
  BENCH_PROPOSAL_WAIT_CONTRACT,
  EVENT_DRIVEN_COMPLETION,
  ORDERING_PARITY_SLOTS,
  PHASES,
  PLANTED_DELAY_CONTRACT,
  READY_HEIGHT_LAG_MAX,
  RELEASE_DAEMON_BINARY,
  SCHEMA_COMPATIBILITY,
  SUPERSEDED_ARTIFACT_SCHEMA_VERSION,
  REQUIRED_PHASES,
  UNMEASURED_PHASES,
  VALUE_KINDS,
  buildCommitPathProfile,
  decimalMillisecondField,
  indexByHeight,
  indexByTxHash,
  integerField,
  millisecondValue,
  parseApprovalLines,
  parseBenchLine,
  parseArgs,
  parseObservationRecords,
  parsePlantedDelayDeclaration,
  profileEnv,
} from "./profile-m4-wallet-authority-commit-path.mjs";

const REQUEST_HASH = "a".repeat(64);
const POLICY_HASH = "b".repeat(64);
const TX_HASH = "c".repeat(64);
const HEIGHT = 412;
const PRODUCER_ACCOUNT_ID = "d".repeat(64);
const PRODUCER_NODE = "validator-20000-orch";
const WORKLOAD_NODE = "validator-20000-workload";
const BLOCK_PAYLOAD_HASH = "e".repeat(64);
const CANONICAL_BLOCK_HASH = "f".repeat(64);

const BASE = {
  admission_ms: 3,
  commit_wait_ms: 2500,
  commit_poll_count: 5,
  commit_poll_interval_ms: 500,
  approval_query_ms: 7,
  approval_verify_ms: 1,
  authority_resolution_ms: 2600,
  // Per-transaction proposal wait, hash-correlated.
  tx_hash: TX_HASH,
  first_seen_at_ms: 1_772_000_411_100,
  proposal_selected_at_ms: 1_772_000_412_050,
  // The exact completion event. `event_wait_ms` is client-side and
  // single-clock; the three timestamps are raw wall-clock readings, two from
  // the server and one from the client.
  event_wait_ms: 2_180,
  event_durable_commit_ms: 1_772_000_412_140,
  event_published_at_ms: 1_772_000_412_152,
  event_observed_at_ms: 1_772_000_412_157,
  select_ms: 4,
  verify_ms: 6,
  process_block_ms: 1800,
  finalize_ms: 120,
  prepare_total_ms: 300,
  commit_total_ms: 1400,
  commit_persist_ms: 1200,
  snapshot_clone_ms: 40,
  block_bytes: 5121,
  proc_cpu_user_ms: 900,
  proc_cpu_sys_ms: 130,
  commitment_ms: 700,
  durable_store_ms: 460,
  version_count: 412,
  tree_depth: 17,
  unique_nodes: 9001,
  new_nodes: 118,
  new_node_bytes: 40960,
  atomic_state_block: "true",
  ordering_profile: "aft",
  ticker_interval_ms: 1000,
  ticker_interval_provenance: "config:block_production_interval_secs",
  min_tick_ms: 50,
  min_tick_provenance: "default",
  genesis_block_interval_ms: 1000,
  genesis_block_interval_provenance: "default:test-genesis",
  block_timestamp_ms: 1_772_000_412_000,
  proposal_observed_at_ms: 1_772_000_412_100,
  view_timeout_secs: 2,
};

const RUN = {
  build_profile: "release",
  state_commitment_backend: "iavl",
  durable_store_backend: "redb",
};

function traceLines(v) {
  return [
    "2026-08-27T00:00:00Z INFO orchestration: unrelated log framing",
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} ordering_profile=${v.ordering_profile} ticker_interval_ms=${v.ticker_interval_ms} ticker_interval_provenance=${v.ticker_interval_provenance} min_tick_ms=${v.min_tick_ms} min_tick_provenance=${v.min_tick_provenance} genesis_block_interval_ms=${v.genesis_block_interval_ms} genesis_block_interval_provenance=${v.genesis_block_interval_provenance} block_timestamp_ms=${v.block_timestamp_ms} proposal_observed_at_ms=${v.proposal_observed_at_ms} view_timeout_secs=${v.view_timeout_secs}`,
    `[BENCH-CONSENSUS] proposal_select height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} candidate_txs=1 valid_txs=1 select_ms=${v.select_ms} verify_ms=${v.verify_ms}`,
    `[BENCH-CONSENSUS] proposal_process height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} tx_count=1 process_block_ms=${v.process_block_ms}`,
    `[BENCH-CONSENSUS] proposal_finalize height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} finalize_ms=${v.finalize_ms}`,
    `[BENCH-EXEC] prepare_block observer_node=${WORKLOAD_NODE} height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} tx_count=1 replay_mode=none replay_gate=none nonce_chain_edges=0 replay_debt=0 validation_aborts=0 validation_errors=0 validation_rewinds=0 execution_errors=0 snapshot_ms=1 parallel_exec_ms=2 fallback_exec_ms=0 overlay_ms=0 collect_results_ms=0 roots_ms=1 total_ms=${v.prepare_total_ms}`,
    `[BENCH-EXEC] commit_block observer_node=${WORKLOAD_NODE} height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} block_payload_hash=${BLOCK_PAYLOAD_HASH} tx_count=1 proof_verify_ms=0 apply_ms=90 end_block_ms=4 persist_ms=${v.commit_persist_ms} put_block_ms=0 total_ms=${v.commit_total_ms} snapshot_clone_ms=${v.snapshot_clone_ms} block_bytes=${v.block_bytes} proc_cpu_user_ms=${v.proc_cpu_user_ms} proc_cpu_sys_ms=${v.proc_cpu_sys_ms}`,
    `${BENCH_IAVL_CONTRACT.tag} commit observer_node=${WORKLOAD_NODE} height=${HEIGHT} block_payload_hash=${BLOCK_PAYLOAD_HASH} version_count=${v.version_count} tree_depth=${v.tree_depth} unique_nodes=${v.unique_nodes} new_nodes=${v.new_nodes} new_node_bytes=${v.new_node_bytes} block_bytes=${v.block_bytes} commitment_ms=${v.commitment_ms} durable_store_ms=${v.durable_store_ms} atomic_state_block=${v.atomic_state_block}`,
    proposalWaitLine(v),
    `${BENCH_CANONICAL_TX_CONTRACT.tag} ${BENCH_CANONICAL_TX_CONTRACT.op} tx_hash=${v.tx_hash} proposal_tx_hash=${v.proposal_tx_hash ?? v.tx_hash} height=${v.committed_height ?? HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} canonical_block_hash=${CANONICAL_BLOCK_HASH} observer_node=${PRODUCER_NODE}`,
    `[BENCH-APPROVAL] request_hash=${REQUEST_HASH} policy_hash=${POLICY_HASH} principal_ref=org://acme/research target_scope=room_participation.request tx_hash=${v.tx_hash} admission_ms=${v.admission_ms} committed_height=${v.committed_height ?? HEIGHT} commit_wait_ms=${v.commit_wait_ms} commit_poll_count=${v.commit_poll_count} commit_poll_interval_ms=${v.commit_poll_interval_ms} approval_query_ms=${v.approval_query_ms} approval_verify_ms=${v.approval_verify_ms} event_wait_ms=${v.event_wait_ms} event_committed_height=${v.event_committed_height ?? v.committed_height ?? HEIGHT} event_durable_commit_ms=${v.event_durable_commit_ms} event_published_at_ms=${v.event_published_at_ms} event_observed_at_ms=${v.event_observed_at_ms}`,
  ];
}

// The proposal-wait line, rendered exactly as the producer renders it.
//
// `proposal_wait_ms` is DERIVED from the two edges here rather than supplied
// independently, because the profiler rechecks that relationship. A fixture
// that let them drift would make the recheck untestable.
function proposalWaitLine(v) {
  const wait = Math.max(0, v.proposal_selected_at_ms - v.first_seen_at_ms);
  // `proposal_wait_tx_hash` overrides ONLY this line's hash, so a test can put
  // a well-formed observation for a different transaction into the trace
  // without also relabelling the approval that must refuse to borrow it.
  const txHash = v.proposal_wait_tx_hash ?? v.tx_hash;
  return `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} ${BENCH_PROPOSAL_WAIT_CONTRACT.op} tx_hash=${txHash} height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} first_seen_at_ms=${v.first_seen_at_ms} proposal_selected_at_ms=${v.proposal_selected_at_ms} proposal_wait_ms=${v.proposal_wait_ms ?? wait}`;
}

const SECOND_REQUEST_HASH = "c".repeat(64);
const SECOND_TX_HASH = "e".repeat(64);

// A COMPLETE secondary approval: its per-transaction proposal-wait line and
// its [BENCH-APPROVAL] line, in that order.
//
// Every per-approval field the profiler requires appears here. Tests that only
// care about a run-level property -- two cadences, two engines, adjacent
// heights -- still have to supply a complete row, because the profiler refuses
// an incomplete one. That is the behaviour under test elsewhere, so these
// fixtures must not quietly opt out of it.
function secondaryApprovalLines(height, overrides = {}) {
  const txHash = overrides.txHash ?? SECOND_TX_HASH;
  const requestHash = overrides.requestHash ?? SECOND_REQUEST_HASH;
  const firstSeenAtMs = overrides.firstSeenAtMs ?? BASE.first_seen_at_ms;
  const selectedAtMs = overrides.proposalSelectedAtMs ?? BASE.proposal_selected_at_ms;
  const eventWaitMs = overrides.eventWaitMs ?? BASE.event_wait_ms;
  const observedAtMs = overrides.eventObservedAtMs ?? BASE.event_observed_at_ms;
  return [
    `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} ${BENCH_PROPOSAL_WAIT_CONTRACT.op} tx_hash=${txHash} height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} first_seen_at_ms=${firstSeenAtMs} proposal_selected_at_ms=${selectedAtMs} proposal_wait_ms=${Math.max(0, selectedAtMs - firstSeenAtMs)}`,
    `${BENCH_CANONICAL_TX_CONTRACT.tag} ${BENCH_CANONICAL_TX_CONTRACT.op} tx_hash=${txHash} proposal_tx_hash=${overrides.proposalTxHash ?? txHash} height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} canonical_block_hash=${CANONICAL_BLOCK_HASH} observer_node=${PRODUCER_NODE}`,
    `[BENCH-APPROVAL] request_hash=${requestHash} policy_hash=${POLICY_HASH} principal_ref=org://acme/research target_scope=room_participation.request tx_hash=${txHash} admission_ms=3 committed_height=${height} commit_wait_ms=2500 commit_poll_count=5 commit_poll_interval_ms=500 approval_query_ms=7 approval_verify_ms=1 event_wait_ms=${eventWaitMs} event_committed_height=${height} event_durable_commit_ms=${BASE.event_durable_commit_ms} event_published_at_ms=${BASE.event_published_at_ms} event_observed_at_ms=${observedAtMs}`,
  ];
}

function secondaryBlockLines(height, overrides = {}) {
  const orderingProfile = overrides.orderingProfile ?? "aft";
  const tickerIntervalMs = overrides.tickerIntervalMs ?? 1000;
  const tickerProvenance = overrides.tickerProvenance ?? "config:block_production_interval_secs";
  const genesisIntervalMs = overrides.genesisIntervalMs ?? 1000;
  const genesisProvenance = overrides.genesisProvenance ?? "default:test-genesis";
  const blockTimestampMs = overrides.blockTimestampMs ?? 1_772_000_413_000;
  const proposalObservedAtMs = overrides.proposalObservedAtMs ?? 1_772_000_413_100;
  return [
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} ordering_profile=${orderingProfile} ticker_interval_ms=${tickerIntervalMs} ticker_interval_provenance=${tickerProvenance} min_tick_ms=50 min_tick_provenance=default genesis_block_interval_ms=${genesisIntervalMs} genesis_block_interval_provenance=${genesisProvenance} block_timestamp_ms=${blockTimestampMs} proposal_observed_at_ms=${proposalObservedAtMs} view_timeout_secs=2`,
    `[BENCH-CONSENSUS] proposal_select height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} candidate_txs=1 valid_txs=1 select_ms=4 verify_ms=6`,
    `[BENCH-CONSENSUS] proposal_process height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} tx_count=1 process_block_ms=1800`,
    `[BENCH-CONSENSUS] proposal_finalize height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} producer_node=${PRODUCER_NODE} finalize_ms=120`,
    `[BENCH-EXEC] prepare_block observer_node=${WORKLOAD_NODE} height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} tx_count=1 total_ms=300`,
    `[BENCH-EXEC] commit_block observer_node=${WORKLOAD_NODE} height=${height} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} block_payload_hash=${BLOCK_PAYLOAD_HASH} tx_count=1 persist_ms=1200 total_ms=1400 snapshot_clone_ms=40 block_bytes=5121 proc_cpu_user_ms=900 proc_cpu_sys_ms=130`,
    `${BENCH_IAVL_CONTRACT.tag} commit observer_node=${WORKLOAD_NODE} height=${height} block_payload_hash=${BLOCK_PAYLOAD_HASH} version_count=${height} tree_depth=17 unique_nodes=9001 new_nodes=118 new_node_bytes=40960 block_bytes=5121 commitment_ms=700 durable_store_ms=460 atomic_state_block=true`,
    ...secondaryApprovalLines(height, overrides),
  ];
}

function inputs(overrides = {}, { dropLines = [], run = RUN } = {}) {
  const values = { ...BASE, ...overrides };
  const lines = traceLines(values).filter(
    (line) => !dropLines.some((fragment) => line.includes(fragment)),
  );
  const traceText = lines.join("\n");
  return {
    approvalFields: parseApprovalLines(traceText),
    observationRecords: parseObservationRecords(
      [
        JSON.stringify({
          kind: "approval_record",
          request_hash: REQUEST_HASH,
          policy_hash: POLICY_HASH,
          target_scope: "room_participation.request",
          record_approval_ms: 2610,
          record_approval_attempts: 1,
        }),
        JSON.stringify({
          kind: "governed_route",
          route: "/v1/goal-orchestration/room-participation-requests",
          request_hash: REQUEST_HASH,
          policy_hash: POLICY_HASH,
          target_scope: "room_participation.request",
          authority_resolution_ms: values.authority_resolution_ms,
          response_status: 200,
        }),
      ].join("\n"),
    ),
    traceText,
    run,
  };
}

const phasesOf = (overrides, options) =>
  buildCommitPathProfile(inputs(overrides, options)).approvals[0].phases;

// The one source field whose delay each phase is supposed to absorb.
//
// `durable_ack_publication` is deliberately ABSENT: it is derived from a pair
// of timestamps, so no single field moves it alone. Moving either edge moves
// it and the transport lag together, which is a real two-phase consequence and
// is asserted exactly, in its own test below, rather than approximated here.
const PLANT_FIELD = {
  client_submission_admission: "admission_ms",
  client_commit_wait: "commit_wait_ms",
  client_event_observation: "event_wait_ms",
  proposal_cadence_wait: "proposal_selected_at_ms",
  notification_transport_lag: "event_observed_at_ms",
  ordering_finalization: "finalize_ms",
  execution_prepare: "prepare_total_ms",
  execution_commit: "commit_total_ms",
  state_commitment_materialization: "commitment_ms",
  durable_persistence: "durable_store_ms",
  proof_exact_state_resolution: "approval_query_ms",
};

const PLANTED_DELAY_MS = 7_000;

// The expectation under test: planting `delay` moved EXACTLY `phase`.
//
// Written as a reusable assertion so the tests below can aim it at a delay
// planted somewhere else and prove it goes red.
function assertOnlyPhaseMoved(phase, baseline, mutated, delay) {
  for (const name of REQUIRED_PHASES) {
    if (name === phase) {
      assert.equal(
        mutated[name],
        baseline[name] + delay,
        `${name} should absorb the full planted delay`,
      );
    } else {
      assert.equal(mutated[name], baseline[name], `${name} must not move`);
    }
  }
}

test("every phase is declared inclusive, exclusive, or unmeasured with its nesting named", () => {
  const allPhases = Object.keys(PHASES);
  for (const name of allPhases) {
    const phase = PHASES[name];
    assert.ok(
      ["inclusive", "exclusive", "unmeasured"].includes(phase.semantics),
      `${name} declares semantics`,
    );
    assert.ok(Object.keys(VALUE_KINDS).includes(phase.semantics), `${name} uses a declared kind`);
    assert.ok(ORDERING_PARITY_SLOTS.includes(phase.slot), `${name} maps to a parity slot`);
    if (phase.measured) {
      assert.ok(phase.source.length > 0, `${name} names its source`);
    } else {
      assert.equal(phase.source, null, `${name} claims no source it does not have`);
      assert.ok(
        (phase.unmeasured_reason ?? "").length > 0,
        `${name} states WHY it is unmeasured rather than silently vanishing`,
      );
    }
    if (phase.semantics === "exclusive") {
      assert.deepEqual(phase.contains, [], `${name} is exclusive so it contains nothing`);
    } else {
      assert.ok(Array.isArray(phase.contains), `${name} lists what it contains`);
    }
    for (const contained of phase.contains) {
      assert.ok(allPhases.includes(contained), `${name} contains a real phase`);
    }
    for (const container of phase.nested_in) {
      assert.ok(allPhases.includes(container), `${name} is nested in a real phase`);
      assert.ok(
        PHASES[container].contains.includes(name),
        `${name} declares it is nested in ${container}, so ${container} must declare it contains ${name}`,
      );
    }
  }
  // The double-counting trap this exists to prevent: the two containers of
  // finality time must both declare that they hold the execution beneath them.
  assert.ok(PHASES.ordering_finalization.contains.includes("execution_commit"));
  assert.ok(PHASES.execution_commit.contains.includes("durable_persistence"));
});

test("all twelve ordering-parity slots are represented, measured or explicitly not", () => {
  const covered = new Set(Object.values(PHASES).map((phase) => phase.slot));
  for (const slot of ORDERING_PARITY_SLOTS) {
    assert.ok(covered.has(slot), `slot '${slot}' must be present, even if unmeasured`);
  }
  assert.equal(ORDERING_PARITY_SLOTS.length, 12, "the contract names exactly twelve slots");
  // The two the estate genuinely cannot measure today. If a seam later makes
  // one of these measurable, this list is the thing that must change.
  //
  // It shrank by one for M04.9(a): `proposal_cadence_wait` acquired a seam.
  // `receipt_creation_durable_ack` did NOT become measurable -- it was split,
  // and the half that stayed unmeasurable kept the unmeasured label under the
  // narrower name `receipt_creation`.
  assert.deepEqual(
    [...UNMEASURED_PHASES].sort(),
    ["admission_queueing", "receipt_creation"],
    "unmeasured phases are exactly the ones with no seam",
  );
});

test("the polled and pushed completion observations are labelled distinctly", () => {
  assert.equal(PHASES.client_commit_wait.quantized_by, "poll_interval_ms");
  // The exact one is NOT quantized. Sharing a slot with the polled phase is
  // deliberate -- they observe the same thing -- but sharing a quantum would
  // have made the exact figure a rounded one.
  assert.equal(PHASES.client_event_observation.quantized_by, null);
  assert.equal(
    PHASES.client_event_observation.slot,
    PHASES.client_commit_wait.slot,
    "both observe client-side completion, so both map to that slot",
  );
  assert.notEqual(
    PHASES.client_event_observation.source,
    PHASES.client_commit_wait.source,
    "and they come from different sources, so neither can silently stand in for the other",
  );
  assert.equal(
    PHASES.proposal_cadence_wait.semantics,
    "exclusive",
    "the cadence WAIT is now a measured leaf, distinct from the cadence CONFIG",
  );
  assert.equal(EVENT_DRIVEN_COMPLETION.status, "implemented");
  assert.equal(EVENT_DRIVEN_COMPLETION.measured, true);
  assert.ok(
    /transaction_committed/u.test(EVENT_DRIVEN_COMPLETION.mechanism),
    "the mechanism names the concrete additive event",
  );
  assert.ok(
    /durably_update_header_then_publish_committed/u.test(
      EVENT_DRIVEN_COMPLETION.durability_ordering,
    ),
    "and names the seam that makes a pre-durability event unreachable",
  );
  assert.ok(
    /fails closed/u.test(EVENT_DRIVEN_COMPLETION.client_discipline),
    "the client's refusal behaviour is declared, not assumed",
  );
  assert.ok(
    /never substitutes a block height, a chain tip, or the polled result/u.test(
      EVENT_DRIVEN_COMPLETION.client_discipline,
    ),
    "including the substitutions it must not make",
  );
  assert.ok(
    EVENT_DRIVEN_COMPLETION.polling_retained.length > 0,
    "polling is retained and reported separately, not replaced",
  );
  assert.ok(
    EVENT_DRIVEN_COMPLETION.unmeasured_residual.length > 0,
    "and what remains unmeasured after this is still named",
  );
});

test("a complete trace attributes one approval across every required phase", () => {
  const profile = buildCommitPathProfile(inputs());
  assert.equal(profile.approvals.length, 1);
  const [approval] = profile.approvals;
  assert.equal(approval.request_hash, REQUEST_HASH);
  assert.equal(approval.policy_hash, POLICY_HASH);
  assert.equal(approval.target_scope, "room_participation.request");
  assert.equal(approval.route, "/v1/goal-orchestration/room-participation-requests");
  assert.equal(approval.dimensions.committed_height, HEIGHT);
  assert.equal(approval.dimensions.version_count, BASE.version_count);
  assert.equal(approval.dimensions.tree_depth, BASE.tree_depth);
  assert.equal(approval.dimensions.block_bytes, BASE.block_bytes);
  assert.equal(approval.dimensions.cpu_user_ms, BASE.proc_cpu_user_ms);
  assert.equal(approval.dimensions.cpu_system_ms, BASE.proc_cpu_sys_ms);
  assert.equal(approval.dimensions.poll_interval_ms, BASE.commit_poll_interval_ms);
  assert.equal(approval.dimensions.poll_count, BASE.commit_poll_count);
  assert.equal(approval.dimensions.snapshot_clone_ms, BASE.snapshot_clone_ms);
  assert.equal(approval.dimensions.build_profile, "release");
  assert.equal(approval.dimensions.state_commitment_backend, "iavl");
  assert.equal(approval.dimensions.durable_store_backend, "redb");
  assert.deepEqual(approval.anomalies, []);
  assert.equal(
    approval.phases.proof_exact_state_resolution,
    BASE.approval_query_ms + BASE.approval_verify_ms,
    "the wallet phase is the post-commit read alone",
  );
  assert.equal(approval.ordering.profile, BASE.ordering_profile);
  assert.equal(
    approval.ordering.scheduler_and_block_cadence.ticker_interval_ms,
    BASE.ticker_interval_ms,
  );
  assert.equal(
    approval.ordering.scheduler_and_block_cadence.min_tick_ms,
    BASE.min_tick_ms,
  );
  assert.equal(
    approval.ordering.scheduler_and_block_cadence.ticker_interval_provenance,
    BASE.ticker_interval_provenance,
  );
  assert.equal(
    approval.ordering.scheduler_and_block_cadence.min_tick_provenance,
    BASE.min_tick_provenance,
  );
  assert.equal(approval.ordering.scheduler_and_block_cadence.measured, false, "cadence is configuration");
  assert.equal(approval.correlation.authority_resolution_ms, BASE.authority_resolution_ms);
  assert.equal(profile.coverage.approvals_route_correlated, 1);
  assert.equal(profile.coverage.approvals_without_route, 0);
  // Residuals partition the nested time instead of restating it.
  assert.equal(
    approval.derived_exclusive_ms.consensus_excluding_execution,
    BASE.select_ms + BASE.verify_ms + BASE.process_block_ms + BASE.finalize_ms -
      (BASE.prepare_total_ms + BASE.commit_total_ms),
  );
  assert.equal(
    approval.derived_exclusive_ms.commit_excluding_commitment_and_store,
    BASE.commit_total_ms - (BASE.commitment_ms + BASE.durable_store_ms),
  );
});

test("fractional IAVL milliseconds survive parsing instead of rounding to zero", () => {
  const profile = buildCommitPathProfile(
    inputs({ commitment_ms: "0.125", durable_store_ms: "0.875" }),
  );
  assert.equal(profile.approvals[0].phases.state_commitment_materialization, 0.125);
  assert.equal(profile.approvals[0].phases.durable_persistence, 0.875);
  assert.equal(decimalMillisecondField({ sample: "unavailable" }, "sample"), null);
  assert.equal(decimalMillisecondField({ sample: "-0.1" }, "sample"), null);
});

test("MUTATION: a planted delay moves only the phase it was planted in", () => {
  const baseline = phasesOf();
  for (const [phase, field] of Object.entries(PLANT_FIELD)) {
    const mutated = phasesOf({ [field]: BASE[field] + PLANTED_DELAY_MS });
    assertOnlyPhaseMoved(phase, baseline, mutated, PLANTED_DELAY_MS);
  }
});

test("MUTATION: aiming a phase's expectation at a delay planted elsewhere goes red", () => {
  const baseline = phasesOf();
  const phases = Object.keys(PLANT_FIELD);
  for (const phase of phases) {
    for (const other of phases) {
      if (other === phase) continue;
      const mutatedElsewhere = phasesOf({
        [PLANT_FIELD[other]]: BASE[PLANT_FIELD[other]] + PLANTED_DELAY_MS,
      });
      assert.throws(
        () => assertOnlyPhaseMoved(phase, baseline, mutatedElsewhere, PLANTED_DELAY_MS),
        assert.AssertionError,
        `attributing a ${other} delay to ${phase} must fail`,
      );
    }
  }
});

test("MUTATION: durable store and state commitment are not interchangeable", () => {
  const baseline = phasesOf();
  const store = phasesOf({ durable_store_ms: BASE.durable_store_ms + PLANTED_DELAY_MS });
  const commitment = phasesOf({ commitment_ms: BASE.commitment_ms + PLANTED_DELAY_MS });
  assert.equal(store.durable_persistence, baseline.durable_persistence + PLANTED_DELAY_MS);
  assert.equal(store.state_commitment_materialization, baseline.state_commitment_materialization);
  assert.equal(
    commitment.state_commitment_materialization,
    baseline.state_commitment_materialization + PLANTED_DELAY_MS,
  );
  assert.equal(commitment.durable_persistence, baseline.durable_persistence);
});

test("FAIL CLOSED: deleting a required phase's source line refuses to build a profile", () => {
  const cases = [
    ["[BENCH-IAVL]", /\[BENCH-IAVL\] canonical payload/u],
    ["commit_block", /commit_block for canonical attempt/u],
    ["prepare_block", /prepare_block for canonical attempt/u],
    ["[BENCH-CONSENSUS] proposal_finalize", /proposal_finalize for canonical attempt/u],
    ["[BENCH-CONSENSUS] proposal_select", /proposal_select for canonical attempt/u],
    ["[BENCH-CONSENSUS] proposal_process", /proposal_process for canonical attempt/u],
  ];
  for (const [fragment, expected] of cases) {
    assert.throws(
      () => buildCommitPathProfile(inputs({}, { dropLines: [fragment] })),
      expected,
      `dropping ${fragment} must fail closed`,
    );
  }
});

test("FAIL CLOSED: a [BENCH-IAVL] line missing one contracted field is refused", () => {
  for (const field of BENCH_IAVL_CONTRACT.required_fields) {
    const identityField = ["height", "observer_node", "block_payload_hash"].includes(field);
    const complete = inputs();
    const stripped = complete.traceText
      .split("\n")
      .map((line) =>
        line.includes(BENCH_IAVL_CONTRACT.tag)
          ? line.replace(new RegExp(`\\s${field}=\\S+`, "u"), "")
          : line,
      )
      .join("\n");
    assert.throws(
      () => buildCommitPathProfile({ ...complete, traceText: stripped }),
      identityField
        ? /canonical payload .* has 0 observations/u
        : new RegExp(`omits required field '${field}'`, "u"),
      `a [BENCH-IAVL] line without ${field} must fail closed`,
    );
  }
});

test("FAIL CLOSED: unmeasured CPU is refused rather than read as zero", () => {
  for (const field of ["proc_cpu_user_ms", "proc_cpu_sys_ms"]) {
    assert.throws(
      () => buildCommitPathProfile(inputs({ [field]: "unavailable" })),
      /process CPU .* was not observed/u,
      `${field}=unavailable must fail closed`,
    );
  }
  // The absence must survive parsing as absence, never as the number 0.
  const parsed = parseBenchLine(
    "[BENCH-EXEC] commit_block height=1 proc_cpu_user_ms=unavailable",
    "[BENCH-EXEC]",
  );
  assert.equal(integerField(parsed.fields, "proc_cpu_user_ms"), null);
  assert.notEqual(integerField(parsed.fields, "proc_cpu_user_ms"), 0);
});

test("FAIL CLOSED: an unobserved committed height is never replaced by a tip", () => {
  assert.throws(
    () => buildCommitPathProfile(inputs({ committed_height: "unavailable" })),
    /exact committed block height was not observed/u,
    "an approval with no exact height must fail closed",
  );
});

test("FAIL CLOSED: a non-atomic state/block commit is refused", () => {
  assert.throws(
    () => buildCommitPathProfile(inputs({ atomic_state_block: "false" })),
    /atomic_state_block=false/u,
  );
});

test("an absent JSON millisecond field does not slip through as NaN", () => {
  // `Number(undefined)` is NaN, which is neither null nor undefined and would
  // otherwise pass a null check straight into the artifact.
  assert.equal(millisecondValue({}, "authority_resolution_ms"), null);
  assert.equal(millisecondValue(null, "authority_resolution_ms"), null);
  assert.equal(millisecondValue({ authority_resolution_ms: "2600" }, "authority_resolution_ms"), null);
  assert.equal(millisecondValue({ authority_resolution_ms: 2600 }, "authority_resolution_ms"), 2600);
});

test("the daemon's authority-resolution time is correlated, never folded into a phase", () => {
  // It wraps a whole second governed effect. Adding it to wallet_proof_resolution
  // would count a commit path twice, so a change to it must move NO phase.
  const baseline = phasesOf();
  const slower = phasesOf({ authority_resolution_ms: BASE.authority_resolution_ms + 60_000 });
  assert.deepEqual(slower, baseline, "no phase may absorb the daemon resolution time");

  const profile = buildCommitPathProfile(
    inputs({ authority_resolution_ms: BASE.authority_resolution_ms + 60_000 }),
  );
  assert.equal(
    profile.approvals[0].correlation.authority_resolution_ms,
    BASE.authority_resolution_ms + 60_000,
  );
  assert.equal(profile.approvals[0].correlation.route_correlated, true);
});

test("FAIL CLOSED: a run where NO approval reached a governed route is refused", () => {
  // A bootstrap approval legitimately carries no route, so this is a run-level
  // check rather than a per-approval one; zero correlation means the
  // governed-helper instrumentation produced nothing at all.
  const complete = inputs();
  assert.throws(
    () =>
      buildCommitPathProfile({
        ...complete,
        observationRecords: complete.observationRecords.filter(
          (record) => record.kind !== "governed_route",
        ),
      }),
    /no approval was correlated to a governed route/u,
  );
});

test("FAIL CLOSED: a run with no attributed approval is not a profile", () => {
  assert.throws(
    () => buildCommitPathProfile({ ...inputs(), approvalFields: [] }),
    /no approval observations were parsed/u,
  );
});

test("the wrapper pins readiness lag because the trace seam would change it", () => {
  const env = profileEnv({ PATH: "/usr/bin" }, "/tmp/trace", "/tmp/tee.log");
  assert.equal(env.IOI_TEST_READY_HEIGHT_LAG_MAX, READY_HEIGHT_LAG_MAX);
  assert.equal(env.IOI_TEST_READY_HEIGHT_LAG_MAX, "1", "the soak's own readiness bar is 1");
  assert.equal(env.IOI_AFT_BENCH_TRACE, "1");
  assert.equal(env.IOI_AFT_BENCH_TRACE_DIR, "/tmp/trace");
  assert.equal(env.IOI_WALLET_FIXTURE_RELEASE, "1");
  assert.equal(env.IOI_HYPERVISOR_DAEMON_BINARY, RELEASE_DAEMON_BINARY);
  assert.equal(env.IOI_WALLET_FIXTURE_TEE_LOG, "/tmp/tee.log");
  assert.equal(env.PATH, "/usr/bin", "the surrounding environment is preserved");
});

test("the artifact declaration records one exact wired planted delay", () => {
  assert.deepEqual(parsePlantedDelayDeclaration("proposal_selection=125"), {
    spec: "proposal_selection=125",
    phase: "proposal_selection",
    delay_ms: 125,
    arming: ["IOI_AFT_BENCH_TRACE", "IOI_TESTING_M049_PLANTED_PHASE_DELAY"],
    provenance:
      "requested:process-environment; propagated explicitly across the sanitized verifier and validator-child boundaries",
  });
  assert.equal(parsePlantedDelayDeclaration(undefined), null);
  assert.equal(parsePlantedDelayDeclaration(""), null);
});

test("the artifact declaration refuses malformed, unwired, and out-of-range mutations", () => {
  assert.throws(() => parsePlantedDelayDeclaration("proposal_selection"), /exactly/u);
  assert.throws(() => parsePlantedDelayDeclaration("unknown=10"), /unwired/u);
  assert.throws(() => parsePlantedDelayDeclaration("proposal_selection=0"), /1\.\.=60000/u);
  assert.throws(() => parsePlantedDelayDeclaration("proposal_selection=60001"), /1\.\.=60000/u);
});

test("post-durability publication is not nested in producer-side finalization", () => {
  assert.equal(PHASES.ordering_finalization.contains.includes("durable_ack_publication"), false);
  assert.equal(PHASES.durable_ack_publication.nested_in.includes("ordering_finalization"), false);
  assert.deepEqual(PHASES.durable_ack_publication.nested_in, [
    "client_commit_wait",
    "client_event_observation",
  ]);
});

test("an observed durable_store on the [BENCH-IAVL] line outranks the declared one", () => {
  const complete = inputs();
  const observed = complete.traceText.replace(
    "atomic_state_block=true",
    "atomic_state_block=true durable_store=sled",
  );
  const profile = buildCommitPathProfile({ ...complete, traceText: observed });
  assert.equal(profile.approvals[0].dimensions.durable_store_backend, "sled");
  assert.equal(
    buildCommitPathProfile(complete).approvals[0].dimensions.durable_store_backend,
    "redb",
  );
});

test("a repeated canonical-attempt observation is refused rather than silently collapsed", () => {
  const complete = inputs();
  const replayed = `${complete.traceText}\n${
    complete.traceText.split("\n").find((line) => line.includes("commit_block"))
  }`;
  assert.throws(
    () => buildCommitPathProfile({ ...complete, traceText: replayed }),
    /commit_block .* has 2 observations/u,
  );
});

test("declared nesting that does not hold is surfaced, not clamped", () => {
  // Commitment plus durable store exceeding the commit that contains them is a
  // contradiction in the declared nesting. Reporting it as a negative residual
  // keeps the contradiction visible; clamping it to zero would erase it.
  const profile = buildCommitPathProfile(inputs({ commit_total_ms: 100 }));
  const [approval] = profile.approvals;
  assert.ok(approval.derived_exclusive_ms.commit_excluding_commitment_and_store < 0);
  assert.ok(approval.anomalies.includes("commit_exclusive_ms_negative: commit time is below the commitment/store it contains"));
});

test("the profiler states its nonclaims and enforces no latency bound", () => {
  const profile = buildCommitPathProfile(inputs());
  const serialized = JSON.stringify(profile);
  assert.ok(profile.nonclaims.some((entry) => /No numeric approval latency budget/u.test(entry)));
  assert.ok(profile.nonclaims.some((entry) => /quantized by poll_interval_ms/u.test(entry)));
  for (const forbidden of ["budget_ms", "threshold_ms", "max_ms", "tripwire"]) {
    assert.ok(!serialized.includes(forbidden), `the artifact must not carry a ${forbidden}`);
  }
  assert.equal(profile.parser_contract.bench_iavl.tag, "[BENCH-IAVL]");
});

test("bench lines are found inside surrounding log framing", () => {
  const framed =
    "2026-08-27T00:00:00.123Z  INFO validator-41000-orch: [BENCH-CONSENSUS] proposal_finalize height=9 view=2 finalize_ms=31";
  const index = indexByHeight(framed, "[BENCH-CONSENSUS]", "proposal_finalize");
  assert.equal(integerField(index.get(9).fields, "finalize_ms"), 31);
  assert.equal(parseBenchLine("nothing here", "[BENCH-EXEC]"), null);
});

// ---------------------------------------------------------------------------
// Ordering/finality parity
// ---------------------------------------------------------------------------

test("the same scenario profiles under either ordering profile, attributed correctly", () => {
  // The parity claim: identical inputs except the ordering engine produce
  // artifacts that differ ONLY in what the engine is called. If the profiler
  // could not tell them apart, no comparison built on it would mean anything.
  const aft = buildCommitPathProfile(inputs({ ordering_profile: "aft" }));
  const solo = buildCommitPathProfile(
    inputs({ ordering_profile: "solo", ticker_interval_ms: 1000, view_timeout_secs: 2 }),
  );
  assert.equal(aft.ordering_parity.ordering_profile, "aft");
  assert.equal(solo.ordering_parity.ordering_profile, "solo");
  assert.equal(solo.approvals[0].ordering.profile, "solo");
  // Every measured phase is read from the same seams either way.
  assert.deepEqual(
    Object.keys(solo.approvals[0].phases).sort(),
    Object.keys(aft.approvals[0].phases).sort(),
    "both profiles report the same phase set; only the attribution differs",
  );
  assert.equal(
    aft.ordering_parity.ordering_profile_provenance,
    `observed:${BENCH_ORDERING_CONTRACT.tag}`,
    "the profile is observed from the trace, never assumed from the run config",
  );
});

test("a profile that cannot name its ordering engine fails closed", () => {
  // Silently attributing an unlabelled run to the default engine is the exact
  // failure that made the Solo-reports-Aft defect invisible.
  assert.throws(
    () => buildCommitPathProfile(inputs({}, { dropLines: [BENCH_ORDERING_CONTRACT.tag] })),
    /\[BENCH-ORDERING\] canonical attempt .* has 0 observations/u,
  );
  assert.throws(
    () => buildCommitPathProfile(inputs({ ordering_profile: "quorum_ish" })),
    /does not know; refusing to attribute/u,
  );
});

test("an artifact spanning two ordering engines is refused", () => {
  // Averaging two engines into one figure would answer the experiment's
  // question with a number that describes neither.
  const single = inputs({ ordering_profile: "aft" });
  const otherHeight = 413;
  const mixedTrace = [
    single.traceText,
    ...secondaryBlockLines(otherHeight, { orderingProfile: "solo" }),
  ].join("\n");
  assert.throws(
    () =>
      buildCommitPathProfile({
        ...single,
        approvalFields: parseApprovalLines(mixedTrace),
        traceText: mixedTrace,
      }),
    /span more than one ordering profile \(aft, solo\)/u,
  );
});

test("unmeasured phases are carried as absent-with-reason, never as zero", () => {
  const profile = buildCommitPathProfile(inputs());
  const [approval] = profile.approvals;
  for (const name of UNMEASURED_PHASES) {
    assert.ok(name in approval.unmeasured_phases, `${name} is present on the row`);
    const entry = approval.unmeasured_phases[name];
    assert.equal(entry.value, null, `${name} must be null, not 0`);
    assert.equal(entry.kind, "unmeasured");
    assert.ok(entry.reason.length > 0, `${name} carries its reason into the artifact`);
    assert.ok(!(name in approval.phases), `${name} must not appear among measured phases`);
  }
  // The cadence the run resolved IS recorded — as configuration.
  assert.equal(profile.ordering_parity.scheduler_and_block_cadence.measured, false);
  assert.equal(
    profile.ordering_parity.scheduler_and_block_cadence.provenance,
    `observed:${BENCH_ORDERING_CONTRACT.tag}`,
  );
  assert.deepEqual(profile.ordering_parity.scheduler_and_block_cadence.values, [
    {
      ticker_interval_ms: BASE.ticker_interval_ms,
      ticker_interval_provenance: BASE.ticker_interval_provenance,
      min_tick_ms: BASE.min_tick_ms,
      min_tick_provenance: BASE.min_tick_provenance,
      genesis_block_interval_ms: BASE.genesis_block_interval_ms,
      genesis_block_interval_provenance: BASE.genesis_block_interval_provenance,
      view_timeout_secs: BASE.view_timeout_secs,
    },
  ]);
});

test("the artifact records the poll interval that quantizes the observed phase", () => {
  const profile = buildCommitPathProfile(inputs({ commit_poll_interval_ms: 25 }));
  assert.deepEqual(profile.ordering_parity.poll_interval_ms.values, [25]);
  assert.equal(profile.ordering_parity.poll_interval_ms.quantizes, "client_commit_wait");
  assert.equal(profile.approvals[0].dimensions.poll_interval_ms, 25);
});

test("the profile selector and poll interval are bounded at the wrapper too", () => {
  assert.deepEqual(parseArgs([]).orderingProfile, null, "unflagged runs request nothing");
  assert.deepEqual(parseArgs([]).pollIntervalMs, null);
  assert.equal(parseArgs(["--ordering-profile", "Solo"]).orderingProfile, "Solo");
  assert.equal(parseArgs(["--ordering-profile=Aft"]).orderingProfile, "Aft");
  assert.equal(parseArgs(["--poll-interval-ms", "25"]).pollIntervalMs, 25);
  // Same bounds crates/cli enforces; a wrapper that accepted more would let a
  // value through that the node then silently replaced with its default.
  for (const bad of ["solo", "AFT", "ProofOfStake", ""]) {
    assert.throws(() => parseArgs(["--ordering-profile", bad]), /--ordering-profile must be one of/u);
  }
  for (const bad of ["0", "5001", "-1", "abc", "1.5"]) {
    assert.throws(() => parseArgs(["--poll-interval-ms", bad]), /--poll-interval-ms must be/u);
  }
});

test("the two scheduler cadence flags are bounded at the wrapper", () => {
  assert.equal(parseArgs([]).proposalCadenceMs, null, "unflagged runs request no cadence");
  assert.equal(parseArgs([]).consensusMinTickMs, null);
  assert.equal(parseArgs(["--proposal-cadence-ms", "250"]).proposalCadenceMs, 250);
  assert.equal(parseArgs(["--proposal-cadence-ms=250"]).proposalCadenceMs, 250);
  assert.equal(parseArgs(["--consensus-min-tick-ms", "10"]).consensusMinTickMs, 10);
  assert.equal(parseArgs(["--consensus-min-tick-ms=10"]).consensusMinTickMs, 10);

  // 0 is refused for the ticker because the scheduler filters
  // ORCH_BLOCK_INTERVAL_MS on `> 0`: accepting it would let the flag read as
  // "cadence 0" while the node quietly ran its config cadence instead.
  for (const bad of ["0", "-1", "60001", "abc", "1.5", ""]) {
    assert.throws(
      () => parseArgs(["--proposal-cadence-ms", bad]),
      /--proposal-cadence-ms must be an integer in 1\.\.=60000/u,
      `--proposal-cadence-ms must refuse ${JSON.stringify(bad)}`,
    );
  }
  // 0 IS accepted for the minimum kick spacing, because the scheduler honours
  // it there. The asymmetry is the scheduler's and is mirrored, not tidied.
  assert.equal(parseArgs(["--consensus-min-tick-ms", "0"]).consensusMinTickMs, 0);
  for (const bad of ["-1", "600001", "abc", "1.5", ""]) {
    assert.throws(
      () => parseArgs(["--consensus-min-tick-ms", bad]),
      /--consensus-min-tick-ms must be an integer in 0\.\.=600000/u,
      `--consensus-min-tick-ms must refuse ${JSON.stringify(bad)}`,
    );
  }
});

test("the three numeric flags are independent of one another", () => {
  // Client poll interval and the two server scheduler knobs sit on opposite
  // sides of the boundary. If setting one set another, a run that varied a
  // single dimension would have silently varied two.
  const only = (flag, raw) => parseArgs([flag, raw]);
  assert.deepEqual(
    [only("--poll-interval-ms", "25").proposalCadenceMs, only("--poll-interval-ms", "25").consensusMinTickMs],
    [null, null],
    "--poll-interval-ms must not imply a scheduler cadence",
  );
  assert.deepEqual(
    [
      only("--proposal-cadence-ms", "250").pollIntervalMs,
      only("--proposal-cadence-ms", "250").consensusMinTickMs,
    ],
    [null, null],
    "--proposal-cadence-ms must not imply a poll interval or a kick spacing",
  );
  assert.deepEqual(
    [
      only("--consensus-min-tick-ms", "10").pollIntervalMs,
      only("--consensus-min-tick-ms", "10").proposalCadenceMs,
    ],
    [null, null],
    "--consensus-min-tick-ms must not imply a poll interval or a ticker cadence",
  );
  // All three together stay distinct values rather than collapsing onto one.
  const all = parseArgs([
    "--poll-interval-ms=25",
    "--proposal-cadence-ms=250",
    "--consensus-min-tick-ms=10",
  ]);
  assert.deepEqual(
    [all.pollIntervalMs, all.proposalCadenceMs, all.consensusMinTickMs],
    [25, 250, 10],
  );
});

test("an argument that names an Object.prototype member does not swallow the flag after it", () => {
  // The flag table is consulted by key. A lookup that walked the prototype
  // chain would treat `constructor` as a known numeric flag, consume the NEXT
  // argv token as its value, and either drop a real flag or fail with a bounds
  // error naming a flag that does not exist. The following-flag case is what
  // makes this observable — a stray token followed by a number fails silently.
  const KNOWN = new Set([
    "out",
    "durableStore",
    "orderingProfile",
    "pollIntervalMs",
    "proposalCadenceMs",
    "consensusMinTickMs",
  ]);
  for (const stray of ["constructor", "toString", "valueOf", "hasOwnProperty"]) {
    const args = parseArgs([stray, "--poll-interval-ms", "25"]);
    assert.equal(
      args.pollIntervalMs,
      25,
      `${stray} must not consume the --poll-interval-ms that follows it`,
    );
    assert.deepEqual(
      Object.keys(args).filter((key) => !KNOWN.has(key)),
      [],
      `${stray} must not write a stray key onto the parsed args`,
    );
  }
});

test("requested profile is carried separately from the profile that actually ran", () => {
  const env = profileEnv({}, "/tmp/t", "/tmp/l", {
    orderingProfile: "Solo",
    pollIntervalMs: 25,
    proposalCadenceMs: 250,
    consensusMinTickMs: 10,
  });
  assert.equal(env.IOI_M049_ORDERING_PROFILE, "Solo");
  assert.equal(env.IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS, "25");
  assert.equal(env.ORCH_BLOCK_INTERVAL_MS, "250");
  assert.equal(env.ORCH_CONSENSUS_MIN_TICK_MS, "10");
  // Unflagged runs must not set any of them, so they stay byte-identical to
  // the M04.8 behaviour.
  const bare = profileEnv({}, "/tmp/t", "/tmp/l");
  for (const name of [
    "IOI_M049_ORDERING_PROFILE",
    "IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS",
    "ORCH_BLOCK_INTERVAL_MS",
    "ORCH_CONSENSUS_MIN_TICK_MS",
  ]) {
    assert.ok(!(name in bare), `an unflagged run must not set ${name}`);
  }
  // Each flag sets ONLY its own variable.
  const cadenceOnly = profileEnv({}, "/tmp/t", "/tmp/l", { proposalCadenceMs: 250 });
  assert.equal(cadenceOnly.ORCH_BLOCK_INTERVAL_MS, "250");
  assert.ok(!("ORCH_CONSENSUS_MIN_TICK_MS" in cadenceOnly));
  assert.ok(!("IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS" in cadenceOnly));
  const minTickOnly = profileEnv({}, "/tmp/t", "/tmp/l", { consensusMinTickMs: 0 });
  // 0 is a real request here, so it must survive rather than being dropped as
  // falsy — the bug this assertion exists to catch.
  assert.equal(minTickOnly.ORCH_CONSENSUS_MIN_TICK_MS, "0");
  assert.ok(!("ORCH_BLOCK_INTERVAL_MS" in minTickOnly));
});

test("the summation rule names only genuinely exclusive phases as summable", () => {
  const profile = buildCommitPathProfile(inputs());
  for (const name of profile.summation_rule.safe_partition) {
    assert.equal(
      PHASES[name].semantics,
      "exclusive",
      `${name} is offered as summable, so it must be exclusive`,
    );
  }
  assert.equal(Object.keys(VALUE_KINDS).length, 6);
});

test("an incompatible change carries a new schema identifier, not the predecessor's", () => {
  // The change IS breaking -- phases and fields were renamed and `exclusive`
  // changed meaning -- so it takes its own identifier. Keeping the predecessor's
  // would ask a reader holding both artifacts to tell them apart by noticing a
  // disclosure rather than by reading the version.
  const profile = buildCommitPathProfile(inputs());
  assert.equal(profile.schema_version, "ioi.m049.ordering-finality-parity-profile.v5");
  assert.notEqual(
    profile.schema_version,
    profile.schema_compatibility.predecessor,
    "a breaking change must not reuse its predecessor's identifier",
  );
  assert.equal(
    profile.schema_compatibility.predecessor,
    "ioi.m049.ordering-finality-parity-profile.v4",
    "the identifier this schema supersedes is named, not implied",
  );
  assert.equal(SCHEMA_COMPATIBILITY.version, profile.schema_version);
  assert.equal(profile.schema_compatibility.version, profile.schema_version);
  assert.equal(profile.schema_compatibility.compatible_with_predecessor, false);
});

test("both predecessor identifiers are carried so the tracked work-item anchors stay satisfied", () => {
  // docs/architecture/_meta/work-items/m04-8-wallet-authority-commit-latency.v1.json
  // requires the profiler source to CONTAIN both strings. A declared lineage
  // satisfies that honestly; continuing to EMIT either after a breaking change
  // would not.
  const profile = buildCommitPathProfile(inputs());
  assert.equal(
    profile.schema_compatibility.originating_predecessor,
    "ioi.m048.commit-path-profile.v1",
  );
  assert.equal(
    profile.schema_compatibility.predecessor,
    "ioi.m049.ordering-finality-parity-profile.v4",
  );
  assert.equal(SUPERSEDED_ARTIFACT_SCHEMA_VERSION, "ioi.m049.ordering-finality-parity-profile.v1");
});

test("the incompatibility is stated exactly, not as a bare boolean", () => {
  // "compatible_with_predecessor: false" tells a reader nothing about WHAT
  // broke. v5 names the corrected post-durability relationship; older causal
  // identities and phase splits remain available as explicit lineage.
  const profile = buildCommitPathProfile(inputs());
  const breaking = profile.schema_compatibility.breaking;
  assert.deepEqual(breaking.phase_nesting.ordering_finalization_no_longer_contains, [
    "durable_ack_publication",
  ]);
  assert.ok(
    breaking.changed_semantics.includes("post-durability status/event publication"),
    "the corrected producer/observer nesting defect must be disclosed",
  );
  assert.ok(/v4 consumer must not read a v5 artifact/u.test(
    profile.schema_compatibility.compatibility_statement,
  ));
  assert.ok(/false producer-to-observer nesting relation/u.test(
    profile.schema_compatibility.compatibility_statement,
  ));
});

test("historical v3-to-v4 receipt-alias incompatibility remains explicit", () => {
  const historical = buildCommitPathProfile(inputs()).schema_compatibility
    .historical_lineage.v3_to_v4;
  assert.deepEqual(historical.required_identity_fields.canonical_admission, [
    "proposal_tx_hash",
  ]);
  assert.ok(historical.changed_semantics.includes("client-visible receipt/status identity"));
});

test("historical v2-to-v3 canonical-attempt incompatibilities remain explicit", () => {
  const profile = buildCommitPathProfile(inputs());
  const historical = profile.schema_compatibility.historical_lineage.v2_to_v3;
  assert.deepEqual(historical.required_identity_fields.proposal_and_ordering, [
    "producer_account_id",
    "producer_node",
  ]);
  assert.deepEqual(historical.required_identity_fields.execution, [
    "observer_node",
    "view",
    "producer_account_id",
    "block_payload_hash",
  ]);
  assert.deepEqual(historical.required_identity_fields.persistence, [
    "observer_node",
    "block_payload_hash",
  ]);
  assert.deepEqual(historical.required_identity_fields.canonical_admission, [
    "tx_hash",
    "height",
    "view",
    "producer_account_id",
    "canonical_block_hash",
    "observer_node",
  ]);
  assert.ok(historical.changed_semantics.includes("selected block phases by height"));
});

test("historical v1-to-v2 incompatibilities remain explicit without masquerading as v3 breaks", () => {
  const profile = buildCommitPathProfile(inputs());
  const historical = profile.schema_compatibility.historical_lineage.v1_to_v2;
  assert.deepEqual(historical.split_slots.receipt_creation_durable_ack, [
    "receipt_creation",
    "durable_ack_publication",
  ]);
  assert.deepEqual(historical.split_slots.completion_notification_client_observation, [
    "completion_notification_transport",
    "completion_client_observation",
  ]);
  assert.deepEqual([...historical.newly_measured_phases].sort(), [
    "client_event_observation",
    "durable_ack_publication",
    "notification_transport_lag",
    "proposal_cadence_wait",
  ]);
  // Every newly-measured phase really does carry a number now.
  const [approval] = profile.approvals;
  for (const name of historical.newly_measured_phases) {
    assert.equal(typeof approval.phases[name], "number", `${name} carries a number`);
  }
  // Every split slot name really is gone from the slot list, and both halves
  // really are present.
  for (const [gone, halves] of Object.entries(historical.split_slots)) {
    assert.ok(!ORDERING_PARITY_SLOTS.includes(gone), `${gone} is no longer a slot`);
    for (const half of halves) {
      assert.ok(ORDERING_PARITY_SLOTS.includes(half), `${half} is a slot`);
    }
  }
});

test("every historical v1-to-v2 rename remains disclosed in the artifact", () => {
  const profile = buildCommitPathProfile(inputs());
  const historical = profile.schema_compatibility.historical_lineage.v1_to_v2;
  assert.equal(historical.renamed_phases.aft_inclusion_finalization, "ordering_finalization");
  assert.equal(historical.renamed_fields.proposal_cadence, "scheduler_and_block_cadence");
  // The renames are real: old names gone, new names carrying the data.
  assert.ok(!("aft_inclusion_finalization" in profile.approvals[0].phases));
  assert.ok("ordering_finalization" in profile.approvals[0].phases);
  assert.ok(!("proposal_cadence" in profile.approvals[0].ordering));
  assert.ok("scheduler_and_block_cadence" in profile.approvals[0].ordering);
  assert.ok(!("proposal_cadence" in profile.ordering_parity));
  assert.ok("scheduler_and_block_cadence" in profile.ordering_parity);
  // Every name the disclosure claims to have renamed TO must actually exist,
  // or the disclosure would send a reader to a key that is not there either.
  for (const renamed of Object.values(historical.renamed_phases)) {
    assert.ok(renamed in PHASES, `${renamed} must be a real phase`);
  }
});

test("the effective cadence is reported with the provenance of each value", () => {
  // The whole point of reporting provenance: 250ms means one thing when the
  // flag under test produced it and another when the override was ignored and
  // config answered instead. A cadence without its origin cannot distinguish
  // "the experiment ran at 250ms" from "the experiment's flag did nothing".
  const overridden = buildCommitPathProfile(
    inputs({
      ticker_interval_ms: 250,
      ticker_interval_provenance: "env:ORCH_BLOCK_INTERVAL_MS",
      min_tick_ms: 10,
      min_tick_provenance: "env:ORCH_CONSENSUS_MIN_TICK_MS",
    }),
  );
  const [cadence] = overridden.ordering_parity.scheduler_and_block_cadence.values;
  assert.equal(cadence.ticker_interval_ms, 250);
  assert.equal(cadence.ticker_interval_provenance, "env:ORCH_BLOCK_INTERVAL_MS");
  assert.equal(cadence.min_tick_ms, 10);
  assert.equal(cadence.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

  // A disabled ticker is a real cadence, reported as 0 rather than dropped.
  const disabled = buildCommitPathProfile(inputs({ ticker_interval_ms: 0 }));
  assert.equal(
    disabled.approvals[0].ordering.scheduler_and_block_cadence.ticker_interval_ms,
    0,
    "ticker_interval_ms=0 means kick-driven only, not an absent measurement",
  );
  const zeroKick = buildCommitPathProfile(
    inputs({ min_tick_ms: 0, min_tick_provenance: "env:ORCH_CONSENSUS_MIN_TICK_MS" }),
  );
  assert.equal(zeroKick.approvals[0].ordering.scheduler_and_block_cadence.min_tick_ms, 0);
});

test("FAIL CLOSED: a [BENCH-ORDERING] line missing one contracted field is refused", () => {
  for (const field of BENCH_ORDERING_CONTRACT.required_fields) {
    const identityField = ["height", "view", "producer_account_id"].includes(field);
    const complete = inputs();
    const stripped = complete.traceText
      .split("\n")
      .map((line) =>
        line.includes(BENCH_ORDERING_CONTRACT.tag)
          ? line.replace(new RegExp(`\\s${field}=\\S+`, "u"), "")
          : line,
      )
      .join("\n");
    assert.throws(
      () => buildCommitPathProfile({ ...complete, traceText: stripped }),
      identityField
        ? /\[BENCH-ORDERING\] canonical attempt .* has 0 observations/u
        : new RegExp(`omits required field '${field}'`, "u"),
      `a [BENCH-ORDERING] line without ${field} must fail closed`,
    );
  }
});

test("FAIL CLOSED: a cadence whose provenance this parser cannot name is refused", () => {
  // A provenance token the parser does not know means the emitter resolved the
  // cadence by a path this file has not been taught. Recording the number
  // anyway would present an unexplained value as an explained one.
  assert.throws(
    () => buildCommitPathProfile(inputs({ ticker_interval_provenance: "env:SOMETHING_ELSE" })),
    /ticker_interval_provenance=env:SOMETHING_ELSE, which this parser does not know/u,
  );
  assert.throws(
    () => buildCommitPathProfile(inputs({ min_tick_provenance: "guessed" })),
    /min_tick_provenance=guessed, which this parser does not know/u,
  );
  // Every provenance the emitter can actually produce is accepted, so the
  // check above cannot pass by refusing everything.
  for (const provenance of BENCH_ORDERING_CONTRACT.known_ticker_provenances) {
    assert.equal(
      buildCommitPathProfile(inputs({ ticker_interval_provenance: provenance })).approvals[0]
        .ordering.scheduler_and_block_cadence.ticker_interval_provenance,
      provenance,
    );
  }
  for (const provenance of BENCH_ORDERING_CONTRACT.known_min_tick_provenances) {
    assert.equal(
      buildCommitPathProfile(inputs({ min_tick_provenance: provenance })).approvals[0].ordering
        .scheduler_and_block_cadence.min_tick_provenance,
      provenance,
    );
  }
  // The block-interval floor is held to the same bar. It matters more than the
  // others: it is the value that actually spaces blocks, so a floor whose
  // origin cannot be named is a floor the profile cannot attribute a cadence to.
  assert.throws(
    () =>
      buildCommitPathProfile(inputs({ genesis_block_interval_provenance: "genesis:assumed" })),
    /genesis_block_interval_provenance=genesis:assumed, which this parser does not know/u,
  );
  for (const provenance of BENCH_ORDERING_CONTRACT.known_block_interval_provenances) {
    assert.equal(
      buildCommitPathProfile(inputs({ genesis_block_interval_provenance: provenance }))
        .approvals[0].ordering.scheduler_and_block_cadence.genesis_block_interval_provenance,
      provenance,
    );
  }
});

test("a run that changed cadence mid-flight is surfaced as two cadence values", () => {
  // Averaging or collapsing them would hide that the run was not one experiment.
  const single = inputs();
  const otherHeight = 413;
  const mixed = [
    single.traceText,
    ...secondaryBlockLines(otherHeight, {
      tickerIntervalMs: 250,
      tickerProvenance: "env:ORCH_BLOCK_INTERVAL_MS",
      genesisIntervalMs: 250,
      genesisProvenance: "env:IOI_BENCH_BLOCK_INTERVAL_MS",
      blockTimestampMs: 1_772_000_412_250,
      proposalObservedAtMs: 1_772_000_412_350,
    }),
  ].join("\n");
  const profile = buildCommitPathProfile({
    ...single,
    approvalFields: parseApprovalLines(mixed),
    traceText: mixed,
  });
  // One engine throughout, so this is a legal profile — but two cadences, and
  // both are reported.
  assert.equal(profile.ordering_parity.ordering_profile, "aft");
  assert.equal(profile.ordering_parity.scheduler_and_block_cadence.values.length, 2);
  assert.deepEqual(
    profile.ordering_parity.scheduler_and_block_cadence.values.map((v) => v.ticker_interval_ms).sort((a, b) => a - b),
    [250, 1000],
  );
});

// ---------------------------------------------------------------------------
// Cadence actually reaches block production
// ---------------------------------------------------------------------------

test("--proposal-cadence-ms sets BOTH the scheduler ticker and the on-chain genesis floor", () => {
  // The defect this exists to prevent: the flag moved only the ticker, but
  // block production defers until the on-chain timestamp is due, so with the
  // historical 1000ms genesis floor every requested cadence below 1000ms
  // produced identical 1000ms blocks while the artifact reported the request.
  const env = profileEnv({}, "/tmp/t", "/tmp/l", { proposalCadenceMs: 50 });
  assert.equal(env.ORCH_BLOCK_INTERVAL_MS, "50", "the scheduler ticker must move");
  assert.equal(
    env.IOI_BENCH_BLOCK_INTERVAL_MS,
    "50",
    "the on-chain genesis floor must move too, or the cadence is inert below 1000ms",
  );
  assert.equal(
    env.ORCH_BLOCK_INTERVAL_MS,
    env.IOI_BENCH_BLOCK_INTERVAL_MS,
    "one flag means one value; a divergence would silently vary two dimensions",
  );

  // Unflagged runs touch neither, so the historical genesis is preserved.
  const bare = profileEnv({}, "/tmp/t", "/tmp/l");
  assert.ok(!("ORCH_BLOCK_INTERVAL_MS" in bare));
  assert.ok(!("IOI_BENCH_BLOCK_INTERVAL_MS" in bare));

  // The other two flags must not reach the genesis floor.
  const minTickOnly = profileEnv({}, "/tmp/t", "/tmp/l", { consensusMinTickMs: 10 });
  assert.ok(!("IOI_BENCH_BLOCK_INTERVAL_MS" in minTickOnly));
  const pollOnly = profileEnv({}, "/tmp/t", "/tmp/l", { pollIntervalMs: 25 });
  assert.ok(!("IOI_BENCH_BLOCK_INTERVAL_MS" in pollOnly));
});

test("the wrapper bound matches the tighter of the two receivers", () => {
  // The genesis builder rejects >60000ms by panicking. A wrapper that accepted
  // more would hand the fixture a value that aborts it during genesis
  // construction rather than being refused up front.
  assert.equal(parseArgs(["--proposal-cadence-ms", "60000"]).proposalCadenceMs, 60_000);
  assert.throws(
    () => parseArgs(["--proposal-cadence-ms", "60001"]),
    /--proposal-cadence-ms must be an integer in 1\.\.=60000/u,
  );
});

test("realized proposal spacing comes from producer wall time, not header timestamps", () => {
  // Header timestamps advance by the on-chain interval by construction. The
  // producer wall-clock seam is independent and can show that actual proposal
  // construction could not keep up with a requested floor.
  const single = inputs();
  const nextHeight = HEIGHT + 1;
  const spacedTrace = [
    single.traceText,
    ...secondaryBlockLines(nextHeight, {
      tickerIntervalMs: 50,
      tickerProvenance: "env:ORCH_BLOCK_INTERVAL_MS",
      genesisIntervalMs: 50,
      genesisProvenance: "env:IOI_BENCH_BLOCK_INTERVAL_MS",
      blockTimestampMs: BASE.block_timestamp_ms + 50,
      proposalObservedAtMs: BASE.proposal_observed_at_ms + 1000,
    }),
  ].join("\n");
  const profile = buildCommitPathProfile({
    ...single,
    approvalFields: parseApprovalLines(spacedTrace),
    traceText: spacedTrace,
  });

  // Chain time advances 50ms; producer wall time advances 1000ms. The latter,
  // and only the latter, is reported as realized proposal spacing.
  assert.deepEqual(profile.ordering_parity.observed_proposal_interval_ms.values, [1000]);
  assert.equal(profile.ordering_parity.observed_proposal_interval_ms.measured, true);
  assert.ok(
    profile.ordering_parity.scheduler_and_block_cadence.values.some(
      (value) => value.genesis_block_interval_ms === 50,
    ),
    "the configured floor is reported alongside, so the contradiction is visible",
  );
});

test("non-adjacent heights are not differenced into a proposal-spacing claim", () => {
  // One approval means no adjacent pair, so there is no realized spacing to
  // report. Inventing one from a single height would be fabrication.
  const profile = buildCommitPathProfile(inputs());
  assert.deepEqual(profile.ordering_parity.observed_proposal_interval_ms.values, []);
});

// ---------------------------------------------------------------------------
// Phase vocabulary
// ---------------------------------------------------------------------------

test("exclusive means a disjoint LEAF, not disjoint from the containers holding it", () => {
  // The old wording -- "disjoint from every other phase" -- was contradicted by
  // the rows carrying it: state_commitment_materialization is exclusive AND
  // declares it is nested inside execution_commit. Both cannot be true as
  // written, and a reader resolving the contradiction either way gets the
  // summation rule wrong.
  assert.ok(
    !VALUE_KINDS.exclusive.includes("Disjoint from every other phase"),
    "the self-contradictory definition must be gone",
  );
  assert.ok(VALUE_KINDS.exclusive.includes("LEAF"));
  assert.ok(
    VALUE_KINDS.exclusive.includes("OTHER exclusive leaf"),
    "disjointness must be scoped to other exclusive leaves",
  );
  // And the rows are consistent with it: every exclusive phase contains
  // nothing, and may still be nested.
  for (const [name, phase] of Object.entries(PHASES)) {
    if (phase.semantics !== "exclusive") continue;
    assert.deepEqual(phase.contains, [], `${name} is a leaf, so it contains nothing`);
  }
  assert.ok(
    PHASES.state_commitment_materialization.nested_in.length > 0,
    "an exclusive leaf can still be nested; that is the point of the correction",
  );
});

test("execution_prepare is a summable leaf and is offered as one", () => {
  // It declares contains: [] and runs before commitment, so it overlaps no
  // other leaf. Labelling it inclusive kept genuinely disjoint execution time
  // out of every partition a reader built from safe_partition.
  assert.equal(PHASES.execution_prepare.semantics, "exclusive");
  assert.deepEqual(PHASES.execution_prepare.contains, []);
  const profile = buildCommitPathProfile(inputs());
  assert.ok(
    profile.summation_rule.safe_partition.includes("execution_prepare"),
    "a disjoint measured leaf must be offered as summable",
  );
});

test("safe_partition is exactly the exclusive leaves, derived rather than hand-listed", () => {
  // A hand-maintained list drifts from the labels. Deriving it means a future
  // relabel cannot leave the summation rule stale.
  const profile = buildCommitPathProfile(inputs());
  const exclusiveLeaves = Object.entries(PHASES)
    .filter(([, phase]) => phase.semantics === "exclusive")
    .map(([name]) => name)
    .sort();
  assert.deepEqual([...profile.summation_rule.safe_partition].sort(), exclusiveLeaves);
  for (const name of profile.summation_rule.safe_partition) {
    assert.equal(PHASES[name].semantics, "exclusive");
  }
});

test("the summation rule states that the leaves are a lower bound, not a partition of the whole", () => {
  // Pairwise disjoint is not exhaustive. Saying "partition" without saying
  // "not exhaustive" invites a reader to treat the sum as the container's total
  // and conclude the residual is zero.
  const profile = buildCommitPathProfile(inputs());
  assert.equal(profile.summation_rule.partition_is_exhaustive, false);
  assert.ok(profile.summation_rule.note.includes("LOWER BOUND"));

  // The arithmetic backs the wording: the named leaves really do fall short of
  // the container that holds them.
  const [approval] = profile.approvals;
  const leafSumInsideCommit =
    approval.phases.state_commitment_materialization + approval.phases.durable_persistence;
  assert.ok(
    leafSumInsideCommit < approval.phases.execution_commit,
    "the leaves inside execution_commit must not be claimed to exhaust it",
  );
  assert.equal(
    approval.derived_exclusive_ms.commit_excluding_commitment_and_store,
    approval.phases.execution_commit - leafSumInsideCommit,
    "the residual is exactly the shortfall the wording describes",
  );
});

// ---------------------------------------------------------------------------
// Nonclaims
// ---------------------------------------------------------------------------

test("the ticker is NOT claimed to bound when a queued tx is picked up", () => {
  // The previous nonclaim asserted the false direction outright. Under the
  // block-timestamp deferral the ticker bounds polling only.
  const profile = buildCommitPathProfile(inputs());
  const joined = profile.nonclaims.join("\n");
  assert.ok(
    !/ticker_interval_ms and min_tick_ms bound when a queued tx can be picked up/u.test(joined),
    "the false claim must be gone",
  );
  assert.ok(
    /bound only how often consensus is POLLED/u.test(joined),
    "and replaced with what they actually bound",
  );
  assert.ok(
    /genesis_block_interval_ms is the binding floor/u.test(joined),
    "naming the mechanism that does bind pickup",
  );
});

test("no proof generation, size, or verification cost is claimed", () => {
  const profile = buildCommitPathProfile(inputs());
  const joined = profile.nonclaims.join("\n");
  assert.ok(/No proof generation, proof size, or cryptographic proof verification is measured/u.test(joined));
  assert.ok(/not a portable proof/u.test(joined));
  // The phase that sounds like a proof measurement says what it actually is.
  assert.ok(
    PHASES.proof_exact_state_resolution.describes.length > 0,
    "the phase describes itself",
  );
});

test("the artifact discloses what co-varies with the ordering profile", () => {
  // The prior cut claimed the ordering profile was the only varied dimension
  // while Solo timestamped on a whole-second wall clock and AFT did not. That
  // co-variable is now removed at the source; the claim is only admissible
  // because the shared abstraction makes it true.
  const profile = buildCommitPathProfile(inputs());
  const control = profile.ordering_parity.dimension_control;
  assert.deepEqual(control.varied, [
    "ordering_profile",
    "profile-required validator topology",
  ]);
  assert.deepEqual(profile.ordering_parity.required_topology, {
    validator_processes: 4,
    voting_members: 4,
    byzantine_fault_tolerance: 1,
    quorum_rule: "3 distinct authenticated signatures (2f+1)",
    synchrony_assumption: "partial_synchrony",
  });
  assert.ok(
    control.held_identical.some((entry) => /compute_next_timestamp_ms/u.test(entry)),
    "the shared timestamp derivation is what makes the single-dimension claim true",
  );
  assert.ok(
    control.unmeasured_timing_dimensions.length > 0,
    "remaining unmeasured timing dimensions are named, not implied absent",
  );
  assert.ok(control.residual_risk.length > 0);
  // The gap that was closed is REMOVED from the open list. A resolved gap left
  // listed as open is as misleading as an open gap left unlisted.
  assert.ok(
    !control.unmeasured_timing_dimensions.some((entry) =>
      /is not bracketed by any seam/u.test(entry),
    ),
    "the mempool-to-proposal wait is measured now and must not still be listed as unbracketed",
  );
});

// ---------------------------------------------------------------------------
// M04.9(a): per-transaction proposal wait
// ---------------------------------------------------------------------------

test("the proposal wait is correlated by the canonical raw proposal hash, not by height", () => {
  const profile = buildCommitPathProfile(inputs());
  const [approval] = profile.approvals;
  assert.equal(approval.tx_hash, TX_HASH);
  assert.equal(
    approval.phases.proposal_cadence_wait,
    BASE.proposal_selected_at_ms - BASE.first_seen_at_ms,
  );
  assert.equal(approval.proposal_wait.first_seen_at_ms, BASE.first_seen_at_ms);
  assert.equal(approval.proposal_wait.proposal_selected_at_ms, BASE.proposal_selected_at_ms);
  assert.equal(approval.proposal_wait.correlated_by, "canonical_attempt.proposal_tx_hash");
  // The contract states the rule in the artifact, so a reader does not have to
  // infer it from which fields happen to be present.
  assert.ok(profile.correlation_contract.by_tx_hash.includes(BENCH_PROPOSAL_WAIT_CONTRACT.tag));
  assert.ok(!profile.correlation_contract.by_height.includes(BENCH_PROPOSAL_WAIT_CONTRACT.tag));
});

test("a client-visible receipt alias is never used as the raw proposal identity", () => {
  const proposalTxHash = "9".repeat(64);
  const profile = buildCommitPathProfile(
    inputs({
      proposal_tx_hash: proposalTxHash,
      proposal_wait_tx_hash: proposalTxHash,
    }),
  );
  const [approval] = profile.approvals;
  assert.equal(approval.tx_hash, TX_HASH, "the approval remains keyed by its client-visible alias");
  assert.equal(approval.canonical_attempt.client_visible_tx_hash, TX_HASH);
  assert.equal(approval.canonical_attempt.proposal_tx_hash, proposalTxHash);
  assert.equal(approval.proposal_wait.selected_from_attempt_observations, 1);
  assert.equal(approval.phases.proposal_cadence_wait, 950);
});

test("MULTI-TX: two approvals at one height get their own waits and their own events", () => {
  // The exact defect a height join produces: one transaction's wait copied
  // onto every row in its block. Both approvals below commit at HEIGHT, so
  // every height-keyed phase must agree and every hash-keyed phase must not.
  const base = inputs();
  const traceText = [
    base.traceText,
    ...secondaryApprovalLines(HEIGHT, {
      requestHash: "d".repeat(64),
      firstSeenAtMs: BASE.first_seen_at_ms + 700,
      eventObservedAtMs: BASE.event_observed_at_ms + 40,
    }),
  ].join("\n");

  const profile = buildCommitPathProfile({
    ...base,
    approvalFields: parseApprovalLines(traceText),
    traceText,
  });

  assert.equal(profile.approvals.length, 2);
  const [first, other] = profile.approvals;
  assert.equal(first.dimensions.committed_height, other.dimensions.committed_height);
  assert.notEqual(
    first.phases.proposal_cadence_wait,
    other.phases.proposal_cadence_wait,
    "same height, different waits -- a height join would have made these equal",
  );
  assert.equal(first.phases.proposal_cadence_wait, 950);
  assert.equal(other.phases.proposal_cadence_wait, 250);
  assert.notEqual(
    first.phases.notification_transport_lag,
    other.phases.notification_transport_lag,
    "and different transport lags",
  );
  // The block-level phases DO coincide, which is correct: they measure
  // per-block work, and one block did it once.
  assert.equal(first.phases.ordering_finalization, other.phases.ordering_finalization);
  assert.equal(first.phases.durable_persistence, other.phases.durable_persistence);
  assert.equal(first.phases.durable_ack_publication, other.phases.durable_ack_publication);
});

test("FAIL CLOSED: a missing proposal-wait line refuses rather than defaulting the wait", () => {
  assert.throws(
    () => buildCommitPathProfile(inputs({}, { dropLines: [BENCH_PROPOSAL_WAIT_CONTRACT.tag] })),
    /\[BENCH-PROPOSAL-WAIT\] canonical attempt for proposal tx/u,
  );
});

test("FAIL CLOSED: a proposal-wait line for a DIFFERENT transaction is not borrowed", () => {
  // The line exists, is well-formed, and names the SAME height -- it simply
  // belongs to another transaction. Accepting it would report a wait this
  // approval never experienced, which a height-keyed join would have done.
  assert.throws(
    () => buildCommitPathProfile(inputs({ proposal_wait_tx_hash: "f".repeat(64) })),
    new RegExp(`\\[BENCH-PROPOSAL-WAIT\\] canonical attempt for proposal tx ${TX_HASH}`, "u"),
  );
});

test("FAIL CLOSED: an approval whose tx_hash is not a hex digest cannot be correlated", () => {
  // Correlation is by transaction hash, so an approval line that carries no
  // usable hash has nothing to correlate on. It refuses rather than falling
  // back to the height it also carries.
  const base = inputs();
  const truncated = base.traceText
    .split("\n")
    .map((line) =>
      line.includes("[BENCH-APPROVAL]") ? line.replace(`tx_hash=${TX_HASH}`, "tx_hash=deadbeef") : line,
    )
    .join("\n");
  assert.throws(
    () =>
      buildCommitPathProfile({
        ...base,
        approvalFields: parseApprovalLines(truncated),
        traceText: truncated,
      }),
    /which is not a 64-character hex transaction hash/u,
  );
});

test("FAIL CLOSED: a duplicated proposal-wait line refuses instead of picking one", () => {
  const base = inputs();
  const duplicated = [base.traceText, proposalWaitLine({ ...BASE, first_seen_at_ms: 1 })].join(
    "\n",
  );
  assert.throws(
    () => buildCommitPathProfile({ ...base, traceText: duplicated }),
    /canonical attempt for proposal tx c{64} has 2 observations/u,
  );
});

test("peer-bearing noncanonical proposal attempts remain visible but are not attributed", () => {
  const base = inputs();
  const otherProducer = "1".repeat(64);
  const losingAttempt =
    `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} ${BENCH_PROPOSAL_WAIT_CONTRACT.op} ` +
    `tx_hash=${TX_HASH} height=${HEIGHT} view=0 producer_account_id=${otherProducer} ` +
    "producer_node=validator-20100-orch first_seen_at_ms=1772000411001 " +
    "proposal_selected_at_ms=1772000412051 proposal_wait_ms=1050";
  const traceText = `${base.traceText}\n${losingAttempt}`;
  const profile = buildCommitPathProfile({ ...base, traceText });
  assert.equal(profile.approvals[0].phases.proposal_cadence_wait, 950);
  assert.equal(profile.approvals[0].proposal_wait.selected_from_attempt_observations, 2);
  assert.equal(profile.approvals[0].canonical_attempt.view, 1);
  assert.equal(profile.approvals[0].canonical_attempt.producer_account_id, PRODUCER_ACCOUNT_ID);
});

test("Agentgres observer replicas must agree on one canonical attempt", () => {
  const base = inputs();
  const replicated =
    `${BENCH_CANONICAL_TX_CONTRACT.tag} ${BENCH_CANONICAL_TX_CONTRACT.op} ` +
    `tx_hash=${TX_HASH} proposal_tx_hash=${TX_HASH} height=${HEIGHT} view=1 producer_account_id=${PRODUCER_ACCOUNT_ID} ` +
    `canonical_block_hash=${CANONICAL_BLOCK_HASH} observer_node=validator-20100-orch`;
  const replicatedTrace = `${base.traceText}\n${replicated}`;
  const profile = buildCommitPathProfile({ ...base, traceText: replicatedTrace });
  assert.equal(profile.approvals[0].canonical_attempt.agentgres_observer_count, 2);

  const conflicting = replicated.replace("view=1", "view=2");
  assert.throws(
    () => buildCommitPathProfile({ ...base, traceText: `${base.traceText}\n${conflicting}` }),
    /reported 2 canonical identities/u,
  );
});

test("FAIL CLOSED: a proposal-wait line whose difference contradicts its own edges refuses", () => {
  // Both raw edges are carried so the reported difference can be RECHECKED.
  // A line that fails its own recheck is refused, not reconciled.
  assert.throws(
    () => buildCommitPathProfile(inputs({ proposal_wait_ms: 4242 })),
    /is not the saturating difference of its own/u,
  );
  // Not vacuous: the honest value passes.
  assert.equal(
    buildCommitPathProfile(inputs({ proposal_wait_ms: 950 })).approvals[0].phases
      .proposal_cadence_wait,
    950,
  );
});

test("FAIL CLOSED: an unknown field on the proposal-wait line does not smuggle in a phase", () => {
  // Extra fields are ignored -- log framing routinely adds them -- but they can
  // never SUPPLY a required one. Dropping a required field and adding a
  // plausible-looking substitute must still refuse.
  const base = inputs();
  const tampered = base.traceText
    .split("\n")
    .map((line) =>
      line.includes(BENCH_PROPOSAL_WAIT_CONTRACT.tag)
        ? line.replace(/proposal_wait_ms=\d+/u, "mempool_wait_ms=950 unrelated_field=abc")
        : line,
    )
    .join("\n");
  assert.throws(
    () => buildCommitPathProfile({ ...base, traceText: tampered }),
    /omits required field 'proposal_wait_ms'/u,
  );
});

test("indexByTxHash ignores lines whose hash is not a 64-character hex digest", () => {
  const text = [
    `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} selected tx_hash=deadbeef height=1 view=0 first_seen_at_ms=1 proposal_selected_at_ms=2 proposal_wait_ms=1`,
    `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} selected height=1 view=0 first_seen_at_ms=1 proposal_selected_at_ms=2 proposal_wait_ms=1`,
    `${BENCH_PROPOSAL_WAIT_CONTRACT.tag} selected tx_hash=${TX_HASH} height=1 view=0 first_seen_at_ms=1 proposal_selected_at_ms=2 proposal_wait_ms=1`,
  ].join("\n");
  const { index, duplicates } = indexByTxHash(text, BENCH_PROPOSAL_WAIT_CONTRACT.tag, "selected");
  assert.deepEqual([...index.keys()], [TX_HASH]);
  assert.equal(duplicates.size, 0);
  // A different op on the same tag is not this observation.
  assert.equal(indexByTxHash(text, BENCH_PROPOSAL_WAIT_CONTRACT.tag, "other").index.size, 0);
});

// ---------------------------------------------------------------------------
// M04.9(a): exact per-transaction completion event
// ---------------------------------------------------------------------------

test("the exact completion event separates publication, transport, and observation", () => {
  const profile = buildCommitPathProfile(inputs());
  const [approval] = profile.approvals;

  assert.equal(
    approval.phases.durable_ack_publication,
    BASE.event_published_at_ms - BASE.event_durable_commit_ms,
  );
  assert.equal(
    approval.phases.notification_transport_lag,
    BASE.event_observed_at_ms - BASE.event_published_at_ms,
  );
  assert.equal(approval.phases.client_event_observation, BASE.event_wait_ms);
  // The polled observation is retained beside it, not replaced.
  assert.equal(approval.phases.client_commit_wait, BASE.commit_wait_ms);
  assert.notEqual(
    approval.phases.client_event_observation,
    approval.phases.client_commit_wait,
    "two mechanisms, two numbers",
  );
  // Raw edges carried so every derived value can be recomputed.
  assert.equal(approval.completion_event.durable_commit_ms, BASE.event_durable_commit_ms);
  assert.equal(approval.completion_event.published_at_ms, BASE.event_published_at_ms);
  assert.equal(approval.completion_event.observed_at_ms, BASE.event_observed_at_ms);
  assert.equal(approval.completion_event.correlated_by, "tx_hash");
  assert.ok(
    /clock/u.test(approval.completion_event.transport_lag_clock_domain),
    "the cross-clock caveat travels with the value it qualifies",
  );
});

test("MUTATION: moving the publication instant moves EXACTLY publication and transport", () => {
  // `durable_ack_publication` is derived from two timestamps, so no single
  // field moves it alone. Delaying publication by 7000ms lengthens the
  // publication interval by 7000 and shortens the transport lag by 7000 --
  // stated exactly, because approximating it would hide a real consequence.
  const baseline = phasesOf();
  const mutated = phasesOf({
    event_published_at_ms: BASE.event_published_at_ms + PLANTED_DELAY_MS,
  });
  assert.equal(
    mutated.durable_ack_publication,
    baseline.durable_ack_publication + PLANTED_DELAY_MS,
  );
  assert.equal(
    mutated.notification_transport_lag,
    baseline.notification_transport_lag - PLANTED_DELAY_MS,
  );
  for (const name of REQUIRED_PHASES) {
    if (name === "durable_ack_publication" || name === "notification_transport_lag") continue;
    assert.equal(mutated[name], baseline[name], `${name} must not move`);
  }
});

test("MUTATION: moving the durable-commit instant moves EXACTLY the publication interval", () => {
  const baseline = phasesOf();
  const earlier = phasesOf({
    event_durable_commit_ms: BASE.event_durable_commit_ms - PLANTED_DELAY_MS,
  });
  assert.equal(
    earlier.durable_ack_publication,
    baseline.durable_ack_publication + PLANTED_DELAY_MS,
  );
  for (const name of REQUIRED_PHASES) {
    if (name === "durable_ack_publication") continue;
    assert.equal(earlier[name], baseline[name], `${name} must not move`);
  }
});

test("FAIL CLOSED: publication before the durability it asserts refuses", () => {
  // The impossibility the seam exists to guarantee. If a profile ever carries
  // this, either the ordering regressed or the timestamps are not what they
  // claim; neither is something to average into a summary.
  assert.throws(
    () =>
      buildCommitPathProfile(
        inputs({ event_published_at_ms: BASE.event_durable_commit_ms - 1 }),
      ),
    /before the \d+ms durability it asserts/u,
  );
  // The boundary is legal: same-millisecond publication is a real zero.
  assert.equal(
    buildCommitPathProfile(
      inputs({ event_published_at_ms: BASE.event_durable_commit_ms }),
    ).approvals[0].phases.durable_ack_publication,
    0,
  );
});

test("FAIL CLOSED: an event height disagreeing with the committed status refuses", () => {
  assert.throws(
    () => buildCommitPathProfile(inputs({ event_committed_height: HEIGHT + 1 })),
    /does not choose between two disagreeing observations/u,
  );
});

test("FAIL CLOSED: a missing exact-event field refuses rather than reporting the polled figure", () => {
  const base = inputs();
  for (const [field, pattern] of [
    ["event_wait_ms", /event-driven completion wait/u],
    ["event_committed_height", /committing height reported by the completion event/u],
    ["event_durable_commit_ms", /server durable-linearization timestamp/u],
    ["event_published_at_ms", /server notification-publication timestamp/u],
    ["event_observed_at_ms", /client notification-observation timestamp/u],
  ]) {
    const stripped = base.traceText
      .split("\n")
      .map((line) =>
        line.includes("[BENCH-APPROVAL]")
          ? line.replace(new RegExp(`\\s${field}=\\S+`, "u"), "")
          : line,
      )
      .join("\n");
    assert.throws(
      () =>
        buildCommitPathProfile({
          ...base,
          approvalFields: parseApprovalLines(stripped),
          traceText: stripped,
        }),
      pattern,
      `a missing ${field} must refuse`,
    );
  }
});

test("FAIL CLOSED: an `unavailable` exact-event field refuses, and is not read as zero", () => {
  // The client emits `unavailable` only on a run that never subscribed. Such a
  // run is not an event-driven profile, and reading `unavailable` as 0 would
  // report a zero-cost notification.
  const base = inputs();
  const unavailable = base.traceText
    .split("\n")
    .map((line) =>
      line.includes("[BENCH-APPROVAL]")
        ? line.replace(/event_wait_ms=\d+/u, "event_wait_ms=unavailable")
        : line,
    )
    .join("\n");
  assert.throws(
    () =>
      buildCommitPathProfile({
        ...base,
        approvalFields: parseApprovalLines(unavailable),
        traceText: unavailable,
      }),
    /event-driven completion wait/u,
  );
});

test("a client clock behind the server's is surfaced as an anomaly, never clamped", () => {
  const profile = buildCommitPathProfile(
    inputs({ event_observed_at_ms: BASE.event_published_at_ms - 5 }),
  );
  const [approval] = profile.approvals;
  assert.equal(approval.phases.notification_transport_lag, -5, "the reading is not floored at 0");
  assert.ok(
    approval.anomalies.some((entry) => entry.startsWith("notification_transport_lag_negative")),
    "and the disagreement is reported",
  );
  assert.equal(profile.coverage.approvals_with_anomalies, 1);
});

// ---------------------------------------------------------------------------
// M04.9(a): planted-delay contract
// ---------------------------------------------------------------------------

test("the planted-delay apparatus is declared, and refuses more than it accepts", () => {
  const profile = buildCommitPathProfile(inputs());
  const contract = profile.planted_delay_contract;
  assert.deepEqual(contract.arming.required_together, [
    "IOI_AFT_BENCH_TRACE",
    "IOI_TESTING_M049_PLANTED_PHASE_DELAY",
  ]);
  assert.equal(contract, PLANTED_DELAY_CONTRACT);
  // Every wired phase names WHICH artifact phase it moves, so a reader can
  // check the attribution claim rather than take it.
  assert.deepEqual(Object.keys(contract.wired_phases).sort(), [
    "durable_ack_publication",
    "proposal_selection",
  ]);
  assert.ok(
    /leaves proposal_cadence_wait where it was/u.test(
      contract.wired_phases.proposal_selection,
    ),
    "the selection seam declares what it does NOT move",
  );
  // Both wired phase names correspond to something real: one is an artifact
  // phase, the other names the span it moves.
  assert.ok("durable_ack_publication" in PHASES);
  assert.ok(
    contract.refuses.some((entry) => /without IOI_AFT_BENCH_TRACE/u.test(entry)),
    "an unarmed spec refuses rather than silently planting nothing",
  );
  assert.ok(contract.refuses.some((entry) => /more than one phase/u.test(entry)));
  assert.ok(contract.refuses.some((entry) => /zero delay/u.test(entry)));
  assert.ok(/not a production default/u.test(contract.is_not));
});

test("the nonclaims name every residual the new instrumentation leaves open", () => {
  const joined = buildCommitPathProfile(inputs()).nonclaims.join("\n");
  assert.ok(
    /proposal_cadence_wait spans the inter-tick gap and the block-production deferral/u.test(
      joined,
    ),
    "the proposal wait does not attribute between the two mechanisms it spans",
  );
  assert.ok(
    /not monotonic-clock derived/u.test(joined),
    "and it discloses which clock it was taken from",
  );
  assert.ok(
    /durable_ack_publication measures publication AFTER durable linearization/u.test(joined),
    "the publication interval is not receipt creation",
  );
  assert.ok(
    /It is not a proof of inclusion, a receipt, or an authority grant/u.test(joined),
    "the completion event is not upgraded into a proof",
  );
  assert.ok(
    /carries their clock offset/u.test(joined),
    "the cross-clock caveat is a nonclaim, not only a phase annotation",
  );
  assert.ok(
    /receipt_creation is unmeasured/u.test(joined),
    "receipt creation stays unmeasured after the split",
  );
});
