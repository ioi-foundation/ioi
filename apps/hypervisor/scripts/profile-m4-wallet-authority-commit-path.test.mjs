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
  BENCH_IAVL_CONTRACT,
  BENCH_ORDERING_CONTRACT,
  EVENT_DRIVEN_COMPLETION,
  ORDERING_PARITY_SLOTS,
  PHASES,
  READY_HEIGHT_LAG_MAX,
  SCHEMA_COMPATIBILITY,
  REQUIRED_PHASES,
  UNMEASURED_PHASES,
  VALUE_KINDS,
  buildCommitPathProfile,
  decimalMillisecondField,
  indexByHeight,
  integerField,
  millisecondValue,
  parseApprovalLines,
  parseBenchLine,
  parseArgs,
  parseObservationRecords,
  profileEnv,
} from "./profile-m4-wallet-authority-commit-path.mjs";

const REQUEST_HASH = "a".repeat(64);
const POLICY_HASH = "b".repeat(64);
const HEIGHT = 412;

const BASE = {
  admission_ms: 3,
  commit_wait_ms: 2500,
  commit_poll_count: 5,
  commit_poll_interval_ms: 500,
  approval_query_ms: 7,
  approval_verify_ms: 1,
  authority_resolution_ms: 2600,
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
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${HEIGHT} view=1 ordering_profile=${v.ordering_profile} ticker_interval_ms=${v.ticker_interval_ms} ticker_interval_provenance=${v.ticker_interval_provenance} min_tick_ms=${v.min_tick_ms} min_tick_provenance=${v.min_tick_provenance} view_timeout_secs=${v.view_timeout_secs}`,
    `[BENCH-CONSENSUS] proposal_select height=${HEIGHT} view=1 candidate_txs=1 valid_txs=1 select_ms=${v.select_ms} verify_ms=${v.verify_ms}`,
    `[BENCH-CONSENSUS] proposal_process height=${HEIGHT} view=1 tx_count=1 process_block_ms=${v.process_block_ms}`,
    `[BENCH-CONSENSUS] proposal_finalize height=${HEIGHT} view=1 finalize_ms=${v.finalize_ms}`,
    `[BENCH-EXEC] prepare_block height=${HEIGHT} tx_count=1 replay_mode=none replay_gate=none nonce_chain_edges=0 replay_debt=0 validation_aborts=0 validation_errors=0 validation_rewinds=0 execution_errors=0 snapshot_ms=1 parallel_exec_ms=2 fallback_exec_ms=0 overlay_ms=0 collect_results_ms=0 roots_ms=1 total_ms=${v.prepare_total_ms}`,
    `[BENCH-EXEC] commit_block height=${HEIGHT} tx_count=1 proof_verify_ms=0 apply_ms=90 end_block_ms=4 persist_ms=${v.commit_persist_ms} put_block_ms=0 total_ms=${v.commit_total_ms} snapshot_clone_ms=${v.snapshot_clone_ms} block_bytes=${v.block_bytes} proc_cpu_user_ms=${v.proc_cpu_user_ms} proc_cpu_sys_ms=${v.proc_cpu_sys_ms}`,
    `${BENCH_IAVL_CONTRACT.tag} commit height=${HEIGHT} version_count=${v.version_count} tree_depth=${v.tree_depth} unique_nodes=${v.unique_nodes} new_nodes=${v.new_nodes} new_node_bytes=${v.new_node_bytes} block_bytes=${v.block_bytes} commitment_ms=${v.commitment_ms} durable_store_ms=${v.durable_store_ms} atomic_state_block=${v.atomic_state_block}`,
    `[BENCH-APPROVAL] request_hash=${REQUEST_HASH} policy_hash=${POLICY_HASH} principal_ref=org://acme/research target_scope=room_participation.request tx_hash=deadbeef admission_ms=${v.admission_ms} committed_height=${v.committed_height ?? HEIGHT} commit_wait_ms=${v.commit_wait_ms} commit_poll_count=${v.commit_poll_count} commit_poll_interval_ms=${v.commit_poll_interval_ms} approval_query_ms=${v.approval_query_ms} approval_verify_ms=${v.approval_verify_ms}`,
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
const PLANT_FIELD = {
  client_submission_admission: "admission_ms",
  client_commit_wait: "commit_wait_ms",
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

test("all ten ordering-parity slots are represented, measured or explicitly not", () => {
  const covered = new Set(Object.values(PHASES).map((phase) => phase.slot));
  for (const slot of ORDERING_PARITY_SLOTS) {
    assert.ok(covered.has(slot), `slot '${slot}' must be present, even if unmeasured`);
  }
  assert.equal(ORDERING_PARITY_SLOTS.length, 10, "the contract names exactly ten slots");
  // The three the estate genuinely cannot measure today. If a seam later makes
  // one of these measurable, this list is the thing that must change.
  assert.deepEqual(
    [...UNMEASURED_PHASES].sort(),
    ["admission_queueing", "proposal_cadence_wait", "receipt_creation_durable_ack"],
    "unmeasured phases are exactly the ones with no seam",
  );
});

test("the client-observed phase is labelled polling-quantized, not an exact latency", () => {
  assert.equal(PHASES.client_commit_wait.quantized_by, "poll_interval_ms");
  assert.equal(
    PHASES.proposal_cadence_wait.semantics,
    "unmeasured",
    "cadence WAIT is not measured even though cadence CONFIG is recorded",
  );
  assert.equal(EVENT_DRIVEN_COMPLETION.status, "unimplemented");
  assert.equal(EVENT_DRIVEN_COMPLETION.measured, false);
  assert.ok(
    EVENT_DRIVEN_COMPLETION.reason.includes("tx_count"),
    "the reason names the concrete reason no per-tx completion event exists",
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
    approval.ordering.proposal_cadence.ticker_interval_ms,
    BASE.ticker_interval_ms,
  );
  assert.equal(
    approval.ordering.proposal_cadence.min_tick_ms,
    BASE.min_tick_ms,
  );
  assert.equal(
    approval.ordering.proposal_cadence.ticker_interval_provenance,
    BASE.ticker_interval_provenance,
  );
  assert.equal(
    approval.ordering.proposal_cadence.min_tick_provenance,
    BASE.min_tick_provenance,
  );
  assert.equal(approval.ordering.proposal_cadence.measured, false, "cadence is configuration");
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
    ["[BENCH-IAVL]", /\[BENCH-IAVL\] at height/u],
    ["commit_block", /commit_block at height/u],
    ["prepare_block", /prepare_block at height/u],
    ["proposal_finalize", /proposal_finalize at height/u],
    ["proposal_select", /proposal_select at height/u],
    ["proposal_process", /proposal_process at height/u],
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
    if (field === "height") continue; // height loss drops the line from the index entirely
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
      new RegExp(`omits required field '${field}'`, "u"),
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
  assert.equal(env.IOI_WALLET_FIXTURE_TEE_LOG, "/tmp/tee.log");
  assert.equal(env.PATH, "/usr/bin", "the surrounding environment is preserved");
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

test("a repeated height is surfaced, not silently collapsed", () => {
  const complete = inputs();
  const replayed = `${complete.traceText}\n${
    complete.traceText.split("\n").find((line) => line.includes("commit_block"))
  }`;
  const profile = buildCommitPathProfile({ ...complete, traceText: replayed });
  assert.ok(
    profile.approvals[0].anomalies.some((entry) => entry.startsWith("exec_commit_height_observed_2")),
  );
  assert.equal(profile.coverage.approvals_with_anomalies, 1);
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
    /\[BENCH-ORDERING\] proposal at height .* was not observed/u,
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
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${otherHeight} view=1 ordering_profile=solo ticker_interval_ms=1000 ticker_interval_provenance=config:block_production_interval_secs min_tick_ms=50 min_tick_provenance=default view_timeout_secs=2`,
    `[BENCH-CONSENSUS] proposal_select height=${otherHeight} view=1 candidate_txs=1 valid_txs=1 select_ms=4 verify_ms=6`,
    `[BENCH-CONSENSUS] proposal_process height=${otherHeight} view=1 tx_count=1 process_block_ms=1800`,
    `[BENCH-CONSENSUS] proposal_finalize height=${otherHeight} view=1 finalize_ms=120`,
    `[BENCH-EXEC] prepare_block height=${otherHeight} tx_count=1 total_ms=300`,
    `[BENCH-EXEC] commit_block height=${otherHeight} tx_count=1 persist_ms=1200 total_ms=1400 snapshot_clone_ms=40 block_bytes=5121 proc_cpu_user_ms=900 proc_cpu_sys_ms=130`,
    `${BENCH_IAVL_CONTRACT.tag} commit height=${otherHeight} version_count=413 tree_depth=17 unique_nodes=9001 new_nodes=118 new_node_bytes=40960 block_bytes=5121 commitment_ms=700 durable_store_ms=460 atomic_state_block=true`,
    `[BENCH-APPROVAL] request_hash=${"c".repeat(64)} policy_hash=${POLICY_HASH} principal_ref=org://acme/research target_scope=room_participation.request tx_hash=feedface admission_ms=3 committed_height=${otherHeight} commit_wait_ms=2500 commit_poll_count=5 commit_poll_interval_ms=500 approval_query_ms=7 approval_verify_ms=1`,
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
  assert.equal(profile.ordering_parity.proposal_cadence.measured, false);
  assert.equal(
    profile.ordering_parity.proposal_cadence.provenance,
    `observed:${BENCH_ORDERING_CONTRACT.tag}`,
  );
  assert.deepEqual(profile.ordering_parity.proposal_cadence.values, [
    {
      ticker_interval_ms: BASE.ticker_interval_ms,
      ticker_interval_provenance: BASE.ticker_interval_provenance,
      min_tick_ms: BASE.min_tick_ms,
      min_tick_provenance: BASE.min_tick_provenance,
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
  for (const bad of ["0", "-1", "600001", "abc", "1.5", ""]) {
    assert.throws(
      () => parseArgs(["--proposal-cadence-ms", bad]),
      /--proposal-cadence-ms must be an integer in 1\.\.=600000/u,
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

test("the schema identifier stays the one the tracked work item pins", () => {
  // docs/architecture/_meta/work-items/m04-8-wallet-authority-commit-latency.v1.json
  // carries a code anchor requiring the profiler source to contain exactly this
  // string. M04.9 extends this artifact in place; it is a diagnostic profile,
  // not a ReceiptCheckpoint or any other consensus-visible structure, so it
  // owes no versioned successor.
  const profile = buildCommitPathProfile(inputs());
  assert.equal(profile.schema_version, "ioi.m048.commit-path-profile.v1");
  assert.equal(SCHEMA_COMPATIBILITY.version, profile.schema_version);
  assert.equal(profile.schema_compatibility.version, profile.schema_version);
});

test("the one incompatible rename is disclosed in the artifact, not just in a comment", () => {
  // Reusing v1's identifier is only honest if a reader who keys on v1's phase
  // names finds out from the artifact that one of them moved.
  const profile = buildCommitPathProfile(inputs());
  assert.equal(
    profile.schema_compatibility.renamed_phases.aft_inclusion_finalization,
    "ordering_finalization",
  );
  // The rename is real: the old name is gone and the new one carries the phase.
  assert.ok(!("aft_inclusion_finalization" in profile.approvals[0].phases));
  assert.ok("ordering_finalization" in profile.approvals[0].phases);
  // Every name the disclosure claims to have renamed TO must actually exist,
  // or the disclosure would send a reader to a key that is not there either.
  for (const renamed of Object.values(profile.schema_compatibility.renamed_phases)) {
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
  const [cadence] = overridden.ordering_parity.proposal_cadence.values;
  assert.equal(cadence.ticker_interval_ms, 250);
  assert.equal(cadence.ticker_interval_provenance, "env:ORCH_BLOCK_INTERVAL_MS");
  assert.equal(cadence.min_tick_ms, 10);
  assert.equal(cadence.min_tick_provenance, "env:ORCH_CONSENSUS_MIN_TICK_MS");

  // A disabled ticker is a real cadence, reported as 0 rather than dropped.
  const disabled = buildCommitPathProfile(inputs({ ticker_interval_ms: 0 }));
  assert.equal(
    disabled.approvals[0].ordering.proposal_cadence.ticker_interval_ms,
    0,
    "ticker_interval_ms=0 means kick-driven only, not an absent measurement",
  );
  const zeroKick = buildCommitPathProfile(
    inputs({ min_tick_ms: 0, min_tick_provenance: "env:ORCH_CONSENSUS_MIN_TICK_MS" }),
  );
  assert.equal(zeroKick.approvals[0].ordering.proposal_cadence.min_tick_ms, 0);
});

test("FAIL CLOSED: a [BENCH-ORDERING] line missing one contracted field is refused", () => {
  for (const field of BENCH_ORDERING_CONTRACT.required_fields) {
    if (field === "height") continue; // height loss drops the line from the index entirely
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
      new RegExp(`omits required field '${field}'`, "u"),
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
        .ordering.proposal_cadence.ticker_interval_provenance,
      provenance,
    );
  }
  for (const provenance of BENCH_ORDERING_CONTRACT.known_min_tick_provenances) {
    assert.equal(
      buildCommitPathProfile(inputs({ min_tick_provenance: provenance })).approvals[0].ordering
        .proposal_cadence.min_tick_provenance,
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
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${otherHeight} view=1 ordering_profile=aft ticker_interval_ms=250 ticker_interval_provenance=env:ORCH_BLOCK_INTERVAL_MS min_tick_ms=50 min_tick_provenance=default view_timeout_secs=2`,
    `[BENCH-CONSENSUS] proposal_select height=${otherHeight} view=1 candidate_txs=1 valid_txs=1 select_ms=4 verify_ms=6`,
    `[BENCH-CONSENSUS] proposal_process height=${otherHeight} view=1 tx_count=1 process_block_ms=1800`,
    `[BENCH-CONSENSUS] proposal_finalize height=${otherHeight} view=1 finalize_ms=120`,
    `[BENCH-EXEC] prepare_block height=${otherHeight} tx_count=1 total_ms=300`,
    `[BENCH-EXEC] commit_block height=${otherHeight} tx_count=1 persist_ms=1200 total_ms=1400 snapshot_clone_ms=40 block_bytes=5121 proc_cpu_user_ms=900 proc_cpu_sys_ms=130`,
    `${BENCH_IAVL_CONTRACT.tag} commit height=${otherHeight} version_count=413 tree_depth=17 unique_nodes=9001 new_nodes=118 new_node_bytes=40960 block_bytes=5121 commitment_ms=700 durable_store_ms=460 atomic_state_block=true`,
    `[BENCH-APPROVAL] request_hash=${"c".repeat(64)} policy_hash=${POLICY_HASH} principal_ref=org://acme/research target_scope=room_participation.request tx_hash=feedface admission_ms=3 committed_height=${otherHeight} commit_wait_ms=2500 commit_poll_count=5 commit_poll_interval_ms=500 approval_query_ms=7 approval_verify_ms=1`,
  ].join("\n");
  const profile = buildCommitPathProfile({
    ...single,
    approvalFields: parseApprovalLines(mixed),
    traceText: mixed,
  });
  // One engine throughout, so this is a legal profile — but two cadences, and
  // both are reported.
  assert.equal(profile.ordering_parity.ordering_profile, "aft");
  assert.equal(profile.ordering_parity.proposal_cadence.values.length, 2);
  assert.deepEqual(
    profile.ordering_parity.proposal_cadence.values.map((v) => v.ticker_interval_ms).sort((a, b) => a - b),
    [250, 1000],
  );
});
