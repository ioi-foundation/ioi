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
  block_interval_secs: 1,
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
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${HEIGHT} view=1 ordering_profile=${v.ordering_profile} block_interval_secs=${v.block_interval_secs} view_timeout_secs=${v.view_timeout_secs}`,
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
    approval.ordering.proposal_cadence.block_interval_secs,
    BASE.block_interval_secs,
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
    inputs({ ordering_profile: "solo", block_interval_secs: 1, view_timeout_secs: 2 }),
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
    `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} height=${otherHeight} view=1 ordering_profile=solo block_interval_secs=1 view_timeout_secs=2`,
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
  // The cadence the run was configured with IS recorded — as configuration.
  assert.equal(profile.ordering_parity.proposal_cadence.measured, false);
  assert.equal(profile.ordering_parity.proposal_cadence.provenance, "configured");
  assert.deepEqual(profile.ordering_parity.proposal_cadence.values, [
    { block_interval_secs: BASE.block_interval_secs, view_timeout_secs: BASE.view_timeout_secs },
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

test("requested profile is carried separately from the profile that actually ran", () => {
  const env = profileEnv({}, "/tmp/t", "/tmp/l", {
    orderingProfile: "Solo",
    pollIntervalMs: 25,
  });
  assert.equal(env.IOI_M049_ORDERING_PROFILE, "Solo");
  assert.equal(env.IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS, "25");
  // Unflagged runs must not set either, so they stay byte-identical to M04.8.
  const bare = profileEnv({}, "/tmp/t", "/tmp/l");
  assert.ok(!("IOI_M049_ORDERING_PROFILE" in bare));
  assert.ok(!("IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS" in bare));
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
  assert.equal(profile.schema_version, "ioi.m049.ordering-parity-profile.v1");
  assert.equal(Object.keys(VALUE_KINDS).length, 6);
});
