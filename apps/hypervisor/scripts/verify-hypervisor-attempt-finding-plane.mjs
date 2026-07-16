#!/usr/bin/env node
// Hosted Attempt + Finding held bar. Positive authority traverses the real wallet.network
// CallService fixture with signed capability transactions and pinned TLS/root proof.

import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const results = [];
const ok = (name, pass, detail = "") => {
  results.push({ name, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}: ${name}${detail ? ` — ${detail}` : ""}`);
};
const names = (dir, family) => {
  try { return readdirSync(join(dir, family)).filter((name) => name.endsWith(".json")).sort(); }
  catch { return []; }
};
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const ROOM = {
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://attempt-finding-program",
  objective: "Admit exact work provenance without implying a verdict.", room_mode: "open_challenge",
  coordination_topology: "hosted_admission", stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible", participation_policy_ref: "policy://open-eligibility",
  privacy_policy_ref: "policy://no-pii", contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1", ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover", host_domain_ref: "domain://acme-host",
};

async function jsonCall(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function governed(call, resolver, principal, path, body) {
  const challenge = await call("POST", path, body);
  const approval = challenge.body.error?.approval;
  if (!approval?.policy_hash || !approval?.request_hash) return { challenge, response: challenge, grant: null };
  const grant = resolver.mint(principal, approval.policy_hash, approval.request_hash);
  const response = await call("POST", path, { ...body, wallet_approval_grant: grant });
  return { challenge, response, grant };
}

async function admitParticipant(call, resolver, roomRef) {
  const submitted = await call("POST", "/v1/hypervisor/room-participation-requests", {
    outcome_room_ref: roomRef, requested_by_ref: "worker://independent-alloy-lab",
    coordination_topology: "hosted_admission", admission_owner_ref: "domain://acme-host",
    operator_and_home_domain_refs: ["org://lab", "domain://lab.example"],
    worker_composition_and_dependency_refs: ["worker://bounded-worker", "runtime://rt-ab"],
    capability_offer_refs: [], affiliation_and_independent_operation_evidence_refs: ["evidence://independent"],
    eligibility_evidence_refs: ["evidence://eligible"],
    accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
  });
  const request = submitted.body.participation_request;
  const path = `/v1/hypervisor/room-participation-requests/${request.participation_request_id.replace("participation-request://", "")}/admit`;
  const admitted = await governed(call, resolver, "domain://acme-host", path, {
    admitted_role: "implementer", operator_ref: "org://lab",
    home_domain_ref: "agentgres://domain/lab", expected_revision: 1,
  });
  if (admitted.response.status !== 200) throw new Error(JSON.stringify(admitted.response));
  return admitted.response.body.participant_lease;
}

const attemptBody = (roomRef, frontierRef, claimRef, participantRef, goalRef, overrides = {}) => ({
  outcome_room_ref: roomRef, frontier_item_ref: frontierRef, work_claim_ref: claimRef,
  participant_ref: participantRef, goal_run_ref: goalRef,
  declared_method_and_hypothesis_refs: ["method://bounded-implementation"],
  parent_and_derivation_refs: [], input_state_and_environment_refs: ["state://clean-worktree"],
  worker_model_harness_tool_and_runtime_versions: ["runtime://rt-ab"],
  authority_and_policy_refs: ["policy://contribution-v1"], resource_and_cost_refs: [],
  artifact_license_ip_retention_and_export_refs: ["license://apache-2.0"], contribution_refs: [],
  coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

const findingBody = (roomRef, attemptRef, resultRef, participantRef, overrides = {}) => ({
  outcome_room_ref: roomRef, attempt_ref: attemptRef, work_result_ref: resultRef,
  participant_ref: participantRef, proposition: "The bounded implementation produced the declared negative result.",
  finding_kind: "negative_result", confidence_or_uncertainty: 0.2, valid_time: null,
  supporting_evidence_refs: ["evidence://attempt-output"], contradicting_evidence_refs: [],
  proof_refs: ["receipt://work-result-admission"], applicability_and_counterexample_refs: [],
  provenance_ontology_and_mapping_refs: [], proposed_effect_refs: [], supersedes_ref: null,
  coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
});

async function poll(call, path, accept, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await call("GET", path);
    if (accept(last)) return last;
    await delay(100);
  }
  return last;
}

async function run() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-attempt-finding-"));
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const room = (await call("POST", "/v1/hypervisor/outcome-rooms", ROOM)).body.outcome_room;
    const roomRef = room.outcome_room_id;
    const roomTail = roomRef.replace("outcome-room://", "");
    const lease = await admitParticipant(call, resolver, roomRef);

    let liveRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const frontierAdmission = await governed(call, resolver, "domain://acme-host", "/v1/hypervisor/work-frontier-items", {
      outcome_room_ref: roomRef, item_kind: "task", objective: "Produce one bounded result and finding.",
      dependency_refs: [], related_attempt_and_finding_refs: [], required_capability_refs: [],
      required_context_resource_authority_and_evidence_refs: [], expected_value: 5, uncertainty: 0.25,
      priority: 100, duplication_policy: "exclusive", claimability: "open", max_concurrency: 1,
      expires_at: null, stop_condition_ref: "policy://done", coordination_topology: "hosted_admission",
      expected_revision: liveRoom.revision,
    });
    const frontier = frontierAdmission.response.body.frontier_item;
    if (!frontier) throw new Error(JSON.stringify(frontierAdmission.response));
    const claimAdmission = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/work-claim-leases", {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id,
      claimant_ref: lease.participant_lease_id, bounded_scope_ref: "task://attempt-finding",
      context_lease_refs: [], authority_resource_compute_data_budget_and_tool_lease_refs: [],
      duplicate_work_policy: "exclusive", heartbeat_ref: null, ttl_seconds: 600,
      coordination_topology: "hosted_admission", expected_revision: lease.revision,
    });
    const claim = claimAdmission.response.body.work_claim;
    if (!claim) throw new Error(JSON.stringify(claimAdmission.response));
    ok("SETUP: active participant owns the exact active frontier claim", claim.status === "active");

    // GoalRun is a prerequisite plane fixture; attach uses the production reciprocal owner seam.
    mkdirSync(join(dataDir, "goal-runs"), { recursive: true });
    writeFileSync(join(dataDir, "goal-runs", "gr_attempt_finding.json"), JSON.stringify({
      schema_version: "ioi.hypervisor.goal-run.v1", goal_run_id: "gr_attempt_finding",
      goal_ref: "goal://gr_attempt_finding", normalized_goal: "bounded provenance fixture",
      status: "active", outcome_room_ref: null, created_at: "2027-01-01T00:00:00Z",
      updated_at: "2027-01-01T00:00:00Z", runtimeTruthSource: "daemon-runtime",
    }));
    liveRoom = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const attached = await call("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/attach-goal-run`, {
      goal_run_ref: "goal://gr_attempt_finding", expected_revision: liveRoom.revision,
    });
    ok("SETUP: GoalRun is reciprocally bound through the production room seam", attached.status === 200, `${attached.status}/${attached.body.error?.code || "ok"}`);

    const resultAdmission = await call("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://gr_attempt_finding", goal_run_ref: "goal://gr_attempt_finding",
      outcome_room_ref: roomRef, result_profile: "research", outcome_class: "negative",
      status: "completed", uncertainty: 0.2, supporting_evidence_refs: ["evidence://attempt-output"],
      artifact_receipt_and_trace_refs: ["receipt://work-result-admission"], reproduction_state: "unreviewed",
    });
    const workResult = resultAdmission.body.work_result;
    ok("SETUP: WorkResult binds the same room and GoalRun", resultAdmission.status === 201 && workResult?.goal_run_ref === "goal://gr_attempt_finding", `${resultAdmission.status}/${resultAdmission.body.error?.code || "ok"}`);

    const createInput = attemptBody(roomRef, frontier.frontier_item_id, claim.work_claim_id, lease.participant_lease_id, "goal://gr_attempt_finding");
    const challenge = await call("POST", "/v1/hypervisor/attempts", createInput);
    if (!challenge.body.error?.approval) throw new Error(`Attempt challenge failed before authority: ${JSON.stringify(challenge)}`);
    const grant = resolver.mint(lease.participant_ref, challenge.body.error.approval.policy_hash, challenge.body.error.approval.request_hash);
    const swapped = await call("POST", "/v1/hypervisor/attempts", {
      ...createInput, resource_and_cost_refs: ["spend://escalated"], wallet_approval_grant: grant,
    });
    ok("AUTHORITY: Attempt payload swap at the same revision refuses with zero mutation", swapped.status === 403 && names(dataDir, "attempts").length === 0, `${swapped.status}/${swapped.body.error?.code}`);
    const created = await call("POST", "/v1/hypervisor/attempts", { ...createInput, wallet_approval_grant: grant });
    const attempt = created.body.attempt;
    ok("ATTEMPT: participant admits canonical exact-coordinate draft", created.status === 201 && /^attempt:\/\/att_[0-9a-f]{64}$/.test(attempt?.attempt_id) && attempt?.bound_coordinates?.goal_run?.record_ref === "goal://gr_attempt_finding", `${created.status}/${created.body.error?.code || "ok"}`);

    const attemptTail = attempt.attempt_id.replace("attempt://", "");
    const heartbeated = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/work-claim-leases/${claim.work_claim_id.replace("work-claim://", "")}/transition`, {
      transition: "heartbeat", heartbeat_ref: "heartbeat://attempt-created", expected_revision: claim.revision,
    });
    const currentClaim = heartbeated.response.body.work_claim;
    const started = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/attempts/${attemptTail}/transition`, {
      transition: "start", expected_revision: attempt.revision,
    });
    ok("HISTORY: claim heartbeat after Attempt creation does not invalidate participant start", heartbeated.response.status === 200 && started.response.status === 200, `${heartbeated.response.status}/${started.response.status}/${started.response.body.error?.code || "ok"}`);

    const otherResultAdmission = await call("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://gr_attempt_finding", goal_run_ref: "goal://gr_attempt_finding",
      outcome_room_ref: roomRef, result_profile: "research", outcome_class: "negative",
      status: "completed", uncertainty: 0.4, supporting_evidence_refs: ["evidence://other-attempt-output"],
      artifact_receipt_and_trace_refs: ["receipt://other-work-result-admission"], reproduction_state: "unreviewed",
    });
    const otherWorkResult = otherResultAdmission.body.work_result;
    const primaryDeltaAdmission = await call("POST", "/v1/hypervisor/outcome-deltas", {
      goal_ref: "goal://gr_attempt_finding", outcome_room_ref: roomRef, delta_kind: "update",
      target_ref: frontier.frontier_item_id, proposed_by_ref: workResult.work_result_id,
    });
    const otherDeltaAdmission = await call("POST", "/v1/hypervisor/outcome-deltas", {
      goal_ref: "goal://gr_attempt_finding", outcome_room_ref: roomRef, delta_kind: "update",
      target_ref: frontier.frontier_item_id, proposed_by_ref: otherWorkResult.work_result_id,
    });
    const primaryDelta = primaryDeltaAdmission.body.outcome_delta;
    const otherDelta = otherDeltaAdmission.body.outcome_delta;
    if (!primaryDelta || !otherDelta) throw new Error(JSON.stringify({ primaryDeltaAdmission, otherDeltaAdmission }));

    const submitBase = {
      transition: "submit", expected_revision: started.response.body.attempt.revision,
      outcome_class: "negative", work_result_ref: workResult.work_result_id,
      artifact_evidence_and_receipt_refs: ["evidence://attempt-output", "receipt://work-result-admission"],
      reproduction_state: "unreviewed",
    };
    const attemptBeforeBadDeltas = readFileSync(join(dataDir, "attempts", `${attemptTail}.json`), "utf8");
    const receiptsBeforeBadDeltas = names(dataDir, "attempt-finding-receipts");
    const ghostDelta = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/attempts/${attemptTail}/transition`, {
      ...submitBase, outcome_delta_refs: [`outcome-delta://od_${"f".repeat(64)}`],
    });
    const primaryResultPath = join(dataDir, "work-result-registry", `${workResult.work_result_id.replace("work-result://", "")}.json`);
    const primaryResultBytes = readFileSync(primaryResultPath, "utf8");
    const poisonedBacklink = JSON.parse(primaryResultBytes);
    poisonedBacklink.outcome_delta_refs = [...poisonedBacklink.outcome_delta_refs, otherDelta.outcome_delta_id];
    writeFileSync(primaryResultPath, JSON.stringify(poisonedBacklink));
    const crossResultDelta = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/attempts/${attemptTail}/transition`, {
      ...submitBase, outcome_delta_refs: [otherDelta.outcome_delta_id],
    });
    writeFileSync(primaryResultPath, primaryResultBytes);
    ok("OUTCOME DELTA: ghost and cross-result evidence refuse with zero Attempt, WorkResult, or receipt mutation", ghostDelta.response.status === 422 && ghostDelta.response.body.error?.code === "attempt_outcome_delta_not_backlinked" && crossResultDelta.response.status === 422 && crossResultDelta.response.body.error?.code === "attempt_outcome_delta_cross_result" && readFileSync(join(dataDir, "attempts", `${attemptTail}.json`), "utf8") === attemptBeforeBadDeltas && readFileSync(primaryResultPath, "utf8") === primaryResultBytes && JSON.stringify(names(dataDir, "attempt-finding-receipts")) === JSON.stringify(receiptsBeforeBadDeltas), `${ghostDelta.response.status}/${ghostDelta.response.body.error?.code}; ${crossResultDelta.response.status}/${crossResultDelta.response.body.error?.code}`);
    const submitted = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/attempts/${attemptTail}/transition`, {
      ...submitBase, outcome_delta_refs: [primaryDelta.outcome_delta_id],
    });
    const admitted = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/attempts/${attemptTail}/transition`, {
      transition: "admit", expected_revision: submitted.response.body.attempt.revision,
    });
    ok("ATTEMPT: start -> submit -> host admission preserves negative evidence", started.response.status === 200 && submitted.response.status === 200 && admitted.response.status === 200 && admitted.response.body.attempt?.status === "admitted" && admitted.response.body.attempt?.outcome_class === "negative", `${started.response.status}/${submitted.response.status}/${admitted.response.status}`);

    const releasedBeforeFinding = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/work-claim-leases/${claim.work_claim_id.replace("work-claim://", "")}/transition`, {
      transition: "release", reason: "work submitted for historical provenance", expected_revision: currentClaim.revision,
    });
    ok("HISTORY: claim release after host admission preserves the immutable Attempt lineage", releasedBeforeFinding.response.status === 200 && releasedBeforeFinding.response.body.work_claim?.status === "released", `${releasedBeforeFinding.response.status}/${releasedBeforeFinding.response.body.error?.code || "ok"}`);

    const findingInput = findingBody(roomRef, attempt.attempt_id, workResult.work_result_id, lease.participant_lease_id);
    const findingsBeforeBadLineage = names(dataDir, "findings");
    const receiptsBeforeBadLineage = names(dataDir, "attempt-finding-receipts");
    const nonexistentSupersession = await call("POST", "/v1/hypervisor/findings", {
      ...findingInput, supersedes_ref: `finding://fnd_${"e".repeat(64)}`,
    });
    const secondRoom = (await call("POST", "/v1/hypervisor/outcome-rooms", { ...ROOM, objective_ref: "goal://cross-room-lineage", objective: "Cross-room negative lineage fixture." })).body.outcome_room;
    const crossRoomFindingRef = `finding://fnd_${"c".repeat(64)}`;
    const crossRoomFindingTail = crossRoomFindingRef.replace("finding://", "");
    const crossRoomFinding = {
      ...JSON.parse(JSON.stringify({
        schema_version: "ioi.hypervisor.finding-envelope.v1", finding_id: crossRoomFindingRef,
        outcome_room_ref: secondRoom.outcome_room_id, attempt_ref: attempt.attempt_id,
        work_result_ref: workResult.work_result_id, participant_ref: lease.participant_lease_id,
        proposition: "Canonical cross-room lineage fixture.", finding_kind: "negative_result",
        confidence_or_uncertainty: 0.5, valid_time: null, supporting_evidence_refs: [],
        contradicting_evidence_refs: [], proof_refs: [], applicability_and_counterexample_refs: [],
        provenance_ontology_and_mapping_refs: [], proposed_effect_refs: [], supersedes_ref: null,
        coordination_topology: "hosted_admission", status: "proposed", revision: 1,
        created_at: "2027-01-01T00:00:00Z", updated_at: "2027-01-01T00:00:00Z",
        runtimeTruthSource: "daemon-runtime",
      })),
    };
    mkdirSync(join(dataDir, "findings"), { recursive: true });
    writeFileSync(join(dataDir, "findings", `${crossRoomFindingTail}.json`), JSON.stringify(crossRoomFinding));
    const lineageFixtureNames = names(dataDir, "findings");
    const crossRoomSupersession = await call("POST", "/v1/hypervisor/findings", {
      ...findingInput, supersedes_ref: crossRoomFindingRef,
    });
    ok("FINDING LINEAGE: nonexistent and canonical cross-room supersession refuse with zero mutation", nonexistentSupersession.status === 404 && nonexistentSupersession.body.error?.code === "finding_supersedes_not_found" && crossRoomSupersession.status === 422 && crossRoomSupersession.body.error?.code === "finding_supersedes_cross_room" && JSON.stringify(names(dataDir, "findings")) === JSON.stringify(lineageFixtureNames) && JSON.stringify(names(dataDir, "attempt-finding-receipts")) === JSON.stringify(receiptsBeforeBadLineage), `${nonexistentSupersession.status}/${nonexistentSupersession.body.error?.code}; ${crossRoomSupersession.status}/${crossRoomSupersession.body.error?.code}`);
    rmSync(join(dataDir, "findings", `${crossRoomFindingTail}.json`), { force: true });
    if (JSON.stringify(names(dataDir, "findings")) !== JSON.stringify(findingsBeforeBadLineage)) throw new Error("cross-room Finding fixture cleanup failed");
    const findingChallenge = await call("POST", "/v1/hypervisor/findings", findingInput);
    const findingGrant = resolver.mint(lease.participant_ref, findingChallenge.body.error.approval.policy_hash, findingChallenge.body.error.approval.request_hash);
    const findingSwap = await call("POST", "/v1/hypervisor/findings", {
      ...findingInput, confidence_or_uncertainty: 0.01,
      proof_refs: ["receipt://scope-escalated-proof"], wallet_approval_grant: findingGrant,
    });
    ok("AUTHORITY: Finding uncertainty/proof swap refuses with zero mutation", findingSwap.status === 403 && names(dataDir, "findings").length === 0, `${findingSwap.status}/${findingSwap.body.error?.code}`);
    const proposed = await call("POST", "/v1/hypervisor/findings", { ...findingInput, wallet_approval_grant: findingGrant });
    const finding = proposed.body.finding;
    ok("FINDING: proposal after claim release freezes historical Attempt, WorkResult, uncertainty, evidence, and proof refs", proposed.status === 201 && /^finding:\/\/fnd_[0-9a-f]{64}$/.test(finding?.finding_id) && finding?.bound_coordinates?.attempt?.record_ref === attempt.attempt_id && finding?.proof_refs?.length === 1, `${proposed.status}/${proposed.body.error?.code || "ok"}`);

    const findingTail = finding.finding_id.replace("finding://", "");
    const findingAdmitted = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/findings/${findingTail}/transition`, {
      transition: "admit", expected_revision: finding.revision,
    });
    const unavailable = await call("POST", `/v1/hypervisor/findings/${findingTail}/transition`, {
      transition: "accept", expected_revision: findingAdmitted.response.body.finding.revision,
    });
    ok("FINDING: host admission is live while acceptance/verdict stays typed unavailable", findingAdmitted.response.status === 200 && findingAdmitted.response.body.finding?.status === "admitted" && unavailable.status === 501 && unavailable.body.error?.code === "finding_verdict_unavailable", `${findingAdmitted.response.status}/${unavailable.status}/${unavailable.body.error?.code}`);

    const attemptBytes = readFileSync(join(dataDir, "attempts", `${attemptTail}.json`), "utf8");
    const findingBytes = readFileSync(join(dataDir, "findings", `${findingTail}.json`), "utf8");
    await plane.stop();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const persisted = await poll(call, `/v1/hypervisor/findings/${findingTail}`, (value) => value.status === 200);
    ok("DURABILITY: restart preserves Attempt and Finding byte-exactly", persisted.status === 200 && readFileSync(join(dataDir, "attempts", `${attemptTail}.json`), "utf8") === attemptBytes && readFileSync(join(dataDir, "findings", `${findingTail}.json`), "utf8") === findingBytes);

    // Receipt durability fails after the complete authorized successor is sealed. The intent
    // reserves room, Finding, Attempt, WorkResult, and participant until one clean restart
    // reauthenticates and materializes those exact bytes.
    await plane.stop();
    plane = await startIsolatedPlane({
      serve: false,
      env: { ...resolver.env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "attempt-finding-receipts" },
      dataDir,
    });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const pendingArchive = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/findings/${findingTail}/transition`, {
      transition: "archive", expected_revision: findingAdmitted.response.body.finding.revision,
    });
    const intentName = names(dataDir, "attempt-finding-intents")[0];
    const sealedIntent = intentName ? JSON.parse(readFileSync(join(dataDir, "attempt-finding-intents", intentName), "utf8")) : null;
    const participantTail = lease.participant_lease_id.replace("participant-lease://", "");
    const participantPath = join(dataDir, "room-participant-leases", `${participantTail}.json`);
    const participantBeforeReservation = readFileSync(participantPath, "utf8");
    const liveParticipant = JSON.parse(participantBeforeReservation);
    const reservedSleep = await governed(call, resolver, lease.participant_ref, `/v1/hypervisor/room-participant-leases/${participantTail}/transition`, {
      transition: "sleep", expected_revision: liveParticipant.revision,
    });
    ok("RESERVATION: pending Finding intent blocks participant mutation byte-stably", pendingArchive.response.status === 500 && reservedSleep.response.status === 409 && reservedSleep.response.body.error?.code === "participant_lease_mutation_in_flight" && readFileSync(participantPath, "utf8") === participantBeforeReservation, `${pendingArchive.response.status}/${reservedSleep.response.status}/${reservedSleep.response.body.error?.code}`);
    await plane.stop();
    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const convergedArchive = await poll(call, `/v1/hypervisor/findings/${findingTail}`, (value) => value.status === 200 && value.body.finding?.status === "archived");
    ok("DURABILITY: one restart reauthorizes and converges the sealed successor byte-exactly", convergedArchive.status === 200 && JSON.stringify(convergedArchive.body.finding) === JSON.stringify(sealedIntent?.final_finding) && names(dataDir, "attempt-finding-intents").length === 0);

    ok("BOUNDARY: provenance admission grants no execution authority and historical claim release remains claim-owned", releasedBeforeFinding.response.body.work_claim?.status === "released" && admitted.response.body.attempt?.execution_authority_granted !== true);

    const overview = await call("GET", "/v1/hypervisor/attempts/overview");
    ok("OVERVIEW: contract names hosted admission and absent acceptance/execution authority honestly", overview.status === 200 && overview.body.execution_authority === "not_provided" && overview.body.acceptance_authority === "not_provided" && overview.body.federated_admission === "typed_unavailable");
  } finally {
    await plane?.stop().catch(() => {});
    await resolver.stop().catch(() => {});
    rmSync(dataDir, { recursive: true, force: true });
  }
  const failures = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failures.length}/${results.length} checks passed.`);
  if (failures.length) process.exitCode = 1;
}

await run();
