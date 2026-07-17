#!/usr/bin/env node
// Hosted VerifierChallenge held bar. Positive authority traverses the real wallet.network
// CallService fixture with signed capability transactions and pinned TLS/root proof.

import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://verifier-challenge-program",
  objective: "Challenge verification posture without creating a verdict.", room_mode: "open_challenge",
  coordination_topology: "hosted_admission", stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible", participation_policy_ref: "policy://open-eligibility",
  privacy_policy_ref: "policy://no-pii", contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1", ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover", host_domain_ref: "domain://acme-host",
};

async function jsonCall(base, method, path, body) {
  const response = await fetch(`${base}${path}`, { method, signal: AbortSignal.timeout(120_000), headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
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
    admitted_role: "verifier", operator_ref: "org://lab", home_domain_ref: "agentgres://domain/lab", expected_revision: 1,
  });
  if (admitted.response.status !== 200) throw new Error(JSON.stringify(admitted.response));
  return admitted.response.body.participant_lease;
}

const challengeBody = (roomRef, participantRef, challengedRef, attemptRefs, overrides = {}) => ({
  outcome_room_ref: roomRef, challenger_ref: participantRef, challenged_ref: challengedRef,
  challenge_kind: "evidence", challenge_evidence_refs: ["evidence://counterexample"],
  adjudicator_policy_ref: "policy://room-host-adjudication", prior_rule_version_ref: null,
  proposed_rule_version_ref: null, affected_attempt_refs: [...attemptRefs].sort(),
  reverification_required: false, coordination_topology: "hosted_admission", expected_revision: 0, ...overrides,
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

function installProvenance(dataDir, roomRef, participantLease, workResult) {
  const attemptRef = `attempt://att_${"a".repeat(64)}`;
  const secondAttemptRef = `attempt://att_${"e".repeat(64)}`;
  const findingRef = `finding://fnd_${"b".repeat(64)}`;
  const common = { outcome_room_ref: roomRef, participant_ref: participantLease.participant_lease_id,
    work_result_ref: workResult.work_result_id, revision: 4, status: "admitted",
    bound_coordinates: { outcome_room: { record_ref: roomRef }, participant_lease: { record_ref: participantLease.participant_lease_id },
      work_result: { record_ref: workResult.work_result_id } }, runtimeTruthSource: "daemon-runtime" };
  mkdirSync(join(dataDir, "attempts"), { recursive: true });
  writeFileSync(join(dataDir, "attempts", `${attemptRef.replace("attempt://", "")}.json`), JSON.stringify({
    schema_version: "ioi.hypervisor.attempt-envelope.v1", attempt_id: attemptRef, ...common,
    frontier_item_ref: `frontier://wfi_${"c".repeat(64)}`, work_claim_ref: `work-claim://wcl_${"d".repeat(64)}`,
    goal_run_ref: "goal://verifier-challenge-program",
  }));
  writeFileSync(join(dataDir, "attempts", `${secondAttemptRef.replace("attempt://", "")}.json`), JSON.stringify({
    schema_version: "ioi.hypervisor.attempt-envelope.v1", attempt_id: secondAttemptRef, ...common,
    frontier_item_ref: `frontier://wfi_${"1".repeat(64)}`, work_claim_ref: `work-claim://wcl_${"2".repeat(64)}`,
    goal_run_ref: "goal://verifier-challenge-program",
  }));
  mkdirSync(join(dataDir, "findings"), { recursive: true });
  writeFileSync(join(dataDir, "findings", `${findingRef.replace("finding://", "")}.json`), JSON.stringify({
    schema_version: "ioi.hypervisor.finding-envelope.v1", finding_id: findingRef, attempt_ref: attemptRef,
    finding_kind: "negative_result", confidence_or_uncertainty: 0.25, ...common,
  }));
  return { attemptRef, secondAttemptRef, findingRef };
}

async function run() {
  let resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-verifier-challenge-"));
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env: { ...resolver.env, IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "60000" }, dataDir });
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const room = (await call("POST", "/v1/hypervisor/outcome-rooms", ROOM)).body.outcome_room;
    const roomRef = room.outcome_room_id;
    const lease = await admitParticipant(call, resolver, roomRef);
    const resultAdmission = await call("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://verifier-challenge-program", goal_run_ref: "goal://verifier-challenge-program",
      outcome_room_ref: roomRef, result_profile: "research", outcome_class: "negative", status: "completed",
      uncertainty: 0.25, supporting_evidence_refs: ["evidence://challenged-output"],
      artifact_receipt_and_trace_refs: ["receipt://challenged-output"], reproduction_state: "unreviewed",
    });
    const workResult = resultAdmission.body.work_result;
    const { attemptRef, secondAttemptRef, findingRef } = installProvenance(dataDir, roomRef, lease, workResult);
    ok("SETUP: production room, active participant, WorkResult, Attempt, and Finding coordinates exist",
      roomRef && lease.status === "active" && workResult && attemptRef && findingRef);

    const input = challengeBody(roomRef, lease.participant_lease_id, findingRef, [attemptRef], {
      reverification_required: true,
    });
    const secondRoom = (await call("POST", "/v1/hypervisor/outcome-rooms", {
      ...ROOM, objective_ref: "goal://verifier-challenge-cross-room", objective: "Cross-room challenge refusal fixture.",
    })).body.outcome_room;
    const negativeBaseline = [names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts"), names(dataDir, "verifier-challenge-intents")];
    const unsupported = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...input, challenged_ref: "benchmark://unresolved-owner",
    });
    const ghost = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...input, challenged_ref: `attempt://att_${"7".repeat(64)}`, affected_attempt_refs: [`attempt://att_${"7".repeat(64)}`],
    });
    const malformed = await call("POST", "/v1/hypervisor/verifier-challenges", { ...input, challenged_ref: "attempt://bad" });
    const malformedAffected = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...input, affected_attempt_refs: ["attempt://bad"],
    });
    const crossRoom = await call("POST", "/v1/hypervisor/verifier-challenges", { ...input, outcome_room_ref: secondRoom.outcome_room_id });
    const relocatedTail = `att_${"6".repeat(64)}`;
    writeFileSync(join(dataDir, "attempts", `${relocatedTail}.json`), JSON.stringify({
      schema_version: "ioi.hypervisor.attempt-envelope.v1", attempt_id: `attempt://att_${"5".repeat(64)}`,
      outcome_room_ref: roomRef, participant_ref: lease.participant_lease_id, work_result_ref: workResult.work_result_id,
      revision: 1, status: "admitted",
    }));
    const relocated = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...input, challenged_ref: `attempt://${relocatedTail}`, affected_attempt_refs: [`attempt://${relocatedTail}`],
    });
    rmSync(join(dataDir, "attempts", `${relocatedTail}.json`));
    ok("TARGETS: unsupported, missing, malformed, relocated, and cross-room targets refuse with zero mutation",
      unsupported.status === 501 && ghost.status === 404 && malformed.status === 422
      && malformedAffected.status === 422 && relocated.status === 500
      && crossRoom.status === 422 && JSON.stringify(negativeBaseline) === JSON.stringify([
        names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts"), names(dataDir, "verifier-challenge-intents"),
      ]), `${unsupported.status}/${ghost.status}/${malformed.status}/${malformedAffected.status}/${relocated.status}/${crossRoom.status}`);
    const missing = await call("POST", "/v1/hypervisor/verifier-challenges", input);
    if (!missing.body.error?.approval) throw new Error(`VerifierChallenge did not reach authority: ${JSON.stringify(missing)}`);
    const grant = resolver.mint(lease.participant_ref, missing.body.error.approval.policy_hash, missing.body.error.approval.request_hash);
    const beforeSwap = [names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts")];
    const swapped = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...input, challenge_kind: "exploit", challenge_evidence_refs: ["evidence://swapped"], wallet_approval_grant: grant,
    });
    ok("AUTHORITY: missing grant challenges and body-swapped grant refuses with zero mutation",
      missing.body.error?.approval && swapped.status === 403
      && JSON.stringify(beforeSwap) === JSON.stringify([names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts")]),
      `${missing.status}/${swapped.status}/${swapped.body.error?.code}`);
    const foreignGrant = resolver.mint("worker://replication-lab-two", missing.body.error.approval.policy_hash, missing.body.error.approval.request_hash);
    const foreign = await call("POST", "/v1/hypervisor/verifier-challenges", { ...input, wallet_approval_grant: foreignGrant });
    ok("AUTHORITY: same hashes with a foreign signer refuse", foreign.status === 403, `${foreign.status}/${foreign.body.error?.code}`);
    const created = await call("POST", "/v1/hypervisor/verifier-challenges", { ...input, wallet_approval_grant: grant });
    const challenge = created.body.verifier_challenge;
    const tail = challenge?.verifier_challenge_id?.replace("verifier-challenge://", "");
    const linkedResult = (await call("GET", `/v1/hypervisor/work-results/${workResult.work_result_id.replace("work-result://", "")}`)).body.work_result;
    ok("CREATE: participant admits canonical Finding challenge with frozen target, WorkResult, affected Attempt, and owner backlink",
      created.status === 201 && /^vc_[0-9a-f]{64}$/.test(tail)
      && challenge.frozen_coordinates?.challenged_target?.kind === "finding"
      && challenge.frozen_coordinates?.work_result?.record_ref === workResult.work_result_id
      && challenge.frozen_coordinates?.bound_attempt_ref === attemptRef
      && JSON.stringify(linkedResult.challenge_refs) === JSON.stringify([challenge.verifier_challenge_id]),
      `${created.status}/${created.body.error?.code || "ok"}`);
    const replayedCreate = await call("POST", "/v1/hypervisor/verifier-challenges", { ...input, wallet_approval_grant: grant });
    const staleAdmit = await call("POST", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "admit", expected_revision: 0,
    });
    ok("CONCURRENCY: replayed create grant and stale transition revision refuse",
      replayedCreate.status === 403 && replayedCreate.body.error?.code === "verifier_challenge_participant_authority_required"
      && staleAdmit.status === 409,
      `${replayedCreate.status}/${replayedCreate.body.error?.code}; ${staleAdmit.status}/${staleAdmit.body.error?.code}`);

    const blockedAccept = await call("POST", `/v1/hypervisor/findings/${findingRef.replace("finding://", "")}/transition`, {
      transition: "accept", expected_revision: 4,
    });
    ok("INTERLOCK: unresolved challenge blocks Finding acceptance before the existing unavailable contract",
      blockedAccept.status === 409 && blockedAccept.body.error?.code === "verifier_challenge_acceptance_unresolved",
      `${blockedAccept.status}/${blockedAccept.body.error?.code}`);

    await plane.stop();
    plane = await startIsolatedPlane({ serve: false, env: { ...resolver.env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "verifier-challenge-receipts" }, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const pendingCreate = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/verifier-challenges",
      challengeBody(roomRef, lease.participant_lease_id, secondAttemptRef, [secondAttemptRef], {
        challenge_kind: "mapping", challenge_evidence_refs: ["evidence://receipt-fault"],
      }));
    const crashIntentName = names(dataDir, "verifier-challenge-intents")[0];
    const crashSealed = crashIntentName ? JSON.parse(readFileSync(join(dataDir, "verifier-challenge-intents", crashIntentName), "utf8")) : null;
    const crashTail = crashSealed?.final_challenge?.verifier_challenge_id?.replace("verifier-challenge://", "");
    ok("DURABILITY: create receipt fault retains exact challenge, room, WorkResult, Attempt, and authority successors",
      pendingCreate.response.status === 500 && crashSealed?.receipt?.wallet_approval_grant
      && crashSealed?.final_work_result?.challenge_refs?.includes(crashSealed?.final_challenge?.verifier_challenge_id)
      && crashSealed?.touched_refs?.includes(secondAttemptRef)
      && crashSealed?.touched_refs?.includes(workResult.work_result_id)
      && crashSealed?.touched_refs?.includes(roomRef),
      `${pendingCreate.response.status}/${pendingCreate.response.body.error?.code}`);
    process.kill(plane.daemonPid, "SIGKILL");
    await delay(300);
    await plane.stop();
    plane = await startIsolatedPlane({ serve: false, env: { ...resolver.env, IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "60000" }, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const crashConverged = await poll(call, `/v1/hypervisor/verifier-challenges/${crashTail}`,
      (value) => value.status === 200 && value.body.verifier_challenge?.status === "proposed", 90_000);
    const crashRecordPath = join(dataDir, "verifier-challenges", `${crashTail}.json`);
    const workResultPath = join(dataDir, "work-result-registry", `${workResult.work_result_id.replace("work-result://", "")}.json`);
    const crashBytesExact = readFileSync(crashRecordPath, "utf8") === JSON.stringify(crashSealed?.final_challenge, null, 2);
    const workResultBytesExact = readFileSync(workResultPath, "utf8") === JSON.stringify(crashSealed?.final_work_result, null, 2);
    ok("DURABILITY: SIGKILL plus one restart converges exact challenge and WorkResult backlink successors",
      crashConverged.status === 200 && crashBytesExact && workResultBytesExact
      && names(dataDir, "verifier-challenge-intents").length === 0,
      `${crashConverged.status}/${crashConverged.body.error?.code || crashConverged.body.verifier_challenge?.status}; challenge=${crashBytesExact}; workResult=${workResultBytesExact}; intents=${names(dataDir, "verifier-challenge-intents").length}`);
    const clearedFaultedCreate = await governed(call, resolver, lease.participant_ref,
      `/v1/hypervisor/verifier-challenges/${crashTail}/transition`,
      { transition: "withdraw", expected_revision: crashConverged.body.verifier_challenge.revision });
    const admitted = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "admit", expected_revision: challenge.revision,
    });
    ok("DURABILITY: converged faulted creation can clear and the original lifecycle remains writable",
      clearedFaultedCreate.response.status === 200 && admitted.response.status === 200,
      `${clearedFaultedCreate.response.status}/${admitted.response.status}`);

    let current = admitted.response.body.verifier_challenge;
    for (const [transition, expected] of [["investigate", "investigating"], ["uphold", "upheld"]]) {
      const moved = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
        transition, expected_revision: current.revision,
      });
      current = moved.response.body.verifier_challenge;
      ok(`LIFECYCLE: host ${transition} -> ${expected}`, moved.response.status === 200 && current?.status === expected,
        `${moved.response.status}/${moved.response.body.error?.code || "ok"}`);
    }
    const omitted = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "rule_changed", expected_revision: current.revision, reverification_required: true,
    });
    ok("RULE CHANGE: omitted rule versions refuse before mutation", omitted.response.status === 422,
      `${omitted.response.status}/${omitted.response.body.error?.code}`);
    const beforeLifecycleBypass = {
      challenge: readFileSync(join(dataDir, "verifier-challenges", `${tail}.json`), "utf8"),
      receipts: names(dataDir, "verifier-challenge-receipts"),
      intents: names(dataDir, "verifier-challenge-intents"),
    };
    const earlyResolve = await governed(call, resolver, "domain://acme-host",
      `/v1/hypervisor/verifier-challenges/${tail}/transition`,
      { transition: "resolve", expected_revision: current.revision });
    const identicalRules = await governed(call, resolver, "domain://acme-host",
      `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
        transition: "rule_changed", expected_revision: current.revision,
        prior_rule_version_ref: "rubric://same", proposed_rule_version_ref: "rubric://same",
        affected_attempt_refs: [attemptRef], reverification_required: true,
      });
    const lifecycleBypassZeroMutation = beforeLifecycleBypass.challenge === readFileSync(join(dataDir, "verifier-challenges", `${tail}.json`), "utf8")
      && JSON.stringify(beforeLifecycleBypass.receipts) === JSON.stringify(names(dataDir, "verifier-challenge-receipts"))
      && JSON.stringify(beforeLifecycleBypass.intents) === JSON.stringify(names(dataDir, "verifier-challenge-intents"));
    ok("LIFECYCLE: upheld required-reverification and identical-rule bypasses refuse with zero mutation",
      earlyResolve.response.status === 422
      && earlyResolve.response.body.error?.code === "verifier_challenge_reverification_incomplete"
      && identicalRules.response.status === 422
      && identicalRules.response.body.error?.code === "verifier_challenge_rule_versions_identical"
      && lifecycleBypassZeroMutation,
      `${earlyResolve.response.status}/${earlyResolve.response.body.error?.code}; ${identicalRules.response.status}/${identicalRules.response.body.error?.code}; zero=${lifecycleBypassZeroMutation}`);
    const substituted = await call("POST", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "rule_changed", expected_revision: current.revision,
      prior_rule_version_ref: "rubric://v1", proposed_rule_version_ref: "rubric://v2",
      affected_attempt_refs: [secondAttemptRef], reverification_required: true,
    });
    ok("RULE CHANGE: affected-Attempt substitution refuses before authorization and mutation",
      substituted.status === 422 && substituted.body.error?.code === "verifier_challenge_affected_attempt_substitution",
      `${substituted.status}/${substituted.body.error?.code}`);
    const ruleChanged = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "rule_changed", expected_revision: current.revision,
      prior_rule_version_ref: "rubric://v1", proposed_rule_version_ref: "rubric://v2",
      affected_attempt_refs: [attemptRef], reverification_required: true,
    });
    current = ruleChanged.response.body.verifier_challenge;
    const beforeRuleResolve = readFileSync(join(dataDir, "verifier-challenges", `${tail}.json`), "utf8");
    const ruleResolve = await governed(call, resolver, "domain://acme-host",
      `/v1/hypervisor/verifier-challenges/${tail}/transition`,
      { transition: "resolve", expected_revision: current.revision });
    ok("LIFECYCLE: rule_changed cannot resolve before begin_reverification",
      ruleResolve.response.status === 422
      && ruleResolve.response.body.error?.code === "verifier_challenge_reverification_incomplete"
      && beforeRuleResolve === readFileSync(join(dataDir, "verifier-challenges", `${tail}.json`), "utf8"),
      `${ruleResolve.response.status}/${ruleResolve.response.body.error?.code}`);
    const reverifying = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "begin_reverification", expected_revision: current.revision,
    });
    current = reverifying.response.body.verifier_challenge;
    const resolved = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${tail}/transition`, {
      transition: "resolve", expected_revision: current.revision,
    });
    current = resolved.response.body.verifier_challenge;
    ok("LIFECYCLE: uphold -> rule_changed -> reverifying -> resolved binds exact versions and reverification",
      ruleChanged.response.status === 200 && reverifying.response.status === 200 && resolved.response.status === 200
      && current.status === "resolved" && current.reverification_required === true,
      `${ruleChanged.response.status}/${reverifying.response.status}/${resolved.response.status}`);
    const unavailableAccept = await call("POST", `/v1/hypervisor/findings/${findingRef.replace("finding://", "")}/transition`, {
      transition: "accept", expected_revision: 4,
    });
    ok("INTERLOCK: resolved challenge clears 409 and existing acceptance authority remains typed unavailable",
      unavailableAccept.status === 501 && unavailableAccept.body.error?.code === "finding_verdict_unavailable",
      `${unavailableAccept.status}/${unavailableAccept.body.error?.code}`);

    // Keep the adversarial bar bounded on saturated development hosts. Each fresh fixture installs
    // the same root-signed bindings and exercises the same pinned production transport; rotating it
    // here prevents one debug consensus chain from dominating unrelated lifecycle lanes.
    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({ serve: false, env: { ...resolver.env, IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "60000" }, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    const negative = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/verifier-challenges",
      challengeBody(roomRef, lease.participant_lease_id, attemptRef, [attemptRef], { challenge_kind: "metric", challenge_evidence_refs: ["evidence://metric-negative"] }));
    let negativeRecord = negative.response.body.verifier_challenge;
    const negativeTail = negativeRecord.verifier_challenge_id.replace("verifier-challenge://", "");
    const derivedFindingBlocked = await call("POST", `/v1/hypervisor/findings/${findingRef.replace("finding://", "")}/transition`, {
      transition: "accept", expected_revision: 4,
    });
    const negativeAdmit = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${negativeTail}/transition`, { transition: "admit", expected_revision: negativeRecord.revision });
    negativeRecord = negativeAdmit.response.body.verifier_challenge;
    const rejected = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/verifier-challenges/${negativeTail}/transition`, { transition: "reject", expected_revision: negativeRecord.revision });
    const derivedFindingCleared = await call("POST", `/v1/hypervisor/findings/${findingRef.replace("finding://", "")}/transition`, {
      transition: "accept", expected_revision: 4,
    });
    ok("INTERLOCK: Attempt challenge blocks its derived Finding until rejection restores the existing 501",
      derivedFindingBlocked.status === 409
      && derivedFindingBlocked.body.error?.code === "verifier_challenge_acceptance_unresolved"
      && rejected.response.status === 200 && rejected.response.body.verifier_challenge?.status === "rejected"
      && derivedFindingCleared.status === 501 && derivedFindingCleared.body.error?.code === "finding_verdict_unavailable",
      `${derivedFindingBlocked.status}/${rejected.response.status}/${derivedFindingCleared.status}`);

    const withdrawnCreated = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/verifier-challenges",
      challengeBody(roomRef, lease.participant_lease_id, findingRef, [attemptRef], { challenge_kind: "mapping", challenge_evidence_refs: ["evidence://withdrawn"] }));
    const withdrawnRecord = withdrawnCreated.response.body.verifier_challenge;
    const withdrawn = await governed(call, resolver, lease.participant_ref,
      `/v1/hypervisor/verifier-challenges/${withdrawnRecord.verifier_challenge_id.replace("verifier-challenge://", "")}/transition`,
      { transition: "withdraw", expected_revision: withdrawnRecord.revision });
    ok("WITHDRAW: active challenger can withdraw a proposed challenge", withdrawn.response.status === 200 && withdrawn.response.body.verifier_challenge?.status === "withdrawn");

    await plane.stop();
    await resolver.stop();
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startIsolatedPlane({ serve: false, env: { ...resolver.env, IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "60000" }, dataDir });
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    const historical = await governed(call, resolver, lease.participant_ref, "/v1/hypervisor/verifier-challenges",
      challengeBody(roomRef, lease.participant_lease_id, attemptRef, [attemptRef], { challenge_kind: "rule", challenge_evidence_refs: ["evidence://historical"] }));
    const historicalRecord = historical.response.body.verifier_challenge;
    const leaseTail = lease.participant_lease_id.replace("participant-lease://", "");
    const liveLease = (await call("GET", `/v1/hypervisor/room-participant-leases/${leaseTail}`)).body.participant_lease;
    const revoked = await governed(call, resolver, "domain://acme-host", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, {
      transition: "revoke", expected_revision: liveLease.revision,
    });
    const beforeInactive = [names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts"), names(dataDir, "verifier-challenge-intents")];
    const inactive = await call("POST", "/v1/hypervisor/verifier-challenges", {
      ...challengeBody(roomRef, lease.participant_lease_id, findingRef, [attemptRef], { challenge_kind: "collusion", challenge_evidence_refs: ["evidence://inactive"] }),
    });
    const inactiveZeroMutation = JSON.stringify(beforeInactive) === JSON.stringify([
      names(dataDir, "verifier-challenges"), names(dataDir, "verifier-challenge-receipts"), names(dataDir, "verifier-challenge-intents"),
    ]);
    const historicalAdmit = await governed(call, resolver, "domain://acme-host",
      `/v1/hypervisor/verifier-challenges/${historicalRecord.verifier_challenge_id.replace("verifier-challenge://", "")}/transition`,
      { transition: "admit", expected_revision: historicalRecord.revision });
    ok("PARTICIPATION: revoked participant cannot create; historical host lifecycle remains valid",
      revoked.response.status === 200 && inactive.status === 409 && inactive.body.error?.code === "verifier_challenge_participant_not_active"
      && inactiveZeroMutation
      && historicalAdmit.response.status === 200,
      `${revoked.response.status}/${inactive.status}/${historicalAdmit.response.status}`);

    const overview = await call("GET", "/v1/hypervisor/verifier-challenges/overview");
    ok("OVERVIEW: unresolved blockers are projected by challenged ref and authority boundaries are honest",
      overview.status === 200 && overview.body.unresolved_blockers_by_challenged_ref?.[attemptRef]?.length === 1
      && overview.body.acceptance_authority === "not_provided" && overview.body.execution_authority === "not_provided");

    const findingPath = join(dataDir, "findings", `${findingRef.replace("finding://", "")}.json`);
    const archivedFinding = JSON.parse(readFileSync(findingPath, "utf8"));
    archivedFinding.status = "archived";
    archivedFinding.revision += 1;
    writeFileSync(findingPath, JSON.stringify(archivedFinding));
    const roomTail = roomRef.replace("outcome-room://", "");
    const roomBeforeClose = (await call("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const blockedClose = await call("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, {
      transition: "close", expected_revision: roomBeforeClose.revision,
    });
    ok("RACE: room close refuses while an unresolved challenge remains",
      blockedClose.status === 409 && blockedClose.body.error?.code === "outcome_room_close_blocked_verifier_challenges",
      `${blockedClose.status}/${blockedClose.body.error?.code}`);

    // Canonical unreadable storage is uncertainty, never absence.
    const participantPath = join(dataDir, "room-participant-leases", `${lease.participant_lease_id.replace("participant-lease://", "")}.json`);
    const revokedParticipantBytes = readFileSync(participantPath, "utf8");
    const temporarilyActive = JSON.parse(revokedParticipantBytes);
    temporarilyActive.status = "active";
    writeFileSync(participantPath, JSON.stringify(temporarilyActive));
    const targetPath = join(dataDir, "attempts", `${attemptRef.replace("attempt://", "")}.json`);
    chmodSync(targetPath, 0o000);
    const unreadable = await call("POST", "/v1/hypervisor/verifier-challenges",
      challengeBody(roomRef, lease.participant_lease_id, attemptRef, [attemptRef], { challenge_kind: "exploit" }));
    chmodSync(targetPath, 0o600);
    writeFileSync(participantPath, revokedParticipantBytes);
    ok("STORAGE: unreadable canonical target refuses typed without treating it as absent",
      unreadable.status === 500 && unreadable.body.error?.code === "verifier_challenge_target_unreadable",
      `${unreadable.status}/${unreadable.body.error?.code}`);

    ok("BOUNDARY: no acceptance, verdict, settlement, execution, or federation semantics were minted",
      current.acceptance_ref == null && current.adjudication_ref == null && overview.body.federated_admission === "typed_unavailable");
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
