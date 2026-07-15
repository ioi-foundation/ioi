#!/usr/bin/env node
// #74 held integration bar. Production routes use the wallet.network HTTP resolution contract;
// this verifier supplies that external boundary, never an in-process/test-only daemon bypass.

import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startPrincipalAuthorityResolver } from "./lib/principal-authority-resolver.mjs";

const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["room-participation-requests", "room-participant-leases", "room-participation-receipts", "room-participation-submit-intents"];
const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });
const names = (dir, family) => { try { return readdirSync(join(dir, family)).sort(); } catch { return []; } };
const count = (dir, family) => names(dir, family).length;

const VALID_ROOM = {
  owner_or_sponsor_ref: "org://acme", objective_ref: "goal://alloy-program",
  objective: "Find a fatigue-resistant alloy candidate.", room_mode: "open_challenge",
  coordination_topology: "hosted_admission", stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible", participation_policy_ref: "policy://open-eligibility",
  privacy_policy_ref: "policy://no-pii", contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1", ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover", host_domain_ref: "domain://acme-host",
};
const VALID_REQUEST = (roomRef, principal = "worker://independent-alloy-lab") => ({
  outcome_room_ref: roomRef, requested_by_ref: principal, coordination_topology: "hosted_admission",
  admission_owner_ref: "domain://acme-host",
  operator_and_home_domain_refs: ["org://alloy-lab", "domain://alloy-lab.example"],
  worker_composition_and_dependency_refs: ["worker://fatigue-sim-worker", "model_route://m1", "harness_profile:codex-local"],
  capability_offer_refs: ["capability-offer://fatigue-sim"],
  affiliation_and_independent_operation_evidence_refs: ["evidence://independent-operation"],
  eligibility_evidence_refs: ["evidence://fatigue-benchmarks"],
  accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
});
const VALID_ADMIT = { admitted_role: "implementer", operator_ref: "org://alloy-lab", home_domain_ref: "agentgres://domain/alloy-lab" };

async function jsonCall(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function challengeAndGrant(plane, resolver, principal, path, body) {
  const challenge = await jsonCall(plane.daemonUrl, "POST", path, body);
  const approval = challenge.body.error?.approval;
  if (!approval?.policy_hash || !approval?.request_hash) return { challenge, grant: null };
  return {
    challenge,
    grant: resolver.mint(principal, approval.policy_hash, approval.request_hash),
  };
}

async function run() {
  const before = Object.fromEntries(FAMILIES.map((family) => [family, count(REAL_DATA_DIR, family)]));
  const resolver = await startPrincipalAuthorityResolver([
    { principalRef: "domain://acme-host", seed: "07".repeat(32) },
    { principalRef: "worker://independent-alloy-lab", seed: "09".repeat(32) },
  ]);
  const env = { IOI_WALLET_NETWORK_URL: resolver.url };
  let plane;
  try {
    plane = await startIsolatedPlane({ serve: false, env });
    if (!plane) { console.log("BLOCKED: hypervisor-daemon binary not built"); process.exit(2); }
    const jd = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

    const roomCreate = await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM);
    const room = roomCreate.body.outcome_room;
    const roomRef = room?.outcome_room_id;
    const roomTail = String(roomRef).replace("outcome-room://", "");
    ok("ROOM: hosted room admitted open", roomCreate.status === 201 && room?.status === "open", `${roomCreate.status}/${room?.status}`);

    const submit = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    const request = submit.body.participation_request;
    const requestTail = String(request?.participation_request_id).replace("participation-request://", "");
    ok("SUBMIT: request is live and grants nothing", submit.status === 201 && request?.status === "submitted" && request?.revision === 1, `${submit.status}/${request?.status}`);
    const posture = await jd("GET", "/v1/hypervisor/room-participation-requests");
    ok("AUTHORITY: production resolver posture is live", posture.body.decision_authority_posture?.status === "available", JSON.stringify(posture.body.decision_authority_posture));

    const evaluatePath = `/v1/hypervisor/room-participation-requests/${requestTail}/transition`;
    const evaluate = await challengeAndGrant(plane, resolver, "domain://acme-host", evaluatePath, { transition: "evaluate", expected_revision: 1 });
    ok("EVALUATE: challenge binds exact operation scope", evaluate.challenge.status === 403 && evaluate.challenge.body.error?.required_scope === "room_participation.evaluate", `${evaluate.challenge.status}/${evaluate.challenge.body.error?.required_scope}`);
    const foreign = mintApprovalGrant({ seed: "08".repeat(32), policyHash: evaluate.challenge.body.error.approval.policy_hash, requestHash: evaluate.challenge.body.error.approval.request_hash });
    const foreignResponse = await jd("POST", evaluatePath, { transition: "evaluate", expected_revision: 1, wallet_approval_grant: foreign });
    ok("EVALUATE: same-hash foreign signer is refused", foreignResponse.status === 403 && foreignResponse.body.error?.code === "room_participation_host_authority_required", `${foreignResponse.status}/${foreignResponse.body.error?.code}`);
    const evaluated = await jd("POST", evaluatePath, { transition: "evaluate", expected_revision: 1, wallet_approval_grant: evaluate.grant });
    ok("EVALUATE: bound host grant advances request", evaluated.status === 200 && evaluated.body.participation_request?.status === "evaluating" && evaluated.body.participation_request?.revision === 2, `${evaluated.status}/${evaluated.body.participation_request?.status}`);

    resolver.setTamper("scope");
    const scopeTamper = await jd("POST", evaluatePath, { transition: "reject", expected_revision: 2 });
    resolver.setTamper("snapshot");
    const snapshotTamper = await jd("POST", evaluatePath, { transition: "reject", expected_revision: 2 });
    resolver.setTamper("expiry");
    const expiryTamper = await jd("POST", evaluatePath, { transition: "reject", expected_revision: 2 });
    resolver.setTamper(null);
    const afterTamper = await jd("GET", `/v1/hypervisor/room-participation-requests/${requestTail}`);
    ok("RESOLUTION: scope-escalated unchanged hash is refused before mutation", scopeTamper.status === 502 && scopeTamper.body.error?.code === "room_participation_authority_resolution_invalid", `${scopeTamper.status}/${scopeTamper.body.error?.code}`);
    ok("RESOLUTION: revoked snapshot with frozen hash is refused before mutation", snapshotTamper.status === 502 && snapshotTamper.body.error?.code === "room_participation_authority_resolution_invalid" && afterTamper.body.participation_request?.revision === 2, `${snapshotTamper.status}/${snapshotTamper.body.error?.code}`);
    ok("RESOLUTION: altered expiry with frozen hash is refused before mutation", expiryTamper.status === 502 && expiryTamper.body.error?.code === "room_participation_authority_resolution_invalid" && afterTamper.body.participation_request?.revision === 2, `${expiryTamper.status}/${expiryTamper.body.error?.code}`);

    const admitPath = `/v1/hypervisor/room-participation-requests/${requestTail}/admit`;
    const admit = await challengeAndGrant(plane, resolver, "domain://acme-host", admitPath, { ...VALID_ADMIT, expected_revision: 2 });
    const admitted = await jd("POST", admitPath, { ...VALID_ADMIT, expected_revision: 2, wallet_approval_grant: admit.grant });
    const lease = admitted.body.participant_lease;
    const leaseTail = String(lease?.participant_lease_id).replace("participant-lease://", "");
    const authorityEvidence = admitted.body.participation_request_receipt;
    ok("ADMIT: request and bounded lease land together", admitted.status === 200 && admitted.body.participation_request?.status === "admitted" && lease?.status === "active", `${admitted.status}/${lease?.status}`);
    ok("ADMIT: evidence retains signed grant plus full pinned tuple", !!authorityEvidence?.wallet_approval_grant?.approver_sig && authorityEvidence?.principal_authority_binding?.required_scope === "room_participation.admit" && authorityEvidence?.principal_authority_binding?.coordinates?.binding_version === 1 && Array.isArray(authorityEvidence?.principal_authority_binding?.approval_authority_snapshot_hash), JSON.stringify(authorityEvidence?.principal_authority_binding || {}));

    const leasePath = `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`;
    const sleep = await challengeAndGrant(plane, resolver, "worker://independent-alloy-lab", leasePath, { transition: "sleep", expected_revision: 1 });
    const slept = await jd("POST", leasePath, { transition: "sleep", expected_revision: 1, wallet_approval_grant: sleep.grant });
    const wake = await challengeAndGrant(plane, resolver, "worker://independent-alloy-lab", leasePath, { transition: "wake", expected_revision: 2 });
    const woke = await jd("POST", leasePath, { transition: "wake", expected_revision: 2, wallet_approval_grant: wake.grant });
    ok("LEASE: participant-bound sleep/wake journey is live", slept.body.participant_lease?.status === "sleeping" && woke.body.participant_lease?.status === "active", `${slept.status}/${woke.status}`);
    const revoke = await challengeAndGrant(plane, resolver, "domain://acme-host", leasePath, { transition: "revoke", expected_revision: 3 });
    const revoked = await jd("POST", leasePath, { transition: "revoke", expected_revision: 3, wallet_approval_grant: revoke.grant });
    const roomAfterRelease = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).body.outcome_room;
    const close = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, { transition: "close", expected_revision: roomAfterRelease.revision });
    ok("TERMINAL: revoke returns only after room release converges", revoked.status === 200 && revoked.body.participant_lease?.status === "revoked" && (roomAfterRelease.released_participant_lease_refs || []).includes(lease.participant_lease_id), `${revoked.status}/${revoked.body.participant_lease?.status}`);
    ok("TERMINAL: released room closes", close.status === 200 && close.body.outcome_room?.status === "closed", `${close.status}/${close.body.outcome_room?.status}`);
  } finally {
    if (plane) await plane.stop();
  }

  // Receipt-fault journey: admission intent retains the tuple; stale rotation refuses replay;
  // restoring the exact binding lets one boot converge. A terminal transition fault then
  // completes both the lease and room release in one further boot pass.
  const faultDir = mkdtempSync(join(tmpdir(), "ioi-room-participation-fault-"));
  let faultPlane;
  try {
    faultPlane = await startIsolatedPlane({ serve: false, env, dataDir: faultDir });
    const f = (method, path, body) => jsonCall(faultPlane.daemonUrl, method, path, body);
    const faultRoom = (await f("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).body.outcome_room;
    const faultRoomTail = faultRoom.outcome_room_id.replace("outcome-room://", "");
    const faultRequest = (await f("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(faultRoom.outcome_room_id))).body.participation_request;
    const faultRequestTail = faultRequest.participation_request_id.replace("participation-request://", "");
    await faultPlane.stop();

    faultPlane = await startIsolatedPlane({ serve: false, env: { ...env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "room-participation-receipts" }, dataDir: faultDir });
    const admitPath = `/v1/hypervisor/room-participation-requests/${faultRequestTail}/admit`;
    const admit = await challengeAndGrant(faultPlane, resolver, "domain://acme-host", admitPath, { ...VALID_ADMIT, expected_revision: 1 });
    const pendingAdmit = await jsonCall(faultPlane.daemonUrl, "POST", admitPath, { ...VALID_ADMIT, expected_revision: 1, wallet_approval_grant: admit.grant });
    const carrying = JSON.parse(readFileSync(join(faultDir, "room-participation-requests", `${faultRequestTail}.json`), "utf8"));
    ok("ADMIT FAULT: typed pending retains complete grant and binding tuple", pendingAdmit.status === 500 && pendingAdmit.body.error?.code === "room_participation_admit_pending_convergence" && !!carrying.admit_intent?.request_receipt?.wallet_approval_grant?.approver_sig && carrying.admit_intent?.request_receipt?.principal_authority_binding?.required_scope === "room_participation.admit", `${pendingAdmit.status}/${pendingAdmit.body.error?.code}`);
    process.kill(faultPlane.daemonPid, "SIGKILL");
    await faultPlane.stop();

    const oldBinding = resolver.rotate("domain://acme-host", "0a".repeat(32));
    faultPlane = await startIsolatedPlane({ serve: false, env, dataDir: faultDir });
    const stale = await jsonCall(faultPlane.daemonUrl, "GET", `/v1/hypervisor/room-participation-requests/${faultRequestTail}`);
    ok("REPLAY: rotated/stale coordinates retain intent and admit nothing", !!stale.body.participation_request?.admit_intent && count(faultDir, "room-participant-leases") === 0, `intent=${!!stale.body.participation_request?.admit_intent}`);
    await faultPlane.stop();
    resolver.restore("domain://acme-host", oldBinding);

    faultPlane = await startIsolatedPlane({ serve: false, env, dataDir: faultDir });
    const converged = await jsonCall(faultPlane.daemonUrl, "GET", `/v1/hypervisor/room-participation-requests/${faultRequestTail}`);
    const leases = (await jsonCall(faultPlane.daemonUrl, "GET", "/v1/hypervisor/room-participant-leases")).body.participant_leases || [];
    const replayedLease = leases[0];
    ok("REPLAY: exact coordinates converge admission in one boot", converged.body.participation_request?.status === "admitted" && !converged.body.participation_request?.admit_intent && leases.length === 1 && replayedLease?.status === "active", `${converged.body.participation_request?.status}/leases=${leases.length}`);
    await faultPlane.stop();

    faultPlane = await startIsolatedPlane({ serve: false, env: { ...env, IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "room-participation-receipts" }, dataDir: faultDir });
    const leaseTail = replayedLease.participant_lease_id.replace("participant-lease://", "");
    const revokePath = `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`;
    const revoke = await challengeAndGrant(faultPlane, resolver, "domain://acme-host", revokePath, { transition: "revoke", expected_revision: 1 });
    const pendingRevoke = await jsonCall(faultPlane.daemonUrl, "POST", revokePath, { transition: "revoke", expected_revision: 1, wallet_approval_grant: revoke.grant });
    ok("TERMINAL FAULT: incomplete transition returns typed pending", pendingRevoke.status === 500 && pendingRevoke.body.error?.code === "room_participation_transition_pending_convergence", `${pendingRevoke.status}/${pendingRevoke.body.error?.code}`);
    process.kill(faultPlane.daemonPid, "SIGKILL");
    await faultPlane.stop();

    faultPlane = await startIsolatedPlane({ serve: false, env, dataDir: faultDir });
    const finalLease = (await jsonCall(faultPlane.daemonUrl, "GET", `/v1/hypervisor/room-participant-leases/${leaseTail}`)).body.participant_lease;
    const finalRoom = (await jsonCall(faultPlane.daemonUrl, "GET", `/v1/hypervisor/outcome-rooms/${faultRoomTail}`)).body.outcome_room;
    const finalClose = await jsonCall(faultPlane.daemonUrl, "POST", `/v1/hypervisor/outcome-rooms/${faultRoomTail}/transition`, { transition: "close", expected_revision: finalRoom.revision });
    ok("TERMINAL REPLAY: one boot finalizes lease and releases room slot", finalLease?.status === "revoked" && !finalLease?.transition_intent && (finalRoom?.released_participant_lease_refs || []).includes(replayedLease.participant_lease_id) && finalClose.status === 200, `${finalLease?.status}/close=${finalClose.status}`);
  } finally {
    if (faultPlane) await faultPlane.stop();
    rmSync(faultDir, { recursive: true, force: true });
    await resolver.stop();
  }

  const after = Object.fromEntries(FAMILIES.map((family) => [family, count(REAL_DATA_DIR, family)]));
  ok("ISOLATION: real daemon participation families untouched", FAMILIES.every((family) => before[family] === after[family]), FAMILIES.map((family) => `${family}:${before[family]}→${after[family]}`).join(" "));
  const passed = results.filter((result) => result.pass).length;
  for (const result of results) console.log(`  ${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? `  (${result.detail})` : ""}`);
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) process.exit(1);
  console.log("room-participation plane held-bar: PASS (full scope-bound wallet.network journey live; #74 remains held)");
}

run().catch((error) => { console.error("VERIFIER CRASH:", error); process.exit(1); });
