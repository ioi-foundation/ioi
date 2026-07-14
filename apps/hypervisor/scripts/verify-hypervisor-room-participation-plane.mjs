#!/usr/bin/env node
// Room-participation plane held-bar (#74, build step 3 first pair) — isolated per verifier
// doctrine. This verifier reflects the honest current posture:
//   - request intake is live and grants no authority;
//   - governed host/participant decisions are typed-unavailable until a trusted, versioned
//     identity-ref → wallet-authority binding plane exists;
//   - two real signers carrying IDENTICAL daemon-derived hashes are both refused with zero
//     mutation (hash binding is not identity binding);
//   - closed-room admission and noncanonical Agentgres home-domain refs write no evidence;
//   - submit durability/restart convergence remains live.
// The successful admit/close transaction race and terminal-release fault recovery are exercised
// at the Rust internal seam because adding a test-only production authority resolver would weaken
// the exact boundary this verifier protects.

import { chmodSync, existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
const { mintApprovalGrant } = await import(new URL("../../../scripts/lib/mint-approval-grant.mjs", import.meta.url));

const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["room-participation-requests", "room-participant-leases", "room-participation-receipts", "room-participation-submit-intents"];
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });
const famNames = (dataDir, family) => { try { return readdirSync(join(dataDir, family)); } catch { return []; } };
const famCount = (dataDir, family) => famNames(dataDir, family).length;
const decisionReceiptNames = (dataDir) => famNames(dataDir, "room-participation-receipts").filter((name) => /^(rlr|rqt|rlt)_/.test(name));

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
const VALID_ADMIT = { admitted_role: "implementer", operator_ref: "org://alloy-lab", home_domain_ref: "domain://alloy-lab.example" };

async function run() {
  const before = Object.fromEntries(FAMILIES.map((family) => [family, famCount(REAL_DATA_DIR, family)]));
  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.log("BLOCKED: hypervisor-daemon binary not built"); process.exit(2); }
  const { dataDir } = plane;
  const jd = async (method, path, body) => {
    const response = await fetch(`${plane.daemonUrl}${path}`, {
      method, headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, j: await response.json().catch(() => ({})) };
  };

  try {
    const roomCreate = await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM);
    const room = roomCreate.j.outcome_room;
    const roomRef = room.outcome_room_id;
    const roomTail = String(roomRef).replace("outcome-room://", "");
    ok("ROOM prerequisite: hosted room admitted open", roomCreate.status === 201 && room?.status === "open", `${roomCreate.status}/${room?.status}`);

    const failClosed = [
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: null }, "room_participation_room_required"],
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: "outcome-room://or_ghost" }, "room_participation_room_not_found"],
      [{ ...VALID_REQUEST(roomRef), coordination_topology: "federated_admission" }, "room_participation_federated_unavailable"],
      [{ ...VALID_REQUEST(roomRef), admission_owner_ref: "domain://not-the-host" }, "room_participation_admission_owner_mismatch"],
      [{ ...VALID_REQUEST(roomRef), private_context_included: true }, "room_participation_private_context_rejected"],
      [{ ...VALID_REQUEST(roomRef), status: "admitted" }, "room_participation_status_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), signature: "sig" }, "room_participation_signature_unavailable"],
      [{ ...VALID_REQUEST(roomRef), worker_composition_and_dependency_refs: ["model-route://m"] }, "room_participation_ref_scheme_invalid"],
      [{ ...VALID_REQUEST(roomRef), notes: { api_key: "SENTINEL_SECRET" } }, "outcome_room_plaintext_secret_rejected"],
    ];
    const refusalDetails = [];
    for (const [body, expectedCode] of failClosed) {
      const response = await jd("POST", "/v1/hypervisor/room-participation-requests", body);
      if (!(response.status >= 400 && response.j.error?.code === expectedCode)) {
        refusalDetails.push(`${expectedCode}→${response.status}/${response.j.error?.code}`);
      }
    }
    ok(`CREATE fail-closed: ${failClosed.length}/${failClosed.length} typed refusals`, refusalDetails.length === 0, refusalDetails.join(" "));
    ok("CREATE refusals persist zero requests", famCount(dataDir, "room-participation-requests") === 0);

    const submit = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    const request = submit.j.participation_request;
    const requestTail = String(request?.participation_request_id).replace("participation-request://", "");
    ok("SUBMIT: ungated intake persists submitted request and canonical ref grammar", submit.status === 201 && request?.status === "submitted" && request?.revision === 1 && request?.worker_composition_and_dependency_refs?.includes("model_route://m1"), `${submit.status}/${request?.status}`);
    const roomAfterSubmit = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).j.outcome_room;
    ok("SUBMIT: request backlink lands through room-owned seam", roomAfterSubmit?.participation_request_refs?.includes(request.participation_request_id), `refs=${roomAfterSubmit?.participation_request_refs}`);

    // An unreadable canonical occupant is unknown truth, never an absent request. Both the read
    // projection and duplicate guard must refuse typed without manufacturing a second request.
    const requestPath = join(dataDir, "room-participation-requests", `${requestTail}.json`);
    const requestMode = statSync(requestPath).mode & 0o777;
    const requestNamesBeforeUnreadable = famNames(dataDir, "room-participation-requests").sort();
    let unreadableList;
    let unreadableDuplicate;
    chmodSync(requestPath, 0o000);
    try {
      unreadableList = await jd("GET", "/v1/hypervisor/room-participation-requests");
      unreadableDuplicate = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    } finally {
      chmodSync(requestPath, requestMode);
    }
    const requestNamesAfterUnreadable = famNames(dataDir, "room-participation-requests").sort();
    ok("UNREADABLE REQUEST: list and duplicate submit refuse typed with no second request file", unreadableList.status === 500 && unreadableList.j.error?.code === "room_participation_registry_unreadable" && unreadableDuplicate.status === 500 && unreadableDuplicate.j.error?.code === "room_participation_registry_unreadable" && JSON.stringify(requestNamesAfterUnreadable) === JSON.stringify(requestNamesBeforeUnreadable), `list=${unreadableList.status}/${unreadableList.j.error?.code} duplicate=${unreadableDuplicate.status}/${unreadableDuplicate.j.error?.code} files=${requestNamesAfterUnreadable.length}`);

    const requestList = await jd("GET", "/v1/hypervisor/room-participation-requests");
    ok("POSTURE: request metadata declares governed decisions and legacy replay unavailable", requestList.j.decision_authority_posture?.status === "unavailable" && requestList.j.decision_authority_posture?.code === "room_participation_authority_binding_unavailable" && requestList.j.decision_authority_posture?.pending_governed_intents?.startsWith("quarantined"), JSON.stringify(requestList.j.decision_authority_posture || {}));

    // Host class: obtain the daemon-derived hashes, then use two distinct real signers over the
    // exact same hashes. Both must remain unavailable and byte-effect-free.
    const hostChallenge = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "evaluate", expected_revision: 1 });
    ok("AUTHORITY/HOST: missing identity binding is typed 501 with required host + hashes", hostChallenge.status === 501 && hostChallenge.j.error?.code === "room_participation_authority_binding_unavailable" && hostChallenge.j.error?.required_authority_ref === "domain://acme-host" && !!hostChallenge.j.error?.approval?.policy_hash && !!hostChallenge.j.error?.approval?.request_hash, `${hostChallenge.status}/${hostChallenge.j.error?.code}`);
    const hostGrantA = mintApprovalGrant({ seed: "07".repeat(32), policyHash: hostChallenge.j.error.approval.policy_hash, requestHash: hostChallenge.j.error.approval.request_hash });
    const hostGrantB = mintApprovalGrant({ seed: "08".repeat(32), policyHash: hostChallenge.j.error.approval.policy_hash, requestHash: hostChallenge.j.error.approval.request_hash });
    const hostA = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "evaluate", expected_revision: 1, wallet_approval_grant: hostGrantA });
    const hostB = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "evaluate", expected_revision: 1, wallet_approval_grant: hostGrantB });
    const afterHost = (await jd("GET", `/v1/hypervisor/room-participation-requests/${requestTail}`)).j.participation_request;
    ok("AUTHORITY/HOST: two SAME-HASH foreign signers are both unavailable", [hostA, hostB].every((r) => r.status === 501 && r.j.error?.code === "room_participation_authority_binding_unavailable"), `A=${hostA.status}/${hostA.j.error?.code} B=${hostB.status}/${hostB.j.error?.code}`);
    ok("AUTHORITY/HOST: same-hash signer attempts mutate nothing", afterHost?.status === "submitted" && afterHost?.revision === 1 && decisionReceiptNames(dataDir).length === 0, `${afterHost?.status}/${afterHost?.revision} receipts=${decisionReceiptNames(dataDir).length}`);

    // Participant class is separately derived from requested_by_ref and equally unavailable.
    const participantChallenge = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "withdraw", expected_revision: 1 });
    const participantGrantA = mintApprovalGrant({ seed: "09".repeat(32), policyHash: participantChallenge.j.error.approval.policy_hash, requestHash: participantChallenge.j.error.approval.request_hash });
    const participantGrantB = mintApprovalGrant({ seed: "0a".repeat(32), policyHash: participantChallenge.j.error.approval.policy_hash, requestHash: participantChallenge.j.error.approval.request_hash });
    const participantA = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "withdraw", expected_revision: 1, wallet_approval_grant: participantGrantA });
    const participantB = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/transition`, { transition: "withdraw", expected_revision: 1, wallet_approval_grant: participantGrantB });
    ok("AUTHORITY/PARTICIPANT: requester ref is reported, but two SAME-HASH signers remain unavailable", participantChallenge.status === 501 && participantChallenge.j.error?.required_authority_ref === "worker://independent-alloy-lab" && [participantA, participantB].every((r) => r.status === 501), `${participantChallenge.status}/${participantChallenge.j.error?.required_authority_ref}`);

    // Field-specific Agentgres path validation occurs before any authority work or persistence.
    const invalidHome = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/admit`, { ...VALID_ADMIT, home_domain_ref: "agentgres://not-domain", expected_revision: 1 });
    const canonicalHome = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/admit`, { ...VALID_ADMIT, home_domain_ref: "agentgres://domain/alloy-lab", expected_revision: 1 });
    ok("HOME DOMAIN: agentgres://not-domain is refused field-specifically", invalidHome.status === 400 && invalidHome.j.error?.code === "room_participation_ref_scheme_invalid", `${invalidHome.status}/${invalidHome.j.error?.code}`);
    ok("HOME DOMAIN: canonical agentgres://domain/... reaches the honest authority-unavailable boundary", canonicalHome.status === 501 && canonicalHome.j.error?.code === "room_participation_authority_binding_unavailable", `${canonicalHome.status}/${canonicalHome.j.error?.code}`);

    // Admission itself gets a same-hashes/two-signers proof and must create no lease, intent,
    // decision receipts, or room lease backlink.
    const admitGrantA = mintApprovalGrant({ seed: "0b".repeat(32), policyHash: canonicalHome.j.error.approval.policy_hash, requestHash: canonicalHome.j.error.approval.request_hash });
    const admitGrantB = mintApprovalGrant({ seed: "0c".repeat(32), policyHash: canonicalHome.j.error.approval.policy_hash, requestHash: canonicalHome.j.error.approval.request_hash });
    const admitA = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/admit`, { ...VALID_ADMIT, home_domain_ref: "agentgres://domain/alloy-lab", expected_revision: 1, wallet_approval_grant: admitGrantA });
    const admitB = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/admit`, { ...VALID_ADMIT, home_domain_ref: "agentgres://domain/alloy-lab", expected_revision: 1, wallet_approval_grant: admitGrantB });
    const afterAdmitRefusal = (await jd("GET", `/v1/hypervisor/room-participation-requests/${requestTail}`)).j.participation_request;
    const roomAfterAdmitRefusal = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail}`)).j.outcome_room;
    ok("ADMIT AUTHORITY: two SAME-HASH signers are unavailable", [admitA, admitB].every((r) => r.status === 501 && r.j.error?.code === "room_participation_authority_binding_unavailable"), `A=${admitA.status} B=${admitB.status}`);
    ok("ADMIT AUTHORITY: zero lease/evidence/intent/backlink mutation", famCount(dataDir, "room-participant-leases") === 0 && decisionReceiptNames(dataDir).length === 0 && !afterAdmitRefusal?.admit_intent && afterAdmitRefusal?.status === "submitted" && (roomAfterAdmitRefusal?.participant_lease_refs || []).length === 0, `leases=${famCount(dataDir, "room-participant-leases")} receipts=${decisionReceiptNames(dataDir).length}`);

    // Close wins cleanly because no lease was admitted. A later admit must fail before creating
    // the old false receipts/stuck intent reproduction.
    const close = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail}/transition`, { transition: "close", expected_revision: roomAfterAdmitRefusal.revision });
    const receiptNamesBeforeClosedAdmit = [...decisionReceiptNames(dataDir)];
    const closedAdmit = await jd("POST", `/v1/hypervisor/room-participation-requests/${requestTail}/admit`, { ...VALID_ADMIT, expected_revision: 1, wallet_approval_grant: admitGrantA });
    const closedRequest = (await jd("GET", `/v1/hypervisor/room-participation-requests/${requestTail}`)).j.participation_request;
    ok("CLOSED ADMIT: closed room is refused typed before finalization", close.status === 200 && closedAdmit.status === 400 && closedAdmit.j.error?.code === "room_participation_room_not_open", `close=${close.status} admit=${closedAdmit.status}/${closedAdmit.j.error?.code}`);
    ok("CLOSED ADMIT: no false receipts, lease, or permanently stuck intent", JSON.stringify(decisionReceiptNames(dataDir)) === JSON.stringify(receiptNamesBeforeClosedAdmit) && famCount(dataDir, "room-participant-leases") === 0 && !closedRequest?.admit_intent && closedRequest?.status === "submitted", `receipts=${decisionReceiptNames(dataDir).length} leases=${famCount(dataDir, "room-participant-leases")}`);

    // Request intake uses the same room-scoped open check + room-first reservation. A closed
    // room cannot strand an internal submit intent or persist a submission receipt.
    const requestNamesBeforeClosedSubmit = famNames(dataDir, "room-participation-requests").sort();
    const allReceiptsBeforeClosedSubmit = famNames(dataDir, "room-participation-receipts").sort();
    const closedSubmit = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef, "worker://late-arrival"));
    ok("CLOSED SUBMIT: typed not-open with zero request/receipt/intent mutation", closedSubmit.status === 400 && closedSubmit.j.error?.code === "room_participation_room_not_open" && JSON.stringify(famNames(dataDir, "room-participation-requests").sort()) === JSON.stringify(requestNamesBeforeClosedSubmit) && JSON.stringify(famNames(dataDir, "room-participation-receipts").sort()) === JSON.stringify(allReceiptsBeforeClosedSubmit) && famCount(dataDir, "room-participation-submit-intents") === 0, `${closedSubmit.status}/${closedSubmit.j.error?.code}`);
  } finally {
    await plane.stop();
  }

  // Submission durability remains a live, ungated flow: visible-unconfirmed receipt → pending,
  // then one clean restart converges the same request and byte-identical evidence.
  const faultPlane = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "room-participation-receipts" } });
  if (faultPlane) {
    try {
      const fjd = async (method, path, body) => {
        const response = await fetch(`${faultPlane.daemonUrl}${path}`, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
        return { status: response.status, j: await response.json().catch(() => ({})) };
      };
      const faultRoom = (await fjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
      const faultRequest = VALID_REQUEST(faultRoom.outcome_room_id);
      const faultSubmit = await fjd("POST", "/v1/hypervisor/room-participation-requests", faultRequest);
      const receiptBytes = famNames(faultPlane.dataDir, "room-participation-receipts").map((name) => [name, readFileSync(join(faultPlane.dataDir, "room-participation-receipts", name))]);
      ok("SUBMIT FAULT: receipt durability refusal retains one internal intent and no request", faultSubmit.status === 500 && faultSubmit.j.error?.code === "room_participation_submit_pending_convergence" && famCount(faultPlane.dataDir, "room-participation-submit-intents") === 1 && famCount(faultPlane.dataDir, "room-participation-requests") === 0, `${faultSubmit.status}/${faultSubmit.j.error?.code}`);
      const intentNamesBeforeDuplicate = famNames(faultPlane.dataDir, "room-participation-submit-intents").sort();
      const receiptNamesBeforeDuplicate = famNames(faultPlane.dataDir, "room-participation-receipts").sort();
      const faultRoomTail = String(faultRoom.outcome_room_id).replace("outcome-room://", "");
      const roomBeforeDuplicate = (await fjd("GET", `/v1/hypervisor/outcome-rooms/${faultRoomTail}`)).j.outcome_room;
      const duplicateFaultSubmit = await fjd("POST", "/v1/hypervisor/room-participation-requests", faultRequest);
      const roomAfterDuplicate = (await fjd("GET", `/v1/hypervisor/outcome-rooms/${faultRoomTail}`)).j.outcome_room;
      const duplicateCode = duplicateFaultSubmit.j.error?.code || "";
      ok("SUBMIT FAULT duplicate: identical retry is a typed duplicate with exactly one pending intent and no added evidence", duplicateFaultSubmit.status === 409 && duplicateCode === "room_participation_request_duplicate" && famCount(faultPlane.dataDir, "room-participation-submit-intents") === 1 && famCount(faultPlane.dataDir, "room-participation-requests") === 0 && JSON.stringify(famNames(faultPlane.dataDir, "room-participation-submit-intents").sort()) === JSON.stringify(intentNamesBeforeDuplicate) && JSON.stringify(famNames(faultPlane.dataDir, "room-participation-receipts").sort()) === JSON.stringify(receiptNamesBeforeDuplicate) && JSON.stringify(roomAfterDuplicate?.participation_request_refs || []) === JSON.stringify(roomBeforeDuplicate?.participation_request_refs || []), `${duplicateFaultSubmit.status}/${duplicateCode} intents=${famCount(faultPlane.dataDir, "room-participation-submit-intents")} receipts=${famCount(faultPlane.dataDir, "room-participation-receipts")}`);
      process.kill(faultPlane.daemonPid, "SIGKILL");
      const restarted = await startIsolatedPlane({ serve: false, dataDir: faultPlane.dataDir });
      const response = await fetch(`${restarted.daemonUrl}/v1/hypervisor/room-participation-requests`);
      const requests = (await response.json()).participation_requests || [];
      const identical = receiptBytes.every(([name, bytes]) => existsSync(join(faultPlane.dataDir, "room-participation-receipts", name)) && readFileSync(join(faultPlane.dataDir, "room-participation-receipts", name)).equals(bytes));
      ok("SUBMIT FAULT restart: one boot converges exactly one request, consumes intent, preserves receipt bytes", requests.length === 1 && requests[0].status === "submitted" && famCount(faultPlane.dataDir, "room-participation-submit-intents") === 0 && identical, `requests=${requests.length} identical=${identical}`);
      await restarted.stop();
    } finally {
      try { const { rmSync } = await import("node:fs"); rmSync(faultPlane.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("SUBMIT FAULT: isolated plane started", false, "daemon did not start");
  }

  const after = Object.fromEntries(FAMILIES.map((family) => [family, famCount(REAL_DATA_DIR, family)]));
  ok("ISOLATION: real daemon participation families are untouched", FAMILIES.every((family) => before[family] === after[family]), FAMILIES.map((family) => `${family}:${before[family]}→${after[family]}`).join(" "));
  const passed = results.filter((result) => result.pass).length;
  for (const result of results) console.log(`  ${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? `  (${result.detail})` : ""}`);
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) process.exit(1);
  console.log("room-participation plane held-bar: PASS (governed decisions remain typed-unavailable)");
}

run().catch((error) => { console.error("VERIFIER CRASH:", error); process.exit(1); });
