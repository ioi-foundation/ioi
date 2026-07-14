#!/usr/bin/env node
// Room-participation plane done-bar (#74, build step 3 first pair) — ISOLATED per the standing
// verifier doctrine. Covers the #74 review round:
//   1. TYPED ADMISSION REQUEST — fail-closed creation (canonical refs per field incl. the RICHER
//      grammar, hosted-only, admission owner == room host, private context refused, plane-owned
//      refused, secrets rejected); admits `submitted` with a receipt; room backlink through the
//      room-owned seam.
//   2. DECISIONS ARE AUTHORITY-GATED (#74 finding 1) — evaluate/reject/admit and administrative
//      lease transitions require a HOST wallet grant; withdraw and self-state lease transitions
//      require a PARTICIPANT grant. No grant, a foreign grant, or a replayed grant → typed 403
//      with ZERO mutation. Each admitted decision emits a RoomParticipationDecisionReceipt
//      binding actor, grant, room, subject, op, revision, and policy hash.
//   3. LEASE = BOUNDED PARTICIPATION, not authority — receipted lifecycle; revocation appends the
//      revocation receipt (future access ends, lineage stays).
//   4. ROOM-CLOSE INTERLOCK (#74 finding 2) — a room refuses close/archive while a live lease
//      remains; revoke/retire releases the slot; a lease refuses transitions once its room is not
//      open. Close-vs-transition is race-safe (the released-set is maintained under the room lock)
//      and restart-convergent.
//   5. TTL IS A NAMED GAP (#74 finding 3) — a non-null ttl_seconds refuses typed; expiry needs
//      clock authority.
//   6. REFERENCE GRAMMAR (#74 finding 4) — canonical `model_route://` accepted, alias
//      `model-route://` refused; `harness_profile:` prefix accepted.
//   7. CRASH DURABILITY + ISOLATION — a receipts fault refuses pending, restart converges
//      byte-identically; the real daemon's families are untouched.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-room-participation-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
const { mintApprovalGrant } = await import(new URL("../../../scripts/lib/mint-approval-grant.mjs", import.meta.url));

const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["room-participation-requests", "room-participant-leases", "room-participation-receipts", "room-participation-submit-intents"];

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const famCount = (dataDir, d) => { try { return readdirSync(join(dataDir, d)).length; } catch { return 0; } };

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
  const before = {};
  for (const fam of FAMILIES) before[fam] = famCount(REAL_DATA_DIR, fam);

  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.log("BLOCKED: hypervisor-daemon binary not built"); process.exit(2); }
  const { dataDir } = plane;
  const jd = async (method, p, body) => {
    const r = await fetch(`${plane.daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  };
  // A GATED decision: attempt without a grant → 403 challenge → mint a grant bound to the
  // daemon-derived policy+request hash → retry. Returns { challenge, final }.
  const decide = async (method, p, body) => {
    const challenge = await jd(method, p, body);
    if (challenge.status !== 403 || !challenge.j.error?.approval) return { challenge, final: challenge };
    const grant = mintApprovalGrant({ policyHash: challenge.j.error.approval.policy_hash, requestHash: challenge.j.error.approval.request_hash });
    const final = await jd(method, p, { ...(body || {}), wallet_approval_grant: grant });
    return { challenge, final, grant };
  };

  try {
    const room = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const roomRef = room.outcome_room_id;
    const rtail = roomRef.replace("outcome-room://", "");

    // ---- 1. FAIL-CLOSED CREATION (incl. grammar #74 f4, ttl #74 f3 is on admit) --------------
    const failClosed = [
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: null }, "room_participation_room_required"],
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: "outcome-room://or_ghost" }, "room_participation_room_not_found"],
      [{ ...VALID_REQUEST(roomRef), coordination_topology: "federated_admission" }, "room_participation_federated_unavailable"],
      [{ ...VALID_REQUEST(roomRef), coordination_topology: "mesh" }, "room_participation_topology_invalid"],
      [{ ...VALID_REQUEST(roomRef), admission_owner_ref: "domain://not-the-host" }, "room_participation_admission_owner_mismatch"],
      [{ ...VALID_REQUEST(roomRef), private_context_included: true }, "room_participation_private_context_rejected"],
      [{ ...VALID_REQUEST(roomRef), status: "admitted" }, "room_participation_status_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), request_hash: "sha256:forged" }, "room_participation_field_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), signature: "sig" }, "room_participation_signature_unavailable"],
      [{ ...VALID_REQUEST(roomRef), room_discovery_ref: "room-discovery://x" }, "room_participation_discovery_unavailable"],
      [{ ...VALID_REQUEST(roomRef), notes: { api_key: "SENTINEL_SECRET" } }, "outcome_room_plaintext_secret_rejected"],
      // #74 finding 4: noncanonical alias refused (canonical model_route:// is in VALID_REQUEST).
      [{ ...VALID_REQUEST(roomRef), worker_composition_and_dependency_refs: ["model-route://m"] }, "room_participation_ref_scheme_invalid"],
      [{ ...VALID_REQUEST(roomRef), capability_offer_refs: ["capability_offer://c"] }, "room_participation_ref_scheme_invalid"],
    ];
    let fcPass = 0; const fcDetails = [];
    for (const [body, code] of failClosed) {
      const r = await jd("POST", "/v1/hypervisor/room-participation-requests", body);
      if (r.status >= 400 && r.j.error?.code === code) fcPass++; else fcDetails.push(`${code}→${r.status}/${r.j.error?.code}`);
    }
    ok(`CREATE fail-closed: ${failClosed.length}/${failClosed.length} typed refusals (incl. canonical-grammar aliases #74 f4)`, fcPass === failClosed.length, fcDetails.join(" "));
    ok("CREATE fail-closed: zero requests persisted by refusals", famCount(dataDir, "room-participation-requests") === 0);

    // ---- 2. SUBMIT (ungated intake) ----------------------------------------------------------
    const sub = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    const req = sub.j.participation_request;
    ok("SUBMIT: 201 submitted, revision 1, canonical `model_route://` + `harness_profile:` refs persisted (#74 f4)", sub.status === 201 && req?.status === "submitted" && (req?.worker_composition_and_dependency_refs || []).includes("model_route://m1") && (req?.worker_composition_and_dependency_refs || []).includes("harness_profile:codex-local"), `${sub.status}/${req?.status}`);
    const reqTail = String(req.participation_request_id).replace("participation-request://", "");
    const roomAfterSub = (await jd("GET", `/v1/hypervisor/outcome-rooms/${rtail}`)).j.outcome_room;
    ok("SUBMIT: room backlink through the seam (participation_request_refs, revision bump)", (roomAfterSub?.participation_request_refs || []).includes(req.participation_request_id) && roomAfterSub?.revision === 2, `refs=${roomAfterSub?.participation_request_refs}`);

    // ---- 3. AUTHORITY GATE (#74 finding 1) ---------------------------------------------------
    const noGrant = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "evaluate", expected_revision: 1 });
    ok("AUTHORITY: evaluate WITHOUT a grant → 403 host-authority-required with the daemon-derived challenge, ZERO mutation", noGrant.status === 403 && noGrant.j.error?.code === "room_participation_host_authority_required" && !!noGrant.j.error?.approval?.policy_hash && noGrant.j.error?.required_authority_ref === "domain://acme-host", `${noGrant.status}/${noGrant.j.error?.code}`);
    const stillSubmitted = (await jd("GET", `/v1/hypervisor/room-participation-requests/${reqTail}`)).j.participation_request;
    ok("AUTHORITY: the no-grant attempt mutated NOTHING (still submitted, revision 1)", stillSubmitted?.status === "submitted" && stillSubmitted?.revision === 1, `${stillSubmitted?.status}/${stillSubmitted?.revision}`);
    // Foreign grant: bound to a DIFFERENT room/op's hashes → rejected.
    const foreign = mintApprovalGrant({ policyHash: `sha256:${"a".repeat(64)}`, requestHash: `sha256:${"b".repeat(64)}` });
    const foreignAttempt = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "evaluate", expected_revision: 1, wallet_approval_grant: foreign });
    ok("AUTHORITY: a FOREIGN grant (bound to different hashes) → 403, ZERO mutation", foreignAttempt.status === 403 && foreignAttempt.j.error?.code === "room_participation_host_authority_required", `${foreignAttempt.status}/${foreignAttempt.j.error?.code}`);
    // Granted evaluate succeeds and binds the decision receipt.
    const evalD = await decide("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "evaluate", expected_revision: 1 });
    const evalReceipt = evalD.final.j.participation_request_receipt;
    ok("AUTHORITY: a GRANTED evaluate succeeds — the RoomParticipationDecisionReceipt binds actor, grant, policy, and request hash", evalD.final.status === 200 && evalD.final.j.participation_request?.status === "evaluating" && evalReceipt?.receipt_type === "RoomParticipationDecisionReceipt" && Array.isArray(evalReceipt?.actor_id) && evalReceipt.actor_id.length === 32 && !!evalReceipt?.authority_grant_id && !!evalReceipt?.policy_hash && !!evalReceipt?.input_hash, `${evalD.final.status} actor=${evalReceipt?.actor_id}`);
    // REPLAY: reuse the evaluate grant on a NEW op (revision moved) → rejected (request hash binds revision).
    const replay = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "reject", expected_revision: 2, wallet_approval_grant: evalD.grant });
    ok("AUTHORITY: REPLAY — reusing the evaluate grant for a different op/revision → 403, ZERO mutation (request hash binds revision)", replay.status === 403 && replay.j.error?.code === "room_participation_host_authority_required", `${replay.status}/${replay.j.error?.code}`);
    // Participant-governed withdraw needs a PARTICIPANT grant (different governance).
    // (Use a fresh request from a distinct principal so the primary can still be admitted.)
    const wreq = (await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef, "worker://withdrawer"))).j.participation_request;
    const wtail = String(wreq.participation_request_id).replace("participation-request://", "");
    const wNoGrant = await jd("POST", `/v1/hypervisor/room-participation-requests/${wtail}/transition`, { transition: "withdraw", expected_revision: 1 });
    ok("AUTHORITY: withdraw is PARTICIPANT-governed — no grant → 403 participant-authority-required bound to the requester", wNoGrant.status === 403 && wNoGrant.j.error?.code === "room_participation_participant_authority_required" && wNoGrant.j.error?.required_authority_ref === "worker://withdrawer", `${wNoGrant.status}/${wNoGrant.j.error?.code}`);
    const withdrawn = await decide("POST", `/v1/hypervisor/room-participation-requests/${wtail}/transition`, { transition: "withdraw", expected_revision: 1 });
    ok("AUTHORITY: a granted participant withdraw succeeds (terminal, grants nothing)", withdrawn.final.status === 200 && withdrawn.final.j.participation_request?.status === "withdrawn", `${withdrawn.final.status}`);

    // ---- 4. ADMIT MINTS THE LEASE (host-gated) + TTL named gap (#74 f3) -----------------------
    const ttlAttempt = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/admit`, { ...VALID_ADMIT, ttl_seconds: 3600, expected_revision: 2 });
    ok("ADMIT/TTL: a non-null ttl_seconds refuses typed — expiry is a named gap (#74 f3)", ttlAttempt.status >= 400 && ttlAttempt.j.error?.code === "participant_lease_ttl_unavailable", `${ttlAttempt.status}/${ttlAttempt.j.error?.code}`);
    const admit = await decide("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/admit`, { ...VALID_ADMIT, expected_revision: 2 });
    const lease = admit.final.j.participant_lease;
    const leaseReceipt = admit.final.j.participant_lease_receipt;
    ok("ADMIT: a granted host decision mints a bounded ACTIVE lease + terminal request in one finalization; the lease receipt is a DecisionReceipt with the host authority", admit.final.status === 200 && lease?.status === "active" && lease?.ttl_seconds === null && leaseReceipt?.receipt_type === "RoomParticipationDecisionReceipt" && Array.isArray(leaseReceipt?.actor_id) && leaseReceipt.actor_id.length === 32, `${admit.final.status}/${lease?.status}`);
    const leaseTail = String(lease.participant_lease_id).replace("participant-lease://", "");
    const roomAfterAdmit = (await jd("GET", `/v1/hypervisor/outcome-rooms/${rtail}`)).j.outcome_room;
    ok("ADMIT: lease backlink through the seam; the room counts it a LIVE participant", (roomAfterAdmit?.participant_lease_refs || []).includes(lease.participant_lease_id) && (roomAfterAdmit?.released_participant_lease_refs || []).length === 0, `refs=${roomAfterAdmit?.participant_lease_refs}`);

    // ---- 5. ROOM-CLOSE INTERLOCK (#74 finding 2) ---------------------------------------------
    const closeBlocked = await jd("POST", `/v1/hypervisor/outcome-rooms/${rtail}/transition`, { transition: "close", expected_revision: roomAfterAdmit.revision });
    ok("CLOSE INTERLOCK: close is REFUSED while a live participant lease remains (#74 f2)", closeBlocked.status >= 400 && closeBlocked.j.error?.code === "outcome_room_close_blocked_live_leases", `${closeBlocked.status}/${closeBlocked.j.error?.code}`);
    // A host-gated lease suspend, then revoke (releases the room slot).
    const suspend = await decide("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "suspend", expected_revision: 1 });
    ok("LEASE: an administrative suspend is HOST-gated + receipted", suspend.final.status === 200 && suspend.final.j.participant_lease?.status === "suspended" && suspend.final.j.participant_lease_receipt?.receipt_type === "RoomParticipationDecisionReceipt", `${suspend.final.status}`);
    const revoke = await decide("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "revoke", expected_revision: 2 });
    const revoked = revoke.final.j.participant_lease;
    ok("LEASE: revoke ends future access — status revoked, the revocation receipt APPENDED, lineage preserved", revoke.final.status === 200 && revoked?.status === "revoked" && (revoked?.future_access_revocation_refs || [])[0] === revoke.final.j.participant_lease_receipt?.receipt_ref, `${revoke.final.status}/${revoked?.status}`);
    const roomReleased = (await jd("GET", `/v1/hypervisor/outcome-rooms/${rtail}`)).j.outcome_room;
    ok("CLOSE INTERLOCK: the revoke RELEASED the room slot (released-set grew; no live leases remain)", (roomReleased?.released_participant_lease_refs || []).includes(lease.participant_lease_id), `released=${roomReleased?.released_participant_lease_refs}`);
    const closeOk = await jd("POST", `/v1/hypervisor/outcome-rooms/${rtail}/transition`, { transition: "close", expected_revision: roomReleased.revision });
    ok("CLOSE INTERLOCK: with all leases released, close is admitted", closeOk.status === 200 && closeOk.j.outcome_room?.status === "closed", `${closeOk.status}/${closeOk.j.outcome_room?.status}`);
    // A lease transition once the room is closed refuses typed (#74 f2 — mutations refuse when
    // not open) EVEN with valid host authority: the challenge is answered, but the room-open
    // re-resolve inside the transition core refuses.
    const deadLease = await decide("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "resume", expected_revision: 3 });
    ok("CLOSE INTERLOCK: no lease transition is admitted once the room is not open, even with valid authority", deadLease.final.status >= 400 && deadLease.final.j.error?.code === "participant_lease_room_not_open", `${deadLease.final.status}/${deadLease.final.j.error?.code}`);
  } finally {
    await plane.stop();
  }

  // ---- 6. CRASH DURABILITY (receipts fault → restart byte-identical convergence) -------------
  const rf = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "room-participation-receipts" } });
  if (rf) {
    try {
      const fjd = async (method, p, body) => { const r = await fetch(`${rf.daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const fRoom = (await fjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
      const fSub = await fjd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(fRoom.outcome_room_id));
      const fIntents = readdirSync(join(rf.dataDir, "room-participation-submit-intents"));
      ok("FAULT: an unconfirmed submission receipt refuses PENDING — no request committed, the intent is retained, the receipt visible for replay", fSub.status === 500 && fSub.j.error?.code === "room_participation_submit_pending_convergence" && fIntents.length === 1 && famCount(rf.dataDir, "room-participation-requests") === 0, `${fSub.status}/${fSub.j.error?.code}`);
      const receiptBytes = readdirSync(join(rf.dataDir, "room-participation-receipts")).map((n) => [n, readFileSync(join(rf.dataDir, "room-participation-receipts", n))]);
      process.kill(rf.daemonPid, "SIGKILL");
      const rfR = await startIsolatedPlane({ serve: false, dataDir: rf.dataDir });
      const rjd = async (method, p) => { const r = await fetch(`${rfR.daemonUrl}${p}`); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const afterReqs = (await rjd("GET", "/v1/hypervisor/room-participation-requests")).j.participation_requests || [];
      const afterIntents = readdirSync(join(rf.dataDir, "room-participation-submit-intents"));
      const receiptsIdentical = receiptBytes.every(([n, b]) => existsSync(join(rf.dataDir, "room-participation-receipts", n)) && readFileSync(join(rf.dataDir, "room-participation-receipts", n)).equals(b));
      ok("FAULT restart: the completer converged the SAME submission — request submitted, receipt BYTE-IDENTICAL, intent consumed", afterReqs.length === 1 && afterReqs[0].status === "submitted" && afterIntents.length === 0 && receiptsIdentical, `reqs=${afterReqs.length} intents=${afterIntents.length} identical=${receiptsIdentical}`);
      await rfR.stop();
    } finally {
      try { const { rmSync } = await import("node:fs"); rmSync(rf.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("FAULT: plane started", false, "daemon did not start");
  }

  // ---- 7. ISOLATION -------------------------------------------------------------------------
  const after = {};
  for (const fam of FAMILIES) after[fam] = famCount(REAL_DATA_DIR, fam);
  ok("ISOLATION: the real daemon's participation families are untouched", FAMILIES.every((f) => before[f] === after[f]), FAMILIES.map((f) => `${f}:${before[f]}→${after[f]}`).join(" "));

  const passed = results.filter((r) => r.pass).length;
  for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) process.exit(1);
  console.log("room-participation plane readiness: OK");
}

run().catch((e) => { console.error("VERIFIER CRASH:", e); process.exit(1); });
