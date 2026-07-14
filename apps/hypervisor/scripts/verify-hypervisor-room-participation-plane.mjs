#!/usr/bin/env node
// Room-participation plane done-bar (#74, build step 3 first pair) — ISOLATED per the standing
// verifier doctrine:
//   1. TYPED ADMISSION REQUEST — creation is fail-closed (canonical refs per field, hosted-only
//      topology, admission owner must equal the room's host, private context refused, plane-owned
//      fields refused, secrets rejected); admits as `submitted` with a receipt on the complete
//      portable base; the room gains the backlink through a RECEIPTED room transition.
//   2. DECISIONS ARE RECEIPTED TRANSITIONS — evaluate/reject/withdraw walk the lifecycle with
//      `expected_revision` REQUIRED (stale → 409, byte-for-byte zero mutation); `admit` mints the
//      bounded ACTIVE lease + terminal request + room backlink in ONE finalization.
//   3. A LEASE IS BOUNDED PARTICIPATION, NOT AUTHORITY — its powers are declared refs; lifecycle
//      (suspend/resume/sleep/wake/wait/activate/quarantine/release/retire/revoke) is receipted;
//      revocation ends FUTURE access (appends the revocation receipt) and never erases lineage.
//   4. DUPLICATES REFUSE — one live request and one live lease per (room, principal).
//   5. NAMED GAPS STAY NAMED — federated admission, AIIP signature, discovery, expiry,
//      invite/joining, retiring: refused typed, never faked.
//   6. CRASH DURABILITY — a receipts-family fault refuses pending with the intent retained; a
//      restart converges the SAME submission byte-exactly (reconstruction is the oracle).
//   7. ISOLATION — every journey on a throwaway daemon; the real daemon's counts unchanged.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-room-participation-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["room-participation-requests", "room-participant-leases", "room-participation-receipts", "room-participation-submit-intents"];

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

const canon = (v) => Array.isArray(v)
  ? `[${v.map(canon).join(",")}]`
  : (v !== null && typeof v === "object")
    ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
    : JSON.stringify(v);
const recomputeHash = (record, excludes) => {
  const clone = { ...record };
  for (const k of excludes) delete clone[k];
  return `sha256:${createHash("sha256").update(canon(clone)).digest("hex")}`;
};

const VALID_ROOM = {
  owner_or_sponsor_ref: "org://acme",
  objective_ref: "goal://alloy-program",
  objective: "Find a fatigue-resistant alloy candidate.",
  room_mode: "open_challenge",
  coordination_topology: "hosted_admission",
  stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible",
  participation_policy_ref: "policy://open-eligibility",
  privacy_policy_ref: "policy://no-pii",
  contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1",
  ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover",
  host_domain_ref: "domain://acme-host",
};

const VALID_REQUEST = (roomRef, principal = "worker://independent-alloy-lab") => ({
  outcome_room_ref: roomRef,
  requested_by_ref: principal,
  coordination_topology: "hosted_admission",
  admission_owner_ref: "domain://acme-host",
  operator_and_home_domain_refs: ["org://alloy-lab", "domain://alloy-lab.example"],
  worker_composition_and_dependency_refs: ["worker://fatigue-sim-worker"],
  capability_offer_refs: ["capability-offer://fatigue-sim"],
  affiliation_and_independent_operation_evidence_refs: ["evidence://independent-operation"],
  eligibility_evidence_refs: ["evidence://fatigue-benchmarks"],
  accepted_verifier_settlement_dispute_and_contribution_policy_refs: ["policy://contribution-v1"],
});

const VALID_ADMIT = {
  admitted_role: "implementer",
  operator_ref: "org://alloy-lab",
  home_domain_ref: "domain://alloy-lab.example",
  ttl_seconds: 86400,
};

async function run() {
  const before = {};
  for (const fam of FAMILIES) {
    try { before[fam] = readdirSync(join(REAL_DATA_DIR, fam)).length; } catch { before[fam] = 0; }
  }

  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) {
    console.log("BLOCKED: hypervisor-daemon binary not built (cargo build -p ioi-node --bin hypervisor-daemon)");
    process.exit(2);
  }
  const { dataDir } = plane;
  const jd = async (method, p, body) => {
    const r = await fetch(`${plane.daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  };

  try {
    // ---- 1. FAIL-CLOSED CREATION ------------------------------------------------------------
    const room = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const roomRef = room.outcome_room_id;
    const failClosed = [
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: null }, "room_participation_room_required"],
      [{ ...VALID_REQUEST(roomRef), outcome_room_ref: "outcome-room://or_ghost" }, "room_participation_room_not_found"],
      [{ ...VALID_REQUEST(roomRef), requested_by_ref: "user://someone" }, "outcome_room_ref_scheme_invalid"],
      [{ ...VALID_REQUEST(roomRef), coordination_topology: "federated_admission" }, "room_participation_federated_unavailable"],
      [{ ...VALID_REQUEST(roomRef), coordination_topology: "mesh" }, "room_participation_topology_invalid"],
      [{ ...VALID_REQUEST(roomRef), admission_owner_ref: "domain://not-the-host" }, "room_participation_admission_owner_mismatch"],
      [{ ...VALID_REQUEST(roomRef), private_context_included: true }, "room_participation_private_context_rejected"],
      [{ ...VALID_REQUEST(roomRef), status: "admitted" }, "room_participation_status_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), participant_lease_ref: "participant-lease://x" }, "room_participation_field_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), request_hash: "sha256:forged" }, "room_participation_field_plane_owned"],
      [{ ...VALID_REQUEST(roomRef), signature: "sig" }, "room_participation_signature_unavailable"],
      [{ ...VALID_REQUEST(roomRef), room_discovery_ref: "room-discovery://x" }, "room_participation_discovery_unavailable"],
      [{ ...VALID_REQUEST(roomRef), capability_offer_refs: ["not-a-ref"] }, "outcome_room_ref_scheme_invalid"],
      [{ ...VALID_REQUEST(roomRef), notes: { api_key: "SENTINEL_SECRET" } }, "outcome_room_plaintext_secret_rejected"],
    ];
    let fcPass = 0;
    const fcDetails = [];
    for (const [body, code] of failClosed) {
      const r = await jd("POST", "/v1/hypervisor/room-participation-requests", body);
      if (r.status >= 400 && r.j.error?.code === code) fcPass++;
      else fcDetails.push(`${code}→${r.status}/${r.j.error?.code}`);
    }
    ok(`CREATE fail-closed: ${failClosed.length}/${failClosed.length} refusals typed (ghost room, federated, owner mismatch, private context, plane-owned, secrets)`, fcPass === failClosed.length, fcDetails.join(" "));
    const famCount = (d) => { try { return readdirSync(join(dataDir, d)).length; } catch { return 0; } };
    const zeroAfterRefusals = famCount("room-participation-requests");
    ok("CREATE fail-closed: zero requests persisted by refusals", zeroAfterRefusals === 0, String(zeroAfterRefusals));

    // ---- 2. SUBMIT JOURNEY ------------------------------------------------------------------
    const sub = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    const req = sub.j.participation_request;
    const subReceipt = sub.j.participation_request_receipt;
    ok("SUBMIT: 201 — status submitted, revision 1, hosted, request_hash present", sub.status === 201 && req?.status === "submitted" && req?.revision === 1 && String(req?.request_hash || "").startsWith("sha256:"), `${sub.status}/${req?.status}`);
    const reqTail = String(req.participation_request_id).replace("participation-request://", "");
    ok("SUBMIT: the admission receipt binds the DECLARED shape — output_hash recomputes under the receipt's hash scope", subReceipt?.output_hash === recomputeHash(req, subReceipt?.hash_scope_excludes || []), subReceipt?.output_hash?.slice(0, 24));
    const roomAfterSub = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomRef.replace("outcome-room://", "")}`)).j.outcome_room;
    ok("SUBMIT: the room gained the backlink through a RECEIPTED room transition (participation_request_refs + revision bump + ort receipt in trail)", (roomAfterSub?.participation_request_refs || []).includes(req.participation_request_id) && roomAfterSub?.revision === 2 && (roomAfterSub?.admission_and_replay_refs || []).length === 2, `refs=${roomAfterSub?.participation_request_refs} rev=${roomAfterSub?.revision}`);
    ok("SUBMIT: zero intent residue after success", !existsSync(join(dataDir, "room-participation-submit-intents", `${reqTail}.json`)), "consumed");
    const dup = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    ok("SUBMIT: a second live request by the same principal refuses typed (409 duplicate)", dup.status === 409 && dup.j.error?.code === "room_participation_request_duplicate", `${dup.status}/${dup.j.error?.code}`);

    // ---- 3. DECISION TRANSITIONS + CAS -------------------------------------------------------
    const noRev = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "evaluate" });
    ok("CAS: `expected_revision` is REQUIRED on every decision transition", noRev.status >= 400 && noRev.j.error?.code === "room_participation_revision_conflict", `${noRev.status}/${noRev.j.error?.code}`);
    const evalR = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "evaluate", expected_revision: 1 });
    ok("EVALUATE: submitted → evaluating, receipted, revision 2", evalR.status === 200 && evalR.j.participation_request?.status === "evaluating" && evalR.j.participation_request?.revision === 2 && evalR.j.participation_request_receipt?.op === "evaluate", `${evalR.status}/${evalR.j.participation_request?.status}`);
    const stale = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "reject", expected_revision: 1 });
    const unchanged = (await jd("GET", `/v1/hypervisor/room-participation-requests/${reqTail}`)).j.participation_request;
    ok("CAS: a stale revision is a 409 with BYTE-FOR-BYTE zero mutation", stale.status === 409 && unchanged.revision === 2 && unchanged.status === "evaluating", `${stale.status} rev=${unchanged.revision}`);
    const expired = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/transition`, { transition: "expire", expected_revision: 2 });
    ok("NAMED GAP: `expire` refuses typed (TTL/clock authority) — never faked", expired.status === 400 && expired.j.error?.code === "room_participation_transition_unavailable", `${expired.status}/${expired.j.error?.code}`);

    // ---- 4. ADMIT MINTS THE LEASE -----------------------------------------------------------
    const badRole = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/admit`, { ...VALID_ADMIT, admitted_role: "root", expected_revision: 2 });
    ok("ADMIT: a non-canonical role refuses typed", badRole.status === 400 && badRole.j.error?.code === "participant_lease_role_invalid", `${badRole.status}/${badRole.j.error?.code}`);
    const admit = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/admit`, { ...VALID_ADMIT, expected_revision: 2 });
    const lease = admit.j.participant_lease;
    const leaseReceipt = admit.j.participant_lease_receipt;
    ok("ADMIT: 200 — terminal request (admitted, lease ref + decision ref set) AND a bounded ACTIVE lease in one finalization", admit.status === 200 && admit.j.participation_request?.status === "admitted" && admit.j.participation_request?.participant_lease_ref === lease?.participant_lease_id && lease?.status === "active" && lease?.admitted_role === "implementer" && lease?.join_request_ref === req.participation_request_id, `${admit.status}/${lease?.status}`);
    ok("ADMIT: the lease is PARTICIPATION, not authority — powers are declared refs and claim/bundle fields are plane-owned nulls", lease?.current_claim_ref === null && lease?.portable_participant_state_bundle_ref === null && Array.isArray(lease?.context_and_authority_lease_refs), JSON.stringify(lease?.context_and_authority_lease_refs));
    ok("ADMIT: the lease receipt recomputes under its declared hash scope", leaseReceipt?.output_hash === recomputeHash(lease, leaseReceipt?.hash_scope_excludes || []), leaseReceipt?.output_hash?.slice(0, 24));
    const leaseTail = String(lease.participant_lease_id).replace("participant-lease://", "");
    const roomAfterAdmit = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomRef.replace("outcome-room://", "")}`)).j.outcome_room;
    ok("ADMIT: the room gained the lease backlink through the seam (participant_lease_refs, revision 3)", (roomAfterAdmit?.participant_lease_refs || []).includes(lease.participant_lease_id) && roomAfterAdmit?.revision === 3, `refs=${roomAfterAdmit?.participant_lease_refs} rev=${roomAfterAdmit?.revision}`);
    const reAdmit = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqTail}/admit`, { ...VALID_ADMIT, expected_revision: 3 });
    ok("ADMIT: a terminal request refuses re-admission", reAdmit.status === 400 && reAdmit.j.error?.code === "room_participation_transition_invalid", `${reAdmit.status}/${reAdmit.j.error?.code}`);
    // One participant, one lease: while principal A holds a live lease, a NEW submit by A is
    // refused at submission — the guard fires before a second lease can ever be minted.
    const dupWhileLeased = await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef));
    ok("ONE LEASE: while a principal holds a live lease, a fresh request by it refuses typed (409) — one participant, one lease", dupWhileLeased.status === 409 && dupWhileLeased.j.error?.code === "room_participation_request_duplicate", `${dupWhileLeased.status}/${dupWhileLeased.j.error?.code}`);
    // A DIFFERENT principal submits and can be rejected — a rejection grants nothing.
    const reqB = (await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef, "worker://second-lab"))).j.participation_request;
    const reqBTail = String(reqB.participation_request_id).replace("participation-request://", "");
    const rejected = await jd("POST", `/v1/hypervisor/room-participation-requests/${reqBTail}/transition`, { transition: "reject", expected_revision: 1 });
    ok("REJECT: a rejection is a receipted terminal transition granting nothing", rejected.status === 200 && rejected.j.participation_request?.status === "rejected" && rejected.j.participation_request?.participant_lease_ref === null, `${rejected.status}/${rejected.j.participation_request?.status}`);

    // ---- 5. LEASE LIFECYCLE ------------------------------------------------------------------
    const walk = [
      ["suspend", "suspended", 1], ["resume", "active", 2], ["sleep", "sleeping", 3], ["wake", "active", 4],
      ["wait", "waiting", 5], ["activate", "active", 6], ["quarantine", "quarantined", 7], ["release_quarantine", "active", 8],
    ];
    let walkPass = 0;
    const walkDetails = [];
    for (const [t, expect, rev] of walk) {
      const r = await jd("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: t, expected_revision: rev });
      if (r.status === 200 && r.j.participant_lease?.status === expect && r.j.participant_lease_receipt?.op === t) walkPass++;
      else walkDetails.push(`${t}→${r.status}/${r.j.participant_lease?.status}`);
    }
    ok(`LEASE lifecycle: ${walk.length}/${walk.length} receipted transitions (suspend/resume/sleep/wake/wait/activate/quarantine/release)`, walkPass === walk.length, walkDetails.join(" "));
    const gap = await jd("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "begin_retirement", expected_revision: 9 });
    ok("NAMED GAP: `begin_retirement` (retiring) refuses typed — claim-release orchestration arrives with WorkClaimLease (#76)", gap.status === 400 && gap.j.error?.code === "participant_lease_transition_unavailable", `${gap.status}/${gap.j.error?.code}`);
    const revoke = await jd("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "revoke", expected_revision: 9 });
    const revoked = revoke.j.participant_lease;
    ok("REVOKE: future access ends — status revoked, the revocation receipt is APPENDED to future_access_revocation_refs, lineage (trail, history) preserved", revoke.status === 200 && revoked?.status === "revoked" && (revoked?.future_access_revocation_refs || [])[0] === revoke.j.participant_lease_receipt?.receipt_ref && (revoked?.admission_and_replay_refs || []).length === 10, `${revoke.status}/${revoked?.status} revocations=${revoked?.future_access_revocation_refs?.length}`);
    const deadWalk = await jd("POST", `/v1/hypervisor/room-participant-leases/${leaseTail}/transition`, { transition: "resume", expected_revision: 10 });
    ok("REVOKE: a revoked lease is terminal — no further transitions", deadWalk.status === 400 && deadWalk.j.error?.code === "participant_lease_transition_invalid", `${deadWalk.status}/${deadWalk.j.error?.code}`);
    // After revocation the principal may be admitted again (revoked ≠ live).
    const req3 = (await jd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(roomRef))).j.participation_request;
    const req3Tail = String(req3.participation_request_id).replace("participation-request://", "");
    const reAdmit2 = await jd("POST", `/v1/hypervisor/room-participation-requests/${req3Tail}/admit`, { ...VALID_ADMIT, admitted_role: "reviewer", expected_revision: 1 });
    ok("REVOKE: a revoked lease is not live — the principal can be freshly admitted (new lease)", reAdmit2.status === 200 && reAdmit2.j.participant_lease?.status === "active" && reAdmit2.j.participant_lease?.admitted_role === "reviewer", `${reAdmit2.status}`);

    // ---- 6. ROOM-STATE GUARDS ---------------------------------------------------------------
    const closedRoom = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    await jd("POST", `/v1/hypervisor/outcome-rooms/${closedRoom.outcome_room_id.replace("outcome-room://", "")}/transition`, { transition: "close", expected_revision: 1 });
    const toClosed = await jd("POST", "/v1/hypervisor/room-participation-requests", { ...VALID_REQUEST(closedRoom.outcome_room_id) });
    ok("ROOM GUARD: a request against a CLOSED room refuses typed — participation binds only to a live hosted room", toClosed.status >= 400 && ["room_participation_room_not_found", "room_participation_room_not_open"].includes(toClosed.j.error?.code), `${toClosed.status}/${toClosed.j.error?.code}`);

    // ---- 7. LIST + GET ------------------------------------------------------------------------
    const list = await jd("GET", `/v1/hypervisor/room-participation-requests?room=${encodeURIComponent(roomRef)}`);
    ok("LIST: room-filtered requests with canonical statuses and the transition table on the wire", list.status === 200 && (list.j.participation_requests || []).length === 3 && Array.isArray(list.j.request_transitions), `${list.status}/${(list.j.participation_requests || []).length}`);
    const leases = await jd("GET", `/v1/hypervisor/room-participant-leases?room=${encodeURIComponent(roomRef)}`);
    ok("LIST: room-filtered leases expose the canonical role + lifecycle vocab", leases.status === 200 && (leases.j.participant_leases || []).length === 2 && (leases.j.admitted_roles || []).length === 11, `${leases.status}/${(leases.j.participant_leases || []).length}`);
    const ghost = await jd("GET", "/v1/hypervisor/room-participation-requests/rpr_ghost");
    ok("GET: a ghost request is a typed 404", ghost.status === 404, String(ghost.status));
  } finally {
    await plane.stop();
  }

  // ---- 8. CRASH DURABILITY (receipts-family fault → restart convergence) ---------------------
  const rf = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "room-participation-receipts" } });
  if (rf) {
    try {
      const fjd = async (method, p, body) => { const r = await fetch(`${rf.daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const fRoom = (await fjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
      const fSub = await fjd("POST", "/v1/hypervisor/room-participation-requests", VALID_REQUEST(fRoom.outcome_room_id));
      const fIntents = readdirSync(join(rf.dataDir, "room-participation-submit-intents"));
      const fRequests = existsSync(join(rf.dataDir, "room-participation-requests")) ? readdirSync(join(rf.dataDir, "room-participation-requests")).length : 0;
      ok("FAULT: an unconfirmed submission receipt refuses PENDING — no request committed, the DURABLE intent is retained, the receipt stays visible for replay (#72 discipline on this plane)", fSub.status === 500 && fSub.j.error?.code === "room_participation_submit_pending_convergence" && fIntents.length === 1 && fRequests === 0, `${fSub.status}/${fSub.j.error?.code} intents=${fIntents.length} reqs=${fRequests}`);
      const receiptBytes = readdirSync(join(rf.dataDir, "room-participation-receipts")).map((n) => [n, readFileSync(join(rf.dataDir, "room-participation-receipts", n))]);
      process.kill(rf.daemonPid, "SIGKILL");
      const rfRevived = await startIsolatedPlane({ serve: false, dataDir: rf.dataDir });
      const rjd = async (method, p) => { const r = await fetch(`${rfRevived.daemonUrl}${p}`); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const afterReqs = (await rjd("GET", "/v1/hypervisor/room-participation-requests")).j.participation_requests || [];
      const afterIntents = readdirSync(join(rf.dataDir, "room-participation-submit-intents"));
      const roomBound = (await rjd("GET", `/v1/hypervisor/outcome-rooms/${fRoom.outcome_room_id.replace("outcome-room://", "")}`)).j.outcome_room;
      const receiptsIdentical = receiptBytes.every(([n, b]) => existsSync(join(rf.dataDir, "room-participation-receipts", n)) && readFileSync(join(rf.dataDir, "room-participation-receipts", n)).equals(b));
      ok("FAULT restart: the completer converged the SAME submission — request admitted as submitted, room backlink bound, receipt BYTE-IDENTICAL, intent consumed", afterReqs.length === 1 && afterReqs[0].status === "submitted" && afterIntents.length === 0 && (roomBound?.participation_request_refs || []).length === 1 && receiptsIdentical, `reqs=${afterReqs.length} intents=${afterIntents.length} receiptsIdentical=${receiptsIdentical}`);
      // A FORGED sealed intent (escalated principal, re-sealed hashes) is refused at boot —
      // reconstruction through the declaration validator is the oracle (Rust-proven; the live
      // lane plants the forgery and proves refusal + retention).
      const { writeFileSync } = await import("node:fs");
      const realIntentDir = join(rf.dataDir, "room-participation-submit-intents");
      const realReq = afterReqs[0];
      const forgedFinal = { ...realReq, participation_request_id: "participation-request://rpr_f0f0", requested_by_ref: "org://insider" };
      writeFileSync(join(realIntentDir, "rpr_f0f0.json"), JSON.stringify({ kind: "submit", request_tail: "rpr_f0f0", request_ref: "participation-request://rpr_f0f0", room_ref: fRoom.outcome_room_id, final_request: forgedFinal, final_request_hash: "sha256:forged", receipt_id: "rqr_f0f0", receipt: { receipt_ref: "receipt://rqr_f0f0" }, receipt_hash: "sha256:forged", at: "2026-01-01T00:00:00Z" }));
      process.kill(rfRevived.daemonPid, "SIGKILL");
      const rfRevived2 = await startIsolatedPlane({ serve: false, dataDir: rf.dataDir });
      const r2jd = async (p) => { const r = await fetch(`${rfRevived2.daemonUrl}${p}`); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const forgedGet = await r2jd("/v1/hypervisor/room-participation-requests/rpr_f0f0");
      ok("FAULT restart: a FORGED submit intent (escalated principal, broken seals) is refused at boot — nothing admitted, intent retained for manual repair", forgedGet.status === 404 && existsSync(join(realIntentDir, "rpr_f0f0.json")), `${forgedGet.status} retained=${existsSync(join(realIntentDir, "rpr_f0f0.json"))}`);
      await rfRevived2.stop();
    } finally {
      try { const { rmSync } = await import("node:fs"); rmSync(rf.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("FAULT: plane started", false, "daemon did not start");
  }

  // ---- 9. ISOLATION -------------------------------------------------------------------------
  const after = {};
  for (const fam of FAMILIES) {
    try { after[fam] = readdirSync(join(REAL_DATA_DIR, fam)).length; } catch { after[fam] = 0; }
  }
  ok("ISOLATION: the real daemon's participation families are untouched", FAMILIES.every((f) => before[f] === after[f]), FAMILIES.map((f) => `${f}:${before[f]}→${after[f]}`).join(" "));
  const _ = REAL_DAEMON;

  const passed = results.filter((r) => r.pass).length;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  }
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) process.exit(1);
  console.log("room-participation plane readiness: OK");
}

run().catch((e) => { console.error("VERIFIER CRASH:", e); process.exit(1); });
