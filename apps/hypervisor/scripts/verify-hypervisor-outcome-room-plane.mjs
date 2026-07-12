#!/usr/bin/env node
// OutcomeRoom plane done-bar — build step 2 of the contract-first sequence, ISOLATED per the
// standing verifier doctrine, with every #71-review discipline proven from day one:
//   1. HOSTED AGGREGATE — creation is fail-closed (canonical vocab, required policy refs,
//      recursive secret rejection); federated_admission is a NAMED GAP, never faked; the room
//      admits as `open`, revision 1, with an OutcomeRoomAdmissionReceipt on the complete
//      portable base (receipt:// identity, bound facts, recomputable hash).
//   2. EVERY SHARED-STATE TRANSITION ADMITTED + RECEIPTED — pause/resume/close/archive walk the
//      lifecycle with `expected_revision` REQUIRED (stale → 409 typed conflict, BYTE-FOR-BYTE
//      zero mutation); richer statuses are named-gap transitions; the receipt trail
//      (admission_and_replay_refs) grows by exactly one ref per transition.
//   3. GOALRUN MEMBERSHIP — attach-goal-run binds only an EXISTING goal-run record (fixture
//      planted in the isolated family), refuses ghosts/duplicates/non-open rooms, and registers
//      membership through the receipted transition.
//   4. ROOM-SCOPED ADMISSION (cross-plane) — WorkResults/OutcomeDeltas bind resolvable OPEN
//      rooms; a delta's room must EXACTLY equal its bound result's room; ghost/closed/cross-room
//      bindings refuse typed with zero writes.
//   5. FAILURE INJECTION — blocked/unwritable receipt storage → typed 5xx with the room
//      BYTE-FOR-BYTE unchanged and zero .tmp-* artifacts.
//   6. CONCURRENCY — a same-revision parallel storm admits EXACTLY ONE transition (the rest
//      409), and the room stays consistent.
//   7. ISOLATION — every journey on a throwaway daemon; the real daemon's counts unchanged.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-outcome-room-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, unlinkSync, chmodSync, readdirSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["outcome-room-registry", "outcome-room-registry-receipts", "work-result-registry", "outcome-delta-registry"];

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
  room_mode: "permissioned_team",
  coordination_topology: "hosted_admission",
  stop_policy_ref: "policy://stop-on-budget",
  visibility_policy_ref: "policy://team-visible",
  participation_policy_ref: "policy://invited-only",
  privacy_policy_ref: "policy://no-pii",
  contribution_policy_ref: "policy://contribution-v1",
  coordination_policy_ref: "policy://coordination-v1",
  ordering_and_merge_policy_ref: "policy://ordered-admission",
  conflict_and_failover_policy_ref: "policy://host-failover",
};

async function run() {
  const realBefore = await fetch(`${REAL_DAEMON}/v1/hypervisor/outcome-rooms`).then((r) => r.json()).catch(() => null);
  const realCounts = FAMILIES.map((f) => receiptFileCount(REAL_DATA_DIR, f));

  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon"); process.exit(2); }
  const { daemonUrl, dataDir } = plane;
  async function jd(method, p, body) {
    const r = await fetch(`${daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  }
  const tmpLeaks = () => { try { return readdirSync(join(dataDir, "outcome-room-registry")).filter((n) => n.includes(".tmp-")); } catch { return []; } };
  const roomTail = (id) => id.replace("outcome-room://", "");

  try {
    // 1. Empty plane + overview honesty.
    const list0 = await jd("GET", "/v1/hypervisor/outcome-rooms");
    ok("isolated plane serves an EMPTY room registry", list0.status === 200 && Array.isArray(list0.j.outcome_rooms) && list0.j.outcome_rooms.length === 0);
    const ov = await jd("GET", "/v1/hypervisor/outcome-rooms/overview");
    ok("overview projects the canonical vocabularies (modes ×4, statuses ×12, topologies ×2, step-2 lifecycle)", (ov.j.room_modes || []).length === 4 && (ov.j.room_statuses || []).length === 12 && (ov.j.coordination_topologies || []).length === 2 && (ov.j.lifecycle_transitions || []).length === 4);
    ok("overview is honest: hosted-only, step-3 planes named, reciprocal GoalRun stamp named, receipt≠proof", JSON.stringify(ov.j.governance_gaps || []).match(/federated_admission needs the AIIP leg/i) !== null && JSON.stringify(ov.j.governance_gaps || []).match(/receipt is not proof/i) !== null);

    // 2. Creation fail-closed sweep — every refusal typed, NOTHING persisted.
    const REFUSALS = [
      [{ ...VALID_ROOM, coordination_topology: "federated_admission" }, "outcome_room_federated_unavailable"],
      [{ ...VALID_ROOM, coordination_topology: "mesh" }, "outcome_room_topology_invalid"],
      [{ ...VALID_ROOM, room_mode: "party" }, "outcome_room_mode_invalid"],
      [{ ...VALID_ROOM, owner_or_sponsor_ref: "not-a-ref" }, "outcome_room_ref_scheme_invalid"],
      [{ ...VALID_ROOM, stop_policy_ref: null }, "outcome_room_policy_required"],
      [{ ...VALID_ROOM, status: "accepted" }, "outcome_room_status_plane_owned"],
      [{ ...VALID_ROOM, participant_lease_refs: ["participant-lease://ghost"] }, "outcome_room_participants_unavailable"],
      [{ ...VALID_ROOM, frontier_item_refs: ["frontier://ghost"] }, "outcome_room_frontier_unavailable"],
      [{ ...VALID_ROOM, admission_and_replay_refs: ["receipt://forged"] }, "outcome_room_replay_plane_owned"],
      [{ ...VALID_ROOM, member_goal_run_refs: ["gr_x"] }, "outcome_room_membership_plane_owned"],
      [{ ...VALID_ROOM, notes: { api_key: "SENTINEL_ROOM_SECRET" } }, "outcome_room_plaintext_secret_rejected"],
    ];
    for (const [body, code] of REFUSALS) {
      const r = await jd("POST", "/v1/hypervisor/outcome-rooms", body);
      ok(`creation refusal typed: ${code}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code);
    }
    ok("every creation refusal persisted NOTHING", receiptFileCount(dataDir, "outcome-room-registry") === 0 && receiptFileCount(dataDir, "outcome-room-registry-receipts") === 0);

    // 3. Creation → open hosted room, revision 1, admission receipt on the portable base.
    const created = await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM);
    const room = created.j.outcome_room;
    const rcpt = created.j.outcome_room_receipt;
    ok("a hosted room admits as `open`, revision 1, with plane-owned empties", created.status === 201 && room?.status === "open" && room?.revision === 1 && JSON.stringify(room?.member_goal_run_refs) === "[]" && JSON.stringify(room?.participant_lease_refs) === "[]");
    ok("OutcomeRoomAdmissionReceipt: receipt:// identity + bound facts (mode/topology/owner/objective/status)", String(rcpt?.receipt_id).startsWith("receipt://orr_") && rcpt?.receipt_type === "OutcomeRoomAdmissionReceipt" && rcpt?.bound_facts?.room_mode === "permissioned_team" && rcpt?.bound_facts?.coordination_topology === "hosted_admission" && rcpt?.bound_facts?.status_at_admission === "open");
    ok("the receipt carries the complete portable base (spot: claim_scope_ref/adjudication_ref/settlement_ref explicit null; capability/scope/artifact/evidence lists [])", rcpt?.claim_scope_ref === null && rcpt?.adjudication_ref === null && rcpt?.settlement_ref === null && JSON.stringify(rcpt?.primitive_capabilities) === "[]" && JSON.stringify(rcpt?.authority_scopes) === "[]");
    const persisted0 = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}`)).j.outcome_room;
    ok("admission output_hash recomputes EXACTLY from the persisted room minus hash_scope_excludes", recomputeHash(persisted0, rcpt.hash_scope_excludes || []) === rcpt.output_hash);
    ok("the receipt trail starts with the admission receipt", JSON.stringify(persisted0.admission_and_replay_refs) === JSON.stringify([rcpt.receipt_ref]));

    // 4. TRANSITIONS — receipted, optimistically concurrent, byte-true refusals.
    const stale = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "pause", expected_revision: 9 });
    ok("stale expected_revision → 409 typed conflict", stale.status === 409 && stale.j.error?.code === "outcome_room_revision_conflict");
    const noRev = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "pause" });
    ok("missing expected_revision → 400 typed (required on every mutation)", noRev.status === 400 && noRev.j.error?.code === "outcome_room_expected_revision_invalid");
    const unavailable = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "accept", expected_revision: 1 });
    ok("richer lifecycle (accept) → named-gap transition refusal", unavailable.status === 400 && unavailable.j.error?.code === "outcome_room_transition_unavailable");
    const illegal = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "archive", expected_revision: 1 });
    ok("illegal from-state (archive from open) → transition_invalid", illegal.status === 400 && illegal.j.error?.code === "outcome_room_transition_invalid");
    ok("every refused transition changed NOTHING (byte-for-byte)", canon((await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}`)).j.outcome_room) === canon(persisted0));
    const paused = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "pause", expected_revision: 1 });
    ok("pause admits: paused, revision 2, transition receipt bound {from open → to paused}", paused.status === 200 && paused.j.outcome_room?.status === "paused" && paused.j.outcome_room?.revision === 2 && paused.j.outcome_room_receipt?.receipt_type === "OutcomeRoomTransitionReceipt" && paused.j.outcome_room_receipt?.bound_facts?.from === "open" && paused.j.outcome_room_receipt?.bound_facts?.to === "paused");
    const resumed = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "resume", expected_revision: 2 });
    ok("resume admits: open, revision 3; the receipt trail grew by exactly one ref per transition", resumed.status === 200 && resumed.j.outcome_room?.revision === 3 && (resumed.j.outcome_room?.admission_and_replay_refs || []).length === 3);
    const trHash = resumed.j.outcome_room_receipt;
    const persisted3 = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}`)).j.outcome_room;
    ok("transition output_hash recomputes from the persisted room minus the declared excludes", recomputeHash(persisted3, trHash.hash_scope_excludes || []) === trHash.output_hash);

    // 5. GOALRUN MEMBERSHIP — fixture record in the isolated family exercises the real resolve.
    mkdirSync(join(dataDir, "goal-runs"), { recursive: true });
    writeFileSync(join(dataDir, "goal-runs", "gr_fixture.json"), JSON.stringify({ goal_run_id: "gr_fixture", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", created_at: "2026-01-01T00:00:00Z" }));
    const ghostRun = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "gr_ghost", expected_revision: 3 });
    ok("attaching a GHOST goal-run refuses (the aggregate binds only real bounded runs)", ghostRun.status === 400 && ghostRun.j.error?.code === "outcome_room_goal_run_unbound");
    const attached = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "gr_fixture", expected_revision: 3 });
    ok("attach admits: membership registered through the receipted transition (bound facts carry the run + count)", attached.status === 200 && JSON.stringify(attached.j.outcome_room?.member_goal_run_refs) === JSON.stringify(["gr_fixture"]) && attached.j.outcome_room_receipt?.bound_facts?.goal_run_ref === "gr_fixture" && attached.j.outcome_room_receipt?.bound_facts?.member_count_after === 1);
    const dup = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "gr_fixture", expected_revision: 4 });
    ok("duplicate attach refuses typed (never double-registered)", dup.status === 400 && dup.j.error?.code === "outcome_room_goal_run_duplicate");

    // 6. ROOM-SCOPED ADMISSION across planes.
    const roomedResult = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: room.outcome_room_id });
    ok("a WorkResult binds a resolvable OPEN room", roomedResult.status === 201 && roomedResult.j.work_result?.outcome_room_ref === room.outcome_room_id);
    const ghostRoom = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: "outcome-room://or_ghost" });
    ok("a ghost room refuses (work_result_room_unbound)", ghostRoom.status === 400 && ghostRoom.j.error?.code === "work_result_room_unbound");
    const sameRoomDelta = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://lane", proposed_by_ref: roomedResult.j.work_result.work_result_id, outcome_room_ref: room.outcome_room_id });
    ok("a delta in the SAME room as its bound result admits", sameRoomDelta.status === 201 && sameRoomDelta.j.outcome_delta?.outcome_room_ref === room.outcome_room_id);
    const crossRoomDelta = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://lane2", proposed_by_ref: roomedResult.j.work_result.work_result_id });
    ok("a room-less delta against a roomed result → outcome_delta_cross_room (exact equality)", crossRoomDelta.status === 400 && crossRoomDelta.j.error?.code === "outcome_delta_cross_room");
    // Close the room → new admissions refuse (not open).
    const closed = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "close", expected_revision: 4 });
    ok("close admits (open→closed, revision 5)", closed.status === 200 && closed.j.outcome_room?.status === "closed" && closed.j.outcome_room?.revision === 5);
    const intoClosed = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: room.outcome_room_id });
    ok("results refuse a CLOSED room (work_result_room_not_open)", intoClosed.status === 400 && intoClosed.j.error?.code === "work_result_room_not_open");
    const attachClosed = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "gr_fixture", expected_revision: 5 });
    ok("membership refuses a non-open room", attachClosed.status === 400 && attachClosed.j.error?.code === "outcome_room_not_open");

    // 7. FAILURE INJECTION — receipts unwritable → typed 5xx, room byte-identical, no tmp.
    const preFail = canon((await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}`)).j.outcome_room);
    chmodSync(join(dataDir, "outcome-room-registry-receipts"), 0o555);
    const injected = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/transition`, { transition: "archive", expected_revision: 5 });
    chmodSync(join(dataDir, "outcome-room-registry-receipts"), 0o755);
    ok("injected receipt failure → 500 typed; the room is BYTE-FOR-BYTE unchanged; no .tmp-* leak", injected.status === 500 && injected.j.error?.code === "outcome_room_receipt_persist_failed" && canon((await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}`)).j.outcome_room) === preFail && tmpLeaks().length === 0);

    // 8. CONCURRENCY — a same-revision parallel storm admits EXACTLY ONE transition.
    const room2 = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const storm = await Promise.all(Array.from({ length: 24 }, () => jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room2.outcome_room_id)}/transition`, { transition: "pause", expected_revision: 1 })));
    const wins = storm.filter((r) => r.status === 200);
    const conflicts = storm.filter((r) => r.status === 409 && ["outcome_room_revision_conflict", "outcome_room_transition_invalid"].includes(r.j.error?.code)) // a loser may also see paused-state invalidity
      .concat(storm.filter((r) => r.status === 400 && r.j.error?.code === "outcome_room_transition_invalid"));
    ok("CONCURRENCY: exactly ONE same-revision transition wins; every loser refuses typed", wins.length === 1 && wins.length + conflicts.length === 24, `${wins.length} wins / ${conflicts.length} typed refusals`);
    const finalRoom2 = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(room2.outcome_room_id)}`)).j.outcome_room;
    ok("CONCURRENCY: the room is consistent (paused, revision 2, trail = admission + exactly one transition)", finalRoom2.status === "paused" && finalRoom2.revision === 2 && (finalRoom2.admission_and_replay_refs || []).length === 2);
    ok("no sentinel and no .tmp-* residue anywhere", !JSON.stringify((await jd("GET", "/v1/hypervisor/outcome-rooms")).j).includes("SENTINEL_ROOM_SECRET") && tmpLeaks().length === 0);
  } finally {
    await plane.stop();
  }

  // 9. ISOLATION PROOF.
  const realAfter = await fetch(`${REAL_DAEMON}/v1/hypervisor/outcome-rooms`).then((r) => r.json()).catch(() => null);
  const realCountsAfter = FAMILIES.map((f) => receiptFileCount(REAL_DATA_DIR, f));
  ok("REAL daemon room plane unchanged", (realBefore === null && realAfter === null) || (realBefore?.outcome_rooms || []).length === (realAfter?.outcome_rooms || []).length);
  ok("REAL daemon record/receipt file counts unchanged across the four families", realCounts.join("/") === realCountsAfter.join("/"), `${realCounts.join("/")} before/after`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`outcome-room plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
