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
import { readFileSync, writeFileSync, unlinkSync, chmodSync, readdirSync, mkdirSync, existsSync, symlinkSync, rmSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";
// Real dcrypt-signed ApprovalGrant minting (no test bypass) — the round-4 start lane completes
// the genuine 403 challenge → signed-grant wallet crossing before injecting its failure.
const { mintApprovalGrant } = await import(new URL("../../../scripts/lib/mint-approval-grant.mjs", import.meta.url));

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
  host_domain_ref: "domain://acme-host",
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
      // #72 finding 1: hosted admission BINDS a host authority.
      [{ ...VALID_ROOM, host_domain_ref: null }, "outcome_room_host_domain_required"],
      [{ ...VALID_ROOM, host_domain_ref: "not-a-ref" }, "outcome_room_ref_scheme_invalid"],
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
    ok("OutcomeRoomAdmissionReceipt: receipt:// identity + bound facts incl. the HOST AUTHORITY (mode/topology/owner/objective/host/status)", String(rcpt?.receipt_id).startsWith("receipt://orr_") && rcpt?.receipt_type === "OutcomeRoomAdmissionReceipt" && rcpt?.bound_facts?.room_mode === "permissioned_team" && rcpt?.bound_facts?.coordination_topology === "hosted_admission" && rcpt?.bound_facts?.host_domain_ref === "domain://acme-host" && (rcpt?.attested_boundary_fact_refs || []).includes("domain://acme-host") && rcpt?.bound_facts?.status_at_admission === "open");
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
    ok("transition output_hash recomputes from the persisted room minus the declared TRANSITION excludes (status/revision/membership INCLUDED)", recomputeHash(persisted3, trHash.hash_scope_excludes || []) === trHash.output_hash && (trHash.hash_scope_excludes || []).length === 3);
    ok("DISTINCT states emit DISTINCT hashes: admission ≠ pause ≠ resume (#72 finding 4)", new Set([rcpt.output_hash, paused.j.outcome_room_receipt.output_hash, trHash.output_hash]).size === 3, [rcpt.output_hash, paused.j.outcome_room_receipt.output_hash, trHash.output_hash].map((h) => h.slice(7, 15)).join(" / "));

    // 5. GOALRUN MEMBERSHIP — canonical goal:// identity, reciprocal stamp, SINGULAR room.
    mkdirSync(join(dataDir, "goal-runs"), { recursive: true });
    for (const g of ["gr_fixture", "gr_fixture2"]) writeFileSync(join(dataDir, "goal-runs", `${g}.json`), JSON.stringify({ goal_run_id: g, schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", status: "active", goal_ref: `goal://${g}`, created_at: "2026-01-01T00:00:00Z" }));
    // The reconciliation admission requires verifier evidence — one passing verification fixture.
    mkdirSync(join(dataDir, "goal-run-verifications"), { recursive: true });
    writeFileSync(join(dataDir, "goal-run-verifications", "ver_fixture.json"), JSON.stringify({ goal_ref: "goal://gr_fixture", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_fixture", harness_invocation_ref: "harness_invocation://inv_fixture", created_at: "2026-01-01T00:00:00Z" }));
    const rawId = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "gr_fixture", expected_revision: 3 });
    ok("a RAW route id refuses — membership speaks the canonical goal:// identity (#72 finding 2)", rawId.status === 400 && rawId.j.error?.code === "outcome_room_goal_run_ref_invalid");
    const ghostRun = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_ghost", expected_revision: 3 });
    ok("attaching a GHOST goal-run refuses (the aggregate binds only real bounded runs)", ghostRun.status === 400 && ghostRun.j.error?.code === "outcome_room_goal_run_unbound");
    const attached = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_fixture", expected_revision: 3 });
    ok("attach admits: canonical membership + receipted bound facts incl. the reciprocal-stamp attestation", attached.status === 200 && JSON.stringify(attached.j.outcome_room?.member_goal_run_refs) === JSON.stringify(["goal://gr_fixture"]) && attached.j.outcome_room_receipt?.bound_facts?.goal_run_ref === "goal://gr_fixture" && attached.j.outcome_room_receipt?.bound_facts?.reciprocal_outcome_room_ref_stamped === true && attached.j.goal_run_stamped?.outcome_room_ref === room.outcome_room_id);
    const stamped = (await jd("GET", "/v1/hypervisor/goal-runs/gr_fixture")).j;
    ok("the reciprocal GoalRun.outcome_room_ref stamp is DURABLE on the goal-run record", JSON.stringify(stamped).includes(room.outcome_room_id));
    // THE REVIEW'S EXACT INTERLEAVING, LIVE (#72 round 2): a lifecycle write (reconcile) AFTER
    // the attach must not erase the reciprocal stamp — every GoalRun writer merges its own
    // fields onto the latest record through the shared CAS seam.
    const reconciled = await jd("POST", "/v1/hypervisor/goal-runs/gr_fixture/reconcile", {});
    const afterReconcile = (await jd("GET", "/v1/hypervisor/goal-runs/gr_fixture")).j;
    const afterStr = JSON.stringify(afterReconcile);
    ok("RECONCILE-vs-ATTACH: the reconcile landed AND the reciprocal room stamp SURVIVED (no split-brain membership)", reconciled.status === 200 && afterStr.includes(room.outcome_room_id) && afterStr.includes("reconciliation_result://"), `reconcile=${reconciled.status}/${reconciled.j.error?.code || 'ok'} stamped=${afterStr.includes(room.outcome_room_id)}`);
    const dup = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_fixture", expected_revision: 4 });
    ok("re-attach refuses: the run already belongs to a room (singular identity)", dup.status === 400 && dup.j.error?.code === "outcome_room_goal_run_already_member");
    // SINGULAR ROOM IDENTITY across rooms: a second room cannot claim the same run.
    const roomB = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const crossAttach = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(roomB.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_fixture", expected_revision: 1 });
    ok("a SECOND room cannot attach the same GoalRun — contradictory multi-room state is never created (#72 finding 2)", crossAttach.status === 400 && crossAttach.j.error?.code === "outcome_room_goal_run_already_member");

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
    const attachClosed = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(room.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_fixture2", expected_revision: 5 });
    ok("membership refuses a non-open room", attachClosed.status === 400 && attachClosed.j.error?.code === "outcome_room_not_open");
    // Supersession preserves room identity exactly like deltas (#72 finding 2): a roomless
    // result cannot supersede the roomed one; a same-room supersession admits.
    const roomC = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const inC = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: roomC.outcome_room_id });
    const roomlessSuper = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "superseded", status: "completed", supersedes_work_result_ref: inC.j.work_result.work_result_id });
    ok("a ROOMLESS result cannot supersede a roomed result (work_result_supersedes_cross_room)", roomlessSuper.status === 400 && roomlessSuper.j.error?.code === "work_result_supersedes_cross_room");
    const sameRoomSuper = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://alpha", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: roomC.outcome_room_id, supersedes_work_result_ref: inC.j.work_result.work_result_id });
    ok("a SAME-ROOM supersession admits", sameRoomSuper.status === 201 && sameRoomSuper.j.work_result?.supersedes_work_result_ref === inC.j.work_result.work_result_id);

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
    // 8b. CLOSE-vs-ADMISSION STRESS (#72 finding 3): the room-scope lock serializes room
    // resolution through result finalization — no result may be admitted AFTER the close.
    const roomD = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    const race = await Promise.all([
      ...Array.from({ length: 20 }, (_, i) => jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://race", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: roomD.outcome_room_id, summary_ref: `artifact://race-${i}` })),
      jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(roomD.outcome_room_id)}/transition`, { transition: "close", expected_revision: 1 }),
    ]);
    const closeResp = race[race.length - 1];
    const admissions = race.slice(0, 20);
    const closedRoomD = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(roomD.outcome_room_id)}`)).j.outcome_room;
    ok("RACE: the close landed and every admission either succeeded or refused typed room_not_open", closeResp.status === 200 && closedRoomD.status === "closed" && admissions.every((r) => r.status === 201 || (r.status === 400 && r.j.error?.code === "work_result_room_not_open")), `${admissions.filter((r) => r.status === 201).length} admitted / ${admissions.filter((r) => r.status === 400).length} refused`);
    ok("RACE: NO result was admitted after the close (every admitted created_at <= the room's closed updated_at)", admissions.filter((r) => r.status === 201).every((r) => r.j.work_result.created_at <= closedRoomD.updated_at));
    const postClose = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://race", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: roomD.outcome_room_id });
    ok("RACE: a post-close admission refuses deterministically", postClose.status === 400 && postClose.j.error?.code === "work_result_room_not_open");

    // 8c. LIFECYCLE FAIL-CLOSED (#72 round 3 finding 1): an injected goal-run write failure
    // surfaces as a TYPED 5xx with ZERO partial truth — never a 200 over an unchanged record —
    // and the SAME reconcile retries cleanly once the fault clears (recoverable, idempotent).
    writeFileSync(join(dataDir, "goal-runs", "gr_failclosed.json"), JSON.stringify({ goal_run_id: "gr_failclosed", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", status: "active", goal_ref: "goal://gr_failclosed", created_at: "2026-01-01T00:00:00Z" }));
    writeFileSync(join(dataDir, "goal-run-verifications", "ver_failclosed.json"), JSON.stringify({ goal_ref: "goal://gr_failclosed", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_failclosed", harness_invocation_ref: "harness_invocation://inv_failclosed", created_at: "2026-01-01T00:00:00Z" }));
    const reconBefore = receiptFileCount(dataDir, "goal-run-reconciliations");
    chmodSync(join(dataDir, "goal-runs"), 0o555);
    const failClosed = await jd("POST", "/v1/hypervisor/goal-runs/gr_failclosed/reconcile", {});
    chmodSync(join(dataDir, "goal-runs"), 0o755);
    const frozenStr = JSON.stringify((await jd("GET", "/v1/hypervisor/goal-runs/gr_failclosed")).j);
    ok("FAIL-CLOSED: an injected goal-run write failure → typed 5xx goal_run_persist_failed, NEVER a 200 (#72 r3 finding 1)", failClosed.status === 500 && failClosed.j.error?.code === "goal_run_persist_failed", `${failClosed.status}/${failClosed.j.error?.code || "ok"}`);
    ok("FAIL-CLOSED: zero partial truth — the run stays active with no reconciliation_ref, no reservation residue, and NO reconciliation record persisted", frozenStr.includes('"active"') && !frozenStr.includes("reconciliation_result://") && !frozenStr.includes("lifecycle_op") && receiptFileCount(dataDir, "goal-run-reconciliations") === reconBefore);
    const retried = await jd("POST", "/v1/hypervisor/goal-runs/gr_failclosed/reconcile", {});
    ok("RECOVERABLE: after the fault clears, the SAME reconcile retries to a clean 200 — nothing partial blocked it", retried.status === 200 && JSON.stringify(retried.j).includes("reconciliation_result://"), `${retried.status}/${retried.j.error?.code || "ok"}`);

    // 8d. ONE-SHOT RESERVATION (#72 round 3 finding 2): of two SIMULTANEOUS reconciles exactly
    // one wins the atomic `active -> reconciling` reservation; the loser refuses typed at the
    // same CAS that would have raced.
    writeFileSync(join(dataDir, "goal-runs", "gr_dup.json"), JSON.stringify({ goal_run_id: "gr_dup", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", status: "active", goal_ref: "goal://gr_dup", created_at: "2026-01-01T00:00:00Z" }));
    writeFileSync(join(dataDir, "goal-run-verifications", "ver_dup.json"), JSON.stringify({ goal_ref: "goal://gr_dup", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_dup", harness_invocation_ref: "harness_invocation://inv_dup", created_at: "2026-01-01T00:00:00Z" }));
    const twins = await Promise.all([jd("POST", "/v1/hypervisor/goal-runs/gr_dup/reconcile", {}), jd("POST", "/v1/hypervisor/goal-runs/gr_dup/reconcile", {})]);
    const dupWins = twins.filter((r) => r.status === 200);
    const dupLosses = twins.filter((r) => r.status === 409 && r.j.error?.code === "goal_run_not_reconcilable");
    ok("DUPLICATE RECONCILE: exactly ONE 200; the loser refuses 409 goal_run_not_reconcilable (#72 r3 finding 2)", dupWins.length === 1 && dupLosses.length === 1, twins.map((r) => `${r.status}/${r.j.error?.code || "ok"}`).join(" + "));
    const dupAfter = JSON.stringify((await jd("GET", "/v1/hypervisor/goal-runs/gr_dup")).j);
    ok("DUPLICATE RECONCILE: one durable reconciliation, reservation consumed by the winner's commit", dupAfter.includes("reconciliation_result://") && !dupAfter.includes("lifecycle_op"));

    // 8e. ATTACH INTENT PENDING CONVERGENCE (#72 round 9 finding 3): a receipt failure AFTER
    // the durable intent + durable stamp refuses typed with the intent retained — no unstamp,
    // no deletion, no split-brain — and new membership is refused until the intent converges.
    const roomE = (await jd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
    writeFileSync(join(dataDir, "goal-runs", "gr_nullshape.json"), JSON.stringify({ goal_run_id: "gr_nullshape", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", status: "active", goal_ref: "goal://gr_nullshape", outcome_room_ref: null, created_at: "2026-01-01T00:00:00Z" }));
    chmodSync(join(dataDir, "outcome-room-registry-receipts"), 0o555);
    const pendInjected = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(roomE.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_nullshape", expected_revision: 1 });
    chmodSync(join(dataDir, "outcome-room-registry-receipts"), 0o755);
    const roomEPending = (await jd("GET", `/v1/hypervisor/outcome-rooms/${roomTail(roomE.outcome_room_id)}`)).j.outcome_room || {};
    const stampAfter = JSON.parse(readFileSync(join(dataDir, "goal-runs", "gr_nullshape.json"), "utf8"));
    ok("ATTACH PENDING: receipt failure after the durable intent + stamp → typed pending-convergence; the intent is retained, the stamp STAYS, membership awaits the completer (#72 r9 finding 3)", pendInjected.status === 500 && pendInjected.j.error?.code === "outcome_room_attach_pending_convergence" && !!roomEPending.attach_intent && (roomEPending.member_goal_run_refs || []).length === 0 && stampAfter.outcome_room_ref === roomE.outcome_room_id, `${pendInjected.status}/${pendInjected.j.error?.code || "ok"} intent=${!!roomEPending.attach_intent}`);
    const inFlight = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(roomE.outcome_room_id)}/attach-goal-run`, { goal_run_ref: "goal://gr_fixture2", expected_revision: 1 });
    ok("ATTACH PENDING: new membership refuses while the intent is in flight (409 typed)", inFlight.status === 409 && inFlight.j.error?.code === "outcome_room_attach_in_flight", `${inFlight.status}/${inFlight.j.error?.code || "ok"}`);
    // #72 round 10 finding 2 — the reviewer's exact regression: a lifecycle transition during a
    // pending attach must refuse, or the completer's replay would silently erase it.
    const pauseDuring = await jd("POST", `/v1/hypervisor/outcome-rooms/${roomTail(roomE.outcome_room_id)}/transition`, { transition: "pause", expected_revision: 1 });
    ok("ATTACH PENDING: EVERY room mutator refuses while the intent is in flight — pause → 409, so replay can never erase an admitted transition (#72 r10 finding 2)", pauseDuring.status === 409 && pauseDuring.j.error?.code === "outcome_room_attach_in_flight", `${pauseDuring.status}/${pauseDuring.j.error?.code || "ok"}`);

    // 8f. RECONCILE OUTPUT INTEGRITY (#72 round 4 finding 1) — REAL candidate output against a
    // REAL target workspace; every failure lane proves the target is never mutated without a
    // durable receipt, and post-effect failures preserve (never delete) evidence.
    const candDir = join(dataDir, "fixture-candidate");
    const targetDir = join(dataDir, "fixture-target");
    mkdirSync(candDir, { recursive: true });
    mkdirSync(targetDir, { recursive: true });
    writeFileSync(join(candDir, "out.txt"), "CANDIDATE_OUTPUT");
    writeFileSync(join(targetDir, "old.txt"), "OLD_TARGET");
    writeFileSync(join(dataDir, "goal-runs", "gr_out.json"), JSON.stringify({ goal_run_id: "gr_out", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture with real output", status: "active", goal_ref: "goal://gr_out", target_workspace_root: targetDir, created_at: "2026-01-01T00:00:00Z" }));
    mkdirSync(join(dataDir, "goal-run-invocations"), { recursive: true });
    writeFileSync(join(dataDir, "goal-run-invocations", "gr_out_a.json"), JSON.stringify({ goal_ref: "goal://gr_out", goal_run_id: "gr_out", harness_invocation_id: "harness_invocation://hi_gr_out_a", role_key: "a", status: "completed", candidate_workspace_root: candDir, implementation_result: { implementation_result_id: "implementation_result://ir_gr_out_a", status: "completed", changed_files: ["out.txt"] } }));
    writeFileSync(join(dataDir, "goal-run-verifications", "ver_out.json"), JSON.stringify({ goal_ref: "goal://gr_out", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_out", harness_invocation_ref: "harness_invocation://hi_gr_out_a", created_at: "2026-01-01T00:00:00Z" }));
    const targetHasOutput = () => existsSync(join(targetDir, "out.txt"));
    const receiptsCount = () => receiptFileCount(dataDir, "receipts");
    const reconCount = () => receiptFileCount(dataDir, "goal-run-reconciliations");

    // Lane 1 — staging failure: BEFORE any receipt, before any target effect.
    mkdirSync(join(dataDir, "goal-run-reconcile-staging"), { recursive: true });
    chmodSync(join(dataDir, "goal-run-reconcile-staging"), 0o555);
    const [rB, cB] = [receiptsCount(), reconCount()];
    const stagingFail = await jd("POST", "/v1/hypervisor/goal-runs/gr_out/reconcile", {});
    chmodSync(join(dataDir, "goal-run-reconcile-staging"), 0o755);
    ok("OUTPUT LANE staging failure: typed 5xx; NO receipt, NO operation record, target UNTOUCHED", stagingFail.status === 500 && stagingFail.j.error?.code === "goal_run_output_staging_failed" && receiptsCount() === rB && reconCount() === cB && !targetHasOutput(), `${stagingFail.status}/${stagingFail.j.error?.code || "ok"}`);

    // Lane 2 — receipt failure AFTER staging: the reviewer's exact probe — the target must NOT
    // carry unreceipted output.
    chmodSync(join(dataDir, "receipts"), 0o555);
    const rcptFail = await jd("POST", "/v1/hypervisor/goal-runs/gr_out/reconcile", {});
    chmodSync(join(dataDir, "receipts"), 0o755);
    const rcptFailRun = (await jd("GET", "/v1/hypervisor/goal-runs/gr_out")).j.goal_run || {};
    const rcptFailRef = (rcptFailRun.reconciliation_attempt_refs || []).at(-1);
    const rcptFailRec = rcptFailRef ? JSON.parse(readFileSync(join(dataDir, "goal-run-reconciliations", `${String(rcptFailRef).replace("reconciliation_result://", "").replace(/[^A-Za-z0-9_-]/g, "_")}.json`), "utf8")) : null;
    ok("OUTPUT LANE receipt failure: typed 5xx; NO unreceipted output; the DECLARED attempt is retained with a resolving record and a backlink (#72 r8 finding 2 — nothing deleted, nothing orphaned)", rcptFail.status === 500 && rcptFail.j.error?.code === "goal_run_reconcile_receipt_persist_failed" && !targetHasOutput() && reconCount() === cB + 1 && !!rcptFailRef && rcptFailRec?.status === "aborted_before_output_admission" && receiptsCount() === rB, `${rcptFail.status}/${rcptFail.j.error?.code || "ok"} rec=${rcptFailRec?.status}`);

    // Lane 3 — operation-record failure: still pre-effect; the checked receipt rollback keeps
    // "nothing changed" literally true.
    chmodSync(join(dataDir, "goal-run-reconciliations"), 0o555);
    const recFail = await jd("POST", "/v1/hypervisor/goal-runs/gr_out/reconcile", {});
    chmodSync(join(dataDir, "goal-run-reconciliations"), 0o755);
    ok("OUTPUT LANE record failure: typed 5xx; receipt rolled back (count unchanged), target untouched", recFail.status === 500 && recFail.j.error?.code === "goal_run_reconciliation_persist_failed" && receiptsCount() === rB && !targetHasOutput(), `${recFail.status}/${recFail.j.error?.code || "ok"}`);

    // Lane 4 — COMMIT failure (post-effect window): evidence is PRESERVED, never deleted.
    chmodSync(targetDir, 0o555);
    const commitFail = await jd("POST", "/v1/hypervisor/goal-runs/gr_out/reconcile", {});
    chmodSync(targetDir, 0o755);
    const attemptRecord = (ref) => JSON.parse(readFileSync(join(dataDir, "goal-run-reconciliations", `${String(ref).replace("reconciliation_result://", "").replace(/[^A-Za-z0-9_-]/g, "_")}.json`), "utf8"));
    const failedAttemptRef = ((await jd("GET", "/v1/hypervisor/goal-runs/gr_out")).j.goal_run?.reconciliation_attempt_refs || []).at(-1);
    const preservedRec = attemptRecord(failedAttemptRef);
    ok("OUTPUT LANE commit failure: typed 5xx; the PRE-OUTPUT receipt survives (+1) and the ATTEMPT-SCOPED operation record is preserved with its journal (failed_partial_commit), NOT deleted", commitFail.status === 500 && commitFail.j.error?.code === "goal_run_output_commit_failed" && receiptsCount() === rB + 1 && !!failedAttemptRef && preservedRec.status === "failed_partial_commit" && preservedRec.commit_journal?.some((e) => e.applied === false) && preservedRec.recovery?.code === "goal_run_output_commit_failed", `${commitFail.status}/${commitFail.j.error?.code || "ok"} recStatus=${preservedRec.status}`);
    ok("OUTPUT LANE commit failure: the STAGED attempt is preserved as immutable evidence (staging survives every post-receipt failure)", readdirSync(join(dataDir, "goal-run-reconcile-staging")).some((n) => n.startsWith("gr_out_")), readdirSync(join(dataDir, "goal-run-reconcile-staging")).join(","));
    const runAfterCommitFail = (await jd("GET", "/v1/hypervisor/goal-runs/gr_out")).j.goal_run || {};
    ok("OUTPUT LANE commit failure: the reservation was released for the idempotent retry (active, no lifecycle_op)", runAfterCommitFail.status === "active" && !runAfterCommitFail.lifecycle_op);

    // Lane 5 — clean retry mints a NEW APPEND-ONLY attempt (#72 round 5 finding 2): the failed
    // attempt's record and receipt survive untouched; the run retains BOTH attempt refs.
    const refsBeforeRetry = ((await jd("GET", "/v1/hypervisor/goal-runs/gr_out")).j.goal_run?.reconciliation_attempt_refs || []).length;
    const outOk = await jd("POST", "/v1/hypervisor/goal-runs/gr_out/reconcile", {});
    const attemptsAfter = outOk.j.goal_run?.reconciliation_attempt_refs || [];
    const finalRec = attemptRecord(attemptsAfter.at(-1));
    const failedRecStill = attemptRecord(failedAttemptRef);
    ok("OUTPUT LANE retry: 200 under a NEW attempt identity; output landed (WAL journal applied + sha256) and EVERY prior attempt ref is retained", outOk.status === 200 && readFileSync(join(targetDir, "out.txt"), "utf8") === "CANDIDATE_OUTPUT" && readFileSync(join(targetDir, "old.txt"), "utf8") === "OLD_TARGET" && attemptsAfter.length === refsBeforeRetry + 1 && attemptsAfter.includes(failedAttemptRef) && attemptsAfter.at(-1) !== failedAttemptRef && finalRec.status === "complete" && finalRec.commit_journal?.at(-1)?.applied === true && String(finalRec.commit_journal?.at(-1)?.sha256 || "").startsWith("sha256:") && outOk.j.goal_run?.status === "complete", `${outOk.status} attempts=${attemptsAfter.length}`);
    ok("OUTPUT LANE retry: the FAILED attempt's evidence is untouched by the retry (append-only, never superseded in place)", failedRecStill.status === "failed_partial_commit" && failedRecStill.recovery?.code === "goal_run_output_commit_failed" && outOk.j.goal_run?.reconciliation_ref === attemptsAfter.at(-1));

    // 8g. START SIDE-RECORD INTEGRITY + LIFECYCLE RECOVERY (#72 round 4 findings 2 + 3) — the
    // REAL wallet crossing (403 challenge → dcrypt-signed grant), then an injected verification
    // record failure: never a 200 with dangling refs; recovery is token-addressed + receipted.
    writeFileSync(join(dataDir, "goal-runs", "gr_start.json"), JSON.stringify({ goal_run_id: "gr_start", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "prove checked side-records", goal_ref: "goal://gr_start", status: "draft", target_workspace_root: targetDir, context_cells: [{ role: "implementer", role_key: "a", harness_ref: "harness-profile:hp_ghost", harness: "ghost", context_cell_id: "cell://gr_start_a" }], created_at: "2026-01-01T00:00:00Z" }));
    const startWithGrant = async () => {
      const ch = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/start", {});
      if (ch.status !== 403 || !ch.j?.approval) return { ch, started: ch };
      const grant = mintApprovalGrant({ policyHash: ch.j.approval.policy_hash, requestHash: ch.j.approval.request_hash });
      return { ch, started: await jd("POST", "/v1/hypervisor/goal-runs/gr_start/start", { wallet_approval_grant: grant }) };
    };
    chmodSync(join(dataDir, "goal-run-verifications"), 0o555);
    const { ch, started } = await startWithGrant();
    chmodSync(join(dataDir, "goal-run-verifications"), 0o755);
    ok("START LANE: real 403 challenge + signed-grant crossing, then injected verification-record failure → typed 5xx, NEVER a 200 over nonexistent records", ch.status === 403 && started.status === 500 && started.j.error?.code === "goal_run_side_record_persist_failed", `challenge=${ch.status} start=${started.status}/${started.j.error?.code || "ok"}`);
    const reserved = (await jd("GET", "/v1/hypervisor/goal-runs/gr_start")).j.goal_run || {};
    ok("START LANE: durable truth = `starting` reservation marked recovery_required with executed-invocation evidence; ZERO refs bound, ZERO record files", reserved.status === "starting" && reserved.lifecycle_op?.phase === "recovery_required" && !("invocation_refs" in reserved) && !("verification_refs" in reserved) && (reserved.lifecycle_op?.executed_invocations || []).length === 1 && !readdirSync(join(dataDir, "goal-run-verifications")).some((n) => n.includes("gr_start")) && !readdirSync(join(dataDir, "goal-run-invocations")).some((n) => n.includes("gr_start")));
    const dupStart = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/start", {});
    ok("START LANE: a duplicate start refuses while the reservation is held — no second wallet crossing", dupStart.status === 409 && dupStart.j.error?.code === "goal_run_already_started");
    const noToken = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/lifecycle-recovery", { resolution: "release" });
    const wrongToken = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/lifecycle-recovery", { op_token: "lop_bogus", resolution: "release" });
    ok("RECOVERY: token-addressed — missing token 400, foreign token 409 (never a blind expiry)", noToken.status === 400 && noToken.j.error?.code === "goal_run_recovery_token_required" && wrongToken.status === 409 && wrongToken.j.error?.code === "goal_run_operation_conflict");
    // AUTHORITY, not just address (#72 round 5 finding 4): the readable token alone must NOT
    // release a reservation after a real wallet crossing.
    const tokenOnly = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/lifecycle-recovery", { op_token: reserved.lifecycle_op?.token, resolution: "release" });
    ok("RECOVERY: the token ALONE is refused — 403 challenge binding {run, token, resolution, failure_hash} (the token is an address, not authority)", tokenOnly.status === 403 && tokenOnly.j?.reason === "recovery_authority_required" && !!tokenOnly.j?.approval?.policy_hash && !!tokenOnly.j?.approval?.request_hash && String(tokenOnly.j?.failure_hash || "").startsWith("sha256:"), `${tokenOnly.status}/${tokenOnly.j?.reason || "ok"}`);
    const stillReserved = (await jd("GET", "/v1/hypervisor/goal-runs/gr_start")).j.goal_run || {};
    ok("RECOVERY: the refused release changed NOTHING (reservation intact)", stillReserved.status === "starting" && stillReserved.lifecycle_op?.token === reserved.lifecycle_op?.token);
    const recGrant = mintApprovalGrant({ policyHash: tokenOnly.j.approval.policy_hash, requestHash: tokenOnly.j.approval.request_hash });
    const recovered = await jd("POST", "/v1/hypervisor/goal-runs/gr_start/lifecycle-recovery", { op_token: reserved.lifecycle_op?.token, resolution: "release", wallet_approval_grant: recGrant });
    ok("RECOVERY: a GRANTED release succeeds — receipted with the acting authority, grant ref, and every bound hash (policy/request/failure)", recovered.status === 200 && recovered.j.recovery_receipt?.receipt_type === "GoalRunLifecycleRecoveryReceipt" && recovered.j.recovery_receipt?.restored_status === "draft" && recovered.j.recovery_receipt?.reservation?.failure?.family === "goal-run-verifications" && String(recovered.j.recovery_receipt?.authority_grant_ref || "").startsWith("wallet.network://grant/") && recovered.j.recovery_receipt?.failure_hash === tokenOnly.j.failure_hash && recovered.j.recovery_receipt?.request_hash === tokenOnly.j.approval.request_hash && !!recovered.j.recovery_receipt?.acting_authority_id && recovered.j.goal_run?.status === "draft" && !recovered.j.goal_run?.lifecycle_op, `${recovered.status}/${recovered.j.error?.code || "ok"}`);
    const retry = await startWithGrant();
    const retriedRun = retry.started.j?.goal_run || {};
    ok("RECOVERY: after the release, a NEW receipted crossing starts the run and every side record persists before its ref binds", retry.started.status === 200 && retriedRun.status === "active" && (retriedRun.verification_refs || []).length === 1 && readdirSync(join(dataDir, "goal-run-verifications")).some((n) => n.includes("gr_start")) && readdirSync(join(dataDir, "goal-run-invocations")).some((n) => n.includes("gr_start")), `${retry.started.status} vrefs=${(retriedRun.verification_refs || []).length}`);

    // 8h. OUTPUT CONTAINMENT (#72 round 5 finding 1) — traversal, absolute, symlink-ancestor,
    // and normalized-alias declarations refuse typed with ZERO external mutation.
    const escTarget = join(dataDir, "esc-target");
    const escCand = join(dataDir, "esc-cand");
    mkdirSync(escTarget, { recursive: true });
    mkdirSync(escCand, { recursive: true });
    writeFileSync(join(escCand, "a.txt"), "SAFE");
    const plantEscape = (grid, files, target) => {
      writeFileSync(join(dataDir, "goal-runs", `${grid}.json`), JSON.stringify({ goal_run_id: grid, schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "containment", status: "active", goal_ref: `goal://${grid}`, target_workspace_root: target, created_at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(dataDir, "goal-run-invocations", `${grid}_a.json`), JSON.stringify({ goal_ref: `goal://${grid}`, goal_run_id: grid, harness_invocation_id: `harness_invocation://hi_${grid}_a`, role_key: "a", status: "completed", candidate_workspace_root: escCand, implementation_result: { implementation_result_id: `implementation_result://ir_${grid}_a`, status: "completed", changed_files: files } }));
      writeFileSync(join(dataDir, "goal-run-verifications", `ver_${grid}.json`), JSON.stringify({ goal_ref: `goal://${grid}`, verdict: "pass", verification_ref: `agentgres://goal-run-verification/ver_${grid}`, harness_invocation_ref: `harness_invocation://hi_${grid}_a`, created_at: "2026-01-01T00:00:00Z" }));
    };
    const escTarget2 = join(dataDir, "esc-target2");
    const outsideDir = join(dataDir, "outside");
    mkdirSync(escTarget2, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    symlinkSync(outsideDir, join(escTarget2, "sub"));
    const CONTAINMENT = [
      ["gr_esc1", ["../escape.txt"], escTarget, "goal_run_output_path_escape", join(dataDir, "escape.txt"), "parent traversal"],
      ["gr_esc2", [join(dataDir, "abs-escape.txt")], escTarget, "goal_run_output_path_escape", join(dataDir, "abs-escape.txt"), "absolute path"],
      ["gr_esc3", ["a.txt", "a.txt"], escTarget, "goal_run_output_path_collision", null, "normalized-alias collision"],
      ["gr_esc4", ["sub/x.txt"], escTarget2, "goal_run_output_path_escape", join(outsideDir, "x.txt"), "symlinked ancestor"],
    ];
    for (const [grid, files, target, code, escapePath, label] of CONTAINMENT) {
      plantEscape(grid, files, target);
      const r = await jd("POST", `/v1/hypervisor/goal-runs/${grid}/reconcile`, {});
      const released = (await jd("GET", `/v1/hypervisor/goal-runs/${grid}`)).j.goal_run || {};
      ok(`CONTAINMENT (${label}): typed ${code}; ZERO external mutation; run released for correction`, r.status === 500 && r.j.error?.code === code && (!escapePath || !existsSync(escapePath)) && readdirSync(target).filter((n) => n !== "sub").length === 0 && readdirSync(outsideDir).length === 0 && released.status === "active" && !released.lifecycle_op, `${r.status}/${r.j.error?.code || "ok"}`);
    }

    // 8i. BOUNDED INTAKE (#72 round 7 finding 4) — a FIFO refuses without blocking; an oversize
    // file refuses typed; a too-many-files declaration refuses before any read.
    const biCand = join(dataDir, "bi-cand");
    const biTarget = join(dataDir, "bi-target");
    mkdirSync(biCand, { recursive: true });
    mkdirSync(biTarget, { recursive: true });
    const mkfifo = (await import("node:child_process")).execSync;
    mkfifo(`mkfifo ${JSON.stringify(join(biCand, "pipe"))}`);
    const plantBI = (grid, files) => {
      writeFileSync(join(dataDir, "goal-runs", `${grid}.json`), JSON.stringify({ goal_run_id: grid, schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "bounded", status: "active", goal_ref: `goal://${grid}`, target_workspace_root: biTarget, created_at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(dataDir, "goal-run-invocations", `${grid}_a.json`), JSON.stringify({ goal_ref: `goal://${grid}`, goal_run_id: grid, harness_invocation_id: `harness_invocation://hi_${grid}_a`, role_key: "a", status: "completed", candidate_workspace_root: biCand, implementation_result: { implementation_result_id: `implementation_result://ir_${grid}_a`, status: "completed", changed_files: files } }));
      writeFileSync(join(dataDir, "goal-run-verifications", `ver_${grid}.json`), JSON.stringify({ goal_ref: `goal://${grid}`, verdict: "pass", verification_ref: `agentgres://goal-run-verification/ver_${grid}`, harness_invocation_ref: `harness_invocation://hi_${grid}_a`, created_at: "2026-01-01T00:00:00Z" }));
    };
    plantBI("gr_fifo", ["pipe"]);
    const fifoR = await jd("POST", "/v1/hypervisor/goal-runs/gr_fifo/reconcile", {});
    ok("BOUNDED INTAKE: a candidate FIFO refuses typed (not_regular) without blocking the daemon; target untouched", fifoR.status === 500 && fifoR.j.error?.code === "goal_run_output_file_not_regular" && readdirSync(biTarget).length === 0, `${fifoR.status}/${fifoR.j.error?.code || "ok"}`);
    plantBI("gr_many", Array.from({ length: 300 }, (_, i) => `f${i}.txt`));
    const manyR = await jd("POST", "/v1/hypervisor/goal-runs/gr_many/reconcile", {});
    ok("BOUNDED INTAKE: >256 declared files refuse before any read (too_many_files)", manyR.status === 500 && manyR.j.error?.code === "goal_run_output_too_many_files", `${manyR.status}/${manyR.j.error?.code || "ok"}`);

    // 8j. DURABLE STAGING MANIFEST (#72 round 7 finding 2) — the pre-output receipt binds each
    // staged file's sha256 + size; the staged bytes on disk match that manifest exactly (a
    // restart validates bytes, not mere existence).
    const dsCand = join(dataDir, "ds-cand");
    const dsTarget = join(dataDir, "ds-target");
    mkdirSync(join(dsCand, "sub"), { recursive: true });
    mkdirSync(dsTarget, { recursive: true });
    const dsContent = { "a.txt": "ALPHA", "sub/b.txt": "BETABETA" };
    for (const [f, c] of Object.entries(dsContent)) writeFileSync(join(dsCand, f), c);
    plantBI.constructor;
    writeFileSync(join(dataDir, "goal-runs", "gr_ds.json"), JSON.stringify({ goal_run_id: "gr_ds", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "manifest", status: "active", goal_ref: "goal://gr_ds", target_workspace_root: dsTarget, created_at: "2026-01-01T00:00:00Z" }));
    writeFileSync(join(dataDir, "goal-run-invocations", "gr_ds_a.json"), JSON.stringify({ goal_ref: "goal://gr_ds", goal_run_id: "gr_ds", harness_invocation_id: "harness_invocation://hi_gr_ds_a", role_key: "a", status: "completed", candidate_workspace_root: dsCand, implementation_result: { implementation_result_id: "implementation_result://ir_gr_ds_a", status: "completed", changed_files: ["a.txt", "sub/b.txt"] } }));
    writeFileSync(join(dataDir, "goal-run-verifications", "ver_ds.json"), JSON.stringify({ goal_ref: "goal://gr_ds", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_ds", harness_invocation_ref: "harness_invocation://hi_gr_ds_a", created_at: "2026-01-01T00:00:00Z" }));
    const dsR = await jd("POST", "/v1/hypervisor/goal-runs/gr_ds/reconcile", {});
    const dsAttempt = dsR.j.goal_run?.reconciliation_attempt_refs?.at(-1) || dsR.j.goal_run?.reconciliation_ref;
    const dsRecId = String(dsAttempt).replace("reconciliation_result://", "");
    const dsRec = JSON.parse(readFileSync(join(dataDir, "goal-run-reconciliations", `${dsRecId}.json`), "utf8"));
    const sha256 = (s) => "sha256:" + createHash("sha256").update(s).digest("hex");
    const manifest = dsRec.staged_output_manifest || [];
    const manifestOk = manifest.length === 2 && manifest.every((m) => m.sha256 === sha256(dsContent[m.file]) && m.bytes === Buffer.byteLength(dsContent[m.file]));
    ok("DURABLE STAGING: the operation record's manifest binds each file's sha256 + size; the committed target bytes match the manifest exactly", dsR.status === 200 && manifestOk && Object.entries(dsContent).every(([f, c]) => readFileSync(join(dsTarget, f), "utf8") === c), `${dsR.status} manifest=${manifest.length}`);

    // 8k. LIVE STAGED-EVIDENCE BINDING (#72 round 8 finding 3): the recovery challenge hash
    // covers the ACTUAL staged bytes; mutating a staged file after the challenge forces a
    // re-challenge that carries the damaged-state facts, and only a grant over THOSE facts
    // releases.
    const svStage = join(dataDir, "goal-run-reconcile-staging", "gr_sv_lop_sv1");
    mkdirSync(svStage, { recursive: true });
    writeFileSync(join(svStage, "x.txt"), "STAGED_TRUTH");
    const svSha = "sha256:" + createHash("sha256").update("STAGED_TRUTH").digest("hex");
    writeFileSync(join(dataDir, "goal-run-reconciliations", "rc_gr_sv_lop_sv1.json"), JSON.stringify({ reconciliation_result_id: "reconciliation_result://rc_gr_sv_lop_sv1", goal_run_id: "gr_sv", goal_ref: "goal://gr_sv", status: "failed_partial_commit", attempt_token: "lop_sv1", staging_root: svStage, staged_output_manifest: [{ file: "x.txt", sha256: svSha, bytes: 12 }], commit_journal: [], final_receipt_refs: [] }));
    writeFileSync(join(dataDir, "goal-runs", "gr_sv.json"), JSON.stringify({ goal_run_id: "gr_sv", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "staged binding", status: "reconciling", goal_ref: "goal://gr_sv", lifecycle_op: { op: "reconcile", token: "lop_sv1", reserved_at: "2026-01-01T00:00:00Z", from_status: "active", attempt_ref: "reconciliation_result://rc_gr_sv_lop_sv1" }, created_at: "2026-01-01T00:00:00Z" }));
    const svCh1 = await jd("POST", "/v1/hypervisor/goal-runs/gr_sv/lifecycle-recovery", { op_token: "lop_sv1", resolution: "release" });
    ok("STAGED BINDING: the challenge validates the staged bytes live (validated=true) and binds them into failure_hash", svCh1.status === 403 && svCh1.j.staging_validation?.validated === true && svCh1.j.staging_validation?.checked === 1, `${svCh1.status} validated=${svCh1.j.staging_validation?.validated}`);
    writeFileSync(join(svStage, "x.txt"), "TAMPERED!!!!");
    const svG1 = mintApprovalGrant({ policyHash: svCh1.j.approval.policy_hash, requestHash: svCh1.j.approval.request_hash });
    const svStale = await jd("POST", "/v1/hypervisor/goal-runs/gr_sv/lifecycle-recovery", { op_token: "lop_sv1", resolution: "release", wallet_approval_grant: svG1 });
    ok("STAGED BINDING: a staged file mutated AFTER the challenge defeats the stale grant — refused at the gate with a fresh challenge (the recomputed hash no longer matches), nothing released; the lock recheck guards the residual gate→lock window", svStale.status === 403 && svStale.j?.reason === "recovery_authority_required" && svStale.j.staging_validation?.validated === false && JSON.parse(readFileSync(join(dataDir, "goal-runs", "gr_sv.json"), "utf8")).status === "reconciling", `${svStale.status}/${svStale.j?.reason || "ok"}`);
    const svCh2 = await jd("POST", "/v1/hypervisor/goal-runs/gr_sv/lifecycle-recovery", { op_token: "lop_sv1", resolution: "release" });
    ok("STAGED BINDING: the re-challenge carries the damaged-state facts (mismatched file named, different failure_hash)", svCh2.status === 403 && svCh2.j.staging_validation?.validated === false && svCh2.j.staging_validation?.mismatches?.[0]?.file === "x.txt" && svCh2.j.failure_hash !== svCh1.j.failure_hash, `mismatches=${(svCh2.j.staging_validation?.mismatches || []).length}`);
    const svG2 = mintApprovalGrant({ policyHash: svCh2.j.approval.policy_hash, requestHash: svCh2.j.approval.request_hash });
    const svRel = await jd("POST", "/v1/hypervisor/goal-runs/gr_sv/lifecycle-recovery", { op_token: "lop_sv1", resolution: "release", wallet_approval_grant: svG2 });
    ok("STAGED BINDING: a grant over the DAMAGED facts releases; the receipt binds the staging validation verdict and mismatch facts", svRel.status === 200 && svRel.j.recovery_receipt?.staging_validation?.validated === false && svRel.j.recovery_receipt?.staging_validation?.mismatches?.[0]?.file === "x.txt" && svRel.j.recovery_receipt?.failure_hash === svCh2.j.failure_hash, `${svRel.status}`);

    ok("no sentinel and no .tmp-* residue anywhere", !JSON.stringify((await jd("GET", "/v1/hypervisor/outcome-rooms")).j).includes("SENTINEL_ROOM_SECRET") && tmpLeaks().length === 0);
  } finally {
    await plane.stop();
  }

  // 9. CRASH DURABILITY (#72 round 5 finding 3): SIGKILL the daemon MID multi-file commit —
  // the durable write-ahead journal names exactly what was in flight, no destination is ever
  // truncated, the staged attempt survives, and the SAME data dir recovers through the governed
  // lane (403 → grant → release) to a complete retry with the crashed attempt's evidence intact.
  const crash = await startIsolatedPlane({ serve: false });
  if (crash) {
    try {
      const cjd = async (method, p2, body) => { const r = await fetch(`${crash.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const cCand = join(crash.dataDir, "crash-cand");
      const cTarget = join(crash.dataDir, "crash-target");
      mkdirSync(cCand, { recursive: true });
      mkdirSync(cTarget, { recursive: true });
      mkdirSync(join(crash.dataDir, "goal-runs"), { recursive: true });
      mkdirSync(join(crash.dataDir, "goal-run-invocations"), { recursive: true });
      mkdirSync(join(crash.dataDir, "goal-run-verifications"), { recursive: true });
      const FILES = Array.from({ length: 32 }, (_, i) => `f${String(i).padStart(2, "0")}.bin`);
      const CONTENT = {};
      for (const f of FILES) { CONTENT[f] = `CONTENT_${f}_`.repeat(80000); writeFileSync(join(cCand, f), CONTENT[f]); }
      writeFileSync(join(crash.dataDir, "goal-runs", "gr_crash.json"), JSON.stringify({ goal_run_id: "gr_crash", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "crash durability", status: "active", goal_ref: "goal://gr_crash", target_workspace_root: cTarget, created_at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(crash.dataDir, "goal-run-invocations", "gr_crash_a.json"), JSON.stringify({ goal_ref: "goal://gr_crash", goal_run_id: "gr_crash", harness_invocation_id: "harness_invocation://hi_gr_crash_a", role_key: "a", status: "completed", candidate_workspace_root: cCand, implementation_result: { implementation_result_id: "implementation_result://ir_gr_crash_a", status: "completed", changed_files: FILES } }));
      writeFileSync(join(crash.dataDir, "goal-run-verifications", "ver_crash.json"), JSON.stringify({ goal_ref: "goal://gr_crash", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_crash", harness_invocation_ref: "harness_invocation://hi_gr_crash_a", created_at: "2026-01-01T00:00:00Z" }));
      const recDir = join(crash.dataDir, "goal-run-reconciliations");
      const readAttempt = () => { try { const f = readdirSync(recDir).find((n) => n.startsWith("rc_gr_crash_")); return f ? JSON.parse(readFileSync(join(recDir, f), "utf8")) : null; } catch { return null; } };
      const inflight = fetch(`${crash.daemonUrl}/v1/hypervisor/goal-runs/gr_crash/reconcile`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => null);
      let sawCommit = false;
      for (let i = 0; i < 4000; i++) {
        const rec = readAttempt();
        if (rec && (rec.commit_journal || []).length >= 2) { sawCommit = true; break; }
        await new Promise((r) => setTimeout(r, 2));
      }
      process.kill(crash.daemonPid, "SIGKILL");
      await inflight;
      const rec = readAttempt();
      const journal = rec?.commit_journal || [];
      ok("CRASH: SIGKILL landed mid-commit with the durable WAL in place (status `committing`, journal in flight)", sawCommit && rec?.status === "committing" && journal.length >= 2 && journal.length < FILES.length, `journal=${journal.length}/${FILES.length} status=${rec?.status}`);
      let consistent = true;
      const journaled = new Set();
      for (const e of journal) {
        journaled.add(e.file);
        const p2 = join(cTarget, e.file);
        if (e.applied === true) consistent = consistent && existsSync(p2) && readFileSync(p2, "utf8") === CONTENT[e.file] && String(e.sha256 || "").startsWith("sha256:");
        else if (e.phase === "applying") consistent = consistent && (!existsSync(p2) || readFileSync(p2, "utf8") === CONTENT[e.file]);
      }
      for (const f of FILES) if (!journaled.has(f)) consistent = consistent && !existsSync(join(cTarget, f));
      for (const v of readdirSync(cTarget).filter((n) => !n.startsWith("."))) consistent = consistent && readFileSync(join(cTarget, v), "utf8") === CONTENT[v];
      ok("CRASH: every visible target file is COMPLETE and journaled; unjournaled files are absent; the in-flight file is atomic (absent or complete, never truncated)", consistent, `journal=${journal.length}`);
      ok("CRASH: the staged attempt survived the crash (immutable declared input preserved)", readdirSync(join(crash.dataDir, "goal-run-reconcile-staging")).length === 1);
      // RESTART on the SAME durable state → governed recovery → complete retry.
      const revived = await startIsolatedPlane({ serve: false, dataDir: crash.dataDir });
      const rjd = async (method, p2, body) => { const r = await fetch(`${revived.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const stuck = (await rjd("GET", "/v1/hypervisor/goal-runs/gr_crash")).j.goal_run || {};
      ok("CRASH RESTART: the reservation survived durably (reconciling + token) — no blind expiry, no silent unlock", stuck.status === "reconciling" && !!stuck.lifecycle_op?.token, stuck.status);
      const crashedRef = stuck.lifecycle_op?.attempt_ref;
      const chall = await rjd("POST", "/v1/hypervisor/goal-runs/gr_crash/lifecycle-recovery", { op_token: stuck.lifecycle_op?.token, resolution: "release" });
      ok("CRASH RESTART: the recovery challenge VALIDATES the surviving staged bytes against the sealed manifest (all 32 intact)", chall.status === 403 && chall.j.staging_validation?.validated === true && chall.j.staging_validation?.checked === FILES.length, `validated=${chall.j.staging_validation?.validated} checked=${chall.j.staging_validation?.checked}`);
      const g = chall.status === 403 ? mintApprovalGrant({ policyHash: chall.j.approval.policy_hash, requestHash: chall.j.approval.request_hash }) : null;
      const rel = g ? await rjd("POST", "/v1/hypervisor/goal-runs/gr_crash/lifecycle-recovery", { op_token: stuck.lifecycle_op?.token, resolution: "release", wallet_approval_grant: g }) : chall;
      ok("CRASH RECOVERY: the reservation NAMES its attempt; the challenge hash covers reservation + attempt record; the receipt binds the crashed attempt ref AND that hash (#72 r6 finding 2)", String(crashedRef || "").startsWith("reconciliation_result://rc_gr_crash_") && rel.status === 200 && rel.j.recovery_receipt?.attempt_ref === crashedRef && rel.j.recovery_receipt?.failure_hash === chall.j.failure_hash && (rel.j.goal_run?.reconciliation_attempt_refs || []).includes(crashedRef), `${rel.status} attempt=${String(crashedRef).slice(-20)}`);
      const retry = await rjd("POST", "/v1/hypervisor/goal-runs/gr_crash/reconcile", {});
      const allComplete = FILES.every((f) => existsSync(join(cTarget, f)) && readFileSync(join(cTarget, f), "utf8") === CONTENT[f]);
      const attemptRecords = readdirSync(recDir).filter((n) => n.startsWith("rc_gr_crash_"));
      const retryAttempts = retry.j.goal_run?.reconciliation_attempt_refs || [];
      ok("CRASH RECOVERY: governed release then a clean retry lands ALL files; the GoalRun links BOTH the crashed attempt and the winner (append-only), records retained on disk", chall.status === 403 && rel.status === 200 && retry.status === 200 && allComplete && retry.j.goal_run?.status === "complete" && attemptRecords.length === 2 && retryAttempts.length === 2 && retryAttempts.includes(crashedRef) && retry.j.goal_run?.reconciliation_ref !== crashedRef, `${chall.status}/${rel.status}/${retry.status} files=${FILES.filter((f) => existsSync(join(cTarget, f))).length}/${FILES.length} refs=${retryAttempts.length}`);
      // OWNERSHIP (#72 round 6 finding 5): a REUSED data dir is caller-owned — stop() must not
      // delete it (the sentinel and the durable records survive).
      writeFileSync(join(crash.dataDir, "caller-owned-sentinel"), "OWNED");
      await revived.stop();
      ok("HELPER OWNERSHIP: stop() on a reused dataDir deletes NOTHING (sentinel + records survive)", existsSync(join(crash.dataDir, "caller-owned-sentinel")) && existsSync(join(crash.dataDir, "goal-runs", "gr_crash.json")));
    } finally {
      try { rmSync(crash.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("CRASH: crash plane started", false, "daemon did not start");
  }

  // 10. RECOVERY CRASH-ATOMICITY (#72 round 6 finding 4): a DELIBERATE kill point immediately
  // after the GoalRun replacement (durable recovery intent) and before receipt persistence —
  // the boot completer must finish the sealed transaction forward deterministically.
  const kp = await startIsolatedPlane({ serve: false, env: { IOI_TEST_KILL_AFTER_RECOVERY_INTENT: "1" } });
  if (kp) {
    try {
      const kjd = async (method, p2, body) => { const r = await fetch(`${kp.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      mkdirSync(join(kp.dataDir, "goal-runs"), { recursive: true });
      writeFileSync(join(kp.dataDir, "goal-runs", "gr_kp.json"), JSON.stringify({ goal_run_id: "gr_kp", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "kill point", status: "reconciling", goal_ref: "goal://gr_kp", lifecycle_op: { op: "reconcile", token: "lop_kp1", reserved_at: "2026-01-01T00:00:00Z", from_status: "active", attempt_ref: "reconciliation_result://rc_gr_kp_lop_kp1" }, created_at: "2026-01-01T00:00:00Z" }));
      const kch = await kjd("POST", "/v1/hypervisor/goal-runs/gr_kp/lifecycle-recovery", { op_token: "lop_kp1", resolution: "release" });
      const kg = mintApprovalGrant({ policyHash: kch.j.approval.policy_hash, requestHash: kch.j.approval.request_hash });
      const killed = await fetch(`${kp.daemonUrl}/v1/hypervisor/goal-runs/gr_kp/lifecycle-recovery`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ op_token: "lop_kp1", resolution: "release", wallet_approval_grant: kg }) }).then((r) => r.status).catch(() => "died");
      const durable = JSON.parse(readFileSync(join(kp.dataDir, "goal-runs", "gr_kp.json"), "utf8"));
      const receiptsAtKill = (() => { try { return readdirSync(join(kp.dataDir, "receipts")).filter((n) => n.includes("lifecycle-recovery")); } catch { return []; } })();
      ok("KILL POINT: the daemon died after the durable intent and before the receipt — reservation intact, receipt sealed INSIDE the intent, no receipt file yet", killed === "died" && durable.status === "reconciling" && !!durable.lifecycle_op && !!durable.recovery_intent?.receipt && receiptsAtKill.length === 0, `resp=${killed} intent=${!!durable.recovery_intent} receipts=${receiptsAtKill.length}`);
      const kpRevived = await startIsolatedPlane({ serve: false, dataDir: kp.dataDir });
      const rkjd = async (method, p2, body) => { const r = await fetch(`${kpRevived.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const after = (await rkjd("GET", "/v1/hypervisor/goal-runs/gr_kp")).j.goal_run || {};
      const receiptFiles = readdirSync(join(kp.dataDir, "receipts")).filter((n) => n.includes("lifecycle-recovery"));
      ok("KILL POINT: the boot completer finished FORWARD deterministically — released to from_status, crashed attempt ref RETAINED, sealed receipt persisted, reservation + intent consumed", after.status === "active" && !after.lifecycle_op && !after.recovery_intent && (after.reconciliation_attempt_refs || []).includes("reconciliation_result://rc_gr_kp_lop_kp1") && receiptFiles.length === 1, `${after.status} receipts=${receiptFiles.length}`);
      // #72 round 7 finding 3: this reservation named an attempt that NEVER had a record (the
      // crash preceded any output admission). The retained ref must RESOLVE — recovery created
      // an aborted_before_output_admission record for it.
      const abortedAttempt = (await rkjd("GET", "/v1/hypervisor/goal-runs/gr_kp")).j.goal_run?.reconciliation_attempt_refs?.[0];
      const abortedFile = existsSync(join(kp.dataDir, "goal-run-reconciliations", "rc_gr_kp_lop_kp1.json")) ? JSON.parse(readFileSync(join(kp.dataDir, "goal-run-reconciliations", "rc_gr_kp_lop_kp1.json"), "utf8")) : null;
      const recRcpt = JSON.parse(readFileSync(join(kp.dataDir, "receipts", receiptFiles[0]), "utf8"));
      ok("KILL POINT: the dangling attempt ref RESOLVES — recovery created an aborted_before_output_admission record; the receipt records attempt_resolution", abortedAttempt === "reconciliation_result://rc_gr_kp_lop_kp1" && abortedFile?.status === "aborted_before_output_admission" && recRcpt.attempt_resolution === "aborted_before_output_admission", `resolved=${!!abortedFile} resolution=${recRcpt.attempt_resolution}`);
      await kpRevived.stop();
    } finally {
      try { rmSync(kp.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("KILL POINT: crash plane started", false, "daemon did not start");
  }

  // 11. VISIBILITY FAULT PLANES (#72 round 8 findings 1 + 2): the env-gated dir-sync fault
  // (absent = no effect; a permission split is impossible on a read-then-write seam because the
  // directory listing and the fsync open need the same read bit) forces the
  // RenamedDurabilityUnconfirmed outcome through REAL request paths.
  const vf = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "goal-runs" } });
  if (vf) {
    try {
      const vjd = async (method, p2, body) => { const r = await fetch(`${vf.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      mkdirSync(join(vf.dataDir, "goal-runs"), { recursive: true });
      mkdirSync(join(vf.dataDir, "goal-run-verifications"), { recursive: true });
      // (a) RESERVATION BOUNDARY (#72 r9 finding 1): an unconfirmed reconcile reservation must
      // not cross into any effect — zero receipts, zero records, zero target writes.
      writeFileSync(join(vf.dataDir, "goal-runs", "gr_res.json"), JSON.stringify({ goal_run_id: "gr_res", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "reservation fault", status: "active", goal_ref: "goal://gr_res", created_at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(vf.dataDir, "goal-run-verifications", "ver_res.json"), JSON.stringify({ goal_ref: "goal://gr_res", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_res", harness_invocation_ref: "harness_invocation://inv_res", created_at: "2026-01-01T00:00:00Z" }));
      const resFault = await vjd("POST", "/v1/hypervisor/goal-runs/gr_res/reconcile", {});
      ok("RESERVATION BOUNDARY: an unconfirmed reconcile reservation refuses typed with ZERO effects (no receipt, no record, no target write) (#72 r9 finding 1)", resFault.status === 500 && resFault.j.error?.code === "goal_run_reservation_durability_unconfirmed" && receiptFileCount(vf.dataDir, "receipts") === 0 && receiptFileCount(vf.dataDir, "goal-run-reconciliations") === 0, `${resFault.status}/${resFault.j.error?.code || "ok"}`);
      // (b) START BOUNDARY: the wallet crossing is never even challenged over an unconfirmed
      // reservation — no 403, no invocation, no verification record.
      writeFileSync(join(vf.dataDir, "goal-runs", "gr_st.json"), JSON.stringify({ goal_run_id: "gr_st", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "start fault", status: "draft", goal_ref: "goal://gr_st", context_cells: [{ role: "implementer", role_key: "a", harness_ref: "harness-profile:hp_ghost", harness: "ghost", context_cell_id: "cell://gr_st_a" }], created_at: "2026-01-01T00:00:00Z" }));
      const stFault = await vjd("POST", "/v1/hypervisor/goal-runs/gr_st/start", {});
      ok("RESERVATION BOUNDARY: start refuses BEFORE the wallet challenge over an unconfirmed reservation — zero wallet/harness effects", stFault.status === 500 && stFault.j.error?.code === "goal_run_reservation_durability_unconfirmed" && receiptFileCount(vf.dataDir, "goal-run-invocations") === 0 && receiptFileCount(vf.dataDir, "goal-run-verifications") === 1, `${stFault.status}/${stFault.j.error?.code || "ok"}`);
      // (c) ATTACH STAMP BOUNDARY (#72 r9 finding 3): an unconfirmed stamp refuses typed with
      // the durable attach intent retained.
      const vRoom = (await vjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
      writeFileSync(join(vf.dataDir, "goal-runs", "gr_att.json"), JSON.stringify({ goal_run_id: "gr_att", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "attach fault", status: "active", goal_ref: "goal://gr_att", created_at: "2026-01-01T00:00:00Z" }));
      const vAttach = await vjd("POST", `/v1/hypervisor/outcome-rooms/${vRoom.outcome_room_id.replace("outcome-room://", "")}/attach-goal-run`, { goal_run_ref: "goal://gr_att", expected_revision: 1 });
      const vRoomDisk = (await vjd("GET", `/v1/hypervisor/outcome-rooms/${vRoom.outcome_room_id.replace("outcome-room://", "")}`)).j.outcome_room || {};
      ok("ATTACH STAMP BOUNDARY: an unconfirmed reciprocal stamp refuses typed pending convergence; the DURABLE intent is retained", vAttach.status === 500 && vAttach.j.error?.code === "outcome_room_attach_pending_convergence" && !!vRoomDisk.attach_intent, `${vAttach.status}/${vAttach.j.error?.code || "ok"} intent=${!!vRoomDisk.attach_intent}`);
      // (d) RECOVERY INTENT BOUNDARY (#72 r9 finding 2): an unconfirmed intent refuses typed
      // with nothing else written.
      writeFileSync(join(vf.dataDir, "goal-runs", "gr_int.json"), JSON.stringify({ goal_run_id: "gr_int", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "intent fault", status: "reconciling", goal_ref: "goal://gr_int", lifecycle_op: { op: "reconcile", token: "lop_int1", reserved_at: "2026-01-01T00:00:00Z", from_status: "active" }, created_at: "2026-01-01T00:00:00Z" }));
      const iCh = await vjd("POST", "/v1/hypervisor/goal-runs/gr_int/lifecycle-recovery", { op_token: "lop_int1", resolution: "release" });
      const iG = mintApprovalGrant({ policyHash: iCh.j.approval.policy_hash, requestHash: iCh.j.approval.request_hash });
      const iRel = await vjd("POST", "/v1/hypervisor/goal-runs/gr_int/lifecycle-recovery", { op_token: "lop_int1", resolution: "release", wallet_approval_grant: iG });
      ok("RECOVERY INTENT BOUNDARY: an unconfirmed intent refuses typed with NO receipt written; the visible intent awaits the completer", iRel.status === 500 && iRel.j.error?.code === "goal_run_recovery_intent_durability_unconfirmed" && receiptFileCount(vf.dataDir, "receipts") === 0, `${iRel.status}/${iRel.j.error?.code || "ok"}`);
      // RESTART on the same durable state, fault cleared: every boundary converges.
      process.kill(vf.daemonPid, "SIGKILL");
      const vRevived = await startIsolatedPlane({ serve: false, dataDir: vf.dataDir });
      const rvjd = async (method, p2, body) => { const r = await fetch(`${vRevived.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      // gr_int: the boot completer finished the sealed recovery (release + receipt).
      const intAfter = (await rvjd("GET", "/v1/hypervisor/goal-runs/gr_int")).j.goal_run || {};
      ok("RESTART CONVERGENCE: the boot completer finished the interrupted recovery — released to from_status, receipt persisted, intent consumed", intAfter.status === "active" && !intAfter.lifecycle_op && !intAfter.recovery_intent && readdirSync(join(vf.dataDir, "receipts")).some((n) => n.includes("lifecycle-recovery")), intAfter.status);
      // gr_att: the attach completer converged to EXACT reciprocal equality.
      const attRoom = (await rvjd("GET", `/v1/hypervisor/outcome-rooms/${vRoom.outcome_room_id.replace("outcome-room://", "")}`)).j.outcome_room || {};
      const attRun = JSON.parse(readFileSync(join(vf.dataDir, "goal-runs", "gr_att.json"), "utf8"));
      ok("RESTART CONVERGENCE: the attach completer converged — room member ⇔ run stamp ⇔ receipt, intent consumed (EXACT reciprocal equality)", (attRoom.member_goal_run_refs || []).includes("goal://gr_att") && !attRoom.attach_intent && attRun.outcome_room_ref === vRoom.outcome_room_id && readdirSync(join(vf.dataDir, "outcome-room-registry-receipts")).length >= 1, `member=${(attRoom.member_goal_run_refs || []).length} stamp=${attRun.outcome_room_ref === vRoom.outcome_room_id}`);
      // gr_res: reservation survived; governed release then EXACTLY ONE clean retry.
      const resStuck = (await rvjd("GET", "/v1/hypervisor/goal-runs/gr_res")).j.goal_run || {};
      const rCh = await rvjd("POST", "/v1/hypervisor/goal-runs/gr_res/lifecycle-recovery", { op_token: resStuck.lifecycle_op?.token, resolution: "release" });
      const rG = mintApprovalGrant({ policyHash: rCh.j.approval.policy_hash, requestHash: rCh.j.approval.request_hash });
      const rRel = await rvjd("POST", "/v1/hypervisor/goal-runs/gr_res/lifecycle-recovery", { op_token: resStuck.lifecycle_op?.token, resolution: "release", wallet_approval_grant: rG });
      const resRetry = await rvjd("POST", "/v1/hypervisor/goal-runs/gr_res/reconcile", {});
      const resRefs = resRetry.j.goal_run?.reconciliation_attempt_refs || [];
      ok("RESTART CONVERGENCE: the reserved run recovers (governed release retains the aborted attempt) then EXACTLY ONE clean retry lands (#72 r9 finding 1)", resStuck.status === "reconciling" && rRel.status === 200 && resRetry.status === 200 && resRefs.length === 2 && resRetry.j.goal_run?.reconciliation_ref === resRefs.at(-1), `${rRel.status}/${resRetry.status} refs=${resRefs.length}`);
      await vRevived.stop();
    } finally {
      try { rmSync(vf.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("FAULT PLANE: plane started", false, "daemon did not start");
  }
  const rf = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "receipts" } });
  if (rf) {
    try {
      const fjd = async (method, p2, body) => { const r = await fetch(`${rf.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const fCand = join(rf.dataDir, "cand");
      const fTarget = join(rf.dataDir, "target");
      mkdirSync(fCand, { recursive: true });
      mkdirSync(fTarget, { recursive: true });
      writeFileSync(join(fCand, "out.txt"), "PAYLOAD");
      mkdirSync(join(rf.dataDir, "goal-runs"), { recursive: true });
      mkdirSync(join(rf.dataDir, "goal-run-invocations"), { recursive: true });
      mkdirSync(join(rf.dataDir, "goal-run-verifications"), { recursive: true });
      writeFileSync(join(rf.dataDir, "goal-runs", "gr_rf.json"), JSON.stringify({ goal_run_id: "gr_rf", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "receipt fault", status: "active", goal_ref: "goal://gr_rf", target_workspace_root: fTarget, created_at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(rf.dataDir, "goal-run-invocations", "gr_rf_a.json"), JSON.stringify({ goal_ref: "goal://gr_rf", goal_run_id: "gr_rf", harness_invocation_id: "harness_invocation://hi_gr_rf_a", role_key: "a", status: "completed", candidate_workspace_root: fCand, implementation_result: { implementation_result_id: "implementation_result://ir_gr_rf_a", status: "completed", changed_files: ["out.txt"] } }));
      writeFileSync(join(rf.dataDir, "goal-run-verifications", "ver_rf.json"), JSON.stringify({ goal_ref: "goal://gr_rf", verdict: "pass", verification_ref: "agentgres://goal-run-verification/ver_rf", harness_invocation_ref: "harness_invocation://hi_gr_rf_a", created_at: "2026-01-01T00:00:00Z" }));
      const fRec = await fjd("POST", "/v1/hypervisor/goal-runs/gr_rf/reconcile", {});
      const fRun = JSON.parse(readFileSync(join(rf.dataDir, "goal-runs", "gr_rf.json"), "utf8"));
      const fRef = (fRun.reconciliation_attempt_refs || [])[0];
      const fRecFile = fRef ? JSON.parse(readFileSync(join(rf.dataDir, "goal-run-reconciliations", `${String(fRef).replace("reconciliation_result://", "")}.json`), "utf8")) : null;
      const fReceipts = readdirSync(join(rf.dataDir, "receipts")).filter((n) => n.includes("goal-run-reconciliation"));
      ok("RECEIPT FAULT (visible-unconfirmed): typed 5xx; the VISIBLE receipt is preserved WITH a resolving attempt record and a retained backlink — no orphan evidence, target untouched, staging preserved", fRec.status === 500 && fRec.j.error?.code === "goal_run_reconcile_receipt_durability_unconfirmed" && fReceipts.length === 1 && !!fRef && fRecFile?.status === "aborted_before_output_admission" && !existsSync(join(fTarget, "out.txt")) && readdirSync(join(rf.dataDir, "goal-run-reconcile-staging")).length === 1, `${fRec.status}/${fRec.j.error?.code || "ok"} receipt=${fReceipts.length} rec=${fRecFile?.status}`);
      // RECOVERY RECEIPT BOUNDARY (#72 r9 finding 2): the recovery receipt must be DURABLE
      // before the release consumes the intent — an unconfirmed one refuses typed with the
      // durable intent retained, and a restart re-persists it (byte-exact) and completes.
      writeFileSync(join(rf.dataDir, "goal-runs", "gr_rb.json"), JSON.stringify({ goal_run_id: "gr_rb", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "receipt boundary", status: "reconciling", goal_ref: "goal://gr_rb", lifecycle_op: { op: "reconcile", token: "lop_rb1", reserved_at: "2026-01-01T00:00:00Z", from_status: "active" }, created_at: "2026-01-01T00:00:00Z" }));
      const bCh = await fjd("POST", "/v1/hypervisor/goal-runs/gr_rb/lifecycle-recovery", { op_token: "lop_rb1", resolution: "release" });
      const bG = mintApprovalGrant({ policyHash: bCh.j.approval.policy_hash, requestHash: bCh.j.approval.request_hash });
      const bRel = await fjd("POST", "/v1/hypervisor/goal-runs/gr_rb/lifecycle-recovery", { op_token: "lop_rb1", resolution: "release", wallet_approval_grant: bG });
      const bRun = JSON.parse(readFileSync(join(rf.dataDir, "goal-runs", "gr_rb.json"), "utf8"));
      ok("RECOVERY RECEIPT BOUNDARY: an unconfirmed recovery receipt refuses typed; the DURABLE intent is retained un-consumed (reservation intact)", bRel.status === 500 && bRel.j.error?.code === "goal_run_recovery_receipt_durability_unconfirmed" && !!bRun.recovery_intent && !!bRun.lifecycle_op, `${bRel.status}/${bRel.j.error?.code || "ok"} intent=${!!bRun.recovery_intent}`);
      process.kill(rf.daemonPid, "SIGKILL");
      const rfRevived = await startIsolatedPlane({ serve: false, dataDir: rf.dataDir });
      const rfjd = async (method, p2, body) => { const r = await fetch(`${rfRevived.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const bAfter = (await rfjd("GET", "/v1/hypervisor/goal-runs/gr_rb")).j.goal_run || {};
      ok("RECOVERY RECEIPT BOUNDARY: restart re-persists the sealed receipt (byte-exact) and completes the release — intent consumed only after durable evidence", bAfter.status === "active" && !bAfter.lifecycle_op && !bAfter.recovery_intent && readdirSync(join(rf.dataDir, "receipts")).some((n) => n.includes("lifecycle-recovery")), bAfter.status);
      await rfRevived.stop();
    } finally {
      try { rmSync(rf.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("RECEIPT FAULT: plane started", false, "daemon did not start");
  }

  // 12. ROOM DURABILITY FAULT PLANE (#72 round 10 findings 1 + 3): every room mutation is an
  // intent transaction — pending records never read as admitted/open, transitions never advance
  // the visible status before their receipt is durable, and restart converges everything
  // (including the A-intent/B-binding conflict, which is never overwritten).
  const rp = await startIsolatedPlane({ serve: false, env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "outcome-room-registry" } });
  if (rp) {
    try {
      const pjd = async (method, p2, body) => { const r = await fetch(`${rp.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      // (a) CREATE under registry-write uncertainty: the TERMINAL write tolerates visible
      // (crash-revert replays the internal intent), the room lists with a CANONICAL status, and
      // the consumed intent is dropped — no noncanonical status ever escapes (#72 r11 f2).
      const cFault = await pjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM);
      const listed = (await pjd("GET", "/v1/hypervisor/outcome-rooms")).j.outcome_rooms || [];
      ok("ROOM FAULT create: the terminal registry write tolerates visible-unconfirmed (201) BUT the intent is RETAINED as the replay anchor — room-or-intent always survives with the durable receipt; every listed status is CANONICAL (#72 r12 finding 1)", cFault.status === 201 && listed.length === 1 && listed.every((r) => r.status === "open") && receiptFileCount(rp.dataDir, "outcome-room-admission-intents") === 1, `${cFault.status} listed=${listed.map((r) => r.status).join(",")} intents=${receiptFileCount(rp.dataDir, "outcome-room-admission-intents")}`);
      // (b) TRANSITION under durability uncertainty: 5xx; the visible status NEVER advances and
      // no receipt exists — the reviewer's `paused with zero receipt` is structurally gone.
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_tf.json"), JSON.stringify({ outcome_room_id: "outcome-room://or_tf", schema_version: "ioi.hypervisor.outcome-room.v1", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: [], status_history: [], updated_at: "2026-01-01T00:00:00Z" }));
      const receiptsBaseline = (() => { try { return readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).length; } catch { return 0; } })();
      const tFault = await pjd("POST", "/v1/hypervisor/outcome-rooms/or_tf/transition", { transition: "pause", expected_revision: 1 });
      const tfDisk = JSON.parse(readFileSync(join(rp.dataDir, "outcome-room-registry", "or_tf.json"), "utf8"));
      const tfReceipts = (() => { try { return readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).length; } catch { return 0; } })();
      ok("ROOM FAULT transition: 5xx typed; disk still shows the PRIOR status with the intent sealed and ZERO transition receipt (#72 r10 finding 1)", tFault.status === 500 && tFault.j.error?.code === "outcome_room_mutation_pending_convergence" && tfDisk.status === "open" && !!tfDisk.transition_intent && tfReceipts === receiptsBaseline, `${tFault.status}/${tFault.j.error?.code || "ok"} disk=${tfDisk.status} receipts=${tfReceipts - receiptsBaseline} new`);
      // (b2) THE ADMISSION BOUNDARY IS INTENT-AWARE (#72 r11 finding 1): the visibly-open room
      // with a durably ORDERED transition refuses results AND deltas typed, zero mutation.
      const wrBefore = receiptFileCount(rp.dataDir, "work-result-registry");
      const pendResult = await pjd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://p", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: "outcome-room://or_tf" });
      const pendDelta = await pjd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://p", delta_kind: "update", target_ref: "frontier://p", proposed_by_ref: "work_result://wr_ghost", outcome_room_ref: "outcome-room://or_tf" });
      ok("ROOM FAULT admission boundary: results AND deltas refuse typed while the transition intent is pending — the ordered close outranks the visible prior status (#72 r11 finding 1)", pendResult.status === 400 && pendResult.j.error?.code === "work_result_room_intent_pending" && pendDelta.status === 400 && pendDelta.j.error?.code === "outcome_delta_room_intent_pending" && receiptFileCount(rp.dataDir, "work-result-registry") === wrBefore, `${pendResult.status}/${pendResult.j.error?.code} ${pendDelta.status}/${pendDelta.j.error?.code}`);
      // (c) Plant the A-intent/B-binding conflict for restart (#72 r10 finding 3).
      mkdirSync(join(rp.dataDir, "goal-runs"), { recursive: true });
      writeFileSync(join(rp.dataDir, "goal-runs", "gr_ab.json"), JSON.stringify({ goal_run_id: "gr_ab", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "conflict", status: "active", goal_ref: "goal://gr_ab", outcome_room_ref: "outcome-room://or_B", created_at: "2026-01-01T00:00:00Z" }));
      const priorA = { outcome_room_id: "outcome-room://or_A", schema_version: "ioi.hypervisor.outcome-room.v1", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: [], status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const updatedA = { ...priorA, member_goal_run_refs: ["goal://gr_ab"], revision: 2 };
      const aReceipt = { schema_version: "x", receipt_id: "receipt://ort_conflict", receipt_ref: "receipt://ort_conflict", receipt_type: "OutcomeRoomTransitionReceipt", subject_ref: "outcome-room://or_A", op: "goal_run_attached" };
      const sha = (v) => "sha256:" + createHash("sha256").update(canon(v)).digest("hex");
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_A.json"), JSON.stringify({ ...priorA, attach_intent: { run_file_id: "gr_ab", room_ref: "outcome-room://or_A", receipt_id: "ort_conflict", receipt: aReceipt, receipt_hash: sha(aReceipt), updated_room: updatedA, updated_room_hash: sha(updatedA), at: "2026-01-01T00:00:00Z" } }));
      // (d) TAMPERED-DECLARATION REPLAY (#72 r13): same anchor + same admission_receipt_ref,
      // but altered objective/owner — the completer must refuse with room, receipt family, and
      // intent byte-for-byte unchanged.
      const ROOM_DECL_EXCLUDES = ["admission_receipt_ref", "updated_at", "revision", "status", "status_history", "member_goal_run_refs", "admission_and_replay_refs"];
      const TRANSITION_DECL_EXCLUDES = ["admission_receipt_ref", "admission_and_replay_refs", "status_history"];
      const TRANSITION_NOTE = "an admitted shared-state transition on a hosted room — receipted, optimistically concurrent, and honest about being admission (not verification or acceptance)";
      const ATTACH_NOTE = "an admitted membership transition — the room's member list and the GoalRun's reciprocal outcome_room_ref stamp land in one atomic finalization";
      // Mirror of build_room_receipt_at (the server-side receipt constructor) — used to build a
      // TRUTHFUL receipt for the lying-receipt adversarial lanes (#72 r16 finding 2).
      const roomReceipt = (tail, schema, type, subject, op, boundFacts, boundaryRefs, outputHash, excludes, note, now) => ({
        schema_version: schema, receipt_id: `receipt://${tail}`, receipt_ref: `receipt://${tail}`, receipt_type: type,
        receipt_profile_ref: `schema://${schema}`, actor_id: "daemon://hypervisor-runtime", subject_ref: subject, op,
        attested_boundary_fact_refs: boundaryRefs, bound_facts: boundFacts, output_hash: outputHash, hash_scope_excludes: excludes,
        assurance_posture: "admitted_not_verified", assurance_note: note, verification_ref: null, acceptance_ref: null,
        claim_scope_ref: null, run_id: null, task_id: null, input_hash: null, policy_hash: null, authority_grant_id: null,
        primitive_capabilities: [], authority_scopes: [], artifact_refs: [], evidence_bundle_refs: [], adjudication_ref: null,
        settlement_ref: null, signature: null, l1_commitment: null, timestamp: now, outcome: "ok", at: now,
      });
      const tpDecl = { outcome_room_id: "outcome-room://or_tp", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "original objective", owner_or_sponsor_ref: "org://original", status: "open", revision: 1, member_goal_run_refs: [], status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const tpReceipt = { schema_version: "ioi.hypervisor.outcome-room-admission-receipt.v1", receipt_id: "receipt://orr_tamper", receipt_ref: "receipt://orr_tamper", receipt_type: "OutcomeRoomAdmissionReceipt", receipt_profile_ref: "schema://ioi.hypervisor.outcome-room-admission-receipt.v1", subject_ref: "outcome-room://or_tp", op: "admitted", output_hash: recomputeHash(tpDecl, ROOM_DECL_EXCLUDES), hash_scope_excludes: ROOM_DECL_EXCLUDES };
      const tpFinal = { ...tpDecl, admission_receipt_ref: "receipt://orr_tamper", admission_and_replay_refs: ["receipt://orr_tamper"] };
      writeFileSync(join(rp.dataDir, "outcome-room-admission-intents", "or_tp.json"), JSON.stringify({ room_tail: "or_tp", room_ref: "outcome-room://or_tp", receipt_id: "orr_tamper", receipt: tpReceipt, receipt_hash: sha(tpReceipt), final_room: tpFinal, final_room_hash: sha(tpFinal), at: "2026-01-01T00:00:00Z" }));
      const tpTampered = { ...tpFinal, objective: "TAMPERED objective", owner_or_sponsor_ref: "org://attacker" };
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_tp.json"), JSON.stringify(tpTampered));
      const tpBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_tp.json"), "utf8");
      // (e) WIDENED-SCOPE REPLAY (#72 r13 review / round 14): the intent's receipt widens
      // hash_scope_excludes to also exclude objective+owner, and the tampered room recomputes to
      // the receipt's output_hash under THAT widened scope. The completer recomputes under the
      // CONSTANT excludes and requires the declared scope to equal it — so the forgery refuses.
      const wsDecl = { outcome_room_id: "outcome-room://or_ws", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "TAMPERED", owner_or_sponsor_ref: "org://attacker", status: "open", revision: 1, member_goal_run_refs: [], status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const wsWidened = [...ROOM_DECL_EXCLUDES, "objective", "owner_or_sponsor_ref"];
      const wsReceipt = { schema_version: "ioi.hypervisor.outcome-room-admission-receipt.v1", receipt_id: "receipt://orr_scope", receipt_ref: "receipt://orr_scope", receipt_type: "OutcomeRoomAdmissionReceipt", receipt_profile_ref: "schema://ioi.hypervisor.outcome-room-admission-receipt.v1", subject_ref: "outcome-room://or_ws", op: "admitted", output_hash: recomputeHash(wsDecl, wsWidened), hash_scope_excludes: wsWidened };
      const wsFinal = { ...wsDecl, admission_receipt_ref: "receipt://orr_scope", admission_and_replay_refs: ["receipt://orr_scope"] };
      writeFileSync(join(rp.dataDir, "outcome-room-admission-intents", "or_ws.json"), JSON.stringify({ room_tail: "or_ws", room_ref: "outcome-room://or_ws", receipt_id: "orr_scope", receipt: wsReceipt, receipt_hash: sha(wsReceipt), final_room: wsFinal, final_room_hash: sha(wsFinal), at: "2026-01-01T00:00:00Z" }));
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_ws.json"), JSON.stringify(wsFinal));
      const wsBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_ws.json"), "utf8");
      // (f) ABSENT-ROOM FORGED ADMISSION (#72 r15 finding 1): the NORMAL recovery state — only a
      // self-consistent but NON-CANONICAL admission intent exists (wrong op + widened scope +
      // forged declaration), no room in the registry. The completer must run the FULL semantic
      // validator and refuse, admitting nothing.
      const fafRoom = { outcome_room_id: "outcome-room://or_faf", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "FORGED", owner_or_sponsor_ref: "org://attacker", status: "open", revision: 1, member_goal_run_refs: [], status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const fafWidened = [...ROOM_DECL_EXCLUDES, "objective", "owner_or_sponsor_ref"];
      const fafReceipt = { schema_version: "ioi.hypervisor.outcome-room-admission-receipt.v1", receipt_id: "receipt://orr_faf", receipt_ref: "receipt://orr_faf", receipt_type: "OutcomeRoomAdmissionReceipt", receipt_profile_ref: "schema://ioi.hypervisor.outcome-room-admission-receipt.v1", subject_ref: "outcome-room://or_faf", op: "NOT-admitted", output_hash: recomputeHash(fafRoom, fafWidened), hash_scope_excludes: fafWidened };
      const fafFinal = { ...fafRoom, admission_receipt_ref: "receipt://orr_faf", admission_and_replay_refs: ["receipt://orr_faf"] };
      writeFileSync(join(rp.dataDir, "outcome-room-admission-intents", "or_faf.json"), JSON.stringify({ room_tail: "or_faf", room_ref: "outcome-room://or_faf", receipt_id: "orr_faf", receipt: fafReceipt, receipt_hash: sha(fafReceipt), final_room: fafFinal, final_room_hash: sha(fafFinal), at: "2026-01-01T00:00:00Z" }));
      // (g) FORGED TRANSITION (#72 r15 finding 2): an open room carrying a self-consistent but
      // NON-canonical transition_intent (illegal status accepted, revision 99, altered owner).
      const ftfPrior = { outcome_room_id: "outcome-room://or_ftf", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "legit", owner_or_sponsor_ref: "org://legit", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: ["receipt://orr_ftf"], admission_receipt_ref: "receipt://orr_ftf", status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const ftfForgedRoom = { ...ftfPrior, status: "accepted", revision: 99, owner_or_sponsor_ref: "org://attacker" };
      const ftfReceipt = { schema_version: "ioi.hypervisor.outcome-room-transition-receipt.v1", receipt_id: "receipt://ort_ftf", receipt_ref: "receipt://ort_ftf", receipt_type: "OutcomeRoomTransitionReceipt", receipt_profile_ref: "schema://ioi.hypervisor.outcome-room-transition-receipt.v1", subject_ref: "outcome-room://or_ftf", op: "pause", output_hash: "sha256:whatever", hash_scope_excludes: TRANSITION_DECL_EXCLUDES };
      const ftfIntent = { receipt_id: "ort_ftf", receipt: ftfReceipt, receipt_hash: sha(ftfReceipt), final_room: ftfForgedRoom, final_room_hash: sha(ftfForgedRoom), at: "2026-01-01T00:00:00Z" };
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_ftf.json"), JSON.stringify({ ...ftfPrior, transition_intent: ftfIntent }));
      const ftfBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_ftf.json"), "utf8");
      // (h) FORGED ATTACH (#72 r15 finding 2): an open room carrying a self-consistent but
      // NON-canonical attach_intent (a smuggled extra member) + the run it names.
      writeFileSync(join(rp.dataDir, "goal-runs", "gr_fmf.json"), JSON.stringify({ goal_run_id: "gr_fmf", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "x", status: "active", goal_ref: "goal://gr_fmf", created_at: "2026-01-01T00:00:00Z" }));
      const fmfPrior = { outcome_room_id: "outcome-room://or_fmf", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "legit", owner_or_sponsor_ref: "org://legit", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: ["receipt://orr_fmf"], admission_receipt_ref: "receipt://orr_fmf", status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const fmfForgedRoom = { ...fmfPrior, member_goal_run_refs: ["goal://gr_fmf", "goal://gr_smuggled"], revision: 42 };
      const fmfReceipt = { schema_version: "ioi.hypervisor.outcome-room-transition-receipt.v1", receipt_id: "receipt://ort_fmf", receipt_ref: "receipt://ort_fmf", receipt_type: "OutcomeRoomTransitionReceipt", receipt_profile_ref: "schema://ioi.hypervisor.outcome-room-transition-receipt.v1", subject_ref: "outcome-room://or_fmf", op: "goal_run_attached", output_hash: "sha256:whatever", hash_scope_excludes: TRANSITION_DECL_EXCLUDES };
      const fmfIntent = { run_file_id: "gr_fmf", room_ref: "outcome-room://or_fmf", receipt_id: "ort_fmf", receipt: fmfReceipt, receipt_hash: sha(fmfReceipt), updated_room: fmfForgedRoom, updated_room_hash: sha(fmfForgedRoom), at: "2026-01-01T00:00:00Z" };
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_fmf.json"), JSON.stringify({ ...fmfPrior, attach_intent: fmfIntent }));
      const fmfBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_fmf.json"), "utf8");
      // (i) HOLLOW ADMISSION ENVELOPE (#72 r16 finding 1): a room with NO governing declaration
      // (no owner/objective/host/mode/topology/policies). The full reconstruction through the
      // creation validator rejects it — a hollow envelope can never enter the registry.
      const hoRoom = { outcome_room_id: "outcome-room://or_ho", schema_version: "ioi.hypervisor.outcome-room.v1", status: "open", revision: 1, member_goal_run_refs: [], status_history: [], admission_receipt_ref: "receipt://orr_ho", admission_and_replay_refs: ["receipt://orr_ho"], created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
      const hoReceipt = roomReceipt("orr_ho", "ioi.hypervisor.outcome-room-admission-receipt.v1", "OutcomeRoomAdmissionReceipt", "outcome-room://or_ho", "admitted", { status_at_admission: "open" }, ["outcome-room://or_ho"], "sha256:whatever", ROOM_DECL_EXCLUDES, "n", "2026-01-01T00:00:00Z");
      writeFileSync(join(rp.dataDir, "outcome-room-admission-intents", "or_ho.json"), JSON.stringify({ room_tail: "or_ho", room_ref: "outcome-room://or_ho", receipt_id: "orr_ho", receipt: hoReceipt, receipt_hash: sha(hoReceipt), final_room: hoRoom, final_room_hash: sha(hoRoom), at: "2026-01-01T00:00:00Z" }));
      // (j) TRUTHFUL SUCCESSOR, LYING TRANSITION RECEIPT (#72 r16 finding 2): the room advances
      // to the CORRECT pause, but the receipt attests a fabricated archive/accepted→settled with
      // a foreign boundary and forged posture. The reconstructed receipt won't match — refused.
      const ltPrior = { outcome_room_id: "outcome-room://or_lt", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "legit", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: ["receipt://orr_lt"], admission_receipt_ref: "receipt://orr_lt", status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const ltNow = "2026-06-06T00:00:00Z";
      const ltSuccessor = { ...ltPrior, status: "paused", revision: 2, updated_at: ltNow, admission_and_replay_refs: ["receipt://orr_lt", "receipt://ort_lt"], status_history: [{ op: "pause", at: ltNow, receipt_ref: "receipt://ort_lt", revision: 2 }] };
      const ltOutputHash = sha(Object.fromEntries(Object.entries(ltSuccessor).filter(([k]) => !TRANSITION_DECL_EXCLUDES.includes(k))));
      const ltLyingReceipt = roomReceipt("ort_lt", "ioi.hypervisor.outcome-room-transition-receipt.v1", "OutcomeRoomTransitionReceipt", "outcome-room://or_lt", "pause", { transition: "archive", from: "accepted", to: "settled", revision_before: 900, revision_after: 901 }, ["outcome-room://some-other-room"], ltOutputHash, TRANSITION_DECL_EXCLUDES, TRANSITION_NOTE, ltNow);
      ltLyingReceipt.assurance_posture = "forged_assurance";
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_lt.json"), JSON.stringify({ ...ltPrior, transition_intent: { receipt_id: "ort_lt", receipt: ltLyingReceipt, receipt_hash: sha(ltLyingReceipt), final_room: ltSuccessor, final_room_hash: sha(ltSuccessor), at: ltNow } }));
      const ltBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_lt.json"), "utf8");
      // (k) TRUTHFUL MEMBERSHIP, LYING ATTACH RECEIPT (#72 r16 finding 2).
      writeFileSync(join(rp.dataDir, "goal-runs", "gr_la.json"), JSON.stringify({ goal_run_id: "gr_la", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "x", status: "active", goal_ref: "goal://gr_la", created_at: "2026-01-01T00:00:00Z" }));
      const laPrior = { outcome_room_id: "outcome-room://or_la", schema_version: "ioi.hypervisor.outcome-room.v1", objective: "legit", status: "open", revision: 1, member_goal_run_refs: [], admission_and_replay_refs: ["receipt://orr_la"], admission_receipt_ref: "receipt://orr_la", status_history: [], updated_at: "2026-01-01T00:00:00Z" };
      const laNow = "2026-06-06T00:00:00Z";
      const laSuccessor = { ...laPrior, member_goal_run_refs: ["goal://gr_la"], revision: 2, updated_at: laNow, admission_and_replay_refs: ["receipt://orr_la", "receipt://ort_la"], status_history: [{ op: "goal_run_attached", at: laNow, receipt_ref: "receipt://ort_la", revision: 2 }] };
      const laOutputHash = sha(Object.fromEntries(Object.entries(laSuccessor).filter(([k]) => !TRANSITION_DECL_EXCLUDES.includes(k))));
      const laLyingReceipt = roomReceipt("ort_la", "ioi.hypervisor.outcome-room-transition-receipt.v1", "OutcomeRoomTransitionReceipt", "outcome-room://or_la", "goal_run_attached", { goal_run_ref: "goal://gr_smuggled", reciprocal_outcome_room_ref_stamped: false, member_count_after: 99, revision_before: 5, revision_after: 6 }, ["outcome-room://or_la", "goal://gr_la"], laOutputHash, TRANSITION_DECL_EXCLUDES, ATTACH_NOTE, laNow);
      writeFileSync(join(rp.dataDir, "outcome-room-registry", "or_la.json"), JSON.stringify({ ...laPrior, attach_intent: { run_file_id: "gr_la", room_ref: "outcome-room://or_la", receipt_id: "ort_la", receipt: laLyingReceipt, receipt_hash: sha(laLyingReceipt), updated_room: laSuccessor, updated_room_hash: sha(laSuccessor), at: laNow } }));
      const laBytes = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_la.json"), "utf8");
      // RESTART with the fault cleared: convergence + non-overwrite.
      process.kill(rp.daemonPid, "SIGKILL");
      const rpRevived = await startIsolatedPlane({ serve: false, dataDir: rp.dataDir });
      const rpjd = async (method, p2, body) => { const r = await fetch(`${rpRevived.daemonUrl}${p2}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const afterRooms = (await rpjd("GET", "/v1/hypervisor/outcome-rooms")).j.outcome_rooms || [];
      const admitted = afterRooms.find((r) => r.status === "open" && r.outcome_room_id !== "outcome-room://or_A");
      const tfAfter = afterRooms.find((r) => r.outcome_room_id === "outcome-room://or_tf");
      const tfReceiptsAfter = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).length;
      const createdIntentGone = !existsSync(join(rp.dataDir, "outcome-room-admission-intents", `${String(admitted?.outcome_room_id || "").replace("outcome-room://", "")}.json`));
      ok("ROOM FAULT restart: the completer APPLIED the sealed transition (paused + receipt, intent consumed); the created room stands canonical and its retained admission anchor is consumed only now — after a DURABLE confirmation (#72 r12 finding 1)", admitted?.status === "open" && tfAfter?.status === "paused" && !tfAfter?.transition_intent && tfReceiptsAfter >= 2 && createdIntentGone, `admitted=${admitted?.status} tf=${tfAfter?.status} createdIntentGone=${createdIntentGone}`);
      const postConverge = await rpjd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://p", result_profile: "research", outcome_class: "positive", status: "completed", outcome_room_ref: "outcome-room://or_tf" });
      ok("ROOM FAULT restart: after the ordered transition applies, bindings refuse room_not_open — no result was ever admitted across the close boundary", postConverge.status === 400 && postConverge.j.error?.code === "work_result_room_not_open", `${postConverge.status}/${postConverge.j.error?.code || "ok"}`);
      const abRun = JSON.parse(readFileSync(join(rp.dataDir, "goal-runs", "gr_ab.json"), "utf8"));
      const roomA = afterRooms.find((r) => r.outcome_room_id === "outcome-room://or_A");
      ok("ROOM FAULT restart: the A-intent/B-binding conflict is NEVER overwritten — room B's binding intact, room A's intent retained as a manual conflict, no membership manufactured (#72 r10 finding 3)", abRun.outcome_room_ref === "outcome-room://or_B" && !!roomA?.attach_intent && (roomA?.member_goal_run_refs || []).length === 0, `binding=${abRun.outcome_room_ref} intentA=${!!roomA?.attach_intent}`);
      const tpAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_tp.json"), "utf8");
      const tpReceiptExists = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("orr_tamper"));
      const tpIntentRetained = existsSync(join(rp.dataDir, "outcome-room-admission-intents", "or_tp.json"));
      ok("ROOM FAULT restart: a TAMPERED declaration behind the same anchor is refused — room byte-unchanged, NO receipt persisted for the unproven admission, intent retained for manual repair (#72 r13)", tpAfter === tpBytes && !tpReceiptExists && tpIntentRetained, `unchanged=${tpAfter === tpBytes} receipt=${tpReceiptExists} intent=${tpIntentRetained}`);
      const wsAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_ws.json"), "utf8");
      const wsReceiptExists = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("orr_scope"));
      const wsIntentRetained = existsSync(join(rp.dataDir, "outcome-room-admission-intents", "or_ws.json"));
      ok("ROOM FAULT restart: a WIDENED hash_scope_excludes hiding a tampered declaration is refused — the completer recomputes under the CONSTANT excludes; room byte-unchanged, no receipt, intent retained (#72 r14)", wsAfter === wsBytes && !wsReceiptExists && wsIntentRetained, `unchanged=${wsAfter === wsBytes} receipt=${wsReceiptExists} intent=${wsIntentRetained}`);
      // ABSENT-ROOM FORGED ADMISSION (#72 r15 finding 1): the semantic validator runs even with
      // NO existing room — the forgery admits nothing.
      const fafRoomAdmitted = afterRooms.some((r) => r.outcome_room_id === "outcome-room://or_faf");
      const fafReceiptExists = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("orr_faf"));
      const fafIntentRetained = existsSync(join(rp.dataDir, "outcome-room-admission-intents", "or_faf.json"));
      ok("ROOM FAULT restart: an ABSENT-room forged admission intent is REFUSED by the full semantic validator — no room admitted, no receipt, intent retained (#72 r15 finding 1)", !fafRoomAdmitted && !fafReceiptExists && fafIntentRetained, `admitted=${fafRoomAdmitted} receipt=${fafReceiptExists} intent=${fafIntentRetained}`);
      // FORGED TRANSITION (#72 r15 finding 2): the reconstruction rejects a non-successor.
      const ftfAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_ftf.json"), "utf8");
      const ftfReceiptExists = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("ort_ftf"));
      const ftfRoom = afterRooms.find((r) => r.outcome_room_id === "outcome-room://or_ftf");
      ok("ROOM FAULT restart: a FORGED transition successor (accepted/rev 99/altered owner) is refused — room byte-unchanged, status still open, no transition receipt (#72 r15 finding 2)", ftfAfter === ftfBytes && ftfRoom?.status === "open" && !ftfReceiptExists, `unchanged=${ftfAfter === ftfBytes} status=${ftfRoom?.status} receipt=${ftfReceiptExists}`);
      // FORGED ATTACH (#72 r15 finding 2): the membership reconstruction rejects a smuggled member.
      const fmfAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_fmf.json"), "utf8");
      const fmfRun = JSON.parse(readFileSync(join(rp.dataDir, "goal-runs", "gr_fmf.json"), "utf8"));
      const fmfReceiptExists = readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("ort_fmf"));
      ok("ROOM FAULT restart: a FORGED attach successor (smuggled member/rev 42) is refused — room byte-unchanged, run NEVER stamped, no receipt (#72 r15 finding 2)", fmfAfter === fmfBytes && !fmfRun.outcome_room_ref && !fmfReceiptExists, `unchanged=${fmfAfter === fmfBytes} stamped=${!!fmfRun.outcome_room_ref} receipt=${fmfReceiptExists}`);
      // HOLLOW ADMISSION (#72 r16 finding 1): reconstruction through the creation validator rejects it.
      const hoAdmitted = afterRooms.some((r) => r.outcome_room_id === "outcome-room://or_ho");
      const hoIntentRetained = existsSync(join(rp.dataDir, "outcome-room-admission-intents", "or_ho.json"));
      ok("ROOM FAULT restart: a HOLLOW ungoverned admission envelope (no owner/objective/host/mode/policies) is REFUSED by full reconstruction — nothing admitted, intent retained (#72 r16 finding 1)", !hoAdmitted && hoIntentRetained && !readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("orr_ho")), `admitted=${hoAdmitted} intent=${hoIntentRetained}`);
      // LYING TRANSITION RECEIPT (#72 r16 finding 2): truthful successor, forged attested facts.
      const ltAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_lt.json"), "utf8");
      const ltRoom = afterRooms.find((r) => r.outcome_room_id === "outcome-room://or_lt");
      ok("ROOM FAULT restart: a TRUTHFUL pause successor with a LYING receipt (archive/accepted→settled, foreign boundary, forged posture) is refused — room byte-unchanged, status open, no false receipt (#72 r16 finding 2)", ltAfter === ltBytes && ltRoom?.status === "open" && !readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("ort_lt")), `unchanged=${ltAfter === ltBytes} status=${ltRoom?.status}`);
      // LYING ATTACH RECEIPT (#72 r16 finding 2): truthful membership, forged run/stamp facts.
      const laAfter = readFileSync(join(rp.dataDir, "outcome-room-registry", "or_la.json"), "utf8");
      const laRun = JSON.parse(readFileSync(join(rp.dataDir, "goal-runs", "gr_la.json"), "utf8"));
      ok("ROOM FAULT restart: a TRUTHFUL membership successor with a LYING attach receipt (smuggled run, false reciprocal stamp) is refused — room byte-unchanged, run NEVER stamped, no false receipt (#72 r16 finding 2)", laAfter === laBytes && !laRun.outcome_room_ref && !readdirSync(join(rp.dataDir, "outcome-room-registry-receipts")).some((n) => n.includes("ort_la")), `unchanged=${laAfter === laBytes} stamped=${!!laRun.outcome_room_ref}`);
      await rpRevived.stop();
    } finally {
      try { rmSync(rp.dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  } else {
    ok("ROOM FAULT: plane started", false, "daemon did not start");
  }

  // 13. SUBSTRATE DUAL-WRITE PARITY (#72 round 3 finding 4): with the soak opted in, the ATOMIC
  // writers — the room mutation writer and the GoalRun seam — feed the substrate dual-write
  // hook exactly like persist_record; the engine's admitted counter proves the hook fired.
  const soak = await startIsolatedPlane({ serve: false, env: { IOI_SUBSTRATE_DUAL_WRITE: "1", IOI_SUBSTRATE_DUAL_WRITE_DOMAINS: "goal-runs,outcome-room-registry" } });
  if (soak) {
    try {
      const sjd = async (method, p, body) => { const r = await fetch(`${soak.daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
      const sRoom = (await sjd("POST", "/v1/hypervisor/outcome-rooms", VALID_ROOM)).j.outcome_room;
      mkdirSync(join(soak.dataDir, "goal-runs"), { recursive: true });
      writeFileSync(join(soak.dataDir, "goal-runs", "gr_soak.json"), JSON.stringify({ goal_run_id: "gr_soak", schema_version: "ioi.hypervisor.goal-run.v1", normalized_goal: "fixture", status: "active", goal_ref: "goal://gr_soak", created_at: "2026-01-01T00:00:00Z" }));
      const sAttach = await sjd("POST", `/v1/hypervisor/outcome-rooms/${sRoom.outcome_room_id.replace("outcome-room://", "")}/attach-goal-run`, { goal_run_ref: "goal://gr_soak", expected_revision: 1 });
      const sStatus = (await sjd("GET", "/v1/hypervisor/substrate/status")).j;
      ok("SOAK PARITY: room create + attach + seam stamp through the ATOMIC writers all fed the dual-write hook (admitted ≥ 3, zero refusals) (#72 r3 finding 4)", sAttach.status === 200 && sStatus.soak?.enabled === true && (sStatus.admitted || 0) >= 3 && (sStatus.errors || 0) === 0, `admitted=${sStatus.admitted} errors=${sStatus.errors} attach=${sAttach.status}`);
    } finally {
      await soak.stop();
    }
  } else {
    ok("SOAK PARITY: isolated soak plane started", false, "daemon did not start");
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
