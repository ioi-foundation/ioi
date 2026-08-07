import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GoalSpaceResponseContractError,
  isCanonicalReceiptRef,
  isCanonicalWorkResultRef,
  validateActivationResponse,
  validateAdmittedActivationResponse,
  validateCollaborativeWorkGraph,
  validateGoalRun,
  validateGoalRunCreate,
  validateGoalRunList,
  validateGoalRunReconcile,
  validateGoalRunStart,
  validateOutcomeRoomCreate,
  validateOutcomeRoomList,
  validateOutcomeRoomMembership,
} from "../src/goal-space-response.ts";

function goalRun(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "ioi.goal-run.v1",
    goal_run_id: "gr_123",
    goal_ref: "goal://gr_123",
    receipt_refs: ["receipt://goal-run/gr_123/admission"],
    work_result_refs: [],
    ...overrides,
  };
}

function activation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ok: true,
    activation: { activation_ref: "goal-run-activation://gra_123", status: "draft" },
    activation_hash: `sha256:${"a".repeat(64)}`,
    goal_draft: { goal_text: "Research" },
    authority_decision: { decision: "review" },
    resolved_profile: { revision_ref: "profile://research/v1" },
    ...overrides,
  };
}

test("GoalRun and OutcomeRoom list emptiness is accepted only through a valid canonical envelope", () => {
  assert.deepEqual(validateGoalRunList({ ok: true, goal_runs: [] }), []);
  assert.deepEqual(
    validateOutcomeRoomList({
      schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
      outcome_rooms: [],
    }),
    [],
  );
  assert.throws(() => validateGoalRunList({ ok: true }), GoalSpaceResponseContractError);
  assert.throws(() => validateGoalRunList({ ok: true, goal_runs: {} }), GoalSpaceResponseContractError);
  assert.throws(() => validateOutcomeRoomList({ outcome_rooms: [] }), GoalSpaceResponseContractError);
});

test("GoalRun response validation rejects malformed ids, arrays, and reference tails", () => {
  assert.equal(validateGoalRun(goalRun()).goal_run_id, "gr_123");
  assert.throws(() => validateGoalRun(goalRun({ goal_run_id: "bad" })), GoalSpaceResponseContractError);
  assert.throws(() => validateGoalRun(goalRun({ receipt_refs: null })), GoalSpaceResponseContractError);
  assert.throws(() => validateGoalRun(goalRun({ work_result_refs: {} })), GoalSpaceResponseContractError);
  assert.throws(() => validateGoalRun(goalRun({ receipt_refs: ["receipt://"] })), GoalSpaceResponseContractError);
  assert.throws(
    () => validateGoalRun(goalRun({ work_result_refs: ["work-result://bad tail"] })),
    GoalSpaceResponseContractError,
  );
  assert.equal(isCanonicalReceiptRef("receipt://goal-run/gr_123/admission"), true);
  assert.equal(isCanonicalReceiptRef("receipt://"), false);
  assert.equal(isCanonicalWorkResultRef("work-result://goal-run/gr_123/result/1"), true);
  assert.equal(isCanonicalWorkResultRef("work-result://\n"), false);
});

test("GoalRun lifecycle success accepts only owner-shaped start and reconciliation envelopes", () => {
  assert.equal(validateGoalRunCreate({ ok: true, goal_run: goalRun({ status: "draft" }) }).goal_run_id, "gr_123");
  assert.throws(
    () => validateGoalRunCreate({ ok: true, goal_run: goalRun({ status: "complete" }) }),
    GoalSpaceResponseContractError,
  );
  const started = validateGoalRunStart(
    {
      ok: true,
      goal_run: goalRun({ status: "active" }),
      invocations: [],
      blockers: [],
      partial_result: false,
    },
    "gr_123",
  );
  assert.equal(started.run.status, "active");
  assert.throws(
    () =>
      validateGoalRunStart(
        { ok: true, goal_run: goalRun({ status: "complete" }), invocations: [], blockers: [], partial_result: false },
        "gr_123",
      ),
    GoalSpaceResponseContractError,
  );
  assert.equal(
    validateGoalRunReconcile(
      { ok: true, goal_run: goalRun({ status: "complete" }), reconciliation: { receipt_ref: "receipt://r" } },
      "gr_123",
    ).run.status,
    "complete",
  );
  assert.throws(
    () => validateGoalRunReconcile({ ok: true, goal_run: goalRun({ status: "active" }), reconciliation: {} }, "gr_123"),
    GoalSpaceResponseContractError,
  );
});

test("OutcomeRoom mutations require Agentgres receipt evidence and reciprocal GoalRun truth", () => {
  const room = {
    schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
    outcome_room_id: "outcome-room://or_123",
    status: "open",
    member_goal_run_refs: [],
  };
  const admission = { receipt_ref: "receipt://agentgres/room/1", operation_ref: "agentgres://room/operation/1" };
  assert.equal(
    validateOutcomeRoomCreate({ outcome_room: room, agentgres_admission: admission, replayed: false }).outcome_room_id,
    "outcome-room://or_123",
  );
  assert.throws(
    () => validateOutcomeRoomCreate({ outcome_room: room, replayed: false }),
    GoalSpaceResponseContractError,
  );
  assert.equal(
    validateOutcomeRoomMembership(
      {
        outcome_room: { ...room, member_goal_run_refs: ["goal://gr_123"] },
        goal_run: goalRun({ outcome_room_ref: "outcome-room://or_123" }),
        agentgres_admission: admission,
        membership_transition: "attach",
      },
      "or_123",
      "gr_123",
      "attach",
    ).run.outcome_room_ref,
    "outcome-room://or_123",
  );
  assert.throws(
    () =>
      validateOutcomeRoomMembership(
        {
          outcome_room: room,
          goal_run: goalRun({ outcome_room_ref: null }),
          agentgres_admission: admission,
          membership_transition: "attach",
        },
        "or_123",
        "gr_123",
        "attach",
      ),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOutcomeRoomMembership(
        {
          outcome_room: room,
          goal_run: goalRun({ outcome_room_ref: "outcome-room://or_123" }),
          agentgres_admission: admission,
          membership_transition: "attach",
        },
        "or_123",
        "gr_123",
        "attach",
      ),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOutcomeRoomCreate({
        outcome_room: room,
        agentgres_admission: { ...admission, operation_ref: "operation-without-agentgres-scheme" },
        replayed: false,
      }),
    GoalSpaceResponseContractError,
  );
});

test("activation review validation distinguishes retained drafts from fully receipted admission", () => {
  assert.equal(validateActivationResponse(activation()).goalRun, null);
  assert.throws(
    () => validateActivationResponse(activation({ activation_hash: "sha256:abc" })),
    GoalSpaceResponseContractError,
  );
  assert.throws(() => validateActivationResponse(activation(), "gra_other"), GoalSpaceResponseContractError);
  assert.throws(
    () =>
      validateActivationResponse(
        activation({ activation: { activation_ref: "goal-run-activation://gra_123", status: "admitted" } }),
      ),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () => validateAdmittedActivationResponse(activation({ goal_run: goalRun() })),
    GoalSpaceResponseContractError,
  );
  const admitted = validateAdmittedActivationResponse(
    activation({
      activation: { activation_ref: "goal-run-activation://gra_123", status: "admitted" },
      goal_run: goalRun(),
      receipts: { activation: { receipt_ref: "receipt://goal-run-activation/gra_123/admission" } },
    }),
    "gra_123",
    `sha256:${"a".repeat(64)}`,
  );
  assert.equal(admitted.goalRun?.goal_run_id, "gr_123");
  assert.throws(
    () =>
      validateAdmittedActivationResponse(
        activation({
          activation: { activation_ref: "goal-run-activation://gra_123", status: "admitted" },
          goal_run: goalRun(),
          receipts: { activation: { receipt_ref: "receipt://goal-run-activation/gra_123/admission" } },
        }),
        "gra_123",
        `sha256:${"b".repeat(64)}`,
      ),
    GoalSpaceResponseContractError,
  );
});

test("projection validation rejects an object-shaped false projection and accepts the complete empty graph", () => {
  assert.throws(() => validateCollaborativeWorkGraph({}, "or_123"), GoalSpaceResponseContractError);
  const graph = {
    schema_version: "ioi.applications.ioi-ai.collaborative-work-graph.v1",
    outcome_room_ref: "outcome-room://or_123",
    member_goal_run_refs: [],
    participant_refs: [],
    frontier_item_refs: [],
    work_claim_refs: [],
    attempt_refs: [],
    finding_refs: [],
    verifier_challenge_refs: [],
    work_result_refs: [],
    outcome_delta_refs: [],
    source_admission_receipt_refs: [],
    information_flow_label_refs: [],
  };
  assert.equal(
    validateCollaborativeWorkGraph({ collaborative_work_graph: graph }, "or_123").outcome_room_ref,
    "outcome-room://or_123",
  );
  assert.throws(
    () =>
      validateCollaborativeWorkGraph(
        { collaborative_work_graph: { ...graph, source_admission_receipt_refs: ["receipt://"] } },
        "or_123",
      ),
    GoalSpaceResponseContractError,
  );
});
