import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GoalSpaceResponseContractError,
  isCanonicalReceiptRef,
  isCanonicalWorkResultRef,
  validateActivationResponse,
  validateAdmittedActivationResponse,
  validateGoalRun,
  validateGoalRunCreate,
  validateGoalRunList,
  validateGoalRunReconcile,
  validateGoalRunStart,
  validateOrchestrationCompose,
  validateOrchestrationDetail,
  validateOrchestrationGraph,
  validateOrchestrationList,
  validateOrchestrationMembership,
  validateOrchestrationReplay,
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

const HEAD = `sha256:${"1".repeat(64)}`;
const NEXT_HEAD = `sha256:${"2".repeat(64)}`;
const SYSTEM = "system://estate/one";

function orchestration(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "ioi.applications.ioi-ai.orchestration.v1",
    orchestration_id: "orchestration://orc_456",
    orchestration_ref: "app-scope://ioi-ai/orchestration/orc_456",
    system_binding: {
      schema_version: "ioi.foundations.system-scoped-object-binding.v1",
      system_id: SYSTEM,
      parent_scope_ref: "app-scope://ioi-ai/orchestration/orc_456",
      proposed_or_issued_by_ref: "user://alice",
      payload_root: `sha256:${"a".repeat(64)}`,
      created_at: "2026-09-17T12:00:00Z",
      updated_at: null,
    },
    owner_ref: "org://local",
    composed_by_ref: "user://alice",
    thread_ref: "thread://thread_1",
    objective: "Coordinate one bounded outcome",
    objective_ref: "goal://gr_123",
    mode: "private_goal",
    coordination_topology: "hosted_admission",
    member_goal_run_refs: [],
    composed_at: "2026-09-17T12:00:00Z",
    status: "open",
    ...overrides,
  };
}

const admission = { receipt_ref: "receipt://event-stream/system-records/1", operation_ref: "agentgres://event-stream/1" };

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

test("GoalRun and orchestration list emptiness is accepted only through a valid canonical envelope", () => {
  assert.deepEqual(validateGoalRunList({ ok: true, goal_runs: [] }), []);
  assert.deepEqual(
    validateOrchestrationList({
      ok: true,
      schema_version: "ioi.applications.ioi-ai.orchestration.v1",
      systems: [],
      orchestrations: [],
      unavailable: [],
    }),
    { orchestrations: [], unavailable: [] },
  );
  const listed = validateOrchestrationList({
    ok: true,
    schema_version: "ioi.applications.ioi-ai.orchestration.v1",
    systems: [{ system_id: SYSTEM, count: 1 }],
    orchestrations: [{ system_id: SYSTEM, orchestration: orchestration(), head: HEAD, revisions: 1 }],
    unavailable: [{ system_id: "system://estate/two", status: 403, error: { error: { code: "request_resource_scope_required" } } }],
  });
  assert.equal(listed.orchestrations[0]?.head, HEAD);
  assert.equal(listed.unavailable[0]?.status, 403);
  assert.throws(() => validateGoalRunList({ ok: true }), GoalSpaceResponseContractError);
  assert.throws(() => validateGoalRunList({ ok: true, goal_runs: {} }), GoalSpaceResponseContractError);
  assert.throws(() => validateOrchestrationList({ orchestrations: [] }), GoalSpaceResponseContractError);
  assert.throws(
    () =>
      validateOrchestrationList({
        ok: true,
        schema_version: "ioi.applications.ioi-ai.orchestration.v1",
        orchestrations: [{ system_id: SYSTEM, orchestration: orchestration(), head: "latest", revisions: 1 }],
        unavailable: [],
      }),
    GoalSpaceResponseContractError,
  );
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

test("orchestration composition and membership require the seam's admission evidence and the exact head", () => {
  const composed = validateOrchestrationCompose({
    ok: true,
    system_id: SYSTEM,
    orchestration: orchestration(),
    head: HEAD,
    thread_id: "thread_1",
    replayed: false,
    admission,
  });
  assert.equal(composed.orchestration.orchestration_id, "orchestration://orc_456");
  assert.equal(composed.head, HEAD);
  assert.equal(composed.admission?.receipt_ref, admission.receipt_ref);
  assert.equal(
    validateOrchestrationCompose({ ok: true, system_id: SYSTEM, orchestration: orchestration(), head: HEAD, thread_id: "thread_1", replayed: true })
      .admission,
    null,
  );
  assert.throws(
    () => validateOrchestrationCompose({ ok: true, system_id: SYSTEM, orchestration: orchestration(), head: HEAD, thread_id: "thread_1", replayed: false }),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOrchestrationCompose({
        ok: true,
        system_id: SYSTEM,
        orchestration: orchestration({ member_goal_run_refs: ["goal://gr_123"] }),
        head: HEAD,
        thread_id: "thread_1",
        replayed: false,
        admission,
      }),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOrchestrationCompose({
        ok: true,
        system_id: SYSTEM,
        orchestration: orchestration({ thread_ref: "thread://thread_other" }),
        head: HEAD,
        thread_id: "thread_1",
        replayed: false,
        admission,
      }),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOrchestrationCompose({
        ok: true,
        system_id: SYSTEM,
        orchestration: orchestration({ orchestration_ref: "app-scope://ioi-ai/orchestration/orc_other" }),
        head: HEAD,
        thread_id: "thread_1",
        replayed: false,
        admission,
      }),
    GoalSpaceResponseContractError,
  );
  const detail = validateOrchestrationDetail(
    { ok: true, system_id: SYSTEM, orchestration: orchestration(), head: HEAD, revisions: 1, thread_id: "thread_1" },
    "orc_456",
  );
  assert.equal(detail.thread_id, "thread_1");
  assert.throws(
    () =>
      validateOrchestrationDetail(
        { ok: true, system_id: SYSTEM, orchestration: orchestration(), head: HEAD, revisions: 1, thread_id: "thread_1" },
        "orc_999",
      ),
    GoalSpaceResponseContractError,
  );
  const attached = validateOrchestrationMembership(
    {
      ok: true,
      system_id: SYSTEM,
      membership_transition: "attach",
      orchestration: orchestration({ member_goal_run_refs: ["goal://gr_123"] }),
      head: NEXT_HEAD,
      admission,
    },
    "orc_456",
    "gr_123",
    "attach",
  );
  assert.equal(attached.head, NEXT_HEAD);
  assert.throws(
    () =>
      validateOrchestrationMembership(
        { ok: true, system_id: SYSTEM, membership_transition: "attach", orchestration: orchestration(), head: NEXT_HEAD, admission },
        "orc_456",
        "gr_123",
        "attach",
      ),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOrchestrationMembership(
        {
          ok: true,
          system_id: SYSTEM,
          membership_transition: "detach",
          orchestration: orchestration({ member_goal_run_refs: ["goal://gr_123"] }),
          head: NEXT_HEAD,
          admission,
        },
        "orc_456",
        "gr_123",
        "detach",
      ),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () =>
      validateOrchestrationMembership(
        {
          ok: true,
          system_id: SYSTEM,
          membership_transition: "attach",
          orchestration: orchestration({ member_goal_run_refs: ["goal://gr_123"] }),
          head: NEXT_HEAD,
          admission: { ...admission, operation_ref: "operation-without-agentgres-scheme" },
        },
        "orc_456",
        "gr_123",
        "attach",
      ),
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

test("graph and replay validation accept the composed projection and reject a false or unrooted one", () => {
  assert.throws(() => validateOrchestrationGraph({}, "orc_456"), GoalSpaceResponseContractError);
  const graph = {
    system_id: SYSTEM,
    scope_ref: "app-scope://ioi-ai/orchestration/orc_456",
    root: "thread:thread_1",
    nodes: [
      { id: `system:${SYSTEM}`, kind: "system", ref: SYSTEM, owner: "system-genesis", detail: {} },
      { id: "thread:thread_1", kind: "thread", ref: "thread_1", owner: "thread-kernel", detail: { status: "active" } },
      {
        id: "record:r",
        kind: "record",
        ref: "r",
        owner: "system-record-seam",
        detail: { parent_scope_ref: "app-scope://ioi-ai/orchestration/orc_456" },
      },
    ],
    edges: [
      { from: `system:${SYSTEM}`, to: "thread:thread_1", kind: "coordinates" },
      { from: "thread:thread_1", to: "record:r", kind: "records" },
    ],
    nonclaim: "This graph mints no object and grants no authority.",
  };
  assert.equal(validateOrchestrationGraph({ ok: true, graph }, "orc_456").root, "thread:thread_1");
  assert.throws(() => validateOrchestrationGraph({ ok: true, graph }, "orc_999"), GoalSpaceResponseContractError);
  assert.throws(
    () => validateOrchestrationGraph({ ok: true, graph: { ...graph, root: "thread:thread_missing" } }, "orc_456"),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () => validateOrchestrationGraph({ ok: true, graph: { ...graph, edges: [{ from: "thread:thread_1", to: "record:absent", kind: "records" }] } }, "orc_456"),
    GoalSpaceResponseContractError,
  );
  assert.throws(
    () => validateOrchestrationGraph({ ok: true, graph: { ...graph, nonclaim: "the composition owns these" } }, "orc_456"),
    GoalSpaceResponseContractError,
  );
  const replay = validateOrchestrationReplay(
    {
      ok: true,
      system_id: SYSTEM,
      orchestration_id: "orchestration://orc_456",
      head: NEXT_HEAD,
      revisions: [orchestration(), orchestration({ member_goal_run_refs: ["goal://gr_123"] })],
      admissions: [admission, { ...admission, receipt_ref: "receipt://event-stream/system-records/2" }],
    },
    "orc_456",
  );
  assert.equal(replay.revisions.length, 2);
  assert.throws(
    () =>
      validateOrchestrationReplay(
        { ok: true, orchestration_id: "orchestration://orc_456", head: NEXT_HEAD, revisions: [orchestration()], admissions: [] },
        "orc_456",
      ),
    GoalSpaceResponseContractError,
  );
});
