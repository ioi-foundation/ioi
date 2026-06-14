import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeConversationArtifactSurface } from "./runtime-conversation-artifact-surface.mjs";

function harness(options = {}) {
  const calls = [];
  const artifacts = new Map([
    ["artifact-one", { id: "artifact-one", thread_id: "thread-one", title: "One", revisions: [{ revision_id: "rev-one" }] }],
    ["artifact-two", { id: "artifact-two", thread_id: "thread-two", title: "Two", revisions: [{ revision_id: "rev-two" }] }],
  ]);
  const surface = createRuntimeConversationArtifactSurface({
    contextPolicyCore: options.contextPolicyCore,
  });
  const store = {
    stateDir: "/runtime-state",
    commitRuntimeArtifactState(request) {
      calls.push({ name: "commitRuntimeArtifactState", request });
      return {
        artifact_id: request.artifact_id,
        object_ref: `artifact://${request.artifact_id}`,
        content_hash: `sha256:${request.artifact_id}`,
        admission_hash: `admission:${request.artifact_id}`,
        commit_hash: `commit:${request.artifact_id}`,
        written_record: request.artifact,
      };
    },
    conversationArtifacts: {
      action(artifactId, input) {
        calls.push({ name: "action", artifactId, input });
        return artifacts.has(artifactId) ? { actionId: "action-one", input } : null;
      },
      create(input) {
        calls.push({ name: "create", input });
        return { artifact_id: "artifact-created", ...input };
      },
      exportArtifact(artifactId, input) {
        calls.push({ name: "exportArtifact", artifactId, input });
        return artifacts.has(artifactId) ? { exportId: "export-one", input } : null;
      },
      get(artifactId) {
        calls.push({ name: "get", artifactId });
        return artifacts.get(artifactId) ?? null;
      },
      list(query) {
        calls.push({ name: "list", query });
        return [...artifacts.values()];
      },
      promoteArtifact(artifactId, input) {
        calls.push({ name: "promoteArtifact", artifactId, input });
        return artifacts.has(artifactId) ? { promotionId: "promotion-one", input } : null;
      },
      revisions(artifactId) {
        calls.push({ name: "revisions", artifactId });
        return [{ revision_id: "revision-one" }];
      },
    },
  };
  return { calls, store, surface };
}

function assertConversationArtifactControlRequired(error, {
  operation,
  operationKind,
  threadId = null,
  artifactId = null,
  code = "runtime_conversation_artifact_control_rust_core_required",
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, code);
  assert.equal(error.details.rust_core_boundary, "runtime.conversation_artifact_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  if (threadId) assert.equal(error.details.thread_id, threadId);
  if (artifactId) assert.equal(error.details.artifact_id, artifactId);
  assert.equal(
    error.details.evidence_refs.includes("runtime_conversation_artifact_control_js_facade_retired"),
    true,
  );
  assert.equal(
    error.details.evidence_refs.includes("runtime_conversation_artifact_control_rust_owned"),
    true,
  );
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "threadId",
    "artifactId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(error.details, key), false, `retired detail alias ${key} must be absent`);
  }
  return true;
}

function assertConversationArtifactProjectionMissing(error, {
  operation,
  operationKind,
  projectionKind,
  threadId = null,
  artifactId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_conversation_artifact_read_projection_rust_projection_missing");
  assert.equal(error.details.rust_core_boundary, "runtime.conversation_artifact_projection");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.projection_kind, projectionKind);
  if (threadId) assert.equal(error.details.thread_id, threadId);
  if (artifactId) assert.equal(error.details.artifact_id, artifactId);
  assert.equal(
    error.details.evidence_refs.includes("runtime_conversation_artifact_read_projection_rust_owned"),
    true,
  );
  assert.equal(
    error.details.evidence_refs.includes("conversation_artifact_read_projection_js_facade_retired"),
    true,
  );
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "projectionKind",
    "threadId",
    "artifactId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(error.details, key), false, `retired detail alias ${key} must be absent`);
  }
  return true;
}

test("conversation artifact mutation plans in Rust and commits artifact truth without JS writers", () => {
  const planCalls = [];
  const { calls, store, surface } = harness({
    contextPolicyCore: {
      planRuntimeConversationArtifactControl(request) {
        planCalls.push(request);
        const artifactId =
          request.artifact_id ?? `artifact-${request.operation.replace("conversation_artifact_", "")}`;
        const artifact = {
          id: artifactId,
          artifact_id: artifactId,
          thread_id: request.thread_id ?? request.artifact?.thread_id ?? "thread-one",
          title: request.request.title ?? request.artifact?.title ?? "Planned",
          receipt_refs: [`receipt-${artifactId}`],
          evidence_refs: ["runtime_conversation_artifact_control_rust_owned"],
          revisions: [{ revision_id: `revision-${artifactId}` }],
        };
        return {
          source: "rust_runtime_conversation_artifact_control_command",
          backend: "rust_policy",
          operation: request.operation,
          operation_kind: request.operation_kind,
          thread_id: artifact.thread_id,
          artifact_id: artifactId,
          artifact,
          result: {
            status: "planned",
            operation_kind: request.operation_kind,
            artifact_id: artifactId,
            artifact,
          },
          receipt_refs: [`receipt-${artifactId}`],
          policy_decision_refs: [`policy-${artifactId}`],
          evidence_refs: ["runtime_conversation_artifact_control_rust_owned"],
        };
      },
    },
  });

  assert.equal(
    surface.createConversationArtifact(store, "thread-one", {
      title: "Draft",
      created_at: "2026-06-12T00:00:00.000Z",
      idempotency_key: "canonical",
      threadId: "retired-thread",
      artifactId: "retired-artifact",
      idempotencyKey: "retired-key",
    }).commit.commit_hash,
    "commit:artifact-create",
  );
  assert.equal(
    surface.performConversationArtifactAction(store, "artifact-one", {
      action_kind: "edit",
      kind: "retired-kind",
      artifactId: "retired-artifact",
    }).commit.commit_hash,
    "commit:artifact-one",
  );
  assert.equal(
    surface.exportConversationArtifact(store, "artifact-one", {
      export_format: "zip",
      format: "retired-format",
    }).commit.commit_hash,
    "commit:artifact-one",
  );
  assert.equal(
    surface.promoteConversationArtifact(store, "artifact-one", {
      promotion_target: "canvas",
      target: "retired-target",
    }).commit.commit_hash,
    "commit:artifact-one",
  );

  assert.equal(planCalls.length, 4);
  assert.deepEqual(
    planCalls.map(({ operation, operation_kind }) => ({ operation, operation_kind })),
    [
      { operation: "conversation_artifact_create", operation_kind: "artifact.conversation.create" },
      { operation: "conversation_artifact_action", operation_kind: "artifact.conversation.action" },
      { operation: "conversation_artifact_export", operation_kind: "artifact.conversation.export" },
      { operation: "conversation_artifact_promote", operation_kind: "artifact.conversation.promote" },
    ],
  );
  assert.equal(planCalls[0].thread_id, "thread-one");
  assert.equal(planCalls[0].request.idempotency_key, "canonical");
  for (const request of planCalls.map((call) => call.request)) {
    for (const alias of ["threadId", "artifactId", "createdAt", "idempotencyKey", "kind", "format", "target"]) {
      assert.equal(Object.hasOwn(request, alias), false, `retired request alias ${alias} must be absent`);
    }
  }
  assert.deepEqual(
    calls.map((call) => call.name),
    [
      "list",
      "commitRuntimeArtifactState",
      "list",
      "commitRuntimeArtifactState",
      "list",
      "commitRuntimeArtifactState",
      "list",
      "commitRuntimeArtifactState",
    ],
  );
  assert.equal(
    calls.some((call) => ["create", "action", "exportArtifact", "promoteArtifact"].includes(call.name)),
    false,
  );
  assert.equal(
    calls[1].request.artifact.evidence_refs?.includes("runtime_conversation_artifact_control_rust_owned"),
    true,
  );
});

test("conversation artifact mutation fails before artifact lookup without Rust planner", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.createConversationArtifact(store, "thread-one", { title: "Draft" }),
    (error) =>
      assertConversationArtifactControlRequired(error, {
        operation: "conversation_artifact_create",
        operationKind: "artifact.conversation.create",
        threadId: "thread-one",
      }),
  );

  assert.deepEqual(calls, []);
});

test("conversation artifact mutation fails before artifact lookup without Agentgres commit", () => {
  const planCalls = [];
  const { calls, store, surface } = harness({
    contextPolicyCore: {
      planRuntimeConversationArtifactControl(request) {
        planCalls.push(request);
        return {};
      },
    },
  });
  delete store.commitRuntimeArtifactState;

  assert.throws(
    () => surface.performConversationArtifactAction(store, "artifact-one", { action_kind: "edit" }),
    (error) =>
      assertConversationArtifactControlRequired(error, {
        operation: "conversation_artifact_action",
        operationKind: "artifact.conversation.action",
        artifactId: "artifact-one",
        code: "runtime_conversation_artifact_agentgres_commit_required",
      }),
  );

  assert.deepEqual(calls, []);
  assert.deepEqual(planCalls, []);
});

test("conversation artifact mutation rejects invalid Rust plans before commit", () => {
  const { calls, store, surface } = harness({
    contextPolicyCore: {
      planRuntimeConversationArtifactControl() {
        return {
          operation_kind: "artifact.conversation.action",
          result: { status: "planned" },
        };
      },
    },
  });

  assert.throws(
    () => surface.performConversationArtifactAction(store, "artifact-one", { action_kind: "edit" }),
    (error) =>
      error.code === "runtime_conversation_artifact_control_plan_invalid" &&
      error.status === 502 &&
      error.details.rust_core_boundary === "runtime.conversation_artifact_control",
  );

  assert.deepEqual(calls, [{ name: "list", query: {} }]);
});

test("conversation artifact read projections fail closed before JS artifact reads without Rust", () => {
  const { calls, store, surface } = harness();
  const cases = [
    {
      operation: "conversation_artifact_list",
      operationKind: "runtime.conversation_artifact_projection.list",
      projectionKind: "list",
      threadId: "thread-one",
      call: () => surface.listConversationArtifacts(store, { thread_id: "thread-one" }),
    },
    {
      operation: "conversation_artifact_get",
      operationKind: "runtime.conversation_artifact_projection.get",
      projectionKind: "get",
      artifactId: "artifact-one",
      call: () => surface.getConversationArtifact(store, "artifact-one"),
    },
    {
      operation: "conversation_artifact_revision_list",
      operationKind: "runtime.conversation_artifact_projection.revisions",
      projectionKind: "revisions",
      artifactId: "artifact-one",
      call: () => surface.listConversationArtifactRevisions(store, "artifact-one"),
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      testCase.call,
      (error) => assertConversationArtifactProjectionMissing(error, testCase),
    );
  }

  assert.deepEqual(calls, []);
});

test("conversation artifact read projections return Rust daemon-core projections", () => {
  const projectionCalls = [];
  const rustArtifacts = [
    { id: "artifact-one", thread_id: "thread-one", title: "One", revisions: [{ revision_id: "rev-one" }] },
    { id: "artifact-two", thread_id: "thread-two", title: "Two", revisions: [{ revision_id: "rev-two" }] },
  ];
  const { calls, store, surface } = harness({
    contextPolicyCore: {
      projectRuntimeConversationArtifactProjection(request) {
        projectionCalls.push(request);
        if (request.projection_kind === "list") {
          return {
            projection_kind: "list",
            projection: rustArtifacts.filter((record) => record.thread_id === request.thread_id),
          };
        }
        if (request.projection_kind === "get") {
          return {
            projection_kind: "get",
            projection: rustArtifacts.find((record) => record.id === request.artifact_id) ?? null,
          };
        }
        return {
          projection_kind: "revisions",
          projection:
            rustArtifacts.find((record) => record.id === request.artifact_id)?.revisions ?? [],
        };
      },
    },
  });

  assert.deepEqual(surface.listConversationArtifacts(store, { thread_id: "thread-one" }), [
    { id: "artifact-one", thread_id: "thread-one", title: "One", revisions: [{ revision_id: "rev-one" }] },
  ]);
  assert.deepEqual(surface.getConversationArtifact(store, "artifact-two"), {
    id: "artifact-two",
    thread_id: "thread-two",
    title: "Two",
    revisions: [{ revision_id: "rev-two" }],
  });
  assert.deepEqual(surface.listConversationArtifactRevisions(store, "artifact-one"), [
    { revision_id: "rev-one" },
  ]);

  assert.deepEqual(calls, []);
  assert.equal(projectionCalls.length, 3);
  assert.deepEqual(
    projectionCalls.map((request) => request.operation),
    [
      "runtime_conversation_artifact_projection",
      "runtime_conversation_artifact_projection",
      "runtime_conversation_artifact_projection",
    ],
  );
  assert.deepEqual(
    projectionCalls.map((request) => request.projection_kind),
    ["list", "get", "revisions"],
  );
  assert.equal(projectionCalls[0].thread_id, "thread-one");
  assert.equal(projectionCalls[1].artifact_id, "artifact-two");
  assert.equal(projectionCalls[0].state_dir, "/runtime-state");
  assert.equal(projectionCalls.every((request) => request.state_dir === "/runtime-state"), true);
  assert.equal(
    projectionCalls.every((request) => Object.hasOwn(request, "projection") === false),
    true,
  );
  assert.equal(
    projectionCalls[0].evidence_refs.includes("conversation_artifact_read_projection_js_facade_retired"),
    true,
  );
});
