import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeConversationArtifactSurface } from "./runtime-conversation-artifact-surface.mjs";

function harness() {
  const calls = [];
  const artifacts = new Map([
    ["artifact-one", { artifact_id: "artifact-one", title: "One" }],
  ]);
  const surface = createRuntimeConversationArtifactSurface({
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
  });
  const store = {
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

function assertConversationArtifactRustCoreRequired(error, {
  operation,
  operationKind,
  threadId = null,
  artifactId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_conversation_artifact_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.conversation_artifact_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  if (threadId) assert.equal(error.details.thread_id, threadId);
  if (artifactId) assert.equal(error.details.artifact_id, artifactId);
  assert.equal(
    error.details.evidence_refs.includes("runtime_conversation_artifact_control_js_facade_retired"),
    true,
  );
  assert.equal(error.details.evidence_refs.includes(`${operation}_js_facade_retired`), true);
  assert.equal(
    error.details.evidence_refs.includes("rust_daemon_core_conversation_artifact_control_required"),
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

test("conversation artifact mutation facades fail closed before JS artifact mutation", () => {
  const { calls, store, surface } = harness();

  assert.throws(
    () => surface.createConversationArtifact(store, "thread-one", { title: "Draft" }),
    (error) =>
      assertConversationArtifactRustCoreRequired(error, {
        operation: "conversation_artifact_create",
        operationKind: "artifact.conversation.create",
        threadId: "thread-one",
      }),
  );
  assert.throws(
    () => surface.performConversationArtifactAction(store, "artifact-one", { kind: "edit" }),
    (error) =>
      assertConversationArtifactRustCoreRequired(error, {
        operation: "conversation_artifact_action",
        operationKind: "artifact.conversation.action",
        artifactId: "artifact-one",
      }),
  );
  assert.throws(
    () => surface.exportConversationArtifact(store, "artifact-one", { format: "zip" }),
    (error) =>
      assertConversationArtifactRustCoreRequired(error, {
        operation: "conversation_artifact_export",
        operationKind: "artifact.conversation.export",
        artifactId: "artifact-one",
      }),
  );
  assert.throws(
    () => surface.promoteConversationArtifact(store, "artifact-one", { target: "canvas" }),
    (error) =>
      assertConversationArtifactRustCoreRequired(error, {
        operation: "conversation_artifact_promote",
        operationKind: "artifact.conversation.promote",
        artifactId: "artifact-one",
      }),
  );

  assert.deepEqual(calls, []);
});

test("conversation artifact surface delegates list, get, and revisions as reads", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.listConversationArtifacts(store, { thread_id: "thread-one" }), [
    { artifact_id: "artifact-one", title: "One" },
  ]);
  assert.deepEqual(surface.getConversationArtifact(store, "artifact-one"), {
    artifact_id: "artifact-one",
    title: "One",
  });
  assert.deepEqual(surface.listConversationArtifactRevisions(store, "artifact-one"), [
    { revision_id: "revision-one" },
  ]);

  assert.deepEqual(calls.map((call) => call.name), [
    "list",
    "get",
    "get",
    "revisions",
  ]);
});

test("conversation artifact surface preserves read not-found behavior", () => {
  const { store, surface } = harness();

  assert.throws(
    () => surface.getConversationArtifact(store, "missing"),
    /Conversation artifact not found: missing/,
  );
});
