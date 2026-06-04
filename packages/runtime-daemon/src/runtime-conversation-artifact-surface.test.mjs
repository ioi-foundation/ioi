import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeConversationArtifactSurface } from "./runtime-conversation-artifact-surface.mjs";

function harness() {
  const calls = [];
  const artifacts = new Map([
    ["artifact-one", { artifactId: "artifact-one", title: "One" }],
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
        return { artifactId: "artifact-created", ...input };
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
        return [{ revisionId: "revision-one" }];
      },
    },
  };
  return { calls, store, surface };
}

test("conversation artifact surface delegates create, list, get, and revisions", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.createConversationArtifact(store, "thread-one", { title: "Draft" }), {
    artifactId: "artifact-created",
    title: "Draft",
    threadId: "thread-one",
  });
  assert.deepEqual(surface.listConversationArtifacts(store, { threadId: "thread-one" }), [
    { artifactId: "artifact-one", title: "One" },
  ]);
  assert.deepEqual(surface.getConversationArtifact(store, "artifact-one"), {
    artifactId: "artifact-one",
    title: "One",
  });
  assert.deepEqual(surface.listConversationArtifactRevisions(store, "artifact-one"), [
    { revisionId: "revision-one" },
  ]);

  assert.deepEqual(calls.map((call) => call.name), [
    "create",
    "list",
    "get",
    "get",
    "revisions",
  ]);
});

test("conversation artifact surface preserves action not-found behavior", () => {
  const { store, surface } = harness();

  assert.deepEqual(surface.performConversationArtifactAction(store, "artifact-one", { kind: "edit" }), {
    actionId: "action-one",
    input: { kind: "edit" },
  });
  assert.deepEqual(surface.exportConversationArtifact(store, "artifact-one", { format: "zip" }), {
    exportId: "export-one",
    input: { format: "zip" },
  });
  assert.deepEqual(surface.promoteConversationArtifact(store, "artifact-one", { target: "canvas" }), {
    promotionId: "promotion-one",
    input: { target: "canvas" },
  });

  assert.throws(
    () => surface.getConversationArtifact(store, "missing"),
    /Conversation artifact not found: missing/,
  );
  assert.throws(
    () => surface.performConversationArtifactAction(store, "missing", {}),
    /Conversation artifact not found: missing/,
  );
  assert.throws(
    () => surface.exportConversationArtifact(store, "missing", {}),
    /Conversation artifact not found: missing/,
  );
  assert.throws(
    () => surface.promoteConversationArtifact(store, "missing", {}),
    /Conversation artifact not found: missing/,
  );
});
