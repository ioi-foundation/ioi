import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
  CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION,
  CONVERSATION_ARTIFACT_SCHEMA_VERSION,
  ConversationArtifactStore,
} from "./conversation-artifacts.mjs";

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, String(value));
}

function seedConversationArtifact(stateDir, overrides = {}) {
  const artifactId = overrides.id ?? "artifact_canonical_web";
  const revisionId = overrides.revision_id ?? "rev_001";
  const previewPath = path.join(
    stateDir,
    "conversation-artifacts",
    "assets",
    artifactId,
    revisionId,
    "index.html",
  );
  writeText(previewPath, "<!doctype html><main><h1>Canonical website</h1></main>");
  const record = {
    schema_version: CONVERSATION_ARTIFACT_SCHEMA_VERSION,
    object: "ioi.conversation_artifact",
    id: artifactId,
    artifact_id: artifactId,
    thread_id: overrides.thread_id ?? "thread-one",
    turn_id: overrides.turn_id ?? "turn-one",
    artifact_class: overrides.artifact_class ?? "static_html_js",
    output_modality: overrides.output_modality ?? "web_preview",
    title: overrides.title ?? "Canonical website",
    status: "preview_ready",
    state_label: "Preview ready",
    summary: "Already admitted Rust/Agentgres projection.",
    generated_files: null,
    renderer: {
      kind: "sandboxed_web_preview",
      label: "Static HTML/CSS/JS",
      sandboxed: true,
      network: "deny_by_default",
      filesystem: "no_ambient_access",
      actions: "typed_daemon_requests",
    },
    source_refs: [],
    original_refs: [],
    projection_refs: [],
    preview_refs: [
      {
        ref: `artifact://${artifactId}/${revisionId}/preview/index.html`,
        role: "preview",
        path: `assets/${artifactId}/${revisionId}/index.html`,
        file_name: "index.html",
        media_type: "text/html",
      },
    ],
    trace_refs: [`trace:conversation-artifact:${artifactId}`],
    policy_refs: [
      "policy:artifact.renderer.sandbox",
      "policy:artifact.actions.daemon_typed",
      "policy:artifact.chat.hide_raw_refs",
    ],
    receipt_refs: ["receipt_artifact_create"],
    action_schema_version: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
    actions: ["edit", "rebuild", "export", "promote", "rollback"],
    revisions: [
      {
        schema_version: CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION,
        object: "ioi.conversation_artifact_revision",
        id: revisionId,
        revision_id: revisionId,
        artifact_id: artifactId,
        status: "ready",
        summary: "Initial admitted projection.",
        source_refs: [],
        original_refs: [],
        projection_refs: [],
        preview_refs: [
          {
            ref: `artifact://${artifactId}/${revisionId}/preview/index.html`,
            role: "preview",
            path: `assets/${artifactId}/${revisionId}/index.html`,
            file_name: "index.html",
            media_type: "text/html",
          },
        ],
        log_refs: [],
        rollback_refs: [],
        created_at: "2026-06-08T00:00:00.000Z",
      },
    ],
    latest_revision_id: revisionId,
    export_refs: [],
    promotion_refs: [],
    fidelity: null,
    created_at: overrides.created_at ?? "2026-06-08T00:00:00.000Z",
    updated_at: overrides.updated_at ?? "2026-06-08T00:00:00.000Z",
    evidence: {
      runtimeOwned: true,
      guiOwnsExecutionSemantics: false,
      rawRefsHiddenFromChat: true,
    },
  };
  writeJson(path.join(stateDir, "artifacts", `${artifactId}.json`), record);
  return record;
}

function assertConversationArtifactStoreRustCoreRequired(error, {
  operation,
  operationKind,
  artifactId = null,
}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_conversation_artifact_store_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.conversation_artifact_control");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  if (artifactId) assert.equal(error.details.artifact_id, artifactId);
  assert.equal(
    error.details.evidence_refs.includes("runtime_conversation_artifact_store_js_writers_retired"),
    true,
  );
  assert.equal(error.details.evidence_refs.includes(`${operation}_js_store_writer_retired`), true);
  assert.equal(
    error.details.evidence_refs.includes("rust_daemon_core_conversation_artifact_control_required"),
    true,
  );
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "artifactId",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(error.details, key), false, `retired detail alias ${key} must be absent`);
  }
  return true;
}

test("conversation artifact direct store mutations fail closed before JS artifact-state writes", async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), "ioi-conversation-artifact-"));
  try {
    const store = new ConversationArtifactStore(stateDir, {
      commitRuntimeArtifactState(request) {
        throw new Error(`commit must not be reached: ${request.operation_kind}`);
      },
    });

    assert.throws(
      () => store.create({ title: "Draft" }),
      (error) =>
        assertConversationArtifactStoreRustCoreRequired(error, {
          operation: "conversation_artifact_create",
          operationKind: "artifact.conversation.create",
        }),
    );
    assert.throws(
      () => store.action("artifact-one", { action: "edit" }),
      (error) =>
        assertConversationArtifactStoreRustCoreRequired(error, {
          operation: "conversation_artifact_action",
          operationKind: "artifact.conversation.action",
          artifactId: "artifact-one",
        }),
    );
    assert.throws(
      () => store.exportArtifact("artifact-one", { format: "zip" }),
      (error) =>
        assertConversationArtifactStoreRustCoreRequired(error, {
          operation: "conversation_artifact_export",
          operationKind: "artifact.conversation.export",
          artifactId: "artifact-one",
        }),
    );
    assert.throws(
      () => store.promoteArtifact("artifact-one", { target: "canvas" }),
      (error) =>
        assertConversationArtifactStoreRustCoreRequired(error, {
          operation: "conversation_artifact_promote",
          operationKind: "artifact.conversation.promote",
          artifactId: "artifact-one",
        }),
    );

    assert.deepEqual(fs.readdirSync(path.join(stateDir, "conversation-artifacts", "records")), []);
    assert.deepEqual(fs.readdirSync(path.join(stateDir, "conversation-artifacts", "receipts")), []);
    assert.equal(fs.existsSync(path.join(stateDir, "artifacts")), false);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("conversation artifact store projects canonical snake_case admitted records without retired aliases", async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), "ioi-conversation-artifact-"));
  try {
    const seeded = seedConversationArtifact(stateDir);
    seedConversationArtifact(stateDir, {
      id: "artifact_second",
      revision_id: "rev_002",
      thread_id: "thread-two",
      title: "Second canonical artifact",
      updated_at: "2026-06-08T00:01:00.000Z",
    });
    const store = new ConversationArtifactStore(stateDir);

    const artifact = store.get(seeded.id);
    const revision = artifact.revisions[0];
    const ref = artifact.preview_refs[0];

    assert.equal(artifact.schema_version, "ioi.conversation_artifact.v1");
    assert.equal(artifact.thread_id, "thread-one");
    assert.equal(artifact.turn_id, "turn-one");
    assert.equal(artifact.artifact_class, "static_html_js");
    assert.equal(artifact.output_modality, "web_preview");
    assert.equal(artifact.preview_inline.media_type, "text/html");
    assert.match(artifact.preview_inline.text, /Canonical website/);
    assert.equal(ref.media_type, "text/html");
    assert.equal(ref.file_name, "index.html");
    assert.equal(revision.schema_version, "ioi.conversation_artifact_revision.v1");
    assert.equal(revision.artifact_id, artifact.id);
    assert.deepEqual(store.revisions(artifact.id), artifact.revisions);

    const retiredKeys = [
      "schemaVersion",
      "artifactId",
      "threadId",
      "turnId",
      "artifactClass",
      "outputModality",
      "stateLabel",
      "generatedFiles",
      "sourceRefs",
      "originalRefs",
      "projectionRefs",
      "previewRefs",
      "traceRefs",
      "policyRefs",
      "receiptRefs",
      "actionSchemaVersion",
      "latestRevisionId",
      "exportRefs",
      "promotionRefs",
      "createdAt",
      "updatedAt",
      "previewInline",
    ];
    for (const key of retiredKeys) {
      assert.equal(Object.hasOwn(artifact, key), false, `retired artifact alias ${key} must be absent`);
    }
    for (const key of ["schemaVersion", "revisionId", "artifactId", "sourceRefs", "originalRefs", "projectionRefs", "previewRefs", "logRefs", "rollbackRefs", "createdAt"]) {
      assert.equal(Object.hasOwn(revision, key), false, `retired revision alias ${key} must be absent`);
    }
    for (const key of ["fileName", "mediaType"]) {
      assert.equal(Object.hasOwn(ref, key), false, `retired ref alias ${key} must be absent`);
    }

    assert.equal(store.list({ thread_id: "thread-one" }).length, 1);
    assert.equal(store.list({ threadId: "thread-one" }).length, 2);
    assert.equal(new ConversationArtifactStore(stateDir).get(artifact.id)?.artifact_id, artifact.id);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});
