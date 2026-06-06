import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { ConversationArtifactStore } from "./conversation-artifacts.mjs";

test("static website artifacts require model-authored source", async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), "ioi-conversation-artifact-"));
  try {
    const store = new ConversationArtifactStore(stateDir);
    assert.throws(
      () => store.create({
        artifact_class: "static_html_js",
        title: "Post-quantum computers website",
        prompt: "Create a website that explains post-quantum computers",
      }),
      /require model-authored HTML\/CSS\/JS source/
    );

    const imported = store.create({
      artifact_class: "imported_document",
      title: "Imported document fixture",
      prompt: "Preserve this document and export it.",
    }).artifact;
    store.action(imported.id, { action: "export" });
    const exported = store.list().find((entry) => entry.id === imported.id);
    assert.equal(exported.export_refs[0].media_type, "application/vnd.oasis.opendocument.text");

    const patch = store.create({
      artifact_class: "diff_patch",
      title: "Patch fixture",
      prompt: "Review and rollback this patch.",
    }).artifact;
    store.action(patch.id, { action: "approve" });
    store.action(patch.id, { action: "apply" });
    store.action(patch.id, { action: "rollback" });
    const rolledBack = store.list().find((entry) => entry.id === patch.id);
    assert.equal(rolledBack.status, "rolled_back");
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("static website artifacts can use model-authored HTML/CSS/JS", async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), "ioi-conversation-artifact-"));
  try {
    const store = new ConversationArtifactStore(stateDir);
    const { artifact } = store.create({
      artifact_class: "static_html_js",
      title: "Neighborhood bakery website",
      prompt: "Create a website about a neighborhood bakery",
      generated_files: {
        title: "Neighborhood bakery website",
        summary: "Fresh model-authored bakery landing page.",
        html: "<main><section class=\"hero\"><h1>Morning Crumb Bakery</h1><p>Small-batch bread, pastry, and coffee from a corner bakery.</p></section></main>",
        css: ".hero{min-height:70vh;background:#f7e2c4;color:#2d1b11;padding:48px}",
        js: "document.body.dataset.ready='true';",
      },
    });

    assert.equal(artifact.preview_inline.media_type, "text/html");
    assert.match(artifact.preview_inline.text, /Morning Crumb Bakery/);
    assert.match(artifact.preview_inline.text, /small-batch bread/i);
    assert.match(artifact.preview_inline.text, /<style>\.hero/);
    assert.match(artifact.preview_inline.text, /document\.body\.dataset\.ready/);
    assert.doesNotMatch(artifact.preview_inline.text, /What it means/);

    assert.throws(
      () => store.action(artifact.id, {
        action: "rebuild",
        generated_files: {
          title: "Neighborhood bakery website",
          html: "",
        },
      }),
      /require model-authored HTML\/CSS\/JS source/
    );
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("conversation artifact store emits canonical snake_case without retired aliases", async () => {
  const stateDir = await mkdtemp(path.join(tmpdir(), "ioi-conversation-artifact-"));
  try {
    const store = new ConversationArtifactStore(stateDir);
    const { artifact, receipt } = store.create({
      artifact_class: "static_html_js",
      thread_id: "thread-one",
      turn_id: "turn-one",
      output_modality: "web_preview",
      title: "Canonical website",
      prompt: "Create a canonical website.",
      generated_files: {
        title: "Canonical website",
        html: "<main><h1>Canonical website</h1></main>",
      },
    });
    store.create({
      artifact_class: "markdown_html_report",
      thread_id: "thread-two",
      title: "Second canonical artifact",
      prompt: "Create a second artifact.",
    });

    const actionResult = store.action(artifact.id, { action: "export" });
    const revision = artifact.revisions[0];
    const ref = artifact.preview_refs[0];
    const promotionResult = store.action(artifact.id, { action: "promote" });
    const promotion = promotionResult.artifact.promotion_refs[0];

    assert.equal(artifact.schema_version, "ioi.conversation_artifact.v1");
    assert.equal(artifact.thread_id, "thread-one");
    assert.equal(artifact.turn_id, "turn-one");
    assert.equal(artifact.artifact_class, "static_html_js");
    assert.equal(artifact.output_modality, "web_preview");
    assert.equal(artifact.preview_inline.media_type, "text/html");
    assert.equal(ref.media_type, "text/html");
    assert.equal(ref.file_name, "index.html");
    assert.equal(revision.schema_version, "ioi.conversation_artifact_revision.v1");
    assert.equal(revision.artifact_id, artifact.id);
    assert.equal(actionResult.schema_version, "ioi.conversation_artifact_action.v1");
    assert.equal(actionResult.artifact.export_refs[0].media_type, "text/html");
    assert.equal(promotion.created_at, promotionResult.artifact.promotion_refs[0].created_at);
    assert.equal(receipt.artifact_id, artifact.id);

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
      assert.equal(Object.hasOwn(actionResult.artifact, key), false, `retired action artifact alias ${key} must be absent`);
    }
    for (const key of ["schemaVersion", "revisionId", "artifactId", "sourceRefs", "originalRefs", "projectionRefs", "previewRefs", "logRefs", "rollbackRefs", "createdAt"]) {
      assert.equal(Object.hasOwn(revision, key), false, `retired revision alias ${key} must be absent`);
    }
    for (const key of ["fileName", "mediaType"]) {
      assert.equal(Object.hasOwn(ref, key), false, `retired ref alias ${key} must be absent`);
    }
    for (const key of ["schemaVersion", "policyVerdict"]) {
      assert.equal(Object.hasOwn(actionResult, key), false, `retired action result alias ${key} must be absent`);
    }
    for (const key of ["artifactId", "policyRefs", "createdAt"]) {
      assert.equal(Object.hasOwn(receipt, key), false, `retired receipt alias ${key} must be absent`);
    }
    assert.equal(Object.hasOwn(promotion, "createdAt"), false);

    assert.equal(store.list({ thread_id: "thread-one" }).length, 1);
    assert.equal(store.list({ threadId: "thread-one" }).length, 2);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});
