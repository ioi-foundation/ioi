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
        artifactClass: "static_html_js",
        title: "Post-quantum computers website",
        prompt: "Create a website that explains post-quantum computers",
      }),
      /require model-authored HTML\/CSS\/JS source/
    );

    const imported = store.create({
      artifactClass: "imported_document",
      title: "Imported document fixture",
      prompt: "Preserve this document and export it.",
    }).artifact;
    store.action(imported.id, { action: "export" });
    const exported = store.list().find((entry) => entry.id === imported.id);
    assert.equal(exported.exportRefs[0].mediaType, "application/vnd.oasis.opendocument.text");

    const patch = store.create({
      artifactClass: "diff_patch",
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
      artifactClass: "static_html_js",
      title: "Neighborhood bakery website",
      prompt: "Create a website about a neighborhood bakery",
      generatedFiles: {
        title: "Neighborhood bakery website",
        summary: "Fresh model-authored bakery landing page.",
        html: "<main><section class=\"hero\"><h1>Morning Crumb Bakery</h1><p>Small-batch bread, pastry, and coffee from a corner bakery.</p></section></main>",
        css: ".hero{min-height:70vh;background:#f7e2c4;color:#2d1b11;padding:48px}",
        js: "document.body.dataset.ready='true';",
      },
    });

    assert.equal(artifact.previewInline.mediaType, "text/html");
    assert.match(artifact.previewInline.text, /Morning Crumb Bakery/);
    assert.match(artifact.previewInline.text, /small-batch bread/i);
    assert.match(artifact.previewInline.text, /<style>\.hero/);
    assert.match(artifact.previewInline.text, /document\.body\.dataset\.ready/);
    assert.doesNotMatch(artifact.previewInline.text, /What it means/);

    assert.throws(
      () => store.action(artifact.id, {
        action: "rebuild",
        generatedFiles: {
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
