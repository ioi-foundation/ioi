import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const { createStudioArtifactPreview } = require("./artifact-preview.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

function createPreview(options = {}) {
  return createStudioArtifactPreview({
    escapeHtml,
    stringValue,
    firstArray: (value) => Array.isArray(value) ? value : [],
    studioRecordValue: (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {},
    getPageNonce: () => "nonce-test",
    ...options,
  });
}

test("artifact preview labels website and generic artifact classes", () => {
  const preview = createPreview();

  assert.equal(preview.studioArtifactClassLabel({
    artifactClass: "static_html_js",
    outputModality: "website",
  }), "Website");
  assert.equal(preview.studioArtifactClassLabel({
    artifact_class: "static_html_js",
    summary: "HTML report",
  }), "HTML report");
  assert.equal(preview.studioArtifactClassLabel({ artifactClass: "browser_observation" }), "Browser capture");
  assert.equal(preview.studioArtifactClassLabel({ artifactClass: "custom_report" }), "Custom Report");
});

test("artifact preview chooses preview labels by media type", () => {
  const preview = createPreview();

  assert.equal(preview.studioArtifactPreviewLabel({}), "Preview pending");
  assert.equal(preview.studioArtifactPreviewLabel({
    artifactClass: "static_html_js",
    outputModality: "landing page",
    previewRefs: [{ mediaType: "text/html" }],
  }), "Website preview");
  assert.equal(preview.studioArtifactPreviewLabel({
    artifactClass: "pdf_preview",
    preview_refs: [{ media_type: "application/pdf" }],
  }), "PDF preview");
  assert.equal(preview.studioArtifactPreviewLabel({
    previewRefs: [{ mediaType: "application/json" }],
  }), "Data preview");
});

test("artifact preview injects missing CSP nonces into inline HTML previews", () => {
  const preview = createPreview();
  const srcdoc = preview.studioArtifactPreviewSrcdoc("<style>body{}</style><script>run()</script>", "abc");

  assert.match(srcdoc, /<style nonce="abc">/);
  assert.match(srcdoc, /<script nonce="abc">/);

  const iframe = preview.studioArtifactInlinePreview({
    title: "Demo <site>",
    previewInline: {
      mediaType: "text/html",
      text: "<style>body{}</style><main>ok</main>",
    },
  });
  assert.match(iframe, /data-testid="studio-conversation-artifact-preview-frame"/);
  assert.match(iframe, /title="Demo &lt;site&gt;"/);
  assert.match(iframe, /nonce=&quot;nonce-test&quot;/);
});

test("artifact preview renders source previews and artifact rows with stable test ids", () => {
  const preview = createPreview();
  const source = preview.studioArtifactInlinePreview({
    preview_inline: {
      media_type: "text/plain",
      text: "<unsafe>",
    },
  });
  assert.match(source, /studio-conversation-artifact-source-preview/);
  assert.match(source, /&lt;unsafe&gt;/);

  const rows = preview.studioConversationArtifactRows([{
    id: "artifact-1",
    artifactClass: "diff_patch",
    title: "Patch <one>",
    status: "compare_ready",
    previewRefs: [{ mediaType: "text/plain" }],
    actions: ["approve_patch", "rollback"],
    revisions: [{ id: "rev-1" }, { id: "rev-2" }],
    fidelity: { message: "Verified <safe>" },
  }]);

  assert.match(rows, /data-testid="studio-conversation-artifacts"/);
  assert.match(rows, /data-artifact-id="artifact-1"/);
  assert.match(rows, /data-testid="studio-conversation-artifact-compare-state"/);
  assert.match(rows, /2 revisions/);
  assert.match(rows, /Patch &lt;one&gt;/);
  assert.match(rows, /Verified &lt;safe&gt;/);
  assert.match(rows, /data-studio-artifact-action="approve_patch"/);
});
