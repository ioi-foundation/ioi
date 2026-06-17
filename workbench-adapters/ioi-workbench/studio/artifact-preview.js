"use strict";

function defaultEscapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function defaultStringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

function defaultFirstArray(value) {
  return Array.isArray(value) ? value : [];
}

function createStudioArtifactPreview({
  escapeHtml = defaultEscapeHtml,
  stringValue = defaultStringValue,
  firstArray = defaultFirstArray,
  studioRecordValue = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {},
  getPageNonce = () => "",
} = {}) {
  function studioArtifactClassLabel(artifact = {}) {
    const value = stringValue(artifact.artifactClass || artifact.artifact_class || artifact.class, "artifact");
    if (value === "static_html_js") {
      return studioArtifactIsWebsite(artifact) ? "Website" : "HTML report";
    }
    if (value === "react_vite_app") return "App preview";
    if (value === "imported_document") return "Document";
    if (value === "pdf_preview") return "PDF";
    if (value === "diff_patch") return "Patch";
    if (value === "dataset_chart") return "Dataset";
    if (value === "browser_observation") return "Browser capture";
    return value
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/\b[a-z]/g, (char) => char.toUpperCase());
  }

  function studioArtifactOutputModality(artifact = {}) {
    return stringValue(
      artifact.outputModality ||
        artifact.output_modality ||
        artifact.generatedFiles?.outputModality ||
        artifact.generated_files?.output_modality ||
        artifact.generatedFiles?.output_modality ||
        artifact.generated_files?.outputModality,
    );
  }

  function studioArtifactIsWebsite(artifact = {}) {
    if ((artifact.artifactClass || artifact.artifact_class) !== "static_html_js") return false;
    const modality = studioArtifactOutputModality(artifact);
    if (/\b(website|web\s*site|webpage|web\s*page|landing\s+page|site)\b/i.test(modality)) return true;
    return /\b(website|web\s*site|webpage|web\s*page|landing\s+page|site)\b/i.test(
      `${artifact.title || ""} ${artifact.summary || ""} ${artifact.generatedFiles?.summary || ""} ${artifact.generated_files?.summary || ""}`,
    );
  }

  function studioArtifactPreviewLabel(artifact = {}) {
    const previewRefs = firstArray(artifact.previewRefs || artifact.preview_refs);
    if (!previewRefs.length) {
      return "Preview pending";
    }
    const firstPreview = previewRefs[0] || {};
    const mediaType = stringValue(firstPreview.mediaType || firstPreview.media_type, "preview");
    if (/html/i.test(mediaType)) {
      return studioArtifactIsWebsite(artifact) ? "Website preview" : "HTML preview";
    }
    if (/pdf/i.test(mediaType)) return "PDF preview";
    if (/csv|json/i.test(mediaType)) return "Data preview";
    return "Preview ready";
  }

  function studioArtifactPreviewSrcdoc(text, pageNonce = "") {
    const nonceAttr = pageNonce ? ` nonce="${escapeHtml(pageNonce)}"` : "";
    return stringValue(text)
      .replace(/<style(?![^>]*\bnonce=)/gi, `<style${nonceAttr}`)
      .replace(/<script(?![^>]*\bnonce=)/gi, `<script${nonceAttr}`);
  }

  function studioArtifactInlinePreview(artifact = {}) {
    const inline = studioRecordValue(artifact.previewInline || artifact.preview_inline);
    const text = stringValue(inline.text);
    if (!text) {
      return "";
    }
    const mediaType = stringValue(inline.mediaType || inline.media_type);
    if (/html/i.test(mediaType)) {
      const previewHtml = studioArtifactPreviewSrcdoc(text, getPageNonce() || "");
      return `
      <iframe
        class="studio-conversation-artifact-frame"
        data-testid="studio-conversation-artifact-preview-frame"
        sandbox="allow-scripts"
        title="${escapeHtml(artifact.title || "Artifact preview")}"
        srcdoc="${escapeHtml(previewHtml)}"
      ></iframe>
    `;
    }
    return `
    <pre class="studio-conversation-artifact-source-preview" data-testid="studio-conversation-artifact-source-preview">${escapeHtml(text.slice(0, 6000))}</pre>
  `;
  }

  function studioArtifactPreviewShell(artifact = {}, { expanded = false } = {}) {
    const inlinePreview = studioArtifactInlinePreview(artifact);
    const stateLabel = stringValue(artifact.stateLabel || artifact.state_label || artifact.status, "Preview ready");
    if (inlinePreview) {
      return `
      <div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--${expanded ? "expanded" : "compact"}" data-testid="studio-conversation-artifact-preview">
        ${inlinePreview}
      </div>
    `;
    }
    return `
    <div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--placeholder" data-testid="studio-conversation-artifact-preview">
      <strong>${escapeHtml(studioArtifactPreviewLabel(artifact))}</strong>
      <span>${escapeHtml(stateLabel)}</span>
    </div>
  `;
  }

  function studioConversationArtifactRows(cards = []) {
    const artifacts = firstArray(cards).filter(Boolean);
    if (!artifacts.length) {
      return "";
    }
    return `
    <section class="studio-conversation-artifacts" data-testid="studio-conversation-artifacts" aria-label="Conversation artifacts">
      ${artifacts.map((artifact) => {
        const artifactId = stringValue(artifact.id || artifact.artifactId || artifact.artifact_id, "artifact");
        const stateLabel = stringValue(artifact.stateLabel || artifact.state_label || artifact.status, "Preview ready");
        const actions = firstArray(artifact.actions).slice(0, 6);
        const revisionCount = firstArray(artifact.revisions).length || 1;
        return `
          <article
            class="studio-conversation-artifact-card"
            data-testid="studio-conversation-artifact-card"
            data-artifact-id="${escapeHtml(artifactId)}"
            data-artifact-class="${escapeHtml(artifact.artifactClass || artifact.artifact_class || "")}"
            data-artifact-status="${escapeHtml(artifact.status || "")}"
            data-artifact-expanded="false"
          >
            <header class="studio-conversation-artifact-card__header">
              <div>
                <span data-testid="studio-conversation-artifact-type">${escapeHtml(studioArtifactClassLabel(artifact))}</span>
                <strong data-testid="studio-conversation-artifact-title">${escapeHtml(artifact.title || "Conversation artifact")}</strong>
              </div>
              <button type="button" data-testid="studio-conversation-artifact-expand" data-studio-artifact-expand aria-expanded="false">Open</button>
            </header>
            <div class="studio-conversation-artifact-compact" data-testid="studio-conversation-artifact-compact">
              <div class="studio-conversation-artifact-compact__status">
                <strong>${escapeHtml(stateLabel)}</strong>
                <span>${escapeHtml(studioArtifactPreviewLabel(artifact))} &#183; ${escapeHtml(String(revisionCount))} revision${revisionCount === 1 ? "" : "s"}</span>
              </div>
              ${studioArtifactPreviewShell(artifact, { expanded: false })}
            </div>
            <div class="studio-conversation-artifact-expanded" data-testid="studio-conversation-artifact-expanded-view">
              <div class="studio-conversation-artifact-meta studio-visually-hidden" data-testid="studio-conversation-artifact-renderer-meta">
                <span>Renderer: ${escapeHtml(artifact.renderer?.label || artifact.renderer?.kind || "sandboxed preview")}</span>
                <span>Sandbox: network denied &#183; no ambient filesystem</span>
              </div>
              ${studioArtifactPreviewShell(artifact, { expanded: true })}
              ${artifact.fidelity?.message ? `
                <div class="studio-conversation-artifact-fidelity" data-testid="studio-conversation-artifact-fidelity">
                  ${escapeHtml(artifact.fidelity.message)}
                </div>
              ` : ""}
              ${/(compare|document|diff|patch)/i.test(`${artifact.status || ""} ${artifact.artifactClass || artifact.artifact_class || ""}`) ? `
                <div class="studio-conversation-artifact-compare" data-testid="studio-conversation-artifact-compare-state">
                  <strong>Compare ready</strong>
                  <span>Original, projection, and latest revision are preserved by the daemon.</span>
                </div>
              ` : ""}
              <div class="studio-conversation-artifact-actions" data-testid="studio-conversation-artifact-actions">
                ${actions.map((action) => `
                  <button type="button" data-testid="studio-conversation-artifact-action" data-studio-artifact-action="${escapeHtml(action)}" data-artifact-id="${escapeHtml(artifactId)}">${escapeHtml(String(action).replace(/[_-]+/g, " "))}</button>
                `).join("")}
              </div>
            </div>
          </article>
        `;
      }).join("")}
    </section>
  `;
  }

  return {
    studioArtifactClassLabel,
    studioArtifactOutputModality,
    studioArtifactIsWebsite,
    studioArtifactPreviewLabel,
    studioArtifactPreviewSrcdoc,
    studioArtifactInlinePreview,
    studioArtifactPreviewShell,
    studioConversationArtifactRows,
  };
}

module.exports = {
  createStudioArtifactPreview,
};
