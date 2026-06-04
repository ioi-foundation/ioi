"use strict";

function createStudioChatOutputRenderers({
  escapeHtml,
  firstArray,
  normalizeReceiptRefs,
  studioVerifiedBadge,
} = {}) {
  const escape = typeof escapeHtml === "function" ? escapeHtml : (value) => String(value ?? "");
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const receipts = typeof normalizeReceiptRefs === "function" ? normalizeReceiptRefs : () => [];
  const verifiedBadge = typeof studioVerifiedBadge === "function" ? studioVerifiedBadge : () => "";

  function studioMermaidSourcesFromText(content = "") {
    const sources = [];
    const fencePattern = /```(?:mermaid|text\/vnd\.mermaid)\s*\n([\s\S]*?)```/gi;
    let match = null;
    while ((match = fencePattern.exec(String(content || "")))) {
      const source = String(match[1] || "").trim();
      if (source) {
        sources.push(source);
      }
    }
    return sources;
  }

  function studioMermaidSummary(source = "") {
    const lines = String(source || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("%%"));
    const nodes = new Set();
    for (const line of lines) {
      for (const match of line.matchAll(/\b([A-Za-z][\w-]*)\s*(?:\[[^\]]+\]|\([^)]+\)|\{[^}]+\})?/g)) {
        const id = match[1];
        if (!/^(graph|flowchart|sequenceDiagram|participant|subgraph|end|classDef|style)$/.test(id)) {
          nodes.add(id);
        }
      }
    }
    return {
      title: lines[0] || "Mermaid diagram",
      nodeIds: [...nodes].slice(0, 8),
      nodeCount: nodes.size,
      edgeCount: lines.filter((line) => /-->|---|==>|-.->/.test(line)).length,
    };
  }

  function studioChatOutputRendererRows(turn = {}, turnIndex = 0) {
    const explicitRenderers = array(turn.outputRenderers || turn.output_renderers);
    const cards = explicitRenderers.length
      ? explicitRenderers
          .filter((item) => String(item?.mimeType || item?.mime_type || item?.rendererId || item?.renderer_id || "").includes("mermaid"))
          .map((item, index) => ({
            id: item.id || `turn-${turnIndex}-renderer-${index}`,
            source: item.source || item.content || item.text || "",
            mimeType: item.mimeType || item.mime_type || "text/vnd.mermaid",
            rendererId: item.rendererId || item.renderer_id || "vscode.chatMermaidDiagram",
            receiptRefs: receipts(item, turn),
          }))
      : studioMermaidSourcesFromText(turn.content || turn.text || "").map((source, index) => ({
          id: `turn-${turnIndex}-mermaid-${index}`,
          source,
          mimeType: "text/vnd.mermaid",
          rendererId: "vscode.chatMermaidDiagram",
          receiptRefs: receipts(turn),
        }));
    if (!cards.length) {
      return "";
    }
    return cards.map((card) => {
      const summary = studioMermaidSummary(card.source);
      return `
        <figure class="studio-chat-output-renderer studio-chat-output-renderer--mermaid" data-testid="studio-chat-mermaid-renderer" data-renderer-id="${escape(card.rendererId)}" data-mime-type="${escape(card.mimeType)}" data-node-count="${escape(String(summary.nodeCount))}" data-edge-count="${escape(String(summary.edgeCount))}">
          <figcaption>
            <strong>Mermaid diagram</strong>
            <span>${escape(summary.nodeCount)} nodes · ${escape(summary.edgeCount)} edges · ${escape(card.mimeType)}</span>
          </figcaption>
          <div class="studio-chat-renderer-toolbar" data-testid="studio-chat-output-renderer-controls">
            <button type="button" data-testid="studio-chat-renderer-zoom-in" data-renderer-action="zoom-in">Zoom in</button>
            <button type="button" data-testid="studio-chat-renderer-zoom-out" data-renderer-action="zoom-out">Zoom out</button>
            <button type="button" data-testid="studio-chat-renderer-fit" data-renderer-action="fit">Fit</button>
          </div>
          <div class="studio-mermaid-diagram" data-testid="studio-mermaid-diagram-surface" role="img" aria-label="${escape(summary.title)}">
            ${summary.nodeIds.length
              ? summary.nodeIds.map((nodeId) => `<button type="button" class="studio-mermaid-node" data-testid="studio-mermaid-clickable-node">${escape(nodeId)}</button>`).join("")
              : '<span class="studio-mermaid-node">diagram</span>'}
          </div>
          <details class="studio-mermaid-source" data-testid="studio-chat-output-renderer-source">
            <summary>Mermaid source</summary>
            <pre>${escape(card.source)}</pre>
          </details>
          ${card.receiptRefs?.length ? `<footer>${verifiedBadge({ id: card.id, kind: "chat.output_renderer", receiptRefs: card.receiptRefs, summary: "Mermaid renderer projected from daemon chat output." }, "Verified renderer")}</footer>` : ""}
        </figure>
      `;
    }).join("");
  }

  return {
    studioChatOutputRendererRows,
    studioMermaidSourcesFromText,
    studioMermaidSummary,
  };
}

module.exports = {
  createStudioChatOutputRenderers,
};
