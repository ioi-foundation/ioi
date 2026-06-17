import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioChatOutputRenderers } = require("./chat-output-renderers.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeReceiptRefs(...sources) {
  const refs = [];
  for (const source of sources) {
    refs.push(...firstArray(source?.receiptRefs), ...firstArray(source?.receipt_refs));
  }
  return [...new Set(refs.filter(Boolean))];
}

function renderer() {
  return createStudioChatOutputRenderers({
    escapeHtml,
    firstArray,
    normalizeReceiptRefs,
    studioVerifiedBadge: (receipt, label) => `<span data-testid="verified-badge">${escapeHtml(label)}:${escapeHtml(receipt.receiptRefs.join(","))}</span>`,
  });
}

test("chat output renderers extract fenced Mermaid diagrams", () => {
  const studio = renderer();

  assert.deepEqual(studio.studioMermaidSourcesFromText([
    "Before",
    "```mermaid",
    "graph TD",
    "  A[Start] --> B[Done]",
    "```",
    "After",
  ].join("\n")), [
    "graph TD\n  A[Start] --> B[Done]",
  ]);
});

test("chat output renderers summarize Mermaid nodes and edges", () => {
  const studio = renderer();
  const summary = studio.studioMermaidSummary([
    "graph TD",
    "  A[Start] --> B[Done]",
    "  B --> C{Check}",
    "%% ignored",
  ].join("\n"));

  assert.equal(summary.title, "graph TD");
  assert.equal(summary.nodeCount, 4);
  assert.equal(summary.edgeCount, 2);
  assert.deepEqual(summary.nodeIds, ["TD", "A", "B", "C"]);
});

test("chat output renderer rows keep stable controls, source, nodes, and receipts", () => {
  const studio = renderer();
  const html = studio.studioChatOutputRendererRows({
    content: [
      "```mermaid",
      "graph TD",
      "  A[Start] --> B[Done]",
      "```",
    ].join("\n"),
    receiptRefs: ["receipt-turn"],
  }, 3);

  assert.match(html, /data-testid="studio-chat-mermaid-renderer"/);
  assert.match(html, /data-testid="studio-chat-output-renderer-controls"/);
  assert.match(html, /data-testid="studio-chat-renderer-zoom-in"/);
  assert.match(html, /data-testid="studio-mermaid-clickable-node"/);
  assert.match(html, /data-node-count="3"/);
  assert.match(html, /data-edge-count="1"/);
  assert.match(html, /Verified renderer:receipt-turn/);
});

test("chat output renderer rows prefer explicit Mermaid renderer cards", () => {
  const studio = renderer();
  const html = studio.studioChatOutputRendererRows({
    output_renderers: [
      {
        id: "renderer-one",
        renderer_id: "vscode.chatMermaidDiagram",
        mime_type: "text/vnd.mermaid",
        source: "flowchart LR\nX --> Y",
        receipt_refs: ["receipt-renderer"],
      },
    ],
  }, 1);

  assert.match(html, /data-renderer-id="vscode.chatMermaidDiagram"/);
  assert.match(html, /data-mime-type="text\/vnd\.mermaid"/);
  assert.match(html, /Verified renderer:receipt-renderer/);
});
