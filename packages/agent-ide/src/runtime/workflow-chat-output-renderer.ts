export const WORKFLOW_CHAT_OUTPUT_RENDERER_SCHEMA_VERSION =
  "ioi.workflow.chat-output-renderer.v1" as const;

export interface WorkflowChatOutputRendererMessageLike {
  id?: string | null;
  role?: string | null;
  content?: string | null;
  text?: string | null;
  mimeType?: string | null;
  mime_type?: string | null;
  rendererId?: string | null;
  renderer_id?: string | null;
}

export interface WorkflowChatOutputRendererInput {
  messages: readonly WorkflowChatOutputRendererMessageLike[];
}

export interface WorkflowChatOutputRendererCard {
  id: string;
  messageId: string;
  rendererId: "vscode.chatMermaidDiagram";
  mimeType: "text/vnd.mermaid";
  title: string;
  status: "ready";
  source: string;
  nodeCount: number;
  edgeCount: number;
  zoomControls: readonly ["zoom_in", "zoom_out", "fit"];
  clickableNodeCount: number;
}

export interface WorkflowChatOutputRendererPanel {
  schemaVersion: typeof WORKFLOW_CHAT_OUTPUT_RENDERER_SCHEMA_VERSION;
  status: "ready" | "empty";
  rendererCount: number;
  mermaidRendererCount: number;
  rawFenceCount: number;
  cards: WorkflowChatOutputRendererCard[];
}

export function buildWorkflowChatOutputRendererPanel(
  input: WorkflowChatOutputRendererInput,
): WorkflowChatOutputRendererPanel {
  const cards = normalizeMessages(input.messages).flatMap((message, index) =>
    mermaidSourcesForMessage(message).map((source, sourceIndex) => {
      const diagram = summarizeMermaidSource(source);
      return {
        id: `${safeId(message.id || `message-${index + 1}`)}:mermaid:${sourceIndex + 1}`,
        messageId: message.id || `message-${index + 1}`,
        rendererId: "vscode.chatMermaidDiagram" as const,
        mimeType: "text/vnd.mermaid" as const,
        title: diagram.title,
        status: "ready" as const,
        source,
        nodeCount: diagram.nodeCount,
        edgeCount: diagram.edgeCount,
        zoomControls: ["zoom_in", "zoom_out", "fit"] as const,
        clickableNodeCount: diagram.nodeCount,
      };
    }),
  );
  return {
    schemaVersion: WORKFLOW_CHAT_OUTPUT_RENDERER_SCHEMA_VERSION,
    status: cards.length > 0 ? "ready" : "empty",
    rendererCount: cards.length,
    mermaidRendererCount: cards.length,
    rawFenceCount: cards.length,
    cards,
  };
}

function normalizeMessages(
  messages: readonly WorkflowChatOutputRendererMessageLike[] | undefined,
): WorkflowChatOutputRendererMessageLike[] {
  return Array.isArray(messages) ? messages.filter(Boolean) : [];
}

function mermaidSourcesForMessage(message: WorkflowChatOutputRendererMessageLike): string[] {
  const content = stringField(message.content) || stringField(message.text) || "";
  const mimeType = stringField(message.mimeType ?? message.mime_type);
  const rendererId = stringField(message.rendererId ?? message.renderer_id);
  const explicitMermaid =
    mimeType === "text/vnd.mermaid" ||
    rendererId === "vscode.chatMermaidDiagram";
  return explicitMermaid ? [content].filter(Boolean) : extractMermaidFences(content);
}

function extractMermaidFences(content: string): string[] {
  const sources: string[] = [];
  const fencePattern = /```(?:mermaid|text\/vnd\.mermaid)\s*\n([\s\S]*?)```/gi;
  let match: RegExpExecArray | null;
  while ((match = fencePattern.exec(content))) {
    const source = match[1]?.trim();
    if (source) {
      sources.push(source);
    }
  }
  return sources;
}

function summarizeMermaidSource(source: string): {
  title: string;
  nodeCount: number;
  edgeCount: number;
} {
  const lines = source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("%%"));
  const title = lines[0] || "Mermaid diagram";
  const edgeCount = lines.filter((line) => /-->|---|==>|-.->/.test(line)).length;
  const nodeIds = new Set<string>();
  for (const line of lines) {
    for (const match of line.matchAll(/\b([A-Za-z][\w-]*)\s*(?:\[[^\]]+\]|\([^)]+\)|\{[^}]+\})?/g)) {
      const id = match[1];
      if (!/^(graph|flowchart|sequenceDiagram|participant|subgraph|end|classDef|style)$/.test(id)) {
        nodeIds.add(id);
      }
    }
  }
  return {
    title,
    nodeCount: nodeIds.size,
    edgeCount,
  };
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "message"
  );
}
