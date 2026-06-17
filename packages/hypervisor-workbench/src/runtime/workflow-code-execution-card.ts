export const WORKFLOW_CODE_EXECUTION_CARD_SCHEMA_VERSION =
  "ioi.workflow.code-execution-card.v1" as const;

export interface WorkflowCodeExecutionMessageLike {
  id?: string | null;
  role?: string | null;
  content?: string | null;
  text?: string | null;
}

export interface WorkflowCodeExecutionCardInput {
  messages: readonly WorkflowCodeExecutionMessageLike[];
}

export interface WorkflowCodeExecutionCard {
  id: string;
  messageId: string;
  language: string;
  status: "ready" | "blocked";
  applyMode: "plan_only";
  commandPreview: string;
  source: string;
  sandbox: {
    network: "deny";
    writeScope: "workspace_only";
    timeoutMs: number;
    receiptRequired: true;
  };
  policyRefs: string[];
  blockReason: string | null;
}

export interface WorkflowCodeExecutionCardPanel {
  schemaVersion: typeof WORKFLOW_CODE_EXECUTION_CARD_SCHEMA_VERSION;
  status: "ready" | "blocked" | "empty";
  cardCount: number;
  blockedCount: number;
  cards: WorkflowCodeExecutionCard[];
}

export function buildWorkflowCodeExecutionCardPanel(
  input: WorkflowCodeExecutionCardInput,
): WorkflowCodeExecutionCardPanel {
  const cards = normalizeMessages(input.messages).flatMap((message, messageIndex) =>
    executableCodeBlocks(message).map((block, blockIndex) => {
      const policy = executionPolicyForBlock(block.source);
      return {
        id: `${safeId(message.id || `message-${messageIndex + 1}`)}:code:${blockIndex + 1}`,
        messageId: message.id || `message-${messageIndex + 1}`,
        language: block.language,
        status: policy.blocked ? "blocked" as const : "ready" as const,
        applyMode: "plan_only" as const,
        commandPreview: commandPreview(block.language, block.source),
        source: block.source,
        sandbox: {
          network: "deny" as const,
          writeScope: "workspace_only" as const,
          timeoutMs: 10_000,
          receiptRequired: true as const,
        },
        policyRefs: policy.policyRefs,
        blockReason: policy.blockReason,
      };
    }),
  );
  const blockedCount = cards.filter((card) => card.status === "blocked").length;
  return {
    schemaVersion: WORKFLOW_CODE_EXECUTION_CARD_SCHEMA_VERSION,
    status: cards.length === 0 ? "empty" : blockedCount > 0 ? "blocked" : "ready",
    cardCount: cards.length,
    blockedCount,
    cards,
  };
}

function normalizeMessages(
  messages: readonly WorkflowCodeExecutionMessageLike[] | undefined,
): WorkflowCodeExecutionMessageLike[] {
  return Array.isArray(messages) ? messages.filter(Boolean) : [];
}

function executableCodeBlocks(message: WorkflowCodeExecutionMessageLike): Array<{
  language: string;
  source: string;
}> {
  const content = stringField(message.content) || stringField(message.text) || "";
  const blocks: Array<{ language: string; source: string }> = [];
  const fencePattern = /```([a-zA-Z0-9_-]+)\s*\n([\s\S]*?)```/g;
  let match: RegExpExecArray | null;
  while ((match = fencePattern.exec(content))) {
    const language = normalizeLanguage(match[1]);
    const source = match[2]?.trim();
    if (source && executableLanguages.has(language)) {
      blocks.push({ language, source });
    }
  }
  return blocks;
}

const executableLanguages = new Set([
  "bash",
  "sh",
  "shell",
  "zsh",
  "python",
  "javascript",
  "typescript",
  "node",
]);

function normalizeLanguage(value: unknown): string {
  const language = String(value || "").trim().toLowerCase();
  if (language === "js") return "javascript";
  if (language === "ts") return "typescript";
  return language || "text";
}

function executionPolicyForBlock(source: string): {
  blocked: boolean;
  policyRefs: string[];
  blockReason: string | null;
} {
  const policyRefs = ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny"];
  if (/\b(curl|wget|ssh|scp|nc|ncat|telnet)\b|https?:\/\//i.test(source)) {
    return {
      blocked: true,
      policyRefs: [...policyRefs, "policy:code_execution.block.network"],
      blockReason: "Network-shaped code block requires explicit approval before execution.",
    };
  }
  if (/\brm\s+-rf\b|>\s*\/|sudo\b/i.test(source)) {
    return {
      blocked: true,
      policyRefs: [...policyRefs, "policy:code_execution.block.host_write"],
      blockReason: "Host-write or privileged command shape cannot be executed from chat.",
    };
  }
  return {
    blocked: false,
    policyRefs,
    blockReason: null,
  };
}

function commandPreview(language: string, source: string): string {
  if (language === "python") return "python";
  if (language === "javascript" || language === "typescript" || language === "node") {
    return "node";
  }
  return source.split(/\r?\n/)[0]?.slice(0, 120) || language;
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
