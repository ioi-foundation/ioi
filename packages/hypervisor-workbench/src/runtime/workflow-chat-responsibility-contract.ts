export const WORKFLOW_CHAT_RESPONSIBILITY_CONTRACT_SCHEMA_VERSION =
  "ioi.workflow.chat-responsibility-contract.v1" as const;

export interface WorkflowChatResponsibilityTurnInput {
  mode?: string | null;
  routeId?: string | null;
  prompt?: string | null;
  responseText?: string | null;
  visibleAssistantText?: string | null;
  latencyMs?: number | string | null;
  receiptId?: string | null;
  toolSequence?: readonly unknown[] | null;
}

export interface WorkflowChatResponsibilityContractInput {
  turns?: readonly WorkflowChatResponsibilityTurnInput[] | null;
}

export interface WorkflowChatResponsibilityRow {
  id: string;
  mode: "ask" | "agent" | "unknown";
  responsibility: "direct_model_answer" | "default_agent_harness" | "unknown";
  status: "ready" | "blocked";
  routeId: string | null;
  prompt: string | null;
  responseText: string | null;
  visibleAssistantText: string | null;
  latencyMs: number | null;
  receiptId: string | null;
  toolSequence: string[];
  directToolLeak: boolean;
  chatReplyCalled: boolean;
  agentCompleteCalled: boolean;
  agentCompleteWithoutReply: boolean;
  conversational: boolean;
  issue: string | null;
}

export interface WorkflowChatResponsibilityContract {
  schemaVersion: typeof WORKFLOW_CHAT_RESPONSIBILITY_CONTRACT_SCHEMA_VERSION;
  status: "ready" | "blocked" | "empty";
  directChatCount: number;
  agentHarnessCount: number;
  conversationalTurnCount: number;
  directToolLeakCount: number;
  missingAgentReplyCount: number;
  agentCompleteWithoutReplyCount: number;
  slowTurnCount: number;
  rows: WorkflowChatResponsibilityRow[];
  receiptIds: string[];
}

export function buildWorkflowChatResponsibilityContract(
  input: WorkflowChatResponsibilityContractInput,
): WorkflowChatResponsibilityContract {
  const rows = (input.turns ?? []).map(rowForTurn);
  const directToolLeakCount = rows.filter((row) => row.directToolLeak).length;
  const missingAgentReplyCount = rows.filter((row) => row.mode === "agent" && !row.chatReplyCalled).length;
  const agentCompleteWithoutReplyCount = rows.filter((row) => row.agentCompleteWithoutReply).length;
  const slowTurnCount = rows.filter((row) => (row.latencyMs ?? 0) > 30_000).length;
  const blockedCount =
    directToolLeakCount + missingAgentReplyCount + agentCompleteWithoutReplyCount + slowTurnCount;
  return {
    schemaVersion: WORKFLOW_CHAT_RESPONSIBILITY_CONTRACT_SCHEMA_VERSION,
    status: rows.length === 0 ? "empty" : blockedCount > 0 ? "blocked" : "ready",
    directChatCount: rows.filter((row) => row.responsibility === "direct_model_answer").length,
    agentHarnessCount: rows.filter((row) => row.responsibility === "default_agent_harness").length,
    conversationalTurnCount: rows.filter((row) => row.conversational).length,
    directToolLeakCount,
    missingAgentReplyCount,
    agentCompleteWithoutReplyCount,
    slowTurnCount,
    rows,
    receiptIds: uniqueStrings(rows.map((row) => row.receiptId)),
  };
}

function rowForTurn(input: WorkflowChatResponsibilityTurnInput, index: number): WorkflowChatResponsibilityRow {
  const mode = normalizedMode(input.mode);
  const responsibility =
    mode === "ask" ? "direct_model_answer" : mode === "agent" ? "default_agent_harness" : "unknown";
  const responseText = cleanString(input.responseText);
  const toolSequence = normalizeToolSequence(input.toolSequence);
  const parsedTool = parseToolName(responseText);
  const effectiveToolSequence = parsedTool ? uniqueStrings([...toolSequence, parsedTool]) : toolSequence;
  const directToolLeak =
    mode === "ask" &&
    (Boolean(parsedTool) || /\b(chat__reply|agent__complete|file__read|file__search|web__search|shell__run)\b/i.test(responseText ?? ""));
  const chatReplyCalled = effectiveToolSequence.includes("chat__reply");
  const agentCompleteCalled = effectiveToolSequence.includes("agent__complete");
  const agentCompleteWithoutReply = mode === "agent" && agentCompleteCalled && !chatReplyCalled;
  const latencyMs = nonNegativeNumber(input.latencyMs);
  const issue =
    directToolLeak
      ? "ask_mode_returned_agent_tool_call"
      : mode === "agent" && !chatReplyCalled
        ? "agent_mode_missing_chat_reply"
        : agentCompleteWithoutReply
          ? "agent_completed_before_visible_chat_reply"
          : latencyMs !== null && latencyMs > 30_000
            ? "turn_exceeded_30s_threshold"
            : null;
  return {
    id: `chat-responsibility-${index + 1}`,
    mode,
    responsibility,
    status: issue ? "blocked" : "ready",
    routeId: cleanString(input.routeId),
    prompt: cleanString(input.prompt),
    responseText,
    visibleAssistantText: cleanString(input.visibleAssistantText) ?? visibleTextFromToolCall(responseText),
    latencyMs,
    receiptId: cleanString(input.receiptId),
    toolSequence: effectiveToolSequence,
    directToolLeak,
    chatReplyCalled,
    agentCompleteCalled,
    agentCompleteWithoutReply,
    conversational: isConversational(input.prompt),
    issue,
  };
}

function normalizedMode(value: unknown): WorkflowChatResponsibilityRow["mode"] {
  const text = cleanString(value)?.toLowerCase();
  if (text === "ask" || text === "chat" || text === "direct") return "ask";
  if (text === "agent" || text === "harness") return "agent";
  return "unknown";
}

function normalizeToolSequence(value: readonly unknown[] | null | undefined): string[] {
  return uniqueStrings((value ?? []).map((item) => parseToolName(item) ?? cleanString(item)));
}

function parseToolName(value: unknown): string | null {
  const text = cleanString(value);
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return cleanString(parsed?.name);
  } catch {
    const match = text.match(/\b(chat__reply|agent__complete|file__read|file__search|web__search|web__read|shell__run)\b/i);
    return match ? match[1] : null;
  }
}

function visibleTextFromToolCall(value: unknown): string | null {
  const text = cleanString(value);
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    const message = cleanString(parsed?.arguments?.message);
    return parseToolName(parsed?.name) === "chat__reply" ? message : null;
  } catch {
    return null;
  }
}

function isConversational(value: unknown): boolean {
  const text = cleanString(value)?.toLowerCase() ?? "";
  return /\b(hiya|hello|thanks|thank you|sounds good|how are you|they can only ignore it for so long|receipts? matter|pythagorean theorem)\b/.test(text);
}

function nonNegativeNumber(value: unknown): number | null {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof number === "number" && Number.isFinite(number) && number >= 0 ? number : null;
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  );
}
