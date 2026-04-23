import type { ActivityKind, AgentEvent } from "../../../types";
import {
  eventOutput,
  eventToolName,
  hashString,
  isChatReplyTool,
  normalizeOutputForHash,
} from "./contentPipeline.helpers";

const WORKLOAD_EVENT_TYPES = new Set([
  "COMMAND_RUN",
  "COMMAND_STREAM",
  "CODE_SEARCH",
  "FILE_READ",
  "FILE_EDIT",
  "TEST_RUN",
  "BROWSER_NAVIGATE",
  "BROWSER_EXTRACT",
]);

const REASONING_SIGNALS = [
  "captured reasoning step",
  "intentresolver",
  "thinking",
  "reasoning",
];

export function classifyActivityEvent(event: AgentEvent): ActivityKind {
  const title = event.title.toLowerCase();
  const toolName = eventToolName(event)?.toLowerCase();

  if (event.event_type === "RECEIPT") {
    return "receipt_event";
  }

  if (isChatReplyTool(toolName)) {
    return "primary_answer_event";
  }

  if (WORKLOAD_EVENT_TYPES.has(event.event_type)) {
    return "workload_event";
  }

  if (REASONING_SIGNALS.some((needle) => title.includes(needle))) {
    return "reasoning_event";
  }

  return "system_event";
}

export function buildSemanticDedupKey(kind: ActivityKind, event: AgentEvent): string {
  const toolName = eventToolName(event) || "none";
  const output = normalizeOutputForHash(eventOutput(event));
  const outputHash = output ? hashString(output) : "no_output";

  if (kind === "primary_answer_event") {
    return `answer:${toolName}:${outputHash}`;
  }

  if (kind === "workload_event") {
    return `${event.step_index}:${toolName}:${outputHash}`;
  }

  if (kind === "receipt_event") {
    return `receipt:${event.step_index}:${toolName}:${outputHash}`;
  }

  return `${event.event_id}:${kind}`;
}
