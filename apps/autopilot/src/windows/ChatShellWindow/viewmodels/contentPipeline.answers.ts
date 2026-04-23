import type {
  AgentEvent,
  AnswerPresentation,
  ChatMessage,
} from "../../../types";
import {
  formatChatContractForClipboard,
  parseChatContractEnvelope,
} from "./chatContract";
import { classifyActivityEvent } from "./contentPipeline.classification";
import {
  eventOutput,
  extractUrls,
  normalizeOutputForHash,
} from "./contentPipeline.helpers";

export function buildAnswerPresentation(message: ChatMessage): AnswerPresentation {
  const text = message.text || "";
  const contractParse = parseChatContractEnvelope(text);
  const contract = contractParse.envelope;
  const rejectedStructuredResponse = !contract && contractParse.issues.length > 0;
  const fallbackText = rejectedStructuredResponse
    ? "Structured response unavailable due to contract validation failure."
    : text;
  const displayText =
    contract?.answer_markdown?.trim() && contract.answer_markdown.trim().length > 0
      ? contract.answer_markdown
      : contract
        ? contract.outcome.summary || ""
        : fallbackText;
  const copyText = contract ? formatChatContractForClipboard(contract) : fallbackText;
  const citationText = contract?.answer_markdown || (rejectedStructuredResponse ? "" : text);
  const sourceUrls = extractUrls(citationText);
  return {
    message,
    displayText,
    copyText,
    contract,
    contractValidationIssues: contractParse.issues,
    citations: extractUrls(citationText).slice(0, 12),
    sourceUrls,
  };
}

export function latestPrompt(history: ChatMessage[]): ChatMessage | null {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    if (history[i]?.role === "user") {
      return history[i];
    }
  }

  return null;
}

function latestAgentAnswer(
  history: ChatMessage[],
  canonicalAnswerHashes?: Set<string>,
): ChatMessage | null {
  const shouldMatchCanonical = !!canonicalAnswerHashes && canonicalAnswerHashes.size > 0;
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const message = history[i];
    if (message?.role === "agent" && message.text.trim().length > 0) {
      if (shouldMatchCanonical) {
        const normalized = normalizeOutputForHash(message.text).toLowerCase();
        if (!canonicalAnswerHashes?.has(normalized)) {
          continue;
        }
      }
      return message;
    }
  }

  return null;
}

function collectPrimaryAnswerHashes(events: AgentEvent[]): Set<string> {
  const hashes = new Set<string>();
  for (const event of events) {
    if (classifyActivityEvent(event) !== "primary_answer_event") continue;
    const output = normalizeOutputForHash(eventOutput(event)).toLowerCase();
    if (!output) continue;
    hashes.add(output);
  }
  return hashes;
}

function answerFromEvents(events: AgentEvent[]): ChatMessage | null {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (classifyActivityEvent(event) !== "primary_answer_event") continue;

    const output = eventOutput(event).trim();
    if (!output) continue;

    return {
      role: "agent",
      text: output,
      timestamp: Date.parse(event.timestamp) || Date.now(),
    };
  }

  return null;
}

const CLARIFICATION_REASONING_SIGNALS = [
  "need more details",
  "need more context",
  "could you please",
  "please specify",
  "please share",
  "what is the goal",
  "history of actions",
  "previous steps",
  "executed up to this point",
];

function looksLikeClarificationReasoning(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed || !trimmed.includes("?")) {
    return false;
  }

  const lowered = trimmed.toLowerCase();
  return (
    lowered.startsWith("to provide the correct") ||
    CLARIFICATION_REASONING_SIGNALS.some((needle) => lowered.includes(needle))
  );
}

function clarificationFromReasoningEvents(events: AgentEvent[]): ChatMessage | null {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (classifyActivityEvent(event) !== "reasoning_event") continue;

    const output = eventOutput(event).trim();
    if (!looksLikeClarificationReasoning(output)) continue;

    return {
      role: "agent",
      text: output,
      timestamp: Date.parse(event.timestamp) || Date.now(),
    };
  }

  return null;
}

export function resolveFinalAnswer(
  history: ChatMessage[],
  events: AgentEvent[],
): AnswerPresentation | null {
  const canonicalAnswerHashes = collectPrimaryAnswerHashes(events);
  const answerMessage =
    latestAgentAnswer(history, canonicalAnswerHashes) ||
    answerFromEvents(events) ||
    clarificationFromReasoningEvents(events) ||
    latestAgentAnswer(history);
  return answerMessage ? buildAnswerPresentation(answerMessage) : null;
}
