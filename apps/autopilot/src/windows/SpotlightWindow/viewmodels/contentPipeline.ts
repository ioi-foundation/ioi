import type {
  ActivityEventRef,
  ActivityGroup,
  ActivityKind,
  ActivitySummary,
  AgentEvent,
  AnswerPresentation,
  Artifact,
  ArtifactRef,
  ChatMessage,
  RunPresentation,
} from "../../../types";

const TOOL_NAME_KEYS = ["tool_name", "tool", "name"];
const RUN_TIMESTAMP_RE = /Run timestamp \(UTC\):\s*([^\n\r]+)/i;
const TOP_TIMESTAMP_RE = /\(as of\s+([^\n\r\)]+)\s+UTC\)/i;
const OVERALL_CONFIDENCE_RE = /Overall confidence:\s*([^\n\r]+)/i;
const STORY_CONFIDENCE_RE = /^Confidence:\s*([^\n\r]+)/im;
const COMPLETION_REASON_RE = /Completion reason:\s*([^\n\r]+)/i;
const URL_RE = /https?:\/\/[^\s)\]}"']+/gim;

function hashString(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

export function normalizeOutputForHash(value: string): string {
  return value
    .replace(/\s+/g, " ")
    .replace(/\|\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s*\|/g, "|TIMESTAMP|")
    .trim();
}

function getValueString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "";
}

function eventOutput(event: AgentEvent): string {
  const details = event.details || {};
  const digest = event.digest || {};

  const candidates = [details.output, details.chunk, details.content, digest.output_snippet];
  for (const candidate of candidates) {
    const text = getValueString(candidate).trim();
    if (text.length > 0) {
      return text;
    }
  }

  return "";
}

function eventToolName(event: AgentEvent): string | undefined {
  const digest = event.digest || {};
  const details = event.details || {};

  for (const key of TOOL_NAME_KEYS) {
    const digestValue = getValueString(digest[key as keyof typeof digest]).trim();
    if (digestValue.length > 0) {
      return digestValue;
    }

    const detailsValue = getValueString(details[key as keyof typeof details]).trim();
    if (detailsValue.length > 0) {
      return detailsValue;
    }
  }

  return undefined;
}

function isChatReplyTool(toolName?: string): boolean {
  if (!toolName) return false;
  const normalized = toolName.trim().toLowerCase();
  return normalized === "chat__reply" || normalized === "chat::reply";
}

export function classifyActivityEvent(event: AgentEvent): ActivityKind {
  const title = event.title.toLowerCase();
  const toolName = eventToolName(event)?.toLowerCase();

  if (event.event_type === "RECEIPT") {
    return "receipt_event";
  }

  if (isChatReplyTool(toolName)) {
    return "primary_answer_event";
  }

  const workloadTypes = new Set([
    "COMMAND_RUN",
    "COMMAND_STREAM",
    "CODE_SEARCH",
    "FILE_READ",
    "FILE_EDIT",
    "TEST_RUN",
    "BROWSER_NAVIGATE",
    "BROWSER_EXTRACT",
  ]);

  if (workloadTypes.has(event.event_type)) {
    return "workload_event";
  }

  const reasoningSignals = [
    "captured reasoning step",
    "intentresolver",
    "thinking",
    "reasoning",
  ];
  if (reasoningSignals.some((needle) => title.includes(needle))) {
    return "reasoning_event";
  }

  return "system_event";
}

function extractRunTimestamp(text: string): string | undefined {
  const runMatch = RUN_TIMESTAMP_RE.exec(text);
  if (runMatch?.[1]) {
    return runMatch[1].trim();
  }

  const topMatch = TOP_TIMESTAMP_RE.exec(text);
  if (topMatch?.[1]) {
    const raw = topMatch[1].trim();
    return raw.endsWith("Z") ? raw : `${raw}Z`;
  }

  return undefined;
}

function extractConfidence(text: string): string | undefined {
  const overall = OVERALL_CONFIDENCE_RE.exec(text);
  if (overall?.[1]) {
    return overall[1].trim();
  }

  const story = STORY_CONFIDENCE_RE.exec(text);
  if (story?.[1]) {
    return story[1].trim();
  }

  return undefined;
}

function extractCompletionReason(text: string): string | undefined {
  const match = COMPLETION_REASON_RE.exec(text);
  return match?.[1] ? match[1].trim() : undefined;
}

function extractUrls(text: string): string[] {
  const matches = text.match(URL_RE) || [];
  const unique = new Set<string>();

  for (const candidate of matches) {
    const cleaned = candidate
      .trim()
      .replace(/[),.;]+$/g, "")
      .trim();
    if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
      unique.add(cleaned);
    }
  }

  return Array.from(unique);
}

function buildAnswerPresentation(message: ChatMessage): AnswerPresentation {
  const text = message.text || "";
  const sourceUrls = extractUrls(text);
  return {
    message,
    runTimestampUtc: extractRunTimestamp(text),
    confidence: extractConfidence(text),
    completionReason: extractCompletionReason(text),
    citations: sourceUrls.slice(0, 12),
    sourceUrls,
  };
}

function latestPrompt(history: ChatMessage[]): ChatMessage | null {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    if (history[i]?.role === "user") {
      return history[i];
    }
  }

  return null;
}

function latestAgentAnswer(history: ChatMessage[]): ChatMessage | null {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const message = history[i];
    if (message?.role === "agent" && message.text.trim().length > 0) {
      return message;
    }
  }

  return null;
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

function buildSemanticDedupKey(kind: ActivityKind, event: AgentEvent): string {
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

function groupTitle(stepIndex: number, events: ActivityEventRef[]): string {
  const firstTool = events.find((entry) => entry.toolName)?.toolName;
  if (firstTool) {
    return `Step ${stepIndex} · ${firstTool}`;
  }

  return `Step ${stepIndex}`;
}

function buildActivitySummary(events: ActivityEventRef[], artifacts: Artifact[]): ActivitySummary {
  let searchCount = 0;
  let readCount = 0;
  let receiptCount = 0;
  let reasoningCount = 0;
  let systemCount = 0;

  for (const entry of events) {
    if (entry.kind === "receipt_event") {
      receiptCount += 1;
      continue;
    }

    if (entry.kind === "reasoning_event") {
      reasoningCount += 1;
      continue;
    }

    if (entry.kind === "system_event") {
      systemCount += 1;
      continue;
    }

    if (entry.kind === "workload_event") {
      const tool = entry.toolName?.toLowerCase() || "";
      if (tool.includes("web__search")) {
        searchCount += 1;
      } else if (tool.includes("web__read")) {
        readCount += 1;
      } else {
        systemCount += 1;
      }
    }
  }

  return {
    searchCount,
    readCount,
    receiptCount,
    reasoningCount,
    systemCount,
    artifactCount: artifacts.length,
  };
}

function collectArtifactRefs(events: ActivityEventRef[], artifacts: Artifact[]): ArtifactRef[] {
  const seen = new Set<string>();
  const refs: ArtifactRef[] = [];

  for (const entry of events) {
    for (const ref of entry.event.artifact_refs || []) {
      const key = `${ref.artifact_type}:${ref.artifact_id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      refs.push(ref);
    }
  }

  for (const artifact of artifacts) {
    const key = `${artifact.artifact_type}:${artifact.artifact_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({
      artifact_id: artifact.artifact_id,
      artifact_type: artifact.artifact_type,
    });
  }

  return refs;
}

export function buildRunPresentation(
  history: ChatMessage[],
  events: AgentEvent[],
  artifacts: Artifact[],
): RunPresentation {
  const deduped: ActivityEventRef[] = [];
  const seenKeys = new Set<string>();

  for (const event of events) {
    const kind = classifyActivityEvent(event);
    const toolName = eventToolName(event);
    const normalized = normalizeOutputForHash(eventOutput(event));
    const outputHash = normalized ? hashString(normalized) : undefined;
    const key = buildSemanticDedupKey(kind, event);

    if (seenKeys.has(key)) {
      continue;
    }
    seenKeys.add(key);

    deduped.push({
      key,
      event,
      kind,
      toolName,
      normalizedOutputHash: outputHash,
    });
  }

  const byStep = new Map<number, ActivityEventRef[]>();
  for (const entry of deduped) {
    const list = byStep.get(entry.event.step_index) || [];
    list.push(entry);
    byStep.set(entry.event.step_index, list);
  }

  const orderedStepIndexes = Array.from(byStep.keys()).sort((a, b) => a - b);
  const activityGroups: ActivityGroup[] = orderedStepIndexes.map((stepIndex) => {
    const entries = byStep.get(stepIndex) || [];
    entries.sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp));
    return {
      stepIndex,
      title: groupTitle(stepIndex, entries),
      events: entries,
    };
  });

  const prompt = latestPrompt(history);
  const answerMessage = latestAgentAnswer(history) || answerFromEvents(events);
  const finalAnswer = answerMessage ? buildAnswerPresentation(answerMessage) : null;

  return {
    prompt,
    finalAnswer,
    activitySummary: buildActivitySummary(deduped, artifacts),
    activityGroups,
    artifactRefs: collectArtifactRefs(deduped, artifacts),
  };
}
