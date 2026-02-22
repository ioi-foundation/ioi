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
  SourceBrowseRow,
  SourceSearchRow,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";

const TOOL_NAME_KEYS = ["tool_name", "tool", "name"];
const RUN_TIMESTAMP_RE = /Run timestamp \(UTC\):\s*([^\n\r]+)/i;
const TOP_TIMESTAMP_RE = /\(as of\s+([^\n\r\)]+)\s+UTC\)/i;
const OVERALL_CONFIDENCE_RE = /Overall confidence:\s*([^\n\r]+)/i;
const STORY_CONFIDENCE_RE = /^Confidence:\s*([^\n\r]+)/im;
const COMPLETION_REASON_RE = /Completion reason:\s*([^\n\r]+)/i;
const URL_RE = /https?:\/\/[^\s)\]}"']+/gim;
const WEB_SEARCH_TOOL = "web__search";
const WEB_READ_TOOL = "web__read";
const MAX_SOURCE_DOMAIN_PREVIEW = 3;
const GOOGLE_FAVICON_BASE = "https://www.google.com/s2/favicons?domain=";
const MAX_THOUGHT_AGENTS = 8;
const MAX_THOUGHT_NOTES_PER_AGENT = 2;
const MAX_THOUGHT_NOTE_CHARS = 260;

interface ParsedWebSource {
  url: string;
  title?: string;
  domain?: string;
}

interface ParsedWebDocument {
  url: string;
  title?: string;
}

interface ParsedWebBundle {
  query?: string;
  url?: string;
  sources: ParsedWebSource[];
  documents: ParsedWebDocument[];
}

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

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function firstStringValue(...values: unknown[]): string | undefined {
  for (const value of values) {
    const text = getValueString(value).trim();
    if (text.length > 0) {
      return text;
    }
  }
  return undefined;
}

function parseOutputJsonObject(output: string): Record<string, unknown> | null {
  const trimmed = output.trim();
  if (!trimmed) return null;

  const candidates = [trimmed];
  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1));
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      const record = asRecord(parsed);
      if (record) {
        return record;
      }
    } catch {
      // Continue trying fallback candidates.
    }
  }

  return null;
}

function parseWebBundle(event: AgentEvent): ParsedWebBundle | null {
  const output = eventOutput(event);
  const payload = parseOutputJsonObject(output);
  if (!payload) return null;

  const sourcesRaw = Array.isArray(payload.sources) ? payload.sources : [];
  const documentsRaw = Array.isArray(payload.documents) ? payload.documents : [];

  const sources: ParsedWebSource[] = [];
  for (const entry of sourcesRaw) {
    const row = asRecord(entry);
    if (!row) continue;

    const url = firstStringValue(row.url);
    if (!url) continue;

    const parsed: ParsedWebSource = { url };
    const title = firstStringValue(row.title);
    const domain = firstStringValue(row.domain);
    if (title) parsed.title = title;
    if (domain) parsed.domain = domain;
    sources.push(parsed);
  }

  const documents: ParsedWebDocument[] = [];
  for (const entry of documentsRaw) {
    const row = asRecord(entry);
    if (!row) continue;

    const url = firstStringValue(row.url);
    if (!url) continue;

    const parsed: ParsedWebDocument = { url };
    const title = firstStringValue(row.title);
    if (title) parsed.title = title;
    documents.push(parsed);
  }

  return {
    query: firstStringValue(
      payload.query,
      event.details?.query,
      event.digest?.query,
    ),
    url: firstStringValue(payload.url, event.details?.url, event.digest?.url),
    sources,
    documents,
  };
}

function normalizedDomain(url: string): string | null {
  try {
    const host = new URL(url).hostname.trim().toLowerCase();
    if (!host) return null;
    return host.replace(/^www\./, "");
  } catch {
    return null;
  }
}

function faviconUrlForDomain(domain: string): string {
  return `${GOOGLE_FAVICON_BASE}${encodeURIComponent(domain)}&sz=256`;
}

function includeSourceUrl(
  rawUrl: string,
  sourceUrls: Set<string>,
  domainCounts: Map<string, number>,
): void {
  const trimmed = rawUrl.trim();
  if (!trimmed) return;
  sourceUrls.add(trimmed);
  const domain = normalizedDomain(trimmed);
  if (!domain) return;
  const current = domainCounts.get(domain) || 0;
  domainCounts.set(domain, current + 1);
}

function buildSourceSummary(events: ActivityEventRef[]): SourceSummary | null {
  const sourceUrls = new Set<string>();
  const domainCounts = new Map<string, number>();
  const searches: SourceSearchRow[] = [];
  const browses: SourceBrowseRow[] = [];
  const seenBrowseUrls = new Set<string>();

  for (const entry of events) {
    if (entry.kind !== "workload_event" && entry.kind !== "receipt_event") continue;
    const normalizedTool = (entry.toolName || "").trim().toLowerCase();
    if (
      !normalizedTool.includes(WEB_SEARCH_TOOL) &&
      !normalizedTool.includes(WEB_READ_TOOL)
    ) {
      continue;
    }

    const bundle = parseWebBundle(entry.event);
    const sourceCandidateUrls =
      bundle?.sources.map((source) => source.url) || extractUrls(eventOutput(entry.event));
    for (const url of sourceCandidateUrls) {
      includeSourceUrl(url, sourceUrls, domainCounts);
    }

    if (normalizedTool.includes(WEB_SEARCH_TOOL)) {
      const resultCount = sourceCandidateUrls.length;
      searches.push({
        query: bundle?.query || "web search",
        resultCount,
        stepIndex: entry.event.step_index,
      });
      continue;
    }

    if (normalizedTool.includes(WEB_READ_TOOL)) {
      const readUrl = firstStringValue(
        bundle?.url,
        bundle?.documents[0]?.url,
        bundle?.sources[0]?.url,
        sourceCandidateUrls[0],
      );
      if (!readUrl) continue;

      includeSourceUrl(readUrl, sourceUrls, domainCounts);
      if (seenBrowseUrls.has(readUrl)) continue;
      seenBrowseUrls.add(readUrl);

      browses.push({
        url: readUrl,
        domain: normalizedDomain(readUrl) || "unknown",
        title: firstStringValue(bundle?.documents[0]?.title, bundle?.sources[0]?.title),
        stepIndex: entry.event.step_index,
      });
    }
  }

  const totalSources =
    sourceUrls.size > 0
      ? sourceUrls.size
      : searches.reduce((sum, row) => sum + row.resultCount, 0);

  if (totalSources === 0 && searches.length === 0 && browses.length === 0) {
    return null;
  }

  const domains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_SOURCE_DOMAIN_PREVIEW)
    .map(([domain, count]) => ({
      domain,
      count,
      faviconUrl: faviconUrlForDomain(domain),
    }));

  return {
    totalSources,
    sourceUrls: Array.from(sourceUrls),
    domains,
    searches,
    browses,
  };
}

function normalizeThoughtNote(raw: string): string {
  const compact = raw.replace(/\s+/g, " ").trim();
  if (!compact) return "";
  if (compact.length <= MAX_THOUGHT_NOTE_CHARS) return compact;
  return `${compact.slice(0, MAX_THOUGHT_NOTE_CHARS - 1).trim()}…`;
}

function buildThoughtSummary(groups: ActivityGroup[]): ThoughtSummary | null {
  const agents: ThoughtSummary["agents"] = [];

  for (const group of groups) {
    if (agents.length >= MAX_THOUGHT_AGENTS) break;
    const notes: string[] = [];
    const seenNotes = new Set<string>();

    for (const entry of group.events) {
      if (entry.kind === "receipt_event") continue;

      const tool = (entry.toolName || "").trim().toLowerCase();
      if (tool.includes(WEB_SEARCH_TOOL) || tool.includes(WEB_READ_TOOL)) {
        continue;
      }

      const candidate = normalizeThoughtNote(
        eventOutput(entry.event) || entry.event.title || "",
      );
      if (!candidate) continue;

      const dedup = candidate.toLowerCase();
      if (seenNotes.has(dedup)) continue;
      seenNotes.add(dedup);
      notes.push(candidate);

      if (notes.length >= MAX_THOUGHT_NOTES_PER_AGENT) {
        break;
      }
    }

    if (notes.length === 0) continue;

    agents.push({
      agentLabel: `Agent ${agents.length + 1}`,
      stepIndex: group.stepIndex,
      notes,
    });
  }

  if (agents.length === 0) return null;
  return { agents };
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
  const sourceSummary = buildSourceSummary(deduped);
  const thoughtSummary = buildThoughtSummary(activityGroups);

  return {
    prompt,
    finalAnswer,
    sourceSummary,
    thoughtSummary,
    activitySummary: buildActivitySummary(deduped, artifacts),
    activityGroups,
    artifactRefs: collectArtifactRefs(deduped, artifacts),
  };
}
