import type {
  ActivityEventRef,
  ActivityGroup,
  ActivitySummary,
  Artifact,
  ArtifactRef,
  PlanSummary,
  SourceBrowseRow,
  SourceSearchRow,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import {
  eventOutput,
  extractUrls,
  faviconUrlForDomain,
  firstStringValue,
  normalizedDomain,
  parseWebBundle,
  toValueString,
  WEB_READ_TOOL,
  WEB_SEARCH_TOOL,
} from "./contentPipeline.helpers";

const MAX_SOURCE_DOMAIN_PREVIEW = 3;
const MAX_THOUGHT_AGENTS = 8;
const MAX_THOUGHT_NOTES_PER_AGENT = 2;
const MAX_THOUGHT_NOTE_CHARS = 260;

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

export function buildSourceSummary(events: ActivityEventRef[]): SourceSummary | null {
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
      searches.push({
        query: bundle?.query || "web search",
        resultCount: sourceCandidateUrls.length,
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
  return `${compact.slice(0, MAX_THOUGHT_NOTE_CHARS - 3).trim()}...`;
}

export function buildThoughtSummary(groups: ActivityGroup[]): ThoughtSummary | null {
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

      const candidate = normalizeThoughtNote(eventOutput(entry.event) || entry.event.title || "");
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

export function buildPlanSummary(events: ActivityEventRef[]): PlanSummary | null {
  const candidates = events
    .map((entry) => entry.event)
    .filter((event) => {
      const title = (event.title || "").toLowerCase();
      const digest = event.digest || {};
      const details = event.details || {};
      return (
        title.includes("plan") ||
        typeof digest.selected_route === "string" ||
        typeof details.selected_route === "string"
      );
    });
  if (candidates.length === 0) {
    return null;
  }

  const latest = candidates[candidates.length - 1];
  const details = latest.details || {};
  const digest = latest.digest || {};
  const selectedRoute =
    firstStringValue(
      details.selected_route,
      digest.selected_route,
      details.route,
      digest.route,
    ) || "unknown";
  const status = firstStringValue(details.status, digest.status) || "captured";
  const workerGraph =
    (Array.isArray(details.worker_graph) ? details.worker_graph : undefined) ||
    (Array.isArray(digest.worker_graph) ? digest.worker_graph : undefined) ||
    [];
  const policyBindingsRaw =
    (Array.isArray(details.policy_bindings) ? details.policy_bindings : undefined) ||
    (Array.isArray(digest.policy_bindings) ? digest.policy_bindings : undefined) ||
    [];
  const policyBindings = policyBindingsRaw
    .map((value) => toValueString(value).trim())
    .filter((value) => value.length > 0);

  return {
    selectedRoute,
    status,
    workerCount: workerGraph.length,
    policyBindings,
  };
}

function groupTitle(stepIndex: number, events: ActivityEventRef[]): string {
  const firstTool = events.find((entry) => entry.toolName)?.toolName;
  if (firstTool) {
    return `Step ${stepIndex} · ${firstTool}`;
  }

  return `Step ${stepIndex}`;
}

export function buildActivityGroups(deduped: ActivityEventRef[]): ActivityGroup[] {
  const byStep = new Map<number, ActivityEventRef[]>();
  for (const entry of deduped) {
    const list = byStep.get(entry.event.step_index) || [];
    list.push(entry);
    byStep.set(entry.event.step_index, list);
  }

  const orderedStepIndexes = Array.from(byStep.keys()).sort((a, b) => a - b);
  return orderedStepIndexes.map((stepIndex) => {
    const entries = byStep.get(stepIndex) || [];
    entries.sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp));
    return {
      stepIndex,
      title: groupTitle(stepIndex, entries),
      events: entries,
    };
  });
}

export function buildActivitySummary(
  events: ActivityEventRef[],
  artifacts: Artifact[],
): ActivitySummary {
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
      if (tool.includes(WEB_SEARCH_TOOL)) {
        searchCount += 1;
      } else if (tool.includes(WEB_READ_TOOL)) {
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

export function collectArtifactRefs(
  events: ActivityEventRef[],
  artifacts: Artifact[],
): ArtifactRef[] {
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
