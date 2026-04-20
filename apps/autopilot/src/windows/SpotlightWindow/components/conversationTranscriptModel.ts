import type {
  ActivityEventRef,
  PlanSummary,
  SourceSummary,
  StudioArtifactSession,
  ToolActivityGroupPresentation,
  ToolActivityRow,
  ToolActivityKind,
  ToolActivityStatus,
} from "../../../types";
import type { StudioConversationArtifactEntry } from "./studioArtifactConversationModel";
import {
  asRecord,
  firstStringValue,
  normalizedDomain,
  parseOutputJsonObject,
  parseWebBundle,
  WEB_READ_TOOL,
  WEB_SEARCH_TOOL,
} from "../viewmodels/contentPipeline.helpers";
import { parseTimestampMs, toEventString } from "../utils/eventFields";

function basename(path: string): string {
  const trimmed = path.trim().replace(/\/+$/g, "");
  if (!trimmed) {
    return "file";
  }
  const slashIndex = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  return slashIndex >= 0 ? trimmed.slice(slashIndex + 1) || trimmed : trimmed;
}

function humanizeFsOperation(operation: string): string {
  const normalized = operation.trim().toLowerCase();
  if (normalized.includes("copy") || normalized.includes("move")) {
    return "Saved";
  }
  if (
    normalized.includes("replace")
    || normalized.includes("edit")
    || normalized.includes("multi_edit")
  ) {
    return "Updated";
  }
  return "Wrote";
}

function previewLines(lines: string[]): string | null {
  const compact = lines
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter((line) => line.length > 0)
    .slice(0, 8);
  if (compact.length === 0) {
    return null;
  }
  return compact.join("\n");
}

function webSearchPreview(entry: ActivityEventRef): string | null {
  const bundle = parseWebBundle(entry.event);
  if (!bundle) {
    return null;
  }
  const lines = bundle.sources.map((source) => {
    const domain = source.domain || normalizedDomain(source.url) || source.url;
    const title = source.title?.trim();
    return title ? `${title} - ${domain}` : domain;
  });
  return previewLines(lines);
}

function webReadPreview(entry: ActivityEventRef): string | null {
  const payload = parseOutputJsonObject(
    toEventString(entry.event.details?.output).trim(),
  );
  const documents = Array.isArray(payload?.documents) ? payload?.documents : [];
  const firstDocument = documents.find((candidate) => asRecord(candidate)) as
    | Record<string, unknown>
    | undefined;
  const preview =
    firstStringValue(
      firstDocument?.content_text,
      firstDocument?.content,
      firstDocument?.excerpt,
      payload?.content_text,
      payload?.content,
      payload?.excerpt,
    ) || "";
  const compact = preview.replace(/\s+/g, " ").trim();
  if (!compact) {
    return null;
  }
  return compact.length <= 640 ? compact : `${compact.slice(0, 637).trim()}...`;
}

function rowStatusFromEvent(entry: ActivityEventRef): ToolActivityStatus {
  const status = toEventString(entry.event.status).trim().toUpperCase();
  if (status === "ERROR" || status === "FAILED" || status === "BLOCKED") {
    return "blocked";
  }
  return "complete";
}

type TurnActivityEntry = ToolActivityRow & {
  sortOrder: number;
  phaseOrder: number;
  source: "receipt" | "runtime" | "artifact" | "operator";
};

const OPERATOR_PHASE_ORDER: Record<string, number> = {
  understand_request: 100,
  route_artifact: 200,
  search_sources: 300,
  read_sources: 400,
  author_artifact: 500,
  repair_artifact: 550,
  inspect_artifact: 600,
  verify_artifact: 700,
  present_artifact: 800,
};

function operatorPhaseOrder(phase: string | null | undefined): number {
  const normalized = String(phase || "").trim().toLowerCase();
  return OPERATOR_PHASE_ORDER[normalized] ?? 9_000;
}

type BuildTurnToolActivityOptions = {
  defaultOpen?: boolean;
  studioSession?: StudioArtifactSession | null;
};

function artifactPreviewRow(
  artifact: StudioConversationArtifactEntry,
): TurnActivityEntry {
  return {
    key: `preview:${artifact.sessionId}`,
    kind: "present",
    status: "complete",
    stepIndex: Number.MAX_SAFE_INTEGER,
    label: `Preview ready for ${artifact.title}`,
    detail: artifact.summary.trim() || null,
    preview: null,
    sourceUrl: null,
    sortOrder: 9_900,
    phaseOrder: 9_900,
    source: "artifact",
  };
}

function artifactVerificationRow(
  artifact: StudioConversationArtifactEntry,
  planSummary: PlanSummary | null,
): TurnActivityEntry | null {
  const quality = planSummary?.artifactQuality;
  if (!quality) {
    return null;
  }

  const detail = quality.notes?.trim()
    || `Fidelity ${quality.fidelityStatus}. Presentation ${quality.presentationStatus}.`;
  return {
    key: `verify:${artifact.sessionId}:${quality.verdict}`,
    kind: "verify",
    status: quality.verdict === "blocked" ? "blocked" : "complete",
    stepIndex: Number.MAX_SAFE_INTEGER - 1,
    label: `Verified ${artifact.title}`,
    detail,
    preview: null,
    sourceUrl: null,
    sortOrder: 9_800,
    phaseOrder: 9_800,
    source: "artifact",
  };
}

function appendRow(
  rows: TurnActivityEntry[],
  seen: Set<string>,
  row: TurnActivityEntry | null,
): void {
  if (!row || seen.has(row.key)) {
    return;
  }
  seen.add(row.key);
  rows.push(row);
}

function operatorStepStatus(value: string | null | undefined): ToolActivityStatus {
  const normalized = String(value || "").trim().toLowerCase();
  if (
    normalized === "active"
    || normalized === "pending"
    || normalized === "other"
  ) {
    return "active";
  }
  if (normalized === "blocked" || normalized === "failed") {
    return "blocked";
  }
  return "complete";
}

function operatorStepKind(phase: string | null | undefined): ToolActivityKind {
  switch (String(phase || "").trim().toLowerCase()) {
    case "understand_request":
      return "understand";
    case "route_artifact":
      return "route";
    case "search_sources":
      return "search";
    case "read_sources":
      return "read";
    case "author_artifact":
    case "repair_artifact":
      return "write";
    case "inspect_artifact":
      return "inspect";
    case "verify_artifact":
      return "verify";
    case "present_artifact":
      return "present";
    default:
      return "other";
  }
}

function operatorStepPreview(
  step: NonNullable<StudioArtifactSession["activeOperatorRun"]>["steps"][number],
): string | null {
  if (step.preview?.content?.trim()) {
    return step.preview.content.trim();
  }

  if (step.sourceRefs.length > 0) {
    const lines = step.sourceRefs
      .slice(0, 6)
      .map((source) => source.excerpt?.trim() || source.title.trim())
      .filter((line) => line.length > 0);
    if (lines.length > 0) {
      return lines.join("\n");
    }
  }

  if (step.verificationRefs.length > 0) {
    const lines = step.verificationRefs
      .slice(0, 6)
      .map((verification) =>
        verification.detail?.trim()
          ? `${verification.summary}\n${verification.detail}`
          : verification.summary,
      )
      .filter((line) => line.trim().length > 0);
    if (lines.length > 0) {
      return lines.join("\n\n");
    }
  }

  return null;
}

function operatorStepSourceSummary(
  step: NonNullable<StudioArtifactSession["activeOperatorRun"]>["steps"][number],
  stepIndex: number,
): SourceSummary | null {
  const sourceUrls = new Set<string>();
  const domainCounts = new Map<string, number>();
  const browses: SourceSummary["browses"] = [];

  for (const source of step.sourceRefs) {
    const url = firstStringValue(source.url);
    if (!url) {
      continue;
    }
    if (!sourceUrls.has(url)) {
      sourceUrls.add(url);
      const domain =
        firstStringValue(source.domain) || normalizedDomain(url) || "unknown";
      domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
      browses.push({
        url,
        domain,
        title: firstStringValue(source.title) || undefined,
        stepIndex,
      });
    }
  }

  if (sourceUrls.size === 0) {
    return null;
  }

  const domains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([domain, count]) => ({
      domain,
      count,
      faviconUrl: `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(domain)}`,
    }));

  return {
    totalSources: sourceUrls.size,
    sourceUrls: Array.from(sourceUrls),
    domains,
    searches: [],
    browses,
  };
}

function sourceQueryFromReason(reason: string | null | undefined): string | null {
  const raw = String(reason || "").trim();
  if (!raw) {
    return null;
  }
  const quoted = raw.match(/for "([^"]+)"/i);
  if (quoted?.[1]?.trim()) {
    return quoted[1].trim();
  }
  return null;
}

function buildOperatorActivityRows(
  studioSession: StudioArtifactSession | null | undefined,
): TurnActivityEntry[] {
  const operatorRun = studioSession?.activeOperatorRun;
  if (!studioSession || !operatorRun) {
    return [];
  }

  const rows: TurnActivityEntry[] = [];
  operatorRun.steps.forEach((step, index) => {
    const sourceSummary =
      operatorStepStatus(step.status) === "active"
        ? operatorStepSourceSummary(step, index)
        : null;
    const phase = String(step.phase || "").trim().toLowerCase();
    const phaseOrder = operatorPhaseOrder(phase);
    if (phase === "search_sources") {
      const query =
        step.sourceRefs
          .map((source) => sourceQueryFromReason(source.reason))
          .find((value): value is string => !!value)
        || sourceQueryFromReason(step.detail)
        || sourceQueryFromReason(step.label);
      rows.push({
        key: step.stepId,
        kind: operatorStepKind(step.phase),
        status: operatorStepStatus(step.status),
        stepIndex: index,
        label: query ? `Searched "${query}"` : (step.label.trim() || "Search sources"),
        detail: step.detail?.trim() || null,
        preview: operatorStepPreview(step),
        sourceUrl: step.sourceRefs.find((source) => !!source.url)?.url || null,
        sourceSummary,
        sortOrder: step.startedAtMs || index,
        phaseOrder,
        source: "operator",
      });
      return;
    }

    if (phase === "read_sources" && step.sourceRefs.length > 0) {
      step.sourceRefs.forEach((source, sourceIndex) => {
        const url = firstStringValue(source.url);
        const domain =
          (url ? normalizedDomain(url) : null)
          || firstStringValue(source.domain)
          || source.title.trim()
          || "source";
        rows.push({
          key: `${step.stepId}:source:${source.sourceId || sourceIndex}`,
          kind: "read",
          status: operatorStepStatus(step.status),
          stepIndex: index,
          label: `Read ${domain}`,
          detail: url || null,
          preview: source.excerpt?.trim() || source.title.trim() || null,
          sourceUrl: url || null,
          sourceSummary: null,
          sortOrder: (step.startedAtMs || index) + (sourceIndex / 100),
          phaseOrder: phaseOrder + (sourceIndex / 100),
          source: "operator",
        });
      });
      return;
    }

    rows.push({
      key: step.stepId,
      kind: operatorStepKind(step.phase),
      status: operatorStepStatus(step.status),
      stepIndex: index,
      label: step.label.trim() || "Artifact step",
      detail: step.detail?.trim() || null,
      preview: operatorStepPreview(step),
      sourceUrl: step.sourceRefs.find((source) => !!source.url)?.url || null,
      sourceSummary,
      sortOrder: step.startedAtMs || index,
      phaseOrder,
      source: "operator",
    });
  });
  return rows;
}

function toolGroupLabel(
  rows: TurnActivityEntry[],
  studioSession: StudioArtifactSession | null,
): string {
  if (studioSession) {
    const hasActiveRow = rows.some((row) => row.status === "active");
    if (hasActiveRow) {
      return `Thinking through ${studioSession.title}`;
    }
    return `${studioSession.title} activity`;
  }

  return `${rows.length} ${rows.length === 1 ? "tool call" : "tool calls"}`;
}

export function buildTurnToolActivityGroup(
  events: ActivityEventRef[],
  planSummary: PlanSummary | null,
  artifacts: StudioConversationArtifactEntry[],
  options: BuildTurnToolActivityOptions = {},
): ToolActivityGroupPresentation | null {
  const studioSession = options.studioSession || artifacts[0]?.studioSession || null;
  const operatorRows = buildOperatorActivityRows(studioSession);
  const rows = [...operatorRows];
  const seen = new Set(rows.map((row) => row.key));

  if (operatorRows.length === 0) {
    for (const entry of events) {
      const toolName = (entry.toolName || "").trim().toLowerCase();
      const digest = asRecord(entry.event.digest) || {};
      const details = asRecord(entry.event.details) || {};
      const receiptKind = toEventString(digest.kind).trim().toLowerCase();

      if (
        toolName.includes(WEB_SEARCH_TOOL)
        || (receiptKind === "web_retrieve" && !!firstStringValue(details.query))
      ) {
        const bundle = parseWebBundle(entry.event);
        const query = firstStringValue(bundle?.query, details.query);
        if (!query) {
          continue;
        }
        appendRow(rows, seen, {
          key: `search:${query.toLowerCase()}`,
          kind: "search",
          status: rowStatusFromEvent(entry),
          stepIndex: entry.event.step_index,
          label: `Searched "${query}"`,
          detail: null,
          preview: webSearchPreview(entry),
          sourceUrl: null,
          sortOrder: 1_200 + entry.event.step_index,
          phaseOrder: 300,
          source: "receipt",
        });
        continue;
      }

      if (
        toolName.includes(WEB_READ_TOOL)
        || (receiptKind === "web_retrieve" && !!firstStringValue(details.url))
      ) {
        const bundle = parseWebBundle(entry.event);
        const readUrl = firstStringValue(bundle?.url, details.url);
        if (!readUrl) {
          continue;
        }
        const domain = normalizedDomain(readUrl) || readUrl;
        appendRow(rows, seen, {
          key: `read:${readUrl.toLowerCase()}`,
          kind: "read",
          status: rowStatusFromEvent(entry),
          stepIndex: entry.event.step_index,
          label: `Read ${domain}`,
          detail: readUrl,
          preview: webReadPreview(entry),
          sourceUrl: readUrl,
          sortOrder: 1_300 + entry.event.step_index,
          phaseOrder: 400,
          source: "receipt",
        });
        continue;
      }

      if (receiptKind === "fs_write") {
        const targetPath = firstStringValue(details.target_path, details.destination_path);
        if (!targetPath) {
          continue;
        }
        const operation = firstStringValue(digest.operation, details.operation) || "write";
        appendRow(rows, seen, {
          key: `write:${targetPath.toLowerCase()}`,
          kind: "write",
          status: rowStatusFromEvent(entry),
          stepIndex: entry.event.step_index,
          label: `${humanizeFsOperation(operation)} ${basename(targetPath)}`,
          detail: targetPath,
          preview: null,
          sourceUrl: null,
          sortOrder: 1_400 + entry.event.step_index,
          phaseOrder: 500,
          source: "receipt",
        });
      }
    }
  }

  const primaryArtifact = artifacts[0] || null;
  if (operatorRows.length === 0) {
    if (!rows.some((row) => row.kind === "verify")) {
      appendRow(
        rows,
        seen,
        primaryArtifact ? artifactVerificationRow(primaryArtifact, planSummary) : null,
      );
    }
    if (!rows.some((row) => row.kind === "present")) {
      appendRow(rows, seen, primaryArtifact ? artifactPreviewRow(primaryArtifact) : null);
    }
  }

  if (rows.length === 0) {
    return null;
  }

  rows.sort((left, right) => {
    if (left.phaseOrder !== right.phaseOrder) {
      return left.phaseOrder - right.phaseOrder;
    }
    if (left.sortOrder !== right.sortOrder) {
      return left.sortOrder - right.sortOrder;
    }
    if (left.stepIndex !== right.stepIndex) {
      return left.stepIndex - right.stepIndex;
    }
    return left.label.localeCompare(right.label);
  });

  const hasInlineTranscript =
    !!studioSession ||
    artifacts.length > 0 ||
    planSummary?.routeFamily === "research" ||
    planSummary?.routeFamily === "artifacts";

  return {
    key: studioSession
      ? `tool-group:${studioSession.sessionId}:${studioSession.originPromptEventId || "turn"}`
      : `tool-group:${rows[0]?.stepIndex || 0}:${rows.length}`,
    label: toolGroupLabel(rows, studioSession),
    rows: rows.map(
      ({ sortOrder: _sortOrder, phaseOrder: _phaseOrder, source: _source, ...row }) => row,
    ),
    defaultOpen: Boolean(options.defaultOpen),
    presentation: hasInlineTranscript ? "inline_transcript" : "default",
  };
}

export function buildReasoningDurationLabel(
  events: ActivityEventRef[],
  promptTimestamp: number | null,
): string | null {
  if (events.length === 0 || promptTimestamp === null) {
    return null;
  }

  const timestamps = events
    .map((entry) => parseTimestampMs(entry.event.timestamp))
    .filter((value): value is number => value !== null);
  if (timestamps.length === 0) {
    return null;
  }

  const latest = Math.max(...timestamps);
  const seconds = Math.max(1, Math.round((latest - promptTimestamp) / 1000));
  return `Thought for ${seconds} ${seconds === 1 ? "second" : "seconds"}`;
}
