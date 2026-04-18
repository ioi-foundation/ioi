import type {
  ActivityEventRef,
  PlanSummary,
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
  source: "receipt" | "runtime" | "artifact";
};

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

function runtimeEventKind(
  event: NonNullable<StudioArtifactSession["materialization"]["runtimeNarrationEvents"]>[number],
): string {
  return String(event.eventKindKey || event.eventKind || "").trim().toLowerCase();
}

function runtimeEventStepKey(
  event: NonNullable<StudioArtifactSession["materialization"]["runtimeNarrationEvents"]>[number],
): string {
  return String(event.stepKey || event.stepId || "").trim().toLowerCase();
}

function runtimeEventStatus(
  event: NonNullable<StudioArtifactSession["materialization"]["runtimeNarrationEvents"]>[number],
): ToolActivityStatus {
  const status = String(event.statusKind || event.status || "").trim().toLowerCase();
  if (status === "active" || status === "pending") {
    return "active";
  }
  if (status === "blocked" || status === "failed" || status === "interrupted") {
    return "blocked";
  }
  return "complete";
}

function runtimeStepSortOrder(stepKey: string): number {
  switch (stepKey) {
    case "understand_request":
      return 100;
    case "artifact_route_committed":
      return 200;
    case "skill_discovery":
      return 300;
    case "skill_read":
      return 350;
    case "artifact_brief":
      return 400;
    case "author_artifact":
      return 500;
    case "replan_execution":
      return 550;
    case "verify_artifact":
      return 700;
    case "present_artifact":
      return 900;
    default:
      return 1_000;
  }
}

function runtimeStepKind(stepKey: string): ToolActivityKind {
  switch (stepKey) {
    case "understand_request":
      return "understand";
    case "artifact_route_committed":
      return "route";
    case "skill_discovery":
    case "skill_read":
    case "artifact_brief":
      return "guidance";
    case "author_artifact":
      return "write";
    case "verify_artifact":
      return "verify";
    case "present_artifact":
      return "present";
    default:
      return "other";
  }
}

function artifactPrimaryPath(
  studioSession: StudioArtifactSession | null | undefined,
): string | null {
  if (!studioSession) {
    return null;
  }
  const primaryFile =
    studioSession.artifactManifest.files.find(
      (file) => file.path === studioSession.artifactManifest.primaryTab,
    ) ||
    studioSession.artifactManifest.files.find(
      (file) => file.renderable && typeof file.path === "string",
    ) ||
    studioSession.artifactManifest.files[0];
  return typeof primaryFile?.path === "string" ? primaryFile.path : null;
}

function runtimeStepLabel(
  stepKey: string,
  event: NonNullable<StudioArtifactSession["materialization"]["runtimeNarrationEvents"]>[number],
  studioSession: StudioArtifactSession | null,
): string {
  const authorTarget = artifactPrimaryPath(studioSession);
  const authorLabel = authorTarget ? basename(authorTarget) : "artifact";

  switch (stepKey) {
    case "understand_request":
      return "Understand request";
    case "artifact_route_committed":
      return "Route to artifact";
    case "skill_discovery":
      return event.title || "Check for guidance";
    case "skill_read":
      return event.title || "Read guidance";
    case "artifact_brief":
      return event.title || "Shape artifact brief";
    case "author_artifact":
      return runtimeEventStatus(event) === "complete"
        ? `Wrote ${authorLabel}`
        : `Write ${authorLabel}`;
    case "replan_execution":
      return event.title || "Switch execution strategy";
    case "verify_artifact":
      return "Verify artifact";
    case "present_artifact":
      return runtimeEventStatus(event) === "blocked" ? "Present artifact" : "Open preview";
    default:
      return event.title || "Artifact step";
  }
}

function renderEvaluationDetail(
  studioSession: StudioArtifactSession | null,
  planSummary: PlanSummary | null,
): {
  status: ToolActivityStatus;
  detail: string | null;
} | null {
  const renderEvaluation = studioSession?.materialization.renderEvaluation;
  if (renderEvaluation) {
    const failedObligation = renderEvaluation.acceptanceObligations.find(
      (obligation) =>
        obligation.required
        && (obligation.status === "failed" || obligation.status === "blocked"),
    );
    if (failedObligation) {
      const witnessSummary = renderEvaluation.executionWitnesses
        .filter((witness) => witness.status === "failed" || witness.status === "blocked")
        .slice(0, 2)
        .map((witness) => witness.summary.trim())
        .filter(Boolean)
        .join("\n");
      const detail = [failedObligation.summary, failedObligation.detail, witnessSummary]
        .filter((value): value is string => !!value && value.trim().length > 0)
        .join("\n");
      return {
        status: "blocked",
        detail,
      };
    }

    if (renderEvaluation.summary.trim()) {
      return {
        status: "complete",
        detail: renderEvaluation.summary.trim(),
      };
    }
  }

  const quality = planSummary?.artifactQuality;
  if (!quality) {
    return null;
  }

  return {
    status: quality.verdict === "blocked" ? "blocked" : "complete",
    detail:
      quality.notes?.trim()
      || `Fidelity ${quality.fidelityStatus}. Presentation ${quality.presentationStatus}.`,
  };
}

function buildRuntimeActivityRows(
  studioSession: StudioArtifactSession | null | undefined,
  planSummary: PlanSummary | null,
): TurnActivityEntry[] {
  if (!studioSession) {
    return [];
  }

  const entries = new Map<string, TurnActivityEntry>();
  const runtimeNarrationEvents = [...studioSession.materialization.runtimeNarrationEvents].sort(
    (left, right) =>
      (left.occurredAtMs || 0) - (right.occurredAtMs || 0)
      || String(left.eventId || "").localeCompare(String(right.eventId || "")),
  );

  runtimeNarrationEvents.forEach((event, index) => {
    const stepKey = runtimeEventStepKey(event);
    if (!stepKey) {
      return;
    }
    const key = `runtime:${studioSession.sessionId}:${stepKey}:${event.attemptId || "base"}`;
    const existing = entries.get(key);
    const next: TurnActivityEntry = existing || {
      key,
      kind: runtimeStepKind(stepKey),
      status: runtimeEventStatus(event),
      stepIndex: index,
      label: runtimeStepLabel(stepKey, event, studioSession),
      detail: null,
      preview: null,
      sourceUrl: null,
      sortOrder: runtimeStepSortOrder(stepKey) + index,
      source: "runtime",
    };

    next.kind = runtimeStepKind(stepKey);
    next.status = runtimeEventStatus(event);
    next.label = runtimeStepLabel(stepKey, event, studioSession);
    next.detail = event.detail?.trim() || next.detail;

    if (runtimeEventKind(event) === "preview" && event.preview?.content?.trim()) {
      next.preview = event.preview.content;
      if (!next.detail && event.detail?.trim()) {
        next.detail = event.detail.trim();
      }
    }

    entries.set(key, next);
  });

  const verifyDetail = renderEvaluationDetail(studioSession, planSummary);
  const verifyKey = `runtime:${studioSession.sessionId}:verify_artifact:base`;
  if (verifyDetail) {
    const existingVerify = entries.get(verifyKey);
    if (existingVerify) {
      existingVerify.status = verifyDetail.status;
      existingVerify.detail = verifyDetail.detail;
    } else {
      entries.set(verifyKey, {
        key: verifyKey,
        kind: "verify",
        status: verifyDetail.status,
        stepIndex: Number.MAX_SAFE_INTEGER - 2,
        label: "Verify artifact",
        detail: verifyDetail.detail,
        preview: null,
        sourceUrl: null,
        sortOrder: runtimeStepSortOrder("verify_artifact"),
        source: "runtime",
      });
    }
  }

  return Array.from(entries.values());
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
  const rows = buildRuntimeActivityRows(studioSession, planSummary);
  const seen = new Set(rows.map((row) => row.key));

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
      const query = firstStringValue(
        bundle?.query,
        details.query,
      );
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
      const runtimeWriteRow = rows.find(
        (row) => row.source === "runtime" && row.kind === "write",
      );
      if (runtimeWriteRow) {
        runtimeWriteRow.label =
          runtimeWriteRow.status === "active"
            ? `Write ${basename(targetPath)}`
            : `${humanizeFsOperation(operation)} ${basename(targetPath)}`;
        runtimeWriteRow.detail = targetPath;
      } else {
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
          source: "receipt",
        });
      }
      continue;
    }
  }

  const primaryArtifact = artifacts[0] || null;
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

  if (rows.length === 0) {
    return null;
  }

  rows.sort((left, right) => {
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
    rows: rows.map(({ sortOrder: _sortOrder, source: _source, ...row }) => row),
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
