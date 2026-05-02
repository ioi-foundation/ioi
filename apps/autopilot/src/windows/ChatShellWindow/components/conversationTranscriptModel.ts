import type {
  ActivityEventRef,
  PlanSummary,
  ChatArtifactSession,
  ToolActivityGroupPresentation,
} from "../../../types";
import type { ConversationArtifactEntry } from "./artifactConversationModel";
import {
  asRecord,
  firstStringValue,
  normalizedDomain,
  parseOutputJsonObject,
  parseWebBundle,
  WEB_READ_TOOL,
  WEB_SEARCH_TOOL,
} from "../viewmodels/contentPipeline.helpers";
import {
  buildOperatorActivityRows,
  type TurnActivityEntry,
  toolGroupLabel,
} from "./transcript/activityRows";
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

function humanizeToolName(toolName: string): string {
  return toolName
    .trim()
    .split(":")[0]
    .replace(/[_:]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
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

function rowStatusFromEvent(entry: ActivityEventRef): "active" | "blocked" | "complete" {
  const status = toEventString(entry.event.status).trim().toUpperCase();
  if (status === "PARTIAL" || status === "RUNNING" || status === "ACTIVE") {
    return "active";
  }
  if (status === "ERROR" || status === "FAILED" || status === "BLOCKED") {
    return "blocked";
  }
  return "complete";
}

function commandActivityLabel(
  entry: ActivityEventRef,
  digest: Record<string, unknown>,
  details: Record<string, unknown>,
): string | null {
  const receiptKind = toEventString(digest.kind).trim().toLowerCase();
  const payload = asRecord(details.payload) || {};
  const toolName = firstStringValue(digest.tool_name, details.tool_name, entry.toolName);
  const commandPreview = firstStringValue(
    digest.command_preview,
    details.command_preview,
    payload.command_preview,
  );
  const toolLabel = toolName ? humanizeToolName(toolName) : "";
  const commandLabel = commandPreview || toolLabel;
  if (!commandLabel) {
    return null;
  }
  if (entry.event.event_type === "COMMAND_STREAM") {
    return rowStatusFromEvent(entry) === "active"
      ? `Running ${commandLabel}`
      : `Ran ${commandLabel}`;
  }
  if (entry.event.event_type === "COMMAND_RUN" || receiptKind === "exec") {
    return `Ran ${commandLabel}`;
  }
  return null;
}

type BuildTurnToolActivityOptions = {
  defaultOpen?: boolean;
  chatSession?: ChatArtifactSession | null;
};

function artifactPreviewRow(
  artifact: ConversationArtifactEntry,
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
  artifact: ConversationArtifactEntry,
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


export function buildTurnToolActivityGroup(
  events: ActivityEventRef[],
  planSummary: PlanSummary | null,
  artifacts: ConversationArtifactEntry[],
  options: BuildTurnToolActivityOptions = {},
): ToolActivityGroupPresentation | null {
  const chatSession = options.chatSession || artifacts[0]?.chatSession || null;
  const operatorRows = buildOperatorActivityRows(chatSession);
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
        continue;
      }

      const commandLabel = commandActivityLabel(entry, digest, details);
      if (commandLabel) {
        const commandPreview =
          firstStringValue(
            digest.command_preview,
            details.command_preview,
            asRecord(details.payload)?.command_preview,
          ) || null;
        appendRow(rows, seen, {
          key: `command:${entry.event.step_index}:${commandLabel.toLowerCase()}`,
          kind: "command",
          status: rowStatusFromEvent(entry),
          stepIndex: entry.event.step_index,
          label: commandLabel,
          detail: commandPreview,
          preview:
            firstStringValue(details.summary, digest.summary, details.chunk, details.output) ||
            null,
          sourceUrl: null,
          sortOrder: 1_500 + entry.event.step_index,
          phaseOrder: 600,
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
    !!chatSession ||
    artifacts.length > 0 ||
    planSummary?.routeFamily === "research" ||
    planSummary?.routeFamily === "artifacts";

  return {
    key: chatSession
      ? `tool-group:${chatSession.sessionId}:${chatSession.originPromptEventId || "turn"}`
      : `tool-group:${rows[0]?.stepIndex || 0}:${rows.length}`,
    label: toolGroupLabel(rows, chatSession),
    rows: rows.map(
      ({ sortOrder: _sortOrder, phaseOrder: _phaseOrder, source: _source, ...row }) => row,
    ),
    defaultOpen: Boolean(options.defaultOpen),
    presentation: hasInlineTranscript ? "inline_transcript" : "default",
  };
}

export function formatTurnDurationSeconds(seconds: number): string {
  const safeSeconds = Math.max(1, Math.round(seconds));
  if (safeSeconds < 60) {
    return `${safeSeconds}s`;
  }
  const minutes = Math.floor(safeSeconds / 60);
  const remainder = safeSeconds % 60;
  if (minutes < 60) {
    return remainder > 0 ? `${minutes}m ${remainder}s` : `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const minuteRemainder = minutes % 60;
  return minuteRemainder > 0 ? `${hours}h ${minuteRemainder}m` : `${hours}h`;
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
  return formatTurnDurationSeconds(seconds);
}
