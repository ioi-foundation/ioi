import { useCallback, useEffect, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import { icons } from "./Icons";
import {
  ArtifactHubDetailView,
  type KernelLogRow,
  type SecurityPolicyRow,
  type SubstrateReceiptRow,
} from "./ArtifactHubViews";
import {
  collectScreenshotReceipts,
  type ScreenshotReceiptEvidence,
} from "../utils/screenshotEvidence";
import {
  eventOutputText,
  eventToolName,
  parseTimestampMs,
  toEventString,
} from "../utils/eventFields";
import {
  buildEventTurnWindows,
  eventBelongsToTurnWindow,
} from "../utils/turnWindows";
import { buildPlanSummary } from "../viewmodels/contentPipeline.summaries";

interface ArtifactHubSidebarProps {
  initialView?: ArtifactHubViewKey;
  initialTurnId?: string | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  onOpenArtifact?: (artifactId: string) => void;
  onClose: () => void;
}

interface HubSection {
  key: ArtifactHubViewKey;
  label: string;
  count: number;
}

type TurnSelection = "all" | string;

const MAX_KERNEL_LOG_ROWS = 240;
const MAX_SUMMARY_CHARS = 220;
const TURN_FILTER_VIEWS = new Set<ArtifactHubViewKey>([
  "active_context",
  "thoughts",
  "substrate",
  "sources",
  "kernel_logs",
  "security_policy",
  "files",
  "revisions",
  "screenshots",
]);

function clipText(value: string, maxChars: number = MAX_SUMMARY_CHARS): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function eventSummary(event: AgentEvent): string {
  return clipText(eventOutputText(event));
}

function formatTimestamp(value: string): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return value;
  return new Date(ms).toISOString();
}

function eventHasPolicyDigest(event: AgentEvent): boolean {
  const digest = event.digest || {};
  const policyKeys = [
    "policy_decision",
    "gate_state",
    "resolution_action",
    "incident_stage",
    "strategy_node",
  ];
  return policyKeys.some(
    (key) =>
      toEventString(digest[key as keyof typeof digest]).trim().length > 0,
  );
}

function toOptionalNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function toOptionalBool(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return null;
}

function extractArtifactUrl(artifact: Artifact): string | null {
  const metadata = artifact.metadata || {};
  const candidates = [
    metadata.url,
    metadata.source_url,
    metadata.screenshot_url,
  ];
  for (const candidate of candidates) {
    const text = toEventString(candidate).trim();
    if (text.startsWith("https://") || text.startsWith("http://")) {
      return text;
    }
  }
  return null;
}

function sectionLabel(key: ArtifactHubViewKey): string {
  switch (key) {
    case "active_context":
      return "Plan";
    case "thoughts":
      return "Workers";
    case "substrate":
      return "Runtime proof";
    case "sources":
      return "Evidence";
    case "kernel_logs":
      return "Raw trace";
    case "security_policy":
      return "Verification";
    case "files":
      return "Outputs";
    case "revisions":
      return "Bundles";
    case "screenshots":
      return "Visual evidence";
    default:
      return "Evidence";
  }
}

function defaultViewForSections(sections: HubSection[]): ArtifactHubViewKey {
  return sections.find((section) => section.count > 0)?.key || "sources";
}

export function ArtifactHubSidebar({
  initialView,
  initialTurnId,
  events,
  artifacts,
  sourceSummary,
  thoughtSummary,
  onOpenArtifact,
  onClose,
}: ArtifactHubSidebarProps) {
  const turnWindows = useMemo(() => buildEventTurnWindows(events), [events]);
  const latestTurn =
    turnWindows.length > 0 ? turnWindows[turnWindows.length - 1] : null;
  const [turnSelection, setTurnSelection] = useState<TurnSelection>("all");

  useEffect(() => {
    if (turnWindows.length === 0) {
      setTurnSelection("all");
      return;
    }

    const requested = (initialTurnId || "").trim();
    if (requested && turnWindows.some((turn) => turn.id === requested)) {
      setTurnSelection(requested);
      return;
    }

    setTurnSelection((previous) => {
      if (previous === "all") {
        return latestTurn?.id || "all";
      }
      if (turnWindows.some((turn) => turn.id === previous)) {
        return previous;
      }
      return latestTurn?.id || "all";
    });
  }, [initialTurnId, latestTurn?.id, turnWindows]);

  const selectedTurn = useMemo(() => {
    if (turnSelection === "all") return null;
    return turnWindows.find((turn) => turn.id === turnSelection) || null;
  }, [turnSelection, turnWindows]);

  const scopedEvents = useMemo(() => {
    if (!selectedTurn) return events;
    return events.filter((event) =>
      eventBelongsToTurnWindow(event, selectedTurn),
    );
  }, [events, selectedTurn]);
  const scopedPlanSummary = useMemo(
    () =>
      buildPlanSummary(
        scopedEvents.map((event) => ({
          key: event.event_id,
          kind:
            event.event_type === "RECEIPT"
              ? "receipt_event"
              : event.event_type === "INFO_NOTE"
                ? "reasoning_event"
                : "workload_event",
          event,
          toolName: eventToolName(event),
        })),
      ),
    [scopedEvents],
  );
  const scopedArtifacts = useMemo(() => {
    if (!selectedTurn) return artifacts;
    return artifacts.filter((artifact) => {
      const createdAtMs = parseTimestampMs(artifact.created_at);
      if (
        selectedTurn.startAtMs !== null &&
        createdAtMs !== null &&
        createdAtMs < selectedTurn.startAtMs
      ) {
        return false;
      }
      if (
        selectedTurn.endAtMs !== null &&
        createdAtMs !== null &&
        createdAtMs >= selectedTurn.endAtMs
      ) {
        return false;
      }
      return true;
    });
  }, [artifacts, selectedTurn]);
  const visibleStepIndexes = useMemo(() => {
    if (!selectedTurn) return null;
    return new Set(scopedEvents.map((event) => event.step_index));
  }, [scopedEvents, selectedTurn]);

  const isStepVisible = useCallback(
    (stepIndex: number) => {
      if (!visibleStepIndexes) return true;
      return visibleStepIndexes.has(stepIndex);
    },
    [visibleStepIndexes],
  );

  const searches = useMemo(
    () =>
      [...(sourceSummary?.searches || [])]
        .filter((entry) => isStepVisible(entry.stepIndex))
        .sort((a, b) => a.stepIndex - b.stepIndex),
    [isStepVisible, sourceSummary?.searches],
  );
  const browses = useMemo(
    () =>
      [...(sourceSummary?.browses || [])]
        .filter((entry) => isStepVisible(entry.stepIndex))
        .sort((a, b) => a.stepIndex - b.stepIndex),
    [isStepVisible, sourceSummary?.browses],
  );
  const thoughtAgents = useMemo(
    () =>
      (thoughtSummary?.agents || []).filter((agent) =>
        isStepVisible(agent.stepIndex),
      ),
    [isStepVisible, thoughtSummary?.agents],
  );
  const visibleSourceCount = useMemo(() => {
    if (!selectedTurn) {
      return sourceSummary?.totalSources || 0;
    }
    const searchTotal = searches.reduce(
      (sum, row) => sum + Math.max(0, row.resultCount),
      0,
    );
    return Math.max(searchTotal, browses.length);
  }, [browses.length, searches, selectedTurn, sourceSummary?.totalSources]);

  const kernelLogs = useMemo<KernelLogRow[]>(() => {
    const rows = scopedEvents
      .slice()
      .reverse()
      .slice(0, MAX_KERNEL_LOG_ROWS)
      .map((event) => ({
        eventId: event.event_id,
        timestamp: formatTimestamp(event.timestamp),
        title: event.title,
        eventType: event.event_type,
        status: event.status.toLowerCase(),
        toolName: eventToolName(event),
        summary: eventSummary(event),
      }));
    return rows;
  }, [scopedEvents]);

  const securityRows = useMemo<SecurityPolicyRow[]>(() => {
    const rows: SecurityPolicyRow[] = [];
    for (const event of scopedEvents) {
      const title = event.title.toLowerCase();
      if (
        event.event_type !== "RECEIPT" &&
        !eventHasPolicyDigest(event) &&
        !title.includes("routingreceipt") &&
        !title.includes("restricted action")
      ) {
        continue;
      }

      const digest = event.digest || {};
      const decision =
        toEventString(digest.policy_decision).trim() ||
        (event.event_type === "RECEIPT" ? "receipt" : "policy");
      const stage = toEventString(digest.incident_stage).trim() || "n/a";
      const resolution =
        toEventString(digest.resolution_action).trim() || "n/a";
      const reportArtifactId =
        event.artifact_refs?.find((ref) => ref.artifact_type === "REPORT")
          ?.artifact_id || null;

      rows.push({
        eventId: event.event_id,
        timestamp: formatTimestamp(event.timestamp),
        decision,
        toolName: eventToolName(event) || "system",
        stage,
        resolution,
        summary: eventSummary(event),
        reportArtifactId,
      });
    }
    return rows.reverse();
  }, [scopedEvents]);

  const fileArtifacts = useMemo(
    () =>
      scopedArtifacts.filter(
        (artifact) =>
          artifact.artifact_type === "FILE" ||
          artifact.artifact_type === "DIFF",
      ),
    [scopedArtifacts],
  );
  const revisionArtifacts = useMemo(
    () =>
      scopedArtifacts.filter(
        (artifact) =>
          artifact.artifact_type === "RUN_BUNDLE" ||
          artifact.artifact_type === "REPORT",
      ),
    [scopedArtifacts],
  );
  const screenshotReceipts = useMemo<ScreenshotReceiptEvidence[]>(
    () => collectScreenshotReceipts(scopedEvents),
    [scopedEvents],
  );
  const substrateReceipts = useMemo<SubstrateReceiptRow[]>(() => {
    const rows: SubstrateReceiptRow[] = [];
    for (const event of scopedEvents) {
      if (event.event_type !== "RECEIPT") continue;
      const digest = event.digest || {};
      const kind = toEventString(digest.kind).trim().toLowerCase();
      if (kind !== "memory_retrieve") continue;

      const payload = (event.details?.payload || {}) as Record<string, unknown>;
      const proofHash = toEventString(payload.proof_hash).trim();
      const proofRef = toEventString(payload.proof_ref).trim();
      const certificateMode = toEventString(payload.certificate_mode).trim();
      const errorClass = toEventString(digest.error_class).trim();

      rows.push({
        eventId: event.event_id,
        timestamp: formatTimestamp(event.timestamp),
        stepIndex: event.step_index,
        toolName: toEventString(digest.tool_name).trim() || "memory_retrieve",
        queryHash: toEventString(digest.query_hash).trim(),
        indexRoot: toEventString(digest.index_root).trim(),
        k: Math.max(1, Math.floor(toOptionalNumber(digest.k) || 1)),
        efSearch: Math.max(
          1,
          Math.floor(toOptionalNumber(digest.ef_search) || 1),
        ),
        candidateLimit: Math.max(
          1,
          Math.floor(toOptionalNumber(digest.candidate_limit) || 1),
        ),
        candidateTotal: Math.max(
          0,
          Math.floor(toOptionalNumber(digest.candidate_count_total) || 0),
        ),
        candidateReranked: Math.max(
          0,
          Math.floor(toOptionalNumber(digest.candidate_count_reranked) || 0),
        ),
        candidateTruncated: toOptionalBool(digest.candidate_truncated) || false,
        distanceMetric:
          toEventString(digest.distance_metric).trim() || "unknown",
        embeddingNormalized:
          toOptionalBool(digest.embedding_normalized) || false,
        proofHash: proofHash || undefined,
        proofRef: proofRef || undefined,
        certificateMode: certificateMode || undefined,
        success: toOptionalBool(digest.success) ?? true,
        errorClass: errorClass || undefined,
      });
    }
    rows.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return rows;
  }, [scopedEvents]);

  const sections = useMemo<HubSection[]>(
    () => [
      {
        key: "active_context",
        label: sectionLabel("active_context"),
        count: scopedPlanSummary ? 1 : 0,
      },
      {
        key: "thoughts",
        label: sectionLabel("thoughts"),
        count: thoughtAgents.length,
      },
      {
        key: "sources",
        label: sectionLabel("sources"),
        count: visibleSourceCount,
      },
      {
        key: "security_policy",
        label: sectionLabel("security_policy"),
        count: securityRows.length,
      },
      {
        key: "files",
        label: sectionLabel("files"),
        count: fileArtifacts.length,
      },
      {
        key: "revisions",
        label: sectionLabel("revisions"),
        count: revisionArtifacts.length,
      },
      {
        key: "screenshots",
        label: sectionLabel("screenshots"),
        count: screenshotReceipts.length,
      },
      {
        key: "substrate",
        label: sectionLabel("substrate"),
        count: substrateReceipts.length,
      },
      {
        key: "kernel_logs",
        label: sectionLabel("kernel_logs"),
        count: kernelLogs.length,
      },
    ],
    [
      scopedPlanSummary,
      fileArtifacts.length,
      kernelLogs.length,
      revisionArtifacts.length,
      screenshotReceipts.length,
      securityRows.length,
      substrateReceipts.length,
      visibleSourceCount,
      thoughtAgents.length,
    ],
  );

  const derivedDefaultView = useMemo(
    () => defaultViewForSections(sections),
    [sections],
  );
  const [activeView, setActiveView] = useState<ArtifactHubViewKey>(
    initialView || derivedDefaultView,
  );

  useEffect(() => {
    if (initialView) {
      setActiveView(initialView);
    }
  }, [initialView]);

  const openExternalUrl = useCallback(async (url: string) => {
    try {
      await openUrl(url);
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }, []);

  const detailView = (
    <ArtifactHubDetailView
      activeView={activeView}
      planSummary={scopedPlanSummary}
      searches={searches}
      browses={browses}
      thoughtAgents={thoughtAgents}
      visibleSourceCount={visibleSourceCount}
      kernelLogs={kernelLogs}
      securityRows={securityRows}
      fileArtifacts={fileArtifacts}
      revisionArtifacts={revisionArtifacts}
      screenshotReceipts={screenshotReceipts}
      substrateReceipts={substrateReceipts}
      onOpenArtifact={onOpenArtifact}
      openExternalUrl={openExternalUrl}
      extractArtifactUrl={extractArtifactUrl}
      formatTimestamp={formatTimestamp}
    />
  );

  const showTurnScopeControls =
    turnWindows.length > 0 && TURN_FILTER_VIEWS.has(activeView);
  const selectedTurnPrompt = selectedTurn?.prompt
    ? clipText(selectedTurn.prompt, 88)
    : "";

  return (
    <div className="artifact-panel artifact-hub-panel">
      <div className="artifact-header">
        <div className="artifact-meta">
          <div className="artifact-icon">{icons.sidebar}</div>
          <span className="artifact-filename artifact-filename--drawer">
            Execution drawer
          </span>
          <span className="artifact-tag">{sectionLabel(activeView)}</span>
        </div>
        <div className="artifact-actions">
          <button
            className="artifact-action-btn close"
            onClick={onClose}
            title="Close drawer"
          >
            {icons.close}
          </button>
        </div>
      </div>

      <div className="artifact-content artifact-hub-layout">
        <aside className="artifact-hub-nav" aria-label="Evidence sections">
          {sections.map((section) => (
            <button
              key={section.key}
              className={`artifact-hub-nav-item ${activeView === section.key ? "active" : ""}`}
              onClick={() => setActiveView(section.key)}
              type="button"
            >
              <span className="artifact-hub-nav-label">{section.label}</span>
              <span className="artifact-hub-nav-count">{section.count}</span>
            </button>
          ))}
        </aside>
        <section
          className="artifact-hub-detail"
          aria-label={sectionLabel(activeView)}
        >
          {showTurnScopeControls && (
            <div className="artifact-hub-turn-scope">
              <div className="artifact-hub-turn-meta">
                <span className="artifact-hub-turn-label">
                  {selectedTurn ? `Turn ${selectedTurn.index}` : "All turns"}
                </span>
                {selectedTurnPrompt && (
                  <span className="artifact-hub-turn-prompt">
                    {selectedTurnPrompt}
                  </span>
                )}
              </div>
              <div className="artifact-hub-turn-actions">
                <label className="artifact-hub-turn-select-wrap">
                  <span className="artifact-hub-turn-select-label">View</span>
                  <select
                    className="artifact-hub-turn-select"
                    value={turnSelection}
                    onChange={(event) => setTurnSelection(event.target.value)}
                  >
                    {latestTurn && (
                      <option value={latestTurn.id}>Latest turn</option>
                    )}
                    {turnWindows
                      .slice()
                      .reverse()
                      .map((turn) => (
                        <option key={turn.id} value={turn.id}>
                          {`Turn ${turn.index}`}
                        </option>
                      ))}
                    <option value="all">All turns</option>
                  </select>
                </label>
              </div>
            </div>
          )}
          {detailView}
        </section>
      </div>
    </div>
  );
}
