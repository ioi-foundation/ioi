import {
  buildSessionReplTargets,
  useAssistantWorkbenchState,
} from "@ioi/agent-ide";
import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AgentTask,
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  CanonicalTraceBundle,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  LocalEngineStagedOperation,
  SessionSummary,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import type { ChatPlaybookRunRecord } from "../../ChatShellWindow/hooks/useChatPlaybookRuns";
import { icons } from "../../../components/ui/icons";
import { ArtifactHubDetailView } from "./ArtifactHubViews";
import type {
  KernelLogRow,
  SecurityPolicyRow,
  SubstrateReceiptRow,
} from "./ArtifactHubViewModels";
import { buildCommitOverview } from "./artifactHubCommitModel";
import { buildDoctorOverview } from "./artifactHubDoctorModel";
import { buildMobileOverview } from "./artifactHubMobileModel";
import { buildReplayTimelineRows } from "./ArtifactHubReplayModel";
import type { ChatRemoteContinuityLaunchRequest } from "./artifactHubRemoteContinuityModel";
import type { TraceBundleExportVariant } from "../utils/traceBundleExportModel";
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
import { exportThreadTraceBundle } from "../utils/exportContext";
import {
  buildPromotionStageDraft,
  type PromotionTarget,
} from "../utils/promotionStageModel";
import {
  buildDurabilityEvidenceOverview,
  type DurabilityEvidenceOverview,
} from "../utils/durabilityEvidenceModel";
import {
  buildPrivacyEvidenceOverview,
  type PrivacyEvidenceOverview,
} from "../utils/privacyEvidenceModel";
import { buildRetainedPortfolioDossier } from "../utils/retainedPortfolioDossierModel";
import { useRetainedWorkbenchTrace } from "../../../hooks/useRetainedWorkbenchTrace";
import { buildAssistantWorkbenchSummary } from "../../../lib/assistantWorkbenchSummary";
import { getSessionOperatorRuntime } from "../../../services/sessionRuntime";
import { buildPlanSummary } from "../viewmodels/contentPipeline.summaries";
import { useChatBranches } from "../hooks/useChatBranches";
import { useChatCapabilityRegistry } from "../hooks/useChatCapabilityRegistry";
import { useChatCompaction } from "../hooks/useChatCompaction";
import { useChatFileContext } from "../hooks/useChatFileContext";
import { useChatHooks } from "../hooks/useChatHooks";
import { useChatKeybindings } from "../hooks/useChatKeybindings";
import { useChatLocalEngine } from "../hooks/useChatLocalEngine";
import { useChatPermissions } from "../hooks/useChatPermissions";
import { useChatPrivacySettings } from "../hooks/useChatPrivacySettings";
import { useChatPlugins } from "../hooks/useChatPlugins";
import { useChatRewind } from "../hooks/useChatRewind";
import { useChatRemoteEnv } from "../hooks/useChatRemoteEnv";
import { useChatServerMode } from "../hooks/useChatServerMode";
import { useChatSourceControl } from "../hooks/useChatSourceControl";
import { useChatTeamMemory } from "../hooks/useChatTeamMemory";
import { useChatVimMode } from "../hooks/useChatVimMode";

interface ArtifactHubSidebarProps {
  initialView?: ArtifactHubViewKey;
  initialTurnId?: string | null;
  activeSessionId?: string | null;
  task: AgentTask | null;
  sessions: SessionSummary[];
  events: AgentEvent[];
  artifacts: Artifact[];
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  playbookRuns: ChatPlaybookRunRecord[];
  playbookRunsLoading: boolean;
  playbookRunsBusyRunId: string | null;
  playbookRunsMessage: string | null;
  playbookRunsError: string | null;
  stagedOperations: LocalEngineStagedOperation[];
  stagedOperationsLoading: boolean;
  stagedOperationsBusyId: string | null;
  stagedOperationsMessage: string | null;
  stagedOperationsError: string | null;
  onOpenArtifact?: (artifactId: string) => void;
  onRetryPlaybookRun?: (runId: string) => void;
  onResumePlaybookRun?: (runId: string, stepId?: string | null) => void;
  onDismissPlaybookRun?: (runId: string) => void;
  onMessageWorkerSession?: (
    runId: string,
    sessionId: string,
    message: string,
  ) => void;
  onStopWorkerSession?: (runId: string, sessionId: string) => void;
  onPromoteRunResult?: (runId: string) => void;
  onPromoteStepResult?: (runId: string, stepId: string) => void;
  onPromoteStagedOperation?: (operationId: string) => void;
  onRemoveStagedOperation?: (operationId: string) => void;
  onLoadSession?: (sessionId: string) => void;
  onStopSession?: () => void;
  onOpenGate?: () => void;
  isGated?: boolean;
  gateInfo?: GateInfo;
  isPiiGate?: boolean;
  gateDeadlineMs?: number;
  gateActionError?: string | null;
  credentialRequest?: CredentialRequest;
  clarificationRequest?: ClarificationRequest;
  onApprove?: () => void;
  onGrantScopedException?: () => void;
  onDeny?: () => void;
  onSubmitRuntimePassword?: (password: string) => Promise<void>;
  onCancelRuntimePassword?: () => void;
  onSubmitClarification?: (optionId: string, otherText: string) => Promise<void>;
  onCancelClarification?: () => void;
  onSeedIntent?: (intent: string) => void;
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
const FOCUSED_TRACE_ENTRY_VIEWS = new Set<ArtifactHubViewKey>([
  "thoughts",
  "sources",
  "screenshots",
  "kernel_logs",
]);
const FOCUSED_TRACE_SECTION_VIEWS = new Set<ArtifactHubViewKey>([
  "thoughts",
  "sources",
  "screenshots",
  "kernel_logs",
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
      return "Implementation plan";
    case "doctor":
      return "Doctor";
    case "compact":
      return "Compact";
    case "branch":
      return "Branches";
    case "commit":
      return "Commit";
    case "review":
      return "Review";
    case "pr_comments":
      return "PR Comments";
    case "mobile":
      return "Mobile";
    case "voice":
      return "Voice";
    case "server":
      return "Server";
    case "repl":
      return "REPL";
    case "export":
      return "Export";
    case "share":
      return "Share";
    case "remote_env":
      return "Remote Env";
    case "mcp":
      return "MCP";
    case "plugins":
      return "Plugins";
    case "vim":
      return "Vim";
    case "privacy":
      return "Privacy";
    case "keybindings":
      return "Keybindings";
    case "permissions":
      return "Permissions";
    case "hooks":
      return "Hooks";
    case "rewind":
      return "Rewind";
    case "replay":
      return "Verification walkthrough";
    case "compare":
      return "Compare";
    case "tasks":
      return "Task list";
    case "thoughts":
      return "Scratchboard";
    case "substrate":
      return "Runtime proof";
    case "sources":
      return "Source evidence";
    case "kernel_logs":
      return "Tool transcript";
    case "security_policy":
      return "Verification";
    case "files":
      return "Files";
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

function workspaceRootFromTask(task: AgentTask | null): string | null {
  return (
    task?.build_session?.workspaceRoot ||
    task?.renderer_session?.workspaceRoot ||
    task?.chat_session?.workspaceRoot ||
    null
  );
}

function workspaceRootForFiles(
  activeSessionId: string | null | undefined,
  task: AgentTask | null,
  sessions: SessionSummary[],
): string | null {
  const taskRoot = workspaceRootFromTask(task);
  if (taskRoot) {
    return taskRoot;
  }

  if (activeSessionId) {
    return (
      sessions.find((session) => session.session_id === activeSessionId)
        ?.workspace_root ?? null
    );
  }

  return sessions.find((session) => session.workspace_root)?.workspace_root ?? null;
}

export function ArtifactHubSidebar({
  initialView,
  initialTurnId,
  activeSessionId,
  task,
  sessions,
  events,
  artifacts,
  sourceSummary,
  thoughtSummary,
  playbookRuns,
  playbookRunsLoading,
  playbookRunsBusyRunId,
  playbookRunsMessage,
  playbookRunsError,
  stagedOperations,
  stagedOperationsLoading,
  stagedOperationsBusyId,
  stagedOperationsMessage,
  stagedOperationsError,
  onOpenArtifact,
  onRetryPlaybookRun,
  onResumePlaybookRun,
  onDismissPlaybookRun,
  onMessageWorkerSession,
  onStopWorkerSession,
  onPromoteRunResult,
  onPromoteStepResult,
  onPromoteStagedOperation,
  onRemoveStagedOperation,
  onLoadSession,
  onStopSession,
  onOpenGate,
  isGated,
  gateInfo,
  isPiiGate,
  gateDeadlineMs,
  gateActionError,
  credentialRequest,
  clarificationRequest,
  onApprove,
  onGrantScopedException,
  onDeny,
  onSubmitRuntimePassword,
  onCancelRuntimePassword,
  onSubmitClarification,
  onCancelClarification,
  onSeedIntent,
  onClose,
}: ArtifactHubSidebarProps) {
  const focusedTraceMode =
    initialView != null && FOCUSED_TRACE_ENTRY_VIEWS.has(initialView);
  const enableOperatorSurfaces = !focusedTraceMode;
  const turnWindows = useMemo(() => buildEventTurnWindows(events), [events]);
  const latestTurn =
    turnWindows.length > 0 ? turnWindows[turnWindows.length - 1] : null;
  const [turnSelection, setTurnSelection] = useState<TurnSelection>("all");
  const [replayBundle, setReplayBundle] = useState<CanonicalTraceBundle | null>(
    null,
  );
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayError, setReplayError] = useState<string | null>(null);
  const [exportStatus, setExportStatus] = useState<
    "idle" | "exporting" | "success" | "error"
  >("idle");
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportedPath, setExportedPath] = useState<string | null>(null);
  const [exportedAtMs, setExportedAtMs] = useState<number | null>(null);
  const [exportedVariant, setExportedVariant] =
    useState<TraceBundleExportVariant | null>(null);
  const [promotionStageBusyTarget, setPromotionStageBusyTarget] =
    useState<PromotionTarget | null>(null);
  const [promotionStageMessage, setPromotionStageMessage] = useState<string | null>(
    null,
  );
  const [promotionStageError, setPromotionStageError] = useState<string | null>(null);

  useEffect(() => {
    if (!activeSessionId) {
      setReplayBundle(null);
      setReplayLoading(false);
      setReplayError(null);
      return;
    }

    let active = true;
    setReplayLoading(true);
    setReplayError(null);

    void invoke<CanonicalTraceBundle>("get_trace_bundle", {
      threadId: activeSessionId,
      thread_id: activeSessionId,
    })
      .then((bundle) => {
        if (!active) return;
        setReplayBundle(bundle);
        setReplayError(null);
      })
      .catch((error) => {
        if (!active) return;
        setReplayBundle(null);
        setReplayError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!active) return;
        setReplayLoading(false);
      });

    return () => {
      active = false;
    };
  }, [activeSessionId]);

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

  const replayRows = useMemo(
    () => buildReplayTimelineRows(replayBundle),
    [replayBundle],
  );

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
  const fileSessionId =
    activeSessionId || task?.session_id || task?.id || sessions[0]?.session_id || null;
  const exportSessionId = fileSessionId;
  const fileWorkspaceRoot = useMemo(
    () => workspaceRootForFiles(fileSessionId, task, sessions),
    [fileSessionId, sessions, task],
  );
  const {
    context: fileContext,
    status: fileContextStatus,
    error: fileContextError,
    browsePath: fileBrowsePath,
    browseEntries: fileBrowseEntries,
    browseStatus: fileBrowseStatus,
    browseError: fileBrowseError,
    refresh: refreshFileContext,
    openDirectory: openFileDirectory,
    browseParent: browseFileParent,
    rememberPath: rememberFilePath,
    pinPath: pinFilePath,
    includePath: includeFilePath,
    excludePath: excludeFilePath,
    removePath: removeFilePath,
    clear: clearFileContext,
    fileContextCount,
  } = useChatFileContext({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    snapshot: localEngineSnapshot,
    status: localEngineStatus,
    error: localEngineError,
    refresh: refreshLocalEngine,
  } = useChatLocalEngine(enableOperatorSurfaces);
  const {
    snapshot: capabilityRegistrySnapshot,
    status: capabilityRegistryStatus,
    error: capabilityRegistryError,
  } = useChatCapabilityRegistry(enableOperatorSurfaces);
  const {
    snapshot: compactionSnapshot,
    status: compactionStatus,
    error: compactionError,
    policy: compactionPolicy,
    refresh: refreshCompaction,
    compact: compactSession,
    updatePolicy: updateCompactionPolicy,
    resetPolicy: resetCompactionPolicy,
  } = useChatCompaction(enableOperatorSurfaces);
  const {
    snapshot: teamMemorySnapshot,
    status: teamMemoryStatus,
    error: teamMemoryError,
    includeGovernanceCritical: teamMemoryIncludeGovernanceCritical,
    setIncludeGovernanceCritical: setTeamMemoryIncludeGovernanceCritical,
    refresh: refreshTeamMemory,
    sync: syncTeamMemory,
    forget: forgetTeamMemory,
  } = useChatTeamMemory({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
  });
  const {
    snapshot: branchSnapshot,
    status: branchStatus,
    error: branchError,
    refresh: refreshBranches,
    createWorktree,
    switchWorktree,
    removeWorktree,
  } = useChatBranches({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    assistantWorkbench,
    assistantWorkbenchActivities,
    activeAssistantWorkbenchActivities,
  } = useAssistantWorkbenchState();
  const activeWorkbenchSummary = useMemo(
    () => buildAssistantWorkbenchSummary(assistantWorkbench),
    [assistantWorkbench],
  );
  const retainedWorkbenchActivities = useMemo(
    () =>
      activeAssistantWorkbenchActivities.length > 0
        ? activeAssistantWorkbenchActivities
        : assistantWorkbenchActivities,
    [activeAssistantWorkbenchActivities, assistantWorkbenchActivities],
  );
  const {
    evidenceThreadId: retainedWorkbenchEvidenceThreadId,
    trace: retainedWorkbenchTrace,
    latestEvent: latestRetainedWorkbenchEvent,
    latestArtifact: latestRetainedWorkbenchArtifact,
  } = useRetainedWorkbenchTrace(retainedWorkbenchActivities);
  const {
    state: sourceControlState,
    status: sourceControlStatus,
    error: sourceControlError,
    lastCommitReceipt,
    refresh: refreshSourceControl,
    stagePath,
    stageAll,
    unstagePath,
    unstageAll,
    discardPath,
    discardAllWorking,
    commit,
  } = useChatSourceControl({
    enabled: enableOperatorSurfaces,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    snapshot: remoteEnvSnapshot,
    status: remoteEnvStatus,
    error: remoteEnvError,
    refresh: refreshRemoteEnv,
  } = useChatRemoteEnv({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    snapshot: serverSnapshot,
    status: serverStatus,
    error: serverError,
    refresh: refreshServer,
  } = useChatServerMode({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    snapshot: pluginSnapshot,
    status: pluginStatus,
    error: pluginError,
    refresh: refreshPlugins,
    trustPlugin,
    setPluginEnabled,
    reloadPlugin,
    refreshPluginCatalog,
    revokePluginTrust,
    installPluginPackage,
    updatePluginPackage,
    removePluginPackage,
  } = useChatPlugins({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const {
    snapshot: rewindSnapshot,
    status: rewindStatus,
    error: rewindError,
    refresh: refreshRewind,
  } = useChatRewind(enableOperatorSurfaces);
  const {
    snapshot: hookSnapshot,
    status: hooksStatus,
    error: hooksError,
    refresh: refreshHooks,
  } = useChatHooks({
    enabled: enableOperatorSurfaces,
    sessionId: fileSessionId,
    workspaceRoot: fileWorkspaceRoot,
  });
  const keybindingSnapshot = useChatKeybindings();
  const { snapshot: vimModeSnapshot, toggle: toggleVimMode } =
    useChatVimMode(enableOperatorSurfaces);
  const {
    status: permissionsStatus,
    error: permissionsError,
    policyState,
    governanceRequest,
    connectorOverrides,
    activeOverrideCount,
    availableProfiles,
    currentProfileId,
    applyingProfileId,
    editingConnectorId,
    applyingGovernanceRequest,
    rememberedApprovals,
    applyProfile,
    applyGovernanceRequest,
    dismissGovernanceRequest,
    forgetApproval,
    updateConnectorOverride,
    resetConnectorOverride,
    setApprovalScopeMode,
    setApprovalExpiry,
    refresh: refreshPermissions,
  } = useChatPermissions(enableOperatorSurfaces);
  const privacySnapshot = useChatPrivacySettings({
    policyState,
    governanceRequest,
    connectorOverrides,
    activeOverrideCount,
    rememberedApprovals,
    isPiiGate,
  });
  const commitOverview = useMemo(
    () =>
      buildCommitOverview(
        sourceControlState,
        branchSnapshot,
        lastCommitReceipt,
      ),
    [branchSnapshot, lastCommitReceipt, sourceControlState],
  );
  const mobileOverview = useMemo(
    () =>
      buildMobileOverview({
        hasActiveWorkbench: Boolean(assistantWorkbench),
        activeWorkbenchTitle: activeWorkbenchSummary?.title ?? null,
        activityCount: retainedWorkbenchActivities.length,
        evidenceThreadId: retainedWorkbenchEvidenceThreadId,
        traceLoading: retainedWorkbenchTrace.loading,
        traceError: retainedWorkbenchTrace.error,
        eventCount: retainedWorkbenchTrace.events.length,
        artifactCount: retainedWorkbenchTrace.artifacts.length,
        sessionHistoryCount: sessions.length,
      }),
    [
      activeWorkbenchSummary?.title,
      assistantWorkbench,
      retainedWorkbenchActivities.length,
      retainedWorkbenchEvidenceThreadId,
      retainedWorkbenchTrace.artifacts.length,
      retainedWorkbenchTrace.error,
      retainedWorkbenchTrace.events.length,
      retainedWorkbenchTrace.loading,
      sessions.length,
    ],
  );
  const retainedWorkbenchEvidenceAttachable = useMemo(() => {
    const evidenceThreadId = retainedWorkbenchEvidenceThreadId?.trim();
    if (!evidenceThreadId) {
      return false;
    }
    return sessions.some(
      (session) =>
        session.session_id === evidenceThreadId &&
        Boolean(session.workspace_root?.trim()),
    );
  }, [retainedWorkbenchEvidenceThreadId, sessions]);
  const doctorOverview = useMemo(
    () =>
      buildDoctorOverview({
        runtime: {
          status: localEngineStatus,
          error: localEngineError,
          pendingApprovalCount: localEngineSnapshot?.pendingApprovalCount ?? 0,
          pendingControlCount: localEngineSnapshot?.pendingControlCount ?? 0,
          activeIssueCount: localEngineSnapshot?.activeIssueCount ?? 0,
          liveJobCount: localEngineSnapshot?.jobs.length ?? 0,
          backendCount: localEngineSnapshot?.managedBackends.length ?? 0,
          healthyBackendCount:
            localEngineSnapshot?.managedBackends.filter(
              (backend) => backend.health === "healthy",
            ).length ?? 0,
          degradedBackendCount:
            localEngineSnapshot?.managedBackends.filter(
              (backend) => backend.health !== "healthy",
            ).length ?? 0,
        },
        authority: {
          permissionsStatus,
          permissionsError,
          pendingGovernance: Boolean(governanceRequest),
          activeOverrideCount,
          rememberedApprovalCount:
            rememberedApprovals?.activeDecisionCount ?? 0,
          requiresPrivacyReview: Boolean(isPiiGate),
          redactedOverrideCount: privacySnapshot.redactedOverrideCount,
        },
        extensions: {
          pluginCount: pluginSnapshot?.pluginCount ?? 0,
          blockedPluginCount: pluginSnapshot?.blockedPluginCount ?? 0,
          reviewRequiredPluginCount:
            pluginSnapshot?.reviewRequiredPluginCount ?? 0,
          criticalUpdateCount: pluginSnapshot?.criticalUpdateCount ?? 0,
          refreshFailedCount: pluginSnapshot?.refreshFailedCount ?? 0,
          updateAvailableCount: pluginSnapshot?.updateAvailableCount ?? 0,
          nonconformantChannelCount:
            pluginSnapshot?.nonconformantChannelCount ?? 0,
          nonconformantSourceCount:
            pluginSnapshot?.nonconformantSourceCount ?? 0,
        },
        workspace: {
          isRepo: branchSnapshot?.isRepo ?? false,
          changedFileCount: branchSnapshot?.changedFileCount ?? 0,
          dirty: branchSnapshot?.dirty ?? false,
          aheadCount: branchSnapshot?.aheadCount ?? 0,
          behindCount: branchSnapshot?.behindCount ?? 0,
          worktreeRiskLabel: branchSnapshot?.worktreeRiskLabel ?? null,
        },
        durability: {
          status: compactionStatus,
          error: compactionError,
          activeSession: Boolean(compactionSnapshot?.activeSessionId),
          recordCount: compactionSnapshot?.recordCount ?? 0,
          shouldCompact:
            compactionSnapshot?.recommendationForActive?.shouldCompact ?? false,
          recommendedPolicyLabel:
            compactionSnapshot?.recommendationForActive
              ?.recommendedPolicyLabel ?? null,
          recommendationReasons:
            compactionSnapshot?.recommendationForActive?.reasonLabels ?? [],
          resumeSafetyStatus:
            compactionSnapshot?.latestForActive?.resumeSafety.status ??
            compactionSnapshot?.previewForActive?.resumeSafety.status ??
            null,
        },
        automation: {
          remoteEnvStatus,
          remoteEnvError,
          bindingCount: remoteEnvSnapshot?.bindingCount ?? 0,
          redactedBindingCount: remoteEnvSnapshot?.redactedBindingCount ?? 0,
          secretBindingCount: remoteEnvSnapshot?.secretBindingCount ?? 0,
          hooksStatus,
          hooksError,
          activeHookCount: hookSnapshot?.activeHookCount ?? 0,
          disabledHookCount: hookSnapshot?.disabledHookCount ?? 0,
          hookReceiptCount:
            (hookSnapshot?.runtimeReceiptCount ?? 0) +
            (hookSnapshot?.approvalReceiptCount ?? 0),
        },
      }),
    [
      activeOverrideCount,
      branchSnapshot?.aheadCount,
      branchSnapshot?.behindCount,
      branchSnapshot?.changedFileCount,
      branchSnapshot?.dirty,
      branchSnapshot?.isRepo,
      branchSnapshot?.worktreeRiskLabel,
      compactionError,
      compactionSnapshot?.activeSessionId,
      compactionSnapshot?.latestForActive?.resumeSafety.status,
      compactionSnapshot?.previewForActive?.resumeSafety.status,
      compactionSnapshot?.recommendationForActive?.reasonLabels,
      compactionSnapshot?.recommendationForActive?.recommendedPolicyLabel,
      compactionSnapshot?.recommendationForActive?.shouldCompact,
      compactionSnapshot?.recordCount,
      compactionStatus,
      governanceRequest,
      hookSnapshot?.activeHookCount,
      hookSnapshot?.disabledHookCount,
      hookSnapshot?.runtimeReceiptCount,
      hooksError,
      hooksStatus,
      isPiiGate,
      localEngineError,
      localEngineSnapshot?.activeIssueCount,
      localEngineSnapshot?.jobs,
      localEngineSnapshot?.managedBackends,
      localEngineSnapshot?.pendingApprovalCount,
      localEngineSnapshot?.pendingControlCount,
      localEngineStatus,
      permissionsError,
      permissionsStatus,
      pluginSnapshot?.blockedPluginCount,
      pluginSnapshot?.criticalUpdateCount,
      pluginSnapshot?.nonconformantChannelCount,
      pluginSnapshot?.nonconformantSourceCount,
      pluginSnapshot?.pluginCount,
      pluginSnapshot?.refreshFailedCount,
      pluginSnapshot?.reviewRequiredPluginCount,
      pluginSnapshot?.updateAvailableCount,
      privacySnapshot.redactedOverrideCount,
      rememberedApprovals?.activeDecisionCount,
      remoteEnvError,
      remoteEnvSnapshot?.bindingCount,
      remoteEnvSnapshot?.redactedBindingCount,
      remoteEnvSnapshot?.secretBindingCount,
      remoteEnvStatus,
    ],
  );
  const screenshotReceipts = useMemo<ScreenshotReceiptEvidence[]>(
    () => collectScreenshotReceipts(scopedEvents),
    [scopedEvents],
  );
  const durabilityOverview: DurabilityEvidenceOverview = useMemo(
    () =>
      buildDurabilityEvidenceOverview({
        activeSessionId: exportSessionId,
        compactionSnapshot,
        teamMemorySnapshot,
      }),
    [compactionSnapshot, exportSessionId, teamMemorySnapshot],
  );
  const privacyOverview: PrivacyEvidenceOverview = useMemo(
    () =>
      buildPrivacyEvidenceOverview({
        snapshot: privacySnapshot,
        exportVariant: exportedVariant,
      }),
    [exportedVariant, privacySnapshot],
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
  const taskSectionCount = useMemo(() => {
    if (!task) return 0;
    const blockerCount =
      task.pending_request_hash ||
      task.clarification_request ||
      task.credential_request ||
      task.gate_info
        ? 1
        : 0;
    return Math.max(
      1,
      task.session_checklist.length +
        task.background_tasks.length +
        blockerCount +
        playbookRuns.length,
    );
  }, [playbookRuns.length, task]);
  const doctorSectionCount = useMemo(() => {
    return Math.max(1, doctorOverview.reviewCount + doctorOverview.watchCount);
  }, [doctorOverview.reviewCount, doctorOverview.watchCount]);
  const replSectionCount = useMemo(() => {
    const currentSessionId = activeSessionId || task?.session_id || task?.id || null;
    const currentTaskRoot = workspaceRootFromTask(task);
    const replTargets = buildSessionReplTargets(sessions, currentSessionId);
    return Math.max(
      currentTaskRoot ? 1 : 0,
      replTargets.length,
    );
  }, [activeSessionId, sessions, task]);
  const branchSectionCount = useMemo(() => {
    if (!fileWorkspaceRoot && !branchSnapshot?.workspaceRoot) {
      return 0;
    }
    if (!branchSnapshot?.isRepo) {
      return 1;
    }
    return Math.max(
      1,
      branchSnapshot.recentBranches.length + Number(branchSnapshot.dirty),
    );
  }, [
    branchSnapshot?.dirty,
    branchSnapshot?.isRepo,
    branchSnapshot?.recentBranches.length,
    branchSnapshot?.workspaceRoot,
    fileWorkspaceRoot,
  ]);
  const commitSectionCount = useMemo(() => {
    if (!fileWorkspaceRoot) {
      return 0;
    }
    return Math.max(
      1,
      commitOverview.stagedCount +
        commitOverview.unstagedCount +
        Number(commitOverview.canCommit),
    );
  }, [
    commitOverview.canCommit,
    commitOverview.stagedCount,
    commitOverview.unstagedCount,
    fileWorkspaceRoot,
  ]);
  const prCommentsSectionCount = useMemo(() => {
    return Math.max(
      1,
      commitOverview.changedCount,
      visibleSourceCount,
      screenshotReceipts.length,
      substrateReceipts.length,
      scopedPlanSummary ? 1 : 0,
    );
  }, [
    commitOverview.changedCount,
    scopedPlanSummary,
    screenshotReceipts.length,
    substrateReceipts.length,
    visibleSourceCount,
  ]);
  const reviewSectionCount = useMemo(() => {
    const reviewSignals =
      Number(
        Boolean(
          task?.pending_request_hash ||
            task?.credential_request ||
            task?.clarification_request ||
            task?.gate_info,
        ),
      ) +
      Number(Boolean(isPiiGate)) +
      Number(Boolean(compactionSnapshot?.recommendationForActive?.shouldCompact)) +
      Number(Boolean(exportSessionId)) +
      Number(commitOverview.changedCount > 0);
    return Math.max(1, reviewSignals);
  }, [
    commitOverview.changedCount,
    compactionSnapshot?.recommendationForActive?.shouldCompact,
    exportSessionId,
    isPiiGate,
    task,
  ]);
  const mobileSectionCount = useMemo(() => {
    if (
      !assistantWorkbench &&
      retainedWorkbenchActivities.length === 0 &&
      !retainedWorkbenchEvidenceThreadId
    ) {
      return Math.max(0, Number(sessions.length > 0));
    }
    return Math.max(
      1,
      Number(Boolean(assistantWorkbench)) +
        retainedWorkbenchActivities.length +
        Number(Boolean(retainedWorkbenchEvidenceThreadId)),
    );
  }, [
    assistantWorkbench,
    retainedWorkbenchActivities.length,
      retainedWorkbenchEvidenceThreadId,
      sessions.length,
  ]);
  const voiceSectionCount = 1;
  const permissionSectionCount = useMemo(() => {
    const blockerCount =
      task?.pending_request_hash ||
      task?.clarification_request ||
      task?.credential_request ||
      task?.gate_info
        ? 1
        : 0;
    const governanceCount = governanceRequest ? 1 : 0;
    const rememberedCount = rememberedApprovals?.activeDecisionCount ?? 0;
    return Math.max(
      1,
      blockerCount + governanceCount + activeOverrideCount + rememberedCount,
    );
  }, [activeOverrideCount, governanceRequest, rememberedApprovals, task]);
  const privacySectionCount = useMemo(() => {
    const reviewCount =
      Number(isPiiGate) +
      Number(Boolean(privacySnapshot.pendingGovernanceSummary)) +
      privacySnapshot.redactedOverrideCount;
    return Math.max(1, reviewCount);
  }, [
    isPiiGate,
    privacySnapshot.pendingGovernanceSummary,
    privacySnapshot.redactedOverrideCount,
  ]);
  const rewindSectionCount = useMemo(() => {
    return Math.max(0, rewindSnapshot?.candidates.length ?? 0);
  }, [rewindSnapshot?.candidates.length]);
  const compactionSectionCount = useMemo(() => {
    const activeBonus = compactionSnapshot?.activeSessionId ? 1 : 0;
    return Math.max(activeBonus, compactionSnapshot?.recordCount ?? 0);
  }, [compactionSnapshot?.activeSessionId, compactionSnapshot?.recordCount]);
  const remoteEnvSectionCount = useMemo(() => {
    return Math.max(0, remoteEnvSnapshot?.bindingCount ?? 0);
  }, [remoteEnvSnapshot?.bindingCount]);
  const serverSectionCount = useMemo(() => {
    return Math.max(
      1,
      serverSnapshot?.remoteSessionCount ?? 0,
      serverSnapshot?.remoteOnlySessionCount ?? 0,
      Number(Boolean(serverSnapshot?.explicitRpcTarget)),
    );
  }, [
    serverSnapshot?.explicitRpcTarget,
    serverSnapshot?.remoteOnlySessionCount,
    serverSnapshot?.remoteSessionCount,
  ]);
  const pluginSectionCount = useMemo(() => {
    return Math.max(0, pluginSnapshot?.pluginCount ?? 0);
  }, [pluginSnapshot?.pluginCount]);
  const mcpSectionCount = useMemo(() => {
    return Math.max(
      0,
      capabilityRegistrySnapshot?.extensionManifests.reduce((count, manifest) => {
        return (
          count +
          manifest.contributions
            .filter((contribution) => contribution.kind === "mcp_servers")
            .reduce(
              (manifestCount, contribution) =>
                manifestCount + Math.max(1, contribution.itemCount ?? 1),
              0,
            )
        );
      }, 0) ?? 0,
    );
  }, [capabilityRegistrySnapshot]);
  const hookSectionCount = useMemo(() => {
    return Math.max(0, hookSnapshot?.hooks.length ?? 0);
  }, [hookSnapshot?.hooks.length]);
  const keybindingSectionCount = Math.max(
    0,
    keybindingSnapshot.records.length,
  );
  const vimSectionCount = Math.max(1, vimModeSnapshot.keyHints.length);
  const exportSectionCount = exportSessionId ? 1 : 0;

  useEffect(() => {
    setExportStatus("idle");
    setExportError(null);
    setExportedPath(null);
    setExportedAtMs(null);
    setExportedVariant(null);
    setPromotionStageBusyTarget(null);
    setPromotionStageMessage(null);
    setPromotionStageError(null);
  }, [exportSessionId]);

  const handleExportBundle = useCallback(
    async (variant: TraceBundleExportVariant = "trace_bundle") => {
      if (!exportSessionId) {
        return;
      }
      setExportStatus("exporting");
      setExportError(null);
      try {
        const path = await exportThreadTraceBundle({
          threadId: exportSessionId,
          variant,
        });
        if (!path) {
          setExportStatus("idle");
          return;
        }
        setExportedPath(path);
        setExportedAtMs(Date.now());
        setExportedVariant(variant);
        setExportStatus("success");
      } catch (error) {
        setExportError(error instanceof Error ? error.message : String(error));
        setExportStatus("error");
      }
    },
    [exportSessionId],
  );

  const handleStagePromotionCandidate = useCallback(
    async (target: PromotionTarget) => {
      if (!exportSessionId && !replayBundle) {
        return;
      }

      setPromotionStageBusyTarget(target);
      setPromotionStageMessage(null);
      setPromotionStageError(null);

      try {
        const dossier = buildRetainedPortfolioDossier({
          sessionTitle: replayBundle?.sessionSummary?.title || exportSessionId,
          bundle: replayBundle,
          portfolio: compactionSnapshot?.durabilityPortfolio ?? null,
          exportVariant: exportedVariant,
          privacyStatusLabel: privacyOverview.statusLabel,
          privacyRecommendationLabel: privacyOverview.recommendationLabel,
          durabilityStatusLabel: durabilityOverview.statusLabel,
        });
        const draft = buildPromotionStageDraft({
          target,
          sessionId: exportSessionId,
          threadId: exportSessionId,
          bundle: replayBundle,
          exportPath: exportedPath,
          exportVariant: exportedVariant,
          durabilitySummary: `${durabilityOverview.statusLabel} · ${durabilityOverview.compactionSummary} · ${durabilityOverview.teamMemorySummary}`,
          privacySummary: `${privacyOverview.statusLabel} · ${privacyOverview.exportSummary}`,
          dossier,
        });
        await getSessionOperatorRuntime().stageLocalEngineOperation(draft);
        setPromotionStageMessage(
          `Staged ${target} promotion in the Local Engine queue with '${dossier.title}' attached to the canonical replay evidence.`,
        );
      } catch (error) {
        setPromotionStageError(
          error instanceof Error ? error.message : String(error),
        );
      } finally {
        setPromotionStageBusyTarget(null);
      }
    },
    [
      compactionSnapshot?.durabilityPortfolio,
      durabilityOverview.compactionSummary,
      durabilityOverview.statusLabel,
      durabilityOverview.teamMemorySummary,
      exportSessionId,
      exportedPath,
      exportedVariant,
      privacyOverview.exportSummary,
      privacyOverview.statusLabel,
      replayBundle,
    ],
  );

  const handleRefreshDoctor = useCallback(async () => {
    await Promise.all([
      refreshLocalEngine().catch(() => null),
      refreshCompaction().catch(() => null),
      refreshBranches().catch(() => null),
      refreshSourceControl().catch(() => null),
      refreshServer().catch(() => null),
      refreshRemoteEnv().catch(() => null),
      refreshPlugins().catch(() => null),
      refreshHooks().catch(() => null),
      refreshPermissions().catch(() => null),
    ]);
  }, [
    refreshBranches,
      refreshCompaction,
      refreshHooks,
      refreshLocalEngine,
      refreshPermissions,
      refreshPlugins,
      refreshRemoteEnv,
      refreshServer,
      refreshSourceControl,
    ]);

  const sections = useMemo<HubSection[]>(
    () => [
      {
        key: "active_context",
        label: sectionLabel("active_context"),
        count: scopedPlanSummary ? 1 : 0,
      },
      {
        key: "doctor",
        label: sectionLabel("doctor"),
        count: doctorSectionCount,
      },
      {
        key: "compact",
        label: sectionLabel("compact"),
        count: compactionSectionCount,
      },
      {
        key: "branch",
        label: sectionLabel("branch"),
        count: branchSectionCount,
      },
      {
        key: "commit",
        label: sectionLabel("commit"),
        count: commitSectionCount,
      },
      {
        key: "review",
        label: sectionLabel("review"),
        count: reviewSectionCount,
      },
      {
        key: "pr_comments",
        label: sectionLabel("pr_comments"),
        count: prCommentsSectionCount,
      },
      {
        key: "mobile",
        label: sectionLabel("mobile"),
        count: mobileSectionCount,
      },
      {
        key: "voice",
        label: sectionLabel("voice"),
        count: voiceSectionCount,
      },
      {
        key: "server",
        label: sectionLabel("server"),
        count: serverSectionCount,
      },
      {
        key: "export",
        label: sectionLabel("export"),
        count: exportSectionCount,
      },
      {
        key: "share",
        label: sectionLabel("share"),
        count: exportSectionCount,
      },
      {
        key: "remote_env",
        label: sectionLabel("remote_env"),
        count: remoteEnvSectionCount,
      },
      {
        key: "mcp",
        label: sectionLabel("mcp"),
        count: mcpSectionCount,
      },
      {
        key: "plugins",
        label: sectionLabel("plugins"),
        count: pluginSectionCount,
      },
      {
        key: "vim",
        label: sectionLabel("vim"),
        count: vimSectionCount,
      },
      {
        key: "keybindings",
        label: sectionLabel("keybindings"),
        count: keybindingSectionCount,
      },
      {
        key: "privacy",
        label: sectionLabel("privacy"),
        count: privacySectionCount,
      },
      {
        key: "replay",
        label: sectionLabel("replay"),
        count: replayRows.length,
      },
      {
        key: "compare",
        label: sectionLabel("compare"),
        count: Math.max(
          0,
          sessions.filter((session) => session.session_id !== activeSessionId)
            .length,
        ),
      },
      {
        key: "rewind",
        label: sectionLabel("rewind"),
        count: rewindSectionCount,
      },
      {
        key: "hooks",
        label: sectionLabel("hooks"),
        count: hookSectionCount,
      },
      {
        key: "permissions",
        label: sectionLabel("permissions"),
        count: permissionSectionCount,
      },
      {
        key: "tasks",
        label: sectionLabel("tasks"),
        count: taskSectionCount,
      },
      {
        key: "repl",
        label: sectionLabel("repl"),
        count: replSectionCount,
      },
      {
        key: "thoughts",
        label: sectionLabel("thoughts"),
        count: thoughtAgents.length + playbookRuns.length + stagedOperations.length,
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
        count: fileArtifacts.length + fileContextCount,
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
      activeOverrideCount,
      compactionSectionCount,
      branchSectionCount,
      commitSectionCount,
      reviewSectionCount,
      doctorSectionCount,
      prCommentsSectionCount,
      mobileSectionCount,
      voiceSectionCount,
      serverSectionCount,
      replSectionCount,
      governanceRequest,
      scopedPlanSummary,
      fileContextCount,
      fileArtifacts.length,
      exportSectionCount,
      remoteEnvSectionCount,
      mcpSectionCount,
      pluginSectionCount,
      vimSectionCount,
      keybindingSectionCount,
      kernelLogs.length,
      privacySectionCount,
      replayRows.length,
      rewindSectionCount,
      hookSectionCount,
      revisionArtifacts.length,
      screenshotReceipts.length,
      securityRows.length,
      substrateReceipts.length,
      taskSectionCount,
      permissionSectionCount,
      visibleSourceCount,
      thoughtAgents.length,
      playbookRuns.length,
      stagedOperations.length,
      sessions,
      activeSessionId,
    ],
  );

  const presentedSections = useMemo(() => {
    const scopedSections = focusedTraceMode
      ? sections.filter((section) => FOCUSED_TRACE_SECTION_VIEWS.has(section.key))
      : sections;
    const visibleSections = scopedSections.filter(
      (section) => section.count > 0 || section.key === initialView,
    );
    return visibleSections.length > 0 ? visibleSections : scopedSections;
  }, [focusedTraceMode, initialView, sections]);

  const derivedDefaultView = useMemo(
    () => defaultViewForSections(presentedSections),
    [presentedSections],
  );
  const [activeView, setActiveView] = useState<ArtifactHubViewKey>(
    initialView || derivedDefaultView,
  );
  const [selectedRewindSessionId, setSelectedRewindSessionId] = useState<string | null>(
    null,
  );
  const [compareTargetSessionId, setCompareTargetSessionId] = useState<string | null>(
    null,
  );
  const [replLaunchRequest, setReplLaunchRequest] =
    useState<ChatRemoteContinuityLaunchRequest | null>(null);

  useEffect(() => {
    if (initialView) {
      setActiveView(initialView);
    }
  }, [initialView]);

  useEffect(() => {
    if (
      presentedSections.length === 0 ||
      presentedSections.some((section) => section.key === activeView)
    ) {
      return;
    }
    setActiveView(defaultViewForSections(presentedSections));
  }, [activeView, presentedSections]);

  useEffect(() => {
    const candidateIds = new Set(
      (rewindSnapshot?.candidates ?? []).map((candidate) => candidate.sessionId),
    );
    if (
      selectedRewindSessionId &&
      !candidateIds.has(selectedRewindSessionId)
    ) {
      setSelectedRewindSessionId(null);
    }
    if (
      compareTargetSessionId &&
      (!candidateIds.has(compareTargetSessionId) ||
        compareTargetSessionId === activeSessionId)
    ) {
      setCompareTargetSessionId(null);
    }
  }, [
    activeSessionId,
    compareTargetSessionId,
    rewindSnapshot,
    selectedRewindSessionId,
  ]);

  const handleOpenView = useCallback((view: ArtifactHubViewKey) => {
    setActiveView(view);
  }, []);

  const handleOpenCompareForSession = useCallback((sessionId: string | null) => {
    setCompareTargetSessionId(sessionId);
    if (sessionId) {
      setSelectedRewindSessionId(sessionId);
      setActiveView("compare");
    }
  }, []);

  const handleRequestReplLaunch = useCallback(
    (request: ChatRemoteContinuityLaunchRequest) => {
      setReplLaunchRequest(request);
      setActiveView("repl");
      const sessionAvailableLocally = sessions.some(
        (session) => session.session_id === request.sessionId,
      );
      if (!sessionAvailableLocally) {
        onLoadSession?.(request.sessionId);
      }
    },
    [onLoadSession, sessions],
  );

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
      activeSessionId={activeSessionId}
      exportSessionId={exportSessionId}
      exportStatus={exportStatus}
      exportError={exportError}
      exportPath={exportedPath}
      exportTimestampMs={exportedAtMs}
      exportVariant={exportedVariant}
      durabilityOverview={durabilityOverview}
      privacyOverview={privacyOverview}
      keybindingSnapshot={keybindingSnapshot}
      vimModeSnapshot={vimModeSnapshot}
      compactionSnapshot={compactionSnapshot}
      compactionPolicy={compactionPolicy}
      compactionStatus={compactionStatus}
      compactionError={compactionError}
      localEngineSnapshot={localEngineSnapshot}
      localEngineStatus={localEngineStatus}
      localEngineError={localEngineError}
      doctorOverview={doctorOverview}
      branchSnapshot={branchSnapshot}
      branchStatus={branchStatus}
      branchError={branchError}
      sourceControlState={sourceControlState}
      sourceControlStatus={sourceControlStatus}
      sourceControlError={sourceControlError}
      sourceControlLastCommitReceipt={lastCommitReceipt}
      assistantWorkbench={assistantWorkbench}
      activeWorkbenchSummary={activeWorkbenchSummary}
      retainedWorkbenchActivities={retainedWorkbenchActivities}
      retainedWorkbenchEvidenceThreadId={retainedWorkbenchEvidenceThreadId}
      retainedWorkbenchTraceLoading={retainedWorkbenchTrace.loading}
      retainedWorkbenchTraceError={retainedWorkbenchTrace.error}
      retainedWorkbenchEventCount={retainedWorkbenchTrace.events.length}
      retainedWorkbenchArtifactCount={retainedWorkbenchTrace.artifacts.length}
      latestRetainedWorkbenchEvent={latestRetainedWorkbenchEvent}
      latestRetainedWorkbenchArtifact={latestRetainedWorkbenchArtifact}
      retainedWorkbenchEvidenceAttachable={retainedWorkbenchEvidenceAttachable}
      mobileOverview={mobileOverview}
      replLaunchRequest={replLaunchRequest}
      onSeedIntent={onSeedIntent}
      capabilityRegistrySnapshot={capabilityRegistrySnapshot}
      capabilityRegistryStatus={capabilityRegistryStatus}
      capabilityRegistryError={capabilityRegistryError}
      pluginSnapshot={pluginSnapshot}
      pluginStatus={pluginStatus}
      pluginError={pluginError}
      remoteEnvSnapshot={remoteEnvSnapshot}
      remoteEnvStatus={remoteEnvStatus}
      remoteEnvError={remoteEnvError}
      serverSnapshot={serverSnapshot}
      serverStatus={serverStatus}
      serverError={serverError}
      sessions={sessions}
      replayBundle={replayBundle}
      replayLoading={replayLoading}
      replayError={replayError}
      replayRows={replayRows}
      planSummary={scopedPlanSummary}
      searches={searches}
      browses={browses}
      thoughtAgents={thoughtAgents}
      playbookRuns={playbookRuns}
      playbookRunsLoading={playbookRunsLoading}
      playbookRunsBusyRunId={playbookRunsBusyRunId}
      playbookRunsMessage={playbookRunsMessage}
      playbookRunsError={playbookRunsError}
      stagedOperations={stagedOperations}
      stagedOperationsLoading={stagedOperationsLoading}
      stagedOperationsBusyId={stagedOperationsBusyId}
      stagedOperationsMessage={stagedOperationsMessage}
      stagedOperationsError={stagedOperationsError}
      visibleSourceCount={visibleSourceCount}
      kernelLogs={kernelLogs}
      securityRows={securityRows}
      fileArtifacts={fileArtifacts}
      revisionArtifacts={revisionArtifacts}
      fileContext={fileContext}
      fileContextStatus={fileContextStatus}
      fileContextError={fileContextError}
      fileBrowsePath={fileBrowsePath}
      fileBrowseEntries={fileBrowseEntries}
      fileBrowseStatus={fileBrowseStatus}
      fileBrowseError={fileBrowseError}
      rewindSnapshot={rewindSnapshot}
      rewindStatus={rewindStatus}
      rewindError={rewindError}
      selectedRewindSessionId={selectedRewindSessionId}
      compareTargetSessionId={compareTargetSessionId}
      hookSnapshot={hookSnapshot}
      hooksStatus={hooksStatus}
      hooksError={hooksError}
      privacySnapshot={privacySnapshot}
      permissionsStatus={permissionsStatus}
      permissionsError={permissionsError}
      permissionPolicyState={policyState}
      permissionGovernanceRequest={governanceRequest}
      permissionConnectorOverrides={connectorOverrides}
      permissionActiveOverrideCount={activeOverrideCount}
      permissionProfiles={availableProfiles}
      permissionCurrentProfileId={currentProfileId}
      permissionApplyingProfileId={applyingProfileId}
      permissionEditingConnectorId={editingConnectorId}
      permissionApplyingGovernanceRequest={applyingGovernanceRequest}
      permissionRememberedApprovals={rememberedApprovals}
      screenshotReceipts={screenshotReceipts}
      substrateReceipts={substrateReceipts}
      onOpenArtifact={onOpenArtifact}
      onRetryPlaybookRun={onRetryPlaybookRun}
      onResumePlaybookRun={onResumePlaybookRun}
      onDismissPlaybookRun={onDismissPlaybookRun}
      onMessageWorkerSession={onMessageWorkerSession}
      onStopWorkerSession={onStopWorkerSession}
      onPromoteRunResult={onPromoteRunResult}
      onPromoteStepResult={onPromoteStepResult}
      onPromoteStagedOperation={onPromoteStagedOperation}
      onRemoveStagedOperation={onRemoveStagedOperation}
      onLoadSession={onLoadSession}
      currentTask={task}
      onStopSession={onStopSession}
      onOpenGate={onOpenGate}
      isGated={isGated}
      gateInfo={gateInfo}
      isPiiGate={isPiiGate}
      gateDeadlineMs={gateDeadlineMs}
      gateActionError={gateActionError}
      credentialRequest={credentialRequest}
      clarificationRequest={clarificationRequest}
      onApprove={onApprove}
      onGrantScopedException={onGrantScopedException}
      onDeny={onDeny}
      onSubmitRuntimePassword={onSubmitRuntimePassword}
      onCancelRuntimePassword={onCancelRuntimePassword}
      onSubmitClarification={onSubmitClarification}
      onCancelClarification={onCancelClarification}
      onRefreshRewind={refreshRewind}
      onSelectRewindSession={setSelectedRewindSessionId}
      onOpenCompareForSession={handleOpenCompareForSession}
      onRefreshCompaction={refreshCompaction}
      teamMemorySnapshot={teamMemorySnapshot}
      teamMemoryStatus={teamMemoryStatus}
      teamMemoryError={teamMemoryError}
      teamMemoryIncludeGovernanceCritical={teamMemoryIncludeGovernanceCritical}
      onSetTeamMemoryIncludeGovernanceCritical={setTeamMemoryIncludeGovernanceCritical}
      onRefreshTeamMemory={refreshTeamMemory}
      onSyncTeamMemory={syncTeamMemory}
      onForgetTeamMemoryEntry={forgetTeamMemory}
      onRefreshDoctor={handleRefreshDoctor}
      onCompactSession={compactSession}
      onUpdateCompactionPolicy={updateCompactionPolicy}
      onResetCompactionPolicy={resetCompactionPolicy}
      onExportBundle={handleExportBundle}
      promotionStageBusyTarget={promotionStageBusyTarget}
      promotionStageMessage={promotionStageMessage}
      promotionStageError={promotionStageError}
      onStagePromotionCandidate={handleStagePromotionCandidate}
      onRefreshPlugins={refreshPlugins}
      onTrustPlugin={trustPlugin}
      onSetPluginEnabled={setPluginEnabled}
      onReloadPlugin={reloadPlugin}
      onRefreshPluginCatalog={refreshPluginCatalog}
      onRevokePluginTrust={revokePluginTrust}
      onInstallPluginPackage={installPluginPackage}
      onUpdatePluginPackage={updatePluginPackage}
      onRemovePluginPackage={removePluginPackage}
      onRefreshServer={refreshServer}
      onRefreshRemoteEnv={refreshRemoteEnv}
      onRefreshHooks={refreshHooks}
      onRefreshPermissions={refreshPermissions}
      onApplyPermissionProfile={applyProfile}
      onApplyPermissionGovernanceRequest={applyGovernanceRequest}
      onDismissPermissionGovernanceRequest={dismissGovernanceRequest}
      onForgetRememberedApproval={forgetApproval}
      onUpdatePermissionOverride={updateConnectorOverride}
      onResetPermissionOverride={resetConnectorOverride}
      onSetRememberedApprovalScopeMode={setApprovalScopeMode}
      onSetRememberedApprovalExpiry={setApprovalExpiry}
      onToggleVimMode={toggleVimMode}
      onRequestReplLaunch={handleRequestReplLaunch}
      onHandleReplLaunchRequest={() => setReplLaunchRequest(null)}
      onRefreshBranches={refreshBranches}
      onCreateBranchWorktree={createWorktree}
      onSwitchBranchWorktree={switchWorktree}
      onRemoveBranchWorktree={removeWorktree}
      onRefreshSourceControl={refreshSourceControl}
      onStageSourceControlPath={stagePath}
      onStageAllSourceControl={stageAll}
      onUnstageSourceControlPath={unstagePath}
      onUnstageAllSourceControl={unstageAll}
      onDiscardSourceControlPath={discardPath}
      onDiscardAllWorkingSourceControl={discardAllWorking}
      onCommitSourceControl={commit}
      onOpenView={handleOpenView}
      onRefreshFileContext={refreshFileContext}
      onOpenFileDirectory={openFileDirectory}
      onBrowseFileParent={browseFileParent}
      onRememberFilePath={rememberFilePath}
      onPinFilePath={pinFilePath}
      onIncludeFilePath={includeFilePath}
      onExcludeFilePath={excludeFilePath}
      onRemoveFilePath={removeFilePath}
      onClearFileContext={clearFileContext}
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
  const showSectionNav = presentedSections.length > 1;

  return (
    <div className="artifact-panel artifact-hub-panel">
      <div className="artifact-header">
        <div className="artifact-meta">
          <div className="artifact-icon">{icons.sidebar}</div>
          <span className="artifact-filename artifact-filename--drawer">
            {focusedTraceMode ? "Scratchboard inspector" : "Runtime workbench"}
          </span>
          <span className="artifact-tag">{sectionLabel(activeView)}</span>
        </div>
        <div className="artifact-actions">
          <button
            className="artifact-action-btn artifact-action-btn--back"
            onClick={onClose}
            title="Back to chat"
            type="button"
          >
            Back to chat
          </button>
          <button
            className="artifact-action-btn close"
            onClick={onClose}
            title="Close drawer"
            type="button"
          >
            {icons.close}
          </button>
        </div>
      </div>

      <div
        className={`artifact-content artifact-hub-layout ${
          showSectionNav ? "" : "artifact-hub-layout--single-column"
        }`}
      >
        {showSectionNav ? (
          <aside className="artifact-hub-nav" aria-label="Evidence sections">
            {presentedSections.map((section) => (
              <button
                key={section.key}
                className={`artifact-hub-nav-item ${activeView === section.key ? "active" : ""}`}
                onClick={() => handleOpenView(section.key)}
                type="button"
              >
                <span className="artifact-hub-nav-label">{section.label}</span>
                <span className="artifact-hub-nav-count">{section.count}</span>
              </button>
            ))}
          </aside>
        ) : null}
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
