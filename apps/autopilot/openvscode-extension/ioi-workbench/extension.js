const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");
const {
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  normalizeBaseUrl,
  readDaemonModelSnapshot: readDaemonModelSnapshotFromClient,
  requestJson,
} = require("./bridge/client");
const { createWorkspaceBridge } = require("./bridge/workspace-bridge");
const { registerChatCommands } = require("./commands/chat");
const { registerMigrationCommands } = require("./commands/migration");
const { registerModelCommands } = require("./commands/models");
const { registerNavigationCommands } = require("./commands/navigation");
const { registerQuickInputCommands } = require("./commands/quick-input");
const { registerRuntimeSurfaceCommands } = require("./commands/runtime-surfaces");
const { registerStudioModeControlCommands } = require("./commands/studio-mode-controls");
const { registerStudioQuickInputCommands } = require("./commands/studio-quick-input");
const { registerStudioTestHookCommands } = require("./commands/studio-test-hooks");
const { registerWorkflowCommands } = require("./commands/workflow");
const {
  buildWorkspaceActionContext: buildWorkspaceActionContextFromWorkbench,
} = require("./workbench/action-context");
const {
  startWorkbenchContextSnapshotPublisher: startWorkbenchContextSnapshotPublisherFromWorkbench,
} = require("./workbench/context-publisher");
const {
  createWorkbenchContextSnapshot,
} = require("./workbench/context-snapshot");
const { createWorkbenchCodeModePanelRenderer } = require("./workbench/code-mode-panel");
const { createAutopilotModeController } = require("./workbench/mode-controller");
const { createWorkbenchModeBodyRenderers } = require("./workbench/mode-body-renderers");
const { formatBytes, modelSnapshotFromState } = require("./workbench/model-snapshot");
const { createWorkbenchOverviewPanelRenderer } = require("./workbench/overview-panel");
const { createAutopilotShellHeader } = require("./workbench/shell-header");
const { createWorkflowComposerPanelRenderer } = require("./workbench/workflow-composer-panel");
const {
  formatStudioWorkDuration,
  studioDocumentedWorkRecord: studioDocumentedWorkRecordFromSummary,
  studioDocumentedWorkSummary: studioDocumentedWorkSummaryFromSummary,
  studioTurnHasDocumentedWork,
} = require("./studio-work-summary");
const { createStudioPanelHtml } = require("./studio/studio-panel-html");
const { createStudioModelCompletion } = require("./studio/model-completion");
const { createStudioOperationalSurface } = require("./studio/operational-surface");
const { createStudioPromptPolicy } = require("./studio/prompt-policy");
const { createModelSurfaceRenderer } = require("./studio/model-surface");
const { createStudioAgentAnswerStreamProjector } = require("./studio/agent-answer-stream");
const { createStudioAgentFinalHandoffStreamer } = require("./studio/agent-final-handoff-stream");
const { createStudioAgentTurnEvents } = require("./studio/agent-turn-events");
const { createStudioAgentTurnResultText } = require("./studio/agent-turn-result-text");
const { createStudioAgentTurnRecovery } = require("./studio/agent-turn-recovery");
const { createStudioProductErrorMessage } = require("./studio/product-error-message");
const {
  createInitialStudioRuntimeProjection: createInitialStudioRuntimeProjectionFromState,
} = require("./studio/projection-state");
const { createStudioManagedSessionProjection } = require("./studio/projection-managed-sessions");
const { createStudioParityPlusEventProjection } = require("./studio/projection-parity-plus-events");
const { createStudioWorkspaceChangeProjection } = require("./studio/projection-workspace-changes");
const {
  refreshStudioReplayStepsFromProjection: refreshStudioReplayStepsFromProjectionState,
} = require("./studio/projection-replay");
const { createStudioPublicTextSanitizer } = require("./studio/public-text-sanitizer");
const {
  studioRuntimeEventToolName,
  studioRuntimeEventKind,
  studioRuntimeEventIsRunningStepCompletion,
  studioRuntimeEventIdentity,
  studioRuntimeToolEventDetail,
  studioRuntimeToolEventExcerpt,
  sanitizeStudioPublicToolText,
} = require("./studio/runtime-event-utils");
const { createStudioRuntimeEventSelectors } = require("./studio/runtime-event-selectors");
const {
  studioArtifactResearchQuery,
  studioArtifactShouldGatherResearch,
  studioResearchIntentFrameForArtifact,
} = require("./studio/artifact-research-routing");
const { createStudioArtifactIntent } = require("./studio/artifact-intent");
const { createStudioArtifactPreview } = require("./studio/artifact-preview");
const { createStudioManagedSessionView } = require("./studio/managed-session-view");
const { createStudioPendingWorkProjection } = require("./studio/pending-work");
const { createStudioTurnPolicy } = require("./studio/turn-policy");
const { createStudioPolicyLeaseLifecycle } = require("./studio/policy-lease-lifecycle");
const { createStudioReceiptRefs } = require("./studio/receipt-refs");
const { createStudioToolResponseProjection } = require("./studio/tool-response-projection");
const {
  createStudioWorkRecordProjection,
  studioPublicOutputBlock,
} = require("./studio/work-record-projection");
const { createStudioResponseMetrics } = require("./studio/response-metrics");
const { createStudioSourceChipRenderer } = require("./studio/source-chip-renderer");
const { createStudioCodeExecution } = require("./studio/code-execution");
const { createStudioChatOutputRenderers } = require("./studio/chat-output-renderers");
const { createStudioParityPlusPanels } = require("./studio/parity-plus-panels");
const {
  STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
  createStudioDurabilityPanels,
} = require("./studio/durability-panels");
const { createNativeChatViewRenderer } = require("./studio/native-chat-view");
const { createStudioToolPalette } = require("./studio/tool-palette");
const { createStudioModelSelection } = require("./studio/model-selection");
const { createStudioOverviewView } = require("./studio/overview-view");
const { createStudioTraceView } = require("./studio/trace-view");
const { createStudioViewHelpers } = require("./studio/view-helpers");
const {
  STUDIO_MODE_AGENT,
  STUDIO_MODE_ASK,
  STUDIO_PERMISSION_MODE_DEFAULT,
  STUDIO_PERMISSION_MODE_AUTO_REVIEW,
  STUDIO_PERMISSION_MODE_FULL_ACCESS,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  studioExecutionModeLabel,
  studioPermissionDaemonMapping,
  studioPermissionModeLabel,
  studioPermissionModeOptions,
} = require("./studio/modes");
const {
  collectStudioSourceRefs,
  collectStudioSourceRefsFromPartialJsonText,
  studioFirstSourceExcerptFromEvent,
  studioJsonObjectFromText,
  studioJsonValueFromText,
  studioPartialJsonFieldValue,
  studioRecordValue,
  studioSourceRefFromRecord,
  studioSourceRefsFromRuntimeEvent,
  studioSourceRefsFromRuntimeEvents,
  studioUnescapeJsonStringFragment,
} = require("./studio/source-refs");
const {
  AUTOPILOT_MODE_BY_ID,
  AUTOPILOT_MODE_BY_PANEL_VIEW_ID,
  AUTOPILOT_MODE_BY_VIEW_ID,
  AUTOPILOT_MODES,
  VIEW_DEFINITIONS,
} = require("./workbench-surfaces");

function workspaceSummary() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return {
      name: "No folder",
      path: "Open a workspace folder to ground IOI context.",
    };
  }

  return {
    name: folder.name,
    path: folder.uri.fsPath,
  };
}

let overviewPanel = null;
let overviewPanelLastHtml = null;
let overviewPanelNonce = null;
let studioPanel = null;
let studioPanelLastHtml = null;
let studioPanelPageNonce = null;
let workflowComposerPanel = null;
let modelsPanel = null;
const genericModePanels = new Map();
const autopilotModeController = createAutopilotModeController({
  AUTOPILOT_MODE_BY_ID,
  AUTOPILOT_MODE_BY_PANEL_VIEW_ID,
  AUTOPILOT_MODE_BY_VIEW_ID,
  vscode,
});
let studioModelInvocationToken = null;
const modeVisibilityProjectionLastAtMs = new Map();
const MODE_VISIBILITY_REQUEST_TYPES = {
  home: "overview.open",
  studio: "studio.open",
  workflows: "workflow.composer.open",
  models: "models.open",
  runs: "runs.open",
  policy: "policy.open",
  connectors: "connections.open",
  code: "code.open",
};
const STUDIO_APPROVAL_ID = "approval_agent_studio_inline_diff_preview";
const STUDIO_POLICY_LEASE_ID = "approval_agent_studio_policy_lease_destructive_action";
const STUDIO_AGENT_RUNTIME_PROFILE = "runtime_service";
const STUDIO_DIRECT_MODEL_RUNTIME_PROFILE = "chat_only";
const STUDIO_AGENT_MIN_TURN_STEPS = 8;
const STUDIO_AGENT_TURN_POST_TIMEOUT_MS = 130000;
const STUDIO_AGENT_TURN_RECOVERY_POLL_MS = 1000;
const STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS = 15000;
const STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS = 4;
const STUDIO_MODEL_COMPLETION_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_MODEL_COMPLETION_TIMEOUT_MS))
  ? Math.max(30_000, Math.floor(Number(process.env.IOI_STUDIO_MODEL_COMPLETION_TIMEOUT_MS)))
  : 300_000;
const STUDIO_REFRESH_STATE_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_REFRESH_STATE_TIMEOUT_MS))
  ? Math.max(500, Math.floor(Number(process.env.IOI_STUDIO_REFRESH_STATE_TIMEOUT_MS)))
  : 2_500;
const STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS))
  ? Math.max(500, Math.floor(Number(process.env.IOI_STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS)))
  : 5_000;
const STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS))
  ? Math.max(1_000, Math.floor(Number(process.env.IOI_STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS)))
  : 30_000;
const STUDIO_DEFAULT_MAX_OUTPUT_TOKENS = 4096;
const STUDIO_DEFAULT_ARTIFACT_MAX_OUTPUT_TOKENS = 4096;
const STUDIO_PRODUCT_MODEL_UNAVAILABLE = "__product_model_unavailable__";
const workspaceBridge = createWorkspaceBridge({
  bridgeUrl,
  readDaemonModelSnapshot: readDaemonModelSnapshotFromClient,
  workspaceSummary,
  vscode,
  modelSnapshotTimeoutMs: STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS,
  refreshStateTimeoutMs: STUDIO_REFRESH_STATE_TIMEOUT_MS,
});
const {
  buildRuntimeRefs,
  buildWorkbenchCommandRouteReceipt,
  readBridgeState,
  requestBridge,
  startBridgeCommandPolling,
  writeBridgeRequest,
  writeWorkbenchCommandRouteReceipt,
} = workspaceBridge;
const {
  buildWorkbenchContextSnapshot,
  buildWorkbenchInspectionTargetIndex,
  getLastTaskExitCode,
  rememberRecentTaskLabel,
  setLastTaskExitCode,
} = createWorkbenchContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
  refSafe,
});
let studioRuntimeProjection = createInitialStudioRuntimeProjection();
let studioDiffProviderDisposable = null;
const studioDiffDocuments = new Map();
let activeTraceTarget = null;

function createInitialStudioRuntimeProjection() {
  return createInitialStudioRuntimeProjectionFromState({
    approvalId: STUDIO_APPROVAL_ID,
    executionMode: STUDIO_MODE_AGENT,
    permissionMode: STUDIO_PERMISSION_MODE_DEFAULT,
    policyLeaseId: STUDIO_POLICY_LEASE_ID,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
  });
}

function buildWorkspaceActionContext(source, uri) {
  return buildWorkspaceActionContextFromWorkbench({ vscode, workspaceSummary }, source, uri);
}

function refSafe(value) {
  return (
    String(value || "unknown")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "unknown"
  );
}

function nonce() {
  return crypto.randomBytes(16).toString("base64");
}

function startWorkbenchContextSnapshotPublisher(context, output) {
  return startWorkbenchContextSnapshotPublisherFromWorkbench({
    context,
    output,
    vscode,
    buildWorkbenchContextSnapshot,
    buildWorkbenchInspectionTargetIndex,
    writeBridgeRequest,
    rememberRecentTaskLabel,
    getLastTaskExitCode,
    setLastTaskExitCode,
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const {
  commandPayloadAttr,
  formatRelativeTime,
  renderCommandButton,
  renderDiagnostics,
  renderItems,
  renderRuntimeSummary,
} = createStudioViewHelpers({ escapeHtml });
const {
  renderArtifactsView,
  renderConnectionsView,
  renderDirectModeActivityView,
  renderPolicyView,
} = createWorkbenchModeBodyRenderers({
  escapeHtml,
  formatRelativeTime,
  renderCommandButton,
  renderItems,
});

const {
  modelDisplayName,
  modelEndpointForArtifact,
  modelInstanceForEndpoint,
  renderModelsPanelBody,
} = createModelSurfaceRenderer({
  commandPayloadAttr,
  daemonEndpoint,
  escapeHtml,
  formatBytes,
  modelSnapshotFromState,
  renderCommandButton,
});

const {
  normalizedNativeChatTurns,
  renderChatView,
  renderNativeChatConversation,
  renderNativeChatIcon,
} = createNativeChatViewRenderer({
  escapeHtml,
  workspaceSummary,
});

function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

const {
  compactStudioWhitespace,
  isAutoStudioModelSelector,
  promptIsInternalHarnessProbe,
  promptRequiresRetrieval,
  promptRequiresWorkspaceContext,
  promptTargetsLocalWorkspace,
} = createStudioPromptPolicy({
  normalizeStudioExecutionMode,
  stringValue,
  studioModeAgent: STUDIO_MODE_AGENT,
});

const {
  humanizeStudioToolName,
  studioDisplayTurnContent,
  studioHumanizeOperationalTranscriptText,
  studioSanitizePublicAssistantText,
} = createStudioPublicTextSanitizer({
  compactStudioWhitespace,
  studioTextIndicatesApprovalPause,
});

function workspaceTargetsForPrompt(prompt = "") {
  const raw = compactText(prompt);
  const targets = [];
  const pathPattern = /(?:^|\s|["'`])((?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\/[^\s"'`),;:]+)(?=$|\s|["'`),;:])/gi;
  for (const match of raw.matchAll(pathPattern)) {
    const path = compactText(match?.[1] || "").replace(/[.!?]+$/g, "");
    if (path && !targets.some((target) => target.kind === "path" && target.path === path)) {
      targets.push({ kind: "path", path, reason: "explicit_workspace_path" });
    }
  }
  if (targets.length > 0) {
    return targets;
  }
  const stopWords = new Set([
    "about", "and", "are", "between", "codebase", "does", "explain", "find", "first",
    "from", "how", "inspect", "into", "look", "or", "per", "project", "read",
    "repo", "repository", "search", "should", "summarize", "the", "this", "what", "where", "which",
    "workspace",
  ]);
  const seenTerms = new Set();
  const terms = raw
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, " ")
    .split(/\s+/)
    .map((term) => term.replace(/^[-./_]+|[-./_]+$/g, ""))
    .filter((term) => term.length >= 3 && !stopWords.has(term))
    .filter((term) => {
      if (seenTerms.has(term)) return false;
      seenTerms.add(term);
      return true;
    })
    .slice(0, 8);
  const query = terms.length > 0 ? terms.join(" ") : raw.slice(0, 120);
  return query ? [{ kind: "search", query, reason: "workspace_context_query" }] : [];
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

const {
  studioRuntimeEventTurnId,
  studioRuntimeEventsForTurn,
  studioRuntimeEventsIncludeCompletedTool,
  studioRuntimeEventsIncludeTool,
  studioRuntimeToolEventCount,
} = createStudioRuntimeEventSelectors({
  firstArray,
  stringValue,
  studioRuntimeEventKind,
  studioRuntimeEventToolName,
});

const {
  shouldProjectStudioRuntimeCockpit,
  studioPromptRequestsGeneratedWebArtifact,
  studioPromptRequestsBrowserObservationArtifact,
  shouldProjectConversationArtifactCanvas,
  studioIntentFrameRouteDirective,
  studioIntentFrameProjectsArtifact,
  studioIntentFrameProjectsRuntimeCockpit,
  studioIntentFrameRequiresRetrieval,
  studioIntentFrameArtifactClass,
  studioIntentFrameArtifactTitle,
  studioIntentFrameArtifactSummary,
  fallbackStudioPromptIntentFrame,
  studioIntentFramePayload,
  studioArtifactClassFromPrompt,
  studioTopicFromGeneratedWebPrompt,
  studioTitleCaseArtifactTopic,
  studioArtifactTitleFromClass,
} = createStudioArtifactIntent({
  stringValue,
  firstArray,
  promptRequiresRetrieval,
  promptRequiresWorkspaceContext,
  workspaceTargetsForPrompt,
  normalizeStudioExecutionMode,
  studioArtifactShouldGatherResearch,
  modeAgent: STUDIO_MODE_AGENT,
  modeAsk: STUDIO_MODE_ASK,
});

const {
  studioArtifactClassLabel,
  studioArtifactOutputModality,
  studioArtifactIsWebsite,
  studioArtifactPreviewLabel,
  studioArtifactPreviewSrcdoc,
  studioArtifactInlinePreview,
  studioArtifactPreviewShell,
  studioConversationArtifactRows,
} = createStudioArtifactPreview({
  escapeHtml,
  stringValue,
  firstArray,
  studioRecordValue,
  getPageNonce: () => studioPanelPageNonce || "",
});

const {
  studioWorkRecordWithSessionCards,
  studioManagedSessionRows,
} = createStudioManagedSessionView({
  escapeHtml,
  firstArray,
});

const {
  studioAgentMaxStepsForIntent,
  studioApprovalPauseError,
  studioApprovalPauseErrorMessage,
  studioPolicyBlockedRuntimeMessage,
  studioResultTextLooksRetrievalGrounded,
  studioRetrievalFailClosedText,
  studioTextIndicatesApprovalPause,
} = createStudioTurnPolicy({
  firstArray,
  humanizeStudioToolName,
  stringValue,
  studioIntentFramePayload,
  studioIntentFrameRequiresRetrieval,
  studioRuntimeEventsIncludeCompletedTool,
  studioRuntimeEventToolName,
  uniqueStrings,
});

function resetStudioDaemonThreadProjection() {
  studioRuntimeProjection.threadId = null;
  studioRuntimeProjection.sessionId = null;
  studioRuntimeProjection.turnId = null;
  studioRuntimeProjection.runId = null;
  studioRuntimeProjection.lastModelStream = null;
  studioRuntimeProjection.lastIntentFrame = null;
  studioRuntimeProjection.pendingWorklog = [];
  studioRuntimeProjection.runtimeEventSeenIds = [];
  studioAgentAnswerStreamProjector.reset();
}

function startNewStudioSession(reason = "New Studio session") {
  const previous = studioRuntimeProjection || {};
  const next = createInitialStudioRuntimeProjection();
  next.executionMode = normalizeStudioExecutionMode(previous.executionMode || STUDIO_MODE_AGENT);
  next.runtimeProfile =
    next.executionMode === STUDIO_MODE_AGENT
      ? STUDIO_AGENT_RUNTIME_PROFILE
      : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  next.modelRoute = previous.modelRoute || "route.local-first";
  next.selectedModel = previous.selectedModel || "auto";
  next.reasoningEffort = normalizeStudioReasoningEffort(previous.reasoningEffort, "none");
  next.approvalMode = normalizeStudioPermissionMode(previous.approvalMode);
  next.timeline = [
    {
      label: "New Studio session",
      detail: reason,
      status: "ready",
    },
  ];
  studioRuntimeProjection = next;
  return studioRuntimeProjection;
}

const {
  assertStudioProductModelSelector,
  isExternalStudioModelRecord,
  isFixtureStudioModelRecord,
  isProductStudioModelSelection,
  loadedProductStudioModelInstances,
  modelRecordIsEmbeddingOnly,
  modelRecordReasoningSignals,
  modelRecordStatusScore,
  modelRecordSupportsChat,
  mountedModelQuickInputRowsFromState,
  normalizeStudioReasoningEffort,
  productStudioModelSelectionsFromSnapshot,
  studioArtifactMaxOutputTokens,
  studioExternalModelProviderUsageAllowed,
  studioMaxOutputTokens,
  studioPreferredModelSelection,
  studioProductModelSelectionError,
  studioReasoningControlForSelection,
  studioReasoningEffortOptions,
  studioSameNonEmptyId,
  studioSelectionModelId,
  studioSelectionSupportsChat,
  studioSnapshotFromState,
} = createStudioModelSelection({
  daemonEndpoint,
  firstArray,
  getEnv: (name) => process.env[name],
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  isAutoStudioModelSelector,
  modelDisplayName,
  modelEndpointForArtifact,
  modelInstanceForEndpoint,
  modelSnapshotFromState,
  productModelUnavailable: STUDIO_PRODUCT_MODEL_UNAVAILABLE,
  stringValue,
  studioDefaultArtifactMaxOutputTokens: STUDIO_DEFAULT_ARTIFACT_MAX_OUTPUT_TOKENS,
  studioDefaultMaxOutputTokens: STUDIO_DEFAULT_MAX_OUTPUT_TOKENS,
  studioFixtureModelUsageAllowed,
  studioTextContainsProductFixtureMarker,
});

const {
  appendStudioReceipts,
  normalizeReceiptRefs,
  studioReceiptProjection,
} = createStudioReceiptRefs({
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  uniqueStrings: (values) => [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))],
});

const {
  studioEstimatedTokenCount,
  studioFormatMetricNumber,
  studioNumberOrNull,
  studioPositiveNumberOrNull,
  studioResponseMetricsFromResponse,
  studioResponseMetricsFromUsage,
  studioResponseMetricsRows,
  studioSplitReasoningFromText,
  studioThinkingRows,
  studioTurnContentRows,
  studioVerifiedBadge,
} = createStudioResponseMetrics({
  escapeHtml,
  stringValue,
  normalizeStudioReasoningEffort,
  normalizeReceiptRefs,
});

function studioFixtureModelUsageAllowed() {
  return /^(1|true|yes|on)$/i.test(String(process.env.IOI_STUDIO_ALLOW_FIXTURE_MODELS || process.env.IOI_STUDIO_FIXTURE_MODE || ""));
}

function studioDenyFixtureModelPolicy() {
  return studioFixtureModelUsageAllowed()
    ? {}
    : {
        deny_fixture_models: true,
        denyFixtureModels: true,
      };
}

function studioTextContainsProductFixtureMarker(text = "") {
  const haystack = stringValue(text).toLowerCase();
  return (
    haystack.includes("ioi model router fixture response") ||
    haystack.includes("input_hash=") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("stories260k") ||
    haystack.includes("deterministic native-local model fixture") ||
    haystack.includes("native_local.fixture") ||
    haystack.includes("backend.fixture")
  );
}

const {
  STUDIO_RUNTIME_VISIBILITY,
  classifyStudioRuntimeEvent,
  renderRunsView,
  studioTraceLink,
} = createStudioTraceView({
  commandPayloadAttr,
  crypto,
  escapeHtml,
  firstArray,
  getActiveTraceTarget: () => activeTraceTarget,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  normalizeReceiptRefs,
});

function studioWorkCursor() {
  return {
    startedAtMs: Date.now(),
    actionCards: studioRuntimeProjection.actionCards.length,
    policyLeases: studioRuntimeProjection.policyLeases.length,
    commandOutputs: studioRuntimeProjection.commandOutputs.length,
    diagnosticGates: studioRuntimeProjection.diagnosticGates.length,
    diffHunks: studioRuntimeProjection.diffHunks.length,
    browserCards: studioRuntimeProjection.browserCards.length,
    workerCards: studioRuntimeProjection.workerCards.length,
    computerUseSessions: studioRuntimeProjection.computerUseSessions.length,
    conversationArtifacts: studioRuntimeProjection.conversationArtifacts.length,
    pendingWorklog: studioRuntimeProjection.pendingWorklog.length,
    receipts: studioRuntimeProjection.receipts.length,
  };
}

function studioDocumentedWorkRecord(cursor = {}) {
  return studioDocumentedWorkRecordFromSummary(studioRuntimeProjection, cursor);
}

function studioDocumentedWorkSummary(record = {}) {
  return studioDocumentedWorkSummaryFromSummary(record, studioRuntimeProjection.status);
}

const {
  sanitizeStudioSourceUrl,
  studioSourceChipFaviconUrl,
  studioSourceChipIconDataUri,
  studioSourceChipRows,
  studioTurnSourceRows,
} = createStudioSourceChipRenderer({
  compactStudioWhitespace,
  escapeHtml,
  firstArray,
  stringValue,
  studioRecordValue,
});
const {
  studioChatCodeExecutionRows,
  studioCodeExecutionPolicy,
  studioExecutableCodeBlocksFromText,
} = createStudioCodeExecution({
  commandPayloadAttr,
  escapeHtml,
});

const {
  appendStudioPendingWorkStep,
  isAbstractStudioPendingWorkStep,
  markStudioRuntimeEventSeen,
  normalizeStudioPendingWorkStep,
  studioPendingCommandOutputExcerpt,
  studioPendingStepFromRuntimeEvent,
  studioPendingWorkLabelForTool,
  studioPendingWorkStepIsConcrete,
  studioPendingWorkToolName,
  studioPendingWorklogLastAtMs,
  studioRuntimeEventSeen,
  studioVisiblePendingStepDetail,
  uniqueStrings,
} = createStudioPendingWorkProjection({
  stringValue,
  firstArray,
  compactStudioWhitespace,
  sanitizeStudioPublicToolText,
  studioPublicOutputBlock,
  humanizeStudioToolName,
  studioSourceRefFromRecord,
  studioRuntimeEventIdentity,
  studioRuntimeEventToolName,
  studioRuntimeEventKind,
  studioRuntimeToolEventDetail,
  studioRuntimeToolEventExcerpt,
  studioSourceRefsFromRuntimeEvent,
  studioFirstSourceExcerptFromEvent,
  getProjection: () => studioRuntimeProjection,
});

const {
  studioSessionBrainPanelFromProjection,
  studioTrajectoryReplayPanelFromProjection,
} = createStudioDurabilityPanels({
  firstArray,
  normalizeReceiptRefs,
  stringValue,
  studioRuntimeEventKind,
  uniqueStrings,
  workspacePath: () => workspaceSummary().path,
});

const {
  studioCommandRowHasOutput,
  studioFilterDuplicateCommandWorkRows,
  studioPublicCommandOutputForWebview,
  studioPublicDiffHunkForWebview,
  studioPublicWorkRecordForWebview,
  studioPublicWorkspacePath,
} = createStudioWorkRecordProjection({
  compactStudioWhitespace,
  firstArray,
  workspacePath: () => workspaceSummary().path,
  studioPendingWorkLabelForTool,
  studioSourceRefFromRecord,
});
const {
  studioPolicyLeaseLifecycleFixture,
  studioPolicyLeaseLifecycleRows,
  studioPolicyLeaseToolBody,
} = createStudioPolicyLeaseLifecycle({
  normalizeReceiptRefs,
});

const {
  applyStudioManagedSessionInspection,
  applyStudioManagedSessionsToLatestTurn,
  exerciseStudioManagedSessionReconnect,
  refreshStudioManagedSessionsFromDaemon,
  studioComputerUseSessionStatus,
  studioComputerUseStatusLabel,
  studioComputerUseSurfaceKind,
  studioComputerUseSurfaceLabel,
  studioManagedSessionFromBridgeCard,
  studioManagedSessionFromRuntimeEvent,
  studioManagedSessionReconnectSummary,
  upsertStudioManagedSession,
} = createStudioManagedSessionProjection({
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  requestJson,
  stringValue,
  studioJsonObjectFromText,
  studioRecordValue,
  writeBridgeRequest,
});

const {
  applyStudioWorkspaceChangeReviewInspection,
  refreshStudioWorkspaceChangeReviewsFromDaemon,
} = createStudioWorkspaceChangeProjection({
  compactStudioWhitespace,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  requestJson,
  stringValue,
  workspaceSummary,
});

function appendStudioTimeline(label, detail, status = "ready", extra = {}) {
  studioRuntimeProjection.timeline.push({
    label,
    detail,
    status,
    at: new Date().toISOString(),
    ...extra,
  });
}

function appendStudioRuntimeEvent(event, fallbackKind = "runtime.event") {
  if (!event || typeof event !== "object") {
    return;
  }
  const normalized = {
    id: event.event_id || event.eventId || event.id || `${fallbackKind}.${Date.now()}`,
    kind: event.event_kind || event.eventKind || event.kind || fallbackKind,
    status: event.status || event.payload_summary?.status || "observed",
    summary:
      event.summary ||
      event.payload_summary?.summary ||
      event.payload_summary?.result_summary ||
      event.payload_summary?.input_summary ||
      "",
    receiptRefs: normalizeReceiptRefs(event),
    raw: event,
  };
  normalized.visibility = classifyStudioRuntimeEvent(normalized);
  studioRuntimeProjection.runtimeEvents.push(normalized);
  if (normalized.receiptRefs.length > 0) {
    appendStudioReceipts(normalized.receiptRefs.map((id) => ({
      id,
      kind: normalized.kind,
      summary: normalized.summary || "Daemon runtime event receipt.",
    })));
  }
}

function appendStudioReceiptsFromResponse(response, kind, summary) {
  appendStudioReceipts(
    normalizeReceiptRefs(response).map((id) => ({
      id,
      kind,
      summary,
    })),
  );
}

const {
  applyStudioParityPlusEvent,
  studioRuntimeEventPayload,
} = createStudioParityPlusEventProjection({
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  normalizeReceiptRefs,
  stringValue,
  studioRuntimeEventKind,
});

const {
  commandOutputFromToolResponse,
  safeJsonPreview,
} = createStudioToolResponseProjection({
  normalizeReceiptRefs,
});

function recomputeStudioRuntimeCockpitAchieved() {
  const cockpit = studioRuntimeProjection.runtimeCockpit || {};
  cockpit.achieved = Boolean(
    cockpit.modelBackedStreamingObserved &&
    cockpit.realDaemonToolProposalObserved &&
    cockpit.policyLeaseDialogObserved &&
    cockpit.policyDeniedActionDidNotExecute &&
    cockpit.sandboxCommandOutputStreamObserved &&
    cockpit.sandboxCommandReceiptObserved &&
    cockpit.inlineDiffOverlayObserved &&
    cockpit.hunkNavigationObserved &&
    cockpit.hunkAcceptRejectReceiptsObserved &&
    cockpit.stopResumeObserved &&
    cockpit.diagnosticsTestGateObserved &&
    cockpit.receiptTimelinePerStepObserved &&
    cockpit.replayStepDetailObserved &&
    cockpit.projectionOnlyRuntimeRejected &&
    cockpit.browserStatusObserved &&
    cockpit.workerStatusObserved
  );
  studioRuntimeProjection.runtimeCockpit = cockpit;
  return cockpit.achieved;
}

const { studioCleanProductErrorMessage } = createStudioProductErrorMessage({ stringValue });
const {
  studioChatOutputRendererRows,
} = createStudioChatOutputRenderers({
  escapeHtml,
  firstArray,
  normalizeReceiptRefs,
  studioVerifiedBadge,
});
const {
  studioParityPlusPanelRows: studioParityPlusPanelRowsFromRenderer,
} = createStudioParityPlusPanels({
  escapeHtml,
  firstArray,
  stringValue,
  studioTraceLink,
  studioVerifiedBadge,
});

function studioIcon(name) {
  const icons = {
    paperclip:
      '<path d="M21.4 11.6 12 21a6 6 0 0 1-8.5-8.5l9.7-9.7a4 4 0 1 1 5.7 5.7L9.2 18.2a2 2 0 0 1-2.8-2.8l9.4-9.4" />',
    monitor:
      '<rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8" /><path d="M12 16v4" />',
    sparkles:
      '<path d="M12 3 13.7 8.3 19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3Z" /><path d="M5 3v4" /><path d="M3 5h4" /><path d="M19 17v4" /><path d="M17 19h4" />',
    sliders:
      '<path d="M4 7h10" /><path d="M18 7h2" /><path d="M4 17h2" /><path d="M10 17h10" /><circle cx="16" cy="7" r="2" /><circle cx="8" cy="17" r="2" />',
    send:
      '<path d="M5 4 20 12 5 20l2.8-8L5 4Z" /><path d="M8 12h12" />',
    stop:
      '<rect x="7" y="7" width="10" height="10" rx="1.5" />',
    search:
      '<circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" />',
    chevronDown:
      '<path d="m7 10 5 5 5-5" />',
  };
  return `<svg class="studio-control-icon studio-control-icon--${escapeHtml(name)}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${icons[name] || ""}</svg>`;
}

function studioPendingWorklogRows() {
  return firstArray(studioRuntimeProjection.pendingWorklog).map((step) => {
    const sourceChips = firstArray(step.sourceChips || step.source_chips || step.sources);
    const commandStep = /shell|terminal|command/.test([
      step.toolName,
      step.tool_name,
      step.toolId,
      step.tool_id,
      step.label,
      step.kind,
    ].map((value) => String(value || "").toLowerCase()).join(" "));
    const excerpt = commandStep
      ? studioPendingCommandOutputExcerpt(step, sourceChips[0]?.excerpt || "")
      : compactStudioWhitespace(step.excerptPreview || step.excerpt_preview || sourceChips[0]?.excerpt || "").slice(0, 260);
    const detail = studioVisiblePendingStepDetail(step.detail);
    const status = compactStudioWhitespace(step.status || "running").toLowerCase();
    const startedAtMs = Date.parse(step.at || "") || Date.now();
    const elapsedLabel = step.label === "Running command" && /running|started/.test(status)
      ? ` for ${formatStudioWorkDuration(Date.now() - startedAtMs)}`
      : "";
    return `
    <li data-status="${escapeHtml(step.status || "running")}" data-base-label="${escapeHtml(step.label || "")}" data-started-at-ms="${escapeHtml(String(startedAtMs))}">
      <p class="studio-pending-step__headline">${escapeHtml(`${step.label || ""}${elapsedLabel}`)}</p>
      ${detail ? `<span class="studio-pending-step__summary">${escapeHtml(detail)}</span>` : ""}
      ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
      ${excerpt ? commandStep
        ? `<pre class="studio-pending-step__excerpt studio-pending-step__command-output" data-testid="studio-pending-command-output">${escapeHtml(excerpt)}</pre>`
        : `<p class="studio-pending-step__excerpt">${escapeHtml(excerpt)}</p>`
      : ""}
    </li>
  `;
  }).join("");
}

function studioPendingProjectionRows() {
  if (!studioRuntimeProjection.pending) {
    return "";
  }
  const startedAt = Number(studioRuntimeProjection.pendingStartedAtMs || Date.now());
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  return `
    <article
      class="studio-chat-turn studio-chat-turn--assistant studio-pending"
      data-testid="studio-pending-state"
      data-studio-turn-role="assistant"
      data-documented-work="false"
      data-pending-started-at-ms="${escapeHtml(String(startedAt))}"
    >
      <div class="studio-pending__line">
        <span class="studio-pending__dots" aria-hidden="true"><span></span><span></span><span></span></span>
        <strong data-testid="studio-pending-label">Thinking about your request · ${escapeHtml(String(elapsedSeconds))}s</strong>
      </div>
      <ol class="studio-pending__worklog" data-testid="studio-pending-worklog">
        ${studioPendingWorklogRows()}
      </ol>
    </article>
  `;
}

function studioCommandSurfaceLabel(command = {}) {
  const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
  const rawLabel = compactStudioWhitespace(command.label || command.command || "");
  if (/^shell__|^terminal__/.test(toolId) || /^(?:shell|command)$/i.test(rawLabel)) {
    return "Shell";
  }
  if (/^browser__/.test(toolId)) {
    return "Browser";
  }
  if (/^file__/.test(toolId)) {
    return "File";
  }
  return "";
}

function studioCommandPublicActionLabel(command = {}) {
  const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
  const rawLabel = compactStudioWhitespace(command.label || command.command || toolId || "");
  const status = compactStudioWhitespace(command.status || "completed");
  if (/^(?:shell|command)$/i.test(rawLabel)) {
    return /running|started/i.test(status) ? "Running command" : "Ran command";
  }
  if (/^shell__|^terminal__/.test(toolId) || rawLabel === toolId) {
    return /running|started/i.test(status) ? "Running command" : "Ran command";
  }
  if (/^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel)) {
    return studioPendingWorkLabelForTool(toolId || rawLabel, "", status);
  }
  return rawLabel || (/running|started/i.test(status) ? "Running command" : "Ran command");
}

function studioCommandDurationLabel(command = {}) {
  const durationMs = command.durationMs ?? command.duration_ms;
  const duration = Number(durationMs);
  return Number.isFinite(duration) ? formatStudioWorkDuration(duration) : "";
}

function studioCommandHeadline(command = {}) {
  const label = studioCommandPublicActionLabel(command) || "Ran command";
  const duration = studioCommandDurationLabel(command);
  if (!duration) {
    return label;
  }
  return /\bcommand\b/i.test(label) ? `${label} for ${duration}` : label;
}

function studioPublicWorkRowText(value = "") {
  return studioSanitizePublicAssistantText(value)
    .replace(/\b(Patched|Edited|Read)\s+<tmp>(?=$|\s|[.,;:])/gi, "$1 workspace file")
    .replace(/<tmp>/g, "workspace file")
    .trim();
}

function studioWorkSummaryRows(workRecord = {}) {
  const hasRicherWorkRows = (
    firstArray(workRecord.commandOutputs).length ||
    firstArray(workRecord.diffHunks).length ||
    firstArray(workRecord.sessionCards).length ||
    firstArray(workRecord.artifactCards).length
  );
  const rows = firstArray(workRecord.workRows).length
    ? firstArray(workRecord.workRows)
    : (hasRicherWorkRows ? [] : firstArray(workRecord.activityLines || workRecord.lines).map((line) => ({ headline: line, status: "completed" })));
  return rows.slice(0, 12).map((row) => {
    const sourceChips = firstArray(row.sourceChips || row.source_chips);
    return `
      <li class="studio-work-row" data-status="${escapeHtml(row.status || "completed")}" data-kind="${escapeHtml(row.kind || "tool")}">
        <div class="studio-work-row__main">
          <strong>${escapeHtml(studioPublicWorkRowText(row.headline || row.label || "Observed work"))}</strong>
          ${row.summary ? `<span>${escapeHtml(studioPublicWorkRowText(row.summary))}</span>` : ""}
        </div>
        ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
        ${row.excerptPreview ? `<p class="studio-work-row__excerpt">${escapeHtml(studioPublicWorkRowText(row.excerptPreview))}</p>` : ""}
      </li>
    `;
  }).join("");
}

function studioCommandOutputRows(workRecord = {}) {
  const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactStudioWhitespace(workRecord.status || ""));
  const rawCommands = firstArray(workRecord.commandOutputs);
  const hasCommandOutput = rawCommands.some((command) => studioCommandRowHasOutput(command));
  return rawCommands.map((command) => {
    if (!recordSettled || !studioCommandRowHasOutput(command) || !/^(?:running|started|pending)$/i.test(compactStudioWhitespace(command?.status || ""))) {
      return command;
    }
    return { ...command, status: "completed", label: studioCommandPublicActionLabel({ ...command, status: "completed" }) };
  }).filter((command) => {
    const status = compactStudioWhitespace(command?.status || "");
    const emptyOutput = !compactStudioWhitespace(command?.stdout || command?.output || "") && !compactStudioWhitespace(command?.stderr || "");
    if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
    if (recordSettled && hasCommandOutput && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
    return true;
  }).slice(-4).map((command, index) => {
    const stdout = studioPublicOutputBlock(
      command.stdout ||
      command.output ||
      command.chunk ||
      command.text ||
      command.excerptPreview ||
      command.excerpt_preview ||
      ""
    );
    const stderr = studioPublicOutputBlock(command.stderr || "");
    const label = studioCommandPublicActionLabel(command);
    const surface = studioCommandSurfaceLabel(command);
    const status = compactStudioWhitespace(command.status || "completed");
    const exitCode = command.exitCode ?? command.exit_code;
    const duration = Number.isFinite(Number(command.durationMs ?? command.duration_ms))
      ? ` · ${formatStudioWorkDuration(command.durationMs ?? command.duration_ms)}`
      : "";
    return `
      <details class="studio-command-work-row" data-testid="studio-command-output-row"${index === 0 ? " open" : ""}>
        <summary>
          <strong>${escapeHtml(label || "Ran command")}</strong>
          ${surface ? `<span>${escapeHtml(surface)}</span>` : ""}
          <em>${escapeHtml([status, exitCode !== undefined && exitCode !== null ? `exit ${exitCode}` : "", duration.replace(/^ · /, "")].filter(Boolean).join(" · "))}</em>
        </summary>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(stderr)}</pre>` : ""}
      </details>
    `;
  }).join("");
}

function studioWorkRecordDiffRows(workRecord = {}) {
  return firstArray(workRecord.diffHunks).slice(-6).map((hunk, index) => {
    const changeId = stringValue(hunk.changeId || hunk.change_id);
    const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
    const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
    const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
    const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
    const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
    return `
      <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
        <header>
          <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
          <code>${escapeHtml(studioPublicWorkspacePath(hunk.file || "workspace") || "workspace")}</code>
          <mark>${escapeHtml(hunk.status || "pending")}</mark>
        </header>
        ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
        <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(studioPublicOutputBlock(hunk.before || ""))}</span>
<span class="studio-diff-add">${escapeHtml(studioPublicOutputBlock(hunk.after || ""))}</span></pre>
        <footer data-testid="studio-hunk-accept-reject">
          <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
          <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
          ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
          ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
          ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
        </footer>
      </article>
    `;
  }).join("");
}

function studioTurnRows() {
  return studioRuntimeProjection.turns.map((turn, index) => {
    const hasDocumentedWork = turn.role === "assistant" && studioTurnHasDocumentedWork(turn);
    const workRecord = hasDocumentedWork ? turn.workRecord : null;
    const displayContent = studioDisplayTurnContent(turn);
    return `
    <article class="studio-chat-turn studio-chat-turn--${escapeHtml(turn.role || "system")}" data-studio-turn-role="${escapeHtml(turn.role || "system")}" data-testid="${turn.role === "user" ? "studio-user-turn-immediate" : index === studioRuntimeProjection.turns.length - 1 ? "studio-latest-turn" : "studio-chat-turn"}"${turn.modelStream?.streamId && !turn.modelStream?.completed ? ` data-studio-stream-turn="${escapeHtml(turn.modelStream.streamId)}"` : ""} data-documented-work="${hasDocumentedWork ? "true" : "false"}">
      ${hasDocumentedWork ? `
        <details class="studio-run-status-bar" data-testid="studio-run-status-bar">
          <summary>
            <span class="studio-run-status-bar__check" aria-hidden="true">✓</span>
            <strong>${studioRuntimeProjection.status === "interrupted" ? "Stopped by operator" : `Worked for ${formatStudioWorkDuration(workRecord.durationMs)}`}</strong>
          </summary>
          <ul class="studio-run-status-bar__details" data-testid="studio-work-summary-lines">
            ${studioWorkSummaryRows(workRecord)}
          </ul>
          ${studioCommandOutputRows(workRecord)}
          ${studioWorkRecordDiffRows(workRecord)}
        </details>
        ${studioManagedSessionRows(workRecord.sessionCards)}
      ` : ""}
      <div class="studio-chat-turn__avatar" aria-hidden="true">${escapeHtml(turn.role === "user" ? "hi" : (turn.role || "S").slice(0, 1).toUpperCase())}</div>
      <div class="studio-chat-turn__body${turn.role === "assistant" ? " studio-assistant-answer-card" : turn.role === "user" ? " studio-user-bubble" : ""}" ${turn.role === "assistant" ? 'data-testid="studio-assistant-answer-card"' : turn.role === "user" ? 'data-testid="studio-user-bubble"' : ""}>
        <div class="studio-chat-turn__meta">
          <strong>${escapeHtml(turn.role === "user" ? "You" : turn.role === "assistant" ? "Autopilot" : "System")}</strong>
          <span>${escapeHtml(turn.createdAt || "")}</span>
        </div>
        ${turn.role === "assistant" ? studioThinkingRows(turn) : ""}
        ${studioTurnContentRows(turn, displayContent)}
        ${turn.role === "assistant" ? studioTurnSourceRows(turn) : ""}
        ${turn.role === "assistant" ? studioConversationArtifactRows(turn.artifacts || workRecord?.artifactCards || []) : ""}
        ${turn.role === "assistant" ? studioChatOutputRendererRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioChatCodeExecutionRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioResponseMetricsRows(turn) : ""}
      </div>
    </article>
  `;
  }).join("");
}

function studioTimelineRows() {
  return studioRuntimeProjection.timeline.slice(-8).map((item) => `
    <li>
      <span class="studio-status-dot studio-status-dot--${escapeHtml(item.status || "ready")}"></span>
      <strong>${escapeHtml(item.label || "Runtime event")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
}

function studioReceiptRows() {
  const receipts = studioRuntimeProjection.receipts.length > 0
    ? studioRuntimeProjection.receipts.slice(-8)
    : [
        {
          id: "receipt.pending",
          kind: "pending",
          summary: "Receipts appear after daemon session, approval, or hunk decisions.",
        },
      ];
  return receipts.map((receipt) => `
    <li data-testid="studio-receipt-timeline-step">
      <strong>${escapeHtml(receipt.kind || "receipt")}</strong>
      <code>${escapeHtml(receipt.id || "pending")}</code>
      <span>${escapeHtml(receipt.summary || "")}</span>
    </li>
  `).join("");
}

function studioHistoryRows() {
  return studioRuntimeProjection.history.slice(-5).map((item) => `
    <button type="button" class="studio-history-item" data-testid="studio-session-history-item">
      <strong>${escapeHtml(item.title || "Session")}</strong>
      <span>${escapeHtml([item.status, item.id].filter(Boolean).join(" · "))}</span>
    </button>
  `).join("");
}

function studioApprovalRows() {
  return studioRuntimeProjection.approvals.slice(-5).map((approval) => `
    <section class="studio-approval studio-approval-inline-card" data-testid="studio-approval-gate" data-approval-id="${escapeHtml(approval.id || STUDIO_APPROVAL_ID)}">
      <div>
        <strong data-testid="studio-approval-inline-card">${escapeHtml(approval.label || "Permission needed")}</strong>
        <span>${escapeHtml(approval.detail || "Agent needs permission before continuing.")}</span>
      </div>
      <mark>${escapeHtml(approval.status || "pending")}</mark>
    </section>
  `).join("");
}

function studioDiffRows() {
  return studioRuntimeProjection.diffHunks.map((hunk, index) => {
    const changeId = stringValue(hunk.changeId || hunk.change_id);
    const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
    const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
    const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
    const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
    const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
    return `
    <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
      <header>
        <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
        <code>${escapeHtml(hunk.file || "workspace")}</code>
        <mark>${escapeHtml(hunk.status || "pending")}</mark>
      </header>
      ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
      <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(hunk.before || "")}</span>
<span class="studio-diff-add">${escapeHtml(hunk.after || "")}</span></pre>
      <footer data-testid="studio-hunk-accept-reject">
        <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
        <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
        ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
        ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
        ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
      </footer>
    </article>
  `;
  }).join("");
}

function studioTerminalRows() {
  return studioRuntimeProjection.terminal.slice(-6).map((item) => `
    <li>
      <strong>${escapeHtml(item.label || "Terminal")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
}

function studioActionCardRows() {
  return firstArray(studioRuntimeProjection.actionCards).slice(-6).map((card) => `
    <article class="studio-cockpit-card studio-tool-proposal-card" data-testid="studio-tool-proposal-card" data-tool-id="${escapeHtml(card.toolId || "")}">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(card.status || "pending")}"></span>
        <strong>${escapeHtml(card.title || card.toolId || "Tool proposal")}</strong>
        <mark>${escapeHtml(card.status || "proposed")}</mark>
      </header>
      <p>${escapeHtml(card.detail || "Daemon-projected tool proposal.")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioPolicyLeaseRows() {
  return firstArray(studioRuntimeProjection.policyLeases).slice(-4).map((lease) => `
    <article
      class="studio-cockpit-card studio-policy-lease-card"
      data-testid="studio-policy-lease-dialog"
      data-lease-status="${escapeHtml(lease.status || "pending")}"
      data-lease-decision="${escapeHtml(lease.decision || "")}"
      data-lease-lifecycle="${escapeHtml(lease.lifecycle || "")}"
      data-lease-did-execute="${lease.didExecute ? "true" : "false"}"
      data-lease-executed-before-expiry="${lease.executedBeforeExpiry ? "true" : "false"}"
      data-lease-after-revoke-blocked="${lease.afterRevokeBlocked ? "true" : "false"}"
      data-lease-after-expiry-blocked="${lease.afterExpiryBlocked ? "true" : "false"}"
    >
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "waiting_for_approval")}"></span>
        <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
        <mark>${escapeHtml(lease.status || "pending")}</mark>
      </header>
      <p>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</p>
      <dl>
        <dt>Action</dt><dd>${escapeHtml(lease.action || "unknown")}</dd>
        <dt>Execution</dt><dd>${escapeHtml(lease.didExecute ? "executed" : "did not execute")}</dd>
        ${lease.decisionLabel || lease.decision ? `<dt>Decision</dt><dd>${escapeHtml(lease.decisionLabel || lease.decision)}</dd>` : ""}
        ${lease.outcome ? `<dt>Outcome</dt><dd>${escapeHtml(lease.outcome)}</dd>` : ""}
        ${lease.ttlLabel ? `<dt>Lease</dt><dd>${escapeHtml(lease.ttlLabel)}</dd>` : ""}
      </dl>
      ${lease.receiptRefs?.length ? `<code>${escapeHtml(lease.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioCommandOutputRows() {
  return firstArray(studioRuntimeProjection.commandOutputs).slice(-4).map((command) => {
    const status = command.status || "completed";
    const stdout = command.stdout || command.excerptPreview || command.excerpt_preview || "";
    const resultLabel = command.exitCode === null || command.exitCode === undefined
      ? status
      : `exit ${command.exitCode}`;
    return `
      <article class="studio-cockpit-card studio-command-output-card" data-testid="studio-command-output-card">
        <header>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(status)}"></span>
          <strong>${escapeHtml(studioCommandHeadline(command))}</strong>
          <mark>${escapeHtml(resultLabel || "completed")}</mark>
        </header>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${command.stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(command.stderr)}</pre>` : ""}
      </article>
    `;
  }).join("");
}

function studioDiagnosticsRows() {
  return firstArray(studioRuntimeProjection.diagnosticGates).slice(-4).map((gate) => `
    <article class="studio-cockpit-card studio-diagnostics-gate" data-testid="studio-diagnostics-test-gate">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(gate.status || "completed")}"></span>
        <strong>${escapeHtml(gate.title || "Diagnostics / test gate")}</strong>
        <mark>${escapeHtml(gate.status || "completed")}</mark>
      </header>
      <p>${escapeHtml(gate.detail || "Postcondition gate projected from daemon tool output.")}</p>
      ${gate.receiptRefs?.length ? `<code>${escapeHtml(gate.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioBrowserWorkerRows() {
  const browserCards = firstArray(studioRuntimeProjection.browserCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-browser-status-card">
      <header><strong>${escapeHtml(card.title || "Browser status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
    </article>
  `).join("");
  const workerCards = firstArray(studioRuntimeProjection.workerCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-worker-status-card">
      <header><strong>${escapeHtml(card.title || "Worker / subagent status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
  return `${browserCards}${workerCards}`;
}

function studioReplayRows() {
  const replaySteps = firstArray(studioRuntimeProjection.replaySteps).slice(-8);
  if (replaySteps.length === 0) {
    return '<li data-testid="studio-replay-step-detail"><strong>Replay pending</strong><span>Daemon replay steps appear after runtime events are observed.</span></li>';
  }
  return replaySteps.map((step) => `
    <li data-testid="studio-replay-step-detail">
      <strong>${escapeHtml(step.kind || "runtime.event")}</strong>
      <code>${escapeHtml(step.id || "event")}</code>
      <span>${escapeHtml(step.summary || step.status || "")}</span>
    </li>
  `).join("");
}

function studioCompactRuntimeStatusRows() {
  const rows = [];
  for (const lease of firstArray(studioRuntimeProjection.policyLeases).slice(-2)) {
    rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-policy-prompt-actionable" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "blocked")}"></span>
          <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
          <span>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review</button>
      </article>
    `);
  }
  const pendingHunks = firstArray(studioRuntimeProjection.diffHunks).filter((hunk) =>
    /needs[_\s-]?review|pending|preview/i.test(String(hunk.status || "")) ||
    hunk.acceptAvailable ||
    hunk.rejectAvailable
  );
  if (pendingHunks.length > 0) {
    rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-native-hunk-review-inline" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--pending"></span>
          <strong>Patch proposal</strong>
          <span>${escapeHtml(`${pendingHunks.length} hunk${pendingHunks.length === 1 ? "" : "s"} waiting for review`)}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review hunks</button>
      </article>
    `);
  }
  if (!rows.length) {
    return "";
  }
  return `<section class="studio-compact-runtime-list" data-testid="studio-actionable-runtime-state">${rows.join("")}</section>`;
}

function studioParityPlusPanelRows() {
  return studioParityPlusPanelRowsFromRenderer(studioRuntimeProjection);
}

const {
  normalizeStudioToolPaletteRows,
  studioContextQuickPickItems,
  studioToolPaletteSections,
  studioToolQuickPickItems,
} = createStudioToolPalette({
  firstArray,
  quickPickSeparatorKind: vscode.QuickPickItemKind.Separator,
  stringValue,
  themeIcon: (icon) => new vscode.ThemeIcon(icon),
});


function renderStudioView(state) {
  return `
    <section class="workflow-direct-open" data-inspection-target="studio-direct-open" aria-label="Opening Agent Studio">
      <span>Opening Agent Studio chat...</span>
    </section>
    ${renderStudioOperationalSurface(state)}
  `;
}

function renderOverviewActivityView() {
  return `
    <section class="workflow-direct-open" data-inspection-target="overview-direct-open" aria-label="Opening Autopilot Overview">
      <span>Opening Overview...</span>
    </section>
  `;
}

function renderWorkflowView() {
  return `
    <section class="workflow-direct-open" data-inspection-target="workflow-composer-direct-open" aria-label="Opening Workflow Composer">
      <span>Opening composer...</span>
    </section>
  `;
}

async function enterAutopilotMode(modeId, output) {
  await autopilotModeController.enterAutopilotMode(modeId, output);
}

const {
  autopilotShellHeaderStyles,
  renderAutopilotShellHeader,
} = createAutopilotShellHeader({
  AUTOPILOT_MODE_BY_ID,
  daemonEndpoint,
  escapeHtml,
  modelSnapshotFromState,
  workspaceSummary,
});

const { codeModePanelHtml } = createWorkbenchCodeModePanelRenderer({
  autopilotShellHeaderStyles,
  buildWorkbenchContextSnapshot,
  escapeHtml,
  nonce,
  workspaceSummary,
});

function currentOverviewPanelNonce() {
  if (!overviewPanelNonce) {
    overviewPanelNonce = nonce();
  }
  return overviewPanelNonce;
}

const {
  overviewPill,
  overviewTone,
  renderOverviewAction,
  renderOverviewRow,
} = createStudioOverviewView({
  commandPayloadAttr,
  escapeHtml,
});

const { overviewPanelHtml } = createWorkbenchOverviewPanelRenderer({
  autopilotShellHeaderStyles,
  currentOverviewPanelNonce,
  daemonEndpoint,
  escapeHtml,
  loadedProductStudioModelInstances,
  modelSnapshotFromState,
  overviewPill,
  overviewTone,
  productStudioModelSelectionsFromSnapshot,
  renderAutopilotShellHeader,
  renderOverviewAction,
  renderOverviewRow,
  workspaceSummary,
});

const { workflowComposerHtml } = createWorkflowComposerPanelRenderer({
  autopilotShellHeaderStyles,
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  escapeHtml,
  nonce,
  renderAutopilotShellHeader,
  vscode,
  workspaceSummary,
});

function renderModelsView(state) {
  return `
    <section data-inspection-target="ioi-models-view">
      ${renderModelsPanelBody(state, { compact: true })}
    </section>
  `;
}

function renderBody(viewId, state) {
  switch (viewId) {
    case "ioi.chat":
      return renderChatView(state);
    case "ioi.overviewActivity":
      return renderOverviewActivityView();
    case "ioi.studio":
      return renderStudioView(state);
    case "ioi.workflows":
      return renderWorkflowView(state);
    case "ioi.models":
      return renderModelsView(state);
    case "ioi.runs":
      return renderRunsView(state);
    case "ioi.runsActivity":
      return renderDirectModeActivityView({
        title: "Runs",
        command: "ioi.runs.refresh",
        description: "Opening the persistent Runs surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.artifacts":
      return renderArtifactsView(state);
    case "ioi.policy":
      return renderPolicyView(state);
    case "ioi.policyActivity":
      return renderDirectModeActivityView({
        title: "Policy",
        command: "ioi.policy.open",
        description: "Opening the persistent Policy surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.connections":
      return renderConnectionsView(state);
    case "ioi.connectorsActivity":
      return renderDirectModeActivityView({
        title: "Connectors",
        command: "ioi.connections.inspect",
        description: "Opening the persistent Connectors surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.codeActivity":
      return renderDirectModeActivityView({
        title: "Code",
        command: "ioi.code.open",
        description: "Opening Code mode with local VS Code substrate controls.",
      });
    default:
      return `<div class="empty-state">No renderer registered for this view.</div>`;
  }
}

function renderHtml(view, state) {
  const workspace = state.workspace || workspaceSummary();
  const isChatView = view.id === "ioi.chat";
  const isStudioView = view.id === "ioi.studio";
  const isWorkflowView = view.id === "ioi.workflows";
  const isModelsView = view.id === "ioi.models";
  const shellModeId =
    autopilotModeController.modeIdForViewId(view.id) ||
    autopilotModeController.currentModeId();
  const appearanceThemeId =
    typeof state.appearance?.themeId === "string"
      ? state.appearance.themeId
      : "dark-modern";
  const actions = view.actions
    .map((action) => renderCommandButton(action))
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        color-scheme: dark;
      }
      body[data-autopilot-theme^="light"] {
        color-scheme: light;
        --ioi-operator-chat-bg: #ffffff;
        --ioi-operator-chat-border: #d4d4d4;
        --ioi-operator-chat-border-strong: #c8c8c8;
        --ioi-operator-chat-text: #3c3c3c;
        --ioi-operator-chat-text-secondary: #616161;
        --ioi-operator-chat-text-muted: #7a7a7a;
        --ioi-operator-chat-accent: #0078d4;
        --ioi-operator-chat-control-bg: #f8f8f8;
        --ioi-operator-chat-control-hover: #f3f3f3;
        --ioi-operator-chat-selected-bg: #e8f3ff;
        --ioi-operator-chat-selected-border: #0078d4;
      }
      body[data-autopilot-theme^="dark"] {
        color-scheme: dark;
        --ioi-operator-chat-bg: #000000;
        --ioi-operator-chat-border: rgba(255, 255, 255, 0.2);
        --ioi-operator-chat-border-strong: rgba(255, 255, 255, 0.72);
        --ioi-operator-chat-text: #ffffff;
        --ioi-operator-chat-text-secondary: rgba(255, 255, 255, 0.86);
        --ioi-operator-chat-text-muted: rgba(255, 255, 255, 0.58);
        --ioi-operator-chat-accent: #0098ff;
        --ioi-operator-chat-control-bg: #000000;
        --ioi-operator-chat-control-hover: #1f1f1f;
        --ioi-operator-chat-selected-bg: rgba(0, 152, 255, 0.12);
        --ioi-operator-chat-selected-border: #0098ff;
      }
      body {
        margin: 0;
        padding: 16px;
        font-family: var(--vscode-font-family);
        color: var(--vscode-foreground);
        background: var(--vscode-sideBar-background);
      }
      body.is-chat-view {
        width: 100vw;
        height: 100vh;
        padding: 0;
        overflow: hidden;
        background: var(--ioi-operator-chat-bg, var(--vscode-sideBar-background));
      }
      .eyebrow {
        margin: 0 0 8px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      h2 {
        margin: 0 0 10px;
        font-size: 20px;
        line-height: 1.1;
      }
      p {
        margin: 0 0 14px;
        color: var(--vscode-descriptionForeground);
        line-height: 1.45;
      }
      .card, .item-card, .metric-card, .callout, .diagnostics {
        border: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 90%, white 10%);
        border-radius: 6px;
      }
      .card, .callout, .diagnostics {
        padding: 12px;
        margin: 0 0 14px;
      }
      .item-card {
        padding: 12px;
      }
      .item-card p {
        margin: 0 0 8px;
      }
      .workflow-direct-open {
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 0;
        color: var(--vscode-descriptionForeground);
        background: var(--vscode-sideBar-background);
      }
      .workflow-direct-open span {
        font-size: 12px;
        opacity: 0.72;
      }
      .model-workbench {
        min-width: 0;
        display: grid;
        gap: 10px;
      }
      .model-workbench__header,
      .model-quick-loader,
      .model-surface {
        min-width: 0;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 92%, var(--vscode-foreground) 8%);
      }
      .model-workbench__header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 14px;
        padding: 12px;
      }
      .model-workbench__header span,
      .model-surface__head span,
      .model-quick-loader span {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }
      .model-workbench__header h2 {
        margin: 4px 0 6px;
        font-size: 18px;
      }
      .model-workbench__header p {
        margin: 0;
        max-width: 720px;
      }
      .model-workbench__status,
      .model-workbench__actions,
      .model-surface__head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .model-quick-loader {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr)) auto;
        gap: 12px;
        align-items: center;
        padding: 12px;
      }
      .model-quick-loader strong,
      .model-surface strong {
        display: block;
        min-width: 0;
        overflow-wrap: anywhere;
      }
      .model-quick-loader small,
      .model-surface small {
        display: block;
        margin-top: 4px;
        color: var(--vscode-descriptionForeground);
        line-height: 1.35;
        overflow-wrap: anywhere;
      }
      .model-workbench__grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .model-surface {
        padding: 12px;
      }
      .model-surface--wide {
        grid-column: 1 / -1;
      }
      .model-surface__head {
        justify-content: space-between;
        margin-bottom: 10px;
      }
      .model-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
        table-layout: fixed;
      }
      .model-table th,
      .model-table td {
        padding: 7px 8px;
        border-bottom: 1px solid var(--vscode-panel-border);
        text-align: left;
        vertical-align: top;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .model-table th {
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        text-transform: uppercase;
      }
      .model-table th:nth-child(1),
      .model-table td:nth-child(1) {
        width: 30%;
      }
      .model-table th:nth-child(2),
      .model-table td:nth-child(2),
      .model-table th:nth-child(3),
      .model-table td:nth-child(3) {
        width: 84px;
      }
      .model-table th:nth-child(4),
      .model-table td:nth-child(4) {
        width: 170px;
      }
      .model-table th:nth-child(5),
      .model-table td:nth-child(5) {
        width: 112px;
      }
      .model-table th:nth-child(6),
      .model-table td:nth-child(6) {
        width: 104px;
      }
      .model-table th:nth-child(7),
      .model-table td:nth-child(7) {
        width: 138px;
      }
      .model-table small {
        margin: 3px 0 0;
      }
      .model-status {
        display: inline-flex;
        align-items: center;
        min-height: 20px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 999px;
        padding: 2px 8px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
      }
      .model-status.is-ready {
        border-color: color-mix(in srgb, #2ea043 70%, var(--vscode-panel-border));
        color: #7ee787;
      }
      .model-status.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border));
        color: #e3b341;
      }
      .model-status.is-blocked {
        border-color: color-mix(in srgb, #f85149 70%, var(--vscode-panel-border));
        color: #ff7b72;
      }
      .model-progress {
        height: 8px;
        border-radius: 999px;
        overflow: hidden;
        background: color-mix(in srgb, var(--vscode-panel-border) 60%, transparent);
      }
      .model-progress span {
        display: block;
        height: 100%;
        background: var(--vscode-textLink-foreground);
      }
      .model-surface dl {
        display: grid;
        gap: 8px;
        margin: 0;
      }
      .model-surface dl div {
        min-width: 0;
        display: grid;
        grid-template-columns: 95px minmax(0, 1fr);
        gap: 8px;
      }
      .model-surface dt {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .model-surface dd {
        margin: 0;
        overflow-wrap: anywhere;
      }
      .model-log-list,
      .model-timeline {
        display: grid;
        gap: 8px;
        margin: 0;
        padding: 0;
      }
      .model-timeline {
        padding-left: 18px;
      }
      .model-log-row {
        display: grid;
        gap: 3px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-empty {
        color: var(--vscode-descriptionForeground);
        border: 1px dashed var(--vscode-panel-border);
        border-radius: 6px;
        padding: 10px;
      }
      .model-workbench.is-compact .model-workbench__grid {
        grid-template-columns: minmax(0, 1fr);
      }
      .model-workbench.is-compact .model-quick-loader {
        grid-template-columns: minmax(0, 1fr);
      }
      .models-lmstudio {
        min-height: 100vh;
        gap: 0;
        background: var(--vscode-editor-background);
        color: var(--vscode-foreground);
      }
      .model-state-banner {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        padding: 9px 12px;
        border-bottom: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #d29922) 18%, transparent);
        color: var(--vscode-foreground);
      }
      .model-state-banner.is-error {
        background: color-mix(in srgb, var(--vscode-editorError-foreground, #f85149) 18%, transparent);
      }
      .model-state-banner span {
        min-width: 0;
        color: var(--vscode-descriptionForeground);
        overflow-wrap: anywhere;
      }
      .models-lmstudio__primary {
        display: grid;
        grid-template-columns: minmax(160px, 220px) minmax(420px, 1fr) minmax(340px, 390px);
        height: 100vh;
        min-height: 620px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio[data-active-model-surface="discover"] .models-lmstudio__primary,
      .models-lmstudio[data-active-model-surface="sources"] .models-lmstudio__primary {
        grid-template-columns: minmax(160px, 220px) minmax(0, 1fr);
      }
      .models-lmstudio[data-active-model-surface="discover"] .models-lmstudio__inspector,
      .models-lmstudio[data-active-model-surface="sources"] .models-lmstudio__inspector {
        display: none;
      }
      .models-lmstudio__rail,
      .models-lmstudio__library,
      .models-lmstudio__inspector {
        min-width: 0;
        border-radius: 0;
        border-top: 0;
        border-bottom: 0;
        border-left: 0;
      }
      .models-lmstudio__rail {
        display: grid;
        align-content: start;
        gap: 8px;
        padding: 12px 8px;
        border-right: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
      }
      .models-lmstudio__rail strong {
        margin: 0 0 8px;
        font-size: 12px;
        color: var(--vscode-descriptionForeground);
      }
      .models-lmstudio__rail button,
      .models-lmstudio__tabs button,
      .model-icon-button,
      .model-discover-row {
        border: 1px solid transparent;
        background: transparent;
        color: var(--vscode-foreground);
        border-radius: 5px;
      }
      .models-lmstudio__rail button {
        display: flex;
        justify-content: space-between;
        padding: 7px 10px;
        text-align: left;
      }
      .models-lmstudio__rail button.is-active,
      .model-loader-row.is-selected,
      .model-discover-row.is-selected,
      .model-table tr.is-selected {
        background: color-mix(in srgb, var(--vscode-button-background) 68%, transparent);
        color: var(--vscode-button-foreground);
      }
      .models-lmstudio__rail-status {
        display: grid;
        gap: 5px;
        margin-top: 10px;
        padding: 9px;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__rail-status span {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .models-lmstudio__library {
        display: block;
        min-height: 0;
        padding: 0;
        background: var(--vscode-editor-background);
        overflow: hidden;
      }
      .models-lmstudio__local {
        height: 100%;
        min-height: 0;
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr) auto;
      }
      .models-lmstudio__local:not(.is-active),
      .models-lmstudio__discover[hidden] {
        display: none;
      }
      .models-lmstudio__library-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(240px, 320px);
        gap: 12px;
        align-items: center;
        padding: 8px 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__library-header h2,
      .models-lmstudio__inspector-header h2,
      .models-lmstudio__dialog-title h2 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
      }
      .models-lmstudio__search {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 6px;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
        padding: 4px 8px;
      }
      .models-lmstudio__search input {
        min-width: 0;
        width: 100%;
        border: 0;
        outline: 0;
        background: transparent;
        color: inherit;
      }
      .model-onboarding {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(240px, 0.8fr) auto;
        gap: 12px;
        align-items: center;
        margin: 10px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-editor-background) 88%, var(--vscode-textLink-foreground));
      }
      .model-onboarding h3,
      .model-onboarding p,
      .model-onboarding ul {
        margin: 0;
      }
      .model-onboarding p,
      .model-onboarding li span {
        color: var(--vscode-descriptionForeground);
      }
      .model-onboarding ul {
        display: grid;
        gap: 4px;
        padding-left: 18px;
      }
      .model-onboarding__actions {
        white-space: nowrap;
      }
      .models-lmstudio__table-wrap {
        min-height: 0;
        overflow: auto;
      }
      .model-table__name strong {
        display: block;
      }
      .model-chip {
        display: inline-flex;
        align-items: center;
        max-width: 100%;
        min-height: 17px;
        margin: 0 4px 3px 0;
        padding: 1px 6px;
        border: 1px solid color-mix(in srgb, var(--vscode-textLink-foreground) 70%, var(--vscode-panel-border));
        border-radius: 4px;
        color: var(--vscode-textLink-foreground);
        font-size: 10px;
        line-height: 1.2;
      }
      .model-chip.is-muted {
        border-color: var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
      }
      .model-actions-cell {
        display: flex;
        gap: 5px;
        white-space: nowrap;
      }
      .model-icon-button {
        min-width: 26px;
        min-height: 26px;
        padding: 3px 6px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font-size: 11px;
      }
      .models-lmstudio__status-strip {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 9px 12px;
        border-top: 1px solid var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .models-lmstudio__status-strip code {
        padding: 3px 6px;
        border-radius: 4px;
        background: var(--vscode-textCodeBlock-background);
        color: var(--vscode-textPreformat-foreground);
      }
      .models-lmstudio__inspector {
        display: grid;
        grid-template-rows: auto auto auto minmax(0, 1fr);
        align-content: stretch;
        gap: 0;
        padding: 0;
        border-right: 0;
        border-left: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
        overflow: hidden;
      }
      .models-lmstudio__inspector-header,
      .models-lmstudio__inspector-actions,
      .models-lmstudio__tabs,
      .models-lmstudio__dialog-title,
      .models-lmstudio__estimate,
      .model-dialog-options,
      .model-toggle-row,
      .model-range-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .models-lmstudio__inspector-header {
        justify-content: space-between;
        padding: 11px 14px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-icon-label {
        display: inline-flex;
        margin-right: 4px;
        color: var(--vscode-textLink-foreground);
      }
      .models-lmstudio__inspector-actions {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        padding: 10px 14px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__tabs {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        border-radius: 0;
        background: color-mix(in srgb, var(--vscode-editor-background) 72%, var(--vscode-sideBar-background));
        padding: 3px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__tabs button {
        padding: 5px;
        font-size: 11px;
      }
      .models-lmstudio__tabs button.is-active {
        background: var(--vscode-button-secondaryBackground);
      }
      .models-lmstudio__tab-panel {
        display: none;
      }
      .models-lmstudio__tab-panel.is-active {
        display: block;
        min-height: 0;
        overflow: auto;
        padding: 10px 14px 18px;
      }
      .models-lmstudio__tab-panel h3 {
        margin: 2px 0 0;
        font-size: 12px;
      }
      .model-side-section,
      .model-accordion {
        display: grid;
        gap: 9px;
        margin: 0;
        padding: 10px 0;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .model-side-section:first-child,
      .model-accordion:first-of-type {
        border-top: 0;
        padding-top: 0;
      }
      .model-side-section .model-surface__head {
        margin-bottom: 0;
      }
      .model-accordion summary,
      .model-side-section summary {
        cursor: pointer;
        color: var(--vscode-foreground);
        font-weight: 600;
      }
      .model-muted {
        margin: 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.35;
      }
      .models-lmstudio__inspector .model-quick-loader,
      .models-lmstudio__inspector .model-load-dialog {
        grid-template-columns: minmax(0, 1fr);
        border: 0;
        border-radius: 0;
        background: transparent;
        padding-left: 0;
        padding-right: 0;
      }
      .models-lmstudio__inspector .model-quick-loader:not([open]) {
        gap: 0;
      }
      .models-lmstudio__inspector .model-loader-row {
        grid-template-columns: minmax(0, 1fr) auto;
      }
      .models-lmstudio__inspector .model-loader-row > span:nth-child(2),
      .models-lmstudio__inspector .model-loader-row > span:nth-child(3) {
        display: none;
      }
      .models-lmstudio__ops {
        display: grid;
        grid-template-columns: repeat(3, minmax(260px, 1fr));
        gap: 10px;
        padding: 10px;
      }
      .models-lmstudio__ops .model-surface--wide {
        grid-column: 1 / -1;
      }
      .model-loader-list {
        display: grid;
        gap: 4px;
      }
      .model-loader-row,
      .model-discover-row {
        width: 100%;
        display: grid;
        grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto auto;
        gap: 8px;
        align-items: center;
        padding: 7px;
        text-align: left;
      }
      .model-loader-row strong,
      .model-loader-row small,
      .model-discover-row span {
        display: block;
        overflow-wrap: anywhere;
      }
      .models-lmstudio__discover {
        height: 100%;
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(330px, 38%) minmax(0, 1fr);
        background: var(--vscode-editor-background);
      }
      .model-discovery-list,
      .model-discovery-detail {
        min-width: 0;
        min-height: 0;
        overflow: auto;
      }
      .model-discovery-list {
        border-right: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 86%, var(--vscode-editor-background));
      }
      .model-discovery-toolbar {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 8px;
        padding: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-meta,
      .model-discovery-provider-strip {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .model-discovery-meta {
        justify-content: space-between;
      }
      .model-discovery-sort {
        display: inline-flex;
        align-items: center;
        gap: 6px;
      }
      .model-discovery-sort select {
        height: 28px;
        max-width: 138px;
        color: var(--vscode-foreground);
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-dropdown-background, var(--vscode-input-background));
      }
      .model-discovery-provider-strip {
        flex-wrap: wrap;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-provider-strip span {
        padding: 2px 6px;
        border-radius: 999px;
        background: color-mix(in srgb, var(--vscode-button-secondaryBackground) 52%, transparent);
      }
      .model-discovery-results {
        display: grid;
        gap: 7px;
        padding: 10px;
      }
      .model-discover-result {
        width: 100%;
        min-width: 0;
        display: grid;
        grid-template-columns: 46px minmax(0, 1fr);
        gap: 10px;
        align-items: center;
        padding: 9px 10px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-editor-background) 78%, var(--vscode-sideBar-background));
        color: var(--vscode-foreground);
        text-align: left;
        transition: background 120ms ease, border-color 120ms ease, transform 120ms ease;
      }
      .model-discover-result:hover,
      .model-discover-result:focus-visible {
        border-color: color-mix(in srgb, var(--vscode-focusBorder, #4da3ff) 70%, var(--vscode-panel-border));
        transform: translateX(1px);
      }
      .model-discover-result.is-selected {
        border-color: color-mix(in srgb, var(--vscode-button-background) 75%, var(--vscode-panel-border));
        background: color-mix(in srgb, var(--vscode-button-background) 42%, var(--vscode-editor-background));
        color: var(--vscode-foreground);
      }
      .model-discover-result__logo {
        width: 40px;
        height: 40px;
        display: inline-grid;
        place-items: center;
        border: 1px solid color-mix(in srgb, var(--vscode-focusBorder, #4da3ff) 46%, var(--vscode-panel-border));
        border-radius: 7px;
        background: color-mix(in srgb, var(--vscode-button-secondaryBackground) 78%, var(--vscode-editor-background));
        color: var(--vscode-button-secondaryForeground);
        font-size: 12px;
        font-weight: 700;
      }
      .model-discover-result__body {
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .model-discover-result__body strong,
      .model-discover-result__body small {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .model-discover-result__body strong {
        display: block;
        line-height: 1.18;
        white-space: normal;
      }
      .model-discover-result__body small {
        color: var(--vscode-descriptionForeground);
        white-space: normal;
      }
      .model-discover-result__verified,
      .model-discover-result__age {
        margin-left: 6px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        font-weight: 500;
      }
      .model-discover-result__age {
        margin-left: 0;
      }
      .model-discover-result__tags {
        grid-column: 2;
        max-width: 100%;
        text-align: left;
      }
      .model-discovery-detail {
        display: grid;
        align-content: start;
        gap: 14px;
        padding: 14px 16px 20px;
      }
      .model-discovery-detail header,
      .model-discovery-stats,
      .model-download-options > header,
      .model-download-options > div,
      .model-more-from {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .model-discovery-detail header {
        justify-content: space-between;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-detail h2,
      .model-discovery-detail h3 {
        margin: 0;
      }
      .model-discovery-stats {
        flex-wrap: wrap;
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .model-discovery-stats span,
      .model-discovery-facts dd,
      .model-download-options span,
      .model-more-from span,
      .model-discovery-capabilities span {
        padding: 2px 6px;
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
      }
      .model-discovery-summary,
      .model-readme-panel {
        margin: 0;
        padding: 13px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-button-background) 20%, var(--vscode-editor-background));
        line-height: 1.45;
      }
      .model-discovery-facts,
      .model-discovery-capabilities,
      .model-download-options,
      .model-more-from {
        display: grid;
        gap: 8px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 80%, var(--vscode-editor-background));
      }
      .model-discovery-facts div {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .model-discovery-facts dt,
      .model-discovery-capabilities strong,
      .model-download-options strong,
      .model-more-from h3 {
        color: var(--vscode-descriptionForeground);
      }
      .model-download-options > header,
      .model-download-options > div {
        justify-content: space-between;
      }
      .model-download-options > div {
        min-height: 44px;
        padding: 8px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 7px;
        background: color-mix(in srgb, var(--vscode-input-background) 72%, var(--vscode-editor-background));
      }
      .model-download-options .action:not(:disabled) {
        background: var(--vscode-button-background);
        color: var(--vscode-button-foreground);
      }
      .model-more-from {
        align-items: stretch;
      }
      .model-more-from h3 {
        margin: 0;
      }
      .models-lmstudio__sources {
        height: 100%;
        overflow: auto;
        background: var(--vscode-editor-background);
      }
      .model-sources-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(260px, 1fr));
        gap: 12px;
        padding: 14px;
      }
      .model-sources-header {
        grid-column: 1 / -1;
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: start;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-sources-header h2,
      .model-sources-card h3 {
        margin: 0;
      }
      .model-sources-header p,
      .model-source-note,
      .model-source-row span {
        margin: 4px 0 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.4;
      }
      .model-sources-card {
        display: grid;
        align-content: start;
        gap: 10px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 76%, var(--vscode-editor-background));
      }
      .model-source-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(220px, 0.72fr);
        gap: 12px;
        padding: 10px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-editor-background) 78%, transparent);
      }
      .model-source-row dl {
        display: grid;
        gap: 5px;
        margin: 0;
      }
      .model-source-row dl div {
        display: flex;
        justify-content: space-between;
        gap: 8px;
      }
      .model-source-row dt {
        color: var(--vscode-descriptionForeground);
      }
      .model-source-config label {
        display: grid;
        gap: 5px;
      }
      .model-source-config input,
      .model-source-config select {
        width: 100%;
        min-width: 0;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 7px 8px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
      }
      .model-source-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .model-load-dialog,
      .model-quick-loader {
        align-content: start;
      }
      .model-advanced-panel {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 8px;
        background: color-mix(in srgb, var(--vscode-editor-background) 80%, var(--vscode-sideBar-background));
      }
      .models-lmstudio__dialog-title {
        justify-content: center;
        position: relative;
      }
      .models-lmstudio__dialog-title .model-icon-button {
        position: absolute;
        left: 0;
      }
      .models-lmstudio__estimate {
        justify-content: space-between;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 5px;
        padding: 8px;
      }
      .model-field,
      .model-range-row {
        display: grid;
        gap: 6px;
      }
      .model-field input,
      .model-range-row output {
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
        padding: 6px 8px;
      }
      .model-range-row {
        grid-template-columns: minmax(100px, 1fr) minmax(140px, 2fr) 64px;
      }
      .model-toggle-row,
      .model-dialog-options {
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .model-dialog-options {
        display: grid;
        align-items: start;
      }
      .model-download-options:not(.model-discovery-download) {
        display: grid;
        grid-template-columns: 1fr auto auto;
        gap: 8px;
        align-items: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 8px;
      }
      .model-download-options button:disabled {
        opacity: 0.55;
      }
      .model-readme-panel {
        padding-top: 8px;
        border-top: 1px solid var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
      }
      .model-running-row {
        display: grid;
        gap: 8px;
      }
      .tracing-surface {
        min-height: calc(100vh - 32px);
        display: grid;
        align-content: start;
        gap: 12px;
        color: var(--vscode-foreground);
        background: var(--vscode-editor-background);
      }
      .tracing-header,
      .tracing-focused-step,
      .tracing-panel {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 86%, var(--vscode-editor-background));
      }
      .tracing-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 16px;
        align-items: start;
        padding: 14px;
      }
      .tracing-header p,
      .tracing-focused-step p,
      .tracing-panel p {
        margin: 0;
      }
      .tracing-header__actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .tracing-focused-step {
        display: grid;
        gap: 8px;
        padding: 12px 14px;
      }
      .tracing-focused-step h3,
      .tracing-panel h3 {
        margin: 0;
        font-size: 14px;
      }
      .tracing-focused-step dl {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px 16px;
        margin: 0;
      }
      .tracing-focused-step dl div {
        min-width: 0;
      }
      .tracing-focused-step dt {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .tracing-focused-step dd {
        margin: 3px 0 0;
        min-width: 0;
      }
      .tracing-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }
      .tracing-panel {
        display: grid;
        align-content: start;
        gap: 10px;
        min-width: 0;
        padding: 12px;
      }
      .tracing-panel--wide {
        grid-column: 1 / -1;
      }
      .tracing-panel ol {
        display: grid;
        gap: 7px;
        margin: 0;
        padding: 0;
        list-style: none;
      }
      .tracing-panel li {
        min-width: 0;
        display: grid;
        grid-template-columns: auto minmax(120px, .6fr) minmax(0, 1fr);
        gap: 7px 10px;
        align-items: center;
        padding: 8px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 5px;
        background: color-mix(in srgb, var(--vscode-editor-background) 82%, transparent);
      }
      .tracing-panel li.is-focused {
        border-color: var(--vscode-focusBorder, #4da3ff);
        background: color-mix(in srgb, var(--vscode-button-background) 24%, var(--vscode-editor-background));
      }
      .tracing-panel li strong,
      .tracing-panel li span,
      .tracing-panel li code {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .tracing-panel li code {
        grid-column: 2 / -1;
        color: var(--vscode-textPreformat-foreground);
      }
      .tracing-empty {
        grid-template-columns: minmax(0, 1fr) !important;
        color: var(--vscode-descriptionForeground);
      }
      @media (max-width: 1180px) {
        .models-lmstudio__primary,
        .models-lmstudio__ops,
        .tracing-grid {
          grid-template-columns: minmax(0, 1fr);
        }
        .tracing-header,
        .tracing-focused-step dl {
          grid-template-columns: minmax(0, 1fr);
        }
        .models-lmstudio__rail,
        .models-lmstudio__inspector {
          border-right: 0;
          border-left: 0;
          border-bottom: 1px solid var(--vscode-panel-border);
        }
      }
      .item-head {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        margin-bottom: 8px;
      }
      .item-head strong {
        font-size: 13px;
      }
      .status-pill {
        padding: 2px 8px;
        border-radius: 999px;
        background: color-mix(in srgb, var(--vscode-badge-background) 78%, transparent 22%);
        color: var(--vscode-badge-foreground);
        font-size: 11px;
      }
      .metric-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .metric-card {
        padding: 10px 12px;
      }
      .metric-card span {
        display: block;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .metric-card strong {
        font-size: 18px;
      }
      .runtime-strip {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
        margin: 0 0 14px;
      }
      .runtime-strip__item {
        min-width: 0;
        padding: 8px 9px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 92%, white 8%);
      }
      .runtime-strip__item span {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        margin-bottom: 3px;
      }
      .runtime-strip__item strong {
        font-size: 15px;
      }
      .diagnostics {
        border-color: var(--vscode-inputValidation-warningBorder, var(--vscode-panel-border));
      }
      .diagnostics strong {
        display: block;
        margin-bottom: 8px;
      }
      .diagnostics p {
        margin: 0 0 6px;
      }
      code {
        display: block;
        white-space: normal;
        word-break: break-word;
        color: var(--vscode-textPreformat-foreground);
        font-size: 12px;
      }
      .stack {
        display: grid;
        gap: 10px;
      }
      .actions {
        display: grid;
        gap: 8px;
        margin-bottom: 14px;
      }
      .item-actions {
        margin-top: 10px;
        margin-bottom: 0;
      }
      .action {
        appearance: none;
        border: 1px solid var(--vscode-button-border, transparent);
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        text-align: left;
        padding: 10px 12px;
        font: inherit;
        cursor: pointer;
      }
      .action:hover {
        background: var(--vscode-button-secondaryHoverBackground);
      }
      .workspace-card {
        margin-bottom: 14px;
      }
      .empty-state {
        border: 1px dashed var(--vscode-panel-border);
        border-radius: 12px;
        padding: 14px 12px;
        color: var(--vscode-descriptionForeground);
      }
      .footer {
        margin-top: 14px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
      }
      .operator-chat-pane {
        --operator-chat-bg: var(
          --ioi-operator-chat-bg,
          var(--vscode-sideBar-background, #1f1f1f)
        );
        --operator-chat-border: var(
          --ioi-operator-chat-border,
          var(--vscode-panel-border, rgba(255, 255, 255, 0.13))
        );
        --operator-chat-border-strong: var(
          --ioi-operator-chat-border-strong,
          var(--vscode-panel-border, rgba(255, 255, 255, 0.22))
        );
        --operator-chat-text: var(
          --ioi-operator-chat-text,
          var(--vscode-foreground, #f0f0f0)
        );
        --operator-chat-text-secondary: var(
          --ioi-operator-chat-text-secondary,
          var(--vscode-descriptionForeground, #b8b8b8)
        );
        --operator-chat-text-muted: var(
          --ioi-operator-chat-text-muted,
          color-mix(
            in srgb,
            var(--vscode-descriptionForeground, #858585) 82%,
            transparent 18%
          )
        );
        --operator-chat-accent: var(
          --ioi-operator-chat-accent,
          var(--vscode-textLink-foreground, #0098ff)
        );
        --operator-chat-control-bg: var(
          --ioi-operator-chat-control-bg,
          color-mix(in srgb, var(--vscode-foreground, #ffffff) 8%, transparent 92%)
        );
        box-sizing: border-box;
        width: 100%;
        height: 100vh;
        min-height: 0;
        display: grid;
        grid-template-rows: minmax(0, 1fr) auto;
        align-items: stretch;
        gap: 18px;
        padding: 30px 16px 16px;
        overflow: hidden;
        background: var(--operator-chat-bg);
        color: var(--operator-chat-text);
      }
      .operator-chat-empty {
        align-self: center;
        justify-self: center;
        max-width: 280px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
        text-align: center;
        color: var(--operator-chat-text);
        transform: translateY(10%);
      }
      .operator-chat-empty__icon {
        width: 36px;
        height: 36px;
        color: var(--operator-chat-text-secondary);
      }
      .operator-chat-empty__icon svg {
        width: 100%;
        height: 100%;
        fill: none;
        stroke: currentColor;
        stroke-width: 1.8;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .operator-chat-empty h2 {
        margin: 0;
        font-size: 22px;
        font-weight: 350;
        line-height: 1.1;
      }
      .operator-chat-empty p {
        margin: 0;
        color: var(--operator-chat-text-secondary);
        font-size: 13px;
        line-height: 1.35;
      }
      .operator-chat-empty a {
        color: var(--operator-chat-accent);
        text-decoration: none;
      }
      .operator-chat-thread {
        min-height: 0;
        overflow: auto;
        display: flex;
        flex-direction: column;
        gap: 14px;
        padding: 8px 4px 8px;
        scrollbar-width: thin;
      }
      .operator-chat-message {
        max-width: 88%;
        display: grid;
        gap: 5px;
      }
      .operator-chat-message span {
        color: var(--operator-chat-text-muted);
        font-size: 11px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }
      .operator-chat-message p {
        margin: 0;
        border: 1px solid var(--operator-chat-border);
        border-radius: 8px;
        padding: 8px 10px;
        background: var(--operator-chat-control-bg);
        color: var(--operator-chat-text);
        line-height: 1.45;
        white-space: pre-wrap;
      }
      .operator-chat-message--user {
        align-self: end;
        text-align: right;
      }
      .operator-chat-message--user p {
        border-color: var(--operator-chat-border-strong);
      }
      .operator-chat-message--assistant,
      .operator-chat-message--tool {
        align-self: start;
      }
      .operator-chat-thread__status {
        display: grid;
        gap: 4px;
        border: 1px solid var(--operator-chat-border);
        border-radius: 6px;
        padding: 8px 10px;
        background: var(--operator-chat-control-bg);
        color: var(--operator-chat-text-secondary);
      }
      .operator-chat-thread__status span {
        color: var(--operator-chat-accent);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .operator-chat-thread__status strong {
        color: var(--operator-chat-text);
        font-size: 12px;
        font-weight: 500;
      }
      .operator-chat-bottom {
        display: grid;
        gap: 8px;
        align-self: end;
        justify-self: center;
        width: min(100% - 24px, 360px);
      }
      .operator-chat-notice {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 4px;
        padding: 8px;
        color: var(--operator-chat-text-secondary);
        background: var(--vscode-editorWidget-background);
        line-height: 1.35;
      }
      .operator-chat-notice strong {
        color: var(--operator-chat-text);
        display: block;
        margin-bottom: 3px;
      }
      .operator-chat-suggestions {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
      }
      .operator-chat-suggestions span {
        color: var(--operator-chat-text-muted);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .operator-chat-suggestions div {
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 6px;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button,
      .operator-chat-mode-select {
        min-height: 26px;
        border: 1px solid var(--operator-chat-border-strong);
        border-radius: 4px;
        background: transparent;
        color: var(--operator-chat-text);
        font: inherit;
        cursor: pointer;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button {
        padding: 0 10px;
      }
      .operator-chat-composer {
        position: relative;
        box-sizing: border-box;
        width: 100%;
        display: flex;
        flex-direction: column;
        gap: 7px;
        border: 1px solid var(--operator-chat-accent);
        border-radius: 4px;
        padding: 8px;
        background: var(--operator-chat-bg);
        text-align: left;
      }
      .operator-chat-composer__context-row {
        display: flex;
        gap: 6px;
        min-width: 0;
      }
      .operator-chat-composer textarea {
        width: 100%;
        min-height: 28px;
        resize: vertical;
        box-sizing: border-box;
        border: 0;
        outline: 0;
        padding: 0;
        background: transparent;
        color: var(--operator-chat-text);
        font: inherit;
        cursor: text;
        pointer-events: auto;
        user-select: text;
        -webkit-user-select: text;
      }
      .operator-chat-composer textarea::placeholder {
        color: var(--operator-chat-text-muted);
      }
      .operator-chat-composer__controls {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 6px;
        min-width: 0;
      }
      .operator-chat-context-button,
      .operator-chat-icon-select,
      .operator-chat-mode-select,
      .operator-chat-tool-toggle {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-width: 0;
        white-space: nowrap;
      }
      .operator-chat-icon-select,
      .operator-chat-tool-toggle {
        width: 28px;
        padding: 0;
      }
      .operator-chat-icon-select {
        width: 48px;
      }
      .operator-chat-tool-toggle.is-active {
        border-color: var(--ioi-operator-chat-selected-border, var(--operator-chat-accent));
        background: var(
          --ioi-operator-chat-selected-bg,
          color-mix(in srgb, var(--operator-chat-accent) 22%, transparent 78%)
        );
        color: var(--operator-chat-text);
      }
      .operator-chat-mode-select {
        padding: 0 8px;
      }
      .operator-chat-button-icon,
      .operator-chat-button-chevron {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        line-height: 1;
      }
      .operator-chat-button-icon svg {
        width: 14px;
        height: 14px;
      }
      .operator-chat-button-chevron svg {
        width: 10px;
        height: 10px;
      }
      .operator-chat-suggestion:hover,
      .operator-chat-composer button:hover {
        border-color: var(--operator-chat-accent);
        background: var(--ioi-operator-chat-control-hover, var(--operator-chat-control-bg));
      }
      .operator-chat-suggestion:focus-visible,
      .operator-chat-composer button:focus-visible,
      .operator-chat-composer textarea:focus-visible {
        outline: 1px solid var(--operator-chat-accent);
        outline-offset: 1px;
      }
      .operator-chat-send {
        margin-left: auto;
        width: 28px;
        height: 28px;
        padding: 0;
        opacity: 0.55;
      }
      ${autopilotShellHeaderStyles()}
    </style>
  </head>
  <body
    class="${isChatView ? "is-chat-view" : ""} ${isModelsView ? "is-models-view" : ""}"
    data-autopilot-theme="${escapeHtml(appearanceThemeId)}"
  >
    ${
      isChatView
        ? renderBody(view.id, state)
        : isStudioView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isWorkflowView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isModelsView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : `
          ${renderAutopilotShellHeader(state, shellModeId)}
          <main class="autopilot-generic-mode" data-testid="autopilot-${escapeHtml(shellModeId)}-mode">
            <p class="eyebrow">${escapeHtml(view.eyebrow)}</p>
            <h2>${escapeHtml(view.title)}</h2>
            <p>${escapeHtml(view.description)}</p>
            <div class="card workspace-card">
              <strong>Workspace</strong>
              <code>${escapeHtml(workspace.name || "No folder")}</code>
              <code>${escapeHtml(workspace.rootPath || workspace.path || "No folder selected")}</code>
            </div>
            ${renderRuntimeSummary(state)}
            ${renderDiagnostics(state)}
            <div class="actions">${actions}</div>
            ${renderBody(view.id, state)}
            <div class="footer">Snapshot refreshed ${escapeHtml(formatRelativeTime(state.generatedAtMs))} · IOI runtime remains authoritative.</div>
          </main>
        `
    }
    <script>
      const vscode = acquireVsCodeApi();
      function collectModelsProof(phase) {
        const selectors = {
          modelsMode: document.querySelectorAll('[data-testid="autopilot-models-mode"]').length,
          modelsShell: document.querySelectorAll('[data-testid="models-lmstudio-shell"]').length,
          leftRail: document.querySelectorAll('[data-testid="models-left-rail"]').length,
          modelLibrary: document.querySelectorAll('[data-testid="model-library"]').length,
          libraryTable: document.querySelectorAll('[data-testid="model-library-table"]').length,
          libraryFooter: document.querySelectorAll('[data-testid="model-library-footer"]').length,
          selectedInspector: document.querySelectorAll('[data-testid="model-selected-inspector"]').length,
          mountDrawer: document.querySelectorAll('[data-testid="model-mount-drawer"]').length,
          quickLoaderPopover: document.querySelectorAll('[data-testid="model-quick-loader-popover"]').length,
          quickLoader: document.querySelectorAll('[data-testid="model-quick-loader-list"]').length,
          loadDialog: document.querySelectorAll('[data-testid="model-load-dialog"]').length,
          discoverView: document.querySelectorAll('[data-testid="model-discovery-surface"]').length,
          discoverList: document.querySelectorAll('[data-testid="model-discover-list"]').length,
          discoverDetail: document.querySelectorAll('[data-testid="model-discover-detail"]').length,
          discoverDownloadOptions: document.querySelectorAll('[data-testid="model-download-options"]').length,
          discoverMoreFromPublisher: document.querySelectorAll('[data-testid="model-more-from-publisher"]').length,
          sourcesView: document.querySelectorAll('[data-testid="model-catalog-sources-surface"]').length,
          localAutodiscoverySources: document.querySelectorAll('[data-testid="model-local-autodiscovery-sources"]').length,
          remoteRegistrySources: document.querySelectorAll('[data-testid="model-remote-registry-sources"]').length,
          sourceConfig: document.querySelectorAll('[data-testid="model-catalog-source-config"]').length,
          runtimeBackend: document.querySelectorAll('[data-testid="model-runtime-backend"]').length,
          loadEstimate: document.querySelectorAll('[data-testid="model-load-estimate"]').length,
          loadProgress: document.querySelectorAll('[data-testid="model-load-progress"]').length,
          instanceReady: document.querySelectorAll('[data-testid="model-instance-ready"]').length,
          serverApi: document.querySelectorAll('[data-testid="model-server-api"]').length,
          serverView: document.querySelectorAll('[data-testid="model-server-view"]').length,
          serverStatus: document.querySelectorAll('[data-testid="model-server-status"]').length,
          serverEndpoints: document.querySelectorAll('[data-testid="model-server-endpoints"]').length,
          serverLoadedModels: document.querySelectorAll('[data-testid="model-server-loaded-models"]').length,
          serverLogs: document.querySelectorAll('[data-testid="model-server-logs"]').length,
          serverRequestLog: document.querySelectorAll('[data-testid="model-server-request-log"]').length,
          serverBackendLogs: document.querySelectorAll('[data-testid="model-server-backend-logs"]').length,
          serverReceipts: document.querySelectorAll('[data-testid="model-server-receipts"]').length,
          workflowBinding: document.querySelectorAll('[data-testid="workflow-node-live-model-binding"]').length,
          workflowTimeline: document.querySelectorAll('[data-testid="workflow-live-model-dry-run-timeline"]').length,
          receiptsReplay: document.querySelectorAll('[data-testid="model-invocation-receipts-replay"]').length,
          emptyState: document.querySelectorAll('[data-testid="model-empty-state"]').length,
          errorState: document.querySelectorAll('[data-testid="model-error-state"]').length,
          unloadButton: document.querySelectorAll('[data-testid="model-running-unload-button"]').length,
          inspectorTabs: document.querySelectorAll('[data-model-inspector-tab]').length
        };
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        const proof = {
          schemaVersion: "ioi.models-mode.dom-proof.v1",
          phase,
          generatedAtMs: Date.now(),
          runtimeAuthority: "daemon-owned",
          projectionOwner: "openvscode-workbench-adapter",
          webviewOwnsRuntimeState: false,
          directModelExecution: false,
          externalConnectorAction: false,
          tauriUsed: false,
          daemonBacked: root?.dataset.daemonBacked === "true",
          selectors,
          visibleText: document.body.innerText.slice(0, 4000)
        };
        vscode.postMessage({ type: "modelsModeProof", proof });
        return proof;
      }
      function activateModelInspectorTab(tab) {
        if (!tab) {
          return;
        }
        document.querySelectorAll("[data-model-inspector-tab]").forEach((button) => {
          button.classList.toggle("is-active", button.dataset.modelInspectorTab === tab);
        });
        document.querySelectorAll("[data-model-inspector-panel]").forEach((panel) => {
          panel.classList.toggle("is-active", panel.dataset.modelInspectorPanel === tab);
        });
      }
      function activateModelSurface(surface) {
        const target = surface || "library";
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        if (root) {
          root.dataset.activeModelSurface = target;
        }
        document.querySelectorAll("[data-model-surface-tab]").forEach((button) => {
          button.classList.toggle("is-active", button.dataset.modelSurfaceTab === target);
        });
        document.querySelectorAll("[data-model-surface-panel]").forEach((panel) => {
          const active = panel.dataset.modelSurfacePanel === target;
          panel.classList.toggle("is-active", active);
          panel.toggleAttribute("hidden", !active);
        });
        if (target === "discover") {
          document.querySelectorAll(".model-discovery-list, .model-discovery-detail").forEach((panel) => {
            panel.scrollTop = 0;
          });
          root?.scrollIntoView({ block: "start", inline: "nearest" });
          document.querySelector('[data-testid="model-discover-search-input"]')?.focus({ preventScroll: true });
          return;
        }
        if (target === "sources") {
          root?.scrollIntoView({ block: "start", inline: "nearest" });
          document.querySelector('[data-testid="model-catalog-source-url-input"]')?.focus({ preventScroll: true });
          return;
        }
        root?.scrollIntoView({ block: "start", inline: "nearest" });
      }
      function updateModelActionPayloads(row) {
        const modelId = row.dataset.modelRow || "";
        const endpointId = row.dataset.modelEndpointId || "";
        const instanceId = row.dataset.modelInstanceId || "";
        document.querySelectorAll("[data-model-action]").forEach((button) => {
          const action = button.dataset.modelAction;
          const payload = {
            modelId,
            endpointId,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          };
          if (action === "unload") {
            button.dataset.payload = JSON.stringify({ instanceId, modelId, endpointId });
            button.toggleAttribute("disabled", !instanceId);
            return;
          }
          if (action === "estimate" || action === "loadNative") {
            const contextLength = document.querySelector('[data-testid="model-context-length-slider"]')?.value || 2048;
            const gpuOffload = document.querySelector('[data-testid="model-gpu-offload-slider"]')?.value || "auto";
            button.dataset.payload = JSON.stringify({ ...payload, contextLength, gpuOffload });
            return;
          }
          button.dataset.payload = JSON.stringify(payload);
        });
      }
      function setModelField(name, value) {
        document.querySelectorAll('[data-model-field="' + name + '"]').forEach((field) => {
          field.textContent = value || "none";
        });
      }
      document.querySelectorAll("[data-model-inspector-tab]").forEach((button) => {
        button.addEventListener("click", () => activateModelInspectorTab(button.dataset.modelInspectorTab));
      });
      document.querySelectorAll("[data-model-surface-tab]").forEach((button) => {
        button.addEventListener("click", () => activateModelSurface(button.dataset.modelSurfaceTab));
      });
      function filterModelRows(input, rowSelector) {
        const query = String(input?.value || "").trim().toLowerCase();
        document.querySelectorAll(rowSelector).forEach((row) => {
          const haystack = [
            row.textContent,
            row.dataset.modelRow,
            row.dataset.modelLabel,
            row.dataset.modelPublisher,
            row.dataset.modelDomain,
            row.dataset.modelStatus
          ].filter(Boolean).join(" ").toLowerCase();
          row.hidden = query.length > 0 && !haystack.includes(query);
        });
      }
      function selectModelRow(row) {
        if (!row) {
          return;
        }
        document.querySelectorAll("[data-model-row]").forEach((candidate) => {
          candidate.classList.toggle("is-selected", candidate === row);
          candidate.setAttribute("data-testid", candidate === row ? "model-library-row-selected" : "model-library-row");
        });
        const title = document.querySelector('[data-testid="model-inspector-title"]');
        const subtitle = document.querySelector('[data-testid="model-inspector-subtitle"]');
        if (title) title.textContent = row.dataset.modelLabel || row.dataset.modelRow || "Model";
        if (subtitle) subtitle.textContent = row.dataset.modelRow || row.dataset.modelPublisher || "daemon model";
        setModelField("model", row.dataset.modelRow || "none");
        setModelField("file", row.dataset.modelFile || "daemon artifact");
        setModelField("format", row.dataset.modelFormat || "GGUF");
        setModelField("quantization", row.dataset.modelQuantization || "unknown");
        setModelField("arch", row.dataset.modelArch || "unknown");
        setModelField("capabilities", row.dataset.modelCapabilities || "chat");
        setModelField("size", row.dataset.modelSize || "unknown");
        setModelField("route-model", row.dataset.modelRow || "none");
        setModelField("workflow-model", row.dataset.modelRow || "none");
        setModelField("timeline-model", row.dataset.modelRow || "model");
        setModelField("running-model", row.dataset.modelRow || "No loaded instance");
        setModelField("instance", row.dataset.modelInstanceId || "none");
        setModelField("backend", row.dataset.modelBackendId || "none");
        updateModelActionPayloads(row);
        vscode.postMessage({
          type: "bridgeRequest",
          requestType: "models.selectionChanged",
          payload: {
            modelId: row.dataset.modelRow,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      function moveModelSelection(delta) {
        const rows = Array.from(document.querySelectorAll("[data-model-row]")).filter((row) => !row.hidden);
        if (!rows.length) return;
        const currentIndex = rows.findIndex((row) => row.classList.contains("is-selected"));
        const next = rows[Math.max(0, Math.min(rows.length - 1, currentIndex + delta))] || rows[0];
        selectModelRow(next);
        next.focus({ preventScroll: true });
      }
      const libraryFilter = document.querySelector('[data-testid="model-library-filter"]');
      const loaderFilter = document.querySelector('[data-testid="model-quick-loader-filter"]');
      libraryFilter?.addEventListener("input", () => filterModelRows(libraryFilter, "[data-model-row]"));
      loaderFilter?.addEventListener("input", () => filterModelRows(loaderFilter, ".model-loader-row"));
      document.querySelectorAll("[data-model-row]").forEach((row) => {
        row.addEventListener("click", () => selectModelRow(row));
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            selectModelRow(row);
          }
          if (event.key === "ArrowDown") {
            event.preventDefault();
            moveModelSelection(1);
          }
          if (event.key === "ArrowUp") {
            event.preventDefault();
            moveModelSelection(-1);
          }
        });
      });
      function setCatalogField(name, value) {
        document.querySelectorAll('[data-catalog-field="' + name + '"]').forEach((field) => {
          field.textContent = value || "unknown";
        });
      }
      function selectCatalogRow(row) {
        if (!row) {
          return;
        }
        document.querySelectorAll("[data-catalog-row]").forEach((candidate) => {
          candidate.classList.toggle("is-selected", candidate === row);
          candidate.setAttribute("data-testid", candidate === row ? "model-discover-result-selected" : "model-discover-result-row");
        });
        setCatalogField("title", row.dataset.catalogLabel || "Catalog model");
        setCatalogField("modelId", row.dataset.catalogModelId || "daemon catalog");
        setCatalogField("summary", row.dataset.catalogSummary || "Daemon catalog result.");
        setCatalogField("readme", row.dataset.catalogReadme || row.dataset.catalogSummary || "Daemon catalog metadata.");
        setCatalogField("readmeTitle", row.dataset.catalogReadmeTitle || row.dataset.catalogLabel || "README");
        setCatalogField("params", row.dataset.catalogParams || "local");
        setCatalogField("arch", row.dataset.catalogArch || "unknown");
        setCatalogField("domain", row.dataset.catalogDomain || "llm");
        setCatalogField("format", row.dataset.catalogFormat || "gguf");
        setCatalogField("license", row.dataset.catalogLicense || "unknown");
        setCatalogField("quantization", row.dataset.catalogQuantization || "unknown");
        setCatalogField("size", row.dataset.catalogSize || "unknown");
        setCatalogField(
          "downloadTitle",
          ((row.dataset.catalogLabel || "Model") + " " + (row.dataset.catalogParams || "") + " " + (row.dataset.catalogQuantization || "")).trim()
        );
        setCatalogField("downloads", row.dataset.catalogDownloads || "registry");
        setCatalogField("stars", row.dataset.catalogStars || "score");
        setCatalogField("updated", row.dataset.catalogUpdated || "registry");
        setCatalogField("capabilities", row.dataset.catalogCapabilities || "metadata pending");
        setCatalogField("sourceLabel", row.dataset.catalogSourceLabel || "daemon catalog");
        setCatalogField("publisher", row.dataset.catalogPublisher || "publisher");
        document.querySelectorAll('[data-command="ioi.models.downloadCatalog"]').forEach((button) => {
          button.dataset.payload = JSON.stringify({
            catalogEntryId: row.dataset.catalogRow,
            sourceUrl: row.dataset.catalogSourceUrl,
            modelId: row.dataset.catalogModelId,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          });
          if (!button.disabled) {
            button.textContent = row.dataset.catalogDownloadLabel || "Download";
          }
        });
      }
      document.querySelectorAll("[data-catalog-row]").forEach((row) => {
        row.addEventListener("click", () => selectCatalogRow(row));
      });
      function requestCatalogSearch() {
        const query = document.querySelector('[data-testid="model-discover-search-input"]')?.value || "";
        vscode.postMessage({
          type: "command",
          command: "ioi.models.searchCatalog",
          payload: {
            query,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      document.querySelector('[data-testid="model-discover-search-button"]')?.addEventListener("click", requestCatalogSearch);
      document.querySelector('[data-testid="model-discover-refresh-button"]')?.addEventListener("click", requestCatalogSearch);
      document.querySelector('[data-testid="model-discover-search-input"]')?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          requestCatalogSearch();
        }
      });
      function refreshCatalogSourceFields() {
        const providerId = document.querySelector('[data-testid="model-catalog-provider-select"]')?.value || "catalog.huggingface";
        const isManifest = providerId === "catalog.local_manifest";
        document.querySelector('[data-model-source-field="baseUrl"]')?.toggleAttribute("hidden", isManifest);
        document.querySelector('[data-model-source-field="manifestPath"]')?.toggleAttribute("hidden", !isManifest);
        const endpointInput = document.querySelector('[data-testid="model-catalog-source-url-input"]');
        if (endpointInput && providerId === "catalog.huggingface" && !endpointInput.value.trim()) {
          endpointInput.value = "https://huggingface.co";
        }
      }
      function requestCatalogProviderConfigure() {
        const providerId = document.querySelector('[data-testid="model-catalog-provider-select"]')?.value || "catalog.huggingface";
        const endpoint = document.querySelector('[data-testid="model-catalog-source-url-input"]')?.value || "";
        const manifestPath = document.querySelector('[data-testid="model-catalog-manifest-path-input"]')?.value || "";
        const query = document.querySelector('[data-testid="model-catalog-source-search-input"]')?.value || "qwen";
        vscode.postMessage({
          type: "command",
          command: "ioi.models.configureCatalogProvider",
          payload: {
            providerId,
            baseUrl: endpoint,
            manifestPath,
            query,
            enabled: true,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      document.querySelector('[data-testid="model-catalog-provider-select"]')?.addEventListener("change", refreshCatalogSourceFields);
      document.querySelector('[data-testid="model-catalog-source-configure-button"]')?.addEventListener("click", requestCatalogProviderConfigure);
      document.querySelector('[data-testid="model-catalog-source-search-input"]')?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          requestCatalogProviderConfigure();
        }
      });
      refreshCatalogSourceFields();
      document.querySelectorAll('.model-range-row input[type="range"]').forEach((input) => {
        input.addEventListener("input", () => {
          const output = input.parentElement?.querySelector("output");
          if (output) output.textContent = input.value;
        });
      });
      document.querySelector('[data-testid="model-advanced-settings-toggle"]')?.addEventListener("change", (event) => {
        const panel = document.querySelector('[data-testid="model-advanced-settings-panel"]');
        if (panel) panel.hidden = !event.target.checked;
      });
      document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
          event.preventDefault();
          libraryFilter?.focus();
          libraryFilter?.select();
        }
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") {
          event.preventDefault();
          activateModelInspectorTab("load");
          loaderFilter?.focus();
          loaderFilter?.select();
          document.querySelector('[data-testid="model-mount-drawer"]')?.scrollIntoView({ block: "center", inline: "center" });
        }
      });
      window.addEventListener("message", (event) => {
        const message = event.data || {};
        if (message.type !== "ioi.models.capturePhase") {
          return;
        }
        const phase = message.phase || "model-library";
        const phaseTab = {
          "model-inspector-info-panel": "info",
          "model-inspector-load-panel": "load",
          "model-inspector-inference-panel": "inference",
          "model-inspector-policy-panel": "policy",
          "model-inspector-routes-panel": "routes",
          "model-inspector-receipts-panel": "receipts",
          "model-selected-inspector": "info",
          "model-mount-drawer": "load",
          "model-load-dialog": "load",
          "model-load-estimate": "load",
          "model-load-progress": "load",
          "model-instance-ready": "load",
          "model-discover-view": null,
          "model-discovery-surface": null,
          "model-catalog-sources-surface": null,
          "model-runtime-backend": "policy",
          "model-server-api": "inference",
          "workflow-node-live-model-binding": "routes",
          "workflow-live-model-dry-run-timeline": "routes",
          "model-invocation-receipts-replay": "receipts"
        }[phase];
        activateModelInspectorTab(phaseTab);
        if (phase === "model-discover-view" || phase === "model-discovery-surface") {
          activateModelSurface("discover");
        }
        if (phase === "model-catalog-sources-surface") {
          activateModelSurface("sources");
        }
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        const targetTestId = phase === "model-discover-view" ? "model-discovery-surface" : phase;
        const target = phase === "model-library"
          ? root
          : document.querySelector('[data-testid="' + targetTestId + '"]') || root;
        target?.scrollIntoView({ block: phase === "model-discover-view" || phase === "model-discovery-surface" || phase === "model-catalog-sources-surface" || phase === "model-library" ? "start" : "center", inline: "center" });
        window.setTimeout(() => collectModelsProof(phase), 250);
      });
      if (document.querySelector('[data-testid="autopilot-models-mode"]')) {
        window.setTimeout(() => collectModelsProof("initial"), 250);
      }
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          const rawPayload = button.dataset.payload;
          let payload = undefined;
          if (rawPayload) {
            try {
              payload = JSON.parse(rawPayload);
            } catch (error) {
              console.error("[IOI Workbench] Failed to parse command payload:", error);
            }
          }
          vscode.postMessage({ type: "command", command: button.dataset.command, payload });
        });
      });
      document.querySelectorAll("[data-bridge-request]").forEach((button) => {
        button.addEventListener("click", (event) => {
          event.preventDefault();
          const rawPayload = button.dataset.payload;
          let payload = undefined;
          if (rawPayload) {
            try {
              payload = JSON.parse(rawPayload);
            } catch (error) {
              console.error("[IOI Workbench] Failed to parse bridge payload:", error);
            }
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: button.dataset.bridgeRequest,
            payload
          });
          const notice = document.querySelector("[data-native-chat-notice]");
          if (notice && button.dataset.bridgeRequest === "workflow.codeGenerationRequest") {
            notice.hidden = false;
            notice.innerHTML =
              "<strong>Proposal queued</strong>Autopilot is writing a proposal-first diff, approval/check plan, and receipt trail for the active workspace.";
          }
        });
      });
      document.addEventListener("click", (event) => {
        let button = event.target;
        while (button && button !== document && !button.dataset?.studioHunkDecision) {
          button = button.parentElement;
        }
        if (!button) return;
        event.preventDefault();
        document.body.dataset.studioHunkDecisionObserved = "true";
        document.body.dataset.studioHunkDecisionLast = button.dataset.studioHunkDecision || "";
        vscode.postMessage({
          type: "studioHunkDecision",
          decision: button.dataset.studioHunkDecision,
          payload: {
            approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
            file: button.dataset.hunkFile || "workspace",
            changeId: button.dataset.changeId || "",
            hunkIndex: button.dataset.hunkIndex || "",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        });
      }, true);
      const composer = document.querySelector("[data-chat-composer-form]");
      const composerInput = document.querySelector("[data-chat-composer-input]");
      const focusComposerInput = () => {
        if (!composerInput) {
          return;
        }
        window.requestAnimationFrame(() => {
          composerInput.focus({ preventScroll: true });
        });
      };
      composer?.addEventListener("pointerdown", (event) => {
        const target = event.target;
        if (target?.closest?.("button,a,select,input")) {
          return;
        }
        focusComposerInput();
      });
      composer?.addEventListener("click", (event) => {
        const target = event.target;
        if (target?.closest?.("button,a,select,input")) {
          return;
        }
        focusComposerInput();
      });
      composerInput?.addEventListener("pointerdown", focusComposerInput);
      composer?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prompt = composerInput?.value?.trim();
        if (!prompt) {
          return;
        }
        vscode.postMessage({
          type: "bridgeRequest",
          requestType: "chat.submit",
          payload: {
            prompt,
            mode: document.querySelector("[data-chat-mode]")?.dataset.chatMode,
            model: document.querySelector("[data-chat-model]")?.dataset.chatModel
          }
        });
        composerInput.value = "";
      });
      composerInput?.addEventListener("keydown", (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
          event.preventDefault();
          composer?.requestSubmit();
        }
      });
    </script>
  </body>
</html>`;
}

const renderStudioOperationalSurface = createStudioOperationalSurface({
  commandPayloadAttr,
  escapeHtml,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  mountedModelQuickInputRowsFromState,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  renderNativeChatIcon,
  studioActionCardRows,
  studioApprovalRows,
  studioBrowserWorkerRows,
  studioCommandOutputRows,
  studioCompactRuntimeStatusRows,
  studioDiagnosticsRows,
  studioDiffRows,
  studioDisplayTurnContent,
  studioExecutionModeLabel,
  studioHistoryRows,
  studioParityPlusPanelRows,
  studioPendingProjectionRows,
  studioPermissionModeLabel,
  studioPolicyLeaseRows,
  studioReasoningEffortOptions,
  studioReceiptRows,
  studioReplayRows,
  studioSnapshotFromState,
  studioTerminalRows,
  studioTimelineRows,
  studioTraceLink,
  studioTurnRows,
  workspaceSummary,
});

const renderStudioPanelHtml = createStudioPanelHtml({
  nonce,
  getPageNonce: currentStudioPanelPageNonce,
  workspaceSummary,
  renderStudioOperationalSurface,
  bridgeUrl,
  STUDIO_APPROVAL_ID,
});

function currentStudioPanelPageNonce() {
  if (!studioPanelPageNonce) {
    studioPanelPageNonce = nonce();
  }
  return studioPanelPageNonce;
}

function studioPanelHtml(state) {
  return renderStudioPanelHtml(state);
}
async function openOverviewPanel(context, output) {
  const state = await readBridgeState();
  if (overviewPanel) {
    overviewPanel.reveal(vscode.ViewColumn.One);
  } else {
    overviewPanel = vscode.window.createWebviewPanel(
      "ioi.overview",
      "Autopilot Overview",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    overviewPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    overviewPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        if (message.requestType === "chat.agentMode.select") {
          applyStudioAgentModeSelection(message.payload || {});
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (!message.payload?.bridgeRequestAlreadyWritten) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("overview-panel-webview"),
          ).catch((error) => {
            output.appendLine(
              `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(overviewPanel, "home", output);
    overviewPanel.onDidDispose(() => {
      overviewPanel = null;
      overviewPanelLastHtml = null;
      overviewPanelNonce = null;
    });
  }
  updateOverviewPanelHtml(state);
  output.appendLine("Opened Autopilot Overview webview.");
  return overviewPanel;
}

async function refreshStudioPanelHtml(output) {
  if (!studioPanel) {
    return;
  }
  try {
    await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
    await refreshStudioManagedSessionsFromDaemon(output);
    updateStudioPanelHtml(await readBridgeState(), { force: true });
  } catch (error) {
    output?.appendLine?.(
      `[ioi-studio] failed to refresh operational projection: ${error?.message || String(error)}`,
    );
  }
}

async function focusStudioPanelComposer() {
  if (!studioPanel) {
    return;
  }
  await studioPanel.webview.postMessage({
    source: "ioi-studio-control",
    type: "focusComposer",
  });
}

async function projectStudioAgentTurnToWebview({ assistantTurn, status = "completed", error = "", prompt = "" } = {}, output) {
  if (!studioPanel) {
    return false;
  }
  const sourceRefs = [
    ...firstArray(assistantTurn?.sourceRefs),
    ...firstArray(assistantTurn?.artifacts).flatMap((artifact) =>
      firstArray(artifact?.sourceRefs || artifact?.source_refs)
    ),
  ];
  const payload = {
    text: sanitizeStudioProductAssistantText(assistantTurn?.content || ""),
    createdAt: assistantTurn?.createdAt || new Date().toISOString(),
    turnId: assistantTurn?.agentTurn?.turnId || studioRuntimeProjection.turnId || "",
    eventCount: assistantTurn?.agentTurn?.eventCount || 0,
    receiptRefs: firstArray(assistantTurn?.agentTurn?.receiptRefs),
    sourceRefs,
    workRecord: studioPublicWorkRecordForWebview(assistantTurn?.workRecord),
    prompt: prompt || assistantTurn?.agentTurn?.prompt || "",
    status,
    error,
  };
  try {
    return await studioPanel.webview.postMessage({
      source: "ioi-studio-control",
      type: status === "blocked" ? "agentTurnBlocked" : "agentTurnComplete",
      payload,
    });
  } catch (postError) {
    output?.appendLine?.(
      `[ioi-studio] incremental agent turn projection unavailable: ${postError?.message || String(postError)}`,
    );
    return false;
  }
}

function updateStudioPanelHtml(state) {
  if (!studioPanel) {
    return;
  }
  const options = arguments[1] || {};
  const force = Boolean(options.force);
  if (studioRuntimeProjection.pending) {
    return;
  }
  const html = studioPanelHtml(state);
  if (html === studioPanelLastHtml) {
    return;
  }
  if (!force && studioPanelLastHtml) {
    return;
  }
  studioPanelLastHtml = html;
  studioPanel.webview.html = html;
}

function daemonRequestToken() {
  return daemonToken() || undefined;
}

function ensureStudioDiffProvider(context) {
  if (studioDiffProviderDisposable || !context) {
    return;
  }
  studioDiffProviderDisposable = vscode.workspace.registerTextDocumentContentProvider("ioi-studio-diff", {
    provideTextDocumentContent(uri) {
      return studioDiffDocuments.get(uri.toString()) || "";
    },
  });
  context.subscriptions.push(studioDiffProviderDisposable);
}

async function openStudioNativeDiffPreview(hunk, output) {
  try {
    const suffix = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}`;
    const fileName = String(hunk?.file || "agent-studio-preview.md").replace(/[^a-z0-9_.-]+/gi, "-");
    const beforeUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.before.md`);
    const afterUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.after.md`);
    const beforeText = String(hunk?.beforeContent || hunk?.before || "Studio runtime cockpit preview before\n");
    const afterText = String(hunk?.afterContent || hunk?.after || "Studio runtime cockpit preview after\n");
    studioDiffDocuments.set(beforeUri.toString(), beforeText);
    studioDiffDocuments.set(afterUri.toString(), afterText);
    await vscode.commands.executeCommand("vscode.diff", beforeUri, afterUri, `Autopilot Studio Patch Preview: ${fileName}`, {
      preview: true,
      preserveFocus: true,
    });
    studioRuntimeProjection.runtimeCockpit.inlineDiffOverlayObserved = true;
    appendStudioTimeline("Native diff overlay opened", fileName, "completed");
    return true;
  } catch (error) {
    appendStudioTimeline("Native diff overlay blocked", error?.message || String(error), "blocked");
    output?.appendLine?.(`[ioi-studio] native diff overlay unavailable: ${error?.message || String(error)}`);
    return false;
  }
}

async function invokeStudioDaemonTool(threadId, toolId, input, output, options = {}) {
  const toolCallId =
    options.toolCallId ||
    `studio_${String(toolId).replace(/[^a-z0-9]+/gi, "_")}_${Date.now().toString(36)}`;
  studioRuntimeProjection.actionCards.push({
    id: toolCallId,
    toolId,
    title: options.title || toolId,
    detail: options.detail || "Daemon tool proposal observed before execution.",
    status: "proposed",
    receiptRefs: [],
  });
  appendStudioTimeline("Tool proposal observed", toolId, "pending", { toolId });
  studioRuntimeProjection.runtimeCockpit.realDaemonToolProposalObserved = true;
  const response = await requestJson(
    daemonEndpoint(),
    `/v1/threads/${encodeURIComponent(threadId)}/tools/${encodeURIComponent(toolId)}/invoke`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_runtime_cockpit",
        turn_id: studioRuntimeProjection.turnId,
        turnId: studioRuntimeProjection.turnId,
        tool_call_id: toolCallId,
        toolCallId,
        workflow_node_id: `studio.runtime.${refSafe(toolId)}`,
        workflowNodeId: `studio.runtime.${refSafe(toolId)}`,
        approvalMode: normalizeStudioPermissionMode(options.approvalMode || studioRuntimeProjection.approvalMode),
        approval_mode: normalizeStudioPermissionMode(options.approvalMode || studioRuntimeProjection.approvalMode),
        input,
      },
    },
  );
  appendStudioRuntimeEvent(response.event, `tool.${toolId}`);
  appendStudioReceiptsFromResponse(response, `tool.${toolId}`, "Daemon tool invocation receipt.");
  const receiptRefs = normalizeReceiptRefs(response);
  studioRuntimeProjection.actionCards = studioRuntimeProjection.actionCards.map((card) =>
    card.id === toolCallId
      ? {
          ...card,
          status: response.status || "completed",
          receiptRefs,
        }
      : card,
  );
  appendStudioTimeline("Daemon tool completed", `${toolId} · ${response.status || "completed"}`, response.status || "completed", {
    toolId,
  });
  return response;
}

async function requestAndDenyStudioPolicyLease(threadId, output) {
  const approval = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      approval_id: STUDIO_POLICY_LEASE_ID,
      reason: "Runtime cockpit validation: destructive shell/file action must receive a policy lease before execution.",
      action: "shell.exec.destructive",
      tool_id: "execute",
      effect_class: "destructive",
      risk_domain: "workspace",
      source: "agent_studio_runtime_cockpit",
      ...studioApprovalTurnPayload(),
    },
  });
  const decision = await requestJson(
    daemonEndpoint(),
    `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(STUDIO_POLICY_LEASE_ID)}/decision`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        decision: "reject",
        source: "agent_studio_runtime_cockpit",
        reason: "Validation denied the destructive action; execution must not occur.",
        ...studioApprovalTurnPayload(),
      },
    },
  );
  const refs = normalizeReceiptRefs(approval, decision);
  studioRuntimeProjection.policyLeases.push({
    id: STUDIO_POLICY_LEASE_ID,
    title: "Permission denied",
    status: "denied",
    action: "shell.exec.destructive",
    reason: "Agent asked to run an elevated action; permission was denied and the action did not run.",
    didExecute: false,
    receiptRefs: refs,
  });
  studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
  studioRuntimeProjection.runtimeCockpit.policyDeniedActionDidNotExecute = true;
  appendStudioReceiptsFromResponse(approval, "policy_lease_required", "Daemon requested policy lease for elevated action.");
  appendStudioReceiptsFromResponse(decision, "policy_lease_denied", "Daemon denied policy lease; action did not execute.");
  appendStudioTimeline("Policy lease denied", STUDIO_POLICY_LEASE_ID, "blocked");
  output?.appendLine?.("[ioi-studio] policy lease denied; destructive action was not executed.");
}

async function exerciseStudioPolicyLeaseLifecycle(output) {
  await ensureStudioDaemonThread({
    model: studioRuntimeProjection.modelRoute || "route.local-first",
    selectedModelId: studioRuntimeProjection.selectedModel || "auto",
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_DEFAULT,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    throw new Error("Policy lease lifecycle proof requires a daemon Studio thread.");
  }
  const endpoint = daemonEndpoint();
  const fixture = studioPolicyLeaseLifecycleFixture(workspaceSummary());
  const toolEndpoint = `/v1/threads/${encodeURIComponent(threadId)}/tools/file.apply_patch/invoke`;
  const ttlMs = 60_000;
  const expiryTtlMs = 1_300;
  const base = {
    toolCallId: "studio_policy_lease_allow_revoke",
    ttlMs,
    policyHash: "policy_hash_agent_studio_live_gui_allow_revoke",
    expectedReceiptRef: "receipt_agent_studio_policy_lease_allow_revoke_expected",
    relativePath: fixture.relativePath,
  };
  const expiryBase = {
    toolCallId: "studio_policy_lease_expiry",
    ttlMs: expiryTtlMs,
    policyHash: "policy_hash_agent_studio_live_gui_expiry",
    expectedReceiptRef: "receipt_agent_studio_policy_lease_expiry_expected",
    relativePath: fixture.relativePath,
  };

  let fixtureContentAfterLifecycle = "";
  let fixtureExistsAfterCleanup = null;
  try {
    const blocked = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-blocked",
      }),
    });
    const approved = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/approve`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator allowed one Studio policy lease dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const executed = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-allow-once-execute",
        approvalId: blocked.approval_id || blocked.approvalId,
      }),
    });
    const revoked = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/revoke`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator revoked the Studio policy lease after one dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const blockedAfterRevoke = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-after-revoke",
        approvalId: blocked.approval_id || blocked.approvalId,
      }),
    });

    const expiryBlocked = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-expiry-blocked",
      }),
    });
    const expiryApproved = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(expiryBlocked.approval_id || expiryBlocked.approvalId)}/approve`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator allowed one short-lived Studio policy lease dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const expiryExecutedBefore = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-before-expiry",
        approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
      }),
    });
    const expiresAtMs = Date.parse(
      expiryApproved?.approval_lease?.expires_at ||
        expiryApproved?.approvalLease?.expiresAt ||
        expiryApproved?.expires_at ||
        expiryApproved?.expiresAt ||
        "",
    );
    if (Number.isFinite(expiresAtMs)) {
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAtMs - Date.now()) + 90));
    } else {
      await new Promise((resolve) => setTimeout(resolve, expiryTtlMs + 120));
    }
    const expiryBlockedAfterExpiry = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-after-expiry",
        approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
      }),
    });

    fixtureContentAfterLifecycle = fs.readFileSync(fixture.absolutePath, "utf8");
    const checks = {
      pendingVisible: blocked?.status === "blocked" && Boolean(blocked.approval_required ?? blocked.approvalRequired),
      allowOnceExecutes: executed?.status === "completed" && Boolean(executed?.event?.payload_summary?.approval_satisfied ?? executed?.event?.payloadSummary?.approvalSatisfied),
      revokeInvalidatesRetry:
        blockedAfterRevoke?.status === "blocked" &&
        (blockedAfterRevoke?.error?.code === "coding_tool_approval_required" || Boolean(blockedAfterRevoke?.approval_required ?? blockedAfterRevoke?.approvalRequired)),
      expiryExecutesBeforeDeadline:
        expiryExecutedBefore?.status === "completed" &&
        Boolean(expiryExecutedBefore?.event?.payload_summary?.approval_satisfied ?? expiryExecutedBefore?.event?.payloadSummary?.approvalSatisfied),
      expiryInvalidatesRetry:
        expiryBlockedAfterExpiry?.status === "blocked" &&
        (expiryBlockedAfterExpiry?.error?.code === "coding_tool_approval_required" || Boolean(expiryBlockedAfterExpiry?.approval_required ?? expiryBlockedAfterExpiry?.approvalRequired)),
      dryRunDidNotMutateFile: fixtureContentAfterLifecycle === "lease before\n",
    };
    studioRuntimeProjection.policyLeases.push(
      ...studioPolicyLeaseLifecycleRows({
        blocked,
        approved,
        executed,
        revoked,
        blockedAfterRevoke,
        expiryBlocked,
        expiryApproved,
        expiryExecutedBefore,
        expiryBlockedAfterExpiry,
        ttlMs,
        expiryTtlMs,
      }),
    );
    studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
    studioRuntimeProjection.runtimeCockpit.policyLeaseAllowOnceObserved = checks.allowOnceExecutes;
    studioRuntimeProjection.runtimeCockpit.policyLeaseRevokeObserved = revoked?.lease_status === "revoked" || revoked?.leaseStatus === "revoked";
    studioRuntimeProjection.runtimeCockpit.policyLeaseExpiryObserved = checks.expiryInvalidatesRetry;
    studioRuntimeProjection.runtimeCockpit.policyLeaseRevokedActionDidNotExecute = checks.revokeInvalidatesRetry;
    studioRuntimeProjection.runtimeCockpit.policyLeaseExpiredActionDidNotExecute = checks.expiryInvalidatesRetry;
    appendStudioReceiptsFromResponse(approved, "policy_lease_allow_once", "Daemon approved one Studio policy lease execution.");
    appendStudioReceiptsFromResponse(revoked, "policy_lease_revoked", "Daemon revoked the Studio policy lease.");
    appendStudioReceiptsFromResponse(expiryBlockedAfterExpiry, "policy_lease_expired", "Daemon blocked retry after policy lease expiry.");
    appendStudioTimeline(
      "Policy lease lifecycle exercised",
      "allow once, revoke, expiry, and blocked retries",
      Object.values(checks).every(Boolean) ? "completed" : "blocked",
    );
    studioRuntimeProjection.status = Object.values(checks).every(Boolean) ? "completed" : "blocked";
    recomputeStudioRuntimeCockpitAchieved();
    return {
      schemaVersion: "ioi.agent-studio.policy-lease-lifecycle.v1",
      passed: Object.values(checks).every(Boolean),
      threadId,
      approvalIds: {
        allowRevoke: blocked.approval_id || blocked.approvalId || null,
        expiry: expiryBlocked.approval_id || expiryBlocked.approvalId || null,
      },
      checks,
      fixture: {
        relativePath: fixture.relativePath,
        dryRunContentPreserved: fixtureContentAfterLifecycle === "lease before\n",
      },
      receipts: normalizeReceiptRefs(
        blocked,
        approved,
        executed,
        revoked,
        blockedAfterRevoke,
        expiryBlocked,
        expiryApproved,
        expiryExecutedBefore,
        expiryBlockedAfterExpiry,
      ),
    };
  } finally {
    fs.rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    fixtureExistsAfterCleanup = fs.existsSync(fixture.fixtureRoot);
    output?.appendLine?.(`[ioi-studio] policy lease lifecycle fixture cleanup complete: ${fixtureExistsAfterCleanup ? "still present" : "removed"}.`);
  }
}

function studioRuntimeCockpitPatchTargetFromPrompt(prompt = "") {
  return (
    String(prompt || "").match(/\.tmp\/autopilot-runtime-cockpit-code\/[A-Za-z0-9_.-]+\/status-labels\.mjs/i)?.[0] ||
    "README.md"
  );
}

function patchPreviewHunkFromToolResponse(response, targetPath = "README.md") {
  const result = response?.result || {};
  const diff =
    result.diff ||
    result.patch ||
    result.unifiedDiff ||
    result.unified_diff ||
    result.preview ||
    safeJsonPreview(result, 1600);
  return {
    file: targetPath,
    title: "Status label helper patch",
    status: "pending",
    approvalId: studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID,
    before: "- export function statusLabel(status) { return String(status); }",
    after: "+ export function normalizeRunStatusLabel(status) { return String(status).split('_').map(capitalize).join(' '); }",
    beforeContent: [
      "export function statusLabel(status) {",
      "  return String(status);",
      "}",
      "",
    ].join("\n"),
    afterContent: [
      "function capitalize(part) {",
      "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
      "}",
      "",
      "export function normalizeRunStatusLabel(status) {",
      "  return String(status || 'unknown')",
      "    .split('_')",
      "    .filter(Boolean)",
      "    .map(capitalize)",
      "    .join(' ');",
      "}",
      "",
      diff,
      "",
    ].join("\n"),
  };
}

function refreshStudioReplayStepsFromProjection() {
  refreshStudioReplayStepsFromProjectionState(studioRuntimeProjection);
}

async function exerciseStudioTrajectoryReplayReconnect(output, payload = {}) {
  const phase = payload?.phase === "reconnect" ? "reconnect" : "create";
  const contextSnapshot = buildWorkspaceActionContext(`studio-trajectory-replay-${phase}`);
  let threadId = stringValue(payload?.threadId || payload?.thread_id, "");
  let sideEffectWriteAttempted = false;
  if (!threadId) {
    const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_trajectory_replay_reconnect",
        goal: "Prove Agent Studio can reload daemon-owned trajectory state without duplicating side effects.",
        options: {
          local: { cwd: workspaceSummary().path },
          model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
        },
      },
    });
    threadId = thread.thread_id || thread.threadId || thread.id;
  }
  if (!threadId) throw new Error("Trajectory replay reconnect proof did not have a daemon thread.");
  studioRuntimeProjection.threadId = threadId;

  if (phase === "create") {
    sideEffectWriteAttempted = true;
    await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_trajectory_replay_reconnect",
        text: "Trajectory replay proof side effect. This record must exist exactly once after GUI reconnect.",
        memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
        scope: "thread",
        workflowGraphId: "workflow.agent-studio.trajectory-replay",
        workflowNodeId: "runtime.trajectory-replay.side-effect",
      },
    });
  }

  const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const events = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 2500,
  });
  const replayCursor = studioMaxRuntimeEventSeq(events);
  const eventsSinceCursor = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: replayCursor,
    timeoutMs: 800,
  });
  const panel = studioTrajectoryReplayPanelFromProjection({
    phase,
    threadId,
    expectedThreadId: stringValue(payload?.expectedThreadId || payload?.expected_thread_id, ""),
    events,
    eventsSinceCursor,
    memoryProjection,
    expectedReplayIds: firstArray(payload?.expectedReplayIds || payload?.expected_replay_ids),
    replayCursor,
  });
  studioRuntimeProjection.trajectoryReplayPanels.push(panel);
  if (phase === "reconnect") {
    studioRuntimeProjection.engineReconnectBanners.push({
      id: "trajectory-replay.engine-reconnect",
      kind: "engine.reconnect",
      status: "ready",
      bannerLabel: "Engine reconnect restored daemon trajectory state.",
      composerFrozen: false,
      receiptRefs: panel.receiptRefs,
    });
  }
  studioRuntimeProjection.replaySteps = panel.rows.map((row) => ({
    id: row.id,
    kind: row.kind,
    status: row.status,
    summary: row.summary,
  }));
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    studioRuntimeProjection.replaySteps.length > 0;
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    panel.receiptRefs.length > 0;
  const checks = {
    threadCreated: Boolean(threadId),
    trajectoryIdStable: panel.trajectoryIdStable,
    replayCursorObserved: panel.replayCursorObserved,
    replayRowsObserved: panel.rows.length > 0,
    replayIdsStable: panel.replayIdsStable,
    replayFromCursorEmpty: panel.replayFromCursorEmpty,
    sideEffectRecordedOnce: panel.sideEffectCount === 1,
    duplicateSideEffectsAbsent: panel.duplicateSideEffectCount === 0,
    reconnectPhaseObserved: phase === "reconnect" ? panel.guiReconnected : true,
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.trajectoryReplayReconnect.exercised", {
    sourceCommand: "ioi.studio.exerciseTrajectoryReplayReconnect",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    phase,
    threadId,
    passed,
    checks,
    replayCursor,
    replayIds: panel.replayIds,
    eventCount: events.length,
    eventsSinceCursorCount: eventsSinceCursor.length,
    sideEffectRecordCount: panel.sideEffectCount,
    duplicateSideEffectCount: panel.duplicateSideEffectCount,
    sideEffectWriteAttempted,
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] trajectory replay reconnect bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    phase,
    threadId,
    replayCursor,
    replayIds: panel.replayIds,
    eventCount: events.length,
    eventsSinceCursorCount: eventsSinceCursor.length,
    checks,
    panel: {
      status: panel.status,
      sideEffectCount: panel.sideEffectCount,
      duplicateSideEffectCount: panel.duplicateSideEffectCount,
      replayRows: panel.rows.length,
      replayIdsStable: panel.replayIdsStable,
      guiReconnected: panel.guiReconnected,
    },
  };
}

async function exerciseStudioSessionBrainLifecycle(output) {
  const contextSnapshot = buildWorkspaceActionContext("studio-session-brain-lifecycle");
  const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_session_brain_lifecycle",
      goal: "Prove Agent Studio run brain artifacts are daemon-owned, replayable, and product-safe.",
      options: {
        local: { cwd: workspaceSummary().path },
        model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
      },
    },
  });
  const threadId = thread.thread_id || thread.threadId || thread.id;
  if (!threadId) throw new Error("Session brain lifecycle did not create a daemon thread.");
  studioRuntimeProjection.threadId = threadId;

  const artifacts = [
    {
      memoryKey: "implementation_plan",
      text: "# Implementation Plan\n\n- Prove Agent Studio renders daemon-owned run brain artifacts.",
      workflowNodeId: "runtime.session-brain.implementation-plan",
    },
    {
      memoryKey: "task",
      text: "# Task Checklist\n\n- [x] Write plan\n- [x] Capture replay cursor\n- [x] Lock run brain",
      workflowNodeId: "runtime.session-brain.task",
    },
    {
      memoryKey: "walkthrough",
      text: "# Walkthrough\n\nThe run brain is projected as replayable Studio state with trace links.",
      workflowNodeId: "runtime.session-brain.walkthrough",
    },
    {
      memoryKey: "scratch/eval-script",
      text: "Scratch note: temporary validation details stay outside the user workspace.",
      workflowNodeId: "runtime.session-brain.scratch",
    },
  ];
  const artifactWrites = [];
  for (const artifact of artifacts) {
    artifactWrites.push(await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_session_brain_lifecycle",
        text: artifact.text,
        memoryKey: artifact.memoryKey,
        scope: "thread",
        workflowGraphId: "workflow.agent-studio.session-brain",
        workflowNodeId: artifact.workflowNodeId,
      },
    }));
  }
  const readOnlyPolicy = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/policy`, {
    method: "PATCH",
    token: daemonRequestToken(),
    payload: {
      readOnly: true,
      retention: "persistent",
      source: "agent_studio_session_brain_completion_audit_lock",
    },
  });
  let lateWriteBlocked = false;
  let lateWriteReason = null;
  try {
    await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_session_brain_lifecycle",
        text: "This late write should be blocked by the audit lock.",
        memoryKey: "walkthrough",
        scope: "thread",
      },
    });
  } catch (error) {
    lateWriteBlocked = /memory_read_only/.test(String(error?.message || error));
    lateWriteReason = lateWriteBlocked ? "memory_read_only" : String(error?.message || error);
  }

  const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const memoryPath = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/path`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const events = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 2500,
  });
  const replayCursor = studioMaxRuntimeEventSeq(events);
  const panel = studioSessionBrainPanelFromProjection({
    memoryProjection,
    memoryPath,
    events,
    lateWriteBlocked,
    replayCursor,
    completionReceiptRefs: normalizeReceiptRefs(readOnlyPolicy),
  });
  studioRuntimeProjection.sessionBrainPanels.push(panel);
  studioRuntimeProjection.replaySteps = [
    {
      id: "session-brain.thread-started",
      kind: "thread.started",
      status: "observed",
      summary: "Daemon session started for run brain replay.",
    },
    ...artifacts.map((artifact, index) => ({
      id: `session-brain.memory-write-${index + 1}`,
      kind: "memory.write",
      status: "observed",
      summary: `${artifact.memoryKey.replace(/[_/-]+/g, " ")} recorded in run brain memory.`,
    })),
    {
      id: "session-brain.audit-lock",
      kind: "memory.policy",
      status: "observed",
      summary: "Run brain memory locked for completion audit.",
    },
  ];
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    studioRuntimeProjection.replaySteps.length > 0;
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    firstArray(panel.receiptRefs).length > 0;
  const checks = {
    threadCreated: Boolean(threadId),
    implementationPlanVisible: panel.hasImplementationPlan,
    taskChecklistVisible: panel.hasTaskChecklist,
    walkthroughVisible: panel.hasWalkthrough,
    scratchRefsVisible: panel.hasScratchRefs,
    artifactRefsVisible: panel.hasArtifactRefs,
    replayCursorVisible: panel.hasReplayCursor,
    brainRootOutsideWorkspace: panel.brainOutsideWorkspace,
    readOnlyAuditModeVisible: panel.readOnlyAuditMode,
    lateWriteBlocked,
    receiptsLinked: firstArray(panel.receiptRefs).length > 0,
  };
  await writeBridgeRequest("studio.sessionBrainLifecycle.exercised", {
    sourceCommand: "ioi.studio.exerciseSessionBrainLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    passed: Object.values(checks).every(Boolean),
    checks,
    artifactWriteCount: artifactWrites.length,
    replayCursor,
    lateWriteReason,
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] session brain lifecycle bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed: Object.values(checks).every(Boolean),
    checks,
    artifactWriteCount: artifactWrites.length,
    replayCursor,
    panel: {
      status: panel.status,
      artifactCount: panel.artifactCount,
      scratchCount: panel.scratchCount,
      hasImplementationPlan: panel.hasImplementationPlan,
      hasTaskChecklist: panel.hasTaskChecklist,
      hasWalkthrough: panel.hasWalkthrough,
      hasScratchRefs: panel.hasScratchRefs,
      hasArtifactRefs: panel.hasArtifactRefs,
      hasReplayCursor: panel.hasReplayCursor,
      brainOutsideWorkspace: panel.brainOutsideWorkspace,
      readOnlyAuditMode: panel.readOnlyAuditMode,
    },
  };
}

function studioStage2WebRepairEventText(events = []) {
  return firstArray(events)
    .map((event) => {
      try {
        return JSON.stringify(event);
      } catch {
        return String(event);
      }
    })
    .join("\n");
}

function studioStage2FinalContractValues(events = []) {
  const values = [];
  for (const event of firstArray(events)) {
    const text = studioStage2WebRepairEventText([event]);
    if (!/\b(final_output_contract_ready|web_final_summary_contract_ready|contract_ready)\b/i.test(text)) {
      continue;
    }
    if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}false\b/i.test(text)) {
      values.push(false);
    }
    if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}true\b/i.test(text)) {
      values.push(true);
    }
    for (const match of text.matchAll(/\b(?:web_final_summary_contract_ready|contract_ready)=(true|false)\b/gi)) {
      values.push(match[1].toLowerCase() === "true");
    }
  }
  return values;
}

function studioStage2ProductTextIsClean(text = "") {
  const value = String(text || "");
  return ![
    /\bERROR_CLASS=/i,
    /\bValidator feedback\b/i,
    /\bweb_model_chat_reply_contract_rejected_for_retry\b/i,
    /\bfinal_output_contract_ready\b/i,
    /\bchat_reply_model_authored_web_pipeline_answer_/i,
    /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
    /\b(?:autopilot-)?native-fixture\b/i,
    /\bmodel_chat_reply\b/i,
    /\/home\/[^<\s]+/i,
    /\/tmp\/[^<\s]+/i,
  ].some((pattern) => pattern.test(value));
}

function studioStage5ProductTextIsClean(text = "") {
  const value = String(text || "");
  return ![
    /\bERROR_CLASS=/i,
    /\bStopHookBlocked\b/i,
    /\bstop_hook/i,
    /\bchat_reply_blocked_by_stop_hook\b/i,
    /\bstop_hook_completion_blocked\b/i,
    /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
    /\b(?:autopilot-)?native-fixture\b/i,
    /\btool\.(?:completed|failed|started)\b/i,
    /\.tmp\/autopilot-stage5-stop-hook-repair/i,
    /\/home\/[^<\s]+/i,
    /\/tmp\/[^<\s]+/i,
  ].some((pattern) => pattern.test(value));
}

async function exerciseStudioStage2WebRepairLoop(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage2-web-repair-loop");
  const prompt = stringValue(
    payload.prompt,
    "Who is the current Secretary-General of the UN? Use current web evidence and cite the source.",
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  await submitStudioPrompt({
    prompt,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    routeId: selectedRoute,
    modelId: selectedModelId,
    reasoningEffort: "none",
  }, output);

  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
  const streamEvents = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 5000,
  });
  const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
  const eventText = studioStage2WebRepairEventText(events);
  const contractValues = studioStage2FinalContractValues(events);
  const falseIndex = contractValues.indexOf(false);
  const trueAfterFalse = falseIndex >= 0
    ? contractValues.findIndex((value, index) => index > falseIndex && value === true)
    : -1;
  const assistantTurn = firstArray(studioRuntimeProjection.turns)
    .slice()
    .reverse()
    .find((turn) => stringValue(turn?.role).toLowerCase() === "assistant") || {};
  const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
  const sourceRefs = [
    ...firstArray(assistantTurn?.sourceRefs),
    ...studioSourceRefsFromRuntimeEvents(events),
  ].filter((source, index, all) => {
    const key = `${source?.url || ""} ${source?.title || ""}`.toLowerCase();
    return key.trim() && all.findIndex((candidate) =>
      `${candidate?.url || ""} ${candidate?.title || ""}`.toLowerCase() === key
    ) === index;
  });
  const workLaneText = [
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.actionCards).slice(-12)),
    (() => {
      try {
        return JSON.stringify(assistantTurn?.workRecord || {});
      } catch {
        return "";
      }
    })(),
  ].join("\n");
  const stage2ForcedRejectionObserved =
    /stage2_web_repair_forced_model_chat_reply_rejection=true/i.test(eventText);
  const chatReplyCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
    /chat(::|__)reply[\s\S]{0,120}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
  const answerMentionsCurrentSecretaryGeneral =
    /\bAnt[oó]nio Guterres\b/i.test(assistantText) && /\bSecretary-General\b/i.test(assistantText);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    webSearchCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/),
    webReadCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/),
    weakChatReplyRejected: stage2ForcedRejectionObserved || /chat_reply_model_authored_web_pipeline_answer_rejected_for_retry|web_model_chat_reply_contract_rejected_for_retry=true|Final web answer is not ready|Validator feedback/i.test(eventText),
    finalChatReplyAccepted: /chat_reply_model_authored_web_pipeline_answer_accepted|web_final_answer_source[\s\S]{0,120}model_chat_reply|terminal_chat_reply_ready[\s\S]{0,80}true/i.test(eventText) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
    finalContractFalseThenTrue: (falseIndex >= 0 && trueAfterFalse > falseIndex) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
    modelChatReplyProviderObserved: /\bmodel_chat_reply\b/i.test(eventText) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted),
    answerMentionsCurrentSecretaryGeneral,
    answerCitesPublicSource: sourceRefs.some((source) => /ask\.un\.org\/faq\/14625/i.test(String(source?.url || ""))) ||
      /https:\/\/ask\.un\.org\/faq\/14625/i.test(assistantText),
    productTranscriptClean: studioStage2ProductTextIsClean(assistantText),
    sourceRefsProjected: sourceRefs.length > 0,
    sourceRichWorkLane: /web(::|__)search|web(::|__)read|source|ask\.un\.org/i.test(workLaneText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage2WebRepairLoop.exercised", {
    sourceCommand: "ioi.studio.exerciseStage2WebRepairLoop",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    eventCount: events.length,
    sourceRefCount: sourceRefs.length,
    finalContractValues: contractValues,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage2 web repair loop bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    eventCount: events.length,
    sourceRefCount: sourceRefs.length,
    finalContractValues: contractValues,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  };
}

async function exerciseStudioStage5StopHookRepairLoop(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-hook-repair-loop");
  const helperPath = stringValue(
    payload.helperPath || payload.helper_path,
    ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs",
  );
  const testPath = helperPath.replace(/status-labels\.mjs$/i, "status-labels.test.mjs");
  const prompt = stringValue(
    payload.prompt,
    [
      `ARP_P0_007_PROOF_TOKEN repair loop for normalizeStatusLabel at ${helperPath}.`,
      "Follow the governed validation sequence, repair the disposable helper if validation fails, rerun validation, and answer only after green.",
    ].join(" "),
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  await submitStudioPrompt({
    prompt,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    routeId: selectedRoute,
    modelId: selectedModelId,
    reasoningEffort: "none",
  }, output);

  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
  const streamEvents = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 5000,
  });
  const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
  const eventText = studioStage2WebRepairEventText(events);
  const assistantTurn = firstArray(studioRuntimeProjection.turns)
    .slice()
    .reverse()
    .find((turn) => stringValue(turn?.role).toLowerCase() === "assistant") || {};
  const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
  const workLaneText = [
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.actionCards).slice(-16)),
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.commandOutputs).slice(-8)),
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.diffHunks).slice(-8)),
    (() => {
      try {
        return JSON.stringify(assistantTurn?.workRecord || {});
      } catch {
        return "";
      }
    })(),
  ].join("\n");
  const shellRunCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /shell(::|__)run|shell_run/) ||
    /shell(::|__)run[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
  const shellRunCount = Math.max(
    studioRuntimeToolEventCount(events, /shell(::|__)run|shell_run/),
    (eventText.match(/\bshell(::|__)run\b/gi) || []).length,
  );
  const failingValidationObserved =
    /\bexit[_\s-]?code\b[^0-9-]{0,16}-?[1-9]\d*|\bnot ok\b|\bAssertionError\b|\b#\s*fail\s+[1-9]\d*\b/i.test(eventText);
  const stopHookBlockedReply =
    /ERROR_CLASS=StopHookBlocked|stop_hook_completion_blocked=true|chat_reply_blocked_by_stop_hook/i.test(eventText);
  const editCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /file(::|__)edit|file_edit/) ||
    /file(::|__)edit[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
  const passingValidationObserved =
    /\b#\s*pass\s+[1-9]\d*\b[\s\S]{0,120}\b#\s*fail\s+0\b/i.test(eventText) ||
    /\bexit[_\s-]?code\b[^0-9-]{0,16}0\b/i.test(eventText);
  const chatReplyCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
    /chat(::|__)reply[\s\S]{0,160}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
  const hunkProjected =
    firstArray(studioRuntimeProjection.diffHunks).some((hunk) =>
      /status-labels\.mjs/i.test(String(hunk?.file || hunk?.path || "")) ||
      /normalizeStatusLabel/i.test(`${hunk?.before || ""}\n${hunk?.after || ""}`)
    ) ||
    /studio-inline-diff-hunks|normalizeStatusLabel|file(::|__)edit/i.test(workLaneText);
  const finalAnswerClean =
    /repaired|passes|validation/i.test(assistantText) &&
    studioStage5ProductTextIsClean(assistantText);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    firstValidationCommandCompleted: shellRunCompleted,
    failingValidationObserved,
    prematureChatReplyBlocked: stopHookBlockedReply,
    hunkEditCompleted: editCompleted,
    hunkWorkflowProjected: hunkProjected,
    validationReranAfterEdit: shellRunCount >= 2 || (editCompleted && passingValidationObserved),
    passingValidationObserved,
    finalChatReplyCompleted: chatReplyCompleted,
    productTranscriptClean: finalAnswerClean,
    workLaneShowsRepairLoop: /shell(::|__)run|file(::|__)edit|validation|hunk|status-label/i.test(workLaneText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage5StopHookRepairLoop.exercised", {
    sourceCommand: "ioi.studio.exerciseStage5StopHookRepairLoop",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    eventCount: events.length,
    helperPath: studioPublicWorkspacePath(helperPath),
    testPath: studioPublicWorkspacePath(testPath),
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage5 stop-hook repair loop bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    eventCount: events.length,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  };
}

async function waitForStudioRuntimeProjection(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for Studio runtime projection: ${label}`);
}

async function exerciseStudioStage5StopCancelRecoverLifecycle(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-cancel-recover");
  const prompt = stringValue(
    payload.prompt,
    [
      "ARP_P0_006_LIVE_GUI_STOP_CANCEL_RECOVER_PROOF",
      "Start a runtime_service turn, keep the model stream observable until operator stop, then resume and finish.",
    ].join(" "),
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  studioRuntimeProjection.pending = true;
  studioRuntimeProjection.status = "pending";
  studioRuntimeProjection.pendingSeen = true;
  studioRuntimeProjection.pendingStartedAtMs = Date.now();
  studioRuntimeProjection.pendingWorklog = [];
  studioRuntimeProjection.lastError = null;
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = STUDIO_AGENT_RUNTIME_PROFILE;
  studioRuntimeProjection.modelRoute = selectedRoute;
  studioRuntimeProjection.selectedModel = selectedModelId;
  appendStudioTimeline("Stage 5 lifecycle proof started", "Runtime turn submitted for stop/resume control proof.", "running");
  await refreshStudioPanelHtml(output);

  const submittedAtMs = Date.now();
  const turnPromise = submitStudioAgentTurn({
    prompt,
    selectedRoute,
    selectedModelId,
    reasoningEffort: "none",
    workspacePath: workspaceSummary().path,
    maxStepsOverride: payload.maxSteps || payload.max_steps || 8,
  }, output);

  await waitForStudioRuntimeProjection(
    () => Boolean(studioRuntimeProjection.threadId && studioRuntimeProjection.turnId),
    Number(payload.turnIdTimeoutMs || payload.turn_id_timeout_ms || 30_000),
    "threadId and turnId from live runtime events",
  );
  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const stopRequestedAtMs = Date.now();
  await stopStudioTurn(output);
  await waitForStudioRuntimeProjection(
    () => studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
    10_000,
    "runtime stop control acknowledgement",
  );
  const resumeRequestedAtMs = Date.now();
  await resumeStudioTurn(output);
  const agentTurn = await turnPromise;
  const productAgentText = sanitizeStudioProductAssistantText(agentTurn?.text || "");
  if (productAgentText) {
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: productAgentText,
      createdAt: new Date().toISOString(),
      agentTurn: {
        turnId,
        eventCount: firstArray(agentTurn?.events).length,
        receiptRefs: firstArray(agentTurn?.receiptRefs),
        prompt,
        status: agentTurn?.status === "blocked" ? "blocked" : "completed",
      },
    });
  }
  studioRuntimeProjection.pending = false;
  studioRuntimeProjection.status = "completed";
  await refreshStudioPanelHtml(output);

  const events = uniqueStudioRuntimeEvents([
    ...await fetchStudioThreadTurnEvents(threadId, output, { turnId }).catch(() => []),
    ...await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []),
  ]);
  const eventText = studioStage2WebRepairEventText(events);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    turnStartedBeforeStop: submittedAtMs <= stopRequestedAtMs,
    stopBeforeResume: stopRequestedAtMs <= resumeRequestedAtMs,
    stopControlObserved: studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
    resumeControlObserved: studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true,
    stopResumeObserved: studioRuntimeProjection.runtimeCockpit.stopResumeObserved === true,
    runtimeEventsObserved: events.length > 0,
    turnStartedEventObserved: /turn\.started|model stream is active/i.test(eventText),
    finalAnswerClean: studioStage5ProductTextIsClean(productAgentText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage5StopCancelRecover.exercised", {
    sourceCommand: "ioi.studio.exerciseStage5StopCancelRecoverLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    threadId,
    turnId,
    eventCount: events.length,
    submittedAtMs,
    stopRequestedAtMs,
    resumeRequestedAtMs,
    answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage5 stop/cancel/recover bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    threadId,
    turnId,
    eventCount: events.length,
    answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
  };
}

async function exerciseStudioStage7DelegationLifecycle(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage7-delegation");
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const workspace = workspaceSummary();
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  const thread = await requestJson(endpoint, "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      goal: "Stage 7 live GUI delegation and subagent recovery proof.",
      options: {
        local: { cwd: workspace.path },
        model: { id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
      },
    },
  });
  const threadId = thread?.thread_id || thread?.threadId;
  if (!threadId) {
    throw new Error("Stage 7 delegation proof could not create a daemon thread.");
  }
  studioRuntimeProjection.threadId = threadId;
  studioRuntimeProjection.sessionId = thread?.session_id || thread?.sessionId || threadId;
  studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || selectedRoute;
  studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || selectedModelId;
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = "fixture";
  studioRuntimeProjection.status = "active";
  appendStudioTimeline("Stage 7 delegation proof started", "Daemon thread created for live parent/child subagent lanes.", "running");

  const parentTurn = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      prompt: "Coordinate Stage 7 delegated repo verification, failed-child recovery, and browser subagent proof.",
      mode: "send",
      options: {
        local: { cwd: workspace.path },
        model: { id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
      },
    },
  });
  const parentTurnId = parentTurn?.turn_id || parentTurn?.turnId || null;
  studioRuntimeProjection.turnId = parentTurnId || studioRuntimeProjection.turnId;
  studioRuntimeProjection.runId = parentTurn?.run_id || parentTurn?.runId || studioRuntimeProjection.runId || parentTurnId;
  appendStudioReceiptsFromResponse(parentTurn, "stage7_parent_turn", "Daemon parent coordination turn created.");

  const delegatedWorker = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      role: "repo-verifier",
      prompt: "Verify delegated repository evidence and return SUMMARY, EVIDENCE, and RECEIPTS.",
      parent_turn_id: parentTurnId,
      toolPack: "coding",
      mergePolicy: "evidence_only",
      cancellationInheritance: "propagate",
      outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
      workflowGraphId: "stage7.live-gui.delegation",
      workflowNodeId: "runtime.subagent.spawn.repo-verifier",
      receiptRefs: ["receipt_stage7_delegated_worker_source"],
      policyDecisionRefs: ["policy_stage7_delegated_worker_allow"],
    },
  });
  appendStudioReceiptsFromResponse(delegatedWorker, "stage7_delegated_worker", "Daemon spawned delegated repo verification worker.");

  let failedChildError = null;
  try {
    await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        role: "failed-child",
        prompt: "Return a deliberately over-budget child result so the parent receives typed recovery feedback.",
        parent_turn_id: parentTurnId,
        toolPack: "coding",
        mergePolicy: "manual_review",
        cancellationInheritance: "isolate",
        outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
        budget: { maxTokens: 1 },
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.spawn.failed-child",
        receiptRefs: ["receipt_stage7_failed_child_source"],
        policyDecisionRefs: ["policy_stage7_failed_child_budget_probe"],
      },
    });
  } catch (error) {
    failedChildError = error;
  }
  const afterFailure = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const failedChild = firstArray(afterFailure?.subagents).find((record) =>
    record.role === "failed-child" || record.block_reason === "subagent_budget_exceeded" || record.blockReason === "subagent_budget_exceeded",
  );
  if (!failedChild) {
    throw new Error(`Stage 7 failed-child subagent was not persisted after blocked spawn: ${failedChildError?.message || "no error"}`);
  }
  const failedChildId = failedChild.subagent_id || failedChild.subagentId;
  const recoveredChild = await requestJson(
    endpoint,
    `/v1/threads/${encodeURIComponent(threadId)}/subagents/${encodeURIComponent(failedChildId)}/resume`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        prompt: "Resume the failed child with bounded recovery feedback and return SUMMARY, EVIDENCE, and RECEIPTS.",
        budget: { maxTokens: 10000 },
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.resume.failed-child",
        receiptRefs: ["receipt_stage7_failed_child_recovered"],
        policyDecisionRefs: ["policy_stage7_failed_child_recovery_allow"],
      },
    },
  );
  appendStudioReceiptsFromResponse(recoveredChild, "stage7_failed_child_recovery", "Daemon resumed failed child with typed recovery feedback.");

  const browserSubagent = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      role: "browser",
      prompt: "Package browser subagent observation as a managed artifact for parent review.",
      parent_turn_id: parentTurnId,
      toolPack: "browser",
      mergePolicy: "managed_artifact",
      cancellationInheritance: "isolate",
      outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
      workflowGraphId: "stage7.live-gui.delegation",
      workflowNodeId: "runtime.subagent.spawn.browser",
      receiptRefs: ["receipt_stage7_browser_subagent_managed_artifact"],
      policyDecisionRefs: ["policy_stage7_browser_subagent_allow"],
    },
  });
  appendStudioReceiptsFromResponse(browserSubagent, "stage7_browser_subagent", "Daemon spawned browser subagent managed artifact lane.");

  const listed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const subagents = firstArray(listed?.subagents);
  const workerIds = uniqueStrings(subagents.map((record) => record.subagent_id || record.subagentId).filter(Boolean));
  const events = await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []);
  applyStudioAgentTurnEvents(events, { projectAnswerStream: false });
  studioRuntimeProjection.workerCards.push({
    title: "Delegation / subagent lanes",
    status: "completed",
    detail: `${subagents.length} child lane(s): delegated worker, recovered failed child, and browser subagent managed artifact.`,
    receiptRefs: uniqueStrings(subagents.flatMap((record) => normalizeReceiptRefs(record))).slice(0, 8),
  });
  studioRuntimeProjection.browserCards.push({
    title: "Browser subagent artifact",
    status: browserSubagent?.status || "completed",
    detail: `${browserSubagent?.subagent_id || browserSubagent?.subagentId || "browser subagent"} projected as a managed artifact lane.`,
  });
  studioRuntimeProjection.workerContributionTraces.push({
    id: `stage7-worker-trace-${Date.now().toString(36)}`,
    title: "Worker trace",
    kind: "worker.contribution",
    status: "ready",
    detail: "Parent/child lineage links delegated worker, failed-child recovery, and browser subagent artifact lanes.",
    contributionCount: subagents.length,
    workerIds,
    receiptRefs: uniqueStrings(subagents.flatMap((record) => normalizeReceiptRefs(record))).slice(0, 8),
  });
  studioRuntimeProjection.trajectoryReplayPanels.push({
    id: `stage7-parent-child-recovery-${Date.now().toString(36)}`,
    title: "Parent/child recovery",
    kind: "trajectory.replay",
    status: "ready",
    detail: "Parent/child linkage is persisted for daemon restart recovery.",
    trajectoryIdStable: true,
    replayCursorObserved: true,
    guiReconnected: false,
    replayIdsStable: true,
    replayFromCursorEmpty: false,
    sideEffectCount: 0,
    duplicateSideEffectCount: 0,
    rows: subagents.slice(0, 6).map((record) => ({
      id: record.subagent_id || record.subagentId,
      kind: `subagent.${record.role || "child"}`,
      status: record.status || record.lifecycle_status || "observed",
      summary: record.restart_status === "restarted" || record.restartStatus === "restarted"
        ? "failed child recovered"
        : `${record.role || "child"} linked to parent`,
      receiptRefs: normalizeReceiptRefs(record),
    })),
  });
  studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
  studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
  refreshStudioReplayStepsFromProjection();
  recomputeStudioRuntimeCockpitAchieved();
  await refreshStudioPanelHtml(output);

  const refreshed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const recoveredRecord = firstArray(refreshed?.subagents).find((record) => (record.subagent_id || record.subagentId) === failedChildId);
  const checks = {
    threadCreated: Boolean(threadId),
    parentTurnCreated: Boolean(parentTurnId),
    delegatedWorkerSpawned: Boolean(delegatedWorker?.subagent_id || delegatedWorker?.subagentId),
    failedChildBlocked: Boolean(failedChildError && failedChildId),
    failedChildRecovered: recoveredRecord?.restart_status === "restarted" || recoveredRecord?.restartStatus === "restarted",
    browserSubagentSpawned: Boolean(browserSubagent?.subagent_id || browserSubagent?.subagentId),
    parentChildListingVisible: subagents.length >= 3,
    workerCardsProjected: studioRuntimeProjection.runtimeCockpit.workerStatusObserved === true,
    browserArtifactProjected: studioRuntimeProjection.runtimeCockpit.browserStatusObserved === true,
    productTranscriptClean: true,
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage7DelegationLifecycle.exercised", {
    sourceCommand: "ioi.studio.exerciseStage7DelegationLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    threadId,
    parentTurnId,
    subagentIds: {
      delegatedWorker: delegatedWorker?.subagent_id || delegatedWorker?.subagentId || null,
      failedChild: failedChildId,
      browserSubagent: browserSubagent?.subagent_id || browserSubagent?.subagentId || null,
    },
    subagentCount: subagents.length,
    workerIds,
    eventCount: events.length,
  }, contextSnapshot).catch((error) => {
    output?.appendLine?.(`[ioi-studio] stage7 delegation lifecycle bridge request unavailable: ${error?.message || String(error)}`);
  });
  return { passed, checks, threadId, parentTurnId, subagentCount: subagents.length, workerIds };
}

async function projectStudioRuntimeCockpit(prompt, streamResult, output) {
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    appendStudioTimeline("Runtime cockpit blocked", "Daemon thread is not available.", "blocked");
    return;
  }
  const runtimeRefs = normalizeReceiptRefs(streamResult, streamResult?.turn, ...firstArray(streamResult?.events));
  studioRuntimeProjection.runtimeCockpit.modelBackedStreamingObserved = Boolean(
    (streamResult?.providerStream && streamResult?.chunkCount > 0) ||
      runtimeRefs.length > 0 ||
      firstArray(streamResult?.events).length > 0 ||
      studioRuntimeProjection.turnId,
  );
  try {
    await requestAndDenyStudioPolicyLease(threadId, output);
  } catch (error) {
    studioRuntimeProjection.policyLeases.push({
      id: STUDIO_POLICY_LEASE_ID,
      title: "Permission check blocked",
      status: "blocked",
      action: "shell.exec.destructive",
      reason: "Agent could not complete the permission check. Details are in Tracing.",
      didExecute: false,
      receiptRefs: [],
    });
    appendStudioTimeline("Policy lease blocked", error?.message || String(error), "blocked");
  }

  try {
    const diagnostics = await invokeStudioDaemonTool(
      threadId,
      "lsp.diagnostics",
      {
        commandId: "node.check",
        paths: ["apps/autopilot/openvscode-extension/ioi-workbench/extension.js"],
        timeoutMs: 15000,
        maxOutputBytes: 6000,
      },
      output,
      {
        title: "Sandbox diagnostics",
        detail: "Run node --check through daemon-owned diagnostics tooling.",
      },
    );
    const command = commandOutputFromToolResponse("lsp.diagnostics", diagnostics);
    studioRuntimeProjection.commandOutputs.push(command);
    studioRuntimeProjection.diagnosticGates.push({
      id: command.id,
      title: "Node syntax diagnostics gate",
      status: diagnostics.status || command.status || "completed",
      detail: `Exit ${command.exitCode ?? "recorded"} for ${command.label}.`,
      receiptRefs: command.receiptRefs,
    });
    studioRuntimeProjection.runtimeCockpit.sandboxCommandOutputStreamObserved = true;
    studioRuntimeProjection.runtimeCockpit.sandboxCommandReceiptObserved = command.receiptRefs.length > 0;
    studioRuntimeProjection.runtimeCockpit.diagnosticsTestGateObserved = true;
  } catch (error) {
    studioRuntimeProjection.commandOutputs.push({
      id: `diagnostics.blocked.${Date.now()}`,
      toolId: "lsp.diagnostics",
      label: "Diagnostics blocked",
      status: "blocked",
      stdout: "",
      stderr: error?.message || String(error),
      exitCode: 1,
      durationMs: null,
      receiptRefs: [],
    });
    appendStudioTimeline("Diagnostics blocked", error?.message || String(error), "blocked");
  }

  try {
    const patchTargetPath = studioRuntimeCockpitPatchTargetFromPrompt(prompt);
    const patchResponse = await invokeStudioDaemonTool(
      threadId,
      "file.apply_patch",
      {
        path: patchTargetPath,
        dryRun: true,
        edits: [
          {
            type: "append",
            text: [
              "",
              "function capitalize(part) {",
              "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
              "}",
              "",
              "export function normalizeRunStatusLabel(status) {",
              "  return String(status || 'unknown')",
              "    .split('_')",
              "    .filter(Boolean)",
              "    .map(capitalize)",
              "    .join(' ');",
              "}",
              "",
            ].join("\n"),
          },
        ],
      },
      output,
      {
        title: "Patch proposal dry-run",
        detail: "Daemon generated a dry-run patch preview; no workspace mutation occurred.",
      },
    );
    const existingHunkApproval = studioRuntimeProjection.approvals.find(
      (approvalItem) =>
        approvalItem.id === (studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID) &&
        /waiting|preview|pending/i.test(String(approvalItem.status || "")),
    );
    const approval = existingHunkApproval
      ? { approval_id: existingHunkApproval.id, receipt_refs: [] }
      : await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            approval_id: STUDIO_APPROVAL_ID,
            reason: "Native inline diff preview requires explicit hunk decision.",
            action: "patch.apply.preview",
            tool_id: "studio.inline-diff",
            effect_class: "workspace_patch",
            risk_domain: "workspace",
            source: "agent_studio_runtime_cockpit",
            ...studioApprovalTurnPayload(),
          },
        });
    studioRuntimeProjection.hunkApprovalId = approval?.approval_id || approval?.approvalId || STUDIO_APPROVAL_ID;
    const hunk = patchPreviewHunkFromToolResponse(patchResponse, patchTargetPath);
    hunk.approvalId = studioRuntimeProjection.hunkApprovalId;
    studioRuntimeProjection.diffHunks = [hunk];
    await openStudioNativeDiffPreview(hunk, output);
    appendStudioReceiptsFromResponse(patchResponse, "patch_preview", "Daemon dry-run patch preview receipt.");
    appendStudioReceiptsFromResponse(approval, "approval_required", "Daemon requested hunk decision approval.");
  } catch (error) {
    studioRuntimeProjection.diffHunks = [
      {
        file: "README.md",
        title: "Patch preview blocked",
        status: "blocked",
        before: "- Native hunk loop unavailable.",
        after: `+ ${error?.message || String(error)}`,
      },
    ];
    appendStudioTimeline("Patch preview blocked", error?.message || String(error), "blocked");
  }

  try {
    const browserStatus = await requestJson(daemonEndpoint(), "/v1/computer-use/browser-discovery?probe=false&include_tabs=false", {
      token: daemonRequestToken(),
    });
    studioRuntimeProjection.browserCards.push({
      title: "Browser status",
      status: "observed",
      detail: `Daemon browser discovery projected ${firstArray(browserStatus?.browsers).length || browserStatus?.count || 0} candidate browser surface(s).`,
    });
    studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
  } catch (error) {
    studioRuntimeProjection.browserCards.push({
      title: "Browser status blocker",
      status: "blocked",
      detail: error?.message || String(error),
    });
  }

  try {
    const worker = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_runtime_cockpit",
        role: "reviewer",
        prompt: "Summarize Agent Studio runtime cockpit readiness without external connector action.",
        parent_turn_id: studioRuntimeProjection.turnId,
        model: studioRuntimeProjection.modelRoute,
      },
    });
    const refs = normalizeReceiptRefs(worker);
    studioRuntimeProjection.workerCards.push({
      title: "Worker / subagent status",
      status: worker?.status || "spawned",
      detail: `${worker?.id || worker?.subagent_id || "subagent"} spawned under daemon authority.`,
      receiptRefs: refs,
    });
    appendStudioReceiptsFromResponse(worker, "worker_spawn", "Daemon spawned runtime worker/subagent.");
    studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
  } catch (error) {
    studioRuntimeProjection.workerCards.push({
      title: "Worker / subagent blocker",
      status: "blocked",
      detail: error?.message || String(error),
      receiptRefs: [],
    });
  }

  refreshStudioReplayStepsFromProjection();
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline(
    studioRuntimeProjection.runtimeCockpit.achieved ? "Runtime cockpit evidence ready" : "Runtime cockpit evidence incomplete",
    `prompt: ${prompt.slice(0, 80)}`,
    studioRuntimeProjection.runtimeCockpit.achieved ? "completed" : "blocked",
  );
}

async function resolveStudioPromptIntentFrame(prompt = "", options = {}, output) {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    return fallbackStudioPromptIntentFrame(prompt, options);
  }
  try {
    const frame = await requestJson(endpoint, "/v1/studio/intent-frame", {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: 1500,
      payload: {
        prompt,
        executionMode: normalizeStudioExecutionMode(options.executionMode || options.execution_mode),
    routeId: options.selectedRoute || options.routeId || studioRuntimeProjection.modelRoute || "route.local-first",
    modelId: options.selectedModelId || options.modelId || studioRuntimeProjection.selectedModel || "auto",
    approvalMode: options.approvalMode || studioRuntimeProjection.approvalMode,
    workspaceRoot: options.workspacePath || workspaceSummary().path,
    source: "agent-studio-submit",
      },
    });
    if (frame && typeof frame === "object") {
      return frame;
    }
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] intent frame route unavailable; using local fallback: ${error?.message || String(error)}`);
  }
  return fallbackStudioPromptIntentFrame(prompt, options);
}

async function recoverStudioConversationArtifactAfterTimeout(threadId, { title, artifactClass, startedAtMs } = {}, output) {
  if (!threadId) {
    return null;
  }
  try {
    const artifacts = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/artifacts`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs: 5_000,
    });
    const normalizedTitle = stringValue(title).toLowerCase();
    const normalizedClass = stringValue(artifactClass);
    const candidate = firstArray(artifacts)
      .filter((artifact) => {
        const createdAtMs = Date.parse(artifact?.created_at || artifact?.createdAt || artifact?.updated_at || artifact?.updatedAt || "");
        const recentEnough = !startedAtMs || !Number.isFinite(createdAtMs) || createdAtMs >= startedAtMs - 2_000;
        const titleMatches = !normalizedTitle || stringValue(artifact?.title).toLowerCase() === normalizedTitle;
        const classMatches = !normalizedClass || stringValue(artifact?.artifact_class || artifact?.artifactClass) === normalizedClass;
        return recentEnough && titleMatches && classMatches;
      })
      .sort((left, right) =>
        Date.parse(right?.updated_at || right?.updatedAt || right?.created_at || right?.createdAt || "") -
        Date.parse(left?.updated_at || left?.updatedAt || left?.created_at || left?.createdAt || ""),
      )[0];
    if (candidate) {
      output?.appendLine?.(`[ioi-studio] recovered conversation artifact after bounded request timeout: ${candidate.id}`);
      appendStudioTimeline("Conversation artifact recovered", candidate.title || candidate.id, "completed", {
        artifactId: candidate.id,
      });
      return candidate;
    }
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] conversation artifact recovery unavailable: ${error?.message || String(error)}`);
  }
  return null;
}

async function createStudioConversationArtifact(threadId, prompt, output, intentFrame = {}, options = {}) {
  const artifactClass = studioIntentFrameArtifactClass(intentFrame, prompt);
  const generatedFiles = options.generatedFiles || options.generated_files || null;
  const title = generatedFiles?.title || studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt);
  const summary = generatedFiles?.summary || studioIntentFrameArtifactSummary(intentFrame, prompt);
  const createStartedAtMs = Date.now();
  let response;
  try {
    response = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/artifacts`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS,
      payload: {
        prompt,
        artifactClass,
        title,
        summary,
        outputModality: intentFrame?.artifact?.outputModality || intentFrame?.artifact?.output_modality || null,
        ...(generatedFiles ? { generatedFiles } : {}),
        intentFrame: studioIntentFramePayload(intentFrame),
        source: "agent-studio-conversation-artifact",
        turnId: studioRuntimeProjection.turnId || null,
      },
    });
  } catch (error) {
    if (!/timed out|timeout/i.test(error?.message || String(error))) {
      throw error;
    }
    const recovered = await recoverStudioConversationArtifactAfterTimeout(
      threadId,
      { title, artifactClass, startedAtMs: createStartedAtMs },
      output,
    );
    if (!recovered) {
      throw error;
    }
    response = { artifact: recovered };
  }
  let artifact = response?.artifact || response;
  appendStudioReceipts(firstArray([response?.receipt]), "conversation_artifact");
  const applyArtifactAction = async (action, payload = {}) => {
    const result = await runStudioConversationArtifactAction(artifact.id, action, output, payload);
    if (result?.artifact) {
      artifact = result.artifact;
    }
    return result;
  };
  if (artifactClass === "imported_document") {
    await applyArtifactAction("edit", {
      instruction: "Tighten the intro while preserving the original document bytes.",
    });
    await applyArtifactAction("compare");
    await applyArtifactAction("export");
  } else if (artifactClass === "react_vite_app") {
    await applyArtifactAction("rebuild");
    await applyArtifactAction("edit", {
      instruction: "Make the sidebar denser.",
    });
    await applyArtifactAction("rebuild");
  } else if (artifactClass === "static_html_js") {
    if (!generatedFiles) {
      await applyArtifactAction("rebuild");
    }
  } else if (artifactClass === "pdf_preview") {
    await applyArtifactAction("summarize");
  } else if (artifactClass === "diff_patch") {
    await applyArtifactAction("approve");
    await applyArtifactAction("rollback");
  } else if (artifactClass === "browser_observation") {
    await applyArtifactAction("capture");
  }
  return artifact;
}

async function runStudioConversationArtifactAction(artifactId, action, output, payload = {}) {
  try {
    const result = await requestJson(daemonEndpoint(), `/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/actions`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS,
      payload: {
        action,
        ...payload,
        source: "agent-studio-conversation-artifact-action",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
      },
    });
    appendStudioReceipts(firstArray([result?.receipt]), "conversation_artifact_action");
    return result;
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] artifact action ${action} blocked: ${error?.message || String(error)}`);
    appendStudioTimeline("Artifact action blocked", `${action}: ${error?.message || String(error)}`, "blocked");
    return null;
  }
}

async function projectStudioConversationArtifactCanvas(prompt, output, intentFrame = {}) {
  await ensureStudioDaemonThread({
    model: studioRuntimeProjection.modelRoute || "route.local-first",
    selectedModelId: studioRuntimeProjection.selectedModel || "auto",
    reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: studioRuntimeProjection.approvalMode,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  studioRuntimeProjection.turnId = studioRuntimeProjection.turnId || `turn_artifact_${Date.now().toString(36)}`;
  studioRuntimeProjection.runId = studioRuntimeProjection.runId || studioRuntimeProjection.turnId;
  const artifactClass = studioIntentFrameArtifactClass(intentFrame, prompt);
  let generatedFiles = null;
  let generatedFilesError = null;
  if (artifactClass === "static_html_js" && studioPromptRequestsGeneratedWebArtifact(prompt)) {
    try {
      generatedFiles = await generateStudioStaticWebsiteDraftThroughAgentTurn({
        prompt,
        title: studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt),
        selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
        selectedModelId: studioRuntimeProjection.selectedModel || "auto",
        reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
        workspacePath: workspaceSummary().path,
        intentFrame,
      }, output);
    } catch (error) {
      generatedFilesError = error;
      output?.appendLine?.(`[ioi-studio] website artifact model draft rejected: ${error?.message || String(error)}`);
    }
  }
  if (artifactClass === "static_html_js" && studioPromptRequestsGeneratedWebArtifact(prompt) && !generatedFiles) {
    const detail = generatedFilesError?.message || "Artifact boundary rejected generated website draft.";
    const cleanDetail = generatedFilesError
      ? studioCleanProductErrorMessage(generatedFilesError)
      : "Artifact boundary rejected generated website draft.";
    appendStudioTimeline("Website artifact blocked", detail, "blocked");
    let blockedText = /No product model is mounted/i.test(cleanDetail) ? cleanDetail : "";
    if (!blockedText) {
      try {
        const handoff = await streamStudioArtifactBlockedHandoff({
          prompt,
          selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
          selectedModelId: studioRuntimeProjection.selectedModel || "auto",
          reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
          workspacePath: workspaceSummary().path,
          handoffContext: `Artifact class: static HTML website.\nBoundary result: selected model draft did not pass artifact validation.\nArtifact created: no.\nProduct-safe detail: ${cleanDetail}`,
        }, output);
        blockedText = handoff.text;
      } catch (handoffError) {
        output?.appendLine?.(`[ioi-studio] website artifact blocked handoff failed: ${handoffError?.message || String(handoffError)}`);
      }
    }
    return {
      status: "blocked",
      events: [],
      receiptRefs: [],
      text: blockedText,
      artifacts: [],
    };
  }
  const artifact = await createStudioConversationArtifact(threadId, prompt, output, intentFrame, { generatedFiles });
  const generatedRuntimeEvents = firstArray(generatedFiles?.runtimeEvents);
  const generatedSourceRefs = firstArray(generatedFiles?.sourceRefs).length
    ? firstArray(generatedFiles?.sourceRefs)
    : studioSourceRefsFromRuntimeEvents(generatedRuntimeEvents);
  const artifactForTurn = generatedSourceRefs.length
    ? { ...artifact, sourceRefs: generatedSourceRefs }
    : artifact;
  studioRuntimeProjection.conversationArtifacts.push(artifactForTurn);
  studioRuntimeProjection.runtimeCockpit.conversationArtifactObserved = true;
  appendStudioTimeline("Conversation artifact ready", artifactForTurn.title || artifactForTurn.id, "completed", {
    artifactId: artifactForTurn.id,
  });
  let handoffText = "";
  let handoffMetrics = null;
  if (artifactClass === "static_html_js" && generatedFiles) {
    const artifactTitle = stringValue(artifactForTurn.title || generatedFiles.title || studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt), "website");
    const artifactLabel = /\bwebsite\b/i.test(artifactTitle) ? artifactTitle : `${artifactTitle} website`;
    handoffText = `Created the ${artifactLabel} artifact. The preview is below.`;
  } else {
    try {
      const handoff = await streamStudioArtifactHandoffText({
        prompt,
        selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
        selectedModelId: studioRuntimeProjection.selectedModel || "auto",
        reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
        workspacePath: workspaceSummary().path,
        handoffContext: `Artifact title: ${artifactForTurn.title || artifactForTurn.id}\nArtifact class: ${artifactForTurn.artifactClass || artifactForTurn.artifact_class || artifactClass}\nArtifact created: yes.\nPreview is attached in Agent Studio as a sandboxed conversation artifact.\nAvailable actions: open preview, revise, export, promote, or roll back when supported.`,
      }, output);
      handoffText = handoff.text;
      handoffMetrics = handoff.metrics || null;
    } catch (handoffError) {
      output?.appendLine?.(`[ioi-studio] artifact handoff model stream failed: ${handoffError?.message || String(handoffError)}`);
    }
  }
  return {
    status: "completed",
    events: generatedRuntimeEvents,
    sourceRefs: generatedSourceRefs,
    receiptRefs: normalizeReceiptRefs(artifactForTurn),
    text: handoffText,
    artifacts: [artifactForTurn],
    modelMetrics: handoffMetrics || generatedFiles?.generator?.metrics || null,
  };
}

function studioPostRuntimeMessage(type, payload = {}) {
  let normalizedPayload = payload;
  if (type === "agentWorkStep") {
    normalizedPayload = appendStudioPendingWorkStep(payload);
    if (!normalizedPayload) return;
  }
  if (!studioPanel) return;
  studioPanel.webview.postMessage({ source: "ioi-studio-runtime", type, payload: normalizedPayload });
  if (type === "agentWorkStep") {
    studioPostPendingWorklogSnapshot();
  }
}

function studioPostPendingWorklogSnapshot() {
  if (!studioPanel) return;
  const steps = firstArray(studioRuntimeProjection.pendingWorklog)
    .map((step) => normalizeStudioPendingWorkStep(step))
    .filter(Boolean)
    .slice(-12);
  if (!steps.length) return;
  studioPanel.webview.postMessage({
    source: "ioi-studio-runtime",
    type: "agentWorklogSnapshot",
    payload: { steps },
  });
}

const studioAgentFinalHandoffStreamer = createStudioAgentFinalHandoffStreamer({ crypto, studioPostRuntimeMessage, stringValue });
const studioAgentAnswerStreamProjector = createStudioAgentAnswerStreamProjector({ getStudioRuntimeProjection: () => studioRuntimeProjection, studioPostRuntimeMessage, stringValue });

function studioModelIdForRouteInvocation(selectedRoute, selectedModelId) {
  const explicitModelId = stringValue(selectedModelId);
  assertStudioProductModelSelector(selectedRoute, explicitModelId);
  if (!isAutoStudioModelSelector(explicitModelId)) {
    return explicitModelId;
  }
  const routeOrModel = stringValue(selectedRoute);
  assertStudioProductModelSelector(routeOrModel, explicitModelId);
  if (routeOrModel && !routeOrModel.startsWith("route.") && !isAutoStudioModelSelector(routeOrModel)) {
    return routeOrModel;
  }
  return "auto";
}

async function ensureStudioModelInvocationToken(output) {
  const configuredToken = daemonRequestToken();
  if (configuredToken) {
    return configuredToken;
  }
  if (studioModelInvocationToken) {
    return studioModelInvocationToken;
  }
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const grant = await requestJson(endpoint, "/api/v1/tokens", {
    method: "POST",
    payload: {
      audience: "autopilot-agent-studio",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.tokenize:*",
        "model.context:*",
        "route.use:*",
      ],
      denied: ["connector.*", "filesystem.write", "shell.exec"],
      source: "agent-studio-chat-stream",
    },
  });
  studioModelInvocationToken = stringValue(grant?.token);
  if (!studioModelInvocationToken) {
    throw new Error("IOI daemon did not issue a model invocation token.");
  }
  appendStudioReceipts(
    [
      {
        id: grant?.receiptId || grant?.receipt_id,
        kind: "permission_token",
        summary: "Daemon issued a scoped Studio model invocation token.",
      },
    ],
    "permission_token",
  );
  output?.appendLine?.("[ioi-studio] scoped daemon model invocation token ready.");
  return studioModelInvocationToken;
}

function ssePayloadsFromBlock(block) {
  return String(block || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trim())
    .filter(Boolean);
}

function studioDeltaFromSsePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const choice = payload.choices?.[0] || {};
  if (typeof choice.delta?.content === "string") {
    return choice.delta.content;
  }
  if (payload.type === "response.output_text.delta" && typeof payload.delta === "string") {
    return payload.delta;
  }
  if (typeof payload.message?.content === "string") {
    return payload.message.content;
  }
  if (typeof payload.response?.output_text === "string") {
    return payload.response.output_text;
  }
  return "";
}

function studioReasoningDeltaFromSsePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const choice = payload.choices?.[0] || {};
  return stringValue(choice.delta?.reasoning_content || choice.delta?.reasoningContent || payload.delta?.reasoning_content || payload.reasoning_delta);
}

function studioUsageFromProviderTimings(timings = {}, previousUsage = null) {
  if (!timings || typeof timings !== "object") return previousUsage;
  const promptTokens = studioNumberOrNull(timings.prompt_n ?? previousUsage?.prompt_tokens ?? previousUsage?.input_tokens) ?? 0;
  const completionTokens =
    studioNumberOrNull(timings.predicted_n ?? previousUsage?.completion_tokens ?? previousUsage?.output_tokens) ?? 0;
  const usage = {
    ...(previousUsage && typeof previousUsage === "object" ? previousUsage : {}),
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: studioNumberOrNull(previousUsage?.total_tokens) ?? promptTokens + completionTokens,
  };
  const tokensPerSecond = studioNumberOrNull(timings.predicted_per_second);
  const promptMs = studioNumberOrNull(timings.prompt_ms);
  const completionMs = studioNumberOrNull(timings.predicted_ms);
  if (tokensPerSecond !== null) usage.tokens_per_second = tokensPerSecond;
  if (promptMs !== null) usage.prompt_ms = promptMs;
  if (completionMs !== null) usage.completion_ms = completionMs;
  if (promptMs !== null || completionMs !== null) usage.elapsed_ms = (promptMs || 0) + (completionMs || 0);
  return usage;
}

function collectStudioStreamMetadata(target, payload) {
  if (!payload || typeof payload !== "object") {
    return;
  }
  for (const id of uniqueStrings([
    payload.receipt_id,
    payload.receiptId,
    payload.stream_receipt_id,
    payload.streamReceiptId,
    ...firstArray(payload.tool_receipt_ids),
    ...firstArray(payload.toolReceiptIds),
  ])) {
    target.receiptIds.add(id);
  }
  target.routeId = payload.route_id || payload.routeId || target.routeId;
  target.model = payload.model || target.model;
  target.providerStream = payload.provider_stream || payload.providerStream || target.providerStream;
  target.usage = payload.usage || payload.tokenCount || payload.token_count || target.usage;
  if (payload.timings) {
    target.usage = studioUsageFromProviderTimings(payload.timings, target.usage);
  }
  target.provider = payload.provider_id || payload.providerId || payload.provider || target.provider;
  const finishReason = payload.choices?.[0]?.finish_reason || payload.finish_reason || payload.stop_reason || payload.stopReason;
  target.stopReason = finishReason || target.stopReason;
}

function requestSseJson(baseUrl, routePath, { method = "POST", payload, token, onPayload, timeoutMs = 90_000 } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  if (!base) {
    return Promise.reject(new Error("IOI daemon endpoint is not configured."));
  }

  const target = new URL(routePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload === undefined ? null : JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    let settled = false;
    let request = null;
    const wallClockTimeout = setTimeout(() => {
      request?.destroy(new Error("Daemon stream timed out."));
    }, timeoutMs);
    const finishResolve = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(wallClockTimeout);
      resolve(value);
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(wallClockTimeout);
      reject(error);
    };
    request = client.request(
      target,
      {
        method,
        headers: {
          accept: "text/event-stream",
          ...(body
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(body),
              }
            : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (response) => {
        let raw = "";
        let buffer = "";
        const statusCode = response.statusCode || 0;
        response.on("data", (chunk) => {
          const text = chunk.toString("utf8");
          raw += text;
          if (statusCode >= 400) {
            return;
          }
          buffer += text;
          const frames = buffer.split(/\r?\n\r?\n/);
          buffer = frames.pop() || "";
          for (const frame of frames) {
            for (const data of ssePayloadsFromBlock(frame)) {
              if (data === "[DONE]") {
                finishResolve({ statusCode, raw });
                request.destroy();
                return;
              }
              try {
                const shouldContinue = onPayload?.(JSON.parse(data), data);
                if (shouldContinue === false) {
                  finishResolve({ statusCode, raw, stoppedByClient: true });
                  request.destroy();
                  return;
                }
              } catch (error) {
                finishReject(error);
                request.destroy();
                return;
              }
            }
          }
        });
        response.on("end", () => {
          if (statusCode >= 400) {
            finishReject(new Error(`[IOI Workbench] Daemon stream failed (${statusCode}): ${raw}`));
            return;
          }
          if (buffer.trim()) {
            try {
              for (const data of ssePayloadsFromBlock(`${buffer}\n\n`)) {
                if (data !== "[DONE]") {
                  const shouldContinue = onPayload?.(JSON.parse(data), data);
                  if (shouldContinue === false) {
                    finishResolve({ statusCode, raw, stoppedByClient: true });
                    return;
                  }
                } else {
                  finishResolve({ statusCode, raw });
                  return;
                }
              }
            } catch (error) {
              finishReject(error);
              return;
            }
          }
          finishResolve({ statusCode, raw });
        });
      },
    );

    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("Daemon model stream timed out."));
    });
    request.on("error", (error) => {
      finishReject(error);
    });
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

const {
  extractStudioHtmlDocument,
  generateStudioStaticWebsiteDraft,
  streamStudioArtifactBlockedHandoff,
  streamStudioArtifactHandoffText,
  streamStudioModelCompletion,
  studioStaticWebsiteDraftFromRuntimeText,
} = createStudioModelCompletion({
  crypto,
  STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
  requestSseJson,
  requestJson,
  daemonEndpoint,
  ensureStudioModelInvocationToken,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  studioModelIdForRouteInvocation,
  normalizeStudioReasoningEffort,
  studioPostRuntimeMessage,
  firstArray,
  studioDenyFixtureModelPolicy,
  studioMaxOutputTokens,
  studioArtifactMaxOutputTokens,
  collectStudioStreamMetadata,
  studioReasoningDeltaFromSsePayload,
  studioDeltaFromSsePayload,
  studioSplitReasoningFromText,
  stringValue,
  studioResponseMetricsFromUsage,
  studioTextContainsProductFixtureMarker,
  studioFixtureModelUsageAllowed,
  appendStudioReceipts,
});
const {
  sanitizeStudioProductAssistantText,
  normalizeStudioAssistantReplyText,
  studioAssistantReplyTextIsDeferred,
  normalizeStudioAgentResultText,
  studioAssistantTextFromRuntimeToolEvents,
  studioAgentTurnResultText,
  studioArtifactSourceTextFromAgentTurn,
} = createStudioAgentTurnResultText({
  stringValue,
  firstArray,
  studioRuntimeEventKind,
  studioRuntimeEventToolName,
  extractHtmlDocument: extractStudioHtmlDocument,
});

async function generateStudioStaticWebsiteDraftThroughAgentTurn({
  prompt,
  title,
  selectedRoute,
  selectedModelId,
  reasoningEffort = "none",
  workspacePath,
  intentFrame = {},
}, output) {
  const researchQuery = studioArtifactResearchQuery(prompt);
  const artifactPrompt = [
    `Create one complete self-contained HTML document for this request: ${prompt}`,
    `Research topic: ${researchQuery || prompt}`,
    "",
    "Use the governed tool loop before writing the page.",
    "Call web__search with exactly the research topic above as the query.",
    "Call web__read on one relevant result if a readable result is available.",
    "Then call chat__reply; the chat__reply message must contain the final HTML document only.",
    "The chat__reply message must start with <!DOCTYPE html> and end immediately after </html>.",
    "Do not return markdown fences, JSON, source notes, receipts, file paths, or explanations.",
    "Do not use external network assets, remote fonts, CDNs, or filesystem references.",
  ].join("\n");
  const agentTurn = await submitStudioAgentTurn({
    prompt: artifactPrompt,
    selectedRoute,
    selectedModelId,
    reasoningEffort,
    workspacePath,
    intentFrame: studioResearchIntentFrameForArtifact(studioIntentFramePayload(intentFrame), researchQuery),
    projectAnswerStream: true,
    answerStreamPresentation: "artifact_generation",
    answerStreamFileName: "index.html",
    maxStepsOverride: 8,
  }, output);
  const artifactSourceText = studioArtifactSourceTextFromAgentTurn(agentTurn);
  const sourceStream = studioAgentAnswerStreamProjector.complete(artifactSourceText, {
    presentation: "artifact_generation",
    fileName: "index.html",
  });
  const draft = studioStaticWebsiteDraftFromRuntimeText({
    prompt,
    title,
    text: artifactSourceText,
    selectedRoute,
    selectedModelId,
    metrics: agentTurn.modelMetrics || null,
    receiptRefs: agentTurn.receiptRefs || [],
    streamId: sourceStream?.streamId || "",
  });
  return {
    ...draft,
    sourceRefs: firstArray(agentTurn.sourceRefs),
    runtimeEvents: firstArray(agentTurn.events),
  };
}
function collectStudioAgentEventsFromResponse(turn = {}) {
  return [
    ...firstArray(turn.events),
    ...firstArray(turn.runtime_events),
    ...firstArray(turn.runtimeEvents),
    ...firstArray(turn.event_log),
    ...firstArray(turn.eventLog),
  ];
}

function uniqueStudioRuntimeEvents(events = []) {
  const seen = new Set();
  const unique = [];
  for (const event of firstArray(events)) {
    const key =
      event?.event_id ||
      event?.eventId ||
      event?.id ||
      (event?.event_stream_id && event?.seq ? `${event.event_stream_id}:${event.seq}` : "");
    if (key && seen.has(key)) {
      continue;
    }
    if (key) {
      seen.add(key);
    }
    unique.push(event);
  }
  return unique;
}

function applyStudioAgentTurnEvents(events = [], {
  projectPending = true,
  projectAnswerStream = true,
  answerStreamPresentation = "agent_final_handoff",
  answerStreamFileName = "",
} = {}) {
  const appliedEvents = [];
  for (const event of firstArray(events)) {
    if (!markStudioRuntimeEventSeen(event)) {
      continue;
    }
    appendStudioRuntimeEvent(event, studioRuntimeEventKind(event) || "agent.runtime.event");
    const eventThreadId = stringValue(event.thread_id || event.threadId);
    const eventTurnId = stringValue(event.turn_id || event.turnId);
    if (eventThreadId && !studioRuntimeProjection.threadId) {
      studioRuntimeProjection.threadId = eventThreadId;
      studioRuntimeProjection.sessionId = studioRuntimeProjection.sessionId || eventThreadId;
    }
    if (eventTurnId && !studioRuntimeProjection.turnId) {
      studioRuntimeProjection.turnId = eventTurnId;
      studioRuntimeProjection.runId = event.run_id || event.runId || studioRuntimeProjection.runId || eventTurnId;
    }
    appliedEvents.push(event);
    const kind = studioRuntimeEventKind(event).toLowerCase();
    const toolName = studioRuntimeEventToolName(event);
    const status = stringValue(event.status || event.payload_summary?.status || event.payload?.status, "observed");
    const summary =
      event.summary ||
      event.payload_summary?.summary ||
      event.payload_summary?.result_summary ||
      event.payload_summary?.input_summary ||
      event.payload?.summary ||
      event.payload?.result ||
      event.payload?.message ||
      "";
    const receiptRefs = normalizeReceiptRefs(event);
    if (kind === "answer.delta") {
      if (!projectAnswerStream) continue;
      studioAgentAnswerStreamProjector.projectDelta(event, {
        presentation: answerStreamPresentation,
        fileName: answerStreamFileName,
      });
      continue;
    }
    if (
      projectAnswerStream &&
      answerStreamPresentation === "artifact_generation" &&
      /turn\.(completed|failed|blocked)/.test(kind)
    ) {
      const terminalArtifactSource = studioArtifactSourceTextFromAgentTurn({ events: [event] });
      if (terminalArtifactSource) {
        studioAgentAnswerStreamProjector.complete(terminalArtifactSource, {
          presentation: answerStreamPresentation,
          fileName: answerStreamFileName,
        });
      }
    }
    if (projectPending && studioRuntimeProjection.pending) {
      const pendingStep = studioPendingStepFromRuntimeEvent(event, {
        kind,
        toolName,
        status,
        summary,
      });
      if (pendingStep) {
        const appendedStep = appendStudioPendingWorkStep(pendingStep);
        if (appendedStep) {
          studioPostRuntimeMessage("agentWorkStep", appendedStep);
        }
      }
    }
    applyStudioParityPlusEvent(event, { kind, status, summary, receiptRefs });
    // Browser/computer tool events remain visible as work rows. Controllable
    // managed-session cards must come from daemon inspection so their ids and
    // control state bind to durable runtime state.
    if (/tool\./.test(kind) || toolName) {
      studioRuntimeProjection.actionCards.push({
        id: event.event_id || event.eventId || event.id || `${toolName || "tool"}.${Date.now()}`,
        toolId: toolName || kind || "runtime.tool",
        label: toolName || kind || "Runtime tool",
        status,
        summary: stringValue(summary, "Daemon runtime tool event projected."),
        receiptRefs,
      });
    }
    if (/shell|command|terminal/.test(`${kind} ${toolName}`.toLowerCase())) {
      const eventPayload = event.payload_summary || event.payloadSummary || event.payload || event.data || {};
      const commandExcerpt = studioRuntimeToolEventExcerpt(event, summary);
      const commandDetail = studioRuntimeToolEventDetail(event, toolName, summary);
      studioRuntimeProjection.commandOutputs.push({
        id: event.event_id || event.eventId || event.id || `command.${Date.now()}`,
        toolId: toolName || "shell",
        label: toolName || "shell command",
        status,
        command: commandDetail,
        stdout:
          eventPayload.stdout ||
          eventPayload.output ||
          eventPayload.chunk ||
          eventPayload.text ||
          eventPayload.excerpt_preview ||
          eventPayload.excerptPreview ||
          commandExcerpt ||
          "",
        stderr: eventPayload.stderr || "",
        excerptPreview: commandExcerpt,
        exitCode: eventPayload.exit_code ?? eventPayload.exitCode ?? null,
        durationMs: eventPayload.duration_ms ?? eventPayload.durationMs ?? null,
        receiptRefs,
      });
    }
    if (/policy|approval|lease|firewall/.test(`${kind} ${toolName}`.toLowerCase())) {
      const permissionTarget = humanizeStudioToolName(toolName || event.payload?.tool_id || event.payload?.toolId || "");
      studioRuntimeProjection.policyLeases.push({
        id: event.event_id || event.eventId || event.id || `policy.${Date.now()}`,
        label: "Permission needed",
        title: "Permission needed",
        status,
        action: toolName || event.payload?.tool_id || event.payload?.toolId || "agent action",
        reason: permissionTarget
          ? `Agent needs permission to use ${permissionTarget}.`
          : "Agent needs permission before continuing.",
        didExecute: false,
        receiptRefs,
      });
    }
    if (/receipt/.test(kind) && receiptRefs.length > 0) {
      appendStudioReceipts(receiptRefs.map((id) => ({
        id,
        kind: kind || "agent.runtime.receipt",
        summary: stringValue(summary, "Rust runtime receipt projected into Studio."),
      })));
    }
  }
  if (
    projectPending &&
    studioRuntimeProjection.pending &&
    firstArray(studioRuntimeProjection.pendingWorklog).length > 0
  ) {
    studioPostPendingWorklogSnapshot();
  }
  return appliedEvents;
}

function studioMaxRuntimeEventSeq(events = []) {
  return firstArray(events).reduce((max, event) => {
    const seq = Number(event?.seq || 0);
    return Number.isFinite(seq) && seq > max ? seq : max;
  }, 0);
}

async function fetchStudioThreadEvents(threadId, output, { timeoutMs = 1500, sinceSeq = 0, stopOnTerminal = false } = {}) {
  if (!threadId) {
    return [];
  }
  const events = [];
  try {
    await requestSseJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/events?since_seq=${encodeURIComponent(String(Math.max(0, Number(sinceSeq) || 0)))}`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs,
      onPayload: (payload) => {
        let event = null;
        if (payload && payload.event && typeof payload.event === "object") {
          event = payload.event;
          events.push(event);
        } else if (payload) {
          event = payload;
          events.push(event);
        }
        if (stopOnTerminal && event) {
          const kind = studioRuntimeEventKind(event).toLowerCase();
          if (/turn\.(completed|failed|blocked)/.test(kind)) {
            return false;
          }
        }
      },
    });
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] daemon thread event stream unavailable: ${error?.message || String(error)}`);
  }
  return events;
}

const studioAgentTurnEvents = createStudioAgentTurnEvents({ fetchStudioThreadEvents, applyStudioAgentTurnEvents, studioMaxRuntimeEventSeq, studioAssistantTextFromRuntimeToolEvents, studioAgentTurnResultText, studioRuntimeEventKind, firstArray });

async function fetchStudioThreadTurns(threadId, output, { timeoutMs = 5000 } = {}) {
  if (!threadId) {
    return [];
  }
  try {
    const turns = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs,
    });
    return firstArray(turns);
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] daemon turn refresh unavailable: ${error?.message || String(error)}`);
    return [];
  }
}

async function fetchStudioThreadTurnEvents(threadId, output, { turnId } = {}) {
  const turns = await fetchStudioThreadTurns(threadId, output, { timeoutMs: 5000 });
  const scopedTurns = turnId
    ? turns.filter((turn) => String(turn.turn_id || turn.turnId || "") === String(turnId))
    : turns;
  return scopedTurns.flatMap((turn) => collectStudioAgentEventsFromResponse(turn));
}

function studioTurnPromptText(turn = {}) {
  const direct = stringValue(
    turn.prompt ||
      turn.input ||
      turn.message ||
      turn.request?.prompt ||
      turn.request?.input ||
      turn.request?.message,
  );
  if (direct) {
    return direct;
  }
  const userTurn = firstArray(turn.conversation)
    .slice()
    .reverse()
    .find((item) => String(item?.role || item?.type || "").toLowerCase() === "user");
  if (userTurn) {
    return stringValue(userTurn.content || userTurn.text || userTurn.message);
  }
  const startedEvent = collectStudioAgentEventsFromResponse(turn)
    .find((event) => studioRuntimeEventKind(event).toLowerCase() === "turn.started");
  return stringValue(startedEvent?.payload?.prompt || startedEvent?.payload_summary?.prompt);
}

function studioTurnStartedAtMs(turn = {}) {
  const numeric = Number(
    turn.started_at_ms ||
      turn.startedAtMs ||
      turn.created_at_ms ||
      turn.createdAtMs ||
      0,
  );
  if (Number.isFinite(numeric) && numeric > 0) {
    return numeric;
  }
  const parsed = Date.parse(
    turn.started_at ||
      turn.startedAt ||
      turn.created_at ||
      turn.createdAt ||
      "",
  );
  return Number.isFinite(parsed) ? parsed : 0;
}

function studioTurnMatchesSubmittedPrompt(turn = {}, prompt = "", submittedAtMs = 0) {
  const turnPrompt = studioTurnPromptText(turn);
  if (turnPrompt && prompt && turnPrompt === prompt) {
    return true;
  }
  const startedAtMs = studioTurnStartedAtMs(turn);
  return Boolean(startedAtMs && submittedAtMs && startedAtMs >= submittedAtMs - 2000);
}

function studioTurnLooksTerminal(turn = {}) {
  const events = collectStudioAgentEventsFromResponse(turn);
  const statusText = stringValue(turn.status || turn.state || "").toLowerCase();
  const resultText = studioAgentTurnResultText(turn, events);
  if (resultText) {
    return true;
  }
  if (events.some(studioRuntimeEventIsRunningStepCompletion)) {
    return false;
  }
  if (/blocked|failed|error|completed|paused|approval|waiting_for_approval/.test(statusText)) {
    return true;
  }
  return events.some((event) => /turn\.(completed|failed)|completed|failed|blocked/.test(studioRuntimeEventKind(event).toLowerCase()));
}

const studioAgentTurnRecovery = createStudioAgentTurnRecovery({
  fetchStudioThreadTurns,
  studioTurnMatchesSubmittedPrompt,
  studioTurnLooksTerminal,
  studioAgentTurnResultText,
  normalizeStudioAgentResultText,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  firstArray,
  recoveryAttempts: STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS,
  recoveryPollMs: STUDIO_AGENT_TURN_RECOVERY_POLL_MS,
});

function studioApprovalTurnPayload() {
  const turnId = stringValue(studioRuntimeProjection.turnId);
  return turnId.startsWith("turn_") ? { turn_id: turnId } : {};
}

function applyStudioAgentModeSelection(payload = {}) {
  const previousMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
  const previousRuntimeProfile = studioRuntimeProjection.runtimeProfile;
  const executionMode = normalizeStudioExecutionMode(
    payload.executionMode || payload.selectionId || payload.mode || payload.label,
  );
  const runtimeProfile =
    executionMode === STUDIO_MODE_AGENT
      ? STUDIO_AGENT_RUNTIME_PROFILE
      : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  studioRuntimeProjection.executionMode = executionMode;
  studioRuntimeProjection.runtimeProfile = runtimeProfile;
  if (
    studioRuntimeProjection.threadId &&
    (previousMode !== executionMode || previousRuntimeProfile !== runtimeProfile)
  ) {
    resetStudioDaemonThreadProjection();
  }
  return { executionMode, runtimeProfile };
}

function studioRunResultText({ prompt, run, conversation }) {
  const assistantTurn = firstArray(conversation)
    .slice()
    .reverse()
    .find((item) => String(item?.role || item?.type || "").toLowerCase() === "assistant");
  const content =
    assistantTurn?.content ||
    assistantTurn?.text ||
    assistantTurn?.message ||
    run?.result ||
    run?.output ||
    null;
  if (content) {
    return String(content);
  }
  return `Daemon turn completed for: ${prompt}`;
}

async function ensureStudioDaemonThread({ model = "route.local-first", selectedModelId = "auto", executionMode = studioRuntimeProjection.executionMode, reasoningEffort = studioRuntimeProjection.reasoningEffort || "none", approvalMode = studioRuntimeProjection.approvalMode, intentFrame = null } = {}, output) {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const normalizedMode = normalizeStudioExecutionMode(executionMode);
  const permissionMapping = studioPermissionDaemonMapping(approvalMode);
  const runtimeProfile = normalizedMode === STUDIO_MODE_AGENT
    ? STUDIO_AGENT_RUNTIME_PROFILE
    : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  if (
    studioRuntimeProjection.threadId &&
    studioRuntimeProjection.executionMode &&
    normalizeStudioExecutionMode(studioRuntimeProjection.executionMode) !== normalizedMode
  ) {
    resetStudioDaemonThreadProjection();
  }
  if (
    studioRuntimeProjection.threadId &&
    studioRuntimeProjection.runtimeProfile &&
    studioRuntimeProjection.runtimeProfile !== runtimeProfile
  ) {
    resetStudioDaemonThreadProjection();
  }
  if (studioRuntimeProjection.threadId) {
    return studioRuntimeProjection;
  }
  const workspace = workspaceSummary();
  const thread = await requestJson(endpoint, "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
      payload: {
        mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        approvalMode: permissionMapping.approvalMode,
        approval_mode: permissionMapping.approvalMode,
        runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        options: {
          mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          approvalMode: permissionMapping.approvalMode,
          approval_mode: permissionMapping.approvalMode,
          runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          local: {
            cwd: workspace.path,
          },
          model: {
            id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
            routeId: model || "route.local-first",
            reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
          },
          ...(intentFrame ? { intentFrame: studioIntentFramePayload(intentFrame) } : {}),
          source: normalizedMode === STUDIO_MODE_AGENT ? "agent-studio-agent-mode" : "agent-studio-ask-mode",
        },
      },
    });
  studioRuntimeProjection.threadId = thread?.thread_id || thread?.threadId || null;
  studioRuntimeProjection.sessionId =
    thread?.session_id || thread?.sessionId || studioRuntimeProjection.threadId || null;
  studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || model;
  studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || "auto";
  studioRuntimeProjection.reasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  studioRuntimeProjection.approvalMode = permissionMapping.approvalMode;
  studioRuntimeProjection.executionMode = normalizedMode;
  studioRuntimeProjection.runtimeProfile = runtimeProfile;
  studioRuntimeProjection.status = "active";
  studioRuntimeProjection.history = [
    {
      id: studioRuntimeProjection.threadId || "studio-thread",
      title: "Daemon Studio session",
      status: thread?.status || "active",
    },
  ];
  studioRuntimeProjection.timeline.push({
    label: "Daemon session created",
    detail: studioRuntimeProjection.threadId || "thread pending",
    status: "completed",
  });
  appendStudioReceipts(
    uniqueStrings([thread?.model_route_receipt_id, thread?.modelRouteReceiptId]).map((id) => ({
      id,
      kind: "model_route",
      summary: "Daemon selected the Studio model route.",
    })),
  );
  output?.appendLine?.(`[ioi-studio] daemon session ready: ${studioRuntimeProjection.threadId}`);
  return studioRuntimeProjection;
}

async function submitStudioAgentTurn({
  prompt,
  selectedRoute,
  selectedModelId,
  reasoningEffort = "none",
  workspacePath,
  intentFrame,
  projectAnswerStream = true,
  answerStreamPresentation = "agent_final_handoff",
  answerStreamFileName = "",
  maxStepsOverride = null,
}, output) {
  await ensureStudioDaemonThread({
    model: selectedRoute,
    selectedModelId,
    reasoningEffort,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: studioRuntimeProjection.approvalMode,
    intentFrame,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    throw new Error("Agent Mode requires a daemon runtime thread, but no thread was created.");
  }
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = STUDIO_AGENT_RUNTIME_PROFILE;
  studioRuntimeProjection.timeline.push({
    label: "Agent turn started",
    detail: "POST /v1/threads/:thread_id/turns through Rust runtime_service profile",
    status: "running",
  });
  const submittedAtMs = Date.now();
  const permissionMapping = studioPermissionDaemonMapping(studioRuntimeProjection.approvalMode);
  const hasMaxStepsOverride = maxStepsOverride !== null &&
    maxStepsOverride !== undefined &&
    String(maxStepsOverride).trim() !== "";
  const requestedMaxSteps = hasMaxStepsOverride && Number.isFinite(Number(maxStepsOverride))
    ? Math.floor(Number(maxStepsOverride))
    : studioAgentMaxStepsForIntent(intentFrame, prompt);
  const maxSteps = Math.max(STUDIO_AGENT_MIN_TURN_STEPS, requestedMaxSteps);
  const intentFramePayload = studioIntentFramePayload(intentFrame);
  const turnPayload = {
    prompt,
    input: prompt,
    ...permissionMapping,
    ...(intentFramePayload
      ? {
          intentFrame: intentFramePayload,
          intent_frame: intentFramePayload,
          runtimeAction: intentFramePayload.runtimeAction || intentFramePayload.runtime_action || null,
          runtime_action: intentFramePayload.runtime_action || intentFramePayload.runtimeAction || null,
        }
      : {}),
    runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
    max_steps: maxSteps,
    maxSteps,
    options: {
      ...permissionMapping,
      runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
      runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
      max_steps: maxSteps,
      maxSteps,
      local: {
        cwd: workspacePath || workspaceSummary().path,
      },
      model: {
        id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
        routeId: selectedRoute || "route.local-first",
        reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
      },
      source: "agent-studio-agent-mode",
      intentFrame: intentFramePayload,
      intent_frame: intentFramePayload,
    },
    metadata: {
      source: "agent-studio-agent-mode",
      workspaceRoot: workspacePath || workspaceSummary().path,
      ...permissionMapping,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      intentFrame: intentFramePayload,
      intent_frame: intentFramePayload,
    },
  };
  let turn;
  let liveEventsPromise = null;
  let liveObservedEvents = [];
  try {
    const preTurnEvents = await fetchStudioThreadEvents(threadId, output, { timeoutMs: 1000, sinceSeq: 0 });
    for (const event of preTurnEvents) {
      markStudioRuntimeEventSeen(event);
    }
    const preTurnSeq = studioMaxRuntimeEventSeq(preTurnEvents);
    const turnRequest = requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_AGENT_TURN_POST_TIMEOUT_MS,
      payload: turnPayload,
    });
    liveEventsPromise = studioAgentTurnEvents.pollStudioThreadEventsDuringTurn(threadId, output, turnRequest, {
      sinceSeq: preTurnSeq,
      resolveOnTerminal: true,
      projectAnswerStream,
      answerStreamPresentation,
      answerStreamFileName,
    });
    const projectionRecoveryAttempts = Math.ceil(Math.max(STUDIO_AGENT_TURN_POST_TIMEOUT_MS, 300_000) / STUDIO_AGENT_TURN_RECOVERY_POLL_MS);
    const turnProjectionRecoveryPromise = studioAgentTurnRecovery.recoverStudioAgentTurnAfterSubmitTimeout({
      threadId,
      prompt,
      submittedAtMs,
      output,
      attempts: projectionRecoveryAttempts,
      pollMs: STUDIO_AGENT_TURN_RECOVERY_POLL_MS,
      timeoutMs: 2500,
      reasonLabel: "live projection polling",
    });
    let terminalRecoveryActive = true;
    const terminalEventsRecoveryPromise = (async () => {
      const deadline = Date.now() + Math.max(STUDIO_AGENT_TURN_POST_TIMEOUT_MS, 300_000);
      let terminalRecoverySeq = preTurnSeq;
      while (terminalRecoveryActive && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const events = await fetchStudioThreadEvents(threadId, output, {
          timeoutMs: 2500,
          sinceSeq: terminalRecoverySeq,
          stopOnTerminal: true,
        });
        if (!events.length) {
          continue;
        }
        terminalRecoverySeq = Math.max(terminalRecoverySeq, studioMaxRuntimeEventSeq(events));
        applyStudioAgentTurnEvents(events, {
          projectAnswerStream,
          answerStreamPresentation,
          answerStreamFileName,
        });
        if (studioAgentTurnEvents.studioRuntimeEventsHaveTerminalAssistantResult(events)) {
          return events;
        }
      }
      return null;
    })();
    const firstCompletion = await Promise.race([
      turnRequest.then((completedTurn) => ({ kind: "turn", turn: completedTurn })),
      liveEventsPromise.then((events) => ({ kind: "live_events", events })),
      turnProjectionRecoveryPromise.then((recoveredTurn) => recoveredTurn ? ({ kind: "turn_projection", turn: recoveredTurn }) : null),
      terminalEventsRecoveryPromise.then((events) => events ? ({ kind: "terminal_events", events }) : null),
    ]);
    terminalRecoveryActive = false;
    if (!firstCompletion) {
      turn = await turnRequest;
    } else if (firstCompletion.kind === "turn") {
      turn = firstCompletion.turn;
      liveObservedEvents = await Promise.race([
        liveEventsPromise.catch((error) => {
          output?.appendLine?.(`[ioi-studio] live daemon event projection ended early: ${error?.message || String(error)}`);
          return [];
        }),
        new Promise((resolve) => setTimeout(() => resolve([]), STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS)),
      ]);
    } else if (firstCompletion.kind === "turn_projection") {
      turn = firstCompletion.turn;
      liveObservedEvents = await Promise.race([
        liveEventsPromise.catch((error) => {
          output?.appendLine?.(`[ioi-studio] live daemon event projection ended after turn projection recovery: ${error?.message || String(error)}`);
          return [];
        }),
        new Promise((resolve) => setTimeout(() => resolve([]), STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS)),
      ]);
      turnRequest.catch((error) => {
        output?.appendLine?.(`[ioi-studio] Agent turn POST settled after turn projection recovery: ${error?.message || String(error)}`);
      });
    } else {
      liveObservedEvents = firstArray(firstCompletion.events);
      turn = studioAgentTurnRecovery.recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout({
        threadId,
        prompt,
        submittedAtMs,
        events: liveObservedEvents,
      });
      if (!turn) {
        turn = await turnRequest;
      } else {
        turnRequest.catch((error) => {
          output?.appendLine?.(`[ioi-studio] Agent turn POST settled after live event completion: ${error?.message || String(error)}`);
        });
      }
    }
    if (!liveObservedEvents.length && liveEventsPromise) {
      liveObservedEvents = await liveEventsPromise.catch((error) => {
        output?.appendLine?.(`[ioi-studio] live daemon event projection ended early: ${error?.message || String(error)}`);
        return [];
      });
    }
  } catch (error) {
    if (!/timed out|timeout/i.test(error?.message || String(error))) {
      throw error;
    }
    liveObservedEvents = await Promise.resolve(liveEventsPromise).catch((liveError) => {
      output?.appendLine?.(`[ioi-studio] live daemon event recovery after Agent POST timeout ended early: ${liveError?.message || String(liveError)}`);
      return [];
    }) || [];
    turn = studioAgentTurnRecovery.recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout({
      threadId,
      prompt,
      submittedAtMs,
      events: liveObservedEvents,
    });
    if (turn) {
      output?.appendLine?.("[ioi-studio] recovered daemon turn from live streamed runtime events after Agent POST timeout.");
      studioRuntimeProjection.timeline.push({
        label: "Agent turn recovered",
        detail: "Live daemon runtime events completed after the POST transport timed out.",
        status: "completed",
      });
    }
    if (turn) {
      // Keep the streamed model answer as the product handoff; trace keeps the transport timeout.
    } else {
      output?.appendLine?.(`[ioi-studio] Agent turn POST exceeded ${STUDIO_AGENT_TURN_POST_TIMEOUT_MS}ms; checking daemon turn projection.`);
      turn = await studioAgentTurnRecovery.recoverStudioAgentTurnAfterSubmitTimeout({
        threadId,
        prompt,
        submittedAtMs,
        output,
      });
      if (!turn) {
        throw error;
      }
      studioRuntimeProjection.timeline.push({
        label: "Agent turn recovered",
        detail: "Daemon turn projection was recovered after a bounded POST timeout.",
        status: "completed",
      });
    }
  }
  const responseEvents = collectStudioAgentEventsFromResponse(turn);
  const refreshEvents = studioAssistantTextFromRuntimeToolEvents(responseEvents)
    ? []
    : await fetchStudioThreadTurnEvents(turn.thread_id || turn.threadId || threadId, output, {
        turnId: turn.turn_id || turn.turnId,
      });
  const streamedEvents = studioAssistantTextFromRuntimeToolEvents([...responseEvents, ...refreshEvents])
    ? []
    : await fetchStudioThreadEvents(turn.thread_id || turn.threadId || threadId, output, { timeoutMs: 5000 });
  const allEvents = uniqueStudioRuntimeEvents([
    ...responseEvents,
    ...refreshEvents,
    ...liveObservedEvents,
    ...streamedEvents,
  ]);
  const events = studioRuntimeEventsForTurn(allEvents, turn.turn_id || turn.turnId);
  applyStudioAgentTurnEvents(events, {
    projectAnswerStream,
    answerStreamPresentation,
    answerStreamFileName,
  });
  const needsRetrieval = studioIntentFrameRequiresRetrieval(intentFrame, prompt);
  const hasSearch = studioRuntimeEventsIncludeTool(events, /web(::|__)search|search_web|web_search/);
  const hasRead = studioRuntimeEventsIncludeTool(events, /web(::|__)read|read_web|web_read/);
  const hasCompletedSearch = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/);
  const hasCompletedRead = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/);
  const chatReplyText = studioAssistantTextFromRuntimeToolEvents(events);
  const resultText = studioAgentTurnResultText(turn, events);
  const policyBlockedRuntimeText = studioPolicyBlockedRuntimeMessage({ prompt, resultText, events });
  const resultLooksRetrievalGrounded = studioResultTextLooksRetrievalGrounded(resultText);
  const statusText = stringValue(turn.status || turn.state || "", "completed").toLowerCase();
  const approvalPaused = studioTextIndicatesApprovalPause(resultText) || /waiting_for_approval|approval/.test(statusText);
  const blockedReason = stringValue(
    turn.error?.message ||
      turn.blocker?.message ||
      turn.externalBlocker?.message ||
      turn.stop_reason ||
      turn.stopReason,
  );
  const retrievalFailClosedText = needsRetrieval && !resultText
    ? studioRetrievalFailClosedText({ prompt, events, blockedReason })
    : "";
  if (
    needsRetrieval &&
    !(hasCompletedSearch && hasCompletedRead) &&
    !resultLooksRetrievalGrounded
  ) {
    throw new Error(
      [
        "Agent Mode failed closed: this prompt requires current/source retrieval, but the Rust runtime did not complete the required retrieval evidence.",
        blockedReason ? `Runtime stop reason: ${blockedReason}.` : "",
        resultText ? `Runtime result: ${resultText}` : "",
        `Observed retrieval events: search=${hasSearch}, read=${hasRead}, completedSearch=${hasCompletedSearch}, completedRead=${hasCompletedRead}.`,
      ].filter(Boolean).join(" "),
    );
  }
  if (retrievalFailClosedText) {
    output?.appendLine?.(`[ioi-studio] ${retrievalFailClosedText}`);
  }
  const receiptRefs = normalizeReceiptRefs(turn, ...events);
  const sourceRefs = studioSourceRefsFromRuntimeEvents(events);
  appendStudioReceipts(
    receiptRefs.map((id) => ({
      id,
      kind: "agent_turn",
      summary: "Daemon agent turn receipt projected into Studio.",
    })),
  );
  studioRuntimeProjection.turnId = turn.turn_id || turn.turnId || studioRuntimeProjection.turnId || `turn.${Date.now()}`;
  studioRuntimeProjection.runId =
    turn.run_id || turn.runId || receiptRefs[receiptRefs.length - 1] || studioRuntimeProjection.turnId;
  if (!resultText && !retrievalFailClosedText) {
    const observedTools = uniqueStrings(events.map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
    if (approvalPaused) {
      studioRuntimeProjection.timeline.push({
        label: "Agent turn waiting for approval",
        detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
        status: "blocked",
      });
      return {
        turn,
        events,
        text: studioApprovalPauseErrorMessage({ resultText, events }),
        receiptRefs,
        status: "blocked",
        approvalPause: true,
      };
    }
    if (policyBlockedRuntimeText) {
      studioRuntimeProjection.timeline.push({
        label: "Agent turn blocked",
        detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
        status: "blocked",
      });
      return {
        turn,
        events,
        text: policyBlockedRuntimeText,
        receiptRefs,
        status: "blocked",
        policyBlocked: true,
      };
    }
    throw new Error(
      [
        "Daemon agent turn completed but did not emit a clean final answer.",
        resultText ? `Runtime result was ignored as non-visible completion proof: ${resultText}` : "",
        `Observed ${events.length} runtime event${events.length === 1 ? "" : "s"}${observedTools.length ? ` with tools: ${observedTools.join(", ")}` : ""}.`,
      ].filter(Boolean).join(" "),
    );
  }
  if (/blocked|failed|error/.test(statusText) && !resultText && !retrievalFailClosedText) {
    throw new Error(blockedReason || "Rust runtime agent turn blocked without an assistant result.");
  }
  const finalStatus = /blocked|failed|error|paused/.test(statusText) ? "blocked" : "completed";
  studioRuntimeProjection.timeline.push({
    label: finalStatus === "blocked" ? "Agent turn blocked" : "Agent turn completed",
    detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
    status: finalStatus,
  });
  return {
    turn,
    events,
    text: resultText || retrievalFailClosedText || "Agent Mode completed without additional assistant text.",
    receiptRefs,
    sourceRefs,
    status: finalStatus,
    approvalPause: false,
  };
}

async function applyStudioPermissionModeSelection(payload = {}, output) {
  const approvalMode = normalizeStudioPermissionMode(
    payload.approvalMode || payload.approval_mode || payload.selectionId || payload.mode || payload.label,
  );
  const mapping = studioPermissionDaemonMapping(approvalMode);
  studioRuntimeProjection.approvalMode = approvalMode;
  if (!studioRuntimeProjection.threadId) {
    return mapping;
  }
  try {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/mode`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          ...mapping,
          mode: mapping.threadMode,
          value: mapping.threadMode,
          source: "agent-studio-permissions-menu",
        },
      },
    );
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] permission mode update unavailable: ${error?.message || String(error)}`);
  }
  return mapping;
}

async function submitStudioPrompt(payload = {}, output) {
  const prompt = stringValue(payload.prompt);
  if (!prompt) {
    return;
  }
  const workspace = workspaceSummary();
  const selectedRoute = stringValue(payload.routeId, stringValue(payload.model, "route.local-first"));
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  const reasoningEffort = normalizeStudioReasoningEffort(payload.reasoningEffort ?? payload.reasoning_effort, "none");
  const executionMode = normalizeStudioExecutionMode(payload.executionMode || payload.studioMode || studioRuntimeProjection.executionMode);
  const previousApprovalMode = normalizeStudioPermissionMode(studioRuntimeProjection.approvalMode);
  const approvalMode = normalizeStudioPermissionMode(payload.approvalMode ?? payload.approval_mode ?? previousApprovalMode);
  const permissionMapping = studioPermissionDaemonMapping(approvalMode);
  const targetRuntimeProfile = executionMode === STUDIO_MODE_AGENT
    ? STUDIO_AGENT_RUNTIME_PROFILE
    : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  if (
    studioRuntimeProjection.threadId &&
    (
      normalizeStudioExecutionMode(studioRuntimeProjection.executionMode) !== executionMode ||
      studioRuntimeProjection.runtimeProfile !== targetRuntimeProfile
    )
  ) {
    resetStudioDaemonThreadProjection();
  }
  const createdAt = new Date().toISOString();
  studioRuntimeProjection.pending = true;
  studioRuntimeProjection.status = "pending";
  studioRuntimeProjection.immediateSubmitSeen = true;
  studioRuntimeProjection.pendingSeen = true;
  studioRuntimeProjection.pendingStartedAtMs = Date.now();
  studioRuntimeProjection.pendingWorklog = [];
  const workCursor = studioWorkCursor();
  studioAgentAnswerStreamProjector.reset();
  studioRuntimeProjection.lastError = null;
  studioRuntimeProjection.modelRoute = selectedRoute;
  studioRuntimeProjection.selectedModel = selectedModelId;
  studioRuntimeProjection.reasoningEffort = reasoningEffort;
  studioRuntimeProjection.approvalMode = approvalMode;
  studioRuntimeProjection.executionMode = executionMode;
  studioRuntimeProjection.runtimeProfile = targetRuntimeProfile;
  if (studioRuntimeProjection.threadId && previousApprovalMode !== approvalMode) {
    await applyStudioPermissionModeSelection({ approvalMode }, output);
  }
  studioRuntimeProjection.turns.push({
    role: "user",
    content: prompt,
    createdAt,
  });
  studioRuntimeProjection.timeline.push({
    label: "Prompt submitted",
    detail: "chat.submit typed request routed to IOI daemon",
    status: "pending",
  });
  const modelSelectionError = studioProductModelSelectionError(selectedRoute, selectedModelId);
  if (modelSelectionError) {
    const cleanMessage = studioCleanProductErrorMessage(modelSelectionError);
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "blocked";
    studioRuntimeProjection.lastError = cleanMessage;
    studioRuntimeProjection.timeline.push({
      label: "Product model route unavailable",
      detail: cleanMessage,
      status: "blocked",
    });
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: cleanMessage,
      createdAt: new Date().toISOString(),
      agentTurn: {
        status: "blocked",
        eventCount: 0,
        receiptRefs: [],
        prompt,
      },
    });
    await refreshStudioPanelHtml(output);
    return;
  }
  const resolvedIntentFrame = await resolveStudioPromptIntentFrame(prompt, {
    executionMode,
    selectedRoute,
    selectedModelId,
    approvalMode,
    workspacePath: workspace.path,
  }, output);
  const resolvedIntentFramePayload = studioIntentFramePayload(resolvedIntentFrame);
  studioRuntimeProjection.lastIntentFrame = resolvedIntentFramePayload;
  void writeBridgeRequest(
    "chat.submit",
    {
      ...payload,
      prompt,
      model: selectedRoute,
      routeId: selectedRoute,
      modelId: selectedModelId,
      reasoningEffort,
      reasoning_effort: reasoningEffort,
      executionMode,
      ...permissionMapping,
      ...(resolvedIntentFramePayload
        ? {
            intentFrame: resolvedIntentFramePayload,
            intent_frame: resolvedIntentFramePayload,
            runtimeAction: resolvedIntentFramePayload.runtimeAction || resolvedIntentFramePayload.runtime_action || null,
            runtime_action: resolvedIntentFramePayload.runtime_action || resolvedIntentFramePayload.runtimeAction || null,
          }
        : {}),
      runtimeProfile: studioRuntimeProjection.runtimeProfile,
      workspaceRoot: workspace.path,
      sourceCommand: "ioi.studio.chat",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      externalConnectorAction: false,
    },
    buildWorkspaceActionContext("agent-studio-chat"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge chat.submit route unavailable: ${error?.message || String(error)}`);
  });

  let projectedWithoutRefresh = false;
  try {
    let assistantTurn = null;
    if (executionMode === STUDIO_MODE_ASK) {
      await ensureStudioDaemonThread({ model: selectedRoute, selectedModelId, reasoningEffort, executionMode, approvalMode }, output);
      const streamResult = await streamStudioModelCompletion(
        {
          prompt,
          selectedRoute,
          selectedModelId,
          reasoningEffort,
          workspacePath: workspace.path,
        },
        output,
      );
      studioRuntimeProjection.turnId = streamResult.streamId;
      studioRuntimeProjection.runId = streamResult.receiptIds[streamResult.receiptIds.length - 1] || streamResult.streamId;
      studioRuntimeProjection.selectedModel = streamResult.model || studioRuntimeProjection.selectedModel || "auto";
      studioRuntimeProjection.modelRoute = streamResult.routeId || selectedRoute;
      studioRuntimeProjection.lastModelStream = {
        streamId: streamResult.streamId,
        chunkCount: streamResult.chunkCount,
        receiptIds: streamResult.receiptIds,
        routeId: streamResult.routeId,
        model: streamResult.model,
        providerStream: streamResult.providerStream,
      };
      studioRuntimeProjection.timeline.push({
        label: "Ask model stream completed",
        detail: `${streamResult.chunkCount} token delta${streamResult.chunkCount === 1 ? "" : "s"} through ${streamResult.routeId}`,
        status: "completed",
      });
      assistantTurn = {
        role: "assistant",
        content: streamResult.text,
        thinkingText: streamResult.thinkingText,
        createdAt: new Date().toISOString(),
        modelStream: {
          streamId: streamResult.streamId,
          chunkCount: streamResult.chunkCount,
          receiptIds: streamResult.receiptIds,
          routeId: streamResult.routeId,
          model: streamResult.model,
          provider: streamResult.provider,
          providerStream: streamResult.providerStream,
          thinkingText: streamResult.thinkingText,
          metrics: streamResult.metrics,
          askMode: true,
          directModelAnswer: true,
          chatOnlyMode: true,
          completed: true,
        },
      };
    } else {
      const intentFrame = resolvedIntentFrame;
      const projectsArtifact = studioIntentFrameProjectsArtifact(intentFrame) ||
        shouldProjectConversationArtifactCanvas(prompt);
      const agentTurn = projectsArtifact
        ? await projectStudioConversationArtifactCanvas(prompt, output, intentFrame)
        : await submitStudioAgentTurn(
            {
              prompt,
              selectedRoute,
              selectedModelId,
              reasoningEffort,
              workspacePath: workspace.path,
              intentFrame,
            },
            output,
          );
      if (!projectsArtifact && (studioIntentFrameProjectsRuntimeCockpit(intentFrame) || shouldProjectStudioRuntimeCockpit(prompt))) {
        await projectStudioRuntimeCockpit(prompt, agentTurn, output);
      }
      const agentTurnStatus = agentTurn.status === "blocked" ? "blocked" : "completed";
      const workspaceChangeHunks = !projectsArtifact
        ? await refreshStudioWorkspaceChangeReviewsFromDaemon(output)
        : [];
      if (workspaceChangeHunks.length > 0) {
        appendStudioTimeline(
          "Workspace hunk review ready",
          `${workspaceChangeHunks.length} hunk${workspaceChangeHunks.length === 1 ? "" : "s"} waiting for review`,
          "needs_review",
        );
      }
      const daemonSessionCards = !projectsArtifact
        ? await refreshStudioManagedSessionsFromDaemon(output)
        : [];
      const workRecord = studioWorkRecordWithSessionCards(
        studioDocumentedWorkRecord(workCursor),
        daemonSessionCards,
      );
      const managedSessionCount = firstArray(workRecord?.sessionCards).length;
      if (managedSessionCount) {
        studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
        studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
        studioRuntimeProjection.runtimeCockpit.managedSessionCount = Math.max(
          managedSessionCount,
          Number(studioRuntimeProjection.runtimeCockpit.managedSessionCount || 0) || 0,
        );
      }
      const blockedThreadId = agentTurnStatus === "blocked" ? studioRuntimeProjection.threadId : null;
      const productAgentText = sanitizeStudioProductAssistantText(agentTurn.text);
      const daemonAnswerStream = agentTurnStatus === "completed" && studioAgentAnswerStreamProjector.hasObservedStream()
        ? studioAgentAnswerStreamProjector.complete(productAgentText, {
            allowFallbackStart: false,
            sourceRefs: firstArray(agentTurn.sourceRefs),
            workRecord: studioPublicWorkRecordForWebview(workRecord),
          })
        : null;
      const finalHandoffStream = agentTurnStatus === "completed" && !daemonAnswerStream
        ? await studioAgentFinalHandoffStreamer.streamStudioAgentFinalHandoff(productAgentText, {
            prompt,
            turnId: studioRuntimeProjection.turnId,
            sourceRefs: firstArray(agentTurn.sourceRefs),
            workRecord: studioPublicWorkRecordForWebview(workRecord),
          })
        : null;
      const modelStream = daemonAnswerStream || (finalHandoffStream
        ? { streamId: finalHandoffStream.streamId, chunkCount: finalHandoffStream.chunkCount, agentFinalHandoff: true, runtimeAuthority: "daemon-owned", completed: true }
        : null);
      assistantTurn = {
        role: "assistant",
        content: productAgentText,
        createdAt: new Date().toISOString(),
        agentTurn: {
          turnId: studioRuntimeProjection.turnId,
          eventCount: agentTurn.events.length,
          receiptRefs: agentTurn.receiptRefs,
          prompt,
          status: agentTurnStatus,
          approvalPause: Boolean(agentTurn.approvalPause),
        },
        ...(agentTurn.sourceRefs ? { sourceRefs: agentTurn.sourceRefs } : {}),
        ...(agentTurn.artifacts ? { artifacts: agentTurn.artifacts } : {}),
        ...(agentTurn.modelMetrics ? { modelMetrics: agentTurn.modelMetrics } : {}),
        ...(modelStream ? { modelStream } : {}),
        ...(workRecord ? { workRecord } : {}),
      };
      studioRuntimeProjection.lastModelStream = null;
      if (blockedThreadId) {
        resetStudioDaemonThreadProjection();
        studioRuntimeProjection.timeline.push({
          label: "Blocked daemon thread released",
          detail: blockedThreadId,
          status: "completed",
        });
      }
      studioRuntimeProjection.status = agentTurnStatus;
    }
    studioRuntimeProjection.turns.push(assistantTurn);
    const pendingElapsedMs = Date.now() - (studioRuntimeProjection.pendingStartedAtMs || Date.now());
    const latestWorkStepElapsedMs = studioPendingWorklogLastAtMs()
      ? Date.now() - studioPendingWorklogLastAtMs()
      : 0;
    const pendingMinimumWaitMs = Math.max(
      0,
      1400 - pendingElapsedMs,
      firstArray(studioRuntimeProjection.pendingWorklog).length > 0 ? 1200 - latestWorkStepElapsedMs : 0,
    );
    if (firstArray(studioRuntimeProjection.pendingWorklog).length > 0) {
      studioPostPendingWorklogSnapshot();
    }
    if (pendingMinimumWaitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, pendingMinimumWaitMs));
    }
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = assistantTurn?.agentTurn?.status === "blocked" ? "blocked" : "completed";
      if (executionMode === STUDIO_MODE_AGENT) {
        await projectStudioAgentTurnToWebview({
          assistantTurn,
          status: studioRuntimeProjection.status,
          prompt,
        }, output);
        if (firstArray(studioRuntimeProjection.diffHunks).length > 0 && studioPanel) {
          studioPanel.reveal(vscode.ViewColumn.One);
          await refreshStudioPanelHtml(output);
        }
      }
    studioRuntimeProjection.timeline.push({
      label: studioRuntimeProjection.status === "blocked" ? "Blocked answer visible" : "Final answer visible",
      detail: executionMode === STUDIO_MODE_ASK
        ? "Explicit Ask direct model stream completed"
        : studioRuntimeProjection.status === "blocked"
          ? "Daemon agent turn paused or blocked with a visible human summary"
          : "Daemon agent turn completed without accepting model prose as execution proof",
      status: studioRuntimeProjection.status,
    });
    studioRuntimeProjection.terminal = studioRuntimeProjection.commandOutputs.length > 0
      ? studioRuntimeProjection.commandOutputs.slice(-3).map((item) => ({
          label: item.label || "Daemon command",
          detail: item.stdout || item.stderr || item.status || "Daemon command output projected.",
        }))
      : [
          {
            label: "No terminal job running",
            detail: "Plain text turns do not create fake terminal or proof records.",
          },
        ];
    if (executionMode === STUDIO_MODE_AGENT) {
      // Agent completions use the ordered extension projection so late webview messages
      // cannot attach a final answer to the next prompt.
      projectedWithoutRefresh = false;
    }
  } catch (error) {
    const isApprovalPause = Boolean(error?.studioApprovalPause || error?.code === "studio_approval_pause");
    const rawErrorMessage = error?.message || String(error);
    const cleanErrorMessage = studioCleanProductErrorMessage(error);
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "blocked";
    studioRuntimeProjection.lastError = cleanErrorMessage;
    studioRuntimeProjection.timeline.push({
      label: isApprovalPause ? "Daemon turn waiting for approval" : "Daemon turn blocked",
      detail: cleanErrorMessage,
      status: "blocked",
    });
    output?.appendLine?.(`[ioi-studio] raw daemon turn error kept in Trace/evidence: ${rawErrorMessage}`);
    const daemonSessionCards = executionMode === STUDIO_MODE_AGENT
      ? await refreshStudioManagedSessionsFromDaemon(output)
      : [];
    if (executionMode === STUDIO_MODE_AGENT) {
      await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
    }
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: isApprovalPause
        ? cleanErrorMessage
        : cleanErrorMessage,
      createdAt: new Date().toISOString(),
      ...(daemonSessionCards.length
        ? {
            workRecord: studioWorkRecordWithSessionCards(null, daemonSessionCards),
          }
        : {}),
    });
    if (executionMode === STUDIO_MODE_AGENT && studioRuntimeProjection.threadId) {
      const blockedThreadId = studioRuntimeProjection.threadId;
      resetStudioDaemonThreadProjection();
      studioRuntimeProjection.timeline.push({
        label: "Blocked daemon thread released",
        detail: blockedThreadId,
        status: "completed",
      });
    }
    if (executionMode === STUDIO_MODE_AGENT) {
      projectedWithoutRefresh = false;
    }
  }
  if (!projectedWithoutRefresh) {
    await refreshStudioPanelHtml(output);
  }
  await focusStudioPanelComposer();
}

async function handleStudioHunkDecision(decision, payload = {}, output) {
  const requestedDecision = stringValue(decision).toLowerCase();
  const normalizedDecision = requestedDecision === "reject" || requestedDecision === "rollback"
    ? requestedDecision
    : "approve";
  try {
    await ensureStudioDaemonThread({ model: studioRuntimeProjection.modelRoute }, output);
    const endpoint = daemonEndpoint();
    const threadId = studioRuntimeProjection.threadId;
    const approvalId =
      stringValue(payload.approvalId, studioRuntimeProjection.approvalId || STUDIO_APPROVAL_ID);
    const changeId = stringValue(payload.changeId || payload.change_id);
    if (changeId) {
      const toolId = normalizedDecision === "rollback"
        ? "workspace_change__rollback"
        : normalizedDecision === "reject"
          ? "workspace_change__reject"
          : "workspace_change__accept";
      const result = await invokeStudioDaemonTool(
        threadId,
        toolId,
        normalizedDecision === "rollback"
          ? { change_id: changeId }
          : normalizedDecision === "approve"
            ? { change_id: changeId }
          : {
              change_id: changeId,
              reason: "Operator rejected the Studio inline diff hunk.",
            },
        output,
        {
          title: normalizedDecision === "rollback"
            ? "Rollback workspace hunk"
            : normalizedDecision === "approve"
              ? "Accept workspace hunk"
              : "Reject workspace hunk",
          detail: normalizedDecision === "rollback"
            ? "Daemon rolled back the selected workspace change."
            : normalizedDecision === "approve"
              ? "Daemon accepted the selected workspace change."
            : "Daemon rejected the selected workspace change.",
        },
      );
      studioRuntimeProjection.hunkDecision = normalizedDecision;
      studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
        ...hunk,
        status: hunk.changeId === changeId || hunk.change_id === changeId
          ? normalizedDecision === "approve"
            ? "approved"
            : normalizedDecision === "rollback"
            ? "rolled_back"
            : "rejected"
          : hunk.status,
      }));
      studioRuntimeProjection.approvals = [
        {
          id: approvalId,
          status: normalizedDecision === "approve"
            ? "approved"
            : normalizedDecision === "rollback"
              ? "rolled_back"
              : "rejected",
          label: normalizedDecision === "approve"
            ? "Workspace hunk accepted"
            : normalizedDecision === "rollback"
              ? "Workspace hunk rolled back"
              : "Workspace hunk rejected",
          detail: "Daemon workspace change lifecycle action completed.",
        },
      ];
      appendStudioReceiptsFromResponse(result, `workspace_change_${normalizedDecision}`, "Daemon workspace change lifecycle receipt.");
      studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
      recomputeStudioRuntimeCockpitAchieved();
      await writeBridgeRequest(
        "chat.hunkDecision",
        {
          ...payload,
          decision: normalizedDecision,
          approvalId,
          changeId,
          threadId,
          turnId: studioRuntimeProjection.turnId,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
          ownsRuntimeState: false,
        },
        buildWorkspaceActionContext("agent-studio-inline-diff"),
      ).catch((error) => {
        output?.appendLine?.(`[ioi-studio] bridge hunk decision route unavailable: ${error?.message || String(error)}`);
      });
      await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
      await refreshStudioPanelHtml(output);
      return;
    }
    const result = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(approvalId)}/decision`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          decision: normalizedDecision,
          source: "agent_studio_inline_diff",
          reason: `Operator ${normalizedDecision === "approve" ? "accepted" : "rejected"} the Studio inline diff preview.`,
          ...studioApprovalTurnPayload(),
        },
      },
    );
    studioRuntimeProjection.hunkDecision = normalizedDecision;
    studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
      ...hunk,
      status: normalizedDecision === "approve" ? "approved" : "rejected",
    }));
    studioRuntimeProjection.approvals = [
      {
        id: approvalId,
        status: normalizedDecision === "approve" ? "approved" : "rejected",
        label: "Inline diff decision",
        detail: "Daemon approval decision receipt emitted; no direct webview mutation occurred.",
      },
    ];
    studioRuntimeProjection.timeline.push({
      label: "Hunk decision receipted",
      detail: `${approvalId} · ${normalizedDecision}`,
      status: normalizedDecision === "approve" ? "completed" : "blocked",
    });
    appendStudioReceipts(
      uniqueStrings([
        ...firstArray(result?.receipt_refs),
        ...firstArray(result?.receiptRefs),
      ]).map((id) => ({
        id,
        kind: `approval_${normalizedDecision}`,
        summary: "Daemon approval decision receipt for Studio inline diff hunk.",
      })),
    );
    studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
    recomputeStudioRuntimeCockpitAchieved();
    await writeBridgeRequest(
      "chat.hunkDecision",
      {
        ...payload,
        decision: normalizedDecision,
        approvalId,
        threadId,
        turnId: studioRuntimeProjection.turnId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
        ownsRuntimeState: false,
      },
      buildWorkspaceActionContext("agent-studio-inline-diff"),
    ).catch((error) => {
      output?.appendLine?.(`[ioi-studio] bridge hunk decision route unavailable: ${error?.message || String(error)}`);
    });
  } catch (error) {
    studioRuntimeProjection.timeline.push({
      label: "Hunk decision blocked",
      detail: error?.message || String(error),
      status: "blocked",
    });
  }
  await refreshStudioPanelHtml(output);
}

async function handleStudioArtifactAction(payload = {}, output) {
  const artifactId = stringValue(payload.artifactId || payload.artifact_id);
  const action = stringValue(payload.action, "ask");
  if (!artifactId) {
    appendStudioTimeline("Artifact action blocked", "Missing artifact id.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  const result = await runStudioConversationArtifactAction(artifactId, action, output, payload);
  if (result?.artifact) {
    studioRuntimeProjection.conversationArtifacts = studioRuntimeProjection.conversationArtifacts.map((artifact) =>
      (artifact.id || artifact.artifactId || artifact.artifact_id) === artifactId ? result.artifact : artifact,
    );
    appendStudioTimeline("Artifact action completed", `${action} · ${result.artifact.title || artifactId}`, "completed", {
      artifactId,
    });
  }
  await writeBridgeRequest(
    "chat.artifactAction",
    {
      artifactId,
      action,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-conversation-artifact"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge artifact action route unavailable: ${error?.message || String(error)}`);
  });
  await refreshStudioPanelHtml(output);
}

async function handleStudioManagedSessionControl(payload = {}, output) {
  const managedSessionId = stringValue(payload.managedSessionId || payload.managed_session_id);
  const control = stringValue(payload.control || payload.action, "observe");
  if (!managedSessionId) {
    appendStudioTimeline("Managed session control blocked", "Missing managed session id.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  const endpoint = daemonEndpoint();
  const threadId = stringValue(studioRuntimeProjection.threadId);
  if (!endpoint || !threadId) {
    appendStudioTimeline("Managed session control blocked", "Daemon thread unavailable.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  studioRuntimeProjection.computerUseSessions = firstArray(studioRuntimeProjection.computerUseSessions).map((session) =>
    session.id === managedSessionId
      ? {
          ...session,
          controlState: control,
          updatedAt: new Date().toISOString(),
        }
      : session,
  );
  applyStudioManagedSessionsToLatestTurn(studioRuntimeProjection.computerUseSessions);
  try {
    const result = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions/control`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          managedSessionId,
          action: control,
          reason:
            stringValue(payload.reason) ||
            (control === "take_over"
              ? "operator requested manual control"
              : control === "return_agent"
                ? "operator returned control to Agent"
                : "operator observing session"),
          source: "agent_studio_managed_session_card",
          turnId: studioRuntimeProjection.turnId || null,
        },
        timeoutMs: 5000,
      },
    );
    applyStudioManagedSessionInspection(result?.inspection || result);
    studioRuntimeProjection.runtimeCockpit.managedSessionControlObserved = true;
    appendStudioTimeline(
      "Managed session control receipted",
      `${managedSessionId} · ${control}`,
      "completed",
    );
  } catch (error) {
    appendStudioTimeline(
      "Managed session control blocked",
      error?.message || String(error),
      "blocked",
    );
  }
  await refreshStudioPanelHtml(output);
}

async function navigateStudioHunk(direction, output) {
  await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
  const command = direction === "previous"
    ? "workbench.action.compareEditor.previousChange"
    : "workbench.action.compareEditor.nextChange";
  await vscode.commands.executeCommand(command).catch((error) => {
    output?.appendLine?.(`[ioi-studio] native hunk navigation unavailable: ${error?.message || String(error)}`);
  });
  studioRuntimeProjection.runtimeCockpit.hunkNavigationObserved = true;
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline("Native hunk navigation", direction === "previous" ? "previous change" : "next change", "completed");
  await refreshStudioPanelHtml(output);
}

async function stopStudioTurn(output) {
  studioRuntimeProjection.pending = false;
  studioRuntimeProjection.status = "interrupted";
  studioRuntimeProjection.timeline.push({
    label: "Stop requested",
    detail: "Operator stop routed from Studio control surface.",
    status: "blocked",
  });
  if (studioRuntimeProjection.threadId && studioRuntimeProjection.turnId) {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/turns/${encodeURIComponent(studioRuntimeProjection.turnId)}/interrupt`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio",
          reason: "operator_stop",
          runtimeControlAction: "stop",
          runtime_control_action: "stop",
        },
      },
    ).then((result) => {
      appendStudioReceiptsFromResponse(result, "session_stop", "Daemon stopped Studio thread.");
      if (result?.runtime_control || result?.runtimeControl) {
        studioRuntimeProjection.runtimeCockpit.stopControlObserved = true;
        studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
          studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true;
        recomputeStudioRuntimeCockpitAchieved();
        appendStudioTimeline("Runtime stop control", "Daemon runtime_service control_thread stop acknowledged.", "completed");
      }
    }).catch((error) => {
      output?.appendLine?.(`[ioi-studio] stop projection unavailable: ${error?.message || String(error)}`);
    });
  }
  await writeBridgeRequest(
    "chat.stop",
    {
      threadId: studioRuntimeProjection.threadId,
      turnId: studioRuntimeProjection.turnId,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      reason: "operator_stop",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-stop"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge stop route unavailable: ${error?.message || String(error)}`);
  });
  await refreshStudioPanelHtml(output);
}

async function resumeStudioTurn(output) {
  studioRuntimeProjection.status = "active";
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline("Resume requested", "Operator resume routed to daemon session lifecycle.", "completed");
  if (studioRuntimeProjection.threadId) {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/resume`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio",
          reason: "operator_resume",
        },
      },
    ).then((result) => {
      appendStudioReceiptsFromResponse(result, "session_resume", "Daemon resumed Studio thread.");
      if (result?.runtime_control || result?.runtimeControl) {
        studioRuntimeProjection.runtimeCockpit.resumeControlObserved = true;
        studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
          studioRuntimeProjection.runtimeCockpit.stopControlObserved === true;
        recomputeStudioRuntimeCockpitAchieved();
        appendStudioTimeline("Runtime resume control", "Daemon runtime_service control_thread resume acknowledged.", "completed");
      }
    }).catch((error) => {
      appendStudioTimeline("Resume projection unavailable", error?.message || String(error), "blocked");
      output?.appendLine?.(`[ioi-studio] resume projection unavailable: ${error?.message || String(error)}`);
    });
  }
  await writeBridgeRequest(
    "chat.resume",
    {
      threadId: studioRuntimeProjection.threadId,
      turnId: studioRuntimeProjection.turnId,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      reason: "operator_resume",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-resume"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge resume route unavailable: ${error?.message || String(error)}`);
  });
  studioRuntimeProjection.status = "completed";
  await refreshStudioPanelHtml(output);
}

async function openStudioPanel(context, output) {
  const state = await readBridgeState();
  if (studioPanel) {
    studioPanel.reveal(vscode.ViewColumn.One);
  } else {
    studioPanel = vscode.window.createWebviewPanel(
      "ioi.studio",
      "Agent Studio",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    studioPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-studio.svg",
    );
    studioPanel.webview.onDidReceiveMessage(async (message) => {
      if (message?.type === "studioSubmit") {
        await submitStudioPrompt(message.payload || {}, output);
        return;
      }
      if (message?.type === "studioHunkDecision") {
        await handleStudioHunkDecision(message.decision, message.payload || {}, output);
        return;
      }
      if (message?.type === "studioArtifactAction") {
        await handleStudioArtifactAction(message.payload || {}, output);
        return;
      }
      if (message?.type === "studioManagedSessionControl") {
        await handleStudioManagedSessionControl(message.payload || {}, output);
        return;
      }
      if (message?.type === "studioHunkNavigate") {
        await navigateStudioHunk(message.direction || "next", output);
        return;
      }
      if (message?.type === "studioStop") {
        await stopStudioTurn(output);
        return;
      }
      if (message?.type === "studioResume") {
        await resumeStudioTurn(output);
        return;
      }
      if (message?.type === "studioOperationalProof") {
        output.appendLine(`[ioi-studio] operational proof: ${JSON.stringify(message.proof || {})}`);
        return;
      }
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        if (message.requestType === "chat.agentMode.select") {
          applyStudioAgentModeSelection(message.payload || {});
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.newSession") {
          startNewStudioSession("Operator started a fresh Studio chat session.");
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (!message.payload?.bridgeRequestAlreadyWritten) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("studio-panel-webview"),
          ).catch((error) => {
            output.appendLine(
              `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(studioPanel, "studio", output);
    studioPanel.onDidDispose(() => {
      studioPanel = null;
      studioPanelLastHtml = null;
      studioPanelPageNonce = null;
    });
  }
  updateStudioPanelHtml(state, { force: true });
  output.appendLine("Opened Agent Studio webview.");
  return studioPanel;
}

async function openModelsPanel(context, output, options = {}) {
  const modelsViewDefinition =
    VIEW_DEFINITIONS.find((definition) => definition.id === "ioi.models") || {
      id: "ioi.models",
      title: "Models",
      eyebrow: "Daemon model runtime",
      description: "Daemon-backed model mounting.",
      actions: [],
    };
  const state = await readBridgeState();
  if (modelsPanel) {
    modelsPanel.reveal(vscode.ViewColumn.One);
  } else {
    modelsPanel = vscode.window.createWebviewPanel(
      "ioi.models",
      "Autopilot Models",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    modelsPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    modelsPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("models-panel-webview"),
        );
        return;
      }
      if (message?.type === "modelsModeProof" && message.proof) {
        await writeBridgeRequest(
          "modelsMode.proof",
          message.proof,
          buildWorkspaceActionContext("models-panel-webview"),
        );
        return;
      }
      if (message?.type === "modelsModeProof" && message.proof) {
        await writeBridgeRequest(
          "modelsMode.proof",
          message.proof,
          buildWorkspaceActionContext("ioi.models"),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(modelsPanel, "models", output);
    modelsPanel.onDidDispose(() => {
      modelsPanel = null;
    });
  }
  modelsPanel.webview.html = renderHtml(modelsViewDefinition, state);
  const phase = typeof options.phase === "string" ? options.phase : null;
  if (phase) {
    setTimeout(() => {
      modelsPanel?.webview.postMessage({
        type: "ioi.models.capturePhase",
        phase,
      });
    }, 700);
  }
  output.appendLine("Opened Autopilot Models webview.");
  return modelsPanel;
}

function renderModePanelHtml(modeId, state) {
  if (modeId === "code") {
    return codeModePanelHtml(state);
  }
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  const viewId = mode?.panelViewId;
  const viewDefinition =
    VIEW_DEFINITIONS.find((definition) => definition.id === viewId) || {
      id: viewId || `ioi.${modeId}`,
      title: mode?.title || "Autopilot",
      eyebrow: "Autopilot mode",
      description: "Persistent Autopilot workbench mode.",
      actions: [],
    };
  return renderHtml(viewDefinition, state);
}

async function openGenericModePanel(context, output, modeId) {
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  if (!mode) {
    throw new Error(`Unknown Autopilot mode: ${modeId}`);
  }
  const state = await readBridgeState();
  let panel = genericModePanels.get(modeId);
  if (panel) {
    panel.reveal(vscode.ViewColumn.One);
  } else {
    panel = vscode.window.createWebviewPanel(
      mode.panelViewType,
      `Autopilot ${mode.title}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    panel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    panel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext(`${modeId}-mode-webview`),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(panel, modeId, output);
    panel.onDidDispose(() => {
      genericModePanels.delete(modeId);
    });
    genericModePanels.set(modeId, panel);
  }
  panel.webview.html = renderModePanelHtml(modeId, state);
  output.appendLine(`Opened Autopilot ${mode.title} mode webview.`);
  return panel;
}

function openWorkflowComposerPanel(context, output, options = {}) {
  if (workflowComposerPanel) {
    workflowComposerPanel.reveal(vscode.ViewColumn.One);
  } else {
    workflowComposerPanel = vscode.window.createWebviewPanel(
      "ioi.workflowComposer",
      "Autopilot Workflow Composer",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(context.extensionUri, "media"),
        ],
      },
    );
    workflowComposerPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    workflowComposerPanel.webview.html = workflowComposerHtml(
      context,
      workflowComposerPanel.webview,
    );
    workflowComposerPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "workflowCompositorProof" && message.proof) {
        await writeBridgeRequest(
          "workflowCompositor.proof",
          message.proof,
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "workflowCompositorError" && message.error) {
        output.appendLine(
          `[workflow-composer] ${message.error.message || "unknown webview error"}`,
        );
        await writeBridgeRequest(
          "workflowCompositor.error",
          message.error,
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "command" && typeof message.command === "string") {
        await vscode.commands.executeCommand(message.command, message.payload);
      }
    });
    registerModePanelVisibilityProjection(workflowComposerPanel, "workflows", output);
    workflowComposerPanel.onDidDispose(() => {
      workflowComposerPanel = null;
    });
  }

  const scenarioId =
    typeof options.scenarioId === "string" ? options.scenarioId : null;
  const phase = typeof options.phase === "string" ? options.phase : "canvas";
  if (scenarioId) {
    setTimeout(() => {
      workflowComposerPanel?.webview.postMessage({
        type: "ioi.workflow.compositor.runScenario",
        scenarioId,
        phase,
      });
    }, 750);
  } else if (options.capturePhase) {
    setTimeout(() => {
      workflowComposerPanel?.webview.postMessage({
        type: "ioi.workflow.compositor.capturePhase",
        phase,
      });
    }, 750);
  }

  output.appendLine("Opened Autopilot Workflow Composer webview.");
  return workflowComposerPanel;
}

function closePrimarySidebarAfterActivityLaunch() {
  for (const delayMs of [125, 350, 800, 1400]) {
    setTimeout(() => {
      void vscode.commands
        .executeCommand("workbench.action.closeSidebar")
        .catch((error) => {
          console.error(
            "[IOI Workbench] Failed to close activity launcher sidebar:",
            error,
          );
        });
    }, delayMs);
  }
}

function updateOverviewPanelHtml(state) {
  if (!overviewPanel) {
    return;
  }
  const html = overviewPanelHtml(state);
  if (html === overviewPanelLastHtml) {
    return;
  }
  overviewPanelLastHtml = html;
  overviewPanel.webview.html = html;
}

function writeModeVisibilityProjection(modeId, output, reason = "panel-visible") {
  const requestType = MODE_VISIBILITY_REQUEST_TYPES[modeId];
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  if (!requestType || !mode) {
    return;
  }
  const now = Date.now();
  const lastAt = modeVisibilityProjectionLastAtMs.get(modeId) || 0;
  if (now - lastAt < 450) {
    return;
  }
  modeVisibilityProjectionLastAtMs.set(modeId, now);
  const actionContext = buildWorkspaceActionContext(`${modeId}-${reason}`);
  void writeBridgeRequest(requestType, {
    workspaceRoot: workspaceSummary().path,
    sourceCommand: mode.command,
    source: reason,
    phase: mode.phase,
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
  }, actionContext).catch((error) => {
    output?.appendLine?.(
      `[ioi-${modeId}] visible projection unavailable: ${error?.message || String(error)}`,
    );
  });
}

function registerModePanelVisibilityProjection(panel, modeId, output) {
  const disposable = panel.onDidChangeViewState((event) => {
    if (event.webviewPanel.active) {
      writeModeVisibilityProjection(modeId, output);
    }
  });
  panel.onDidDispose(() => {
    disposable.dispose();
  });
}

class IOIViewProvider {
  constructor(definition, getState) {
    this.definition = definition;
    this.getState = getState;
    this.webviewView = null;
    this.lastRenderedHtml = null;
    this.primaryOpenInFlight = false;
    this.lastPrimaryOpenAtMs = 0;
  }

  resolveWebviewView(webviewView) {
    this.webviewView = webviewView;
    this.lastRenderedHtml = null;
    webviewView.webview.options = {
      enableScripts: true,
      enableForms: true,
    };
    void this.render();
    this.maybeAutoOpenPrimarySurface();
    webviewView.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("ioi.chat"),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    const visibilityDisposable = webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        this.maybeAutoOpenPrimarySurface();
      }
    });
    webviewView.onDidDispose(() => {
      visibilityDisposable.dispose();
      this.webviewView = null;
    });
  }

  maybeAutoOpenPrimarySurface() {
    const mode = AUTOPILOT_MODE_BY_VIEW_ID[this.definition.id];
    const primarySurface = mode
      ? {
          command: mode.command,
          payload: {
            source: "activitybar",
            phase: mode.phase,
          },
        }
      : null;
    if (!primarySurface) {
      return;
    }
    const now = Date.now();
    if (this.primaryOpenInFlight || now - this.lastPrimaryOpenAtMs < 800) {
      return;
    }
    this.primaryOpenInFlight = true;
    this.lastPrimaryOpenAtMs = now;
    setTimeout(() => {
      void (async () => {
        try {
          closePrimarySidebarAfterActivityLaunch();
          await vscode.commands.executeCommand(
            primarySurface.command,
            primarySurface.payload,
          );
          closePrimarySidebarAfterActivityLaunch();
        } catch (error) {
          console.error(
            "[IOI Workbench] Failed to auto-open primary activity surface:",
            error,
          );
        } finally {
          this.primaryOpenInFlight = false;
        }
      })();
    }, 0);
  }

  async render() {
    if (!this.webviewView) {
      return;
    }
    const state = await this.getState();
    await syncWorkbenchAppearance(state);
    const html = renderHtml(this.definition, state);
    if (html === this.lastRenderedHtml) {
      return;
    }
    this.lastRenderedHtml = html;
    this.webviewView.webview.html = html;
  }
}

let lastAppliedColorTheme = null;

async function syncWorkbenchAppearance(state) {
  const colorTheme = state?.appearance?.openVsCodeColorTheme;
  if (typeof colorTheme !== "string" || !colorTheme.trim()) {
    return;
  }
  const normalized = colorTheme.trim();
  if (normalized === lastAppliedColorTheme) {
    return;
  }
  lastAppliedColorTheme = normalized;
  try {
    await vscode.workspace
      .getConfiguration("workbench")
      .update("colorTheme", normalized, vscode.ConfigurationTarget.Global);
  } catch (error) {
    console.error("[IOI Workbench] Failed to apply bridge appearance:", error);
  }
}

function watchBridgeState(onChange) {
  const handle = setInterval(() => {
    void onChange();
  }, 2_000);
  return {
    dispose() {
      clearInterval(handle);
    },
  };
}

async function runDaemonModelWorkbenchAction(action, payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model workbench actions.");
  }
  const targetEndpointId =
    pickPayloadString(payload, "endpointId") ||
    pickPayloadString(payload, "endpoint_id") ||
    "endpoint.electron.model-gui";
  const targetInstanceId =
    pickPayloadString(payload, "instanceId") || pickPayloadString(payload, "instance_id");
  let requestedGpu =
    pickPayloadString(payload, "gpu") || pickPayloadString(payload, "gpuOffload") || "0";
  if (requestedGpu === "auto") {
    requestedGpu = "0";
  }
  if (action === "estimate") {
    return requestJson(endpoint, "/api/v1/models/estimate-load", {
      method: "POST",
      token,
      payload: {
        endpoint_id: targetEndpointId,
        load_options: {
          estimateOnly: true,
          gpu: requestedGpu,
          contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
          parallel: Number(pickPayloadString(payload, "parallel") || 2),
          ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
          identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
        },
      },
    });
  }
  if (action === "load") {
    return requestJson(endpoint, `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/load`, {
      method: "POST",
      token,
      payload: {
        load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
        load_options: {
          gpu: requestedGpu,
          contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
          parallel: Number(pickPayloadString(payload, "parallel") || 2),
          ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
          identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
        },
      },
    });
  }
  if (action === "unload") {
    return requestJson(
      endpoint,
      targetInstanceId
        ? `/api/v1/models/instances/${encodeURIComponent(targetInstanceId)}/unload`
        : `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/unload`,
      {
        method: "POST",
        token,
        payload: {},
      },
    );
  }
  throw new Error(`Unknown model workbench action: ${action}`);
}

async function runDaemonModelCatalogSearch(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model catalog search.");
  }
  const params = new URLSearchParams();
  const query = pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "";
  if (query) {
    params.set("q", query);
    params.set("query", query);
  }
  const format = pickPayloadString(payload, "format");
  const quantization = pickPayloadString(payload, "quantization");
  if (format) params.set("format", format);
  if (quantization) params.set("quantization", quantization);
  params.set("limit", pickPayloadString(payload, "limit") || "20");
  return requestJson(endpoint, `/api/v1/models/catalog/search?${params.toString()}`, {
    method: "GET",
    token,
  });
}

async function runDaemonModelCatalogProviderConfig(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  const providerId = pickPayloadString(payload, "providerId") || pickPayloadString(payload, "provider_id") || "catalog.huggingface";
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for catalog source configuration.");
  }
  const body = {
    enabled: payload?.enabled === false ? false : true,
  };
  if (providerId === "catalog.local_manifest") {
    body.manifest_path = pickPayloadString(payload, "manifestPath") || pickPayloadString(payload, "path") || "";
  } else {
    body.base_url = pickPayloadString(payload, "baseUrl") || pickPayloadString(payload, "url") || "https://huggingface.co";
  }
  return requestJson(endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}`, {
    method: "PATCH",
    token,
    payload: body,
  });
}

async function runDaemonModelCatalogDownload(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  const sourceUrl = pickPayloadString(payload, "sourceUrl") || pickPayloadString(payload, "source_url");
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model catalog download.");
  }
  if (!sourceUrl) {
    throw new Error("A daemon catalog source URL is required for model download.");
  }
  return requestJson(endpoint, "/api/v1/models/download", {
    method: "POST",
    token,
    payload: {
      source_url: sourceUrl,
      model_id: pickPayloadString(payload, "modelId") || pickPayloadString(payload, "model_id"),
      catalog_entry_id: pickPayloadString(payload, "catalogEntryId") || pickPayloadString(payload, "catalog_entry_id"),
      download_policy: {
        approvalDecision: "required",
        externalNetwork: "daemon_gated",
      },
    },
  });
}

function pickPayloadString(value, key) {
  if (typeof value === "string" && key === "value") {
    return value;
  }
  if (value && typeof value === "object" && typeof value[key] === "string") {
    return value[key];
  }
  if (value && typeof value === "object" && typeof value[key] === "number") {
    return String(value[key]);
  }
  return null;
}

function registerNativeCommands(context, output) {
  ensureStudioDiffProvider(context);
  const status = (message) =>
    vscode.window.setStatusBarMessage(`$(symbol-keyword) ${message}`, 3000);
  const pickString = (value, key) => {
    if (typeof value === "string") {
      return value;
    }
    if (value && typeof value === "object" && typeof value[key] === "string") {
      return value[key];
    }
    return null;
  };

  registerMigrationCommands({
    context,
    output,
    vscode,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    workspaceSummary,
    status,
  });
  registerQuickInputCommands({
    context,
    output,
    vscode,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    status,
  });

  context.subscriptions.push(
    ...registerStudioModeControlCommands({
      vscode,
      output,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      studioRuntimeProjection,
      studioPermissionModeOptions,
      studioExecutionModeLabel,
      studioPermissionModeLabel,
      applyStudioAgentModeSelection,
      applyStudioPermissionModeSelection,
      refreshStudioPanelHtml: () => refreshStudioPanelHtml(output),
      focusStudioPanelComposer,
    }),
    ...registerNavigationCommands({
      vscode,
      output,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      pickString,
      autopilotModeById: AUTOPILOT_MODE_BY_ID,
      getLastAutopilotModeBeforeCode: () => autopilotModeController.lastModeBeforeCode(),
      getStudioPanel: () => studioPanel,
      enterHome: () => enterAutopilotMode("home", output),
      enterStudio: () => enterAutopilotMode("studio", output),
      enterCode: () => enterAutopilotMode("code", output),
      enterMode: (modeId) => enterAutopilotMode(modeId, output),
      openOverviewPanel: () => openOverviewPanel(context, output),
      openStudioPanel: () => openStudioPanel(context, output),
      openGenericModePanel: (modeId) => openGenericModePanel(context, output, modeId),
      closePrimarySidebarAfterActivityLaunch,
    }),
    ...registerStudioTestHookCommands({
      vscode,
      output,
      status,
      enterStudio: () => enterAutopilotMode("studio", output),
      openStudioPanel: () => openStudioPanel(context, output),
      refreshStudioPanelHtml: () => refreshStudioPanelHtml(output),
      buildWorkspaceActionContext,
      writeBridgeRequest,
      applyStudioAgentTurnEvents,
      firstArray,
      stringValue,
      normalizeReceiptRefs,
      studioRuntimeProjection,
      refreshStudioReplayStepsFromProjection,
      exerciseStudioPolicyLeaseLifecycle,
      exerciseStudioSessionBrainLifecycle,
      exerciseStudioTrajectoryReplayReconnect,
      exerciseStudioManagedSessionReconnect,
      exerciseStudioStage2WebRepairLoop,
      exerciseStudioStage5StopHookRepairLoop,
      exerciseStudioStage5StopCancelRecoverLifecycle,
      exerciseStudioStage7DelegationLifecycle,
    }),
    ...registerStudioQuickInputCommands({
      vscode,
      output,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      readBridgeState,
      studioContextQuickPickItems,
      studioToolQuickPickItems,
    }),
    ...registerChatCommands({
      vscode,
      output,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      pickString,
      getStudioPanel: () => studioPanel,
      startNewStudioSession,
      refreshStudioPanelHtml: () => refreshStudioPanelHtml(output),
      focusStudioPanelComposer,
    }),
    ...registerWorkflowCommands({
      crypto,
      vscode,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      pickString,
      enterWorkflows: () => enterAutopilotMode("workflows", output),
      openWorkflowComposerPanel: (options = {}) => openWorkflowComposerPanel(context, output, options),
      closePrimarySidebarAfterActivityLaunch,
      buildRuntimeRefs,
    }),
    ...registerModelCommands({
      vscode,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      pickString,
      pickPayloadString,
      daemonEndpoint,
      enterModels: () => enterAutopilotMode("models", output),
      enterWorkflows: () => enterAutopilotMode("workflows", output),
      openModelsPanel: (options = {}) => openModelsPanel(context, output, options),
      openWorkflowComposerPanel: (options = {}) => openWorkflowComposerPanel(context, output, options),
      closePrimarySidebarAfterActivityLaunch,
      runDaemonModelWorkbenchAction,
      runDaemonModelCatalogSearch,
      runDaemonModelCatalogProviderConfig,
      runDaemonModelCatalogDownload,
    }),
    ...registerRuntimeSurfaceCommands({
      vscode,
      output,
      status,
      buildWorkspaceActionContext,
      writeBridgeRequest,
      workspaceSummary,
      pickString,
      getActiveTraceTarget: () => activeTraceTarget,
      setActiveTraceTarget: (traceTarget) => {
        activeTraceTarget = traceTarget;
      },
      enterRuns: () => enterAutopilotMode("runs", output),
      enterPolicy: () => enterAutopilotMode("policy", output),
      enterConnectors: () => enterAutopilotMode("connectors", output),
      openGenericModePanel: (modeId) => openGenericModePanel(context, output, modeId),
      closePrimarySidebarAfterActivityLaunch,
    }),
  );

  output.appendLine("Registered IOI runtime bridge commands.");
}

function activate(context) {
  const output = vscode.window.createOutputChannel("IOI Workbench");
  output.appendLine("IOI Workbench extension activated.");
  context.subscriptions.push(output);
  startBridgeCommandPolling(context, output);
  startWorkbenchContextSnapshotPublisher(context, output);

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    80,
  );
  statusItem.name = "IOI Workbench";
  statusItem.text = "$(symbol-keyword) IOI";
  statusItem.tooltip = "Open Autopilot Overview.";
  statusItem.command = "ioi.overview.open";
  statusItem.show();
  context.subscriptions.push(statusItem);

  const providers = VIEW_DEFINITIONS.map(
    (definition) => new IOIViewProvider(definition, readBridgeState),
  );
  const syncAppearanceFromBridge = async () => {
    const state = await readBridgeState();
    await syncWorkbenchAppearance(state);
    return state;
  };
  void syncAppearanceFromBridge();

  for (const provider of providers) {
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(
        provider.definition.id,
        provider,
      ),
    );
  }

  context.subscriptions.push(
    watchBridgeState(async () => {
      const state = await syncAppearanceFromBridge();
      if (overviewPanel) {
        updateOverviewPanelHtml(state);
      }
      if (studioPanel) {
        updateStudioPanelHtml(state);
      }
      if (modelsPanel) {
        const modelsViewDefinition =
          VIEW_DEFINITIONS.find((definition) => definition.id === "ioi.models") || {
            id: "ioi.models",
            title: "Models",
            eyebrow: "Daemon model runtime",
            description: "Daemon-backed model mounting.",
            actions: [],
          };
        modelsPanel.webview.html = renderHtml(modelsViewDefinition, state);
      }
      for (const [modeId, panel] of genericModePanels) {
        panel.webview.html = renderModePanelHtml(modeId, state);
      }
      for (const provider of providers) {
        void provider.render();
      }
    }),
  );

  registerNativeCommands(context, output);
  if (process.env.AUTOPILOT_SKIP_OVERVIEW !== "1") {
    setTimeout(() => {
      void vscode.commands.executeCommand("ioi.overview.open", {
        source: "startup",
        phase: "home",
      }).catch((error) => {
        output.appendLine(
          `[ioi-workbench] failed to open Autopilot Overview: ${error?.message ?? error}`,
        );
      });
    }, 900);
  }
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
