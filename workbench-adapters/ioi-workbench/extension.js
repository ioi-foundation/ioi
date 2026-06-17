const crypto = require("crypto");
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
const { createNativeCommandRegistrar } = require("./commands/native");
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
const { createHypervisorModeController } = require("./workbench/mode-controller");
const { createWorkbenchModeBodyRenderers } = require("./workbench/mode-body-renderers");
const { formatBytes, modelSnapshotFromState } = require("./workbench/model-snapshot");
const { createWorkbenchOverviewPanelRenderer } = require("./workbench/overview-panel");
const { createOverviewPanelLifecycle } = require("./workbench/overview-panel-lifecycle");
const { createWorkbenchPanelLifecycle } = require("./workbench/panel-lifecycle");
const { createPersistentModePanels } = require("./workbench/persistent-mode-panels");
const { createHypervisorShellHeader } = require("./workbench/shell-header");
const { createStudioPanelLifecycle } = require("./workbench/studio-panel-lifecycle");
const { createWorkflowComposerPanelLifecycle } = require("./workbench/workflow-composer-panel-lifecycle");
const { createWorkflowComposerPanelRenderer } = require("./workbench/workflow-composer-panel");
const {
  formatStudioWorkDuration,
  studioDocumentedWorkRecord: studioDocumentedWorkRecordFromSummary,
  studioDocumentedWorkSummary: studioDocumentedWorkSummaryFromSummary,
  studioTurnHasDocumentedWork,
} = require("./studio-work-summary");
const { createStudioPanelHtml } = require("./studio/studio-panel-html");
const {
  createStudioModelCompletion,
  createStudioModelStreamHelpers,
  createStudioSseJsonRequester,
  studioDeltaFromSsePayload,
} = require("./studio/model-completion");
const { createStudioOperationalSurface } = require("./studio/operational-surface");
const { createStudioPromptPolicy } = require("./studio/prompt-policy");
const { createModelSurfaceRenderer } = require("./studio/model-surface");
const { createStudioAgentAnswerStreamProjector } = require("./studio/agent-answer-stream");
const { createStudioAgentFinalHandoffStreamer } = require("./studio/agent-final-handoff-stream");
const { createStudioAgentTurnEvents } = require("./studio/agent-turn-events");
const { createStudioAgentTurnResultText } = require("./studio/agent-turn-result-text");
const {
  createStudioAgentTurnRecovery,
  createStudioAgentTurnRecoveryHelpers,
} = require("./studio/agent-turn-recovery");
const { createStudioProductErrorMessage } = require("./studio/product-error-message");
const {
  createInitialStudioRuntimeProjection: createInitialStudioRuntimeProjectionFromState,
  createStudioProjectionLifecycle,
} = require("./studio/projection-state");
const { createStudioManagedSessionProjection } = require("./studio/projection-managed-sessions");
const { createStudioParityPlusEventProjection } = require("./studio/projection-parity-plus-events");
const { createStudioRuntimeEventProjection } = require("./studio/projection-runtime-events");
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
const { createStudioRuntimeControls } = require("./studio/runtime-controls");
const { createStudioRuntimeEventSelectors } = require("./studio/runtime-event-selectors");
const { createStudioThreadEvents } = require("./studio/thread-events");
const { createStudioThreadLifecycle } = require("./studio/thread-lifecycle");
const {
  studioArtifactResearchQuery,
  studioArtifactShouldGatherResearch,
  studioResearchIntentFrameForArtifact,
} = require("./studio/artifact-research-routing");
const { createStudioArtifactIntent } = require("./studio/artifact-intent");
const { createStudioArtifactPreview } = require("./studio/artifact-preview");
const { createStudioManagedSessionView } = require("./studio/managed-session-view");
const { createStudioHunkLifecycle } = require("./studio/hunk-lifecycle");
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
const { createStudioPendingView } = require("./studio/pending-view");
const { createStudioRuntimeCockpitRows } = require("./studio/runtime-cockpit-rows");
const { createStudioRuntimeRailRows } = require("./studio/runtime-rail-rows");
const { createStudioTurnRows } = require("./studio/turn-rows");
const { createStudioWorkRunRows } = require("./studio/work-run-rows");
const {
  createStudioDurabilityPanels,
} = require("./studio/durability-panels");
const { createStudioRuntimeCockpitLifecycle } = require("./studio/runtime-cockpit-lifecycle");
const { createNativeChatViewRenderer } = require("./studio/native-chat-view");
const { createStudioToolPalette } = require("./studio/tool-palette");
const { createStudioModelSelection } = require("./studio/model-selection");
const { createStudioModelFixturePolicy } = require("./studio/model-fixture-policy");
const { createStudioNativeDiffPreview } = require("./studio/native-diff-preview");
const { createStudioStage7DelegationLifecycle } = require("./studio/stage7-delegation-lifecycle");
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
  firstArray,
  stringValue,
} = require("./studio/value-helpers");
const {
  HYPERVISOR_MODE_BY_ID,
  HYPERVISOR_MODE_BY_PANEL_VIEW_ID,
  HYPERVISOR_MODE_BY_VIEW_ID,
  HYPERVISOR_MODES,
  VIEW_DEFINITIONS,
} = require("./workbench-surfaces");

const hypervisorWorkbenchRuntimeTruth = {
  runtimeTruthSource: "daemon-runtime",
};

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
const hypervisorModeController = createHypervisorModeController({
  HYPERVISOR_MODE_BY_ID,
  HYPERVISOR_MODE_BY_PANEL_VIEW_ID,
  HYPERVISOR_MODE_BY_VIEW_ID,
  vscode,
});
let studioModelInvocationToken = null;
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
let studioRuntimeProjection = createInitialStudioRuntimeProjectionFromState({
  approvalId: STUDIO_APPROVAL_ID,
  executionMode: STUDIO_MODE_AGENT,
  permissionMode: STUDIO_PERMISSION_MODE_DEFAULT,
  policyLeaseId: STUDIO_POLICY_LEASE_ID,
  runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
});
let activeTraceTarget = null;

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

function uniqueStrings(values = []) {
  return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
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

const {
  compactStudioWhitespace,
  isAutoStudioModelSelector,
  promptIsInternalHarnessProbe,
  promptRequiresRetrieval,
  promptRequiresWorkspaceContext,
  promptTargetsLocalWorkspace,
  workspaceTargetsForPrompt,
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
  studioTextIndicatesApprovalPause: (...args) => studioTextIndicatesApprovalPause(...args),
});

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

const {
  studioDenyFixtureModelPolicy,
  studioFixtureModelUsageAllowed,
  studioTextContainsProductFixtureMarker,
} = createStudioModelFixturePolicy({
  getEnv: (name) => process.env[name],
  stringValue,
});

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
  studioModelIdForRouteInvocation,
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

const {
  resetStudioDaemonThreadProjection,
  startNewStudioSession,
  studioDocumentedWorkRecord,
  studioDocumentedWorkSummary,
  studioWorkCursor,
} = createStudioProjectionLifecycle({
  agentRuntimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
  createInitialProjection: () => createInitialStudioRuntimeProjectionFromState({
    approvalId: STUDIO_APPROVAL_ID,
    executionMode: STUDIO_MODE_AGENT,
    permissionMode: STUDIO_PERMISSION_MODE_DEFAULT,
    policyLeaseId: STUDIO_POLICY_LEASE_ID,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
  }),
  directModelRuntimeProfile: STUDIO_DIRECT_MODEL_RUNTIME_PROFILE,
  documentedWorkRecord: studioDocumentedWorkRecordFromSummary,
  documentedWorkSummary: studioDocumentedWorkSummaryFromSummary,
  getProjection: () => studioRuntimeProjection,
  normalizeExecutionMode: normalizeStudioExecutionMode,
  normalizePermissionMode: normalizeStudioPermissionMode,
  normalizeReasoningEffort: normalizeStudioReasoningEffort,
  resetAnswerStream: () => studioAgentAnswerStreamProjector.reset(),
  setProjection: (projection) => {
    studioRuntimeProjection = projection;
  },
  studioModeAgent: STUDIO_MODE_AGENT,
});

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
  exerciseStudioSessionBrainLifecycle: exerciseStudioSessionBrainLifecycleFromModule,
  exerciseStudioTrajectoryReplayReconnect: exerciseStudioTrajectoryReplayReconnectFromModule,
  studioSessionBrainPanelFromProjection,
  studioTrajectoryReplayPanelFromProjection,
} = createStudioDurabilityPanels({
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  fetchStudioThreadEvents,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  normalizeReceiptRefs,
  requestJson,
  stringValue,
  studioMaxRuntimeEventSeq,
  studioRuntimeEventKind,
  uniqueStrings,
  workspaceSummary,
  workspacePath: () => workspaceSummary().path,
  writeBridgeRequest,
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

const {
  appendStudioReceiptsFromResponse,
  appendStudioRuntimeEvent,
  appendStudioTimeline,
  recomputeStudioRuntimeCockpitAchieved,
} = createStudioRuntimeEventProjection({
  appendStudioReceipts,
  classifyStudioRuntimeEvent,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  normalizeReceiptRefs,
});

const {
  exerciseStudioPolicyLeaseLifecycle: exerciseStudioPolicyLeaseLifecycleFromModule,
  requestAndDenyStudioPolicyLease: requestAndDenyStudioPolicyLeaseFromModule,
} = createStudioPolicyLeaseLifecycle({
  STUDIO_POLICY_LEASE_ID,
  STUDIO_MODE_AGENT,
  STUDIO_PERMISSION_MODE_DEFAULT,
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  daemonEndpoint,
  daemonRequestToken,
  ensureStudioDaemonThread,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  normalizeReceiptRefs,
  recomputeStudioRuntimeCockpitAchieved,
  requestJson,
  studioApprovalTurnPayload,
  workspaceSummary,
});

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

const { studioCleanProductErrorMessage } = createStudioProductErrorMessage({ stringValue });
const {
  studioChatOutputRendererRows,
} = createStudioChatOutputRenderers({
  escapeHtml,
  firstArray,
  normalizeReceiptRefs,
  studioVerifiedBadge,
});

let studioThreadEvents;
let studioThreadLifecycle;
let studioRuntimeControls;
let studioHunkLifecycle;

function collectStudioAgentEventsFromResponse(turn = {}) {
  return studioThreadEvents.collectStudioAgentEventsFromResponse(turn);
}

function uniqueStudioRuntimeEvents(events = []) {
  return studioThreadEvents.uniqueStudioRuntimeEvents(events);
}

function studioMaxRuntimeEventSeq(events = []) {
  return studioThreadEvents.studioMaxRuntimeEventSeq(events);
}

async function fetchStudioThreadEvents(threadId, output, options = {}) {
  return studioThreadEvents.fetchStudioThreadEvents(threadId, output, options);
}

async function fetchStudioThreadTurns(threadId, output, options = {}) {
  return studioThreadEvents.fetchStudioThreadTurns(threadId, output, options);
}

async function fetchStudioThreadTurnEvents(threadId, output, options = {}) {
  return studioThreadEvents.fetchStudioThreadTurnEvents(threadId, output, options);
}

function applyStudioAgentModeSelection(payload = {}) {
  return studioThreadLifecycle.applyStudioAgentModeSelection(payload);
}

function studioRunResultText(payload = {}) {
  return studioThreadLifecycle.studioRunResultText(payload);
}

async function ensureStudioDaemonThread(payload = {}, output) {
  return studioThreadLifecycle.ensureStudioDaemonThread(payload, output);
}

async function applyStudioPermissionModeSelection(payload = {}, output) {
  return studioThreadLifecycle.applyStudioPermissionModeSelection(payload, output);
}

async function stopStudioTurn(output) {
  return studioRuntimeControls.stopStudioTurn(output);
}

async function resumeStudioTurn(output) {
  return studioRuntimeControls.resumeStudioTurn(output);
}

const {
  exerciseStudioStage2WebRepairLoop: exerciseStudioStage2WebRepairLoopFromModule,
  exerciseStudioStage5StopCancelRecoverLifecycle: exerciseStudioStage5StopCancelRecoverLifecycleFromModule,
  exerciseStudioStage5StopHookRepairLoop: exerciseStudioStage5StopHookRepairLoopFromModule,
  studioParityPlusPanelRows: studioParityPlusPanelRowsFromRenderer,
  studioStage2FinalContractValues,
  studioStage2ProductTextIsClean,
  studioStage2WebRepairEventText,
  studioStage5ProductTextIsClean,
} = createStudioParityPlusPanels({
  appendStudioTimeline,
  buildWorkspaceActionContext,
  compactStudioWhitespace,
  escapeHtml,
  fetchStudioThreadEvents,
  fetchStudioThreadTurnEvents,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  sanitizeStudioProductAssistantText: (value) => sanitizeStudioProductAssistantText(value),
  refreshStudioPanelHtml,
  resumeStudioTurn,
  STUDIO_MODE_AGENT,
  STUDIO_AGENT_RUNTIME_PROFILE,
  STUDIO_PERMISSION_MODE_FULL_ACCESS,
  stopStudioTurn,
  stringValue,
  studioRuntimeEventsIncludeCompletedTool,
  studioRuntimeToolEventCount,
  studioSourceRefsFromRuntimeEvents,
  studioPublicWorkspacePath,
  studioTraceLink,
  studioVerifiedBadge,
  submitStudioAgentTurn,
  submitStudioPrompt,
  uniqueStudioRuntimeEvents,
  workspaceSummary,
  writeBridgeRequest,
});

const {
  exerciseStudioStage7DelegationLifecycle: exerciseStudioStage7DelegationLifecycleFromModule,
} = createStudioStage7DelegationLifecycle({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  applyStudioAgentTurnEvents,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  fetchStudioThreadEvents,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  isAutoStudioModelSelector,
  normalizeReceiptRefs,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  refreshStudioReplayStepsFromProjection,
  requestJson,
  stringValue,
  uniqueStrings,
  workspaceSummary,
  writeBridgeRequest,
});

const {
  projectStudioRuntimeCockpit: projectStudioRuntimeCockpitFromModule,
} = createStudioRuntimeCockpitLifecycle({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  commandOutputFromToolResponse,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  invokeStudioDaemonTool,
  normalizeReceiptRefs,
  openStudioNativeDiffPreview: (hunk, output) => openStudioNativeDiffPreview(hunk, output),
  patchPreviewHunkFromToolResponse: (response, targetPath) =>
    patchPreviewHunkFromToolResponse(response, targetPath),
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioReplayStepsFromProjection,
  requestAndDenyStudioPolicyLease,
  requestJson,
  studioApprovalTurnPayload,
  studioRuntimeCockpitPatchTargetFromPrompt: (prompt, fallback) =>
    studioRuntimeCockpitPatchTargetFromPrompt(prompt, fallback),
  STUDIO_APPROVAL_ID,
  STUDIO_POLICY_LEASE_ID,
});

const {
  studioPendingProjectionRows,
  studioPendingWorklogRows,
} = createStudioPendingView({
  compactStudioWhitespace,
  escapeHtml,
  firstArray,
  formatStudioWorkDuration,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  studioPendingCommandOutputExcerpt,
  studioSourceChipRows,
  studioVisiblePendingStepDetail,
});

const {
  studioCommandHeadline,
  studioWorkCommandOutputRows,
  studioWorkRecordDiffRows,
  studioWorkSummaryRows,
} = createStudioWorkRunRows({
  compactStudioWhitespace,
  escapeHtml,
  firstArray,
  formatStudioWorkDuration,
  getHunkApprovalId: () => studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID,
  studioCommandRowHasOutput,
  studioPendingWorkLabelForTool,
  studioPublicOutputBlock,
  studioPublicWorkspacePath,
  studioSanitizePublicAssistantText,
  studioSourceChipRows,
  stringValue,
});

const { studioTurnRows } = createStudioTurnRows({
  escapeHtml,
  formatStudioWorkDuration,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  studioChatCodeExecutionRows,
  studioChatOutputRendererRows,
  studioConversationArtifactRows,
  studioDisplayTurnContent,
  studioManagedSessionRows,
  studioResponseMetricsRows,
  studioThinkingRows,
  studioTurnContentRows,
  studioTurnHasDocumentedWork,
  studioTurnSourceRows,
  studioWorkCommandOutputRows,
  studioWorkRecordDiffRows,
  studioWorkSummaryRows,
});

const {
  patchPreviewHunkFromToolResponse,
  studioActionCardRows,
  studioBrowserWorkerRows,
  studioCommandOutputRows,
  studioCompactRuntimeStatusRows,
  studioDiagnosticsRows,
  studioDiffRows,
  studioPolicyLeaseRows,
  studioRuntimeCockpitPatchTargetFromPrompt,
} = createStudioRuntimeCockpitRows({
  STUDIO_RUNTIME_VISIBILITY,
  escapeHtml,
  firstArray,
  getHunkApprovalId: () => studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  safeJsonPreview,
  studioCommandHeadline,
  stringValue,
});

const {
  studioApprovalRows,
  studioHistoryRows,
  studioParityPlusPanelRows,
  studioReceiptRows,
  studioReplayRows,
  studioTerminalRows,
  studioTimelineRows,
} = createStudioRuntimeRailRows({
  escapeHtml,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  studioParityPlusPanelRowsFromRenderer,
});

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
    <section class="workflow-direct-open" data-inspection-target="overview-direct-open" aria-label="Opening Hypervisor Overview">
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

async function enterHypervisorMode(modeId, output) {
  await hypervisorModeController.enterHypervisorMode(modeId, output);
}

const {
  hypervisorShellHeaderStyles,
  renderHypervisorShellHeader,
} = createHypervisorShellHeader({
  HYPERVISOR_MODE_BY_ID,
  daemonEndpoint,
  escapeHtml,
  modelSnapshotFromState,
  workspaceSummary,
});

const { codeModePanelHtml } = createWorkbenchCodeModePanelRenderer({
  hypervisorShellHeaderStyles,
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
  hypervisorShellHeaderStyles,
  currentOverviewPanelNonce,
  daemonEndpoint,
  escapeHtml,
  loadedProductStudioModelInstances,
  modelSnapshotFromState,
  overviewPill,
  overviewTone,
  productStudioModelSelectionsFromSnapshot,
  renderHypervisorShellHeader,
  renderOverviewAction,
  renderOverviewRow,
  workspaceSummary,
});

const { workflowComposerHtml } = createWorkflowComposerPanelRenderer({
  hypervisorShellHeaderStyles,
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  escapeHtml,
  nonce,
  renderHypervisorShellHeader,
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
    hypervisorModeController.modeIdForViewId(view.id) ||
    hypervisorModeController.currentModeId();
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
      body[data-hypervisor-theme^="light"] {
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
      body[data-hypervisor-theme^="dark"] {
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
      ${hypervisorShellHeaderStyles()}
    </style>
  </head>
  <body
    class="${isChatView ? "is-chat-view" : ""} ${isModelsView ? "is-models-view" : ""}"
    data-hypervisor-theme="${escapeHtml(appearanceThemeId)}"
  >
    ${
      isChatView
        ? renderBody(view.id, state)
        : isStudioView
          ? `${renderHypervisorShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isWorkflowView
          ? `${renderHypervisorShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isModelsView
          ? `${renderHypervisorShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : `
          ${renderHypervisorShellHeader(state, shellModeId)}
          <main class="hypervisor-generic-mode" data-testid="autopilot-${escapeHtml(shellModeId)}-mode">
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
          modelsMode: document.querySelectorAll('[data-testid="hypervisor-models-mode"]').length,
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
        const root = document.querySelector('[data-testid="hypervisor-models-mode"]');
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
        const root = document.querySelector('[data-testid="hypervisor-models-mode"]');
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
        const root = document.querySelector('[data-testid="hypervisor-models-mode"]');
        const targetTestId = phase === "model-discover-view" ? "model-discovery-surface" : phase;
        const target = phase === "model-library"
          ? root
          : document.querySelector('[data-testid="' + targetTestId + '"]') || root;
        target?.scrollIntoView({ block: phase === "model-discover-view" || phase === "model-discovery-surface" || phase === "model-catalog-sources-surface" || phase === "model-library" ? "start" : "center", inline: "center" });
        window.setTimeout(() => collectModelsProof(phase), 250);
      });
      if (document.querySelector('[data-testid="hypervisor-models-mode"]')) {
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
              "<strong>Proposal queued</strong>Hypervisor is writing a proposal-first diff, approval/check plan, and receipt trail for the active workspace.";
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

const { ensureStudioDiffProvider, openStudioNativeDiffPreview } = createStudioNativeDiffPreview({
  appendStudioTimeline,
  crypto,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  vscode,
});

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
  return requestAndDenyStudioPolicyLeaseFromModule(threadId, output);
}

async function exerciseStudioPolicyLeaseLifecycle(output) {
  return exerciseStudioPolicyLeaseLifecycleFromModule(output);
}

function refreshStudioReplayStepsFromProjection() {
  refreshStudioReplayStepsFromProjectionState(studioRuntimeProjection);
}

async function exerciseStudioTrajectoryReplayReconnect(output, payload = {}) {
  return exerciseStudioTrajectoryReplayReconnectFromModule(output, payload);
}

async function exerciseStudioSessionBrainLifecycle(output) {
  return exerciseStudioSessionBrainLifecycleFromModule(output);
}

async function exerciseStudioStage2WebRepairLoop(output, payload = {}) {
  return exerciseStudioStage2WebRepairLoopFromModule(output, payload);
}

async function exerciseStudioStage5StopHookRepairLoop(output, payload = {}) {
  return exerciseStudioStage5StopHookRepairLoopFromModule(output, payload);
}

async function exerciseStudioStage5StopCancelRecoverLifecycle(output, payload = {}) {
  return exerciseStudioStage5StopCancelRecoverLifecycleFromModule(output, payload);
}

async function exerciseStudioStage7DelegationLifecycle(output, payload = {}) {
  return exerciseStudioStage7DelegationLifecycleFromModule(output, payload);
}

async function projectStudioRuntimeCockpit(prompt, streamResult, output) {
  return projectStudioRuntimeCockpitFromModule(prompt, streamResult, output);
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
  const grant = await requestJson(endpoint, "/v1/model-mount/tokens", {
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

const requestSseJson = createStudioSseJsonRequester({ normalizeBaseUrl });
const {
  collectStudioStreamMetadata,
  studioReasoningDeltaFromSsePayload,
} = createStudioModelStreamHelpers({
  firstArray,
  studioNumberOrNull,
  uniqueStrings,
});

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

studioThreadEvents = createStudioThreadEvents({
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  requestJson,
  requestSseJson,
  studioRuntimeEventKind,
});

studioThreadLifecycle = createStudioThreadLifecycle({
  appendStudioReceipts,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  isAutoStudioModelSelector,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  normalizeStudioReasoningEffort,
  requestJson,
  resetStudioDaemonThreadProjection,
  STUDIO_AGENT_RUNTIME_PROFILE,
  STUDIO_DIRECT_MODEL_RUNTIME_PROFILE,
  STUDIO_MODE_AGENT,
  studioIntentFramePayload,
  studioPermissionDaemonMapping,
  stringValue,
  uniqueStrings,
  workspaceSummary,
});

studioRuntimeControls = createStudioRuntimeControls({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  requestJson,
  writeBridgeRequest,
});

studioHunkLifecycle = createStudioHunkLifecycle({
  appendStudioReceipts,
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  ensureStudioDaemonThread,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  invokeStudioDaemonTool,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  refreshStudioWorkspaceChangeReviewsFromDaemon,
  requestJson,
  stringValue,
  studioApprovalTurnPayload,
  STUDIO_APPROVAL_ID,
  uniqueStrings,
  vscode,
  writeBridgeRequest,
});

const studioAgentTurnEvents = createStudioAgentTurnEvents({ fetchStudioThreadEvents, applyStudioAgentTurnEvents, studioMaxRuntimeEventSeq, studioAssistantTextFromRuntimeToolEvents, studioAgentTurnResultText, studioRuntimeEventKind, firstArray });

const {
  studioTurnLooksTerminal,
  studioTurnMatchesSubmittedPrompt,
} = createStudioAgentTurnRecoveryHelpers({
  collectStudioAgentEventsFromResponse,
  firstArray,
  stringValue,
  studioAgentTurnResultText,
  studioRuntimeEventIsRunningStepCompletion,
  studioRuntimeEventKind,
});

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
  return studioHunkLifecycle.handleStudioHunkDecision(decision, payload, output);
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
  return studioHunkLifecycle.navigateStudioHunk(direction, output);
}

const {
  IOIViewProvider,
  closePrimarySidebarAfterActivityLaunch,
  registerModePanelVisibilityProjection,
  syncWorkbenchAppearance,
  watchBridgeState,
} = createWorkbenchPanelLifecycle({
  HYPERVISOR_MODE_BY_ID,
  HYPERVISOR_MODE_BY_VIEW_ID,
  MODE_VISIBILITY_REQUEST_TYPES,
  buildWorkspaceActionContext,
  renderHtml,
  vscode,
  workspaceSummary,
  writeBridgeRequest,
});

const {
  openOverviewPanel: openOverviewPanelFromManager,
} = createOverviewPanelLifecycle({
  applyStudioAgentModeSelection,
  applyStudioPermissionModeSelection,
  buildWorkspaceActionContext,
  focusStudioPanelComposer,
  getOverviewPanel: () => overviewPanel,
  readBridgeState,
  refreshStudioPanelHtml,
  registerModePanelVisibilityProjection,
  resetOverviewPanelRenderState: () => {
    overviewPanelLastHtml = null;
    overviewPanelNonce = null;
  },
  setOverviewPanel: (panel) => {
    overviewPanel = panel;
  },
  updateOverviewPanelHtml,
  vscode,
  writeBridgeRequest,
});

async function openOverviewPanel(context, output) {
  return openOverviewPanelFromManager(context, output);
}

const {
  openStudioPanel: openStudioPanelFromManager,
} = createStudioPanelLifecycle({
  applyStudioAgentModeSelection,
  applyStudioPermissionModeSelection,
  buildWorkspaceActionContext,
  focusStudioPanelComposer,
  getStudioPanel: () => studioPanel,
  handleStudioArtifactAction,
  handleStudioHunkDecision,
  handleStudioManagedSessionControl,
  navigateStudioHunk,
  readBridgeState,
  refreshStudioPanelHtml,
  registerModePanelVisibilityProjection,
  resetStudioPanelRenderState: () => {
    studioPanelLastHtml = null;
    studioPanelPageNonce = null;
  },
  resumeStudioTurn,
  setStudioPanel: (panel) => {
    studioPanel = panel;
  },
  startNewStudioSession,
  stopStudioTurn,
  submitStudioPrompt,
  updateStudioPanelHtml,
  vscode,
  writeBridgeRequest,
});

async function openStudioPanel(context, output) {
  return openStudioPanelFromManager(context, output);
}

const {
  openGenericModePanel: openGenericModePanelFromManager,
  openModelsPanel: openModelsPanelFromManager,
  refreshPersistentModePanels,
} = createPersistentModePanels({
  HYPERVISOR_MODE_BY_ID,
  VIEW_DEFINITIONS,
  buildWorkspaceActionContext,
  codeModePanelHtml,
  readBridgeState,
  registerModePanelVisibilityProjection,
  renderHtml,
  vscode,
  writeBridgeRequest,
});
const {
  openWorkflowComposerPanel: openWorkflowComposerPanelFromManager,
} = createWorkflowComposerPanelLifecycle({
  buildWorkspaceActionContext,
  registerModePanelVisibilityProjection,
  vscode,
  workflowComposerHtml,
  writeBridgeRequest,
});

async function openModelsPanel(context, output, options = {}) {
  return openModelsPanelFromManager(context, output, options);
}

async function openGenericModePanel(context, output, modeId) {
  return openGenericModePanelFromManager(context, output, modeId);
}

function openWorkflowComposerPanel(context, output, options = {}) {
  return openWorkflowComposerPanelFromManager(context, output, options);
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

const registerNativeCommands = createNativeCommandRegistrar();

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
  statusItem.tooltip = "Open Hypervisor Overview.";
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
      refreshPersistentModePanels(state);
      for (const provider of providers) {
        void provider.render();
      }
    }),
  );

  registerNativeCommands({
    context,
    output,
    vscode,
    daemonEndpoint,
    daemonToken,
    requestJson,
    ensureStudioDiffProvider,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    workspaceSummary,
    studioRuntimeProjection,
    studioPermissionModeOptions,
    studioExecutionModeLabel,
    studioPermissionModeLabel,
    applyStudioAgentModeSelection,
    applyStudioPermissionModeSelection,
    refreshStudioPanelHtml: () => refreshStudioPanelHtml(output),
    focusStudioPanelComposer,
    hypervisorModeById: HYPERVISOR_MODE_BY_ID,
    getLastHypervisorModeBeforeCode: () => hypervisorModeController.lastModeBeforeCode(),
    getStudioPanel: () => studioPanel,
    enterHypervisorMode,
    openOverviewPanel: () => openOverviewPanel(context, output),
    openStudioPanel: () => openStudioPanel(context, output),
    openGenericModePanel: (modeId) => openGenericModePanel(context, output, modeId),
    closePrimarySidebarAfterActivityLaunch,
    applyStudioAgentTurnEvents,
    firstArray,
    stringValue,
    normalizeReceiptRefs,
    refreshStudioReplayStepsFromProjection,
    exerciseStudioPolicyLeaseLifecycle,
    exerciseStudioSessionBrainLifecycle,
    exerciseStudioTrajectoryReplayReconnect,
    exerciseStudioManagedSessionReconnect,
    exerciseStudioStage2WebRepairLoop,
    exerciseStudioStage5StopHookRepairLoop,
    exerciseStudioStage5StopCancelRecoverLifecycle,
    exerciseStudioStage7DelegationLifecycle,
    readBridgeState,
    studioContextQuickPickItems,
    studioToolQuickPickItems,
    startNewStudioSession,
    openWorkflowComposerPanel: (options = {}) => openWorkflowComposerPanel(context, output, options),
    buildRuntimeRefs,
    openModelsPanel: (options = {}) => openModelsPanel(context, output, options),
    getActiveTraceTarget: () => activeTraceTarget,
    setActiveTraceTarget: (traceTarget) => {
      activeTraceTarget = traceTarget;
    },
  });
  if (process.env.AUTOPILOT_SKIP_OVERVIEW !== "1") {
    setTimeout(() => {
      void vscode.commands.executeCommand("ioi.overview.open", {
        source: "startup",
        phase: "home",
      }).catch((error) => {
        output.appendLine(
          `[ioi-workbench] failed to open Hypervisor Overview: ${error?.message ?? error}`,
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
