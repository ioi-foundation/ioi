function createInitialStudioRuntimeProjection({
  approvalId,
  executionMode,
  permissionMode,
  policyLeaseId,
  runtimeProfile,
} = {}) {
  return {
    schemaVersion: "ioi.agent-studio.operational-chat.projection.v1",
    threadId: null,
    sessionId: null,
    runId: null,
    turnId: null,
    status: "idle",
    pending: false,
    immediateSubmitSeen: false,
    pendingSeen: false,
    pendingStartedAtMs: null,
    pendingWorklog: [],
    runtimeEventSeenIds: [],
    lastError: null,
    lastModelStream: null,
    lastIntentFrame: null,
    executionMode,
    runtimeProfile,
    modelRoute: "route.local-first",
    selectedModel: "auto",
    reasoningEffort: "none",
    approvalMode: permissionMode,
    approvalId,
    hunkApprovalId: approvalId,
    policyLeaseId,
    hunkDecision: null,
    runtimeCockpit: {
      achieved: false,
      modelBackedStreamingObserved: false,
      realDaemonToolProposalObserved: false,
      policyLeaseDialogObserved: false,
      policyDeniedActionDidNotExecute: false,
      policyLeaseAllowOnceObserved: false,
      policyLeaseRevokeObserved: false,
      policyLeaseExpiryObserved: false,
      policyLeaseRevokedActionDidNotExecute: false,
      policyLeaseExpiredActionDidNotExecute: false,
      sandboxCommandOutputStreamObserved: false,
      sandboxCommandReceiptObserved: false,
      inlineDiffOverlayObserved: false,
      hunkNavigationObserved: false,
      hunkAcceptRejectReceiptsObserved: false,
      stopControlObserved: false,
      resumeControlObserved: false,
      stopResumeObserved: false,
      diagnosticsTestGateObserved: false,
      receiptTimelinePerStepObserved: false,
      replayStepDetailObserved: false,
      projectionOnlyRuntimeRejected: true,
      browserStatusObserved: false,
      workerStatusObserved: false,
      managedLiveViewportObserved: false,
      managedSessionLabelsObserved: false,
      conversationArtifactObserved: false,
    },
    runtimeUx: {
      denoised: true,
      tracingSeparationAchieved: true,
      compactStatusesHaveTraceLinks: true,
      modelProseNotAcceptedAsRuntimeTruth: true,
      verifiedBadgesRequireReceiptRefs: true,
    },
    runtimeEvents: [],
    actionCards: [],
    policyLeases: [],
    commandOutputs: [],
    diagnosticGates: [],
    engineReconnectBanners: [],
    trajectoryReplayPanels: [],
    sessionBrainPanels: [],
    chatResponsibilityContracts: [],
    securityScanPanels: [],
    workerContributionTraces: [],
    safeModeToolSuppressionPanels: [],
    onboardingDiagnosticsPanels: [],
    gatewayTokenHygienePanels: [],
    sandboxResourceLimitPanels: [],
    parentTrajectoryLinkagePanels: [],
    battleModePermissionImportPanels: [],
    importedStopHookGatePanels: [],
    importedBrowserActionEvidencePanels: [],
    importedExecutorConfigPanels: [],
    importedPolicyDraftPanels: [],
    importedGenerationMetadataPanels: [],
    importedErrorRenderInfoPanels: [],
    outputRenderers: [],
    replaySteps: [],
    browserCards: [],
    workerCards: [],
    computerUseSessions: [],
    conversationArtifacts: [],
    turns: [
      {
        role: "assistant",
        content:
          "Agent Studio is ready. Prompts run through daemon-owned sessions; Studio stays calm by default and links proof details into Tracing.",
        createdAt: new Date().toISOString(),
      },
    ],
    history: [
      {
        id: "studio-session-current",
        title: "Current daemon session",
        status: "idle",
      },
    ],
    timeline: [
      {
        label: "Studio surface opened",
        detail: "Awaiting prompt",
        status: "ready",
      },
    ],
    approvals: [],
    receipts: [],
    terminal: [
      {
        label: "No terminal job running",
        detail: "Terminal/test output will be projected from daemon-owned execution receipts.",
      },
    ],
    diffHunks: [],
  };
}

function createStudioProjectionLifecycle({
  createInitialProjection,
  getProjection,
  setProjection,
  resetAnswerStream = () => {},
  normalizeExecutionMode = (value) => value,
  normalizePermissionMode = (value) => value,
  normalizeReasoningEffort = (value, fallback) => value ?? fallback,
  studioModeAgent,
  agentRuntimeProfile,
  directModelRuntimeProfile,
  documentedWorkRecord,
  documentedWorkSummary,
  now = () => Date.now(),
} = {}) {
  const currentProjection = () => getProjection?.() || {};
  const arrayLength = (value) => (Array.isArray(value) ? value.length : 0);

  function resetStudioDaemonThreadProjection() {
    const projection = currentProjection();
    projection.threadId = null;
    projection.sessionId = null;
    projection.turnId = null;
    projection.runId = null;
    projection.lastModelStream = null;
    projection.lastIntentFrame = null;
    projection.pendingWorklog = [];
    projection.runtimeEventSeenIds = [];
    resetAnswerStream();
    return projection;
  }

  function startNewStudioSession(reason = "New Studio session") {
    const previous = currentProjection();
    const next = createInitialProjection();
    next.executionMode = normalizeExecutionMode(previous.executionMode || studioModeAgent);
    next.runtimeProfile =
      next.executionMode === studioModeAgent ? agentRuntimeProfile : directModelRuntimeProfile;
    next.modelRoute = previous.modelRoute || "route.local-first";
    next.selectedModel = previous.selectedModel || "auto";
    next.reasoningEffort = normalizeReasoningEffort(previous.reasoningEffort, "none");
    next.approvalMode = normalizePermissionMode(previous.approvalMode);
    next.timeline = [
      {
        label: "New Studio session",
        detail: reason,
        status: "ready",
      },
    ];
    setProjection(next);
    return currentProjection();
  }

  function studioWorkCursor() {
    const projection = currentProjection();
    return {
      startedAtMs: now(),
      actionCards: arrayLength(projection.actionCards),
      policyLeases: arrayLength(projection.policyLeases),
      commandOutputs: arrayLength(projection.commandOutputs),
      diagnosticGates: arrayLength(projection.diagnosticGates),
      diffHunks: arrayLength(projection.diffHunks),
      browserCards: arrayLength(projection.browserCards),
      workerCards: arrayLength(projection.workerCards),
      computerUseSessions: arrayLength(projection.computerUseSessions),
      conversationArtifacts: arrayLength(projection.conversationArtifacts),
      pendingWorklog: arrayLength(projection.pendingWorklog),
      receipts: arrayLength(projection.receipts),
    };
  }

  function studioDocumentedWorkRecord(cursor = {}) {
    return documentedWorkRecord(currentProjection(), cursor);
  }

  function studioDocumentedWorkSummary(record = {}) {
    return documentedWorkSummary(record, currentProjection().status);
  }

  return {
    resetStudioDaemonThreadProjection,
    startNewStudioSession,
    studioDocumentedWorkRecord,
    studioDocumentedWorkSummary,
    studioWorkCursor,
  };
}

module.exports = {
  createInitialStudioRuntimeProjection,
  createStudioProjectionLifecycle,
};
