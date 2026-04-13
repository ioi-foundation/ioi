// apps/autopilot/src/windows/SpotlightWindow/index.tsx

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  hideSpotlightShell,
  setSessionRuntime,
  showGateShell,
  stopSessionTask,
  type AgentSessionRuntime,
  SessionHistorySidebar,
  useAssistantWorkbenchState,
  useSessionGateState,
  useSessionConversationScroll,
  useSessionDeferredFocus,
  useSessionRunSurface,
  useSessionShellShortcuts,
  useSessionStudioArtifactDrawer,
} from "@ioi/agent-ide";
import { bootstrapAgentSession, useAgentStore } from "../../session/autopilotSession";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import { recordStudioLaunchReceipt } from "../../services/studioLaunchState";
import { buildAssistantWorkbenchSummary } from "../../lib/assistantWorkbenchSummary";
import { useLiveValidationSummary } from "../../hooks/useLiveValidationSummary";
import { useRetainedWorkbenchTrace } from "../../hooks/useRetainedWorkbenchTrace";
import {
  AgentEvent,
  Artifact,
  SourceSummary,
} from "../../types";
import { useSpotlightLayout } from "./hooks/useSpotlightLayout";
import { useSpotlightPlaybookRuns } from "./hooks/useSpotlightPlaybookRuns";
import { useSpotlightStagedOperations } from "./hooks/useSpotlightStagedOperations";
import {
  selectRetainableDrawerSession,
  useSpotlightSurfaceState,
} from "./hooks/useSpotlightSurfaceState";
import { useSpotlightSession } from "./hooks/useSpotlightSession";
import { useLegacyPresentation } from "./hooks/useLegacyPresentation";

// Sub-components
import { icons } from "./components/Icons";
import { IOIWatermark } from "./components/IOIWatermark";
import { ThoughtChain } from "./components/ThoughtChain";
import { OverlayConversationSurface } from "./components/OverlayConversationSurface";
import { SpotlightArtifactPanel } from "./components/SpotlightArtifactPanel";
import { ConversationTimeline } from "./components/ConversationTimeline";
import { SpotlightInputSection } from "./components/SpotlightInputSection";
import { SpotlightGateDock } from "./components/SpotlightGateDock";
import { SpotlightOperatorStrip } from "./components/SpotlightOperatorStrip";
import { SpotlightOrchestrationBoard } from "./components/SpotlightOrchestrationBoard";
import { StudioConversationSurface } from "./components/StudioConversationSurface";
import { StudioArtifactSurface } from "./components/StudioArtifactSurface";
import { collectAvailableStudioArtifacts } from "./components/studioArtifactConversationModel";
import {
  StudioConversationWelcome,
  StudioRunStateCard,
} from "./components/StudioConversationPanels";
import { exportThreadTraceBundle } from "./utils/exportContext";
import {
  CONTENT_PIPELINE_V2_ENABLED,
  modelOptions,
  workspaceOptions,
} from "./constants";

// Styles
import "./styles/Layout.css";
import "./styles/Chat.css";
import "./styles/Sidebar.css";
import "./styles/Components.css";
import "./styles/Visuals.css";
import "./styles/ArtifactPanel.css";
import "./styles/Overrides.css";
import "./styles/MicroEventCard.css";
import "./styles/StudioSurface.css";

type SpotlightWindowProps = {
  variant?: "overlay" | "studio";
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime?: AgentSessionRuntime;
};

// ============================================
// MAIN COMPONENT
// ============================================

export function SpotlightWindow({
  variant = "overlay",
  seedIntent = null,
  onConsumeSeedIntent,
  sessionRuntime,
}: SpotlightWindowProps) {
  const isStudioVariant = variant === "studio";
  const [studioArtifactVisible, setStudioArtifactVisible] = useState(false);
  const [selectedStudioArtifactSessionId, setSelectedStudioArtifactSessionId] =
    useState<string | null>(null);

  // Layout management (synced with Tauri backend)
  const { layout, toggleSidebar, toggleArtifactPanel } = useSpotlightLayout({
    persistToBackend: !isStudioVariant,
  });

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const {
    task,
    events,
    artifacts,
    selectedArtifactId,
    sessions,
    startTask,
    dismissTask,
    continueTask,
    loadSession,
    refreshSessionHistory,
    refreshCurrentTask,
    resetSession,
    setSelectedArtifactId,
    loadThreadEvents,
    loadThreadArtifacts,
  } = useAgentStore();
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
    validationSummary,
    preferredEvidenceArtifactId,
  } = useLiveValidationSummary({
    task,
    sessions,
    retainedWorkbenchActivities,
    retainedWorkbenchTrace,
    latestRetainedWorkbenchEvent,
    latestRetainedWorkbenchArtifact,
    loadThreadEvents: (threadId) =>
      loadThreadEvents(threadId) as Promise<AgentEvent[]>,
    loadThreadArtifacts: (threadId) =>
      loadThreadArtifacts(threadId) as Promise<Artifact[]>,
  });

  const {
    chatEvents,
    setChatEvents,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
    gateActionError,
    credentialRequest,
    clarificationRequest,
    activeSessionId,
    showPasswordPrompt,
    showClarificationPrompt,
    inputLockedByCredential,
    gateInfo,
    isPiiGate,
    isGated,
    gateDeadlineMs,
    handleApprove,
    handleDeny,
    handleGrantScopedException,
  } = useSessionGateState({
    task,
  });

  const {
    intent,
    setIntent,
    localHistory,
    submissionInFlight,
    submissionError,
    autoContext,
    setAutoContext,
    activeDropdown,
    setActiveDropdown,
    workspaceMode,
    setWorkspaceMode,
    selectedModel,
    setSelectedModel,
    planMode,
    togglePlanMode,
    artifactHubView,
    artifactHubTurnId,
    openArtifactById,
    openArtifactHub,
    closeInspectionSurface,
    inputFocused,
    setInputFocused,
    searchQuery,
    setSearchQuery,
    isDraggingFile,
    openStudio,
    handleLoadSession,
    handleSubmit,
    handleSubmitText,
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
    handleNewChat,
    handleGlobalClick,
    handleInputChange,
    handleInputKeyDown,
  } = useSpotlightSession({
    bootstrapSessionController: bootstrapAgentSession,
    isStudioVariant,
    task,
    inputRef,
    setChatEvents,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
    sessions,
    startTask,
    continueTask,
    dismissTask,
    loadSession,
    resetSession,
    setSelectedArtifactId,
    toggleArtifactPanel,
    loadThreadEvents,
    loadThreadArtifacts,
  });

  const {
    runs: playbookRuns,
    loading: playbookRunsLoading,
    busyRunId: playbookRunsBusyRunId,
    message: playbookRunsMessage,
    error: playbookRunsError,
    retryPlaybookRun,
    resumePlaybookRun,
    dismissPlaybookRun,
    messageWorkerSession,
    stopWorkerSession,
    promoteRunResult,
    promoteStepResult,
  } = useSpotlightPlaybookRuns(activeSessionId);
  const {
    operations: stagedOperations,
    loading: stagedOperationsLoading,
    busyOperationId: stagedOperationsBusyId,
    message: stagedOperationsMessage,
    error: stagedOperationsError,
    promoteOperation: promoteStagedOperation,
    removeOperation: removeStagedOperation,
  } = useSpotlightStagedOperations();

  // ============================================
  // INITIALIZATION
  // ============================================

  useEffect(() => {
    if (!sessionRuntime) {
      return;
    }

    setSessionRuntime(sessionRuntime);
    return () => {
      setSessionRuntime(null);
    };
  }, [sessionRuntime]);

  useEffect(() => {
    if (isStudioVariant) {
      return;
    }

    const className = "spotlight-shell-host";
    const root = document.getElementById("root");
    document.documentElement.classList.add(className);
    document.body.classList.add(className);
    root?.classList.add(className);
    return () => {
      document.documentElement.classList.remove(className);
      document.body.classList.remove(className);
      root?.classList.remove(className);
    };
  }, [isStudioVariant]);

  useEffect(() => {
    if (!seedIntent?.trim()) {
      return;
    }

    const nextIntent = seedIntent.trim();
    if (isStudioVariant) {
      console.info("[Studio][SeedIntent] auto-submit requested", {
        length: nextIntent.length,
      });
      void recordStudioLaunchReceipt("studio_seed_intent_submit_requested", {
        intentLength: nextIntent.length,
      });
      window.setTimeout(() => {
        console.info("[Studio][SeedIntent] auto-submit dispatching");
        void recordStudioLaunchReceipt("studio_seed_intent_submit_dispatching", {
          intentLength: nextIntent.length,
        });
        void handleSubmitText(nextIntent)
          .then(() => {
            console.info("[Studio][SeedIntent] auto-submit resolved");
            void recordStudioLaunchReceipt("studio_seed_intent_submit_resolved", {
              intentLength: nextIntent.length,
            });
          })
          .catch((error) => {
            console.error("[Studio][SeedIntent] auto-submit failed", error);
            void recordStudioLaunchReceipt("studio_seed_intent_submit_failed", {
              intentLength: nextIntent.length,
              error: error instanceof Error ? error.message : String(error),
            });
          });
      }, 0);
      onConsumeSeedIntent?.();
      return;
    }

    setIntent(nextIntent);
    onConsumeSeedIntent?.();
  }, [
    handleSubmitText,
    inputRef,
    isStudioVariant,
    onConsumeSeedIntent,
    seedIntent,
    setIntent,
  ]);

  useSessionDeferredFocus({
    focusRef: inputRef,
    enabled: Boolean(seedIntent?.trim()),
    focusDeps: [seedIntent],
  });

  useEffect(() => {
    const resetUnlistenPromise = listenForAutopilotDataReset();
    return () => {
      resetUnlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    if (!layout.artifactPanelVisible || artifactHubView !== "tasks") {
      return;
    }

    const sessionId = task?.session_id || task?.id || null;
    const timeout = window.setTimeout(() => {
      if (sessionId) {
        void loadSession(sessionId).catch((error) => {
          console.error("Failed to reload task session for Tasks drawer:", error);
          void refreshCurrentTask().catch((refreshError) => {
            console.error(
              "Failed to refresh task for Tasks drawer:",
              refreshError,
            );
          });
        });
        return;
      }

      void refreshSessionHistory()
        .then((latestSessions) => {
          const candidate = selectRetainableDrawerSession(latestSessions);
          if (!candidate?.session_id) {
            return refreshCurrentTask();
          }
          return loadSession(candidate.session_id);
        })
        .catch((error) => {
          console.error(
            "Failed to promote retained session for Tasks drawer:",
            error,
          );
          return refreshCurrentTask();
        })
        .catch((error) => {
          console.error("Failed to refresh task for Tasks drawer:", error);
        });
    }, 120);

    return () => window.clearTimeout(timeout);
  }, [
    artifactHubView,
    layout.artifactPanelVisible,
    loadSession,
    refreshSessionHistory,
    refreshCurrentTask,
    task?.id,
    task?.session_id,
    task?.phase,
    task?.current_step,
  ]);

  const latestLocalHistoryTimestamp =
    localHistory.length > 0
      ? localHistory[localHistory.length - 1]?.timestamp ?? 0
      : 0;
  const latestRemoteHistoryTimestamp =
    task?.history && task.history.length > 0
      ? task.history[task.history.length - 1]?.timestamp ?? 0
      : 0;
  const shouldPreferOptimisticHistory =
    submissionInFlight ||
    task?.phase === "Failed" ||
    (task?.phase === "Running" &&
      localHistory.length > 0 &&
      (localHistory.length > (task?.history?.length ?? 0) ||
        latestLocalHistoryTimestamp > latestRemoteHistoryTimestamp));

  const {
    activeHistory,
    activeEvents,
    activeArtifacts,
    selectedArtifact,
    isRunning,
  } = useSessionRunSurface({
    task,
    localHistory,
    events,
    artifacts,
    preferLocalHistory: shouldPreferOptimisticHistory,
    selectedArtifactId,
    getArtifactId: (artifact) => artifact.artifact_id,
  });
  const {
    containerStyle,
    conversationTurns,
    hasSessionContent,
    inlineStudioDecisionPrompt,
    isDualPanelSpotlight,
    latestAnsweredTurnIndex,
    runPresentation,
    selectedInspectionArtifact,
    shouldAutoFocusStudioComposer,
    showInitialLoader,
    showOverlaySessionChrome,
    studioArtifactAvailable,
    studioArtifactExpected,
    studioStatusCard,
    suppressConversationPendingIndicators,
    turnContexts,
  } = useSpotlightSurfaceState({
    isStudioVariant,
    layout,
    activeHistory,
    activeEvents,
    activeArtifacts,
    selectedArtifact,
    selectedArtifactId,
    retainedArtifacts: retainedWorkbenchTrace.artifacts,
    task,
    chatEvents,
    inputLockedByCredential,
    seedIntent,
    intent,
    isRunning,
    submissionInFlight,
    submissionError,
    clarificationRequest,
    isGated,
    showPasswordPrompt,
  });
  const studioAvailableArtifacts = useMemo(
    () => collectAvailableStudioArtifacts(activeEvents, task?.studio_session ?? null),
    [activeEvents, task?.studio_session],
  );
  const activeArtifactStudioSessionId =
    task?.studio_session?.outcomeRequest?.outcomeKind === "artifact"
      ? task.studio_session.sessionId
      : null;
  const studioArtifactDrawerAvailable =
    studioArtifactAvailable || studioArtifactExpected || studioAvailableArtifacts.length > 0;

  useEffect(() => {
    if (!shouldAutoFocusStudioComposer) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [inputRef, shouldAutoFocusStudioComposer]);

  const {
    showScrollButton,
    scrollToBottom,
  } = useSessionConversationScroll({
    scrollContainerRef: chatAreaRef,
    autoScrollDeps: [
      activeHistory,
      chatEvents,
      task?.current_step,
      task?.events,
      events,
    ],
  });

  useSessionShellShortcuts({
    activeDropdown,
    clearActiveDropdown: () => setActiveDropdown(null),
    inspectionVisible: layout.artifactPanelVisible,
    closeInspectionSurface,
    canHideShell: !isStudioVariant,
    hideCurrentShell: hideSpotlightShell,
    toggleCommandPalette: inputLockedByCredential
      ? undefined
      : () => {
          setActiveDropdown(
            activeDropdown === "command_palette" ? null : "command_palette",
          );
        },
    toggleSidebar,
    startNewSession: handleNewChat,
  });

  const openSourceSummaryPanel = useCallback(
    (_summary: SourceSummary) => {
      void openArtifactHub("sources");
    },
    [openArtifactHub],
  );

  const handleStopSession = useCallback(async () => {
    try {
      await stopSessionTask();
    } catch (error) {
      console.error("Failed to stop session task:", error);
      return;
    }

    resetSession();
    void refreshSessionHistory().catch((error) => {
      console.error("Failed to refresh session history after stop:", error);
    });
  }, [refreshSessionHistory, resetSession]);

  const handleExportTraceBundle = useCallback(async () => {
    if (!activeSessionId) {
      return;
    }
    try {
      await exportThreadTraceBundle({
        threadId: activeSessionId,
        includeArtifactPayloads: true,
      });
    } catch (error) {
      console.error("Failed to export canonical trace bundle:", error);
    }
  }, [activeSessionId]);

  // ============================================
  // LEGACY PRESENTATION
  // ============================================

  const { legacyChatElements } = useLegacyPresentation({
    activeHistory,
    chatEvents,
    activeEvents,
    isRunning,
    taskMeta: {
      currentStep: task?.current_step,
      agent: task?.agent,
      generation: task?.generation,
      progress: task?.progress,
      totalSteps: task?.total_steps,
    },
    onOpenArtifact: openArtifactById,
  });

  useSessionStudioArtifactDrawer({
    enabled: isStudioVariant,
    artifactAvailable: studioArtifactDrawerAvailable,
    artifactExpected: studioArtifactExpected,
    activeSessionId: activeArtifactStudioSessionId,
    fallbackSessionId: task?.id || null,
    setVisible: setStudioArtifactVisible,
  });

  useEffect(() => {
    if (!isStudioVariant) {
      return;
    }
    setSelectedStudioArtifactSessionId((current) => {
      if (
        current &&
        (current === activeArtifactStudioSessionId ||
          studioAvailableArtifacts.some((artifact) => artifact.sessionId === current))
      ) {
        return current;
      }

      return null;
    });
  }, [
    activeArtifactStudioSessionId,
    isStudioVariant,
    studioAvailableArtifacts,
  ]);

  const handleOpenStudioArtifact = useCallback((studioSessionId: string) => {
    setSelectedStudioArtifactSessionId(studioSessionId);
    setStudioArtifactVisible(true);
  }, []);
  const handleToggleStudioArtifacts = useCallback(() => {
    if (!studioArtifactVisible) {
      setSelectedStudioArtifactSessionId(null);
      setStudioArtifactVisible(true);
      return;
    }

    if (selectedStudioArtifactSessionId !== null) {
      setSelectedStudioArtifactSessionId(null);
      return;
    }

    setStudioArtifactVisible(false);
  }, [selectedStudioArtifactSessionId, studioArtifactVisible]);
  const studioArtifactToggleLabel = !studioArtifactVisible
    ? "Show artifacts"
    : selectedStudioArtifactSessionId !== null
      ? "Browse artifacts"
      : "Hide artifacts";
  const studioArtifactMenuVisible =
    studioArtifactVisible && selectedStudioArtifactSessionId === null;
  const showStudioArtifactToggle =
    isStudioVariant && studioArtifactDrawerAvailable;
  const studioStatusCardNode = studioStatusCard ? (
    <StudioRunStateCard
      tone={studioStatusCard.tone}
      title={studioStatusCard.title}
      detail={studioStatusCard.detail}
      metrics={studioStatusCard.metrics}
      processes={studioStatusCard.processes}
      selectedSkills={studioStatusCard.selectedSkills}
      livePreview={studioStatusCard.livePreview}
      codePreview={studioStatusCard.codePreview}
    />
  ) : null;

  // ============================================
  // RENDER
  // ============================================

  const conversationSurface = (
    <div
      className={`${isStudioVariant ? "spot-studio-conversation" : "spot-main"} ${
        studioArtifactVisible ? "is-artifact-open" : ""
      }`}
    >
      {!layout.sidebarVisible && (
        <button
          className="spot-sidebar-toggle"
          onClick={() => toggleSidebar(true)}
          title="Show Sidebar (⌘K)"
        >
          {icons.sidebar}
        </button>
      )}

      {showStudioArtifactToggle ? (
        <div className="spot-studio-toolbar">
          <button
            type="button"
            className={`spot-studio-artifact-toggle ${
              studioArtifactVisible ? "is-open" : ""
            }`}
            onClick={handleToggleStudioArtifacts}
            aria-label={`${studioArtifactToggleLabel} (${
              task?.studio_session?.artifactManifest?.renderer === "workspace_surface"
                ? "Workspace renderer"
                : "Artifact stage"
            })`}
            aria-pressed={studioArtifactVisible}
            title={`${studioArtifactToggleLabel} (${
              task?.studio_session?.artifactManifest?.renderer === "workspace_surface"
                ? "Workspace renderer"
                : "Artifact stage"
            })`}
          >
            {icons.artifacts}
          </button>
        </div>
      ) : null}

      {showOverlaySessionChrome ? (
        <SpotlightOperatorStrip
          task={task}
          canOpenRewind={Boolean(task?.session_id || task?.id || sessions.length > 0)}
          planSummary={runPresentation.planSummary}
          artifactCount={activeArtifacts.length}
          eventCount={activeEvents.length}
          validationSummary={validationSummary}
          retainedTraceSummary={
            retainedWorkbenchEvidenceThreadId
              ? {
                  title:
                    activeWorkbenchSummary?.title ??
                    "Retained workbench trace",
                  loading: retainedWorkbenchTrace.loading,
                  error: retainedWorkbenchTrace.error,
                  eventCount: retainedWorkbenchTrace.events.length,
                  artifactCount: retainedWorkbenchTrace.artifacts.length,
                  latestEventTitle: latestRetainedWorkbenchEvent?.title ?? null,
                  latestArtifactTitle:
                    latestRetainedWorkbenchArtifact?.title ?? null,
                }
              : null
          }
          onOpenGate={() => {
            void showGateShell();
          }}
          onOpenRetainedEvidence={() => {
            if (preferredEvidenceArtifactId) {
              void openArtifactById(preferredEvidenceArtifactId);
              return;
            }
            void openArtifactHub("kernel_logs");
          }}
          onOpenView={(view) => {
            void openArtifactHub(view);
          }}
        />
      ) : null}

      {showOverlaySessionChrome ? (
        <SpotlightOrchestrationBoard
          task={task}
          planSummary={runPresentation.planSummary}
          runs={playbookRuns}
          loading={playbookRunsLoading}
          busyRunId={playbookRunsBusyRunId}
          message={playbookRunsMessage}
          error={playbookRunsError}
          onOpenView={(view) => {
            void openArtifactHub(view);
          }}
          onOpenArtifact={(artifactId) => {
            void openArtifactById(artifactId);
          }}
          onLoadSession={(sessionId) => {
            void handleLoadSession(sessionId);
          }}
          onResumeRun={(runId, stepId) => {
            void resumePlaybookRun(runId, stepId);
          }}
          onMessageWorker={(runId, sessionId, message) => {
            void messageWorkerSession(runId, sessionId, message);
          }}
          onStopWorker={(runId, sessionId) => {
            void stopWorkerSession(runId, sessionId);
          }}
          onStopSession={handleStopSession}
          onPromoteRunResult={(runId) => {
            void promoteRunResult(runId);
          }}
          onPromoteStepResult={(runId, stepId) => {
            void promoteStepResult(runId, stepId);
          }}
        />
      ) : null}

      <div className="spot-chat" ref={chatAreaRef}>
        {!hasSessionContent &&
          (isStudioVariant ? (
            <StudioConversationWelcome
              onSuggestionClick={(text) => {
                void handleSubmitText(text);
              }}
            />
          ) : (
            <IOIWatermark onSuggestionClick={(text) => setIntent(text)} />
          ))}

        {CONTENT_PIPELINE_V2_ENABLED ? (
          <ConversationTimeline
            conversationTurns={conversationTurns}
            latestAnsweredTurnIndex={latestAnsweredTurnIndex}
            turnContexts={turnContexts}
            runPresentation={runPresentation}
            isRunning={isRunning}
            currentStep={task?.current_step}
            visualHash={task?.visual_hash || null}
            sourceDurationLabel={task?.receipt?.duration}
            showInitialLoader={showInitialLoader}
            suppressPendingIndicators={suppressConversationPendingIndicators}
            icons={icons}
            onExportTraceBundle={handleExportTraceBundle}
            onOpenArtifactHub={(view, turnId) => {
              void openArtifactHub(view, turnId);
            }}
            onOpenSourceSummary={openSourceSummaryPanel}
            activeStudioArtifactSessionId={selectedStudioArtifactSessionId}
            onOpenStudioArtifact={
              isStudioVariant ? handleOpenStudioArtifact : undefined
            }
            inlineStatusCard={isStudioVariant ? studioStatusCardNode : null}
          />
        ) : (
          <>{legacyChatElements}</>
        )}

        {showInitialLoader && !CONTENT_PIPELINE_V2_ENABLED && (
          <ThoughtChain
            messages={[]}
            activeStep={task?.current_step || "Initializing..."}
            agentName={task?.agent || "Autopilot"}
            generation={task?.generation || 0}
            progress={0}
            totalSteps={task?.total_steps || 10}
          />
        )}

        {inlineStudioDecisionPrompt ? (
          <SpotlightGateDock
            inline={true}
            isGated={isGated}
            gateInfo={gateInfo}
            isPiiGate={isPiiGate}
            gateDeadlineMs={gateDeadlineMs}
            gateActionError={gateActionError}
            onApprove={handleApprove}
            onGrantScopedException={handleGrantScopedException}
            onDeny={handleDeny}
            showPasswordPrompt={showPasswordPrompt}
            credentialRequest={credentialRequest}
            onSubmitRuntimePassword={handleSubmitRuntimePassword}
            onCancelRuntimePassword={handleCancelRuntimePassword}
            showClarificationPrompt={showClarificationPrompt}
            clarificationRequest={clarificationRequest}
            onSubmitClarification={handleSubmitClarification}
            onCancelClarification={handleCancelClarification}
          />
        ) : null}
      </div>

      {!inlineStudioDecisionPrompt ? (
        <SpotlightGateDock
          isGated={isGated}
          gateInfo={gateInfo}
          isPiiGate={isPiiGate}
          gateDeadlineMs={gateDeadlineMs}
          gateActionError={gateActionError}
          onApprove={handleApprove}
          onGrantScopedException={handleGrantScopedException}
          onDeny={handleDeny}
          showPasswordPrompt={showPasswordPrompt}
          credentialRequest={credentialRequest}
          onSubmitRuntimePassword={handleSubmitRuntimePassword}
          onCancelRuntimePassword={handleCancelRuntimePassword}
          showClarificationPrompt={showClarificationPrompt}
          clarificationRequest={clarificationRequest}
          onSubmitClarification={handleSubmitClarification}
          onCancelClarification={handleCancelClarification}
        />
      ) : null}

      <SpotlightInputSection
        inputRef={inputRef}
        inputFocused={inputFocused}
        setInputFocused={setInputFocused}
        isDraggingFile={isDraggingFile}
        inputLockedByCredential={inputLockedByCredential}
        showPasswordPrompt={showPasswordPrompt}
        task={task}
        sessions={sessions}
        intent={intent}
        setIntent={setIntent}
        onInputChange={handleInputChange}
        onInputKeyDown={handleInputKeyDown}
        autoContext={autoContext}
        onToggleAutoContext={() => setAutoContext(!autoContext)}
        isRunning={isRunning}
        isGated={isGated}
        onStop={() => stopSessionTask().catch(console.error)}
        onSubmit={handleSubmit}
        onNewSession={handleNewChat}
        onLoadSession={(sessionId) => {
          void handleLoadSession(sessionId);
        }}
        onOpenGate={() => {
          void showGateShell();
        }}
        onOpenView={(view) => {
          void openArtifactHub(view);
        }}
        onSubmitClarification={(optionId, otherText) =>
          handleSubmitClarification(optionId, otherText)
        }
        onOpenValidationEvidence={() => {
          if (preferredEvidenceArtifactId) {
            void openArtifactById(preferredEvidenceArtifactId);
            return;
          }
          void openArtifactHub("kernel_logs");
        }}
        workspaceOptions={workspaceOptions}
        workspaceMode={workspaceMode}
        onSelectWorkspaceMode={setWorkspaceMode}
        modelOptions={modelOptions}
        selectedModel={selectedModel}
        onSelectModel={setSelectedModel}
        planMode={planMode}
        onTogglePlanMode={togglePlanMode}
        artifactCount={activeArtifacts.length}
        workerCount={Math.max(
          runPresentation.planSummary?.workerCount ?? 0,
          task?.swarm_tree.length ?? 0,
        )}
        activeDropdown={activeDropdown}
        setActiveDropdown={setActiveDropdown}
        onOpenSettings={() => openStudio("settings")}
        placeholder={
          isStudioVariant
            ? "Describe the outcome you want. Studio will route it into conversation, widget, visualizer, or artifact."
            : undefined
        }
      />
    </div>
  );

  const artifactPanelNode = (
    <SpotlightArtifactPanel
      visible={layout.artifactPanelVisible}
      artifactHubView={artifactHubView}
      artifactHubTurnId={artifactHubTurnId}
      activeSessionId={activeSessionId}
      task={task}
      sessions={sessions}
      events={activeEvents}
      artifacts={activeArtifacts}
      selectedArtifact={selectedInspectionArtifact}
      sourceSummary={runPresentation.sourceSummary}
      thoughtSummary={runPresentation.thoughtSummary}
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
      onOpenArtifact={(artifactId) => {
        void openArtifactById(artifactId);
      }}
      onRetryPlaybookRun={(runId) => {
        void retryPlaybookRun(runId);
      }}
      onResumePlaybookRun={(runId, stepId) => {
        void resumePlaybookRun(runId, stepId);
      }}
      onDismissPlaybookRun={(runId) => {
        void dismissPlaybookRun(runId);
      }}
      onMessageWorkerSession={(runId, sessionId, message) => {
        void messageWorkerSession(runId, sessionId, message);
      }}
      onStopWorkerSession={(runId, sessionId) => {
        void stopWorkerSession(runId, sessionId);
      }}
      onPromoteRunResult={(runId) => {
        void promoteRunResult(runId);
      }}
      onPromoteStepResult={(runId, stepId) => {
        void promoteStepResult(runId, stepId);
      }}
      onPromoteStagedOperation={(operationId) => {
        void promoteStagedOperation(operationId);
      }}
      onRemoveStagedOperation={(operationId) => {
        void removeStagedOperation(operationId);
      }}
      onLoadSession={(sessionId) => {
        void handleLoadSession(sessionId);
      }}
      onStopSession={handleStopSession}
      onOpenGate={() => {
        void showGateShell();
      }}
      isGated={isGated}
      gateInfo={gateInfo}
      isPiiGate={isPiiGate}
      gateDeadlineMs={gateDeadlineMs}
      gateActionError={gateActionError}
      credentialRequest={credentialRequest}
      clarificationRequest={clarificationRequest}
      onApprove={handleApprove}
      onGrantScopedException={handleGrantScopedException}
      onDeny={handleDeny}
      onSubmitRuntimePassword={handleSubmitRuntimePassword}
      onCancelRuntimePassword={handleCancelRuntimePassword}
      onSubmitClarification={handleSubmitClarification}
      onCancelClarification={handleCancelClarification}
      onSeedIntent={(nextIntent) => {
        setIntent(nextIntent);
        window.setTimeout(() => {
          inputRef.current?.focus();
        }, 0);
      }}
      onClose={() => {
        void closeInspectionSurface();
      }}
    />
  );

  const overlaySurface = (
    <OverlayConversationSurface
      isStudioVariant={isStudioVariant}
      conversationContent={conversationSurface}
      showScrollButton={showScrollButton}
      onScrollToBottom={scrollToBottom}
      artifactPanelVisible={layout.artifactPanelVisible}
      artifactPanel={artifactPanelNode}
    />
  );

  return (
    <div
      className={`spot-window ${isStudioVariant ? "spot-window--studio" : ""}`}
      onClick={handleGlobalClick}
      ref={containerRef}
    >
      <div
        className={`spot-container ${layout.sidebarVisible ? "sidebar-open" : ""}`}
        style={containerStyle}
      >
        <div
          className={`spot-content ${
            isDualPanelSpotlight ? "spot-content--dual-panel" : ""
          }`}
        >
          {layout.sidebarVisible && (
            <SessionHistorySidebar
              sessions={sessions}
              onSelectSession={handleLoadSession}
              onNewChat={handleNewChat}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              onToggleSidebar={() => toggleSidebar(false)}
              activeSessionId={task?.session_id || task?.id || null}
              title="Chats"
              newLabel="New chat"
              emptyLabel="No chats yet"
              icons={{
                plus: icons.plus,
                search: icons.search,
                sidebar: icons.sidebar,
              }}
            />
          )}

          {isStudioVariant ? (
            <StudioConversationSurface
              artifactVisible={studioArtifactVisible}
              artifactMenuVisible={studioArtifactMenuVisible}
              artifactDrawerVisible={
                studioArtifactDrawerAvailable && studioArtifactVisible
              }
              conversationSurface={overlaySurface}
              artifactDrawer={
                <div
                  className={`spot-studio-artifact-drawer ${
                    studioArtifactVisible ? "is-open" : ""
                  } ${studioArtifactMenuVisible ? "is-menu" : ""}`}
                  aria-hidden={!studioArtifactVisible}
                >
                  <StudioArtifactSurface
                    task={task}
                    events={activeEvents}
                    selectedStudioSessionId={selectedStudioArtifactSessionId}
                    onSelectStudioSession={setSelectedStudioArtifactSessionId}
                    onCollapse={() => setStudioArtifactVisible(false)}
                    onSeedIntent={(nextIntent) => {
                      setIntent(nextIntent);
                      window.setTimeout(() => {
                        inputRef.current?.focus();
                      }, 0);
                    }}
                  />
                </div>
              }
            />
          ) : (
            overlaySurface
          )}
        </div>
      </div>
    </div>
  );
}
