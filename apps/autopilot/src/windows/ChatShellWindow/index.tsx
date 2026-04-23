// apps/autopilot/src/windows/ChatShellWindow/index.tsx

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  hideChatSessionShell,
  setActiveAssistantSessionRuntime,
  stopAssistantSession,
  type AssistantSessionRuntime,
  SessionHistorySidebar,
  useAssistantWorkbenchState,
  useSessionApprovalState,
  useSessionConversationScroll,
  useSessionDeferredFocus,
  useSessionDisplayState,
  useSessionShellShortcuts,
  useSessionChatArtifactDrawer,
} from "@ioi/agent-ide";
import { bootstrapAgentSession, useAgentStore } from "../../session/autopilotSession";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import { recordChatLaunchReceipt } from "../../services/chatLaunchState";
import { openCompanionGate } from "../../services/companionShellNavigation";
import { buildAssistantWorkbenchSummary } from "../../lib/assistantWorkbenchSummary";
import { useLiveValidationSummary } from "../../hooks/useLiveValidationSummary";
import { useRetainedWorkbenchTrace } from "../../hooks/useRetainedWorkbenchTrace";
import { buildArtifactHubNavigation } from "../../services/artifactHubNavigation";
import { applyPendingChatShellLaunch } from "../../services/chatShellPendingLaunchNavigation";
import {
  AgentTask,
  AgentEvent,
  Artifact,
  SessionSummary,
} from "../../types";
import { useChatLayout } from "./hooks/useChatLayout";
import { useChatPlaybookRuns } from "./hooks/useChatPlaybookRuns";
import { useChatStagedOperations } from "./hooks/useChatStagedOperations";
import {
  selectRetainableDrawerSession,
  useChatSurfaceState,
} from "./hooks/useChatSurfaceState";
import {
  shouldContinueChatComposerSession,
  useChatSession,
} from "./hooks/useChatSession";
import { useLegacyPresentation } from "./hooks/useLegacyPresentation";

// Sub-components
import { icons } from "../ChatShellWindow/components/Icons";
import { IOIWatermark } from "../ChatShellWindow/components/IOIWatermark";
import { ThoughtChain } from "../ChatShellWindow/components/ThoughtChain";
import { OverlayConversationSurface } from "../ChatShellWindow/components/OverlayConversationSurface";
import { ChatArtifactPanel } from "./components/ChatArtifactPanel";
import { ConversationTimeline } from "../ChatShellWindow/components/ConversationTimeline";
import { ChatInputSection } from "./components/ChatInputSection";
import { ChatGateDock } from "./components/ChatGateDock";
import { ChatOperatorStrip } from "./components/ChatOperatorStrip";
import { ChatOrchestrationBoard } from "./components/ChatOrchestrationBoard";
import { ChatConversationSurface } from "../ChatShellWindow/components/ChatConversationSurface";
import { ChatConversationSidebar } from "../ChatShellWindow/components/ChatConversationSidebar";
import { ChatArtifactSurface } from "../ChatShellWindow/components/ChatArtifactSurface";
import { collectAvailableArtifacts } from "../ChatShellWindow/components/artifactConversationModel";
import {
  ChatConversationWelcome,
  ChatRunStateCard,
} from "../ChatShellWindow/components/ChatConversationPanels";
import { exportThreadTraceBundle } from "../ChatShellWindow/utils/exportContext";
import {
  CONTENT_PIPELINE_V2_ENABLED,
  modelOptions,
  workspaceOptions,
} from "../ChatShellWindow/constants";

// Styles
import "../ChatShellWindow/styles/Layout.css";
import "../ChatShellWindow/styles/Chat.css";
import "../ChatShellWindow/styles/Sidebar.css";
import "../ChatShellWindow/styles/Components.css";
import "../ChatShellWindow/styles/Visuals.css";
import "../ChatShellWindow/styles/ArtifactPanel.css";
import "../ChatShellWindow/styles/Overrides.css";
import "../ChatShellWindow/styles/MicroEventCard.css";
import "../ChatShellWindow/styles/ChatSurface.css";

type ChatShellWindowProps = {
  variant?: "overlay" | "chat";
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  sessionRuntime?: AssistantSessionRuntime;
};

function taskSessionId(task: AgentTask | null): string | null {
  return task?.session_id || task?.id || null;
}

function isLikelyContextDependentSeedIntent(intent: string): boolean {
  const normalized = intent.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  return [
    /^how about\b/,
    /^what about\b/,
    /^and\b/,
    /^also\b/,
    /^instead\b/,
    /^then\b/,
    /^tomorrow\b/,
    /^next\b/,
    /^same\b/,
    /^that\b/,
    /^those\b/,
    /^them\b/,
    /\b(instead|tomorrow|next one|same one|that one|those)\b/,
  ].some((pattern) => pattern.test(normalized));
}

function sessionLikelyAwaitingFollowUp(session: SessionSummary): boolean {
  const phase = (session.phase ?? "").trim().toLowerCase();
  const currentStep = (session.current_step ?? "").trim().toLowerCase();
  const resumeHint = (session.resume_hint ?? "").trim().toLowerCase();

  if (phase && phase !== "complete" && phase !== "failed") {
    return true;
  }

  return [currentStep, resumeHint].some(
    (value) =>
      value.includes("clarification") ||
      value.includes("approval") ||
      value.includes("waiting for") ||
      value.includes("resume"),
  );
}

function looksLikeEllipticalFollowUpReply(intent: string): boolean {
  const normalized = intent.trim().toLowerCase();
  if (!normalized || normalized.endsWith("?")) {
    return false;
  }

  const wordCount = normalized.split(/\s+/).filter(Boolean).length;
  const startsFreshRequest = /^(find|show|give|list|draft|write|make|create|plan|build|generate|tell|recommend|search|look up|book|buy|compose|reply|summarize|explain)\b/.test(
    normalized,
  );

  if (
    [
      /^(near|around|within|in|at|by|for|via|through|on)\b/,
      /^(slack|email|gmail|text|sms|chat)\b/,
      /^(today|tomorrow|tonight|this weekend|this week|next week)\b/,
    ].some((pattern) => pattern.test(normalized))
  ) {
    return true;
  }

  if (
    !startsFreshRequest &&
    wordCount <= 6 &&
    (normalized.includes(",") || normalized.endsWith("."))
  ) {
    return true;
  }

  return !startsFreshRequest && wordCount <= 3 && normalized.length <= 48;
}

function preferredClarificationOptionId(task: AgentTask | null): string | null {
  const options = task?.clarification_request?.options ?? [];
  return (
    options.find((option) => option.recommended)?.id ??
    options[0]?.id ??
    null
  );
}

function selectSeedIntentContinuationSession(
  sessions: SessionSummary[],
): SessionSummary | null {
  const sorted = [...sessions].sort((left, right) => right.timestamp - left.timestamp);
  return (
    sorted.find((session) => sessionLikelyAwaitingFollowUp(session)) ||
    sorted.find((session) => (session.phase || "").trim().toLowerCase() !== "failed") ||
    null
  );
}

// ============================================
// MAIN COMPONENT
// ============================================

export function ChatShellWindow({
  variant = "overlay",
  seedIntent = null,
  onConsumeSeedIntent,
  sessionRuntime,
}: ChatShellWindowProps) {
  const isStudioVariant = variant === "chat";
  const [chatArtifactVisible, setChatArtifactVisible] = useState(false);
  const [selectedChatArtifactSessionId, setSelectedChatArtifactSessionId] =
    useState<string | null>(null);

  // Layout management (synced with Tauri backend)
  const { layout, toggleSidebar, toggleArtifactPanel } = useChatLayout({
    persistToBackend: !isStudioVariant,
  });

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const submittedSeedIntentRef = useRef<string | null>(null);
  const seedIntentAttachAttemptRef = useRef<string | null>(null);
  const seedIntentProjectionRefreshRef = useRef<string | null>(null);

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
  } = useSessionApprovalState({
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
    openChat,
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
  } = useChatSession({
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
  } = useChatPlaybookRuns(activeSessionId);
  const {
    operations: stagedOperations,
    loading: stagedOperationsLoading,
    busyOperationId: stagedOperationsBusyId,
    message: stagedOperationsMessage,
    error: stagedOperationsError,
    promoteOperation: promoteStagedOperation,
    removeOperation: removeStagedOperation,
  } = useChatStagedOperations();

  // ============================================
  // INITIALIZATION
  // ============================================

  useEffect(() => {
    if (!sessionRuntime) {
      return;
    }

    setActiveAssistantSessionRuntime(sessionRuntime);
    return () => {
      setActiveAssistantSessionRuntime(null);
    };
  }, [sessionRuntime]);

  useEffect(() => {
    if (isStudioVariant) {
      return;
    }

    const className = "chat-session-shell-host";
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
      submittedSeedIntentRef.current = null;
      seedIntentAttachAttemptRef.current = null;
      seedIntentProjectionRefreshRef.current = null;
      return;
    }

    const nextIntent = seedIntent.trim();
    if (submittedSeedIntentRef.current === nextIntent) {
      void recordChatLaunchReceipt("chat_seed_intent_submit_skipped_duplicate", {
        intentLength: nextIntent.length,
      });
      onConsumeSeedIntent?.();
      return;
    }

    if (isStudioVariant) {
      const looksEllipticalReply = looksLikeEllipticalFollowUpReply(nextIntent);
      const clarificationOptionId = preferredClarificationOptionId(task);
      const hasPendingFollowUpSession = sessions.some((session) =>
        sessionLikelyAwaitingFollowUp(session),
      );
      const shouldWaitForRetainedProjection =
        looksEllipticalReply &&
        sessions.length === 0 &&
        !taskSessionId(task);
      const requiresRetainedContext =
        isLikelyContextDependentSeedIntent(nextIntent) ||
        (hasPendingFollowUpSession &&
          looksEllipticalReply) ||
        shouldWaitForRetainedProjection;
      const hasAttachableCurrentTask = shouldContinueChatComposerSession(
        isStudioVariant,
        task,
      );
      const currentSessionId = taskSessionId(task);

      if (requiresRetainedContext && !hasAttachableCurrentTask) {
        const continuationSession = selectSeedIntentContinuationSession(sessions);

        if (!continuationSession) {
          if (sessions.length === 0) {
            if (seedIntentProjectionRefreshRef.current !== nextIntent) {
              seedIntentProjectionRefreshRef.current = nextIntent;
              void Promise.allSettled([
                refreshSessionHistory(),
                refreshCurrentTask(),
              ]).catch((error) => {
                console.error(
                  "[Chat][SeedIntent] failed to refresh retained session projection",
                  error,
                );
              });
            }
            void recordChatLaunchReceipt(
              "chat_seed_intent_waiting_for_session_projection",
              {
                intentLength: nextIntent.length,
              },
            );
            if (shouldWaitForRetainedProjection) {
              return;
            }
          }
        } else if (continuationSession.session_id !== currentSessionId) {
          seedIntentProjectionRefreshRef.current = null;
          const attachKey = `${nextIntent}:${continuationSession.session_id}`;
          if (seedIntentAttachAttemptRef.current !== attachKey) {
            seedIntentAttachAttemptRef.current = attachKey;
            void recordChatLaunchReceipt("chat_seed_intent_attach_requested", {
              intentLength: nextIntent.length,
              sessionId: continuationSession.session_id,
            });
            void handleLoadSession(continuationSession.session_id)
              .then(() => {
                void recordChatLaunchReceipt("chat_seed_intent_attach_resolved", {
                  intentLength: nextIntent.length,
                  sessionId: continuationSession.session_id,
                });
              })
              .catch((error) => {
                seedIntentAttachAttemptRef.current = null;
                console.error(
                  "[Chat][SeedIntent] failed to attach retained session",
                  error,
                );
                void recordChatLaunchReceipt("chat_seed_intent_attach_failed", {
                  intentLength: nextIntent.length,
                  sessionId: continuationSession.session_id,
                  error:
                    error instanceof Error ? error.message : String(error),
                });
              });
          }
          return;
        }
      }

      submittedSeedIntentRef.current = nextIntent;
      seedIntentAttachAttemptRef.current = null;
      seedIntentProjectionRefreshRef.current = null;
      console.info("[Chat][SeedIntent] auto-submit requested", {
        length: nextIntent.length,
      });
      void recordChatLaunchReceipt("chat_seed_intent_submit_requested", {
        intentLength: nextIntent.length,
      });
      window.setTimeout(() => {
        try {
          if (task?.clarification_request && clarificationOptionId) {
            console.info("[Chat][SeedIntent] clarification submit dispatching");
            void recordChatLaunchReceipt(
              "chat_seed_intent_clarification_submit_dispatching",
              {
                intentLength: nextIntent.length,
                optionId: clarificationOptionId,
              },
            );
            const submitPromise = handleSubmitClarification(
              clarificationOptionId,
              nextIntent,
            );
            void recordChatLaunchReceipt(
              "chat_seed_intent_clarification_submit_called",
              {
                intentLength: nextIntent.length,
                optionId: clarificationOptionId,
              },
            );
            void submitPromise
              .then(() => {
                console.info("[Chat][SeedIntent] clarification submit resolved");
                void recordChatLaunchReceipt(
                  "chat_seed_intent_clarification_submit_resolved",
                  {
                    intentLength: nextIntent.length,
                    optionId: clarificationOptionId,
                  },
                );
              })
              .catch((error) => {
                console.error(
                  "[Chat][SeedIntent] clarification submit failed",
                  error,
                );
                void recordChatLaunchReceipt(
                  "chat_seed_intent_clarification_submit_failed",
                  {
                    intentLength: nextIntent.length,
                    optionId: clarificationOptionId,
                    error: error instanceof Error ? error.message : String(error),
                  },
                );
              });
            return;
          }

          console.info("[Chat][SeedIntent] auto-submit dispatching");
          void recordChatLaunchReceipt("chat_seed_intent_submit_dispatching", {
            intentLength: nextIntent.length,
          });
          const submitPromise = handleSubmitText(nextIntent);
          void recordChatLaunchReceipt("chat_seed_intent_submit_called", {
            intentLength: nextIntent.length,
          });
          void submitPromise
            .then(() => {
              console.info("[Chat][SeedIntent] auto-submit resolved");
              void recordChatLaunchReceipt("chat_seed_intent_submit_resolved", {
                intentLength: nextIntent.length,
              });
            })
            .catch((error) => {
              console.error("[Chat][SeedIntent] auto-submit failed", error);
              void recordChatLaunchReceipt("chat_seed_intent_submit_failed", {
                intentLength: nextIntent.length,
                error: error instanceof Error ? error.message : String(error),
              });
            });
        } catch (error) {
          console.error("[Chat][SeedIntent] auto-submit threw synchronously", error);
          void recordChatLaunchReceipt("chat_seed_intent_submit_sync_failed", {
            intentLength: nextIntent.length,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }, 0);
      onConsumeSeedIntent?.();
      return;
    }

    setIntent(nextIntent);
    onConsumeSeedIntent?.();
  }, [
    handleSubmitClarification,
    handleSubmitText,
    handleLoadSession,
    inputRef,
    isStudioVariant,
    onConsumeSeedIntent,
    refreshCurrentTask,
    refreshSessionHistory,
    sessions,
    seedIntent,
    setIntent,
    task,
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
  } = useSessionDisplayState({
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
    isDualPanelChat,
    latestAnsweredTurnIndex,
    runPresentation,
    selectedInspectionArtifact,
    shouldAutoFocusStudioComposer,
    showInitialLoader,
    showOverlaySessionChrome,
    studioArtifactAvailable,
    studioArtifactExpected,
    chatStatusCard,
    suppressConversationPendingIndicators,
    turnContexts,
  } = useChatSurfaceState({
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
    () => collectAvailableArtifacts(activeEvents, task?.chat_session ?? null),
    [activeEvents, task?.chat_session],
  );
  const activeArtifactStudioSessionId =
    task?.chat_session?.outcomeRequest?.outcomeKind === "artifact"
      ? task.chat_session.sessionId
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
    hideCurrentShell: hideChatSessionShell,
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

  const hubNavigation = useMemo(
    () =>
      buildArtifactHubNavigation({
        openArtifactHub,
        openArtifactById,
        preferredEvidenceArtifactId,
      }),
    [openArtifactById, openArtifactHub, preferredEvidenceArtifactId],
  );
  const appliedChatShellLaunchIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    return applyPendingChatShellLaunch(
      hubNavigation,
      appliedChatShellLaunchIdsRef.current,
    );
  }, [hubNavigation]);

  const handleStopSession = useCallback(async () => {
    try {
      await stopAssistantSession();
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

  useSessionChatArtifactDrawer({
    enabled: isStudioVariant,
    artifactAvailable: studioArtifactDrawerAvailable,
    artifactExpected: studioArtifactExpected,
    activeSessionId: activeArtifactStudioSessionId,
    fallbackSessionId: task?.id || null,
    setVisible: setChatArtifactVisible,
  });

  useEffect(() => {
    if (!isStudioVariant) {
      return;
    }
    setSelectedChatArtifactSessionId((current) => {
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

  const handleOpenChatArtifact = useCallback((chatSessionId: string) => {
    setSelectedChatArtifactSessionId(chatSessionId);
    setChatArtifactVisible(true);
  }, []);
  const handleToggleChatArtifacts = useCallback(() => {
    if (!chatArtifactVisible) {
      setSelectedChatArtifactSessionId(null);
      setChatArtifactVisible(true);
      return;
    }

    if (selectedChatArtifactSessionId !== null) {
      setSelectedChatArtifactSessionId(null);
      return;
    }

    setChatArtifactVisible(false);
  }, [selectedChatArtifactSessionId, chatArtifactVisible]);
  const studioArtifactMenuVisible =
    chatArtifactVisible && selectedChatArtifactSessionId === null;
  const showChatArtifactNav =
    isStudioVariant && studioArtifactDrawerAvailable;
  const handleStudioNewSession = useCallback(() => {
    setSelectedChatArtifactSessionId(null);
    setChatArtifactVisible(false);
    handleNewChat();
  }, [handleNewChat]);
  const handleStudioSelectSession = useCallback(
    (sessionId: string) => {
      setSelectedChatArtifactSessionId(null);
      setChatArtifactVisible(false);
      void handleLoadSession(sessionId);
    },
    [handleLoadSession],
  );
  const chatStatusCardNode = chatStatusCard ? (
    <ChatRunStateCard
      tone={chatStatusCard.tone}
      title={chatStatusCard.title}
      detail={chatStatusCard.detail}
      metrics={chatStatusCard.metrics}
      processes={chatStatusCard.processes}
      selectedSkills={chatStatusCard.selectedSkills}
      livePreview={chatStatusCard.livePreview}
      codePreview={chatStatusCard.codePreview}
    />
  ) : null;
  const studioSidebarNode = isStudioVariant ? (
    <ChatConversationSidebar
      sessions={sessions}
      activeSessionId={task?.session_id || task?.id || null}
      searchQuery={searchQuery}
      onSearchChange={setSearchQuery}
      onNewSession={handleStudioNewSession}
      onSelectSession={handleStudioSelectSession}
      showArtifactNav={showChatArtifactNav}
      artifactVisible={chatArtifactVisible}
      artifactCount={studioAvailableArtifacts.length}
      onToggleArtifacts={handleToggleChatArtifacts}
    />
  ) : null;

  // ============================================
  // RENDER
  // ============================================

  const conversationSurface = (
    <div
      className={`${isStudioVariant ? "spot-chat-conversation" : "spot-main"} ${
        chatArtifactVisible ? "is-artifact-open" : ""
      } ${isStudioVariant && !hasSessionContent ? "is-empty" : ""}`}
    >
      {!isStudioVariant && !layout.sidebarVisible && (
        <button
          className="spot-sidebar-toggle"
          onClick={() => toggleSidebar(true)}
          title="Show Sidebar (⌘K)"
        >
          {icons.sidebar}
        </button>
      )}

      {showOverlaySessionChrome ? (
        <ChatOperatorStrip
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
            void openCompanionGate();
          }}
          onOpenRetainedEvidence={() => {
            void hubNavigation.openValidationEvidence();
          }}
          onOpenView={(view) => {
            void hubNavigation.openView(view);
          }}
        />
      ) : null}

      {showOverlaySessionChrome ? (
        <ChatOrchestrationBoard
          task={task}
          planSummary={runPresentation.planSummary}
          runs={playbookRuns}
          loading={playbookRunsLoading}
          busyRunId={playbookRunsBusyRunId}
          message={playbookRunsMessage}
          error={playbookRunsError}
          onOpenView={(view) => {
            void hubNavigation.openView(view);
          }}
          onOpenArtifact={(artifactId) => {
            void hubNavigation.openArtifact(artifactId);
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
            <ChatConversationWelcome
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
              void hubNavigation.openView(view, turnId);
            }}
            onOpenSourceSummary={hubNavigation.openSourceSummary}
            activeChatArtifactSessionId={selectedChatArtifactSessionId}
            onOpenChatArtifact={
              isStudioVariant ? handleOpenChatArtifact : undefined
            }
            inlineStatusCard={isStudioVariant ? chatStatusCardNode : null}
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
          <ChatGateDock
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
        <ChatGateDock
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

      <ChatInputSection
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
        onStop={() => stopAssistantSession().catch(console.error)}
        onSubmit={handleSubmit}
        onNewSession={isStudioVariant ? handleStudioNewSession : handleNewChat}
        onLoadSession={(sessionId) => {
          if (isStudioVariant) {
            handleStudioSelectSession(sessionId);
            return;
          }
          void handleLoadSession(sessionId);
        }}
        onOpenGate={() => {
          void openCompanionGate();
        }}
        onOpenView={(view) => {
          void hubNavigation.openView(view);
        }}
        onSubmitClarification={(optionId, otherText) =>
          handleSubmitClarification(optionId, otherText)
        }
        onOpenValidationEvidence={() => {
          void hubNavigation.openValidationEvidence();
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
        onOpenSettings={() => openChat("settings")}
        placeholder={
          isStudioVariant
            ? "What do you want to materialize?"
            : undefined
        }
      />
    </div>
  );

  const artifactPanelNode = (
    <ChatArtifactPanel
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
        void hubNavigation.openArtifact(artifactId);
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
        void openCompanionGate();
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
      className={`spot-window ${isStudioVariant ? "spot-window--chat" : ""}`}
      onClick={handleGlobalClick}
      ref={containerRef}
    >
      <div
        className={`spot-container ${layout.sidebarVisible ? "sidebar-open" : ""}`}
        style={containerStyle}
      >
        <div
          className={`spot-content ${
            isDualPanelChat ? "spot-content--dual-panel" : ""
          }`}
        >
          {!isStudioVariant && layout.sidebarVisible && (
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
            <ChatConversationSurface
              sidebar={studioSidebarNode}
              artifactVisible={chatArtifactVisible}
              artifactMenuVisible={studioArtifactMenuVisible}
              artifactDrawerVisible={
                studioArtifactDrawerAvailable && chatArtifactVisible
              }
              conversationSurface={overlaySurface}
              artifactDrawer={
                <div
                  className={`spot-chat-artifact-drawer ${
                    chatArtifactVisible ? "is-open" : ""
                  } ${studioArtifactMenuVisible ? "is-menu" : ""}`}
                  aria-hidden={!chatArtifactVisible}
                >
                  <ChatArtifactSurface
                    task={task}
                    events={activeEvents}
                    selectedChatSessionId={selectedChatArtifactSessionId}
                    onSelectChatSession={setSelectedChatArtifactSessionId}
                    onCollapse={() => setChatArtifactVisible(false)}
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
