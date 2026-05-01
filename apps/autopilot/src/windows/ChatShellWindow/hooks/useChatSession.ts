import { useCallback } from "react";
import type {
  Dispatch,
  RefObject,
  SetStateAction,
} from "react";
import {
  hideChatSessionShell,
  type SessionGateChatEvent as ChatEvent,
  useHydrateSessionStore,
  useSessionInputComposer,
  useSessionDeferredFocus,
  useSessionInspectionSurface,
  useSessionInterruptionActions,
  useSessionShellActions,
  useSessionUiState,
} from "@ioi/agent-ide";
import type {
  AgentTask,
  ArtifactHubViewKey,
  ChatMessage,
  SessionSummary,
} from "../../../types";
import { buildPlanModeIntent } from "../../ChatShellWindow/utils/planModePrompt";

type UseChatSessionOptions = {
  bootstrapSessionController: () => Promise<void>;
  isChatVariant: boolean;
  task: AgentTask | null;
  inputRef: RefObject<HTMLTextAreaElement>;
  setChatEvents: Dispatch<SetStateAction<ChatEvent[]>>;
  setRuntimePasswordPending: Dispatch<SetStateAction<boolean>>;
  setRuntimePasswordSessionId: Dispatch<SetStateAction<string | null>>;
  sessions: SessionSummary[];
  startTask: (intent: string) => Promise<AgentTask | null>;
  continueTask: (sessionId: string, input: string) => Promise<void>;
  dismissTask: () => Promise<void>;
  loadSession: (sessionId: string) => Promise<AgentTask | null>;
  resetSession: () => void;
  setSelectedArtifactId: (artifactId: string | null) => void;
  toggleArtifactPanel: (visible?: boolean) => Promise<void>;
  loadThreadEvents: (threadId: string, limit?: number, cursor?: number) => Promise<unknown>;
  loadThreadArtifacts: (threadId: string) => Promise<unknown>;
  contextualizeIntent?: (text: string) => string;
};

export function shouldContinueChatComposerSession(
  isChatVariant: boolean,
  task: AgentTask | null,
): boolean {
  if (!task?.id || task.phase === "Failed") {
    return false;
  }

  if (isChatVariant && task.phase === "Complete") {
    // Chat follow-ups should continue the completed session by default so
    // retained widget or artifact context stays available unless the user
    // explicitly starts a new outcome.
    return true;
  }

  return true;
}

export function useChatSession({
  bootstrapSessionController,
  isChatVariant,
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
  contextualizeIntent,
}: UseChatSessionOptions) {
  const {
    intent,
    setIntent,
    localHistory,
    setLocalHistory,
    submissionInFlight,
    setSubmissionInFlight,
    submissionError,
    setSubmissionError,
    autoContext,
    setAutoContext,
    activeDropdown,
    setActiveDropdown,
    workspaceMode,
    setWorkspaceMode,
    selectedModel,
    setSelectedModel,
    planMode,
    setPlanMode,
    inspectionView: artifactHubView,
    setInspectionView: setArtifactHubView,
    inspectionTargetId: artifactHubTurnId,
    setInspectionTargetId: setArtifactHubTurnId,
    inputFocused,
    setInputFocused,
    searchQuery,
    setSearchQuery,
    isDraggingFile,
  } = useSessionUiState<ChatMessage, ArtifactHubViewKey>();

  const getTaskThreadId = useCallback(
    (currentTask: AgentTask) => currentTask.session_id || currentTask.id || null,
    [],
  );

  const resolveChatView = useCallback((targetView: string) => targetView, []);

  const {
    openArtifactById,
    openInspectionHub: openArtifactHub,
    closeInspectionSurface,
    resetInspectionSurface,
  } = useSessionInspectionSurface<ArtifactHubViewKey>({
    setInspectionView: (view) => setArtifactHubView(view),
    setInspectionTargetId: (turnId) => setArtifactHubTurnId(turnId),
    setSelectedArtifactId,
    toggleInspectionVisible: toggleArtifactPanel,
  });

  const handleTogglePlanMode = useCallback(
    (nextValue?: boolean) => {
      const nextPlanMode =
        typeof nextValue === "boolean" ? nextValue : !planMode;
      setPlanMode(nextPlanMode);
      if (nextPlanMode) {
        void openArtifactHub("active_context");
      }
    },
    [openArtifactHub, planMode, setPlanMode],
  );

  const prepareForSessionAttach = useCallback(async () => {
    setSubmissionInFlight(false);
    setSubmissionError(null);
    await resetInspectionSurface();
  }, [
    setSubmissionError,
    setSubmissionInFlight,
    resetInspectionSurface,
  ]);

  useHydrateSessionStore<AgentTask>({
    connectSessionStore: bootstrapSessionController,
    session: task,
    getSessionThreadId: getTaskThreadId,
    loadSessionEvents: loadThreadEvents,
    loadSessionArtifacts: loadThreadArtifacts,
  });

  useSessionDeferredFocus({
    focusRef: inputRef,
  });

  const { openChat, attachSession: handleLoadSession } =
    useSessionShellActions<AgentTask>({
      isChatShell: isChatVariant,
      hideCurrentShell: hideChatSessionShell,
      resolveChatView,
      loadSession,
      beforeAttachSession: prepareForSessionAttach,
      onAttachSessionError: (error) => {
        console.error("Failed to load session:", error);
      },
    });

  const {
    handleSubmit,
    submitText: handleSubmitText,
    handleNewSession: handleNewChat,
    handleInputChange,
    handleInputKeyDown,
  } = useSessionInputComposer<AgentTask, ChatMessage, ChatEvent>({
    task,
    intent,
    inputRef,
    startTask: (text) =>
      startTask(buildPlanModeIntent(contextualizeIntent?.(text) ?? text, planMode)),
    continueTask: (sessionId, text) =>
      continueTask(
        sessionId,
        buildPlanModeIntent(contextualizeIntent?.(text) ?? text, planMode),
      ),
    dismissTask,
    resetSession,
    setIntent,
    setLocalHistory,
    setSubmissionInFlight,
    setSubmissionError,
    setChatEvents,
    resetInspectionSurface,
    beforeStartTask: async (text) => {
      if (
        !isChatVariant &&
        (text.toLowerCase().includes("work graph") || text.toLowerCase().includes("team"))
      ) {
        await openChat("autopilot");
      }
    },
    shouldContinueExistingSession: (currentTask) =>
      shouldContinueChatComposerSession(isChatVariant, currentTask),
    onSubmitError: (error) => {
      console.error(error);
    },
    onEscapeKeyDown: !isChatVariant
      ? () => hideChatSessionShell().catch(console.error)
      : undefined,
    resolveTaskFailureMessage: (currentTask) => {
      const verifiedChatArtifact =
        currentTask.chat_session?.artifactManifest?.verification.status ===
        "ready";
      return verifiedChatArtifact
        ? null
        : currentTask.current_step || "Chat could not complete this run.";
    },
  });

  const {
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
  } = useSessionInterruptionActions<AgentTask>({
    task,
    continueTask,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
    onClarificationSubmit: ({ sessionId, optionId, exactIdentifier }) => {
      console.info("[Autopilot][Clarification] submit", {
        sessionId,
        optionId,
        exactIdentifier,
      });
    },
    onClarificationCancel: ({ sessionId }) => {
      console.info("[Autopilot][Clarification] cancel", { sessionId });
    },
  });

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown, setActiveDropdown]);

  return {
    intent,
    setIntent,
    localHistory,
    submissionInFlight,
    submissionError,
    autoContext,
    setAutoContext,
    activeDropdown,
    setActiveDropdown,
    sessions,
    workspaceMode,
    setWorkspaceMode,
    selectedModel,
    setSelectedModel,
    planMode,
    setPlanMode,
    togglePlanMode: handleTogglePlanMode,
    artifactHubView,
    setArtifactHubView,
    artifactHubTurnId,
    setArtifactHubTurnId,
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
  };
}
