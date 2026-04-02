// apps/autopilot/src/windows/SpotlightWindow/index.tsx

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAgentStore } from "../../store/agentStore";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import {
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  ChatMessage,
  RunPresentation,
  SourceSummary,
} from "../../types";
import { useSpotlightLayout } from "./hooks/useSpotlightLayout";
import { useSpotlightSession } from "./hooks/useSpotlightSession";
import { useGateState } from "./hooks/useGateState";
import { useTurnContexts } from "./hooks/useTurnContexts";
import { useLegacyPresentation } from "./hooks/useLegacyPresentation";

// Sub-components
import { icons } from "./components/Icons";
import { IOIWatermark } from "./components/IOIWatermark";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { HistorySidebar } from "./components/HistorySidebar";
import { ThoughtChain } from "./components/ThoughtChain";
import { SpotlightArtifactPanel } from "./components/SpotlightArtifactPanel";
import { ConversationTimeline } from "./components/ConversationTimeline";
import { SpotlightInputSection } from "./components/SpotlightInputSection";
import { SpotlightGateDock } from "./components/SpotlightGateDock";
import { StudioArtifactSurface } from "./components/StudioArtifactSurface";
import { hasOpenableArtifactSurface } from "./components/studioArtifactSurfaceModel";
import {
  StudioConversationWelcome,
  StudioRunStateCard,
} from "./components/StudioConversationPanels";
import { buildRunPresentation } from "./viewmodels/contentPipeline";
import { exportThreadContextBundle } from "./utils/exportContext";
import {
  ARTIFACT_PANEL_WIDTH,
  BASE_PANEL_WIDTH,
  CONTENT_PIPELINE_V2_ENABLED,
  modelOptions,
  SIDEBAR_PANEL_WIDTH,
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
};

// ============================================
// MAIN COMPONENT
// ============================================

export function SpotlightWindow({
  variant = "overlay",
  seedIntent = null,
  onConsumeSeedIntent,
}: SpotlightWindowProps) {
  const isStudioVariant = variant === "studio";
  const [studioArtifactVisible, setStudioArtifactVisible] = useState(false);

  // Layout management (synced with Tauri backend)
  const { layout, toggleSidebar, toggleArtifactPanel } = useSpotlightLayout();

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const isUserAtBottomRef = useRef(true);
  const autoOpenedStudioArtifactSessionRef = useRef<string | null>(null);

  const {
    task,
    events,
    artifacts,
    selectedArtifactId,
    startTask,
    continueTask,
    resetSession,
    refreshCurrentTask,
    setSelectedArtifactId,
    loadThreadEvents,
    loadThreadArtifacts,
  } = useAgentStore();

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
    sessions,
    workspaceMode,
    setWorkspaceMode,
    selectedModel,
    setSelectedModel,
    chatEvents,
    setChatEvents,
    artifactHubView,
    setArtifactHubView,
    artifactHubTurnId,
    setArtifactHubTurnId,
    runtimePasswordPending,
    setRuntimePasswordPending,
    runtimePasswordSessionId,
    setRuntimePasswordSessionId,
    inputFocused,
    setInputFocused,
    searchQuery,
    setSearchQuery,
    isDraggingFile,
    openStudio,
    handleLoadSession,
    handleSubmit,
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
    handleNewChat,
    handleGlobalClick,
    handleInputChange,
    handleInputKeyDown,
  } = useSpotlightSession({
    isStudioVariant,
    task,
    inputRef,
    startTask,
    continueTask,
    resetSession,
    refreshCurrentTask,
    setSelectedArtifactId,
    toggleArtifactPanel,
    loadThreadEvents,
    loadThreadArtifacts,
  });

  const {
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
  } = useGateState({
    task,
    chatEvents,
    setChatEvents,
    runtimePasswordPending,
    runtimePasswordSessionId,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
  });

  const [showScrollButton, setShowScrollButton] = useState(false);

  // ============================================
  // INITIALIZATION
  // ============================================

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

    setIntent(seedIntent);
    window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
    onConsumeSeedIntent?.();
  }, [inputRef, onConsumeSeedIntent, seedIntent, setIntent]);

  useEffect(() => {
    const resetUnlistenPromise = listenForAutopilotDataReset();
    return () => {
      resetUnlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  // ============================================
  // SCROLL MANAGEMENT
  // ============================================

  useEffect(() => {
    const chatArea = chatAreaRef.current;
    if (!chatArea) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = chatArea;
      const distFromBottom = scrollHeight - scrollTop - clientHeight;
      const isNearBottom = distFromBottom < 100;

      isUserAtBottomRef.current = isNearBottom;
      setShowScrollButton(!isNearBottom);
    };

    chatArea.addEventListener("scroll", handleScroll);
    return () => chatArea.removeEventListener("scroll", handleScroll);
  }, []);

  const shouldPreferLocalHistory =
    localHistory.length > 0 &&
    (!task?.history?.length || task?.phase === "Failed" || submissionInFlight);
  const activeHistory: ChatMessage[] = shouldPreferLocalHistory
    ? localHistory
    : (task?.history ?? []);
  const activeEvents: AgentEvent[] = task?.events?.length
    ? task.events
    : events;
  const activeArtifacts: Artifact[] = task?.artifacts?.length
    ? task.artifacts
    : artifacts;
  const selectedArtifact =
    activeArtifacts.find(
      (artifact) => artifact.artifact_id === selectedArtifactId,
    ) || null;

  const isRunning = task?.phase === "Running";
  const hasContent =
    !!task ||
    localHistory.length > 0 ||
    chatEvents.length > 0 ||
    activeEvents.length > 0;
  const activeStudioSessionId = task?.studio_session?.sessionId ?? null;
  const studioArtifactAvailable = useMemo(() => {
    const manifest = task?.studio_session?.artifactManifest;
    if (!manifest) {
      return false;
    }

    return hasOpenableArtifactSurface(
      manifest,
      task?.renderer_session ?? null,
      task?.build_session?.workspaceRoot ?? null,
    );
  }, [
    task?.build_session?.workspaceRoot,
    task?.renderer_session,
    task?.studio_session,
  ]);

  const panelWidth =
    BASE_PANEL_WIDTH +
    (layout.sidebarVisible ? SIDEBAR_PANEL_WIDTH : 0) +
    (layout.artifactPanelVisible ? ARTIFACT_PANEL_WIDTH : 0);
  const containerStyle = isStudioVariant
    ? undefined
    : { width: `${panelWidth}px` };

  const runPresentation: RunPresentation = useMemo(
    () => buildRunPresentation(activeHistory, activeEvents, activeArtifacts),
    [activeArtifacts, activeEvents, activeHistory],
  );

  const { conversationTurns, latestAnsweredTurnIndex, turnContexts } =
    useTurnContexts({
      activeHistory,
      activeEvents,
      runPresentation,
    });

  useEffect(() => {
    if (chatAreaRef.current && isUserAtBottomRef.current) {
      chatAreaRef.current.scrollTo({
        top: chatAreaRef.current.scrollHeight,
        behavior: "smooth",
      });
    }
  }, [activeHistory, chatEvents, task?.current_step, task?.events, events]);

  const scrollToBottom = useCallback(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTo({
        top: chatAreaRef.current.scrollHeight,
        behavior: "smooth",
      });
      isUserAtBottomRef.current = true;
      setShowScrollButton(false);
    }
  }, []);

  // ============================================
  // KEYBOARD SHORTCUTS
  // ============================================

  useEffect(() => {
    const isEditableTarget = (target: EventTarget | null): boolean => {
      if (!(target instanceof HTMLElement)) return false;
      const tag = target.tagName.toLowerCase();
      return (
        target.isContentEditable ||
        tag === "input" ||
        tag === "textarea" ||
        tag === "select"
      );
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      const editableTarget = isEditableTarget(e.target);

      if (editableTarget) {
        return;
      }

      if (e.key === "Escape") {
        if (activeDropdown) {
          setActiveDropdown(null);
        } else if (layout.artifactPanelVisible) {
          toggleArtifactPanel(false);
        } else if (!isStudioVariant) {
          invoke("hide_spotlight").catch(console.error);
        }
        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        toggleSidebar();
        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key === "n") {
        e.preventDefault();
        handleNewChat();
        return;
      }
    };

    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, [
    activeDropdown,
    handleNewChat,
    isStudioVariant,
    layout.artifactPanelVisible,
    setActiveDropdown,
    toggleSidebar,
    toggleArtifactPanel,
  ]);

  // ============================================
  // ARTIFACT PANEL HANDLERS
  // ============================================

  const openArtifactById = useCallback(
    (artifactId: string) => {
      setArtifactHubView(null);
      setArtifactHubTurnId(null);
      setSelectedArtifactId(artifactId);
      void toggleArtifactPanel(true);
    },
    [
      setArtifactHubTurnId,
      setArtifactHubView,
      setSelectedArtifactId,
      toggleArtifactPanel,
    ],
  );

  const openArtifactHub = useCallback(
    (preferredView?: ArtifactHubViewKey, preferredTurnId?: string | null) => {
      setArtifactHubView(preferredView || null);
      setArtifactHubTurnId(preferredTurnId || null);
      setSelectedArtifactId(null);
      void toggleArtifactPanel(true);
    },
    [
      setArtifactHubTurnId,
      setArtifactHubView,
      setSelectedArtifactId,
      toggleArtifactPanel,
    ],
  );

  const openSourceSummaryPanel = useCallback(
    (_summary: SourceSummary) => {
      openArtifactHub("sources");
    },
    [openArtifactHub],
  );

  const closeRightPanel = useCallback(() => {
    setArtifactHubView(null);
    setArtifactHubTurnId(null);
    void toggleArtifactPanel(false);
  }, [setArtifactHubTurnId, setArtifactHubView, toggleArtifactPanel]);

  const handleDownloadContext = useCallback(async () => {
    if (!activeSessionId) {
      return;
    }
    try {
      await exportThreadContextBundle({
        threadId: activeSessionId,
        includeArtifactPayloads: true,
      });
    } catch (error) {
      console.error("Failed to export run context bundle:", error);
    }
  }, [activeSessionId]);

  // ============================================
  // LEGACY PRESENTATION
  // ============================================

  const { legacyChatElements, hasLegacyChainContent } = useLegacyPresentation({
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

  const showInitialLoader = CONTENT_PIPELINE_V2_ENABLED
    ? isRunning && conversationTurns.length === 0
    : isRunning && !hasLegacyChainContent;

  useEffect(() => {
    if (!isStudioVariant) {
      return;
    }

    if (!studioArtifactAvailable) {
      setStudioArtifactVisible(false);
      if (!activeStudioSessionId) {
        autoOpenedStudioArtifactSessionRef.current = null;
      }
      return;
    }

    const nextSessionId = activeStudioSessionId || task?.id || null;
    if (!nextSessionId) {
      return;
    }

    if (autoOpenedStudioArtifactSessionRef.current === nextSessionId) {
      return;
    }

    autoOpenedStudioArtifactSessionRef.current = nextSessionId;
    setStudioArtifactVisible(true);
  }, [
    activeStudioSessionId,
    isStudioVariant,
    studioArtifactAvailable,
    task?.id,
  ]);

  const studioStatusCard = useMemo(() => {
    if (!isStudioVariant) {
      return null;
    }

    if (submissionError) {
      return (
        <StudioRunStateCard
          tone="error"
          title={
            task?.studio_session
              ? "Studio could not produce a usable artifact"
              : "Studio could not start this run"
          }
          detail={submissionError}
        />
      );
    }

    if (submissionInFlight) {
      return (
        <StudioRunStateCard
          title="Routing the request"
          detail="Studio is choosing whether this should remain conversational, open a tool surface, render a visualizer, or materialize an artifact."
        />
      );
    }

    if (
      task &&
      isRunning &&
      !activeStudioSessionId &&
      !runPresentation.finalAnswer
    ) {
      return (
        <StudioRunStateCard
          title="Preparing the outcome surface"
          detail={
            task.current_step ||
            "Studio is materializing the right outcome type and waiting for verification evidence."
          }
        />
      );
    }

    if (
      task?.clarification_request &&
      task.studio_session &&
      !studioArtifactAvailable
    ) {
      return (
        <StudioRunStateCard
          title="Studio needs clarification before it can open an artifact"
          detail={task.current_step || task.clarification_request.question}
        />
      );
    }

    if (
      task?.studio_session &&
      !studioArtifactAvailable &&
      task.studio_session.lifecycleState === "blocked"
    ) {
      return (
        <StudioRunStateCard
          tone="error"
          title="Studio stopped before a usable artifact existed"
          detail={
            task.current_step ||
            task.studio_session.artifactManifest.verification.summary ||
            task.studio_session.verifiedReply.summary
          }
        />
      );
    }

    return null;
  }, [
    activeStudioSessionId,
    isRunning,
    isStudioVariant,
    runPresentation.finalAnswer,
    studioArtifactAvailable,
    submissionError,
    submissionInFlight,
    task,
  ]);

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

      {isStudioVariant && studioArtifactAvailable ? (
        <div className="spot-studio-toolbar">
          <button
            type="button"
            className={`spot-studio-artifact-toggle ${
              studioArtifactVisible ? "is-open" : ""
            }`}
            onClick={() => setStudioArtifactVisible((current) => !current)}
          >
            <span>
              {studioArtifactVisible ? "Hide artifact" : "Open artifact"}
            </span>
            <small>
              {task?.studio_session?.artifactManifest?.renderer ===
              "workspace_surface"
                ? "Workspace renderer"
                : "Artifact renderer"}
            </small>
          </button>
        </div>
      ) : null}

      <div className="spot-chat" ref={chatAreaRef}>
        {!hasContent &&
          (isStudioVariant ? (
            <StudioConversationWelcome
              onSuggestionClick={(text) => setIntent(text)}
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
            icons={icons}
            onDownloadContext={handleDownloadContext}
            onOpenArtifactHub={openArtifactHub}
            onOpenSourceSummary={openSourceSummaryPanel}
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

        {studioStatusCard}
      </div>

      <ScrollToBottom visible={showScrollButton} onClick={scrollToBottom} />

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

      <SpotlightInputSection
        inputRef={inputRef}
        inputFocused={inputFocused}
        setInputFocused={setInputFocused}
        isDraggingFile={isDraggingFile}
        inputLockedByCredential={inputLockedByCredential}
        showPasswordPrompt={showPasswordPrompt}
        intent={intent}
        setIntent={setIntent}
        onInputChange={handleInputChange}
        onInputKeyDown={handleInputKeyDown}
        autoContext={autoContext}
        onToggleAutoContext={() => setAutoContext(!autoContext)}
        isRunning={isRunning}
        isGated={isGated}
        onStop={() => invoke("cancel_task").catch(console.error)}
        onSubmit={handleSubmit}
        workspaceOptions={workspaceOptions}
        workspaceMode={workspaceMode}
        onSelectWorkspaceMode={setWorkspaceMode}
        modelOptions={modelOptions}
        selectedModel={selectedModel}
        onSelectModel={setSelectedModel}
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
        <div className="spot-content">
          {layout.sidebarVisible && (
            <HistorySidebar
              sessions={sessions}
              onSelectSession={handleLoadSession}
              onNewChat={handleNewChat}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              onToggleSidebar={() => toggleSidebar(false)}
              activeSessionId={task?.session_id || task?.id || null}
              title={isStudioVariant ? "Studio threads" : "Chats"}
              newLabel={isStudioVariant ? "New artifact" : "New"}
              emptyLabel={
                isStudioVariant ? "No Studio threads yet" : "No chats yet"
              }
            />
          )}

          <div
            className={`spot-main ${isStudioVariant ? "spot-main--studio" : ""}`}
          >
            {isStudioVariant ? (
              <div
                className={`spot-studio-shell ${
                  studioArtifactVisible
                    ? "is-artifact-open"
                    : "is-artifact-collapsed"
                }`}
              >
                {conversationSurface}
                {studioArtifactAvailable ? (
                  <div
                    className={`spot-studio-artifact-drawer ${
                      studioArtifactVisible ? "is-open" : ""
                    }`}
                    aria-hidden={!studioArtifactVisible}
                  >
                    <StudioArtifactSurface
                      task={task}
                      onCollapse={() => setStudioArtifactVisible(false)}
                      onSeedIntent={(nextIntent) => {
                        setIntent(nextIntent);
                        window.setTimeout(() => {
                          inputRef.current?.focus();
                        }, 0);
                      }}
                    />
                  </div>
                ) : null}
              </div>
            ) : (
              conversationSurface
            )}
          </div>

          <SpotlightArtifactPanel
            visible={layout.artifactPanelVisible}
            artifactHubView={artifactHubView}
            artifactHubTurnId={artifactHubTurnId}
            events={activeEvents}
            artifacts={activeArtifacts}
            selectedArtifact={selectedArtifact}
            sourceSummary={runPresentation.sourceSummary}
            thoughtSummary={runPresentation.thoughtSummary}
            onOpenArtifact={openArtifactById}
            onClose={closeRightPanel}
          />
        </div>
      </div>
    </div>
  );
}
