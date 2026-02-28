// apps/autopilot/src/windows/SpotlightWindow/index.tsx

import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAgentStore } from "../../store/agentStore";
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
import { MarkdownMessage } from "./components/MarkdownMessage";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { HistorySidebar } from "./components/HistorySidebar";
import { ThoughtChain } from "./components/ThoughtChain";
import { AnswerCard } from "./components/AnswerCard";
import { SpotlightArtifactPanel } from "./components/SpotlightArtifactPanel";
import { VisualEvidenceCard } from "./components/VisualEvidenceCard";
import { SpotlightInputSection } from "./components/SpotlightInputSection";
import { SpotlightGateDock } from "./components/SpotlightGateDock";
import { buildRunPresentation } from "./viewmodels/contentPipeline";
import { exportThreadContextBundle } from "./utils/exportContext";
import { normalizeVisualHash } from "./utils/visualHash";
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

type SpotlightWindowProps = {
  variant?: "overlay" | "studio";
};

// ============================================
// MAIN COMPONENT
// ============================================

export function SpotlightWindow({ variant = "overlay" }: SpotlightWindowProps) {
  const isStudioVariant = variant === "studio";

  // Layout management (synced with Tauri backend)
  const { layout, toggleSidebar, toggleArtifactPanel } = useSpotlightLayout();

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const isUserAtBottomRef = useRef(true);

  const {
    task,
    events,
    artifacts,
    selectedArtifactId,
    startTask,
    continueTask,
    resetSession,
    setSelectedArtifactId,
    loadThreadEvents,
    loadThreadArtifacts,
  } = useAgentStore();

  const {
    intent,
    setIntent,
    localHistory,
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

  const activeHistory: ChatMessage[] = task?.history || localHistory;
  const activeEvents: AgentEvent[] = task?.events?.length ? task.events : events;
  const activeArtifacts: Artifact[] = task?.artifacts?.length ? task.artifacts : artifacts;
  const selectedArtifact =
    activeArtifacts.find((artifact) => artifact.artifact_id === selectedArtifactId) || null;

  const isRunning = task?.phase === "Running";
  const hasContent =
    !!task || localHistory.length > 0 || chatEvents.length > 0 || activeEvents.length > 0;

  const panelWidth =
    BASE_PANEL_WIDTH +
    (layout.sidebarVisible ? SIDEBAR_PANEL_WIDTH : 0) +
    (layout.artifactPanelVisible ? ARTIFACT_PANEL_WIDTH : 0);
  const containerStyle = isStudioVariant ? undefined : { width: `${panelWidth}px` };

  const runPresentation: RunPresentation = useMemo(
    () => buildRunPresentation(activeHistory, activeEvents, activeArtifacts),
    [activeArtifacts, activeEvents, activeHistory],
  );

  const { conversationTurns, latestAnsweredTurnIndex, turnContexts } = useTurnContexts({
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
    [setArtifactHubTurnId, setArtifactHubView, setSelectedArtifactId, toggleArtifactPanel],
  );

  const openArtifactHub = useCallback(
    (preferredView: ArtifactHubViewKey = "kernel_logs", preferredTurnId?: string | null) => {
      setArtifactHubView(preferredView);
      setArtifactHubTurnId(preferredTurnId || null);
      setSelectedArtifactId(null);
      void toggleArtifactPanel(true);
    },
    [setArtifactHubTurnId, setArtifactHubView, setSelectedArtifactId, toggleArtifactPanel],
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
    chatEvents: chatEvents as any,
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

  // ============================================
  // RENDER
  // ============================================

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
            />
          )}

          <div className="spot-main">
            {!layout.sidebarVisible && (
              <button
                className="spot-sidebar-toggle"
                onClick={() => toggleSidebar(true)}
                title="Show Sidebar (⌘K)"
              >
                {icons.sidebar}
              </button>
            )}

            <div className="spot-chat" ref={chatAreaRef}>
              {!hasContent && <IOIWatermark onSuggestionClick={(text) => setIntent(text)} />}

              {CONTENT_PIPELINE_V2_ENABLED ? (
                <>
                  {conversationTurns.map((turn, index) => {
                    const isLatestTurn = index === conversationTurns.length - 1;
                    const isLatestAnsweredTurn = index === latestAnsweredTurnIndex;
                    const turnContext = turnContexts[index] || null;
                    const latestAnswerMatches =
                      isLatestAnsweredTurn &&
                      !!turn.answer &&
                      !!runPresentation.finalAnswer;
                    const hasThoughtSummary = !!runPresentation.thoughtSummary;
                    const showLiveThinking = isLatestTurn && !!turn.prompt && !turn.answer && isRunning;
                    const showThoughtTrigger = !!turn.prompt && (showLiveThinking || !!turn.answer);
                    const thoughtCount = turnContext?.thoughtCount || 0;
                    const visualReceiptCount = turnContext?.visualReceiptCount || 0;
                    const liveVisualHash =
                      isLatestTurn && showLiveThinking
                        ? normalizeVisualHash(task?.visual_hash ?? "") || null
                        : null;
                    const inlineVisualHash = liveVisualHash || turnContext?.latestVisualHash || null;
                    const showInlineVisualReceipt =
                      !!inlineVisualHash || (!!turnContext && turnContext.visualReceiptCount > 0);
                    const hasTurnTrace =
                      (turnContext?.kernelEventCount || 0) > 0 ||
                      thoughtCount > 0 ||
                      visualReceiptCount > 0;

                    return (
                      <React.Fragment key={turn.key}>
                        {turn.prompt && (
                          <div className="spot-message user spot-message--prompt">
                            <div className="message-content-text">{turn.prompt.text}</div>
                          </div>
                        )}

                        {showThoughtTrigger && (
                          <button
                            className={`spot-thinking-pill ${
                              showLiveThinking ? "spot-thinking-pill--active" : ""
                            }`}
                            type="button"
                            onClick={() =>
                              openArtifactHub(
                                turnContext?.defaultView ||
                                  (hasThoughtSummary ? "thoughts" : "kernel_logs"),
                                turnContext?.turnId || null,
                              )
                            }
                            title="Open thinking artifacts"
                          >
                            <span className="spot-thinking-pill-icon">{icons.sparkles}</span>
                            <span className="spot-thinking-pill-text">Thinking...</span>
                            <span className="spot-thinking-pill-detail">
                              {showLiveThinking
                                ? task?.current_step || "Reasoning across tools"
                                : !hasTurnTrace
                                  ? "No trace captured"
                                  : thoughtCount > 0
                                    ? `${thoughtCount} ${thoughtCount === 1 ? "step" : "steps"} captured`
                                    : visualReceiptCount > 0
                                      ? `${visualReceiptCount} visual ${
                                          visualReceiptCount === 1 ? "receipt" : "receipts"
                                        } captured`
                                      : `${turnContext?.kernelEventCount || 0} events captured`}
                            </span>
                          </button>
                        )}

                        {showInlineVisualReceipt && (
                          <VisualEvidenceCard
                            hash={inlineVisualHash || ""}
                            timestamp={turnContext?.latestVisualTimestamp || null}
                            stepIndex={turnContext?.latestVisualStepIndex || null}
                            title={
                              showLiveThinking
                                ? "Live visual context"
                                : turnContext?.latestVisualHasBlob
                                  ? "Captured visual context"
                                  : "Captured screenshot receipt (metadata-only)"
                            }
                            compact={true}
                            className="spot-inline-visual-evidence"
                          />
                        )}
                        {showInlineVisualReceipt &&
                          !inlineVisualHash &&
                          !!turnContext?.latestVisualSummary && (
                            <p className="spot-inline-visual-summary">
                              {turnContext.latestVisualSummary}
                            </p>
                          )}

                        {turn.answer &&
                          (latestAnswerMatches && runPresentation.finalAnswer ? (
                            <AnswerCard
                              answer={runPresentation.finalAnswer}
                              sourceSummary={runPresentation.sourceSummary}
                              sourceDurationLabel={task?.receipt?.duration}
                              onDownloadContext={handleDownloadContext}
                              onOpenArtifacts={() =>
                                openArtifactHub(
                                  turnContext?.defaultView ||
                                    (runPresentation.thoughtSummary
                                      ? "thoughts"
                                      : runPresentation.sourceSummary
                                        ? "sources"
                                        : "kernel_logs"),
                                  turnContext?.turnId || null,
                                )
                              }
                              onOpenSources={openSourceSummaryPanel}
                            />
                          ) : (
                            <div className="spot-message agent">
                              <MarkdownMessage text={turn.answer.text} />
                            </div>
                          ))}
                      </React.Fragment>
                    );
                  })}

                  {conversationTurns.length === 0 && runPresentation.finalAnswer && (
                    <AnswerCard
                      answer={runPresentation.finalAnswer}
                      sourceSummary={runPresentation.sourceSummary}
                      sourceDurationLabel={task?.receipt?.duration}
                      onDownloadContext={handleDownloadContext}
                      onOpenArtifacts={() =>
                        openArtifactHub(
                          runPresentation.thoughtSummary
                            ? "thoughts"
                            : runPresentation.sourceSummary
                              ? "sources"
                              : "kernel_logs",
                        )
                      }
                      onOpenSources={openSourceSummaryPanel}
                    />
                  )}
                </>
              ) : (
                <>{legacyChatElements}</>
              )}

              {showInitialLoader &&
                (CONTENT_PIPELINE_V2_ENABLED ? (
                  <button
                    className="spot-thinking-pill spot-thinking-pill--active"
                    type="button"
                    onClick={() =>
                      openArtifactHub(runPresentation.thoughtSummary ? "thoughts" : "kernel_logs")
                    }
                    title="Open thinking artifacts"
                  >
                    <span className="spot-thinking-pill-icon">{icons.sparkles}</span>
                    <span className="spot-thinking-pill-text">Thinking...</span>
                    <span className="spot-thinking-pill-detail">
                      {task?.current_step || "Initializing..."}
                    </span>
                  </button>
                ) : (
                  <ThoughtChain
                    messages={[]}
                    activeStep={task?.current_step || "Initializing..."}
                    agentName={task?.agent || "Autopilot"}
                    generation={task?.generation || 0}
                    progress={0}
                    totalSteps={task?.total_steps || 10}
                  />
                ))}
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
            />
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
