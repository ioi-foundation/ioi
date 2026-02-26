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

// Sub-components
import { icons } from "./components/Icons";
import { IOIWatermark } from "./components/IOIWatermark";
import { MessageActions } from "./components/MessageActions";
import { MarkdownMessage } from "./components/MarkdownMessage";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { HistorySidebar } from "./components/HistorySidebar";
import { ThoughtChain } from "./components/ThoughtChain";
import { AnswerCard } from "./components/AnswerCard";
import { DropdownOption } from "./components/SpotlightDropdown";
import { ArtifactSidebar } from "./components/ArtifactSidebar";
import { ArtifactHubSidebar } from "./components/ArtifactHubSidebar";
import { VisualEvidenceCard } from "./components/VisualEvidenceCard";
import { SpotlightInputSection } from "./components/SpotlightInputSection";
import { SpotlightGateDock } from "./components/SpotlightGateDock";
import { buildRunPresentation } from "./viewmodels/contentPipeline";
import { exportThreadContextBundle } from "./utils/exportContext";
import { normalizeVisualHash } from "./utils/visualHash";

// Styles
import "./styles/Layout.css";
import "./styles/Chat.css";
import "./styles/Sidebar.css";
import "./styles/Components.css";
import "./styles/Visuals.css";
import "./styles/ArtifactPanel.css";
import "./styles/Overrides.css";
import "./styles/MicroEventCard.css";

// ============================================
// CONSTANTS
// ============================================

const workspaceOptions: DropdownOption[] = [
  { value: "local", label: "Local", desc: "On-device", icon: icons.laptop },
  { value: "cloud", label: "Cloud", desc: "Remote", icon: icons.cloud },
];

const modelOptions: DropdownOption[] = [
  { value: "GPT-4o", label: "GPT-4o", desc: "OpenAI" },
  { value: "Claude 3.5", label: "Claude 3.5", desc: "Anthropic" },
  { value: "Llama 3", label: "Llama 3", desc: "Meta" },
];

const BASE_PANEL_WIDTH = 450;
const SIDEBAR_PANEL_WIDTH = 260;
const ARTIFACT_PANEL_WIDTH = 400;
const CONTENT_PIPELINE_V2_FLAG = "AUTOPILOT_CONTENT_PIPELINE_V2";
const CONTENT_PIPELINE_V2_ENABLED =
  String((import.meta as any).env?.[CONTENT_PIPELINE_V2_FLAG] ?? "true").toLowerCase() !==
  "false";

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

  const { legacyChatElements, hasLegacyChainContent } = useMemo(() => {
    const combined = [
      ...activeHistory.map((message) => ({ ...message, isGate: false, gateData: null })),
      ...chatEvents,
    ];

    const groups: Array<{
      type: "message" | "chain" | "gate";
      content: any;
    }> = [];

    let currentChain: ChatMessage[] = [];
    let foundChain = false;

    combined.forEach((message) => {
      if (message.role === "tool" || (message.role === "system" && !message.isGate)) {
        currentChain.push(message);
      } else if (message.isGate) {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "gate", content: message.gateData });
      } else {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "message", content: message });
      }
    });

    if (currentChain.length > 0) {
      groups.push({ type: "chain", content: currentChain });
      foundChain = true;
    }

    const historyElements = groups.map((group, index) => (
      <React.Fragment key={index}>
        {group.type === "message" && (
          <div className={`spot-message ${group.content.role === "user" ? "user" : "agent"}`}>
            {group.content.role === "agent" ? (
              <MarkdownMessage text={group.content.text} />
            ) : (
              <div className="message-content-text">{group.content.text}</div>
            )}
            {group.content.role !== "user" && (
              <MessageActions text={group.content.text} showRetry={true} onRetry={() => {}} />
            )}
          </div>
        )}

        {group.type === "chain" && (
          <ThoughtChain
            messages={group.content}
            activeStep={isRunning && index === groups.length - 1 ? task?.current_step : null}
            agentName={task?.agent}
            generation={task?.generation}
            progress={task?.progress}
            totalSteps={task?.total_steps}
            onOpenArtifact={openArtifactById}
          />
        )}

        {group.type === "gate" && null}
      </React.Fragment>
    ));

    const timelineElements: React.ReactNode[] = [];
    if (activeEvents.length > 0) {
      const byStep = new Map<number, AgentEvent[]>();
      for (const event of activeEvents) {
        const list = byStep.get(event.step_index) || [];
        list.push(event);
        byStep.set(event.step_index, list);
      }
      const orderedSteps = Array.from(byStep.keys()).sort((a, b) => a - b);
      const latestStep = orderedSteps[orderedSteps.length - 1];
      for (const stepIndex of orderedSteps) {
        timelineElements.push(
          <ThoughtChain
            key={`thinking-${stepIndex}`}
            messages={[]}
            events={byStep.get(stepIndex) || []}
            onOpenArtifact={openArtifactById}
            activeStep={isRunning && stepIndex === latestStep ? task?.current_step : null}
            agentName={task?.agent}
            generation={task?.generation}
            progress={task?.progress}
            totalSteps={task?.total_steps}
          />,
        );
      }
    }

    return {
      legacyChatElements: [...historyElements, ...timelineElements],
      hasLegacyChainContent: foundChain || timelineElements.length > 0,
    };
  }, [activeEvents, activeHistory, chatEvents, isRunning, openArtifactById, task]);

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
                      !!runPresentation.finalAnswer &&
                      runPresentation.finalAnswer.message.text.trim() === turn.answer.text.trim();
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
                              planSummary={runPresentation.planSummary}
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
                      planSummary={runPresentation.planSummary}
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

          {layout.artifactPanelVisible && artifactHubView && (
            <ArtifactHubSidebar
              initialView={artifactHubView}
              initialTurnId={artifactHubTurnId}
              events={activeEvents}
              artifacts={activeArtifacts}
              sourceSummary={runPresentation.sourceSummary}
              thoughtSummary={runPresentation.thoughtSummary}
              onOpenArtifact={openArtifactById}
              onClose={closeRightPanel}
            />
          )}

          {layout.artifactPanelVisible && selectedArtifact && !artifactHubView && (
            <ArtifactSidebar artifact={selectedArtifact} onClose={closeRightPanel} />
          )}
        </div>
      </div>
    </div>
  );
}
