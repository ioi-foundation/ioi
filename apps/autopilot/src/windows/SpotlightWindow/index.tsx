// apps/autopilot/src/windows/SpotlightWindow/index.tsx

import React, {
  useState,
  useEffect,
  useRef,
  useMemo,
  useCallback,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../../store/agentStore";
import {
  AgentEvent,
  AgentTask,
  Artifact,
  ChatMessage,
  SessionSummary,
} from "../../types";
import { useSpotlightLayout } from "./hooks/useSpotlightLayout";

// Sub-components
import { icons } from "./components/Icons";
import { IOIWatermark } from "./components/IOIWatermark";
import { MessageActions } from "./components/MessageActions";
import { MarkdownMessage } from "./components/MarkdownMessage";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { HistorySidebar } from "./components/HistorySidebar";
import { SpotlightApprovalCard } from "./components/SpotlightApprovalCard";
import { ThoughtChain } from "./components/ThoughtChain";
import { Dropdown, DropdownOption } from "./components/SpotlightDropdown";
import { ArtifactSidebar } from "./components/ArtifactSidebar";

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

type ChatEvent = ChatMessage & {
  isGate?: boolean;
  gateData?: any;
};

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

  // Core state
  const [intent, setIntent] = useState("");
  const [localHistory, setLocalHistory] = useState<ChatMessage[]>([]);
  const [autoContext, setAutoContext] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [workspaceMode, setWorkspaceMode] = useState("local");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [chatEvents, setChatEvents] = useState<ChatEvent[]>([]);

  // UI state
  const [inputFocused, setInputFocused] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [isDraggingFile] = useState(false);

  // Refs
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  // [FIX] Track user scroll intention explicitly
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
    initEventListeners();
    window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
  }, []);

  // Load session history
  useEffect(() => {
    const loadHistory = async () => {
      try {
        const history = await invoke<SessionSummary[]>("get_session_history");
        setSessions(history);
      } catch (e) {
        console.error("Failed to load history:", e);
      }
    };

    loadHistory();
    const interval = setInterval(loadHistory, 5000);
    return () => clearInterval(interval);
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
      const isNearBottom = distFromBottom < 100; // Threshold

      // [FIX] Update ref immediately on scroll to track intent
      isUserAtBottomRef.current = isNearBottom;
      setShowScrollButton(!isNearBottom);
    };

    chatArea.addEventListener("scroll", handleScroll);
    return () => chatArea.removeEventListener("scroll", handleScroll);
  }, []);

  // Auto-scroll on new messages
  const activeHistory: ChatMessage[] =
    (task as AgentTask | null)?.history || localHistory;

  useEffect(() => {
    // [FIX] Scroll only if user was already at bottom (stick-to-bottom behavior)
    // or if this is likely the first load (e.g. no scroll happened yet)
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
      // Force state update
      isUserAtBottomRef.current = true;
      setShowScrollButton(false);
    }
  }, []);

  // ============================================
  // ARTIFACT/GATE EVENTS
  // ============================================

  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
      const last = chatEvents[chatEvents.length - 1];
      if (!last || !last.isGate) {
        setChatEvents((prev) => [
          ...prev,
          {
            role: "system",
            text: "",
            timestamp: Date.now(),
            isGate: true,
            gateData: task.gate_info,
          },
        ]);
      }
    }
  }, [task?.phase, task?.gate_info, chatEvents]);

  useEffect(() => {
    const threadId = task?.session_id || task?.id;
    if (!threadId) return;
    void loadThreadEvents(threadId).catch(console.error);
    void loadThreadArtifacts(threadId).catch(console.error);
  }, [task?.session_id, task?.id, loadThreadEvents, loadThreadArtifacts]);

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

      // Never run global shortcuts while typing in editable fields.
      if (editableTarget) {
        return;
      }

      // Escape to close/dismiss
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

      // Cmd/Ctrl + K to toggle sidebar
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        toggleSidebar();
        return;
      }

      // Cmd/Ctrl + N for new chat
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
    isStudioVariant,
    layout.artifactPanelVisible,
    toggleSidebar,
    toggleArtifactPanel,
  ]);

  // ============================================
  // HANDLERS
  // ============================================

  const openStudio = useCallback(
    async (targetView: string = "compose") => {
      // "settings" is not a first-class Studio tab yet; route to an existing view.
      const resolvedView = targetView === "settings" ? "marketplace" : targetView;
      await emit("request-studio-view", resolvedView);
      if (isStudioVariant) {
        return;
      }
      await invoke("hide_spotlight");
      await invoke("show_studio");
    },
    [isStudioVariant],
  );

  const handleLoadSession = useCallback(async (id: string) => {
    try {
      await invoke("load_session", { sessionId: id });
    } catch (e) {
      console.error("Failed to load session:", e);
    }
  }, []);

  const handleSubmit = useCallback(async () => {
    const text = intent.trim();
    if (!text) return;
    if (task?.phase === "Gate" || task?.pending_request_hash) return;

    setIntent("");

    // Reset textarea height
    if (inputRef.current) {
      inputRef.current.style.height = "auto";
    }

    if (task && task.phase === "Running") return;

    try {
      if (task && task.id && task.phase !== "Failed") {
        await continueTask(task.id, text);
      } else {
        if (
          !isStudioVariant &&
          (text.toLowerCase().includes("swarm") ||
            text.toLowerCase().includes("team"))
        ) {
          await openStudio("autopilot");
        }
        await startTask(text);
      }
    } catch (e) {
      console.error(e);
    }
  }, [intent, isStudioVariant, task, continueTask, startTask, openStudio]);

  const handleApprove = useCallback(async () => {
    await invoke("gate_respond", { approved: true });
    setChatEvents((prev) =>
      prev.map((m) =>
        m.isGate ? { ...m, isGate: false, text: "✓ Authorized" } : m,
      ),
    );
  }, []);

  const handleDeny = useCallback(async () => {
    await invoke("gate_respond", { approved: false });
    setChatEvents((prev) =>
      prev.map((m) =>
        m.isGate ? { ...m, isGate: false, text: "✗ Denied" } : m,
      ),
    );
  }, []);

  const handleNewChat = useCallback(() => {
    resetSession();
    setLocalHistory([]);
    setChatEvents([]);
    setSelectedArtifactId(null);
    toggleArtifactPanel(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [resetSession, setSelectedArtifactId, toggleArtifactPanel]);

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown]);

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      setIntent(e.target.value);
      // Auto-resize textarea
      e.target.style.height = "auto";
      e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
    },
    [],
  );

  const handleInputKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Escape") {
        if (!isStudioVariant) {
          e.preventDefault();
          invoke("hide_spotlight").catch(console.error);
        }
        return;
      }

      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSubmit();
      }
    },
    [handleSubmit, isStudioVariant],
  );

  // ============================================
  // COMPUTED VALUES
  // ============================================

  const activeEvents: AgentEvent[] = task?.events?.length
    ? task.events
    : events;
  const activeArtifacts: Artifact[] = task?.artifacts?.length
    ? task.artifacts
    : artifacts;
  const selectedArtifact =
    activeArtifacts.find((a) => a.artifact_id === selectedArtifactId) || null;

  const isRunning = task?.phase === "Running";
  const hasPendingApproval = !!task?.pending_request_hash;
  const gateInfo = task?.gate_info
    ? task.gate_info
    : hasPendingApproval
      ? {
          title: "Approval Required",
          description: task?.pending_request_hash
            ? `Authorization required for request ${task.pending_request_hash}.`
            : "Authorization required before execution can continue.",
          risk: "high" as const,
        }
      : undefined;
  const isGated = (task?.phase === "Gate" || hasPendingApproval) && !!gateInfo;
  const hasContent =
    !!task ||
    localHistory.length > 0 ||
    chatEvents.length > 0 ||
    activeEvents.length > 0;
  const panelWidth =
    BASE_PANEL_WIDTH +
    (layout.sidebarVisible ? SIDEBAR_PANEL_WIDTH : 0) +
    (layout.artifactPanelVisible ? ARTIFACT_PANEL_WIDTH : 0);
  const containerStyle = isStudioVariant ? undefined : { width: `${panelWidth}px` };

  const openArtifactById = useCallback(
    (artifactId: string) => {
      setSelectedArtifactId(artifactId);
      toggleArtifactPanel(true);
    },
    [setSelectedArtifactId, toggleArtifactPanel],
  );

  // ============================================
  // RENDER CHAT STREAM
  // ============================================

  const { chatElements, hasChainContent } = useMemo(() => {
    if (activeEvents.length > 0) {
      const byStep = new Map<number, AgentEvent[]>();
      for (const event of activeEvents) {
        const list = byStep.get(event.step_index) || [];
        list.push(event);
        byStep.set(event.step_index, list);
      }
      const orderedSteps = Array.from(byStep.keys()).sort((a, b) => a - b);
      const latestStep = orderedSteps[orderedSteps.length - 1];
      const elements: React.ReactNode[] = orderedSteps.map((stepIndex) => (
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
        />
      ));

      return {
        chatElements: elements,
        hasChainContent: true,
      };
    }

    const combined: ChatEvent[] = [
      ...activeHistory.map((m) => ({ ...m, isGate: false, gateData: null })),
      ...chatEvents,
    ];

    const groups: Array<{
      type: "message" | "chain" | "gate";
      content: any;
    }> = [];

    let currentChain: ChatMessage[] = [];
    let foundChain = false;

    combined.forEach((msg) => {
      if (msg.role === "tool" || (msg.role === "system" && !msg.isGate)) {
        currentChain.push(msg);
      } else if (msg.isGate) {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "gate", content: msg.gateData });
      } else {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "message", content: msg });
      }
    });

    if (currentChain.length > 0) {
      groups.push({ type: "chain", content: currentChain });
      foundChain = true;
    }

    const elements = groups.map((g, i) => (
      <React.Fragment key={i}>
        {g.type === "message" && (
          <div
            className={`spot-message ${g.content.role === "user" ? "user" : "agent"}`}
          >
            {g.content.role === "agent" ? (
              <MarkdownMessage text={g.content.text} />
            ) : (
              <div className="message-content-text">{g.content.text}</div>
            )}
            {g.content.role !== "user" && (
              <MessageActions
                text={g.content.text}
                showRetry={true}
                onRetry={() => {}}
              />
            )}
          </div>
        )}

        {g.type === "chain" && (
          <ThoughtChain
            messages={g.content}
            activeStep={
              isRunning && i === groups.length - 1 ? task?.current_step : null
            }
            agentName={task?.agent}
            generation={task?.generation}
            progress={task?.progress}
            totalSteps={task?.total_steps}
          />
        )}

        {g.type === "gate" && null}
      </React.Fragment>
    ));

    return { chatElements: elements, hasChainContent: foundChain };
  }, [
    activeEvents,
    activeHistory,
    chatEvents,
    handleApprove,
    handleDeny,
    isRunning,
    openArtifactById,
    task,
  ]);

  // Only show initial loader if running AND no chain content exists yet
  const showInitialLoader = isRunning && !hasChainContent;

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
        {/* ============================================
            CONTENT AREA
            ============================================ */}
        <div className="spot-content">
          {/* Left Sidebar */}
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

          {/* Main Panel */}
          <div className="spot-main">
            {/* Sidebar toggle - shown when sidebar is hidden */}
            {!layout.sidebarVisible && (
              <button
                className="spot-sidebar-toggle"
                onClick={() => toggleSidebar(true)}
                title="Show Sidebar (⌘K)"
              >
                {icons.sidebar}
              </button>
            )}

            {/* Chat Area */}
            <div className="spot-chat" ref={chatAreaRef}>
              {!hasContent && (
                <IOIWatermark onSuggestionClick={(text) => setIntent(text)} />
              )}

              {chatElements}

              {showInitialLoader && (
                <ThoughtChain
                  messages={[]}
                  activeStep={task?.current_step || "Initializing..."}
                  agentName={task?.agent || "Autopilot"}
                  generation={task?.generation || 0}
                  progress={0}
                  totalSteps={task?.total_steps || 10}
                />
              )}
            </div>

            {/* [FIX] Moved ScrollToBottom outside spot-chat to float over it correctly */}
            <ScrollToBottom
              visible={showScrollButton}
              onClick={scrollToBottom}
            />

            {isGated && gateInfo && (
              <div className="spot-gate-dock">
                <SpotlightApprovalCard
                  title={gateInfo.title}
                  description={gateInfo.description}
                  risk={gateInfo.risk}
                  onApprove={handleApprove}
                  onDeny={handleDeny}
                />
              </div>
            )}

            {/* Input Section */}
            <div
              className={`spot-input-section ${inputFocused ? "focused" : ""} ${isDraggingFile ? "drag-active" : ""}`}
            >
              <div className="spot-input-wrapper">
                <textarea
                  ref={inputRef}
                  className="spot-input"
                  placeholder="How can I help you today?"
                  value={intent}
                  onChange={handleInputChange}
                  onKeyDown={handleInputKeyDown}
                  onFocus={() => setInputFocused(true)}
                  onBlur={() => setInputFocused(false)}
                  rows={1}
                />

                <div className="spot-controls">
                  <div className="spot-controls-left">
                    <button
                      className="spot-action-btn"
                      title="Attach file (⌘U)"
                    >
                      {icons.paperclip}
                    </button>
                    <button className="spot-action-btn" title="Commands (/)">
                      {icons.slash}
                    </button>
                    <button
                      className={`spot-context-btn ${autoContext ? "active" : ""}`}
                      onClick={() => setAutoContext(!autoContext)}
                      title="Auto context (⌘.)"
                    >
                      {icons.sparkles}
                      <span>Context</span>
                    </button>
                  </div>

                  {isRunning ? (
                    <button
                      className="spot-stop-btn"
                      onClick={() => invoke("cancel_task").catch(console.error)}
                      title="Stop (Esc)"
                    >
                      {icons.stop}
                      <span>Stop</span>
                    </button>
                  ) : (
                    <button
                      className="spot-send-btn"
                      onClick={handleSubmit}
                      disabled={!intent.trim() || isGated}
                      title="Send (⏎)"
                    >
                      {icons.send}
                    </button>
                  )}
                </div>
              </div>

              <div className="spot-toggles">
                <Dropdown
                  icon={icons.laptop}
                  options={workspaceOptions}
                  selected={workspaceMode}
                  onSelect={setWorkspaceMode}
                  isOpen={activeDropdown === "workspace"}
                  onToggle={() =>
                    setActiveDropdown(
                      activeDropdown === "workspace" ? null : "workspace",
                    )
                  }
                  footer={{
                    label: "Manage Workspaces...",
                    onClick: () => openStudio("settings"),
                  }}
                />
                <Dropdown
                  icon={icons.cube}
                  options={modelOptions}
                  selected={selectedModel}
                  onSelect={setSelectedModel}
                  isOpen={activeDropdown === "model"}
                  onToggle={() =>
                    setActiveDropdown(
                      activeDropdown === "model" ? null : "model",
                    )
                  }
                  footer={{
                    label: "Manage Models...",
                    onClick: () => openStudio("settings"),
                  }}
                />
              </div>
            </div>
          </div>

          {/* Artifact Panel */}
          {layout.artifactPanelVisible && selectedArtifact && (
            <ArtifactSidebar
              artifact={selectedArtifact}
              onClose={() => toggleArtifactPanel(false)}
            />
          )}
        </div>
      </div>
    </div>
  );
}
