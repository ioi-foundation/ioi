import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../../store/agentStore";
import { AgentTask, ChatMessage, SessionSummary } from "../../types";
import { formatTimeAgo } from "./utils";

// Sub-components
import { icons } from "./components/Icons";
import { ThinkingOrb } from "./components/ThinkingOrb";
import { IOIWatermark } from "./components/IOIWatermark";
import { MessageActions } from "./components/MessageActions";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { VisualArtifact } from "./components/VisualArtifact";
import { ResizeHandle } from "./components/ResizeHandle";
import { HistorySidebar } from "./components/HistorySidebar";
import { SpotlightApprovalCard } from "./components/SpotlightApprovalCard";
import { ThoughtChain } from "./components/ThoughtChain";
import { Dropdown, DropdownOption } from "./components/SpotlightDropdown";

// Styles
import "./styles/Layout.css";
import "./styles/Chat.css";
import "./styles/Sidebar.css";
import "./styles/Components.css";
import "./styles/Visuals.css";

const workspaceOptions: DropdownOption[] = [
  { value: "local", label: "Local", desc: "On-device", icon: icons.laptop },
  { value: "cloud", label: "Cloud", desc: "Remote", icon: icons.cloud },
];

const modelOptions: DropdownOption[] = [
  { value: "GPT-4o", label: "GPT-4o", desc: "OpenAI" },
  { value: "Claude 3.5", label: "Claude 3.5", desc: "Anthropic" },
  { value: "Llama 3", label: "Llama 3", desc: "Meta" },
];

type ChatEvent = ChatMessage & { isGate?: boolean; gateData?: any; isArtifact?: boolean; artifactData?: any; };
const LAYOUT_WIDE_THRESHOLD = 600;

export function SpotlightWindow() {
  const [intent, setIntent] = useState("");
  const [localHistory, setLocalHistory] = useState<ChatMessage[]>([]);
  const [autoContext, setAutoContext] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [workspaceMode, setWorkspaceMode] = useState("local");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [chatEvents, setChatEvents] = useState<ChatEvent[]>([]);
  const [inputFocused, setInputFocused] = useState(false);
  const [containerWidth, setContainerWidth] = useState(400);
  const [searchQuery, setSearchQuery] = useState("");
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [isDraggingFile, setIsDraggingFile] = useState(false);

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const { task, startTask, continueTask, resetSession } = useAgentStore();

  // Track container width
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) setContainerWidth(entry.contentRect.width);
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Scroll detection
  useEffect(() => {
    const chatArea = chatAreaRef.current;
    if (!chatArea) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = chatArea;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      setShowScrollButton(!isNearBottom);
    };

    chatArea.addEventListener("scroll", handleScroll);
    return () => chatArea.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToBottom = useCallback(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTo({ top: chatAreaRef.current.scrollHeight, behavior: "smooth" });
    }
  }, []);

  const isWideMode = containerWidth >= LAYOUT_WIDE_THRESHOLD;

  useEffect(() => {
    initEventListeners();
    invoke("set_spotlight_mode", { mode: "sidebar" }).catch(console.error);
    setTimeout(() => inputRef.current?.focus(), 150);

    const loadHistory = async () => {
      try {
        const history = await invoke<SessionSummary[]>("get_session_history");
        setSessions(history);
      } catch (e) { console.error("Failed to load history:", e); }
    };
    loadHistory();
    const interval = setInterval(loadHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  // Listen for gate events and artifact events
  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
      const last = chatEvents[chatEvents.length - 1];
      if (!last || !last.isGate) {
        setChatEvents((prev) => [...prev, { role: "system", text: "", timestamp: Date.now(), isGate: true, gateData: task.gate_info }]);
      }
    }
    // Add artifact when browsing
    if (task && task.phase === "Running" && task.current_step?.toLowerCase().includes("brows")) {
      const hasArtifact = chatEvents.some(e => e.isArtifact);
      if (!hasArtifact) {
        setChatEvents((prev) => [...prev, { 
          role: "system", text: "", timestamp: Date.now(), 
          isArtifact: true, 
          artifactData: { url: "loading...", isActive: true } 
        }]);
      }
    }
  }, [task?.phase, task?.gate_info, task?.current_step]);

  // Update artifact when step changes
  useEffect(() => {
    if (task?.current_step) {
      setChatEvents((prev) => prev.map(e => 
        e.isArtifact ? { ...e, artifactData: { ...e.artifactData, url: task.current_step, title: task.current_step, isActive: task.phase === "Running" } } : e
      ));
    }
  }, [task?.current_step, task?.phase]);

  const activeHistory: ChatMessage[] = (task as AgentTask | null)?.history || localHistory;

  useEffect(() => {
    if (chatAreaRef.current) chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
  }, [activeHistory, chatEvents]);

  const handleResize = useCallback((delta: number) => {
    setContainerWidth((prev) => Math.max(320, Math.min(1200, prev + delta)));
    invoke("resize_spotlight", { width: containerWidth + delta }).catch(console.error);
  }, [containerWidth]);

  const openStudio = useCallback(async (targetView: string = "compose") => {
    await emit("request-studio-view", targetView);
    await invoke("hide_spotlight");
    await invoke("show_studio");
  }, []);

  const handleLoadSession = useCallback(async (id: string) => {
    try { await invoke("load_session", { sessionId: id }); } catch (e) { console.error("Failed to load session:", e); }
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!intent.trim()) return;
    const text = intent;
    setIntent("");
    if (task && task.phase === "Running") return;
    try {
      if (task && task.id && task.phase !== "Failed") {
        await continueTask(task.id, text);
      } else {
        if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) await openStudio("copilot");
        await startTask(text);
      }
    } catch (e) { console.error(e); }
  }, [intent, task, continueTask, startTask, openStudio]);

  const handleApprove = useCallback(async () => {
    await invoke("gate_respond", { approved: true });
    setChatEvents((prev) => prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✓ Authorized" } : m)));
  }, []);

  const handleDeny = useCallback(async () => {
    await invoke("gate_respond", { approved: false });
    setChatEvents((prev) => prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✗ Denied" } : m)));
  }, []);

  const handleNewChat = useCallback(() => {
    resetSession();
    setLocalHistory([]);
    setChatEvents([]);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [resetSession]);

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown]);

  // Render chat stream
  const renderChatStream = useMemo(() => {
    const combined: ChatEvent[] = [...activeHistory.map((m) => ({ ...m, isGate: false, gateData: null })), ...chatEvents];
    const groups: Array<{ type: "message" | "chain" | "gate" | "artifact"; content: any }> = [];
    let currentChain: ChatMessage[] = [];

    combined.forEach((msg) => {
      if (msg.isArtifact) {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "artifact", content: msg.artifactData });
      } else if (msg.role === "tool" || (msg.role === "system" && !msg.isGate)) {
        currentChain.push(msg);
      } else if (msg.isGate) {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "gate", content: msg.gateData });
      } else {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "message", content: msg });
      }
    });
    if (currentChain.length > 0) groups.push({ type: "chain", content: currentChain });

    return groups.map((g, i) => (
      <React.Fragment key={i}>
        {g.type === "message" && (
          <div className={`spot-message ${g.content.role === "user" ? "user" : "agent"}`}>
            <div className="message-content">{g.content.text}</div>
            {g.content.role !== "user" && (
              <MessageActions text={g.content.text} showRetry={true} onRetry={() => {}} />
            )}
          </div>
        )}
        {g.type === "chain" && <ThoughtChain messages={g.content} isThinking={false} />}
        {g.type === "gate" && <SpotlightApprovalCard title={g.content.title} description={g.content.description} risk={g.content.risk} onApprove={handleApprove} onDeny={handleDeny} />}
        {g.type === "artifact" && <VisualArtifact url={g.content.url} title={g.content.title} isActive={g.content.isActive} screenshot={g.content.screenshot} />}
      </React.Fragment>
    ));
  }, [activeHistory, chatEvents, handleApprove, handleDeny]);

  const isRunning = task?.phase === "Running";
  const isGated = task?.phase === "Gate";
  const hasContent = task || localHistory.length > 0 || chatEvents.length > 0;
  const progressPercent = task ? (task.progress / Math.max(task.total_steps, 1)) * 100 : 0;

  return (
    <div className="spot-window" onClick={handleGlobalClick} ref={containerRef}>
      <div className={`spot-container ${isWideMode ? "wide-mode" : ""}`}>
        
        {/* History Sidebar (wide mode only) */}
        {isWideMode && (
          <HistorySidebar
            sessions={sessions}
            onSelectSession={handleLoadSession}
            onNewChat={handleNewChat}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
          />
        )}

        {/* Resize Handle */}
        <ResizeHandle onResize={handleResize} />

        {/* Main Chat Panel */}
        <div className="spot-main">
          {/* Header Actions */}
          <div className="spot-header-actions">
            {!isWideMode && <button className="spot-icon-btn" onClick={handleNewChat} title="New Chat">{icons.plus}</button>}
            {!isWideMode && <div className="divider-vertical" />}
            <button className="spot-icon-btn" onClick={() => openStudio("history")} title="History">{icons.history}</button>
            <button className="spot-icon-btn" onClick={() => openStudio("settings")} title="Settings">{icons.settings}</button>
            <button className="spot-icon-btn" onClick={() => openStudio("copilot")} title="Expand">{icons.expand}</button>
            <button className="spot-icon-btn close" onClick={() => invoke("hide_spotlight")} title="Close">{icons.close}</button>
          </div>

          {/* Tasks Section (narrow mode only) */}
          {!isWideMode && (
            <div className="spot-tasks-section">
              <div className="spot-tasks-bar">
                <span className="spot-tasks-title">Recent</span>
                {sessions.length > 3 && <button className="spot-tasks-more" onClick={() => openStudio("history")}>View all</button>}
              </div>
              <div className="spot-tasks-list">
                {sessions.slice(0, 3).map((s) => (
                  <button key={s.session_id} className="spot-task-item" onClick={() => handleLoadSession(s.session_id)}>
                    <span className="spot-task-title">{s.title}</span>
                    <span className="spot-task-age">{formatTimeAgo(s.timestamp)}</span>
                  </button>
                ))}
                {sessions.length === 0 && <div className="spot-task-empty">No recent tasks</div>}
              </div>
            </div>
          )}

          {/* Status Header */}
          {task && task.phase !== "Idle" && (
            <div className={`spot-status-header ${task.phase.toLowerCase()}`}>
              <div className="status-progress-rail"><div className="status-progress-fill" style={{ width: `${progressPercent}%` }} /></div>
              <div className="status-content">
                <div className={`status-beacon ${isRunning ? "pulse" : ""} ${task.phase === "Failed" ? "error" : ""} ${task.phase === "Complete" ? "success" : ""}`} />
                <div className="status-info">
                  <span className="status-step">{task.current_step}</span>
                  <span className="status-meta">{task.agent} · Gen {task.generation} · {task.progress}/{task.total_steps}</span>
                </div>
              </div>
            </div>
          )}

          {/* Chat Area */}
          <div className="spot-chat" ref={chatAreaRef}>
            {!hasContent && <IOIWatermark onSuggestionClick={(text) => setIntent(text)} />}
            {renderChatStream}
            {isRunning && !chatEvents.some(e => e.isArtifact) && (
              <div className="spot-thinking-indicator"><ThinkingOrb isActive /><span className="thinking-label">Processing...</span></div>
            )}
            <ScrollToBottom visible={showScrollButton} onClick={scrollToBottom} />
          </div>

          {/* Input Section */}
          <div className={`spot-input-section ${inputFocused ? "focused" : ""} ${isDraggingFile ? "drag-active" : ""}`}>
            <div className="spot-input-wrapper">
              <textarea
                ref={inputRef}
                className="spot-input"
                placeholder="How can I help you today?"
                value={intent}
                onChange={(e) => {
                  setIntent(e.target.value);
                  // Auto-resize
                  e.target.style.height = 'auto';
                  e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                onFocus={() => setInputFocused(true)}
                onBlur={() => setInputFocused(false)}
                disabled={isGated}
                rows={1}
              />
            </div>
            <div className="spot-controls">
              <div className="spot-controls-left">
                <button className="spot-action-btn" title="Attach (⌘U)">{icons.paperclip}</button>
                <button className="spot-action-btn" title="Commands (/)">{icons.slash}</button>
                <button className={`spot-context-btn ${autoContext ? "active" : ""}`} onClick={() => setAutoContext(!autoContext)} title="Auto context (⌘.)">
                  {icons.sparkles}<span>Context</span>
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
                <button className="spot-send-btn" onClick={handleSubmit} disabled={!intent.trim()} title="Send (⏎)">
                  {icons.send}
                </button>
              )}
            </div>
            <div className="spot-toggles">
              <Dropdown 
                icon={icons.laptop} 
                options={workspaceOptions} 
                selected={workspaceMode} 
                onSelect={setWorkspaceMode} 
                isOpen={activeDropdown === "workspace"} 
                onToggle={() => setActiveDropdown(activeDropdown === "workspace" ? null : "workspace")} 
              />
              <Dropdown 
                icon={icons.cube} 
                options={modelOptions} 
                selected={selectedModel} 
                onSelect={setSelectedModel} 
                isOpen={activeDropdown === "model"} 
                onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")}
                footer={{
                    label: "Manage Models...",
                    onClick: () => openStudio("settings")
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}