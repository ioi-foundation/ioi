// apps/autopilot/src/windows/SpotlightWindow/index.tsx

import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../../store/agentStore";
import { AgentTask, ChatMessage, SessionSummary } from "../../types";
import { formatTimeAgo } from "./utils";
import { useSpotlightLayout } from "./hooks/useSpotlightLayout";

// Sub-components
import { icons } from "./components/Icons";
import { IOIWatermark } from "./components/IOIWatermark";
import { MessageActions } from "./components/MessageActions";
import { ScrollToBottom } from "./components/ScrollToBottom";
import { VisualArtifact } from "./components/VisualArtifact";
import { HistorySidebar } from "./components/HistorySidebar";
import { SpotlightApprovalCard } from "./components/SpotlightApprovalCard";
import { ThoughtChain } from "./components/ThoughtChain";
import { Dropdown, DropdownOption } from "./components/SpotlightDropdown";
import { ArtifactPanel } from "./components/ArtifactPanel";

// Styles
import "./styles/Layout.css";
import "./styles/Chat.css";
import "./styles/Sidebar.css";
import "./styles/Components.css";
import "./styles/Visuals.css";
import "./styles/ArtifactPanel.css";
import "./styles/Overrides.css";

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

type ChatEvent = ChatMessage & { 
  isGate?: boolean; 
  gateData?: any; 
  isArtifact?: boolean; 
  artifactData?: any; 
};

// ============================================
// MAIN COMPONENT
// ============================================

export function SpotlightWindow() {
  // Layout management (synced with Tauri backend)
  const { 
    layout, 
    toggleSidebar, 
    toggleArtifactPanel, 
    dockRight,
    setDockPosition 
  } = useSpotlightLayout();

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
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  
  // Artifact state
  const [currentArtifact, setCurrentArtifact] = useState<{name: string, content: string} | null>(null);

  // Refs
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const { task, startTask, continueTask, resetSession } = useAgentStore();

  // ============================================
  // INITIALIZATION
  // ============================================

  useEffect(() => {
    initEventListeners();
    
    // Set initial dock mode
    invoke("set_spotlight_mode", { mode: "right" }).catch(console.error);
    
    // Focus input after mount
    const timer = setTimeout(() => inputRef.current?.focus(), 150);
    return () => clearTimeout(timer);
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
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 80;
      setShowScrollButton(!isNearBottom);
    };

    chatArea.addEventListener("scroll", handleScroll);
    return () => chatArea.removeEventListener("scroll", handleScroll);
  }, []);

  // Auto-scroll on new messages
  const activeHistory: ChatMessage[] = (task as AgentTask | null)?.history || localHistory;
  
  useEffect(() => {
    if (chatAreaRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = chatAreaRef.current;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 150;
      
      if (isNearBottom) {
        chatAreaRef.current.scrollTo({ 
          top: chatAreaRef.current.scrollHeight, 
          behavior: "smooth" 
        });
      }
    }
  }, [activeHistory, chatEvents]);

  const scrollToBottom = useCallback(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTo({ 
        top: chatAreaRef.current.scrollHeight, 
        behavior: "smooth" 
      });
    }
  }, []);

  // ============================================
  // ARTIFACT/GATE EVENTS
  // ============================================

  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
      const last = chatEvents[chatEvents.length - 1];
      if (!last || !last.isGate) {
        setChatEvents((prev) => [...prev, { 
          role: "system", 
          text: "", 
          timestamp: Date.now(), 
          isGate: true, 
          gateData: task.gate_info 
        }]);
      }
    }
    
    // Handle code artifacts
    if (task && task.phase === "Running" && task.current_step?.toLowerCase().includes("code")) {
      if (!currentArtifact) {
        setCurrentArtifact({
          name: "generated_script.ts",
          content: `// Automatically generated by Autopilot
import { Tool } from "@ioi/sdk";

export const myTool = new Tool({
  name: "demo",
  handler: async () => {
    console.log("Hello World");
  }
});`
        });
        // Auto-show artifact panel
        toggleArtifactPanel(true);
      }
    }
    
    // Handle browsing artifacts
    if (task && task.phase === "Running" && task.current_step?.toLowerCase().includes("brows")) {
      const hasArtifact = chatEvents.some(e => e.isArtifact);
      if (!hasArtifact) {
        setChatEvents((prev) => [...prev, { 
          role: "system", 
          text: "", 
          timestamp: Date.now(), 
          isArtifact: true, 
          artifactData: { url: "loading...", isActive: true } 
        }]);
      }
    }
  }, [task?.phase, task?.gate_info, task?.current_step, toggleArtifactPanel]);

  // Update artifact URL when step changes
  useEffect(() => {
    if (task?.current_step) {
      setChatEvents((prev) => prev.map(e => 
        e.isArtifact 
          ? { 
              ...e, 
              artifactData: { 
                ...e.artifactData, 
                url: task.current_step, 
                title: task.current_step, 
                isActive: task.phase === "Running" 
              } 
            } 
          : e
      ));
    }
  }, [task?.current_step, task?.phase]);

  // ============================================
  // KEYBOARD SHORTCUTS
  // ============================================

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Escape to close/dismiss
      if (e.key === "Escape") {
        if (activeDropdown) {
          setActiveDropdown(null);
        } else if (layout.artifactPanelVisible) {
          toggleArtifactPanel(false);
        } else {
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

      // Cmd/Ctrl + D to re-dock
      if ((e.metaKey || e.ctrlKey) && e.key === "d") {
        e.preventDefault();
        dockRight();
        return;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [activeDropdown, layout.artifactPanelVisible, toggleSidebar, toggleArtifactPanel, dockRight]);

  // ============================================
  // HANDLERS
  // ============================================

  const openStudio = useCallback(async (targetView: string = "compose") => {
    await emit("request-studio-view", targetView);
    await invoke("hide_spotlight");
    await invoke("show_studio");
  }, []);

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
    
    setIntent("");
    
    // Reset textarea height
    if (inputRef.current) {
      inputRef.current.style.height = 'auto';
    }
    
    if (task && task.phase === "Running") return;
    
    try {
      if (task && task.id && task.phase !== "Failed") {
        await continueTask(task.id, text);
      } else {
        if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) {
          await openStudio("copilot");
        }
        await startTask(text);
      }
    } catch (e) { 
      console.error(e); 
    }
  }, [intent, task, continueTask, startTask, openStudio]);

  const handleApprove = useCallback(async () => {
    await invoke("gate_respond", { approved: true });
    setChatEvents((prev) => prev.map((m) => 
      m.isGate ? { ...m, isGate: false, text: "✓ Authorized" } : m
    ));
  }, []);

  const handleDeny = useCallback(async () => {
    await invoke("gate_respond", { approved: false });
    setChatEvents((prev) => prev.map((m) => 
      m.isGate ? { ...m, isGate: false, text: "✗ Denied" } : m
    ));
  }, []);

  const handleNewChat = useCallback(() => {
    resetSession();
    setLocalHistory([]);
    setChatEvents([]);
    setCurrentArtifact(null);
    toggleArtifactPanel(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [resetSession, toggleArtifactPanel]);

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown]);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setIntent(e.target.value);
    // Auto-resize textarea
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
  }, []);

  const handleInputKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }, [handleSubmit]);

  // ============================================
  // COMPUTED VALUES
  // ============================================

  const isRunning = task?.phase === "Running";
  const isGated = task?.phase === "Gate";
  const hasContent = task || localHistory.length > 0 || chatEvents.length > 0;
  const isFloating = layout.dockPosition === "float";

  // ============================================
  // RENDER CHAT STREAM
  // ============================================

  const { chatElements, hasChainContent } = useMemo(() => {
    const combined: ChatEvent[] = [
      ...activeHistory.map((m) => ({ ...m, isGate: false, gateData: null })), 
      ...chatEvents
    ];
    
    const groups: Array<{ 
      type: "message" | "chain" | "gate" | "artifact"; 
      content: any 
    }> = [];
    
    let currentChain: ChatMessage[] = [];
    let foundChain = false;

    combined.forEach((msg) => {
      if (msg.isArtifact) {
        if (currentChain.length > 0) { 
          groups.push({ type: "chain", content: [...currentChain] }); 
          foundChain = true;
          currentChain = []; 
        }
        groups.push({ type: "artifact", content: msg.artifactData });
      } else if (msg.role === "tool" || (msg.role === "system" && !msg.isGate)) {
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
          <div className={`spot-message ${g.content.role === "user" ? "user" : "agent"}`}>
            <div className="message-content">{g.content.text}</div>
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
            activeStep={(isRunning && i === groups.length - 1) ? task?.current_step : null} 
            agentName={task?.agent}
            generation={task?.generation}
            progress={task?.progress}
            totalSteps={task?.total_steps}
          />
        )}
        
        {g.type === "gate" && (
          <SpotlightApprovalCard 
            title={g.content.title} 
            description={g.content.description} 
            risk={g.content.risk} 
            onApprove={handleApprove} 
            onDeny={handleDeny} 
          />
        )}
        
        {g.type === "artifact" && (
          <VisualArtifact 
            url={g.content.url} 
            title={g.content.title} 
            isActive={g.content.isActive} 
            screenshot={g.content.screenshot} 
          />
        )}
      </React.Fragment>
    ));

    return { chatElements: elements, hasChainContent: foundChain };
  }, [activeHistory, chatEvents, handleApprove, handleDeny, isRunning, task]);

  // Only show initial loader if running AND no chain content exists yet
  const showInitialLoader = isRunning && !hasChainContent;

  // ============================================
  // RENDER
  // ============================================

  return (
    <div 
      className={`spot-window ${isFloating ? "floating" : ""}`} 
      onClick={handleGlobalClick} 
      ref={containerRef}
    >
      <div className={`spot-container ${layout.sidebarVisible ? "sidebar-open" : ""}`}>
        
        {/* Left Sidebar */}
        {layout.sidebarVisible && (
          <HistorySidebar
            sessions={sessions}
            onSelectSession={handleLoadSession}
            onNewChat={handleNewChat}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            onClose={() => invoke("hide_spotlight")}
            onToggle={() => toggleSidebar(false)} 
          />
        )}

        {/* Main Panel */}
        <div className="spot-main">
          {/* Header */}
          <div className="spot-header-actions">
            {/* Left side controls */}
            {!layout.sidebarVisible && (
              <>
                <button 
                  className="spot-icon-btn" 
                  onClick={() => toggleSidebar(true)} 
                  title="Toggle Sidebar (⌘K)"
                  style={{ marginRight: "auto" }} 
                >
                  {icons.sidebar}
                </button>
                <button 
                  className="spot-icon-btn" 
                  onClick={handleNewChat} 
                  title="New Chat (⌘N)"
                >
                  {icons.plus}
                </button>
                <div className="divider-vertical" />
              </>
            )}
            
            {/* Floating indicator / re-dock button */}
            {isFloating && (
              <button 
                className="spot-icon-btn dock-btn"
                onClick={dockRight}
                title="Dock to right (⌘D)"
              >
                {icons.sidebar}
              </button>
            )}
            
            {/* Artifact panel toggle */}
            {currentArtifact && (
              <button 
                className={`spot-icon-btn ${layout.artifactPanelVisible ? 'active' : ''}`}
                onClick={() => toggleArtifactPanel()}
                title="View Code"
              >
                {icons.code}
              </button>
            )}
            
            <button 
              className="spot-icon-btn" 
              onClick={() => openStudio("history")} 
              title="History"
            >
              {icons.history}
            </button>
            <button 
              className="spot-icon-btn" 
              onClick={() => openStudio("settings")} 
              title="Settings"
            >
              {icons.settings}
            </button>
            <button 
              className="spot-icon-btn" 
              onClick={() => openStudio("copilot")} 
              title="Expand"
            >
              {icons.expand}
            </button>
            <button 
              className="spot-icon-btn close" 
              onClick={() => invoke("hide_spotlight")} 
              title="Close (Esc)"
            >
              {icons.close}
            </button>
          </div>

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
                onChange={handleInputChange}
                onKeyDown={handleInputKeyDown}
                onFocus={() => setInputFocused(true)}
                onBlur={() => setInputFocused(false)}
                disabled={isGated}
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
                  <button 
                    className="spot-action-btn" 
                    title="Commands (/)"
                  >
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
                    disabled={!intent.trim()} 
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
                onToggle={() => setActiveDropdown(
                  activeDropdown === "workspace" ? null : "workspace"
                )} 
              />
              <Dropdown 
                icon={icons.cube} 
                options={modelOptions} 
                selected={selectedModel} 
                onSelect={setSelectedModel} 
                isOpen={activeDropdown === "model"} 
                onToggle={() => setActiveDropdown(
                  activeDropdown === "model" ? null : "model"
                )}
                footer={{
                  label: "Manage Models...",
                  onClick: () => openStudio("settings")
                }}
              />
            </div>
          </div>
        </div>

        {/* Artifact Panel */}
        {layout.artifactPanelVisible && currentArtifact && (
          <ArtifactPanel 
            fileName={currentArtifact.name}
            content={currentArtifact.content}
            onClose={() => toggleArtifactPanel(false)}
          />
        )}
      </div>
    </div>
  );
}