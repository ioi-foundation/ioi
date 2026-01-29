// apps/autopilot/src/windows/StudioWindow/components/StudioCopilot.tsx
import { useState, useRef, useMemo, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAgentStore } from "../../../store/agentStore";
import type { ChatMessage, GateInfo } from "../../../store/agentStore";
import { SessionSummary } from "../../../types";
import { SwarmViz } from "../../../components/SwarmViz";
import { 
  BotIcon, MessageIcon, SwarmIcon, CubeIcon, 
  GlobeIcon, AppsIcon, PlusIcon, SidebarIcon, SearchIcon,
  ApprovalCard
} from "./SharedUI"; 
import { StudioDropdown } from "./SharedUI";

type DisplayMessage = {
  role: string;
  text: string;
  isGate: false;
} | {
  role: string;
  text: string;
  isGate: true;
  gateData: GateInfo;
};

export function StudioCopilotView() {
  // --- Global State (Source of Truth) ---
  const { startTask, continueTask, resetSession, task } = useAgentStore();
  
  // --- Local UI State ---
  const [intent, setIntent] = useState("");
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  
  // Configuration State
  const [agentMode, setAgentMode] = useState("Swarm");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");

  const inputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const showSwarmPanel = agentMode === "Swarm";

  // --- Derived State (Binding to Kernel) ---
  
  // 1. Swarm Visualization Data
  // If no task is running, we show an empty array or could show previous state.
  // The 'swarm_tree' is populated by 'Spawn' events from the backend.
  const swarmState = task?.swarm_tree || [];

  // 2. Chat Stream & Gate Injection
  // We merge the persistent history with the ephemeral Gate state.
  const displayMessages = useMemo(() => {
    // Map backend history to UI format
    const msgs: DisplayMessage[] = (task?.history || []).map((h: ChatMessage) => ({
        role: h.role,
        text: h.text,
        isGate: false
    }));

    // If the kernel is blocking for approval, inject the Gate Card at the bottom
    if (task?.phase === 'Gate' && task.gate_info) {
        msgs.push({
            role: 'system',
            text: '', // Text ignored for gates
            isGate: true,
            gateData: task.gate_info
        });
    } else if (msgs.length === 0 && !task) {
        // Initial Greeting if absolutely nothing exists
        msgs.push({
            role: 'agent',
            text: 'Swarm Orchestrator ready. System allows "GPT-4o" via "Net" mode.',
            isGate: false
        });
    }

    return msgs;
  }, [task?.history, task?.phase, task?.gate_info, task]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [displayMessages.length, task?.phase]);

  // --- Handlers ---

  const handleSubmit = async () => {
    if (!intent.trim()) return;
    
    // Auto-switch mode context
    if (intent.toLowerCase().includes("swarm") && agentMode !== "Swarm") {
      setAgentMode("Swarm");
    }
    
    const intentToSend = intent;
    setIntent(""); // Clear input immediately
    
    try {
        // Logic Branch: New vs Continue
        if (task && task.id && task.phase !== "Failed") {
            // If we have an active task/session, append to it
            await continueTask(task.id, intentToSend);
        } else {
            // Otherwise, start a fresh session
            await startTask(intentToSend); // [FIX] No mode param
        }
    } catch (e) {
        console.error("Task error:", e);
    }
  };

  const handleApprove = async () => {
    // This signature allows the blocked action to proceed in the backend
    await invoke("gate_respond", { approved: true });
  };

  const handleReject = async () => {
     await invoke("gate_respond", { approved: false });
  };
  
  const handleNewChat = () => {
      resetSession();
      setTimeout(() => inputRef.current?.focus(), 50);
  };

  const handleLoadSession = async (id: string) => {
    try {
      await invoke("load_session", { sessionId: id });
    } catch (e) {
      console.error("Failed to load session:", e);
    }
  };

  const handleGlobalClick = () => { 
    if (activeDropdown) setActiveDropdown(null); 
  };

  const getModeIcon = () => {
    switch (agentMode) {
      case "Chat": return <MessageIcon />;
      case "Swarm": return <SwarmIcon />;
      default: return <BotIcon />;
    }
  };

  return (
    <div className="copilot-layout" onClick={handleGlobalClick}>
      <ChatHistorySidebar 
        onSelectSession={handleLoadSession} 
        onNewChat={handleNewChat} // Pass handler
      />

      <div className={`copilot-chat ${!showSwarmPanel ? 'expanded' : ''}`}>
        <div className="copilot-chat-header">
          <BotIcon />
          {agentMode} Mode
          {task && (
             <span style={{marginLeft: 'auto', fontSize: 10, color: '#6B7280'}}>
                ID: {task.id.slice(0, 8)} • {task.phase}
             </span>
          )}
        </div>
        
        <div className={`copilot-messages ${!showSwarmPanel ? 'centered' : ''}`}>
          {displayMessages.map((msg: DisplayMessage, i: number) => (
            <div key={i} className={`chat-msg-wrapper ${msg.role}`}>
                {msg.isGate ? (
                    <ApprovalCard 
                        title={msg.gateData.title}
                        description={msg.gateData.description}
                        risk={msg.gateData.risk}
                        onApprove={handleApprove}
                        onDeny={handleReject}
                    />
                ) : (
                    <div className={`chat-msg ${msg.role}`}>
                        {msg.text}
                    </div>
                )}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="copilot-input-area">
          <div className={`copilot-input-container ${!showSwarmPanel ? 'centered' : ''}`}>
            <div className="copilot-input-wrapper">
              <input
                ref={inputRef}
                className="copilot-input"
                placeholder={agentMode === "Swarm" ? "Command the swarm..." : "How can I help you today?"}
                value={intent}
                onChange={e => setIntent(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                // Disable input during Gate to force decision
                disabled={task?.phase === 'Gate'}
              />
            </div>
            
            <div className="copilot-controls">
              <StudioDropdown
                icon={getModeIcon()}
                label={agentMode}
                options={["Chat", "Agent", "Swarm"]}
                selected={agentMode}
                onSelect={setAgentMode}
                isOpen={activeDropdown === "agent"}
                onToggle={() => setActiveDropdown(activeDropdown === "agent" ? null : "agent")}
              />
              <StudioDropdown
                icon={<CubeIcon />}
                label={selectedModel}
                options={["GPT-4o", "Claude 3.5", "Llama 3"]}
                selected={selectedModel}
                onSelect={setSelectedModel}
                isOpen={activeDropdown === "model"}
                onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")}
              />
              <StudioDropdown
                icon={<GlobeIcon />}
                label={networkMode}
                options={["Net", "Local Only"]}
                selected={networkMode}
                onSelect={setNetworkMode}
                isOpen={activeDropdown === "network"}
                onToggle={() => setActiveDropdown(activeDropdown === "network" ? null : "network")}
              />
              <StudioDropdown
                icon={<AppsIcon />}
                label={connectedApp}
                options={["Apps", "Slack", "Notion"]}
                selected={connectedApp}
                onSelect={setConnectedApp}
                isOpen={activeDropdown === "connect"}
                onToggle={() => setActiveDropdown(activeDropdown === "connect" ? null : "connect")}
              />
            </div>
          </div>
        </div>
      </div>

      {showSwarmPanel && (
        <div className="copilot-swarm">
          {/* SwarmViz now receives live state from the Kernel via the Store */}
          <SwarmViz
            agents={swarmState}
            onApproveAgent={() => handleApprove()}
            onRejectAgent={() => handleReject()}
          />
        </div>
      )}
    </div>
  );
}

interface ChatHistorySidebarProps {
    onSelectSession: (id: string) => void;
    onNewChat: () => void;
}

function ChatHistorySidebar({ onSelectSession, onNewChat }: ChatHistorySidebarProps) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);

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
      // Poll for updates
      const interval = setInterval(loadHistory, 5000);
      return () => clearInterval(interval);
  }, []);

  const dockOut = async () => {
    await invoke("show_spotlight");
    await invoke("hide_studio");
  };

  const formatTimeAgo = (ms: number) => {
      const diff = Date.now() - ms;
      const min = Math.floor(diff / 60000);
      if (min < 1) return 'just now';
      if (min < 60) return `${min}m ago`;
      const hr = Math.floor(min / 60);
      if (hr < 24) return `${hr}h ago`;
      return `${Math.floor(hr / 24)}d ago`;
  };

  return (
    <div className="copilot-sidebar">
      <div className="copilot-sidebar-header">
        <button className="copilot-new-btn" onClick={onNewChat}>
          <PlusIcon /> New Chat
        </button>
        <button className="copilot-dock-btn" onClick={dockOut} title="Pop out to Sidebar">
          <SidebarIcon />
        </button>
      </div>
      
      <div className="copilot-search">
        <div className="copilot-search-box">
          <SearchIcon />
          <input placeholder="Search chats..." />
        </div>
      </div>

      <div className="copilot-history">
        <div className="copilot-history-label">Recent</div>
        {sessions.length === 0 ? (
            <div style={{padding: 12, color: '#6B7280', fontSize: 11, fontStyle: 'italic'}}>
                No recent history
            </div>
        ) : (
            sessions.map(item => (
              <div key={item.session_id} className="copilot-history-item" onClick={() => onSelectSession(item.session_id)}>
                <div className="copilot-history-title">{item.title}</div>
                <div className="copilot-history-time">{formatTimeAgo(item.timestamp)}</div>
              </div>
            ))
        )}
      </div>
    </div>
  );
}