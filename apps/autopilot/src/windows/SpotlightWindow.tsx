// apps/autopilot/src/windows/SpotlightWindow.tsx
import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../store/agentStore";
import { AgentTask, ChatMessage, SessionSummary } from "../types"; 
import "./SpotlightWindow.css";

// --- Minimal Icons ---
const icons = {
  close: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  ),
  expand: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
    </svg>
  ),
  history: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10"/>
      <polyline points="12 6 12 12 16 14"/>
    </svg>
  ),
  settings: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/>
    </svg>
  ),
  plus: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 5v14M5 12h14"/>
    </svg>
  ),
  slash: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M7 4l10 16"/>
    </svg>
  ),
  sparkles: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3v2M12 19v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M3 12h2M19 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
      <circle cx="12" cy="12" r="4"/>
    </svg>
  ),
  send: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 19V5M5 12l7-7 7 7"/>
    </svg>
  ),
  laptop: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 16V7a2 2 0 00-2-2H6a2 2 0 00-2 2v9m16 0H4m16 0l1.28 2.55a1 1 0 01-.9 1.45H3.62a1 1 0 01-.9-1.45L4 16"/>
    </svg>
  ),
  cloud: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinejoin="round">
      <path d="M6.5 18.5a4 4 0 01-.43-7.97 6.5 6.5 0 0112.86 0 4 4 0 01-.43 7.97h-12z"/>
    </svg>
  ),
  chat: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
    </svg>
  ),
  robot: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="11" width="18" height="10" rx="2"/>
      <circle cx="12" cy="5" r="2"/>
      <path d="M12 7v4"/>
      <circle cx="8" cy="16" r="1" fill="currentColor"/>
      <circle cx="16" cy="16" r="1" fill="currentColor"/>
    </svg>
  ),
  swarm: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <circle cx="12" cy="12" r="2.5"/>
      <circle cx="6" cy="6" r="2"/>
      <circle cx="18" cy="6" r="2"/>
      <circle cx="6" cy="18" r="2"/>
      <circle cx="18" cy="18" r="2"/>
      <path d="M12 9.5V7M12 14.5V17M9.5 12H7M14.5 12H17M9.88 9.88L7.5 7.5M14.12 9.88L16.5 7.5M9.88 14.12L7.5 16.5M14.12 14.12L16.5 16.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
    </svg>
  ),
  cube: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
      <path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/>
    </svg>
  ),
  chevron: (
    <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <path d="M6 9l6 6 6-6"/>
    </svg>
  ),
  chevronRight: (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 18l6-6-6-6"/>
    </svg>
  ),
};

// IOI Logo Watermark Component
const IOIWatermark = () => (
  <svg className="spot-watermark" viewBox="108.97 89.47 781.56 706.06" fill="none">
    <g stroke="currentColor" strokeWidth="1" strokeLinejoin="round" strokeLinecap="round">
      <path d="M295.299 434.631L295.299 654.116 485.379 544.373z"/>
      <path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z"/>
      <path d="M514.621 544.373L704.701 654.115 704.701 434.631z"/>
      <path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z"/>
      <path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z"/>
      <path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z"/>
      <path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z"/>
      <path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z"/>
      <path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z"/>
      <path d="M302.61 666.778L500 780.741 500 552.815z"/>
      <path d="M500 552.815L500 780.741 697.39 666.778z"/>
    </g>
  </svg>
);

// [NEW] Local Approval Card Definition (mirroring SharedUI)
function SpotlightApprovalCard({ title, description, risk, onApprove, onDeny }: any) {
    const riskColor = risk === 'high' ? '#EF4444' : risk === 'medium' ? '#F59E0B' : '#10B981';
    return (
        <div style={{
            background: 'rgba(23, 26, 32, 0.95)',
            border: `1px solid ${riskColor}40`,
            borderRadius: 8,
            padding: 12,
            marginTop: 8,
            marginBottom: 8,
            borderLeft: `3px solid ${riskColor}`,
            width: '100%',
        }}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6}}>
                <span style={{fontSize: 12, fontWeight: 600, color: '#E5E7EB'}}>{title}</span>
                <span style={{fontSize: 9, fontWeight: 700, color: riskColor, background: `${riskColor}15`, padding: '1px 5px', borderRadius: 3}}>
                    {risk.toUpperCase()}
                </span>
            </div>
            <div style={{fontSize: 11, color: '#9CA3AF', marginBottom: 10, lineHeight: 1.4}}>
                {description}
            </div>
            <div style={{display: 'flex', gap: 6}}>
                <button onClick={onApprove} style={{flex: 1, background: riskColor, color: 'white', border: 'none', borderRadius: 4, padding: '4px', fontSize: 11, fontWeight: 600, cursor: 'pointer'}}>
                    Authorize
                </button>
                <button onClick={onDeny} style={{padding: '4px 8px', background: 'transparent', border: '1px solid #3F4652', color: '#9CA3AF', borderRadius: 4, fontSize: 11, cursor: 'pointer'}}>
                    Deny
                </button>
            </div>
        </div>
    );
}

interface DropdownOption {
  value: string;
  label: string;
  desc?: string;
  icon?: React.ReactNode;
}

interface DropdownProps {
  icon: React.ReactNode;
  options: DropdownOption[];
  selected: string;
  onSelect: (val: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  footer?: { label: string; onClick: () => void };
}

function Dropdown({ icon, options, selected, onSelect, isOpen, onToggle, footer }: DropdownProps) {
  const selectedOption = options.find(opt => opt.value === selected);
  const displayIcon = selectedOption?.icon || icon;

  return (
    <div className="spot-dropdown">
      <button 
        className={`spot-toggle ${isOpen ? 'open' : ''}`}
        onClick={(e) => { e.stopPropagation(); onToggle(); }}
      >
        {displayIcon}
        {icons.chevron}
      </button>
      
      {isOpen && (
        <div className="spot-dropdown-menu">
          {options.map(opt => (
            <button 
              key={opt.value} 
              className={`spot-dropdown-item ${selected === opt.value ? 'selected' : ''}`}
              onClick={() => { onSelect(opt.value); onToggle(); }}
            >
              {opt.icon && <span className="spot-dropdown-icon">{opt.icon}</span>}
              <div className="spot-dropdown-content">
                <span className="spot-dropdown-label">{opt.label}</span>
                {opt.desc && <span className="spot-dropdown-desc">{opt.desc}</span>}
              </div>
            </button>
          ))}
          {footer && (
            <>
              <div className="spot-dropdown-divider" />
              <button 
                className="spot-dropdown-footer"
                onClick={(e) => { e.stopPropagation(); footer.onClick(); onToggle(); }}
              >
                <span>{footer.label}</span>
                {icons.chevronRight}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

const workspaceOptions: DropdownOption[] = [
  { value: "local", label: "Local workspace", desc: "Process on device", icon: icons.laptop },
  { value: "cloud", label: "Send to cloud", desc: "Use remote compute", icon: icons.cloud },
];

const modeOptions: DropdownOption[] = [
  { value: "Chat", label: "Chat", desc: "Simple conversation", icon: icons.chat },
  { value: "Agent", label: "Agent", desc: "Autonomous actions", icon: icons.robot },
  { value: "Swarm", label: "Swarm", desc: "Multi-agent team", icon: icons.swarm },
];

const modelOptions: DropdownOption[] = [
  { value: "GPT-4o", label: "GPT-4o", desc: "OpenAI flagship" },
  { value: "Claude 3.5", label: "Claude 3.5", desc: "Anthropic Sonnet" },
  { value: "Llama 3", label: "Llama 3", desc: "Meta open weights" },
  { value: "Local", label: "Local", desc: "On-device model" },
];

function formatTimeAgo(ms: number) {
  const diff = Date.now() - ms;
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const day = Math.floor(hr / 24);
  return `${day}d`;
}

export function SpotlightWindow() {
  const [intent, setIntent] = useState("");
  const [localHistory, setLocalHistory] = useState<ChatMessage[]>([]);
  const [autoContext, setAutoContext] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  
  // History State
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  
  // Dropdown selections
  const [workspaceMode, setWorkspaceMode] = useState("local");
  const [conversationMode, setConversationMode] = useState("Agent");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  
  // [NEW] Local state for chat stream including Gates
  const [chatEvents, setChatEvents] = useState<{role: string, text: string, isGate?: boolean, gateData?: any}[]>([]);

  const inputRef = useRef<HTMLInputElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  
  const { task, startTask } = useAgentStore();

  useEffect(() => {
    initEventListeners();
    invoke("set_spotlight_mode", { mode: "sidebar" }).catch(console.error);
    setTimeout(() => inputRef.current?.focus(), 150);
    
    // Load history
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

  const activeHistory: ChatMessage[] = (task as AgentTask | null)?.history || localHistory;

  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [activeHistory, chatEvents]); 

  // [UPDATED] Listen for Gate Phase
  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
        // Prevent dupes
        const last = chatEvents[chatEvents.length - 1];
        if (!last || !last.isGate) {
            setChatEvents(prev => [...prev, {
                role: 'system',
                text: '',
                isGate: true,
                gateData: task.gate_info
            }]);
            
            // Scroll to bottom
            setTimeout(() => {
                if (chatAreaRef.current) chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
            }, 100);
        }
    }
  }, [task?.phase, task?.gate_info]);

  const openStudio = async (targetView: string = "compose") => {
    await emit("request-studio-view", targetView);
    await invoke("hide_spotlight");
    await invoke("show_studio");
  };

  const handleLoadSession = async (id: string) => {
    try {
      await invoke("load_session", { sessionId: id });
    } catch (e) {
      console.error("Failed to load session:", e);
    }
  };

  const handleDeleteSession = async (e: React.MouseEvent, id: string) => {
      e.stopPropagation(); // Prevent opening the session
      if (!confirm("Are you sure? This action cannot be undone.")) return;

      try {
          await invoke("delete_session", { sessionId: id });
          // Optimistic UI update
          setSessions(prev => prev.filter(s => s.session_id !== id));
      } catch (err) {
          console.error("Failed to delete session:", err);
      }
  };

  const handleSubmit = async (textOverride?: string) => {
    const text = textOverride || intent;
    if (!text.trim()) return;

    setIntent("");
    
    // Optimistic add to local history if no task active
    if (!task) {
        setLocalHistory(prev => [...prev, { role: 'user', text, timestamp: Date.now() }]);
    }
    
    if (task && task.phase === "Running") return;

    try {
      if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) {
        await openStudio("copilot");
      }
      await startTask(text, conversationMode);
    } catch (e) {
      console.error(e);
    }
  };

  const handleApprove = async () => {
      await invoke("gate_respond", { approved: true });
      setChatEvents(prev => prev.map(m => m.isGate ? { ...m, isGate: false, text: "✅ Approved" } : m));
  };

  const handleDeny = async () => {
      await invoke("gate_respond", { approved: false });
      setChatEvents(prev => prev.map(m => m.isGate ? { ...m, isGate: false, text: "❌ Denied" } : m));
  };

  const handleGlobalClick = () => {
    if (activeDropdown) setActiveDropdown(null);
  };

  const hasContent = activeHistory.length > 0 || chatEvents.length > 0;

  return (
    <div className="spot-window" onClick={handleGlobalClick}>
      <div className="spot-container">
        
        {/* Tasks List */}
        <div className="spot-tasks-bar">
          <span className="spot-tasks-title">Recent Tasks</span>
        </div>
        <div className="spot-tasks-list">
          {sessions.slice(0, 5).map(s => (
            <div key={s.session_id} className="spot-task-row-container" style={{display: 'flex', alignItems: 'center'}}>
                <button 
                    className="spot-task-item"
                    onClick={() => handleLoadSession(s.session_id)}
                >
                  <span className="spot-task-title">{s.title}</span>
                  <span className="spot-task-age">{formatTimeAgo(s.timestamp)}</span>
                </button>
                <button 
                    className="spot-task-delete"
                    onClick={(e) => handleDeleteSession(e, s.session_id)}
                    title="Delete Session"
                    style={{background: 'none', border: 'none', cursor: 'pointer', color: '#6B7280', padding: 8}}
                >
                   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                     <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                   </svg>
                </button>
            </div>
          ))}
          {sessions.length === 0 && (
              <div className="spot-task-item disabled" style={{opacity: 0.5}}>
                  <span className="spot-task-title">No recent tasks</span>
              </div>
          )}
          {sessions.length > 5 && (
              <button className="spot-tasks-more">View all ({sessions.length})</button>
          )}
        </div>

        {/* Chat Area */}
        <div className="spot-chat" ref={chatAreaRef}>
          {!hasContent && !task && (
            <div className="spot-empty">
              <IOIWatermark />
            </div>
          )}

          {/* Render regular history first */}
          {activeHistory.map((msg: ChatMessage, i: number) => (
            <div key={i} className={`spot-message ${msg.role}`}>
              {msg.text}
            </div>
          ))}

          {/* Render dynamic events (including gates) */}
          {chatEvents.map((msg, i) => (
              <div key={i} className={`spot-message-wrapper ${msg.role}`} style={{width: '100%', display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start'}}>
                  {msg.isGate ? (
                      <SpotlightApprovalCard 
                         title={msg.gateData.title}
                         description={msg.gateData.description}
                         risk={msg.gateData.risk}
                         onApprove={handleApprove}
                         onDeny={handleDeny}
                      />
                  ) : (
                      <div className={`spot-message ${msg.role}`}>
                          {msg.text}
                      </div>
                  )}
              </div>
          ))}

          {task && task.phase === "Running" && (
            <div className="spot-thinking">
              <span className="spot-thinking-dot" />
              <span className="spot-thinking-dot" />
              <span className="spot-thinking-dot" />
            </div>
          )}
        </div>

        {/* Input Section */}
        <div className="spot-input-section">
          <div className="spot-input-row">
            <input
              ref={inputRef}
              className="spot-input"
              placeholder={conversationMode === "Chat" ? "Ask anything..." : "How can I help you today?"}
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              disabled={task?.phase === "Running"}
            />
          </div>

          <div className="spot-controls">
            <div className="spot-controls-left">
              <button className="spot-action-btn" title="Attach file">
                {icons.plus}
              </button>
              <button className="spot-action-btn" title="Commands">
                {icons.slash}
              </button>
              <button 
                className={`spot-context-btn ${autoContext ? 'active' : ''}`}
                onClick={() => setAutoContext(!autoContext)}
              >
                {icons.sparkles}
                <span>Auto context</span>
              </button>
            </div>
            <button 
              className="spot-send-btn"
              onClick={() => handleSubmit()}
              disabled={!intent.trim()}
            >
              {icons.send}
            </button>
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
              icon={icons.chat}
              options={modeOptions}
              selected={conversationMode}
              onSelect={setConversationMode}
              isOpen={activeDropdown === "conversation"}
              onToggle={() => setActiveDropdown(activeDropdown === "conversation" ? null : "conversation")}
              footer={{ label: "Open Studio...", onClick: () => openStudio("compose") }}
            />
            <Dropdown
              icon={icons.cube}
              options={modelOptions}
              selected={selectedModel}
              onSelect={setSelectedModel}
              isOpen={activeDropdown === "model"}
              onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")}
            />
          </div>
        </div>

        {/* Header Actions */}
        <div className="spot-header-actions">
          <button className="spot-icon-btn" onClick={() => openStudio("history")} title="History">{icons.history}</button>
          <button className="spot-icon-btn" onClick={() => openStudio("settings")} title="Settings">{icons.settings}</button>
          <button className="spot-icon-btn" onClick={() => openStudio("copilot")} title="Expand">{icons.expand}</button>
          <button className="spot-icon-btn" onClick={() => invoke("hide_spotlight")} title="Close">{icons.close}</button>
        </div>
      </div>
    </div>
  );
}