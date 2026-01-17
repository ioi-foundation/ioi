import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../store/agentStore";
import "./SpotlightWindow.css";

// --- Icons ---
const MaximizeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" /></svg>
);
const CloseIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
);
const IncognitoIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
);
const SendIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
);

// --- Mode Icons ---
const MessageIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
);
const BotIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>
);
const SwarmIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="M7.5 17.5 10 12.5"/><path d="M16.5 17.5 14 12.5"/></svg>
);

// Suggestion Icons
const CubeIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>;
const GlobeIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>;
const AppsIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /></svg>;

const MailIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>;
const FlightIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 12h20"/><path d="m19 12-7-7-7 7"/><path d="M12 19V5"/></svg>;
const DollarIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>;
const SearchIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>;

interface ChatMessage {
  role: 'user' | 'agent';
  text: string;
}

export function SpotlightWindow() {
  const [isIncognito, setIsIncognito] = useState(false);
  const [intent, setIntent] = useState("");
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  
  // State for selections
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [agentMode, setAgentMode] = useState("Agent");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");
  
  const { task, startTask } = useAgentStore();

  useEffect(() => {
    initEventListeners();
    // Ensure we are in sidebar mode on mount
    invoke("set_spotlight_mode", { mode: "sidebar" }).catch(console.error);
    setTimeout(() => inputRef.current?.focus(), 150);
  }, []);

  // [NEW] Logic to handle Agent Mode switching -> Open Studio Copilot
  useEffect(() => {
    if (agentMode === "Swarm") {
      openStudio("copilot"); // Pass "copilot" payload
      // Reset dropdown to default after triggering transition
      setTimeout(() => setAgentMode("Agent"), 500); 
    }
  }, [agentMode]);

  // Sync task to chat
  useEffect(() => {
    if (!task) return;

    if (task.phase === "Running" && task.current_step.length > 80) {
        setChatHistory(prev => {
            const lastMsg = prev[prev.length - 1];
            if (lastMsg?.text === task.current_step) return prev;
            return [...prev, { role: 'agent', text: task.current_step }];
        });
    }

    if (task.phase === "Complete" && task.receipt) {
      setChatHistory(prev => {
        const lastMsg = prev[prev.length - 1];
        if (lastMsg?.text.includes("Task complete")) return prev;
        return [...prev, { role: 'agent', text: `✅ Task complete. ${task.receipt?.actions} actions.` }];
      });
    }
    if (task.phase === "Failed") {
      setChatHistory(prev => {
         const lastMsg = prev[prev.length - 1];
         if (lastMsg?.text.startsWith("❌ Task failed")) return prev;
         return [...prev, { role: 'agent', text: `❌ Task failed: ${task.current_step}` }];
      });
    }
  }, [task]);

  // Auto-scroll
  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [chatHistory]);

  const openStudio = async (targetView: string = "compose") => {
    // Emit event to tell Studio which tab to open
    await emit("request-studio-view", targetView);
    await invoke("hide_spotlight");
    await invoke("show_studio");
  };

  const handleSubmit = async (textOverride?: string) => {
    const text = textOverride || intent;
    if (!text.trim()) return;

    setIntent("");
    setChatHistory(prev => [...prev, { role: 'user', text }]);
    
    if (task && task.phase === "Running") {
      return;
    }

    try {
      // Heuristic: If "swarm" or "team" is in prompt, switch to Studio Copilot
      if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) {
          await openStudio("copilot");
      }

      await startTask(text);
      setChatHistory(prev => [...prev, { role: 'agent', text: "Initializing workflow..." }]);
    } catch (e) {
      console.error(e);
    }
  };

  const handleGlobalClick = () => {
    if (activeDropdown) setActiveDropdown(null);
  };

  // Helper to get the correct icon for the dropdown trigger
  const getModeIcon = () => {
    switch (agentMode) {
      case "Chat": return <MessageIcon />;
      case "Swarm": return <SwarmIcon />;
      default: return <BotIcon />;
    }
  };

  const hasContent = chatHistory.length > 0 || task != null;

  return (
    <div 
      className="spotlight-window mode-sidebar" 
      onClick={handleGlobalClick}
    >
      <div className="assistant-container">
        
        {/* --- SINGLE PANE (Chat + Controls) --- */}
        <div className="spot-left-pane">
            {/* Header */}
            <div className="spot-header" data-tauri-drag-region>
              <div className="header-brand">
                 <div className="brand-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                      <path d="M12 2L2 7L12 12L22 7L12 2Z" fill="currentColor" fillOpacity="0.5" stroke="currentColor" strokeWidth="2"/>
                      <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2"/>
                      <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2"/>
                    </svg>
                 </div>
                 <span className="brand-text">Autopilot</span>
              </div>

              <div className="header-actions">
                <button 
                  className={`header-btn ${isIncognito ? "active" : ""}`} 
                  onClick={() => setIsIncognito(!isIncognito)} 
                  title="Toggle Incognito"
                >
                  <IncognitoIcon />
                </button>
                <button 
                  className="header-btn" 
                  onClick={() => openStudio("copilot")} 
                  title="Expand to Studio Copilot"
                >
                  <MaximizeIcon />
                </button>
                <button className="header-btn" onClick={() => invoke("hide_spotlight")} title="Close">
                  <CloseIcon />
                </button>
              </div>
            </div>

            {/* Chat / Content Area */}
            <div className="chat-area" ref={chatAreaRef}>
              {/* Welcome / Suggestions (Empty State) */}
              {!hasContent && (
                 <div className="suggestions-container">
                    <div className="suggestions-title">Quick Actions</div>
                    <div className="suggestions-grid">
                      <SuggestionCard 
                        icon={<MailIcon />} 
                        label="Summarize Inbox" 
                        desc="Read unread emails"
                        onClick={() => handleSubmit("Summarize Inbox")} 
                      />
                      <SuggestionCard 
                        icon={<DollarIcon />} 
                        label="Analyze Spend" 
                        desc="Scan PDF invoices"
                        onClick={() => handleSubmit("Analyze recent invoices")} 
                      />
                      <SuggestionCard 
                        icon={<FlightIcon />} 
                        label="Book Travel" 
                        desc="Find flights & hotels"
                        onClick={() => handleSubmit("Book a flight to NYC")} 
                      />
                      <SuggestionCard 
                        icon={<SearchIcon />} 
                        label="System Audit" 
                        desc="Check security logs"
                        onClick={() => handleSubmit("Run security audit")} 
                      />
                    </div>
                 </div>
              )}

              {/* Chat History */}
              {chatHistory.map((msg, i) => (
                <div key={i} className={`chat-msg ${msg.role}`}>
                  {msg.text}
                </div>
              ))}
            </div>

            {/* Embedded Pill (Active Task) */}
            {task && (
              <div className={`embedded-pill ${task.phase.toLowerCase()}`}>
                  <div className="pill-content">
                    {task.phase === 'Running' ? (
                      <div className="pill-spinner" />
                    ) : (
                      <div className="pill-status-icon">{task.phase === 'Complete' ? '✅' : '⏸'}</div>
                    )}
                    <div>
                       <div className="pill-text">
                           {task.current_step.length > 60 ? "Reasoning..." : task.current_step}
                       </div>
                       {task.intent && <div style={{fontSize: 10, color: '#9ca3af'}}>{task.intent}</div>}
                    </div>
                  </div>
                  <div className="pill-sub">{task.progress}/{task.total_steps}</div>
              </div>
            )}

            {/* Input Area */}
            <div className="input-section">
                <div className="input-wrapper">
                    <input
                        ref={inputRef}
                        className="main-input"
                        placeholder={task ? "Wait for task..." : "Ask Copilot or type a command..."}
                        value={intent}
                        onChange={(e) => setIntent(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                        disabled={!!task && task.phase === "Running"}
                    />
                    <button className="send-btn" onClick={() => handleSubmit()} disabled={!intent.trim()}>
                    <SendIcon />
                    </button>
                </div>

                <div className="stack-footer">
                    <Dropdown 
                        icon={getModeIcon()} 
                        label={agentMode} 
                        options={["Chat", "Agent", "Swarm"]}
                        selected={agentMode}
                        onSelect={setAgentMode}
                        footer={{ label: "Open Studio...", onClick: () => openStudio("compose") }}
                        isOpen={activeDropdown === "agent"}
                        onToggle={() => setActiveDropdown(activeDropdown === "agent" ? null : "agent")}
                    />
                    <Dropdown 
                        icon={<CubeIcon />} 
                        label={selectedModel} 
                        options={["GPT-4o", "Claude 3.5", "Llama 3"]} 
                        selected={selectedModel}
                        onSelect={setSelectedModel}
                        isOpen={activeDropdown === "model"}
                        onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")}
                    />
                    <Dropdown 
                        icon={<GlobeIcon />} 
                        label={networkMode} 
                        options={["Net", "Local Only"]} 
                        selected={networkMode}
                        onSelect={setNetworkMode}
                        isOpen={activeDropdown === "network"}
                        onToggle={() => setActiveDropdown(activeDropdown === "network" ? null : "network")}
                    />
                    <Dropdown 
                        icon={<AppsIcon />} 
                        label={connectedApp}
                        options={["Apps", "Slack", "Notion", "GitHub"]}
                        selected={connectedApp}
                        onSelect={setConnectedApp} 
                        isOpen={activeDropdown === "connect"}
                        onToggle={() => setActiveDropdown(activeDropdown === "connect" ? null : "connect")}
                    />
                </div>
            </div>
        </div>
      </div>
    </div>
  );
}

// --- Helper Components ---

function SuggestionCard({ icon, label, desc, onClick }: { icon: React.ReactNode, label: string, desc: string, onClick: () => void }) {
  return (
    <div className="suggestion-card" onClick={onClick}>
       <div className="sugg-icon">{icon}</div>
       <div className="sugg-content">
          <div className="sugg-label">{label}</div>
          <div className="sugg-desc">{desc}</div>
       </div>
    </div>
  );
}

interface DropdownProps {
  icon: React.ReactNode;
  label: string;
  options: string[];
  selected?: string;
  onSelect?: (val: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  footer?: { label: string; onClick: () => void };
}

function Dropdown({ icon, label, options, selected, onSelect, isOpen, onToggle, footer }: DropdownProps) {
  return (
    <div className="custom-dropdown">
      <div 
        className={`dropdown-trigger ${isOpen ? 'open' : ''}`}
        onClick={(e) => {
          e.stopPropagation();
          onToggle();
        }}
      >
        <span>{icon}</span>
        <span>{label}</span>
        <svg className="trigger-caret" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{marginLeft: 2, opacity: 0.5}}>
           <polyline points="6 9 12 15 18 9" />
        </svg>
      </div>
      
      {isOpen && (
        <div className="dropdown-menu">
          {options.map(opt => (
            <div 
              key={opt} 
              className={`dropdown-item ${selected === opt ? 'selected' : ''}`}
              onClick={() => {
                if(onSelect) onSelect(opt);
                onToggle();
              }}
            >
              {opt}
            </div>
          ))}
          
          {footer && (
            <>
              <div className="dropdown-separator" />
              <div 
                className="dropdown-footer"
                onClick={(e) => {
                   e.stopPropagation();
                   footer.onClick();
                   onToggle();
                }}
              >
                {footer.label}
                <svg className="dropdown-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}