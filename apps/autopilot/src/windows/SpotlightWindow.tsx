// Path: apps/autopilot/src/windows/SpotlightWindow.tsx
import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAgentStore, initEventListeners } from "../store/agentStore";
import "./SpotlightWindow.css";

// --- Icons ---
const MaximizeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" /></svg>
);
const SidebarIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="15" y="3" width="6" height="18" rx="2" /><path d="M3 12h8" /><path d="M3 6h8" /><path d="M3 18h8" /></svg>
);
const CloseIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
);
const BuildIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
);
const IncognitoIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
);
const SendIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
);
const CursorIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
    <path d="M5.5 3.2L11.5 19.5L14.5 13L21 12L5.5 3.2Z" fill="black" stroke="white" strokeWidth="1.5"/>
  </svg>
);

// Suggestion Icons
const SparklesIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>;
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

interface ContextBlob {
    data_base64: string;
    mime_type: string;
}

type ViewMode = "sidebar" | "spotlight";

export function SpotlightWindow() {
  const [viewMode, setViewMode] = useState<ViewMode>("sidebar"); // Default to sidebar
  const [isIncognito, setIsIncognito] = useState(false);
  const [intent, setIntent] = useState("");
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  
  // State for selections
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [agentMode, setAgentMode] = useState("Agent");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");
  
  // [NEW] Context Visualization State
  const [visualContext, setVisualContext] = useState<string | null>(null);
  const [semanticContext, setSemanticContext] = useState<string | null>(null);
  const [contextLoading, setContextLoading] = useState(false);

  const { task, startTask } = useAgentStore();

  // Show split view if in spotlight mode and running a task
  const showPreview = viewMode === "spotlight" && task?.phase === "Running";

  useEffect(() => {
    initEventListeners();
    const timer = setTimeout(() => {
      invoke("set_spotlight_mode", { mode: "sidebar" }).catch((e) =>
        console.error("Failed to set window mode:", e)
      );
      inputRef.current?.focus();
    }, 800);

    return () => clearTimeout(timer);
  }, []);

  // Sync task to chat and fetch context blobs
  useEffect(() => {
    if (task?.phase === "Complete" && task.receipt) {
      setChatHistory(prev => [...prev, { role: 'agent', text: `✅ Task complete. ${task.receipt?.actions} actions.` }]);
    }
    if (task?.phase === "Failed") {
      setChatHistory(prev => [...prev, { role: 'agent', text: `❌ Task failed: ${task.current_step}` }]);
    }

    // [NEW] Fetch Context Slice if Hash is available (mocking the property on AgentTask for now)
    // In a real scenario, task would have `visual_hash` field from the event.
    // We check if the task object (extended) has a visual_hash
    const visualHash = (task as any)?.visual_hash;
    
    if (visualHash && showPreview) {
        setContextLoading(true);
        invoke<ContextBlob>("get_context_blob", { hash: visualHash })
            .then(blob => {
                if (blob.mime_type.startsWith("image/")) {
                    setVisualContext(`data:${blob.mime_type};base64,${blob.data_base64}`);
                } else if (blob.mime_type.includes("xml") || blob.mime_type.includes("json")) {
                    // Decode base64 to string for text display
                    const text = atob(blob.data_base64);
                    setSemanticContext(text);
                }
            })
            .catch(e => console.error("Failed to fetch context blob:", e))
            .finally(() => setContextLoading(false));
    }

  }, [task, showPreview]);

  const toggleViewMode = async () => {
    const newMode = viewMode === "sidebar" ? "spotlight" : "sidebar";
    setViewMode(newMode);
    await invoke("set_spotlight_mode", { mode: newMode });
    setTimeout(() => inputRef.current?.focus(), 200);
  };

  const openStudio = async () => {
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
      if (viewMode === "sidebar") toggleViewMode();

      await startTask(text);
      setChatHistory(prev => [...prev, { role: 'agent', text: "Initializing workflow..." }]);
    } catch (e) {
      console.error(e);
    }
  };

  const handleGlobalClick = () => {
    if (activeDropdown) setActiveDropdown(null);
  };

  const hasContent = chatHistory.length > 0 || task != null;

  return (
    <div className={`spotlight-window mode-${viewMode} ${showPreview ? 'has-preview' : ''}`} onClick={handleGlobalClick}>
      <div className="assistant-container">
        
        {/* --- LEFT PANE (Chat + Controls) --- */}
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
                <button className="header-btn" onClick={openStudio} title="Open Studio IDE">
                  <BuildIcon />
                </button>
                <button className="header-btn" onClick={toggleViewMode} title={viewMode === "sidebar" ? "Maximize" : "Dock Right"}>
                  {viewMode === "sidebar" ? <MaximizeIcon /> : <SidebarIcon />}
                </button>
                <button className="header-btn" onClick={() => invoke("hide_spotlight")} title="Close">
                  <CloseIcon />
                </button>
              </div>
            </div>

            {/* Chat / Content Area */}
            <div className="chat-area">
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
                       <div className="pill-text">{task.current_step}</div>
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
                  icon={<SparklesIcon />} 
                  label={agentMode} 
                  options={["Agent", "Chat"]}
                  selected={agentMode}
                  onSelect={setAgentMode}
                  footer={{ label: "Configure Custom Agents...", onClick: openStudio }}
                  isOpen={activeDropdown === "agent"}
                  onToggle={() => setActiveDropdown(activeDropdown === "agent" ? null : "agent")}
                />
                <Dropdown 
                  icon={<CubeIcon />} 
                  label={selectedModel} 
                  options={["GPT-4o", "Claude 3.5", "Llama 3"]} 
                  selected={selectedModel}
                  onSelect={setSelectedModel}
                  footer={{ label: "Manage Models...", onClick: openStudio }}
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
                  footer={{ label: "Connect Apps...", onClick: openStudio }}
                  isOpen={activeDropdown === "connect"}
                  onToggle={() => setActiveDropdown(activeDropdown === "connect" ? null : "connect")}
                />
              </div>
            </div>
        </div>

        {/* --- RIGHT PANE (Live Context Preview) --- */}
        {showPreview && (
            <div className="spot-right-pane">
                <div className="browser-card">
                    <div className="browser-chrome">
                        <div className="traffic-lights">
                            <div className="traffic-dot" style={{background: '#ff5f56'}} />
                            <div className="traffic-dot" style={{background: '#ffbd2e'}} />
                            <div className="traffic-dot" style={{background: '#27c93f'}} />
                        </div>
                        <div className="url-bar">
                            {visualContext ? "scs://visual-memory/latest" : "Waiting for visual context..."}
                        </div>
                    </div>
                    <div className="browser-viewport">
                        {contextLoading ? (
                            <div className="pill-spinner" style={{width: 32, height: 32, borderWidth: 3}} />
                        ) : visualContext ? (
                            <img src={visualContext} alt="Agent View" style={{width: '100%', height: '100%', objectFit: 'contain'}} />
                        ) : semanticContext ? (
                            <pre style={{padding: 20, fontSize: 10, color: '#333', overflow: 'auto'}}>{semanticContext}</pre>
                        ) : (
                            /* Fallback Mock Content */
                            <div style={{width: '90%', height: '80%', background: '#f3f4f6', borderRadius: 4, padding: 20}}>
                                <div style={{fontWeight: 'bold', color: '#1f2937', marginBottom: 10}}>Booking.com</div>
                                <div style={{display: 'flex', gap: 10}}>
                                    <div style={{flex: 1, height: 100, background: 'white', borderRadius: 4, border: '1px solid #e5e7eb'}} />
                                    <div style={{flex: 1, height: 100, background: 'white', borderRadius: 4, border: '2px solid #3b82f6'}} />
                                    <div style={{flex: 1, height: 100, background: 'white', borderRadius: 4, border: '1px solid #e5e7eb'}} />
                                </div>
                            </div>
                        )}
                        
                        {/* Simulated Cursor - Only show if not displaying real image */}
                        {!visualContext && (
                            <div className="agent-cursor" style={{ top: '45%', left: '55%' }}>
                                <CursorIcon />
                            </div>
                        )}
                    </div>
                </div>

                <div className="vision-log">
                    <LogItem 
                        icon="👁️" 
                        title="Observation" 
                        accent="purple"
                        desc={visualContext ? "Visual context synchronized from SCS." : "Waiting for agent eye-tracking..."}
                        meta={visualContext ? `MIME: image/png` : undefined}
                    />
                    <LogItem 
                        icon="⚡" 
                        title="Action" 
                        accent="blue"
                        desc={task?.current_step || "Processing..."} 
                        meta="Browser Vision Control"
                    />
                </div>
            </div>
        )}

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
        {/* Caret Down Icon */}
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

function LogItem({ icon, title, desc, meta, accent }: { icon: string, title: string, desc: string, meta?: string, accent: 'purple' | 'blue' }) {
    return (
        <div className="log-entry">
            <div className="log-line">
                <div className="log-icon-wrapper">{icon}</div>
            </div>
            <div className="log-content">
                <div className="log-header">
                    <span className={`log-title accent-${accent}`}>{title}</span>
                    <span className="log-status">Success</span>
                </div>
                <div className="log-desc">{desc}</div>
                {meta && <span className="log-meta">{meta}</span>}
            </div>
        </div>
    );
}