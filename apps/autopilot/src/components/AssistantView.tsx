import React, { useState, useEffect, useRef } from "react";
import { useAgentStore } from "../store/agentStore";
import { SwarmViz } from "./SwarmViz";
import type { SwarmAgent } from "../types";
import "./AssistantView.css";

// Icons
const SidebarIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M9 3v18" /></svg>;
const SendIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>;
const CubeIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>;
const GlobeIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>;
const AppsIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /></svg>;
const BotIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/></svg>;
const MailIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>;
const DollarIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>;

interface AssistantViewProps {
  onToggleSidebar: () => void; // Triggered when user clicks the sidebar icon
}

export function AssistantView({ onToggleSidebar }: AssistantViewProps) {
  const [intent, setIntent] = useState("");
  const [chatHistory, setChatHistory] = useState<{role: string, text: string}[]>([]);
  const [swarmState, setSwarmState] = useState<SwarmAgent[]>([]);
  
  // Footer Selection State
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [agentMode, setAgentMode] = useState("Agent");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");

  const inputRef = useRef<HTMLInputElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  
  const { startTask, task } = useAgentStore();

  const showPreview = (task?.phase === "Running" || swarmState.length > 0);

  useEffect(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
    }
  }, [chatHistory]);

  // Global click to close dropdowns
  useEffect(() => {
    const handleClick = () => setActiveDropdown(null);
    window.addEventListener("click", handleClick);
    return () => window.removeEventListener("click", handleClick);
  }, []);

  const handleSubmit = async (textOverride?: string) => {
    const text = textOverride || intent;
    if (!text.trim()) return;

    setChatHistory(prev => [...prev, { role: 'user', text }]);
    setIntent("");
    
    if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) {
       setAgentMode("Swarm");
       initializeMockSwarm();
    } else {
       await startTask(text);
    }
  };

  const initializeMockSwarm = () => {
      setSwarmState([
        { id: "root", parentId: null, name: "Manager", role: "Planner", status: "running", budget_used: 0.05, budget_cap: 1.00, policy_hash: "0x123", artifacts_produced: 0 },
        { id: "w1", parentId: "root", name: "Researcher", role: "Browser", status: "requisition", budget_used: 0, budget_cap: 0.2, estimated_cost: 0.15, policy_hash: "0x456", artifacts_produced: 0 },
      ]);
  };

  const handleApprove = (id: string) => {
      setSwarmState(prev => prev.map(a => a.id === id ? { ...a, status: 'running' } : a));
      setChatHistory(prev => [...prev, { role: 'agent', text: "✅ Agent authorized and starting..." }]);
  };

  const handleReject = (id: string) => {
      setSwarmState(prev => prev.filter(a => a.id !== id));
      setChatHistory(prev => [...prev, { role: 'agent', text: "❌ Authorization denied." }]);
  };

  return (
    <div className={`assistant-view ${showPreview ? 'has-preview' : ''}`}>
      <div className="assistant-container">
        
        {/* LEFT PANE */}
        <div className="av-left-pane">
            <div className="av-header">
              <div className="av-brand">
                 <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7L12 12L22 7L12 2Z" fill="currentColor" fillOpacity="0.5" stroke="currentColor" strokeWidth="2"/><path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2"/><path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2"/></svg>
                 <span>Autopilot Assistant</span>
              </div>
              <div className="av-actions">
                {/* BUTTON: Pop out to Sidebar (Spotlight) */}
                <button className="av-btn" onClick={onToggleSidebar} title="Open Floating Sidebar">
                  <SidebarIcon />
                </button>
              </div>
            </div>

            <div className="av-chat-area" ref={chatAreaRef}>
              {chatHistory.length === 0 && !task && (
                 <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div className="suggestions-grid">
                      <SuggestionCard icon={<MailIcon />} label="Summarize Inbox" desc="Read unread emails" onClick={() => handleSubmit("Summarize Inbox")} />
                      <SuggestionCard icon={<DollarIcon />} label="Analyze Spend" desc="Scan PDF invoices" onClick={() => handleSubmit("Analyze invoices")} />
                    </div>
                 </div>
              )}
              
              {chatHistory.map((msg, i) => (
                <div key={i} className={`av-msg ${msg.role}`}>
                  {msg.text}
                </div>
              ))}
              
              {task && task.phase === "Running" && (
                  <div className="av-embedded-pill">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <div className="av-pill-spinner" />
                          <div style={{ fontSize: 13, fontWeight: 600, color: '#E5E7EB' }}>
                             {task.current_step}
                          </div>
                      </div>
                      <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#6B7280' }}>
                         {task.progress}/{task.total_steps}
                      </div>
                  </div>
              )}
            </div>

            <div className="av-input-section">
                <div className="av-input-wrapper">
                    <input
                        ref={inputRef}
                        className="av-input"
                        placeholder="Describe your intent..."
                        value={intent}
                        onChange={(e) => setIntent(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                    />
                    <button className="av-send-btn" onClick={() => handleSubmit()}>
                        <SendIcon />
                    </button>
                </div>

                <div className="av-stack-footer">
                    <Dropdown 
                        id="mode" label={agentMode} icon={<BotIcon />} 
                        options={["Chat", "Agent", "Swarm"]} 
                        activeId={activeDropdown} onToggle={setActiveDropdown} onSelect={setAgentMode}
                    />
                    <Dropdown 
                        id="model" label={selectedModel} icon={<CubeIcon />} 
                        options={["GPT-4o", "Claude 3.5", "Llama 3"]} 
                        activeId={activeDropdown} onToggle={setActiveDropdown} onSelect={setSelectedModel}
                    />
                    <Dropdown 
                        id="net" label={networkMode} icon={<GlobeIcon />} 
                        options={["Net", "Local Only"]} 
                        activeId={activeDropdown} onToggle={setActiveDropdown} onSelect={setNetworkMode}
                    />
                    <Dropdown 
                        id="app" label={connectedApp} icon={<AppsIcon />} 
                        options={["Apps", "Github", "Slack"]} 
                        activeId={activeDropdown} onToggle={setActiveDropdown} onSelect={setConnectedApp}
                    />
                </div>
            </div>
        </div>

        {/* RIGHT PANE (Swarm Viz) */}
        {showPreview && (
            <div className="av-right-pane">
                <SwarmViz 
                    agents={swarmState}
                    onApproveAgent={handleApprove}
                    onRejectAgent={handleReject}
                />
            </div>
        )}

      </div>
    </div>
  );
}

// Helpers
function SuggestionCard({ icon, label, desc, onClick }: { icon: React.ReactNode, label: string, desc: string, onClick: () => void }) {
  return (
    <div className="suggestion-card" onClick={onClick}>
       <div className="sugg-icon">{icon}</div>
       <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="sugg-label">{label}</div>
          <div className="sugg-desc">{desc}</div>
       </div>
    </div>
  );
}

function Dropdown({ id, label, icon, options, activeId, onToggle, onSelect }: any) {
  const isOpen = activeId === id;
  return (
    <div style={{ position: 'relative' }}>
      <div 
        className={`dd-trigger ${isOpen ? 'open' : ''}`}
        onClick={(e) => { e.stopPropagation(); onToggle(isOpen ? null : id); }}
      >
        {icon} <span>{label}</span>
      </div>
      {isOpen && (
        <div className="dd-menu" onClick={e => e.stopPropagation()}>
          {options.map((opt: string) => (
            <div key={opt} className={`dd-item ${label === opt ? 'selected' : ''}`} onClick={() => { onSelect(opt); onToggle(null); }}>
              {opt} {label === opt && "✓"}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}