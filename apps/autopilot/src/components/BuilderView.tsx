import { useState } from "react";
import type { AgentConfiguration } from "../types";
import "./BuilderView.css";

// =========================================
// TYPES
// =========================================

interface BuilderViewProps {
  // Callback now accepts the configuration payload
  onSwitchToCompose: (config: AgentConfiguration) => void;
}

interface ChatMsg {
  role: 'agent' | 'user';
  text: string;
}

// =========================================
// ICONS
// =========================================

const RobotIcon = () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="10" rx="2" /><circle cx="12" cy="5" r="2" /><path d="M12 7v4" /><line x1="8" y1="16" x2="8" y2="16" /><line x1="16" y1="16" x2="16" y2="16" /></svg>;
const SettingsIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>;
const TrashIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /></svg>;
const SendIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>;

// =========================================
// CONSTANTS
// =========================================

const DEFAULT_INSTRUCTIONS = `You are an intelligent assistant designed to answer questions about internal documentation and execute safe tools.

Use the retrieval_context to find information before answering.
If the user asks for actions outside your scope, politely decline.`;

// =========================================
// COMPONENT
// =========================================

export function BuilderView({ onSwitchToCompose }: BuilderViewProps) {
  // --- Config State ---
  const [name, setName] = useState("New Agent");
  const [desc, setDesc] = useState("");
  const [instructions, setInstructions] = useState(DEFAULT_INSTRUCTIONS);
  const [temperature, setTemperature] = useState(0.5);
  const [tools, setTools] = useState([
    { id: 't1', name: 'Knowledge Retrieval', desc: 'Search internal docs', icon: '📚' },
    { id: 't2', name: 'Web Browser', desc: 'Read external pages', icon: '🌐' }
  ]);

  // --- Preview Chat State ---
  const [messages, setMessages] = useState<ChatMsg[]>([
    { role: 'agent', text: 'Hello! I am your new agent. Configure me on the left, and test me here.' }
  ]);
  const [input, setInput] = useState("");

  // --- Handlers ---

  const handleSend = () => {
    if (!input.trim()) return;
    setMessages(prev => [...prev, { role: 'user', text: input }]);
    const currentInput = input;
    setInput("");
    
    // Simulate Agent Thinking based on current instructions
    setTimeout(() => {
      setMessages(prev => [...prev, { 
        role: 'agent', 
        text: `[Simulated Response]\nI have received your message: "${currentInput}".\n\nI am configured with ${tools.length} tools and my temperature is set to ${temperature}.\n\nBased on my instructions, I should: ${instructions.slice(0, 40)}...` 
      }]);
    }, 800);
  };

  const handleSwitchToCompose = () => {
    // Package current state into a configuration object
    const config: AgentConfiguration = {
      name,
      description: desc,
      instructions,
      model: "GPT-4o", // In a real app, bind this to the model selector
      temperature,
      tools
    };
    
    // Hand off to StudioWindow to generate nodes
    onSwitchToCompose(config);
  };

  return (
    <div className="builder-view">
      
      {/* LEFT: CONFIGURATION RAIL */}
      <div className="builder-config">
        
        {/* 1. Identity */}
        <div className="config-header">
          <div className="config-title-row">
            <div className="agent-avatar-upload" title="Upload Avatar">
              <RobotIcon />
            </div>
            <div style={{ flex: 1 }}>
              <input 
                className="config-name-input" 
                value={name} 
                onChange={e => setName(e.target.value)} 
                placeholder="Agent Name"
              />
              <input 
                className="config-desc-input" 
                value={desc} 
                onChange={e => setDesc(e.target.value)} 
                placeholder="Add a description..."
              />
            </div>
          </div>
        </div>

        {/* 2. Model & Params */}
        <div className="config-section">
          <div className="section-label">
            <span>Model Configuration</span>
            <div className="section-actions"><button className="icon-btn"><SettingsIcon /></button></div>
          </div>
          
          <div className="model-card">
            <div className="model-row">
              <span className="model-name">✨ GPT-4o</span>
              <span style={{ fontSize: 10, color: '#3D85C6', background: 'rgba(61, 133, 198, 0.1)', padding: '2px 6px', borderRadius: 4 }}>Fast</span>
            </div>
            
            <div className="temp-control">
              <div className="temp-header">
                <span>Deterministic (0.0)</span>
                <span>Creative (1.0)</span>
              </div>
              <input 
                type="range" 
                min="0" max="1" step="0.1" 
                value={temperature} 
                onChange={e => setTemperature(parseFloat(e.target.value))}
                className="temp-slider"
              />
              <div style={{ textAlign: 'center', fontSize: 10, color: '#E5E7EB', marginTop: 4 }}>
                {temperature.toFixed(1)}
              </div>
            </div>
          </div>
        </div>

        {/* 3. System Instructions */}
        <div className="config-section" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <div className="section-label">
            <span>Instructions</span>
          </div>
          <textarea 
            className="instructions-editor"
            value={instructions}
            onChange={e => setInstructions(e.target.value)}
            placeholder="How should this agent behave?"
          />
          <div className="instructions-hint">
            Type <code>/</code> to reference tools or state
          </div>
        </div>

        {/* 4. Tools / Capabilities */}
        <div className="config-section">
          <div className="section-label">
            <span>Tools & Context</span>
            <span>{tools.length} Enabled</span>
          </div>
          
          {tools.map(tool => (
            <div key={tool.id} className="tool-item">
              <span className="tool-icon">{tool.icon}</span>
              <div className="tool-info">
                <span className="tool-name">{tool.name}</span>
                <span className="tool-desc">{tool.desc}</span>
              </div>
              <button 
                className="icon-btn" 
                onClick={() => setTools(tools.filter(t => t.id !== tool.id))}
                title="Remove Tool"
              >
                <TrashIcon />
              </button>
            </div>
          ))}
          
          <button className="add-tool-btn" onClick={() => console.log("Open Tool Picker")}>
            + Add Tool or Datasource
          </button>
        </div>

      </div>

      {/* RIGHT: LIVE PREVIEW */}
      <div className="builder-preview">
        <div className="preview-header">
          <div className="preview-title">
            <span>Preview</span>
            <span className="live-badge">LIVE</span>
          </div>
          <div className="preview-actions">
            <button className="action-btn secondary" onClick={handleSwitchToCompose}>
              Advanced Mode
            </button>
            <button className="action-btn primary" onClick={() => console.log("Publish")}>
              Publish Agent
            </button>
          </div>
        </div>

        <div className="preview-chat">
          {messages.length === 0 ? (
            <div className="empty-preview">
              <RobotIcon />
              <span>Test your agent here</span>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={`chat-msg ${m.role}`}>
                {m.text}
              </div>
            ))
          )}
        </div>

        <div className="preview-input-area">
          <div className="preview-input-wrapper">
            <input 
              className="preview-input" 
              placeholder="Message your agent..." 
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSend()}
            />
            <button className="send-btn" onClick={handleSend}><SendIcon /></button>
          </div>
        </div>
      </div>

    </div>
  );
}
