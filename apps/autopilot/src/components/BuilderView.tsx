// src/components/BuilderView.tsx
import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core"; // [NEW] Import invoke
import type { AgentConfiguration } from "../types";
import "./BuilderView.css";

// Icons
const BackIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>;
const RefreshIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path fillRule="evenodd" d="M20.719 4.696a1 1 0 0 0-1.415-1.415l-4.796 4.796-.634-.635a3.002 3.002 0 0 0-3.788-.375l-7.64 5.093a1 1 0 0 0-.153 1.541l8.005 8.005a1.002 1.002 0 0 0 1.541-.152l5.093-7.64a3.001 3.001 0 0 0-.375-3.789l-.634-.633 4.796-4.796Zm-9.523 4.037a1 1 0 0 1 1.263.124l2.682 2.684a1 1 0 0 1 .126 1.262l-.414.621-4.278-4.277.62-.414ZM8.877 10.28l-4.305 2.87 1.43 1.43 1.294-1.292a1 1 0 0 1 1.415 1.415l-1.294 1.294 3.433 3.432 2.871-4.306-4.844-4.843Z" clipRule="evenodd"></path></svg>;
const LogsIcon = () => <svg width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path fillRule="evenodd" d="M18 5a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1h-2V5h2Zm-4 0v14H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h8Zm7 1a3 3 0 0 0-3-3H6a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3V6Z" clipRule="evenodd"></path></svg>;
const FileIcon = () => <svg width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M13 12a1 1 0 1 0-2 0v4a1 1 0 1 0 2 0v-4Zm-1-2.5A1.25 1.25 0 1 0 12 7a1.25 1.25 0 0 0 0 2.5Z"></path><path fillRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2ZM4 12a8 8 0 1 1 16 0 8 8 0 0 1-16 0Z" clipRule="evenodd"></path></svg>;
const CodeIcon = () => <svg width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M13 12a1 1 0 1 0-2 0v4a1 1 0 1 0 2 0v-4Zm-1-2.5A1.25 1.25 0 1 0 12 7a1.25 1.25 0 0 0 0 2.5Z"></path><path fillRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2ZM4 12a8 8 0 1 1 16 0 8 8 0 0 1-16 0Z" clipRule="evenodd"></path></svg>;
const FunctionIcon = () => <svg width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path fillRule="evenodd" d="M12 5a1 1 0 0 1 1 1v5h5a1 1 0 1 1 0 2h-5v5a1 1 0 1 1-2 0v-5H6a1 1 0 1 1 0-2h5V6a1 1 0 0 1 1-1Z" clipRule="evenodd"></path></svg>;
const ChevronDownIcon = () => <svg width="1em" height="1em" viewBox="0 0 10 16" fill="currentColor"><path fillRule="evenodd" clipRule="evenodd" d="M4.34151 0.747423C4.71854 0.417526 5.28149 0.417526 5.65852 0.747423L9.65852 4.24742C10.0742 4.61111 10.1163 5.24287 9.75259 5.6585C9.38891 6.07414 8.75715 6.11626 8.34151 5.75258L5.00001 2.82877L1.65852 5.75258C1.24288 6.11626 0.61112 6.07414 0.247438 5.6585C-0.116244 5.24287 -0.0741267 4.61111 0.34151 4.24742L4.34151 0.747423ZM0.246065 10.3578C0.608879 9.94139 1.24055 9.89795 1.65695 10.2608L5.00001 13.1737L8.34308 10.2608C8.75948 9.89795 9.39115 9.94139 9.75396 10.3578C10.1168 10.7742 10.0733 11.4058 9.65695 11.7687L5.65695 15.2539C5.28043 15.582 4.7196 15.582 4.34308 15.2539L0.343082 11.7687C-0.0733128 11.4058 -0.116749 10.7742 0.246065 10.3578Z"></path></svg>;
const GenerateIcon = () => <svg width="1em" height="1em" viewBox="0 0 24 24" fill="currentColor"><path d="M5.5 2a.5.5 0 0 1 .49.402c.137.683.404 1.266.814 1.708.406.437.977.763 1.778.897a.5.5 0 0 1 0 .986c-.8.134-1.372.46-1.778.897-.41.442-.677 1.025-.814 1.708a.5.5 0 0 1-.98 0c-.137-.683-.404-1.266-.814-1.708-.406-.437-.977-.763-1.778-.897a.5.5 0 0 1 0-.986c.8-.134 1.372-.46 1.778-.897.41-.442.677-1.025.814-1.708A.5.5 0 0 1 5.5 2Z"></path></svg>;
const AttachIcon = () => <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path fillRule="evenodd" d="M12 7a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v4a1 1 0 1 1-2 0V8h-3a1 1 0 0 1-1-1Zm-5 5a1 1 0 0 1 1 1v3h3a1 1 0 1 1 0 2H7a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1Z" clipRule="evenodd"></path></svg>;
const PlusIcon = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 5v14M5 12h14"/></svg>;

interface BuilderViewProps {
  onAddToGraph: (config: AgentConfiguration) => void;
  onBack: () => void;
}

interface ChatMsg {
  role: 'agent' | 'user';
  text: string;
}

interface LogEntry {
  ts: string;
  level: string;
  msg: string;
}

// [NEW] Execution Result Type
interface ExecutionResult {
  status: string;
  output: string;
  metrics?: { latency_ms?: number };
}

const DEFAULT_INSTRUCTIONS = `You are an intelligent assistant designed to answer questions about internal documentation and execute safe tools.

Use the retrieval_context to find information before answering.
If the user asks for actions outside your scope, politely decline.`;

export function BuilderView({ onAddToGraph, onBack }: BuilderViewProps) {
  // Config State
  const [name, setName] = useState("New Agent");
  const [instructions, setInstructions] = useState(DEFAULT_INSTRUCTIONS);
  const [model, setModel] = useState("gpt-4o");
  
  // Tools Toggles
  const [tools, setTools] = useState({
    fileSearch: false,
    codeInterpreter: false,
    functions: false
  });

  // Chat State
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  // Logs State
  const [showLogs, setShowLogs] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const addLog = (msg: string, level = "info") => {
    const now = new Date();
    const ts = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`;
    setLogs(prev => [...prev, { ts, level, msg }]);
  };

  // [UPDATED] Real Execution Handler
  const handleSend = async () => {
    if (!input.trim()) return;
    const userMsg = input;
    
    // 1. Update UI
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setInput("");
    setIsTyping(true);
    
    addLog(`User input: "${userMsg}"`, "info");
    addLog(`Invoking model: ${model}`, "system");

    // 2. Construct Ephemeral Config
    const configPayload = {
        model: model,
        temperature: 0.7,
        systemPrompt: instructions,
        // In a real app, enabled tools would be mapped to the `tools` array here
        tools: Object.keys(tools).filter(k => tools[k as keyof typeof tools])
    };

    try {
        // 3. Invoke Kernel
        const result = await invoke<ExecutionResult>("test_node_execution", {
            nodeType: "model",
            config: configPayload,
            input: JSON.stringify({ input: userMsg }), // Pass input as JSON context
            nodeId: "builder-preview", // Arbitrary ID for logs
            session_id: null
        });

        setIsTyping(false);

        if (result.status === "success") {
            setMessages(prev => [...prev, { role: 'agent', text: result.output }]);
            addLog(`Response generated (${result.metrics?.latency_ms || 0}ms)`, "info");
        } else {
            setMessages(prev => [...prev, { role: 'agent', text: `Error: ${result.output}` }]);
            addLog(`Execution failed: ${result.output}`, "error");
        }

    } catch (e) {
        setIsTyping(false);
        setMessages(prev => [...prev, { role: 'agent', text: `System Error: ${e}` }]);
        addLog(`IPC Error: ${e}`, "error");
    }
  };

  const toggleTool = (key: keyof typeof tools) => {
    setTools(prev => ({ ...prev, [key]: !prev[key] }));
    addLog(`${key} ${!tools[key] ? 'enabled' : 'disabled'}`, "system");
  };

  const handleAdd = () => {
    const config: AgentConfiguration = {
      name,
      description: "Generated by Builder",
      instructions,
      model,
      temperature: 0.7,
      tools: [] 
    };
    onAddToGraph(config);
  };

  const handleClear = () => {
    setMessages([]);
    setLogs([]);
    addLog("Session cleared", "system");
  };

  useEffect(() => {
    if (chatScrollRef.current) {
        chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  return (
    <div className="builder-view">
      
      {/* LEFT PANEL: CONFIGURATION */}
      <div className="builder-config">
        <div className="config-container">
          
          <div className="input-group" style={{marginBottom: 20}}>
             <button className="btn-ghost" onClick={onBack} style={{paddingLeft: 0, justifyContent: 'flex-start', color: '#E5E7EB'}}>
                <BackIcon /> <span style={{marginLeft: 8}}>Back to Agents</span>
             </button>
          </div>

          {/* Name */}
          <div className="input-group">
            <div className="field-label">Name</div>
            <input 
              className="text-input" 
              placeholder="Enter a user friendly name" 
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {/* Instructions */}
          <div className="input-group">
            <div className="field-label">
              <span>System instructions</span>
              <button className="btn-ghost">
                <GenerateIcon /> Generate
              </button>
            </div>
            <textarea 
              className="text-input textarea-input"
              placeholder="You are a helpful assistant..."
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
            />
          </div>

          {/* Model */}
          <div className="input-group">
            <div className="field-label">Model</div>
            <div className="model-selector">
              <span className="model-name">{model}</span>
              <ChevronDownIcon />
            </div>
          </div>

          {/* Tools */}
          <div className="input-group">
            <div className="field-label">Tools</div>
            <div className="tools-section">
              <div className="tool-row">
                <div className="tool-info">
                  <div className="tool-icon"><FileIcon /></div>
                  <span>File Search</span>
                </div>
                <button 
                  className="switch" 
                  aria-checked={tools.fileSearch}
                  onClick={() => toggleTool('fileSearch')}
                >
                  <span className="switch-thumb" />
                </button>
              </div>

              <div className="tool-row">
                <div className="tool-info">
                  <div className="tool-icon"><CodeIcon /></div>
                  <span>Code interpreter</span>
                </div>
                <button 
                  className="switch" 
                  aria-checked={tools.codeInterpreter}
                  onClick={() => toggleTool('codeInterpreter')}
                >
                  <span className="switch-thumb" />
                </button>
              </div>

              <div className="tool-row">
                <div className="tool-info">
                  <div className="tool-icon"><FunctionIcon /></div>
                  <span>Functions</span>
                </div>
                <button className="btn-ghost" onClick={() => console.log("Add Function")}>
                  <FileIcon /> 
                  <span>+ Functions</span>
                </button>
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* RIGHT PANEL: PREVIEW / THREAD */}
      <div className="builder-preview">
        
        {/* Header */}
        <div className="playground-header">
          <div className="header-left">Thread</div>
          <div className="header-actions">
            <button className="icon-action-btn" title="Clear Thread" onClick={handleClear}>
              <RefreshIcon />
            </button>
            <button 
                className="icon-action-btn" 
                title="Add to Graph"
                onClick={handleAdd}
                style={{color: '#E5E7EB', borderColor: '#3F4652', gap: 6, width: 'auto', padding: '0 12px'}}
            >
                <PlusIcon />
                <span style={{fontSize: 12, fontWeight: 500}}>Add to Graph</span>
            </button>
            <button 
              className={`logs-btn ${showLogs ? 'active' : ''}`} 
              onClick={() => setShowLogs(!showLogs)}
            >
              <span>Logs</span>
              <LogsIcon />
            </button>
          </div>
        </div>

        {/* Chat Messages */}
        <div className="playground-chat" ref={chatScrollRef}>
          {messages.length === 0 ? (
            <div className="playground-empty">
              <div style={{color: '#6B7280', fontSize: 14}}>Playground session</div>
            </div>
          ) : (
            messages.map((msg, i) => (
              <div key={i} className="message-row">
                <div className={`message-avatar ${msg.role === 'agent' ? 'agent' : 'user'}`}>
                  {msg.role === 'agent' ? 'AI' : 'U'}
                </div>
                <div className="message-content">
                  {msg.text}
                </div>
              </div>
            ))
          )}
          {isTyping && (
             <div className="message-row">
                <div className="message-avatar agent">AI</div>
                <div className="spot-thinking" style={{paddingTop: 8}}>
                    <span className="spot-thinking-dot"></span>
                    <span className="spot-thinking-dot"></span>
                    <span className="spot-thinking-dot"></span>
                </div>
             </div>
          )}
        </div>

        {/* Logs Panel (Overlay/Collapsible) */}
        {showLogs && (
            <div className="logs-panel">
                <div className="logs-header">
                    <span>Trace</span>
                    <span style={{fontSize: 10, color: '#5F6B7C'}}>LIVE</span>
                </div>
                <div className="logs-content">
                    {logs.length === 0 && <span style={{fontStyle:'italic', opacity:0.5}}>Waiting for activity...</span>}
                    {logs.map((log, i) => (
                        <div key={i} className="log-entry">
                            <span className="log-ts">{log.ts}</span>
                            <span className={`log-msg ${log.level}`}>{log.msg}</span>
                        </div>
                    ))}
                </div>
            </div>
        )}

        {/* Input Area */}
        <div className="playground-input-container">
          <div className="input-wrapper">
            <textarea 
              className="chat-textarea"
              placeholder="Enter your message..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                }
              }}
            />
            <div className="input-footer">
              <button className="attach-btn" title="Attach file">
                <AttachIcon />
              </button>
              <button 
                className="run-btn"
                onClick={handleSend}
                disabled={!input.trim() || isTyping}
              >
                <span>Run</span>
                <div className="kbd-shortcut">
                  <span className="kbd-key">↵</span>
                </div>
              </button>
            </div>
          </div>
          <div className="helper-text">
            Playground executes on the local runtime via the Kernel.
          </div>
        </div>

      </div>

    </div>
  );
}