import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAgentStore } from "../../../store/agentStore";
import { SwarmViz } from "../../../components/SwarmViz";
import { SwarmAgent } from "../../../types";
import { 
  BotIcon, MessageIcon, SwarmIcon, CubeIcon, 
  GlobeIcon, AppsIcon, PlusIcon, SidebarIcon, SearchIcon 
} from "./SharedUI"; 
import { StudioDropdown } from "./SharedUI";

export function StudioCopilotView() {
  const [chatHistory, setChatHistory] = useState<{role: string; text: string}[]>([]);
  const [intent, setIntent] = useState("");
  const [swarmState, setSwarmState] = useState<SwarmAgent[]>([]);
  
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [agentMode, setAgentMode] = useState("Swarm");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");

  const { startTask } = useAgentStore();
  const inputRef = useRef<HTMLInputElement>(null);

  const showSwarmPanel = agentMode === "Swarm";

  useEffect(() => {
    setSwarmState([
      { 
        id: "root", parentId: null, name: "Manager", role: "Planner", status: "running", 
        budget_used: 0.05, budget_cap: 1.00, policy_hash: "0xab42def8", 
        current_thought: "Initializing Studio Swarm Context...", artifacts_produced: 0 
      },
      { 
        id: "w1", parentId: "root", name: "Research-1", role: "Researcher", status: "requisition", 
        budget_used: 0.00, budget_cap: 0.20, policy_hash: "0xcd99fa12", 
        estimated_cost: 0.15, artifacts_produced: 0 
      },
    ]);
    setChatHistory([{ role: 'agent', text: "Swarm Orchestrator initialized. Pending requisitions detected." }]);
  }, []);

  const handleSubmit = async () => {
    if (!intent.trim()) return;
    setChatHistory(prev => [...prev, { role: 'user', text: intent }]);
    setIntent("");
    
    if (intent.toLowerCase().includes("swarm") && agentMode !== "Swarm") {
      setAgentMode("Swarm");
    }
    
    await startTask(intent, agentMode);
  };

  const handleApprove = (id: string) => {
    setSwarmState(prev => prev.map(a => a.id === id ? { ...a, status: 'running' } : a));
    setChatHistory(prev => [...prev, { role: 'agent', text: `✅ Agent authorized.` }]);
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
      <ChatHistorySidebar />

      <div className={`copilot-chat ${!showSwarmPanel ? 'expanded' : ''}`}>
        <div className="copilot-chat-header">
          <BotIcon />
          {agentMode} Mode
        </div>
        
        <div className={`copilot-messages ${!showSwarmPanel ? 'centered' : ''}`}>
          {chatHistory.map((msg, i) => (
            <div key={i} className={`chat-msg ${msg.role}`}>
              {msg.text}
            </div>
          ))}
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
          <SwarmViz
            agents={swarmState}
            onApproveAgent={handleApprove}
            onRejectAgent={(id: string) => setSwarmState(p => p.filter(a => a.id !== id))}
          />
        </div>
      )}
    </div>
  );
}

function ChatHistorySidebar() {
  const historyItems = [
    { id: 1, title: "Invoice Analysis", time: "2m ago" },
    { id: 2, title: "DeFi Research", time: "1h ago" },
    { id: 3, title: "Email Summary", time: "Yesterday" },
  ];

  const dockOut = async () => {
    await invoke("show_spotlight");
    await invoke("hide_studio");
  };

  return (
    <div className="copilot-sidebar">
      <div className="copilot-sidebar-header">
        <button className="copilot-new-btn">
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
        {historyItems.map(item => (
          <div key={item.id} className="copilot-history-item">
            <div className="copilot-history-title">{item.title}</div>
            <div className="copilot-history-time">{item.time}</div>
          </div>
        ))}
      </div>
    </div>
  );
}