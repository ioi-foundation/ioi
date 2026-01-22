import { useState, useCallback, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { initEventListeners, useAgentStore } from "../store/agentStore";

// Import Shared Types from the central types file
import { Node, Edge, SwarmAgent } from "../types";

// Import components
import { ActivityBar } from "../components/ActivityBar";
import { IDEHeader, InterfaceMode } from "../components/IDEHeader";
import { ExplorerPanel } from "../components/ExplorerPanel";
import { Canvas } from "../components/Canvas";
import { RightPanel } from "../components/RightPanel";
import { DataPanel } from "../components/DataPanel";
import { CommandPalette } from "../components/CommandPalette";
import { BuilderView } from "../components/BuilderView";
import { StatusBar } from "../components/StatusBar";
import { MarketplaceView } from "../components/MarketplaceView";
import { AgentInstallModal } from "../components/AgentInstallModal";
import { VisionHUD } from "../components/VisionHUD";
import { SwarmViz } from "../components/SwarmViz"; 
import { FleetView } from "../components/FleetView";

// Import CSS
import "../components/ActivityBar.css";
import "../components/IDEHeader.css";
import "../components/ExplorerPanel.css";
import "../components/Canvas.css";
import "../components/CanvasNode.css";
import "../components/CanvasEdge.css";
import "../components/RightPanel.css";
import "../components/DataPanel.css";
import "../components/CommandPalette.css";
import "../components/BuilderView.css";
import "../components/StatusBar.css";
import "../components/MarketplaceView.css";
import "../components/AgentInstallModal.css";
import "../components/VisionHUD.css";
import "../components/FleetView.css";
import "./StudioWindow.css";

// =========================================
// ICONS — Minimal, 14x14, stroke 2
// =========================================

const CubeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
    <path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/>
  </svg>
);

const GlobeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/>
    <line x1="2" y1="12" x2="22" y2="12"/>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
);

const AppsIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="3" width="7" height="7" rx="2" />
    <rect x="14" y="3" width="7" height="7" rx="2" />
    <rect x="14" y="14" width="7" height="7" rx="2" />
    <rect x="3" y="14" width="7" height="7" rx="2" />
  </svg>
);

const MessageIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
  </svg>
);

const BotIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="10" rx="2"/>
    <circle cx="12" cy="5" r="2"/>
    <path d="M12 7v4"/>
    <circle cx="8" cy="16" r="1" fill="currentColor"/>
    <circle cx="16" cy="16" r="1" fill="currentColor"/>
  </svg>
);

const SwarmIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
    <circle cx="12" cy="12" r="2.5"/>
    <circle cx="6" cy="6" r="2"/>
    <circle cx="18" cy="6" r="2"/>
    <circle cx="6" cy="18" r="2"/>
    <circle cx="18" cy="18" r="2"/>
    <path d="M12 9.5V7M12 14.5V17M9.5 12H7M14.5 12H17M9.88 9.88L7.5 7.5M14.12 9.88L16.5 7.5M9.88 14.12L7.5 16.5M14.12 14.12L16.5 16.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
  </svg>
);

const SidebarIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <path d="M9 3v18" />
  </svg>
);

const PlusIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

const SearchIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8"/>
    <path d="m21 21-4.3-4.3"/>
  </svg>
);

const ChevronIcon = () => (
  <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
    <path d="M6 9l6 6 6-6"/>
  </svg>
);

// =========================================
// SAMPLE PIPELINE DATA
// =========================================

const initialNodes: Node[] = [
  { id: "n-1", type: "trigger", name: "Cron Trigger", x: 100, y: 150, status: "success", outputs: ["out"], ioTypes: {in: "—", out: "Signal"} },
  { id: "n-2", type: "action", name: "Read Invoices", x: 400, y: 150, status: "success", inputs: ["in"], outputs: ["out"], ioTypes: {in: "Signal", out: "PDF[]"} },
  { id: "n-3", type: "action", name: "Parse + Classify", x: 700, y: 150, status: "idle", inputs: ["in"], outputs: ["out"], ioTypes: {in: "PDF[]", out: "Invoice[]"}, metrics: { records: 300, time: "1.2s" } },
  { id: "n-4", type: "gate", name: "Policy Gate", x: 1000, y: 150, status: "idle", inputs: ["in"], outputs: ["out"], ioTypes: {in: "Invoice[]", out: "Invoice[]"} },
  { id: "n-5", type: "receipt", name: "Receipt Logger", x: 1300, y: 150, status: "idle", inputs: ["in"], ioTypes: {in: "Invoice[]", out: "Log"} },
];

const initialEdges: Edge[] = [
  { id: "e-1", from: "n-1", to: "n-2", fromPort: "out", toPort: "in", type: "control", active: false },
  { id: "e-2", from: "n-2", to: "n-3", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-3", from: "n-3", to: "n-4", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-4", from: "n-4", to: "n-5", fromPort: "out", toPort: "in", type: "control", active: false },
];

// =========================================
// MAIN STUDIO WINDOW COMPONENT
// =========================================

export function StudioWindow() {
  const [interfaceMode, setInterfaceMode] = useState<InterfaceMode>("COMPOSE");
  const [activeView, setActiveView] = useState("compose");

  const [nodes, setNodes] = useState<Node[]>(initialNodes);
  const [edges, setEdges] = useState<Edge[]>(initialEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Layout State
  const [explorerWidth] = useState(240);
  const [inspectorWidth] = useState(300);
  const [dataPanelHeight, setDataPanelHeight] = useState(300);
  const [dataPanelCollapsed, setDataPanelCollapsed] = useState(false);

  // Canvas State
  const [canvasTransform, setCanvasTransform] = useState({ x: 50, y: 50, scale: 1 });

  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  
  // Install Modal State
  const [installModalOpen, setInstallModalOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<any>(null);

  const { startTask, task } = useAgentStore();

  useEffect(() => {
    initEventListeners();

    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      console.log("Studio received view request:", event.payload);
      setActiveView(event.payload);
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  // --- Live Simulation Logic Mapping ---
  useEffect(() => {
    if (!task) return;

    if (task.phase === "Running" && task.progress === 0) {
      setNodes(nds => nds.map(n => ({ ...n, status: "idle" })));
      setEdges(eds => eds.map(e => ({ ...e, active: false })));
    }

    let activeNodeId = "";
    if (task.current_step.includes("Parsing") || task.current_step.includes("Identifying")) {
      activeNodeId = "n-3";
    } else if (task.phase === "Gate") {
      activeNodeId = "n-4";
    } else if (task.current_step.includes("Executing") || task.current_step.includes("Verifying")) {
      activeNodeId = "n-5";
    }

    if (activeNodeId) {
      setNodes(prev => prev.map(n => {
        if (n.id === activeNodeId) return { ...n, status: task.phase === "Gate" ? "running" : "running" }; 
        if (n.id < activeNodeId) return { ...n, status: "success" };
        return n;
      }));

      setEdges(prev => prev.map(e => {
        if (e.to === activeNodeId) return { ...e, active: true };
        if (e.to < activeNodeId) return { ...e, active: false };
        return e;
      }));
    }

    if (task.phase === "Complete") {
      setNodes(prev => prev.map(n => ({ ...n, status: "success" })));
      setEdges(prev => prev.map(e => ({ ...e, active: false })));
    }
  }, [task]);

  // --- Ghost Mode Logic ---
  useEffect(() => {
    if (interfaceMode === "GHOST") {
      const timer = setTimeout(() => {
        const ghostNode: Node = {
          id: "n-ghost", type: "action", name: "Verify Stripe", x: 1000, y: 350,
          status: "idle", ioTypes: { in: "Invoice", out: "Bool" }, isGhost: true
        };
        setNodes(prev => { if (prev.find(n => n.id === "n-ghost")) return prev; return [...prev, ghostNode]; });
        
        const ghostEdge: Edge = {
          id: "e-ghost", from: "n-3", to: "n-ghost", fromPort: "out", toPort: "in", type: "data", active: true
        };
        setEdges(prev => { if (prev.find(e => e.id === "e-ghost")) return prev; return [...prev, ghostEdge]; });
      }, 1500);
      return () => clearTimeout(timer);
    } else {
      setNodes(prev => prev.filter(n => !n.isGhost));
      setEdges(prev => prev.filter(e => e.id !== "e-ghost"));
    }
  }, [interfaceMode]);

  const handleNodeSelect = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  const handleNodeMove = useCallback((nodeId: string, x: number, y: number) => {
    setNodes((prev) => prev.map((n) => (n.id === nodeId ? { ...n, x, y } : n)));
  }, []);

  const handleCanvasDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    try {
      const data = e.dataTransfer.getData("application/json");
      if (!data) return;
      const item = JSON.parse(data);
      
      const rect = e.currentTarget.getBoundingClientRect();
      const dropX = (e.clientX - rect.left - canvasTransform.x) / canvasTransform.scale;
      const dropY = (e.clientY - rect.top - canvasTransform.y) / canvasTransform.scale;

      const newNode: Node = {
        id: `n-${Date.now()}`, type: item.type, name: item.name, x: dropX - 110, y: dropY - 20,
        status: "idle", ioTypes: { in: "Any", out: "Any" }, inputs: ["in"], outputs: ["out"],
      };

      setNodes(prev => [...prev, newNode]);
      setSelectedNodeId(newNode.id);
    } catch (err) {
      console.error("Drop failed", err);
    }
  }, [canvasTransform]);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) ?? null;

  const handleRun = async () => {
    if (dataPanelCollapsed) setDataPanelCollapsed(false);
    setNodes(initialNodes);
    setEdges(initialEdges);
    await startTask("Manual Run: Invoice Guard Workflow");
  };

  const handleInstallAgent = (agent: any) => {
    setSelectedAgent(agent);
    setInstallModalOpen(true);
  };

  const handleZoomIn = () => setCanvasTransform(t => ({ ...t, scale: Math.min(2, t.scale * 1.2) }));
  const handleZoomOut = () => setCanvasTransform(t => ({ ...t, scale: Math.max(0.2, t.scale / 1.2) }));
  const handleFit = () => setCanvasTransform({ x: 50, y: 50, scale: 1 });

  return (
    <div className="studio-window">
      <ActivityBar 
        activeView={activeView} 
        onViewChange={setActiveView}
      />

      <div className="studio-main">
        {/* IDE Header: Hidden in Copilot/Marketplace/Fleet for immersion */}
        {activeView !== "marketplace" && activeView !== "copilot" && activeView !== "fleet" && (
          <IDEHeader
            projectPath="Personal"
            projectName={activeView === "agent-builder" ? "Agent Builder" : "Invoice Guard"}
            branch="main"
            mode={interfaceMode}
            onModeChange={setInterfaceMode}
            isComposeView={activeView === "compose"}
            onSave={() => console.log("Save")}
            onRun={handleRun}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onFit={handleFit}
          />
        )}

        <div className="studio-content">
          {activeView === "marketplace" ? (
            <MarketplaceView onInstallAgent={handleInstallAgent} />
          ) : activeView === "agent-builder" ? (
            <div className="studio-center-area">
              <BuilderView onSwitchToCompose={() => setActiveView("compose")} />
            </div>
          ) : activeView === "copilot" ? (
            <StudioCopilotView />
          ) : activeView === "fleet" ? (
            <FleetView />
          ) : (
            // Default: Composition / Graph View
            <>
              <ExplorerPanel width={explorerWidth} />
              <div className="studio-center-area">
                <div 
                  className="canvas-area"
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={handleCanvasDrop}
                >
                  <div className="canvas-container" style={{ bottom: dataPanelCollapsed ? 32 : dataPanelHeight }}>
                    {/* GHOST MODE */}
                    {interfaceMode === "GHOST" && (
                      <>
                        <div className="ghost-overlay">
                          <div className="ghost-badge">
                            <span className="ghost-dot" />
                            <span>Ghost Mode: Observing & Inferring...</span>
                          </div>
                        </div>
                        <VisionHUD />
                      </>
                    )}

                    <Canvas
                      nodes={nodes} edges={edges} selectedNodeId={selectedNodeId}
                      onNodeSelect={handleNodeSelect} onNodeMove={handleNodeMove}
                      transform={canvasTransform} onTransformChange={setCanvasTransform}
                    />
                  </div>
                  
                  <DataPanel
                    height={dataPanelHeight}
                    collapsed={dataPanelCollapsed}
                    onToggleCollapse={() => setDataPanelCollapsed(!dataPanelCollapsed)}
                    onResize={setDataPanelHeight}
                    selectedNodeName={selectedNode?.name}
                    isRunning={task?.phase === "Running" || task?.phase === "Gate"}
                  />
                </div>
              </div>
              <div className="studio-right-panel" style={{ width: inspectorWidth }}>
                {interfaceMode === "GHOST" ? (
                  <GhostChatPanel />
                ) : (
                  <RightPanel width={inspectorWidth} selectedNode={selectedNode} />
                )}
              </div>
            </>
          )}
        </div>
        
        <StatusBar 
          metrics={{ cost: 0.42, privacy: 0.15, risk: 0.6 }} 
          status={task ? task.phase : "Ready"} 
        />
      </div>

      {commandPaletteOpen && (
        <CommandPalette onClose={() => setCommandPaletteOpen(false)} />
      )}
      
      {installModalOpen && selectedAgent && (
        <AgentInstallModal 
          isOpen={installModalOpen}
          onClose={() => setInstallModalOpen(false)}
          agent={selectedAgent}
        />
      )}
    </div>
  );
}

// =========================================
// GHOST CHAT PANEL (Right Sidebar)
// =========================================

function GhostChatPanel() {
  return (
    <aside className="ghost-panel">
      <div className="ghost-panel-header">
        <h2 className="ghost-panel-title">
          <span className="ghost-panel-indicator" />
          Ghost Copilot
        </h2>
      </div>
      <div className="ghost-panel-messages">
        <div className="ghost-panel-msg">
          I'm watching your actions. Perform the manual task in the "Sandbox" browser, and I'll generate the graph nodes.
        </div>
      </div>
      <div className="ghost-panel-input">
        <input type="text" placeholder="Describe intent..." />
      </div>
    </aside>
  );
}

// =========================================
// STUDIO COPILOT VIEW — 3-Pane Layout
// =========================================

function StudioCopilotView() {
  const [chatHistory, setChatHistory] = useState<{role: string; text: string}[]>([]);
  const [intent, setIntent] = useState("");
  const [swarmState, setSwarmState] = useState<SwarmAgent[]>([]);
  
  // Dropdown State
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [agentMode, setAgentMode] = useState("Swarm");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [networkMode, setNetworkMode] = useState("Net");
  const [connectedApp, setConnectedApp] = useState("Apps");

  const { startTask } = useAgentStore();
  const inputRef = useRef<HTMLInputElement>(null);

  const showSwarmPanel = agentMode === "Swarm";

  // Auto-initialize swarm for demo
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
    
    await startTask(intent);
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
            onRejectAgent={(id) => setSwarmState(p => p.filter(a => a.id !== id))}
          />
        </div>
      )}
    </div>
  );
}

// =========================================
// CHAT HISTORY SIDEBAR
// =========================================

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

// =========================================
// DROPDOWN COMPONENT
// =========================================

interface StudioDropdownProps {
  icon: React.ReactNode;
  label: string;
  options: string[];
  selected?: string;
  onSelect?: (val: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  footer?: { label: string; onClick: () => void };
}

function StudioDropdown({ 
  icon, 
  label, 
  options, 
  selected, 
  onSelect, 
  isOpen, 
  onToggle, 
  footer 
}: StudioDropdownProps) {
  return (
    <div className="studio-dropdown">
      <button
        className={`studio-dropdown-trigger ${isOpen ? 'open' : ''}`}
        onClick={(e) => { e.stopPropagation(); onToggle(); }}
      >
        {icon}
        <span>{label}</span>
        <span className="chevron"><ChevronIcon /></span>
      </button>
      
      {isOpen && (
        <div className="studio-dropdown-menu">
          {options.map(opt => (
            <button
              key={opt}
              className={`studio-dropdown-item ${selected === opt ? 'selected' : ''}`}
              onClick={() => { if (onSelect) onSelect(opt); onToggle(); }}
            >
              {opt}
            </button>
          ))}
          {footer && (
            <>
              <div className="studio-dropdown-separator" />
              <button
                className="studio-dropdown-footer"
                onClick={(e) => { e.stopPropagation(); footer.onClick(); onToggle(); }}
              >
                {footer.label}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}