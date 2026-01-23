import { useState, useCallback, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { 
  ReactFlowProvider, 
  useReactFlow, 
  useNodesState, 
  useEdgesState, 
  addEdge,
  Connection,
  Edge as FlowEdge,
  Node as FlowNode
} from "@xyflow/react"; 
import "@xyflow/react/dist/style.css"; 

import { initEventListeners, useAgentStore } from "../store/agentStore";

// Import Shared Types from the central types file
import { Node as IOINode, Edge as IOIEdge, SwarmAgent, AgentConfiguration, NodeLogic, NodeLaw } from "../types";

// Import components
import { ActivityBar } from "../components/ActivityBar";
import { IDEHeader, InterfaceMode } from "../components/IDEHeader";
import { ExplorerPanel } from "../components/ExplorerPanel";
import { Canvas } from "../components/Canvas";
import { RightPanel } from "../components/RightPanel";
import { BottomDrawer, DrawerTab } from "../components/BottomDrawer"; // [UPDATED]
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
import "../components/BottomDrawer.css"; // [UPDATED]
import "../components/CommandPalette.css";
import "../components/BuilderView.css";
import "../components/StatusBar.css";
import "../components/MarketplaceView.css";
import "../components/AgentInstallModal.css";
import "../components/VisionHUD.css";
import "../components/FleetView.css";
import "./StudioWindow.css";

// =========================================
// TYPES
// =========================================

// Structure to store real execution results from the Kernel
interface NodeArtifact {
  output?: string;
  metrics?: any;
  timestamp: number;
}

interface NodeArtifacts {
  [nodeId: string]: NodeArtifact;
}

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
    <rect x="3" y="3" width="18" height="10" rx="2"/>
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

// Config objects initialized here to prevent "Amnesiac Editor" issues
const initialIOINodes: IOINode[] = [
  { 
    id: "n-1", type: "trigger", name: "Cron Trigger", x: 100, y: 150, status: "idle", 
    outputs: ["out"], ioTypes: {in: "—", out: "Signal"},
    config: { 
      logic: { cronSchedule: "*/5 * * * *" }, 
      law: {} 
    } 
  },
  { 
    id: "n-2", type: "action", name: "Read Invoices", x: 400, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "Signal", out: "PDF[]"},
    config: { 
      logic: { method: "GET", endpoint: "https://api.invoicing.com/v1/list" }, 
      law: { privacyLevel: "masked" } 
    }
  },
  { 
    id: "n-3", type: "model", name: "Parse + Classify", x: 700, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "PDF[]", out: "Invoice[]"}, 
    metrics: { records: 300, time: "1.2s" },
    config: { 
      logic: { model: "local-llm", temperature: 0.2, systemPrompt: "Extract vendor and total." }, 
      law: { budgetCap: 0.50 } 
    }
  },
  { 
    id: "n-4", type: "gate", name: "Policy Gate", x: 1000, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "Invoice[]", out: "Invoice[]"},
    config: { 
      logic: { conditionScript: "risk < 0.5" }, 
      law: { requireHumanGate: true } 
    }
  },
  { 
    id: "n-5", type: "receipt", name: "Receipt Logger", x: 1300, y: 150, status: "idle", 
    inputs: ["in"], ioTypes: {in: "Invoice[]", out: "Log"},
    config: { logic: {}, law: {} }
  },
];

const initialIOIEdges: IOIEdge[] = [
  { id: "e-1", from: "n-1", to: "n-2", fromPort: "out", toPort: "in", type: "control", active: false },
  { id: "e-2", from: "n-2", to: "n-3", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-3", from: "n-3", to: "n-4", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-4", from: "n-4", to: "n-5", fromPort: "out", toPort: "in", type: "control", active: false },
];

// Mapper: IOI Node -> ReactFlow Node
const toFlowNode = (n: IOINode): FlowNode => ({
  id: n.id,
  type: n.type,
  position: { x: n.x, y: n.y },
  data: { ...n }
});

// Mapper: IOI Edge -> ReactFlow Edge
const toFlowEdge = (e: IOIEdge): FlowEdge => ({
  id: e.id,
  source: e.from,
  target: e.to,
  sourceHandle: e.fromPort,
  targetHandle: e.toPort,
  animated: e.active,
  style: { stroke: e.active ? '#3D85C6' : '#2E333D', strokeWidth: 2 },
});

// =========================================
// STUDIO WINDOW CONTAINER
// =========================================

export function StudioWindow() {
  return (
    <ReactFlowProvider>
      <StudioLayout />
    </ReactFlowProvider>
  );
}

// =========================================
// STUDIO LAYOUT (Inner Component)
// =========================================

function StudioLayout() {
  const [interfaceMode, setInterfaceMode] = useState<InterfaceMode>("COMPOSE");
  const [activeView, setActiveView] = useState("compose");

  // ReactFlow State
  const [nodes, setNodes, onNodesChange] = useNodesState(initialIOINodes.map(toFlowNode));
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialIOIEdges.map(toFlowEdge));
  const { screenToFlowPosition, fitView, zoomIn, zoomOut } = useReactFlow();

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // --- Execution State ---
  const [nodeArtifacts, setNodeArtifacts] = useState<NodeArtifacts>({});
  const [executionLogs, setExecutionLogs] = useState<any[]>([]);
  const [executionSteps, setExecutionSteps] = useState<any[]>([]);

  // Layout State
  const [explorerWidth] = useState(240);
  const [inspectorWidth] = useState(300);
  const [drawerHeight, setDrawerHeight] = useState(300);
  const [drawerCollapsed, setDrawerCollapsed] = useState(false);
  const [activeDrawerTab, setActiveDrawerTab] = useState<DrawerTab>("console");

  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<any>(null);

  const { task } = useAgentStore();

  useEffect(() => {
    initEventListeners();
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      setActiveView(event.payload);
    });
    return () => { unlistenPromise.then((unlisten) => unlisten()); };
  }, []);

  // --- LOCAL GRAPH RUNTIME HOOK ---
  // Listens for execution events from Rust Orchestrator to animate graph AND update BottomDrawer
  useEffect(() => {
    const unlisten = listen<any>("graph-event", (event) => {
      const { node_id, status, result } = event.payload;
      const timestamp = new Date().toISOString();
      const nodeName = nodes.find(n => n.id === node_id)?.data?.name || node_id;
      
      // 1. Update Node Status (Visuals)
      setNodes((nds) => nds.map((n) => {
        if (n.id === node_id) {
          return { 
            ...n, 
            data: { ...n.data, status }
          };
        }
        return n;
      }));

      // 2. Log to Console
      const logLevel = status === "error" || status === "failed" ? "error" : status === "blocked" ? "warn" : "info";
      setExecutionLogs(prev => [...prev, {
        id: `log-${Date.now()}-${Math.random()}`,
        timestamp,
        level: logLevel,
        source: nodeName,
        message: result?.output || `Status update: ${status}`
      }]);

      // 3. Update Timeline
      setExecutionSteps(prev => {
        // Update existing or add new
        const existing = prev.findIndex(s => s.id === node_id);
        const step = {
            id: node_id,
            name: nodeName,
            status,
            timestamp,
            duration: result?.metrics?.latency_ms ? `${result.metrics.latency_ms}ms` : undefined,
            dataCount: result?.output?.length
        };
        
        if (existing >= 0) {
            const newSteps = [...prev];
            newSteps[existing] = step;
            return newSteps;
        }
        return [...prev, step];
      });

      // 4. Capture Artifacts (Data Plane)
      if (result) {
        setNodeArtifacts(prev => ({
          ...prev,
          [node_id]: {
            output: result.output,
            metrics: result.metrics,
            timestamp: Date.now()
          }
        }));
      }

      // 5. Animate Edges
      if (status === "success") {
        setEdges((eds) => eds.map((e) => {
          if (e.source === node_id) {
            return { 
              ...e, 
              animated: true, 
              style: { stroke: '#3D85C6', strokeWidth: 3 }
            };
          }
          return e;
        }));
      }
    });

    return () => { unlisten.then(f => f()); };
  }, [setNodes, setEdges, nodes]); // Depend on nodes to resolve names

  // --- RUN GRAPH HANDLER ---
  const handleRunGraph = async () => {
    // 1. Reset Visual State & Data
    setNodeArtifacts({}); 
    setExecutionLogs([]);
    setExecutionSteps([]);
    setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, status: "idle" } })));
    setEdges(eds => eds.map(e => ({ ...e, animated: false, style: { stroke: '#2E333D', strokeWidth: 2 } })));
    
    // Switch to console to see execution start
    setActiveDrawerTab("console");
    setDrawerCollapsed(false);

    // 2. Serialize Graph for Rust Orchestrator
    const payload = {
      nodes: nodes.map(n => ({
        id: n.id,
        type: n.type || "action",
        // Pass the actual config edited in the RightPanel
        config: (n.data as IOINode).config || { logic: {}, law: {} }
      })),
      edges: edges.map(e => ({
        source: e.source,
        target: e.target,
        // Pass semantic handles for governance routing
        sourceHandle: e.sourceHandle 
      }))
    };

    // 3. Invoke Rust Command
    try {
      await invoke("run_studio_graph", { payload });
    } catch (e) {
      console.error("Graph execution failed:", e);
      setExecutionLogs(prev => [...prev, {
          id: `err-${Date.now()}`,
          timestamp: new Date().toISOString(),
          level: "error",
          source: "Orchestrator",
          message: `Failed to start graph: ${e}`
      }]);
    }
  };

  // --- UPSTREAM CONTEXT INJECTION ---
  const getUpstreamContext = useCallback((targetNodeId: string): string => {
    // 1. Find incoming edges
    const incomingEdges = edges.filter(e => e.target === targetNodeId);
    
    if (incomingEdges.length === 0) {
      return ""; // Root node, no upstream context
    }

    // 2. Aggregate outputs from source nodes
    const inputs = incomingEdges.map(edge => {
      const sourceArtifact = nodeArtifacts[edge.source];
      return sourceArtifact?.output || "";
    }).filter(Boolean);

    // 3. Join logic
    if (inputs.length === 0) return "";
    return inputs.join("\n---\n");
  }, [edges, nodeArtifacts]);

  // --- SINGLE NODE RUN HANDLER (Stateful Debugging) ---
  const handleNodeRunComplete = useCallback((nodeId: string, result: any) => {
    // 1. Update Artifacts (Data Plane)
    setNodeArtifacts(prev => ({
      ...prev,
      [nodeId]: {
        output: result.output,
        metrics: result.metrics,
        timestamp: Date.now()
      }
    }));
    
    // Add single unit test log
    setExecutionLogs(prev => [...prev, {
        id: `unit-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: "info",
        source: "Unit Test",
        message: `Manually executed node ${nodeId}`
    }]);

    // 2. Visual Feedback (Update Status to Success)
    setNodes((nds) => nds.map((n) => {
      if (n.id === nodeId) {
        return { 
          ...n, 
          data: { ...n.data, status: "success" }
        };
      }
      return n;
    }));

    // 3. Animate Outgoing Edges
    setEdges((eds) => eds.map((e) => {
      if (e.source === nodeId) {
        return { 
          ...e, 
          animated: true, 
          style: { stroke: '#3D85C6', strokeWidth: 3 }
        };
      }
      return e;
    }));
  }, [setNodes, setEdges]);

  // --- Ghost Mode Logic ---
  useEffect(() => {
    if (interfaceMode === "GHOST") {
      const timer = setTimeout(() => {
        const ghostNode: IOINode = {
          id: "n-ghost", type: "action", name: "Verify Stripe", x: 1000, y: 350,
          status: "idle", ioTypes: { in: "Invoice", out: "Bool" }, isGhost: true
        };
        setNodes(prev => { 
          if (prev.find(n => n.id === "n-ghost")) return prev; 
          return [...prev, toFlowNode(ghostNode)]; 
        });
        
        const ghostEdge: IOIEdge = {
          id: "e-ghost", from: "n-3", to: "n-ghost", fromPort: "out", toPort: "in", type: "data", active: true
        };
        setEdges(prev => { 
          if (prev.find(e => e.id === "e-ghost")) return prev; 
          return [...prev, toFlowEdge(ghostEdge)]; 
        });
      }, 1500);
      return () => clearTimeout(timer);
    } else {
      setNodes(prev => prev.filter(n => n.id !== "n-ghost"));
      setEdges(prev => prev.filter(e => e.id !== "e-ghost"));
    }
  }, [interfaceMode, setNodes, setEdges]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ ...params, animated: true, style: { stroke: '#2E333D', strokeWidth: 2 } }, eds)),
    [setEdges],
  );

  const handleNodeSelect = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  // --- Node Configuration Updater ---
  const handleNodeUpdate = useCallback((nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<NodeLaw>) => {
    setNodes((nds) => nds.map((node) => {
      if (node.id === nodeId) {
        const currentData = node.data as unknown as IOINode;
        // Ensure config structure exists
        const currentConfig = currentData.config || { logic: {}, law: {} };
        
        return {
          ...node,
          data: {
            ...currentData,
            config: {
              ...currentConfig,
              [section]: { 
                ...(currentConfig[section] || {}), 
                ...updates 
              }
            }
          },
        };
      }
      return node;
    }));
  }, [setNodes]);

  // --- Drag & Drop Handler ---
  const handleCanvasDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    try {
      const dataStr = e.dataTransfer.getData("application/json");
      if (!dataStr) return;
      const item = JSON.parse(dataStr); // { nodeId, nodeName } from ExplorerPanel
      
      const position = screenToFlowPosition({ x: e.clientX, y: e.clientY });

      const newNodeData: IOINode = {
        id: item.nodeId ? `${item.nodeId}-${Date.now()}` : `n-${Date.now()}`,
        type: "action",
        name: item.nodeName || "New Node",
        x: position.x, 
        y: position.y,
        status: "idle", 
        ioTypes: { in: "Any", out: "Any" }, 
        inputs: ["in"], 
        outputs: ["out"],
        // Initialize config so editor works immediately
        config: { logic: {}, law: {} }
      };

      const flowNode = toFlowNode(newNodeData);
      setNodes(prev => [...prev, flowNode]);
      setSelectedNodeId(flowNode.id);
    } catch (err) {
      console.error("Drop failed", err);
    }
  }, [screenToFlowPosition, setNodes]);

  // --- Builder Handoff ---
  const handleBuilderHandoff = (config: AgentConfiguration) => {
    const agentNode = toFlowNode({
        id: `n-agent-${Date.now()}`,
        type: "model",
        name: config.name,
        x: 600, y: 300,
        status: "idle", ioTypes: {in: "Q", out: "A"}, inputs:["in"], outputs:["out"],
        config: {
          logic: { 
            systemPrompt: config.instructions, 
            temperature: config.temperature,
            model: config.model 
          },
          law: { budgetCap: 1.0 } // Default budget
        }
    });
    setNodes([agentNode]);
    setEdges([]);
    setActiveView("compose");
    setInterfaceMode("COMPOSE");
  };

  // Convert selected ReactFlow Node back to IOINode for the RightPanel
  const selectedNodeData = nodes.find(n => n.id === selectedNodeId)?.data as IOINode | undefined;
  const selectedNode = selectedNodeData || null;

  return (
    <div className="studio-window">
      <ActivityBar activeView={activeView} onViewChange={setActiveView} />

      <div className="studio-main">
        {/* IDE Header */}
        {activeView !== "marketplace" && activeView !== "copilot" && activeView !== "fleet" && (
          <IDEHeader
            projectPath="Personal"
            projectName={activeView === "agent-builder" ? "Agent Builder" : "Invoice Guard"}
            branch="main"
            mode={interfaceMode}
            onModeChange={setInterfaceMode}
            isComposeView={activeView === "compose"}
            onSave={() => console.log("Save")}
            
            /* Hook up local graph runner */
            onRun={handleRunGraph} 
            
            onZoomIn={() => zoomIn()}
            onZoomOut={() => zoomOut()}
            onFit={() => fitView()}
          />
        )}

        <div className="studio-content">
          {activeView === "marketplace" ? (
            <MarketplaceView onInstallAgent={(a) => { setSelectedAgent(a); setInstallModalOpen(true); }} />
          ) : activeView === "agent-builder" ? (
            <div className="studio-center-area">
              <BuilderView onSwitchToCompose={handleBuilderHandoff} />
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
                  <div className="canvas-container" style={{ bottom: drawerCollapsed ? 32 : drawerHeight }}>
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
                      nodes={nodes}
                      edges={edges}
                      onNodesChange={onNodesChange}
                      onEdgesChange={onEdgesChange}
                      onConnect={onConnect}
                      onNodeSelect={handleNodeSelect}
                    />
                  </div>
                  
                  {/* [UPDATED] Replaced DataPanel with BottomDrawer */}
                  <BottomDrawer
                    height={drawerHeight}
                    collapsed={drawerCollapsed}
                    onToggleCollapse={() => setDrawerCollapsed(!drawerCollapsed)}
                    onResize={setDrawerHeight}
                    activeTab={activeDrawerTab}
                    onTabChange={setActiveDrawerTab}
                    logs={executionLogs}
                    steps={executionSteps}
                    selectedNodeId={selectedNodeId}
                    selectedArtifact={selectedNodeId ? nodeArtifacts[selectedNodeId] : null}
                  />
                </div>
              </div>
              <div className="studio-right-panel" style={{ width: inspectorWidth }}>
                {interfaceMode === "GHOST" ? (
                  <GhostChatPanel />
                ) : (
                  // Pass the update handler, upstream data, AND the completion handler
                  <RightPanel 
                    width={inspectorWidth} 
                    selectedNode={selectedNode} 
                    onUpdateNode={handleNodeUpdate}
                    // @ts-ignore
                    upstreamData={selectedNodeId ? getUpstreamContext(selectedNodeId) : ""}
                    onRunComplete={handleNodeRunComplete}
                  />
                )}
              </div>
            </>
          )}
        </div>
        
        <StatusBar metrics={{ cost: 0.42, privacy: 0.15, risk: 0.6 }} status={task ? task.phase : "Ready"} />
      </div>

      {commandPaletteOpen && <CommandPalette onClose={() => setCommandPaletteOpen(false)} />}
      
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