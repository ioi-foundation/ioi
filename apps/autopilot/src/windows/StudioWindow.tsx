import { useState, useCallback, useEffect } from "react";
import { initEventListeners, useAgentStore } from "../store/agentStore";

// Import Shared Types from the central types file
import { Node, Edge } from "../types";

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

import "./StudioWindow.css";

// Sample pipeline data
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
          id: "n-ghost",
          type: "action",
          name: "Verify Stripe",
          x: 1000, 
          y: 350,
          status: "idle",
          ioTypes: { in: "Invoice", out: "Bool" },
          isGhost: true
        };
        
        setNodes(prev => {
          if (prev.find(n => n.id === "n-ghost")) return prev;
          return [...prev, ghostNode];
        });

        const ghostEdge: Edge = {
          id: "e-ghost",
          from: "n-3",
          to: "n-ghost",
          fromPort: "out",
          toPort: "in",
          type: "data",
          active: true
        };
        setEdges(prev => {
            if (prev.find(e => e.id === "e-ghost")) return prev;
            return [...prev, ghostEdge];
        });

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
    setNodes((prev) =>
      prev.map((n) => (n.id === nodeId ? { ...n, x, y } : n))
    );
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
        id: `n-${Date.now()}`,
        type: item.type,
        name: item.name,
        x: dropX - 110, 
        y: dropY - 20,
        status: "idle",
        ioTypes: { in: "Any", out: "Any" },
        inputs: ["in"],
        outputs: ["out"],
      };

      setNodes(prev => [...prev, newNode]);
      setSelectedNodeId(newNode.id);
    } catch (err) {
      console.error("Drop failed", err);
    }
  }, [canvasTransform]);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) ?? null;

  const handleRun = async () => {
    if (dataPanelCollapsed) {
      setDataPanelCollapsed(false);
    }
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
        {/* IDE Header hidden in Marketplace view to maximize space */}
        {activeView !== "marketplace" && (
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
          ) : (
             <>
               <ExplorerPanel width={explorerWidth} />
               <div className="studio-center-area">
                  <div 
                      className="canvas-area"
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={handleCanvasDrop}
                  >
                      <div 
                          className="canvas-container" 
                          style={{ bottom: dataPanelCollapsed ? 32 : dataPanelHeight }}
                      >
                          {interfaceMode === "GHOST" && (
                              <div className="ghost-overlay">
                                  <div className="ghost-badge">
                                      <span className="ghost-dot" />
                                      <span>Ghost Mode: Observing & Inferring...</span>
                                  </div>
                              </div>
                          )}

                          <Canvas
                            nodes={nodes}
                            edges={edges}
                            selectedNodeId={selectedNodeId}
                            onNodeSelect={handleNodeSelect}
                            onNodeMove={handleNodeMove}
                            transform={canvasTransform}
                            onTransformChange={setCanvasTransform}
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
      
      {/* Install Modal */}
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

// --- Ghost Chat Component ---
function GhostChatPanel() {
    return (
        <aside style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div className="panel-header" style={{ padding: '12px 16px', borderBottom: '1px solid #2E333D' }}>
                <h2 className="panel-title" style={{ fontSize: '12px', fontWeight: 600, color: '#F59E0B', display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ width: 8, height: 8, background: '#F59E0B', borderRadius: '50%', boxShadow: '0 0 8px rgba(245, 158, 11, 0.4)' }} />
                    Ghost Copilot
                </h2>
            </div>
            
            <div style={{ flex: 1, padding: 16, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ alignSelf: 'flex-start', background: '#252A33', padding: '8px 12px', borderRadius: 6, fontSize: '12px', color: '#D1D5DB', border: '1px solid #3F4652' }}>
                    I'm watching your actions. Perform the manual task in the "Sandbox" browser, and I'll generate the graph nodes.
                </div>
                <div style={{ alignSelf: 'flex-end', background: 'rgba(61, 133, 198, 0.2)', padding: '8px 12px', borderRadius: 6, fontSize: '12px', color: '#D1D5DB', border: '1px solid rgba(61, 133, 198, 0.3)' }}>
                    Opening Stripe dashboard...
                </div>
                <div style={{ alignSelf: 'flex-start', background: '#252A33', padding: '8px 12px', borderRadius: 6, fontSize: '12px', color: '#D1D5DB', border: '1px solid #3F4652' }}>
                    Observed: <strong>Network Request (GET api.stripe.com)</strong>.<br/>
                    <button style={{ marginTop: 8, background: 'transparent', border: '1px solid #F59E0B', color: '#F59E0B', padding: '4px 8px', borderRadius: 4, cursor: 'pointer', fontSize: '10px' }}>
                       + Add Node to Graph
                    </button>
                </div>
            </div>

            <div style={{ padding: 12, borderTop: '1px solid #2E333D' }}>
                <input 
                    type="text" 
                    placeholder="Describe intent..." 
                    style={{ width: '100%', background: '#111418', border: '1px solid #3F4652', padding: '8px', borderRadius: 4, color: 'white', fontSize: '12px' }}
                />
            </div>
        </aside>
    );
}