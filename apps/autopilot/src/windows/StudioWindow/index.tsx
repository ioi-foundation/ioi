import { useState, useEffect } from "react";
import { ReactFlowProvider, useReactFlow } from "@xyflow/react"; 
import { listen } from "@tauri-apps/api/event";
import "@xyflow/react/dist/style.css"; 

import { initEventListeners, useAgentStore } from "../../store/agentStore";
import { Node as IOINode } from "../../types";

// Local Hooks
import { useGraphState } from "./hooks/useGraphState.ts";
import { useGraphExecution } from "./hooks/useGraphExecution.ts";
import { GraphGlobalConfig } from "./types.ts";

// Local Components
import { StudioCopilotView } from "./components/StudioCopilot";
import { GhostChatPanel } from "./components/GhostPanel.tsx";

// Global Components
import { ActivityBar } from "../../components/ActivityBar";
import { IDEHeader, InterfaceMode } from "../../components/IDEHeader";
import { ExplorerPanel } from "../../components/ExplorerPanel";
import { Canvas } from "../../components/Canvas";
import { RightPanel } from "../../components/RightPanel";
import { BottomDrawer, DrawerTab } from "../../components/BottomDrawer"; 
import { CommandPalette } from "../../components/CommandPalette";
import { BuilderView } from "../../components/BuilderView";
import { StatusBar } from "../../components/StatusBar";
import { MarketplaceView } from "../../components/MarketplaceView";
import { AgentInstallModal } from "../../components/AgentInstallModal";
import { VisionHUD } from "../../components/VisionHUD";
import { FleetView } from "../../components/FleetView";

// CSS
import "../../components/ActivityBar.css";
import "../../components/IDEHeader.css";
import "../../components/ExplorerPanel.css";
import "../../components/Canvas.css";
import "../../components/CanvasNode.css";
import "../../components/CanvasEdge.css";
import "../../components/RightPanel.css";
import "../../components/BottomDrawer.css";
import "../../components/CommandPalette.css";
import "../../components/BuilderView.css";
import "../../components/StatusBar.css";
import "../../components/MarketplaceView.css";
import "../../components/AgentInstallModal.css";
import "../../components/VisionHUD.css";
import "../../components/FleetView.css";
import "./StudioWindow.css";

export function StudioWindow() {
  return (
    <ReactFlowProvider>
      <StudioLayout />
    </ReactFlowProvider>
  );
}

function StudioLayout() {
  const [interfaceMode, setInterfaceMode] = useState<InterfaceMode>("COMPOSE");
  const [activeView, setActiveView] = useState("compose");
  const { task } = useAgentStore();

  // Layout State
  const [explorerWidth] = useState(240);
  const [inspectorWidth] = useState(320);
  const [drawerHeight, setDrawerHeight] = useState(300);
  const [drawerCollapsed, setDrawerCollapsed] = useState(false);
  const [activeDrawerTab, setActiveDrawerTab] = useState<DrawerTab>("console");
  
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<any>(null);

  // --- Graph Global State ---
  const [graphConfig, setGraphConfig] = useState<GraphGlobalConfig>({
    env: '{\n  "ENV": "local",\n  "API_URL": "http://localhost:3000"\n}',
    policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
    meta: { name: "Untitled Agent", description: "" }
  });

  // --- Hooks ---
  const { 
    nodes, edges, selectedNodeId,
    setNodes, setEdges, onNodesChange, onEdgesChange, onConnect,
    handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    handleBuilderHandoff, injectGhostNode, clearGhostNodes
  } = useGraphState();

  const {
    nodeArtifacts, executionLogs, executionSteps,
    traceData, // <--- Get the transformed trace data from the hook
    runGraph, handleNodeRunComplete, getUpstreamContext
  } = useGraphExecution(nodes, edges, setNodes, setEdges);

  // ReactFlow Tools
  const { fitView, zoomIn, zoomOut } = useReactFlow();

  // Listen for external view requests
  useEffect(() => {
    initEventListeners();
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      setActiveView(event.payload);
    });
    return () => { unlistenPromise.then((unlisten) => unlisten()); };
  }, []);

  // Handle Ghost Mode Toggles
  useEffect(() => {
    if (interfaceMode === "GHOST") injectGhostNode();
    else clearGhostNodes();
  }, [interfaceMode, injectGhostNode, clearGhostNodes]);

  // Wrapper for run
  const onRunGraph = async () => {
    setActiveDrawerTab("timeline"); // Switch to timeline to show trace
    setDrawerCollapsed(false);
    await runGraph(graphConfig);
  };

  const handleGraphUpdate = (updates: Partial<GraphGlobalConfig>) => {
    setGraphConfig((prev: GraphGlobalConfig) => ({ ...prev, ...updates }));
  };

  // Derived selected node
  const selectedNodeData = nodes.find((n) => n.id === selectedNodeId)?.data as IOINode | undefined;
  const selectedNode = selectedNodeData || null;

  return (
    <div className="studio-window">
      <ActivityBar activeView={activeView} onViewChange={setActiveView} />

      <div className="studio-main">
        {activeView !== "marketplace" && activeView !== "copilot" && activeView !== "fleet" && (
          <IDEHeader
            projectPath="Personal"
            projectName={graphConfig.meta.name}
            branch="main"
            mode={interfaceMode}
            onModeChange={setInterfaceMode}
            isComposeView={activeView === "compose"}
            onSave={() => console.log("Save")}
            onRun={onRunGraph}
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
              <BuilderView onSwitchToCompose={(c) => { handleBuilderHandoff(c); setActiveView("compose"); setInterfaceMode("COMPOSE"); }} />
            </div>
          ) : activeView === "copilot" ? (
            <StudioCopilotView />
          ) : activeView === "fleet" ? (
            <FleetView />
          ) : (
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
                      nodes={nodes} edges={edges}
                      onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                      onConnect={onConnect} onNodeSelect={handleNodeSelect}
                    />
                  </div>
                  
                  <BottomDrawer
                    height={drawerHeight}
                    collapsed={drawerCollapsed}
                    onToggleCollapse={() => setDrawerCollapsed(!drawerCollapsed)}
                    onResize={setDrawerHeight}
                    activeTab={activeDrawerTab}
                    onTabChange={setActiveDrawerTab}
                    logs={executionLogs}
                    traceData={traceData} // <--- Pass real trace data
                    steps={executionSteps} // Kept for legacy if needed, but unused in new component
                    selectedNodeId={selectedNodeId}
                    selectedArtifact={selectedNodeId ? nodeArtifacts[selectedNodeId] : null}
                  />
                </div>
              </div>
              <div className="studio-right-panel" style={{ width: inspectorWidth }}>
                {interfaceMode === "GHOST" ? (
                  <GhostChatPanel />
                ) : (
                  <RightPanel 
                    width={inspectorWidth} 
                    selectedNode={selectedNode} 
                    onUpdateNode={handleNodeUpdate}
                    graphConfig={graphConfig}
                    onUpdateGraph={handleGraphUpdate}
                    // @ts-ignore
                    upstreamData={selectedNodeId ? getUpstreamContext(selectedNodeId) : ""}
                    onRunComplete={handleNodeRunComplete}
                  />
                )}
              </div>
            </>
          )}
        </div>
        
        <StatusBar metrics={{ cost: 0.00, privacy: 0.0, risk: 0.0 }} status={task ? task.phase : "Ready"} />
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