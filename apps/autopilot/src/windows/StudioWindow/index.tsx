// apps/autopilot/src/windows/StudioWindow/index.tsx
import { useState, useEffect } from "react";
import { ReactFlowProvider, useReactFlow } from "@xyflow/react"; 
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
// Ensure you have installed this package: npm install @tauri-apps/plugin-dialog
import { save, open } from "@tauri-apps/plugin-dialog";
import "@xyflow/react/dist/style.css"; 

import { initEventListeners, useAgentStore } from "../../store/agentStore";
import { Node as IOINode, Edge as IOIEdge } from "../../types";

// Local Hooks
import { useGraphState } from "./hooks/useGraphState.ts";
import { useGraphExecution } from "./hooks/useGraphExecution.ts";
import { GraphGlobalConfig } from "./types.ts";

// Components
import { StudioCopilotView } from "./components/StudioCopilot";
import { GhostChatPanel } from "./components/GhostPanel.tsx";
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
// ... (other CSS imports unchanged) ...
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

  // [NEW] Edge Selection State for Inspection
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // --- Graph Global State ---
  const [graphConfig, setGraphConfig] = useState<GraphGlobalConfig>({
    env: '{\n  "ENV": "local",\n  "API_URL": "http://localhost:3000"\n}',
    policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
    meta: { name: "Untitled Agent", description: "" }
  });

  // --- Hooks ---
  const { 
    nodes, edges, selectedNodeId, setSelectedNodeId,
    setNodes, setEdges, onNodesChange, onEdgesChange, onConnect,
    handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    handleBuilderHandoff, injectGhostNode, clearGhostNodes
  } = useGraphState();

  const {
    nodeArtifacts, executionLogs, executionSteps,
    traceData, 
    runGraph, handleNodeRunComplete, getUpstreamContext
  } = useGraphExecution(nodes, edges, setNodes, setEdges);

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

  const onRunGraph = async () => {
    setActiveDrawerTab("timeline"); 
    setDrawerCollapsed(false);
    await runGraph(graphConfig);
  };

  const handleGraphUpdate = (updates: Partial<GraphGlobalConfig>) => {
    setGraphConfig((prev: GraphGlobalConfig) => ({ ...prev, ...updates }));
  };

  // Persistence Handlers
  const handleSave = async () => {
    const path = await save({
      filters: [{
        name: 'Autopilot Agent',
        extensions: ['json', 'ioi']
      }]
    });
    
    if (!path) return;

    // Transform ReactFlow nodes to Rust GraphNode format
    const exportNodes = nodes.map((n) => ({
      id: n.id,
      type: n.type || "action",
      config: (n.data as IOINode).config || { logic: {}, law: {} }
    }));

    const exportEdges = edges.map((e) => ({
      source: e.source,
      target: e.target,
      sourceHandle: e.sourceHandle 
    }));

    const projectFile = {
        version: "1.0",
        nodes: exportNodes,
        edges: exportEdges,
        global_config: {
            env: graphConfig.env,
            policy: graphConfig.policy,
            meta: graphConfig.meta
        }
    };

    try {
        await invoke("save_project", { path, project: projectFile });
    } catch (err) {
        console.error("Save failed:", err);
    }
  };

  const handleOpen = async () => {
    const path = await open({
      multiple: false,
      filters: [{
        name: 'Autopilot Agent',
        extensions: ['json', 'ioi']
      }]
    });

    if (!path) return;

    try {
        const project: any = await invoke("load_project", { path });
        
        // Hydrate Graph Config
        if (project.global_config) {
            setGraphConfig({
                env: project.global_config.env || graphConfig.env,
                policy: project.global_config.policy || graphConfig.policy,
                meta: project.global_config.meta || graphConfig.meta
            });
        }

        // Hydrate Nodes (Map back to FlowNodes)
        const flowNodes = project.nodes.map((n: any) => ({
            id: n.id,
            type: n.node_type || n.type, // Handle rename
            position: { x: 0, y: 0 }, // TODO: Persist layout x/y if stored
            data: { 
                id: n.id, 
                type: n.node_type || n.type,
                name: n.config?.meta?.name || n.id, // Fallback name logic
                config: n.config
            }
        }));
        
        // Hydrate Edges
        const flowEdges = project.edges.map((e: any, i: number) => ({
            id: `e-${i}`,
            source: e.source,
            target: e.target,
            sourceHandle: e.source_handle || 'out',
            targetHandle: 'in', // Assumption
            type: 'semantic'
        }));

        setNodes(flowNodes);
        setEdges(flowEdges);
        setTimeout(() => fitView(), 100);

    } catch (err) {
        console.error("Load failed:", err);
    }
  };

  // Derived selected node
  const selectedNodeData = nodes.find((n) => n.id === selectedNodeId)?.data as IOINode | undefined;
  const selectedNode = selectedNodeData || null;

  // [NEW] Derived selected edge & throughput data
  const flowEdge = edges.find((e) => e.id === selectedEdgeId);
  const selectedEdge: IOIEdge | null = flowEdge ? {
      id: flowEdge.id,
      from: flowEdge.source,
      to: flowEdge.target,
      fromPort: flowEdge.sourceHandle || "out",
      toPort: flowEdge.targetHandle || "in",
      type: "data", // Defaulting, would need storage in data payload
      // @ts-ignore
      data: flowEdge.data
  } : null;

  // The throughput is the output of the source node
  const edgeThroughput = selectedEdge ? nodeArtifacts[selectedEdge.from]?.output : null;

  return (
    <div className="studio-window">
      <ActivityBar activeView={activeView} onViewChange={setActiveView} />

      <div className="studio-main">
        {activeView !== "marketplace" && activeView !== "copilot" && activeView !== "fleet" && (
          <IDEHeader
            projectPath="Personal"
            projectName={graphConfig.meta.name || "Untitled"}
            branch="main"
            mode={interfaceMode}
            onModeChange={setInterfaceMode}
            isComposeView={activeView === "compose"}
            onSave={handleSave} 
            onOpen={handleOpen} 
            onRun={onRunGraph}
            onZoomIn={() => zoomIn()}
            onZoomOut={() => zoomOut()}
            onFit={() => fitView()}
          />
        )}

        <div className="studio-content">
          {/* ... (View Switching Logic) ... */}
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
                      onConnect={onConnect} 
                      onNodeSelect={handleNodeSelect}
                      // [NEW] Wire up edge clicks
                      /* @ts-ignore - ReactFlow's onEdgeClick signature */
                      onEdgeClick={(_, edge) => {
                        setSelectedNodeId(null);
                        setSelectedEdgeId(edge.id);
                      }}
                      /* @ts-ignore - ReactFlow's onNodeClick signature */
                      onNodeClick={(_, node) => {
                        setSelectedEdgeId(null);
                        setSelectedNodeId(node.id);
                      }}
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
                    traceData={traceData} 
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
                  <RightPanel 
                    width={inspectorWidth} 
                    selectedNode={selectedNode} 
                    // [NEW] Pass graph state
                    nodes={nodes.map(n => n.data as IOINode)}
                    edges={edges.map(e => ({
                        id: e.id, from: e.source, to: e.target, 
                        fromPort: e.sourceHandle || 'out', toPort: e.targetHandle || 'in', 
                        type: 'data'
                    }))}
                    onUpdateNode={handleNodeUpdate}
                    graphConfig={graphConfig}
                    onUpdateGraph={handleGraphUpdate}
                    // @ts-ignore
                    upstreamData={selectedNodeId ? getUpstreamContext(selectedNodeId) : ""}
                    onRunComplete={handleNodeRunComplete}
                    // [NEW] Pass Edge props
                    selectedEdge={selectedEdge}
                    edgeThroughput={edgeThroughput}
                    onUpdateEdge={(id, data) => {
                        // eslint-disable-next-line @typescript-eslint/no-explicit-any
                        setEdges((eds: any[]) => eds.map(e => e.id === id ? { ...e, data: { ...e.data, ...data } } : e));
                    }}
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