// src/windows/StudioWindow/index.tsx
import { useState, useEffect, useCallback } from "react";
import { ReactFlowProvider, useReactFlow } from "@xyflow/react"; 
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
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
import { IDEHeader } from "../../components/IDEHeader";
import { ExplorerPanel } from "../../components/ExplorerPanel";
import { Canvas } from "../../components/Canvas";
import { RightPanel } from "../../components/RightPanel";
import { BottomDrawer, DrawerTab } from "../../components/BottomDrawer"; 
import { CommandPalette } from "../../components/CommandPalette";
import { BuilderView } from "../../components/BuilderView";
import { AgentsDashboard, SimpleAgent } from "../../components/AgentsDashboard"; 
import { StatusBar } from "../../components/StatusBar";
import { MarketplaceView } from "../../components/MarketplaceView";
import { AgentInstallModal } from "../../components/AgentInstallModal";
import { VisionHUD } from "../../components/VisionHUD";
import { FleetView } from "../../components/FleetView";

import "../../components/ActivityBar.css";
import "./StudioWindow.css";

type InterfaceMode = "GHOST" | "AGENT" | "COMPOSE";

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

  const [explorerWidth] = useState(240);
  const [inspectorWidth] = useState(320);
  const [drawerHeight, setDrawerHeight] = useState(300);
  const [drawerCollapsed, setDrawerCollapsed] = useState(false);
  const [activeDrawerTab, setActiveDrawerTab] = useState<DrawerTab>("console");
  
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<any>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  
  // [NEW] Hover State for Bi-Directional Linking
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  const [editingAgent, setEditingAgent] = useState<SimpleAgent | null>(null);
  const [projectPath, setProjectPath] = useState<string>("");
  const [projectName, setProjectName] = useState<string>("Untitled");

  const [graphConfig, setGraphConfig] = useState<GraphGlobalConfig>({
    env: '{\n  "ENV": "local",\n  "API_URL": "http://localhost:3000"\n}',
    policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
    contract: { developerBond: 0, adjudicationRubric: "" },
    meta: { name: "Untitled Agent", description: "" }
  });

  const { 
    nodes, edges, selectedNodeId, setSelectedNodeId,
    setNodes, setEdges, onNodesChange, onEdgesChange, onConnect,
    handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    addAgentToGraph, 
    injectGhostNode, clearGhostNodes
  } = useGraphState();

  const {
    nodeArtifacts, executionLogs, executionSteps,
    traceData, 
    runGraph, handleNodeRunComplete, getUpstreamContext
  } = useGraphExecution(nodes, edges, setNodes, setEdges);

  const { fitView, zoomIn, zoomOut, setCenter, getNodes } = useReactFlow();

  useEffect(() => {
    initEventListeners();
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      setActiveView(event.payload);
    });
    return () => { unlistenPromise.then((unlisten) => unlisten()); };
  }, []);

  useEffect(() => {
    if (interfaceMode === "GHOST") injectGhostNode();
    else clearGhostNodes();
  }, [interfaceMode, injectGhostNode, clearGhostNodes]);

  // [NEW] Propagate Hover State to Node Data
  // This updates the 'highlighted' property on nodes without triggering a full re-render of everything
  useEffect(() => {
      setNodes((nds) => nds.map((node) => ({
          ...node,
          data: {
              ...node.data,
              highlighted: node.id === hoveredNodeId
          }
      })));
  }, [hoveredNodeId, setNodes]);

  // [NEW] Handle Trace Click -> Pan Canvas
  const handleTraceSelect = useCallback((nodeId: string) => {
      setSelectedNodeId(nodeId);
      const node = getNodes().find(n => n.id === nodeId);
      if (node) {
          // Center the view on the node with animation
          setCenter(node.position.x + 100, node.position.y + 50, { zoom: 1.2, duration: 800 });
      }
  }, [getNodes, setCenter, setSelectedNodeId]);

  const onRunGraph = async () => {
    setActiveDrawerTab("timeline"); 
    setDrawerCollapsed(false);
    await runGraph(graphConfig);
  };

  const handleGraphUpdate = (updates: Partial<GraphGlobalConfig>) => {
    setGraphConfig((prev: GraphGlobalConfig) => ({ ...prev, ...updates }));
  };

  const handleSave = async () => {
    let path = projectPath;
    if (!path) {
        const selected = await save({
            filters: [{ name: 'Autopilot Agent', extensions: ['json', 'ioi'] }]
        });
        if (!selected) return;
        path = selected;
        setProjectPath(path);
        // @ts-ignore
        setProjectName(path.split(/[\\/]/).pop()?.split('.')[0] || "Untitled");
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const exportNodes = nodes.map((n) => ({
      id: n.id,
      type: n.type || "action",
      x: n.position.x,
      y: n.position.y,
      config: (n.data as IOINode).config || { logic: {}, law: {} }
    }));

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
      filters: [{ name: 'Autopilot Agent', extensions: ['json', 'ioi'] }]
    });

    if (!path) return;

    try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const project: any = await invoke("load_project", { path });
        setProjectPath(path);
        // @ts-ignore
        setProjectName(path.split(/[\\/]/).pop()?.split('.')[0] || "Untitled");

        if (project.global_config) {
            setGraphConfig({
                env: project.global_config.env || graphConfig.env,
                policy: project.global_config.policy || graphConfig.policy,
                contract: project.global_config.contract || graphConfig.contract,
                meta: project.global_config.meta || graphConfig.meta
            });
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const flowNodes = project.nodes.map((n: any) => ({
            id: n.id,
            type: n.node_type || n.type,
            position: { x: n.x || 0, y: n.y || 0 },
            data: { 
                id: n.id, 
                type: n.node_type || n.type,
                name: n.config?.meta?.name || n.id,
                config: n.config,
                status: 'idle'
            }
        }));
        
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const flowEdges = project.edges.map((e: any, i: number) => ({
            id: `e-${i}`,
            source: e.source,
            target: e.target,
            sourceHandle: e.source_handle || 'out',
            targetHandle: 'in',
            type: 'semantic',
            data: { active: false, status: 'idle' }
        }));

        setNodes(flowNodes);
        setEdges(flowEdges);
        setSelectedNodeId(null);
        setSelectedEdgeId(null);
        setTimeout(() => fitView({ padding: 0.2 }), 100);

    } catch (err) {
        console.error("Load failed:", err);
    }
  };

  const handleOpenAgent = (agent: SimpleAgent | null) => {
    setEditingAgent(agent || { id: 'new', name: 'New Agent', description: '' });
  };

  const selectedNodeData = nodes.find((n) => n.id === selectedNodeId)?.data as IOINode | undefined;
  const selectedNode = selectedNodeData || null;
  const flowEdge = edges.find((e) => e.id === selectedEdgeId);
  const selectedEdge: IOIEdge | null = flowEdge ? {
      id: flowEdge.id, from: flowEdge.source, to: flowEdge.target,
      fromPort: flowEdge.sourceHandle || "out", toPort: flowEdge.targetHandle || "in", type: "data",
      // @ts-ignore
      data: flowEdge.data
  } : null;
  const edgeThroughput = selectedEdge ? nodeArtifacts[selectedEdge.from]?.output : null;

  const showHeader = activeView === "compose";

  return (
    <div className="studio-window">
      <ActivityBar 
        activeView={activeView} 
        onViewChange={(view) => { setActiveView(view); if (view !== 'agents') setEditingAgent(null); }}
        ghostMode={interfaceMode === "GHOST"}
        // [FIX] Explicit type
        onToggleGhost={() => setInterfaceMode((prev: InterfaceMode) => prev === "GHOST" ? "COMPOSE" : "GHOST")}
      />

      <div className="studio-main">
        {showHeader && (
          <IDEHeader
            projectPath={projectPath ? "Local File" : ""}
            projectName={projectName}
            onRun={onRunGraph}
            onSave={handleSave}
            onOpen={handleOpen}
            onZoomIn={() => zoomIn()} onZoomOut={() => zoomOut()} onFit={() => fitView()}
          />
        )}

        <div className="studio-content">
          {activeView === "marketplace" ? (
            <MarketplaceView onInstallAgent={(a) => { setSelectedAgent(a); setInstallModalOpen(true); }} />
          
          ) : activeView === "agents" ? (
            !editingAgent ? (
                <div className="studio-center-area">
                    <AgentsDashboard onSelectAgent={handleOpenAgent} />
                </div>
            ) : (
                <div className="studio-center-area">
                    <BuilderView 
                        onBack={() => setEditingAgent(null)}
                        onAddToGraph={(c) => { 
                            addAgentToGraph(c);
                            setEditingAgent(null); 
                            setActiveView('compose'); 
                        }} 
                    />
                </div>
            )
          
          ) : activeView === "compose" ? (
            <>
              <ExplorerPanel width={explorerWidth} />
              <div className="studio-center-area">
                <div className="canvas-area" onDragOver={(e) => e.preventDefault()} onDrop={handleCanvasDrop}>
                  <div className="canvas-container" style={{ bottom: drawerCollapsed ? 32 : drawerHeight }}>
                    {interfaceMode === "GHOST" && (
                      <>
                        <div className="ghost-overlay">
                          <div className="ghost-badge"><span className="ghost-dot" /><span>Ghost Mode</span></div>
                        </div>
                        <VisionHUD />
                      </>
                    )}
                    <Canvas
                      nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect} 
                      onNodeSelect={handleNodeSelect}
                      /* @ts-ignore */ onEdgeClick={(_, e) => { setSelectedNodeId(null); setSelectedEdgeId(e.id); }}
                      /* @ts-ignore */ onNodeClick={(_, n) => { setSelectedEdgeId(null); setSelectedNodeId(n.id); }}
                    />
                  </div>
                  <BottomDrawer
                    height={drawerHeight} collapsed={drawerCollapsed} onToggleCollapse={() => setDrawerCollapsed(!drawerCollapsed)} onResize={setDrawerHeight}
                    activeTab={activeDrawerTab} onTabChange={setActiveDrawerTab}
                    logs={executionLogs} traceData={traceData} steps={executionSteps} 
                    selectedNodeId={selectedNodeId} selectedArtifact={selectedNodeId ? nodeArtifacts[selectedNodeId] : null}
                    // [NEW] Pass click handler to TraceViewer inside BottomDrawer
                    onTraceClick={handleTraceSelect}
                    onTraceHover={setHoveredNodeId}
                  />
                </div>
              </div>
              <div className="studio-right-panel" style={{ width: inspectorWidth }}>
                {interfaceMode === "GHOST" ? <GhostChatPanel /> : 
                  <RightPanel 
                    width={inspectorWidth} selectedNode={selectedNode} selectedEdge={selectedEdge}
                    nodes={nodes.map(n => n.data as IOINode)}
                    edges={edges.map(e => ({ id: e.id, from: e.source, to: e.target, fromPort: e.sourceHandle||'out', toPort: e.targetHandle||'in', type: 'data' }))}
                    onUpdateNode={handleNodeUpdate} graphConfig={graphConfig} onUpdateGraph={handleGraphUpdate}
                    // @ts-ignore
                    upstreamData={selectedNodeId ? getUpstreamContext(selectedNodeId) : ""}
                    onRunComplete={handleNodeRunComplete} edgeThroughput={edgeThroughput}
                    onUpdateEdge={(id, data) => setEdges((eds) => eds.map(e => e.id === id ? { ...e, data: { ...e.data, ...data } } : e))}
                  />
                }
              </div>
            </>

          ) : activeView === "copilot" ? (
            <StudioCopilotView />
          
          ) : activeView === "fleet" ? (
            <FleetView />
          
          ) : (
            <div className="studio-center-area">Select a view</div>
          )}
        </div>
        
        <StatusBar metrics={{ cost: 0.00, privacy: 0.0, risk: 0.0 }} status={task ? task.phase : "Ready"} />
      </div>

      {commandPaletteOpen && <CommandPalette onClose={() => setCommandPaletteOpen(false)} />}
      
      {installModalOpen && selectedAgent && (
        <AgentInstallModal isOpen={installModalOpen} onClose={() => setInstallModalOpen(false)} agent={selectedAgent} />
      )}
    </div>
  );
}
