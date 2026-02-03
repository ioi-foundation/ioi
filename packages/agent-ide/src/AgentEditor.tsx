// packages/agent-ide/src/AgentEditor.tsx
import { useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import { AgentRuntime } from "./runtime/agent-runtime";
import { useGraphState } from "./hooks/useGraphState";
import { useGraphExecution } from "./hooks/useGraphExecution";
import { GraphGlobalConfig } from "./types/graph";

// Sub-components
import { Canvas } from "./features/Editor/Canvas/Canvas";
import { Inspector } from "./features/Editor/Inspector/Inspector";
import { Explorer } from "./features/Editor/Explorer/Explorer"; 
import { Console } from "./features/Editor/BottomPanel/Console"; 
import { IDEHeader } from "./features/Editor/Header/IDEHeader";

import "./styles/theme.css";

export interface AgentEditorProps {
  runtime: AgentRuntime;
  initialFile?: any; 
}

function AgentEditorContent({ runtime }: AgentEditorProps) {
  const { 
    nodes, edges, setNodes, setEdges, 
    onNodesChange, onEdgesChange, onConnect, 
    handleCanvasDrop, selectedNodeId, handleNodeSelect, handleNodeUpdate,
    fitView, zoomIn, zoomOut
  } = useGraphState();

  const execution = useGraphExecution(runtime, nodes, edges, setNodes, setEdges);
  const selectedNode = nodes.find(n => n.id === selectedNodeId)?.data;
  
  // Get artifacts for selected node
  const selectedArtifact = selectedNodeId ? execution.artifacts[selectedNodeId] : null;

  // [NEW] Get upstream context for simulation
  // This depends on the execution hook exposing a helper or we calculate it here.
  // For now, we pass the execution logic's context hydration if available, 
  // or just null to let the view fallback.
  // Assuming useGraphExecution (or a future useDataFlow) provides getUpstreamContext:
  const upstreamContext = selectedNodeId && execution.getUpstreamContext 
      ? execution.getUpstreamContext(selectedNodeId) 
      : null;

  // Global Config State
  const [globalConfig, setGlobalConfig] = useState<GraphGlobalConfig>({
      env: "{}",
      policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
      contract: { developerBond: 0, adjudicationRubric: "" },
      meta: { name: "Untitled Agent", description: "" }
  });

  // Layout State
  const [consoleHeight] = useState(200); 
  const [showConsole, setShowConsole] = useState(true);

  return (
    <div className="agent-ide-root" style={{ display: 'flex', flexDirection: 'column', width: '100%', height: '100%', background: 'var(--bg-dark)', color: 'var(--text-primary)' }}>
      
      {/* HEADER */}
      <IDEHeader 
        projectName={globalConfig.meta.name}
        onRun={() => execution.runGraph(globalConfig)}
        onFit={() => fitView({ padding: 0.2 })}
        onZoomIn={() => zoomIn({ duration: 200 })}
        onZoomOut={() => zoomOut({ duration: 200 })}
        onSave={() => console.log("Save triggered")} 
        onOpen={() => console.log("Open triggered")}
      />

      {/* MAIN WORKSPACE */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        
        {/* LEFT: EXPLORER */}
        <Explorer 
            runtime={runtime} 
            onDragStart={(e, type) => {
                e.dataTransfer.setData("nodeType", type);
            }} 
        />

        {/* CENTER: CANVAS + CONSOLE */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
            
            {/* Canvas Area */}
            <div style={{ flex: 1, position: 'relative' }}>
                <Canvas 
                    nodes={nodes} edges={edges}
                    onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
                    onNodeSelect={handleNodeSelect}
                    onDrop={handleCanvasDrop}
                />
                
                {/* Canvas Overlay Controls */}
                <div style={{ position: 'absolute', top: 16, right: 16, zIndex: 10, display: 'flex', gap: 8 }}>
                    <button 
                        onClick={() => setShowConsole(!showConsole)}
                        style={{ background: 'var(--surface-3)', padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border-default)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '12px' }}
                    >
                        {showConsole ? 'Hide Logs' : 'Show Logs'}
                    </button>
                </div>
            </div>

            {/* Bottom Console */}
            {showConsole && (
                <div style={{ height: consoleHeight, borderTop: '1px solid var(--border-subtle)', flexShrink: 0 }}>
                    <Console 
                        logs={execution.logs} 
                        height={consoleHeight} 
                        selectedArtifact={selectedArtifact}
                    />
                </div>
            )}
        </div>

        {/* RIGHT: INSPECTOR */}
        <Inspector 
            // @ts-ignore
            selectedNode={selectedNode} 
            selectedEdge={null} 
            globalConfig={globalConfig}
            runtime={runtime}
            // @ts-ignore
            onUpdateNode={(id, cfg) => handleNodeUpdate(id, 'logic', cfg.logic)}
            onUpdateGlobal={(updates) => setGlobalConfig(prev => ({ ...prev, ...updates }))}
            // [NEW] Pass context to inspector
            upstreamContext={upstreamContext}
        />
      </div>
    </div>
  );
}

export function AgentEditor(props: AgentEditorProps) {
  return (
    <ReactFlowProvider>
      <AgentEditorContent {...props} />
    </ReactFlowProvider>
  );
}