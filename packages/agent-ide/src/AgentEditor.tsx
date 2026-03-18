// packages/agent-ide/src/AgentEditor.tsx
import { useCallback, useEffect, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import { AgentRuntime } from "./runtime/agent-runtime";
import { useGraphState } from "./hooks/useGraphState";
import { useGraphExecution } from "./hooks/useGraphExecution";
import { GraphGlobalConfig, ProjectFile } from "./types/graph";

// Sub-components
import { Canvas } from "./features/Editor/Canvas/Canvas";
import { Inspector } from "./features/Editor/Inspector/Inspector";
import { Explorer } from "./features/Editor/Explorer/Explorer"; 
import { Console } from "./features/Editor/BottomPanel/Console"; 
import { IDEHeader } from "./features/Editor/Header/IDEHeader";

import "./AgentEditor.css";
import "./styles/theme.css";

export interface AgentEditorProps {
  runtime: AgentRuntime;
  initialFile?: any; 
}

const DEFAULT_GLOBAL_CONFIG: GraphGlobalConfig = {
  env: "{}",
  policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
  contract: { developerBond: 0, adjudicationRubric: "" },
  meta: { name: "Untitled Agent", description: "" }
};

const CONSOLE_HEIGHT = 220;

function AgentEditorContent({ runtime, initialFile }: AgentEditorProps) {
  const { 
    nodes, edges, setNodes, setEdges, 
    onNodesChange, onEdgesChange, onConnect, 
    handleCanvasDrop, selectedNodeId, handleNodeSelect, handleNodeUpdate,
    fitView, zoomIn, zoomOut, replaceGraph
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
  const [globalConfig, setGlobalConfig] = useState<GraphGlobalConfig>(DEFAULT_GLOBAL_CONFIG);

  // Layout State
  const [showConsole, setShowConsole] = useState(false);

  const loadProjectIntoEditor = useCallback((project: ProjectFile) => {
    replaceGraph(project);
    setGlobalConfig(project.global_config ?? DEFAULT_GLOBAL_CONFIG);
    requestAnimationFrame(() => {
      fitView({ padding: 0.2 });
    });
  }, [fitView, replaceGraph]);

  useEffect(() => {
    if (!initialFile) return;
    loadProjectIntoEditor(initialFile as ProjectFile);
  }, [initialFile, loadProjectIntoEditor]);

  return (
    <div className="agent-ide-root">
      <IDEHeader 
        projectName={globalConfig.meta.name}
        onRun={() => execution.runGraph(globalConfig)}
        onFit={() => fitView({ padding: 0.2 })}
        onZoomIn={() => zoomIn({ duration: 200 })}
        onZoomOut={() => zoomOut({ duration: 200 })}
        onSave={() => console.log("Save triggered")} 
        onOpen={() => console.log("Open triggered")}
      />

      <div className="agent-ide-workspace">
        <div className="agent-ide-sidebar">
          <Explorer 
              runtime={runtime} 
              onLoadProject={loadProjectIntoEditor}
              onDragStart={(e, type) => {
                  e.dataTransfer.setData("nodeType", type);
              }} 
          />
        </div>

        <div className="agent-ide-editor-pane">
          <div className="agent-ide-canvas-shell">
            <Canvas 
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
                onNodeSelect={handleNodeSelect}
                onDrop={handleCanvasDrop}
            />

            <div className="agent-ide-canvas-actions">
              <button
                type="button"
                className="agent-ide-canvas-action"
                onClick={() => setShowConsole((value) => !value)}
              >
                {showConsole ? "Hide drawer" : "Open drawer"}
              </button>
            </div>
          </div>

          {showConsole ? (
            <div className="agent-ide-console-slot">
              <Console 
                  logs={execution.logs} 
                  height={CONSOLE_HEIGHT} 
                  selectedArtifact={selectedArtifact}
                  onCollapse={() => setShowConsole(false)}
              />
            </div>
          ) : (
            <button
              type="button"
              className="agent-ide-console-collapsed"
              onClick={() => setShowConsole(true)}
            >
              <span>Logs</span>
              <span>Trace</span>
              <span>Receipts</span>
            </button>
          )}
        </div>

        <div className="agent-ide-inspector">
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
