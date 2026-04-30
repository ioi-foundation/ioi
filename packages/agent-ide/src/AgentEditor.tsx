import { useCallback, useEffect, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import { AgentWorkbenchRuntime } from "./runtime/agent-runtime";
import { useGraphState } from "./hooks/useGraphState";
import { useGraphExecution } from "./hooks/useGraphExecution";
import { GraphGlobalConfig, Node, ProjectFile } from "./types/graph";

import { Canvas } from "./features/Editor/Canvas/Canvas";
import { Inspector } from "./features/Editor/Inspector/Inspector";
import { Explorer } from "./features/Editor/Explorer/Explorer";
import { Console } from "./features/Editor/BottomPanel/Console";
import { IDEHeader } from "./features/Editor/Header/IDEHeader";

import "./AgentEditor.css";
import "./styles/theme.css";

export interface AgentEditorProps {
  runtime: AgentWorkbenchRuntime;
  initialFile?: ProjectFile | null;
  onInitialFileLoaded?: () => void;
  onOpenSystemSettings?: () => void;
}

const DEFAULT_MODEL_BINDINGS = {
  reasoning: { modelId: "", required: false },
  vision: { modelId: "", required: false },
  embedding: { modelId: "", required: false },
  image: { modelId: "", required: false },
};

const DEFAULT_CAPABILITY_REQUIREMENTS = {
  reasoning: { required: false, bindingKey: "reasoning" },
  vision: { required: false, bindingKey: "vision" },
  embedding: { required: false, bindingKey: "embedding" },
  image: { required: false, bindingKey: "image" },
  speech: { required: false },
  video: { required: false },
};

const DEFAULT_GLOBAL_CONFIG: GraphGlobalConfig = {
  env: "{}",
  modelBindings: DEFAULT_MODEL_BINDINGS,
  requiredCapabilities: DEFAULT_CAPABILITY_REQUIREMENTS,
  policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
  contract: { developerBond: 0, adjudicationRubric: "" },
  meta: { name: "Untitled Agent", description: "" }
};

function normalizeGlobalConfig(config?: Partial<GraphGlobalConfig> | null): GraphGlobalConfig {
  return {
    ...DEFAULT_GLOBAL_CONFIG,
    ...config,
    modelBindings: {
      ...DEFAULT_MODEL_BINDINGS,
      ...(config?.modelBindings ?? {}),
    },
    requiredCapabilities: {
      ...DEFAULT_CAPABILITY_REQUIREMENTS,
      ...(config?.requiredCapabilities ?? {}),
    },
    policy: {
      ...DEFAULT_GLOBAL_CONFIG.policy,
      ...(config?.policy ?? {}),
    },
    contract: {
      ...DEFAULT_GLOBAL_CONFIG.contract,
      ...(config?.contract ?? {}),
    },
    meta: {
      ...DEFAULT_GLOBAL_CONFIG.meta,
      ...(config?.meta ?? {}),
    },
  };
}

const CONSOLE_HEIGHT = 220;

function AgentEditorContent({
  runtime,
  initialFile,
  onInitialFileLoaded,
  onOpenSystemSettings,
}: AgentEditorProps) {
  const {
    nodes, edges, setNodes, setEdges,
    onNodesChange, onEdgesChange, onConnect,
    handleCanvasDrop, selectedNodeId, handleNodeSelect, handleNodeUpdate,
    fitView, zoomIn, zoomOut, replaceGraph
  } = useGraphState();

  const execution = useGraphExecution(runtime, nodes, edges, setNodes, setEdges);
  const selectedNode =
    (nodes.find((node) => node.id === selectedNodeId)?.data as Node | undefined) ?? null;
  const selectedOutput = selectedNodeId ? execution.outputs[selectedNodeId] : null;
  const upstreamContext = selectedNodeId
    ? execution.getUpstreamContext(selectedNodeId)
    : null;

  const [globalConfig, setGlobalConfig] = useState<GraphGlobalConfig>(DEFAULT_GLOBAL_CONFIG);
  const [showConsole, setShowConsole] = useState(false);

  const loadProjectIntoEditor = useCallback((project: ProjectFile) => {
    replaceGraph(project);
    setGlobalConfig(normalizeGlobalConfig(project.global_config ?? DEFAULT_GLOBAL_CONFIG));
    requestAnimationFrame(() => {
      fitView({ padding: 0.2 });
    });
  }, [fitView, replaceGraph]);

  useEffect(() => {
    if (!initialFile) return;
    loadProjectIntoEditor(initialFile);
    onInitialFileLoaded?.();
  }, [initialFile, loadProjectIntoEditor, onInitialFileLoaded]);

  return (
    <div className="agent-ide-root">
      <IDEHeader 
        projectName={globalConfig.meta.name}
        onRun={() => execution.runGraph(globalConfig)}
        onFit={() => fitView({ padding: 0.2 })}
        onZoomIn={() => zoomIn({ duration: 200 })}
        onZoomOut={() => zoomOut({ duration: 200 })}
      />

      <div className="agent-ide-workspace">
        <div className="agent-ide-sidebar">
          <Explorer
              runtime={runtime}
              onLoadProject={loadProjectIntoEditor}
              onDragStart={(e, type, name, schema) => {
                  e.dataTransfer.setData("nodeType", type);
                  e.dataTransfer.setData("nodeName", name);
                  if (schema) {
                    e.dataTransfer.setData("nodeSchema", schema);
                  }
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
                  selectedArtifact={selectedOutput}
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
              selectedNode={selectedNode}
              globalConfig={globalConfig}
              runtime={runtime}
              onUpdateNode={handleNodeUpdate}
              onUpdateGlobal={(updates) =>
                setGlobalConfig((prev) =>
                  normalizeGlobalConfig({
                    ...prev,
                    ...updates,
                    modelBindings: {
                      ...prev.modelBindings,
                      ...(updates.modelBindings ?? {}),
                    },
                    requiredCapabilities: {
                      ...prev.requiredCapabilities,
                      ...(updates.requiredCapabilities ?? {}),
                    },
                    policy: { ...prev.policy, ...(updates.policy ?? {}) },
                    contract: { ...prev.contract, ...(updates.contract ?? {}) },
                    meta: { ...prev.meta, ...(updates.meta ?? {}) },
                  })
                )
              }
              onOpenSystemSettings={onOpenSystemSettings}
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
