import { useState, useEffect } from "react";
import {
  FirewallPolicy,
  GraphGlobalConfig,
  Node,
  NodeLogic,
} from "../../../types/graph";
import { AgentWorkbenchRuntime } from "../../../runtime/agent-runtime";
import { LogicView } from "./views/LogicView";
import { PolicyView } from "./views/PolicyView";
import { SimulationView } from "./views/SimulationView";
import { GraphConfigView } from "./views/GraphConfigView";
import { DnaView } from "./views/DnaView";
import "./Inspector.css";

interface InspectorProps {
  selectedNode: Node | null;
  globalConfig?: GraphGlobalConfig;
  upstreamContext?: unknown;
  runtime: AgentWorkbenchRuntime;
  onOpenSystemSettings?: () => void;
  onUpdateNode: (
    id: string,
    section: "logic" | "law",
    updates: Partial<NodeLogic> | Partial<FirewallPolicy>,
  ) => void;
  onUpdateGlobal?: (config: Partial<GraphGlobalConfig>) => void;
}

export function Inspector({
  selectedNode,
  globalConfig,
  upstreamContext,
  runtime,
  onOpenSystemSettings,
  onUpdateNode,
  onUpdateGlobal,
}: InspectorProps) {
  const [activeTab, setActiveTab] = useState<'logic' | 'law' | 'run' | 'dna'>('logic');

  useEffect(() => {
      if (selectedNode) setActiveTab('logic');
  }, [selectedNode?.id]);

  if (!selectedNode) {
    return (
        <aside className="inspector-panel">
            <GraphConfigView 
                config={globalConfig || {} as any} 
                runtime={runtime}
                onOpenSystemSettings={onOpenSystemSettings}
                onChange={(updates) => onUpdateGlobal?.(updates)}
            />
        </aside>
    );
  }

  const config = selectedNode.config ?? { logic: {}, law: {} };

  return (
    <aside className="inspector-panel">
      <div className="inspector-header">
        <div className="node-identity">
            <span className="node-type">{selectedNode.type}</span>
            <span className="node-id">{selectedNode.id}</span>
        </div>
        <div className="inspector-tabs">
            <button className={activeTab === 'logic' ? 'active' : ''} onClick={() => setActiveTab('logic')}>Logic</button>
            <button className={activeTab === 'law' ? 'active' : ''} onClick={() => setActiveTab('law')}>Law</button>
            <button className={activeTab === 'run' ? 'active' : ''} onClick={() => setActiveTab('run')}>Run</button>
            <button className={activeTab === 'dna' ? 'active' : ''} onClick={() => setActiveTab('dna')}>DNA</button>
        </div>
      </div>
      
      <div className="inspector-content">
        {activeTab === 'logic' && (
            <LogicView 
                type={selectedNode.type}
                availableModelRefs={Object.keys(globalConfig?.modelBindings ?? {})}
                config={config.logic} 
                onChange={(updates) => onUpdateNode(selectedNode.id, "logic", updates)}
            />
        )}
        {activeTab === 'law' && (
            <PolicyView 
                config={config.law} 
                onChange={(updates) => onUpdateNode(selectedNode.id, "law", updates)}
            />
        )}
        {activeTab === 'run' && (
            <SimulationView 
                node={selectedNode}
                globalConfig={globalConfig}
                upstreamContext={upstreamContext}
                runtime={runtime}
            />
        )}
        {activeTab === 'dna' && (
            <DnaView node={selectedNode} />
        )}
      </div>
    </aside>
  );
}
