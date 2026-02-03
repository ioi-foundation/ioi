import { useState, useEffect } from "react";
import { Node, GraphGlobalConfig } from "../../../types/graph";
import { AgentRuntime } from "../../../runtime/agent-runtime";
import { LogicView } from "./views/LogicView";
import { PolicyView } from "./views/PolicyView";
import { SimulationView } from "./views/SimulationView";
import { GraphConfigView } from "./views/GraphConfigView";
import { DnaView } from "./views/DnaView"; // [NEW]
import { EdgeView } from "./views/EdgeView"; // [NEW]
import "./Inspector.css";

interface InspectorProps {
  selectedNode: Node | null;
  selectedEdge: any | null; 
  globalConfig?: GraphGlobalConfig;
  runtime: AgentRuntime;
  onUpdateNode: (id: string, config: any) => void;
  onUpdateGlobal?: (config: Partial<GraphGlobalConfig>) => void;
}

export function Inspector({ selectedNode, selectedEdge, globalConfig, runtime, onUpdateNode, onUpdateGlobal }: InspectorProps) {
  const [activeTab, setActiveTab] = useState<'logic' | 'law' | 'run' | 'dna'>('logic');

  // Reset tab when selection changes
  useEffect(() => {
      if (selectedNode) setActiveTab('logic');
  }, [selectedNode?.id]);

  // Case 1: No Selection -> Global Config
  if (!selectedNode && !selectedEdge) {
    return (
        <aside className="inspector-panel">
            <GraphConfigView 
                config={globalConfig || {} as any} 
                onChange={(updates) => onUpdateGlobal?.(updates)}
            />
        </aside>
    );
  }

  // Case 2: Edge Selection
  if (selectedEdge && !selectedNode) {
      return (
        <aside className="inspector-panel">
            <EdgeView edge={selectedEdge} />
        </aside>
      );
  }

  // Case 3: Node Selection
  const config = selectedNode!.config || { logic: {}, law: {} };

  return (
    <aside className="inspector-panel">
      <div className="inspector-header">
        <div className="node-identity">
            <span className="node-type">{selectedNode!.type}</span>
            <span className="node-id">{selectedNode!.id}</span>
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
                type={selectedNode!.type}
                config={config.logic} 
                // @ts-ignore
                onChange={(updates) => onUpdateNode(selectedNode!.id, { ...config, logic: { ...config.logic, ...updates } })}
            />
        )}
        {activeTab === 'law' && (
            <PolicyView 
                config={config.law} 
                // @ts-ignore
                onChange={(updates) => onUpdateNode(selectedNode!.id, { ...config, law: { ...config.law, ...updates } })}
            />
        )}
        {activeTab === 'run' && (
            <SimulationView 
                node={selectedNode!}
                runtime={runtime}
                onRunComplete={(res) => console.log("Run complete", res)}
            />
        )}
        {activeTab === 'dna' && (
            <DnaView node={selectedNode!} />
        )}
      </div>
    </aside>
  );
}