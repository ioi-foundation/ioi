// apps/autopilot/src/components/RightPanel/RightPanel.tsx
import { useState, useEffect } from "react";
import { RightPanelProps, InspectorTab, GraphTab } from "./types";
import { DEFAULT_GRAPH_CONFIG } from "./utils";
// [UPDATED] Import ContractIcon
import { ShieldIcon, BrainIcon, TerminalIcon, GlobeIcon, SettingsIcon, DnaIcon, ContractIcon } from "./icons";
import { Edge } from "../../types";

// Views
import { LogicView } from "./views/LogicView";
import { PolicyView } from "./views/PolicyView";
import { SimulationView } from "./views/SimulationView";
import { DnaView } from "./views/DnaView";
import { GraphConfigView } from "./views/GraphConfigView";
import { EdgeView } from "./views/EdgeView";

import "./RightPanel.css";
// PolicyInspector.css contains shared styling for law cards
import "../PolicyInspector.css";

// Extend props locally to include edge inspection capabilities
interface ExtendedRightPanelProps extends RightPanelProps {
  selectedEdge?: Edge | null;
  onUpdateEdge?: (edgeId: string, data: any) => void;
  edgeThroughput?: any;
}

export function RightPanel({ 
  width, 
  selectedNode, 
  // [NEW] Destructure nodes and edges for logic view suggestions
  nodes = [],
  edges = [],
  onUpdateNode, 
  graphConfig = DEFAULT_GRAPH_CONFIG,
  onUpdateGraph,
  upstreamData, 
  onRunComplete,
  // New props for Edge Inspection
  selectedEdge,
  onUpdateEdge,
  edgeThroughput
}: ExtendedRightPanelProps) {
  
  const [activeTab, setActiveTab] = useState<InspectorTab>("LOGIC");
  const [activeGraphTab, setActiveGraphTab] = useState<GraphTab>("ENV");

  useEffect(() => {
    // Reset to Logic when selecting a new node
    if (selectedNode) setActiveTab("LOGIC");
  }, [selectedNode?.id]);

  const handleUpdate = (section: 'logic' | 'law', updates: any) => {
    if (selectedNode && onUpdateNode) {
      onUpdateNode(selectedNode.id, section, updates);
    }
  };

  const handleGraphUpdate = (section: keyof typeof graphConfig, updates: any) => {
    if (!onUpdateGraph) return;
    if (section === "env") {
      onUpdateGraph({ env: updates });
      return;
    }
    onUpdateGraph({ [section]: { ...(graphConfig[section] as object), ...updates } });
  };

  // [NEW] Calculate upstream nodes for context suggestions
  const upstreamNodes = selectedNode 
    ? edges
        .filter(e => e.to === selectedNode.id)
        .map(e => nodes.find(n => n.id === e.from))
        .filter((n): n is typeof n & object => n !== undefined)
    : [];

  // --- RENDER EDGE INSPECTOR (If edge selected and no node selected) ---
  if (selectedEdge && !selectedNode) {
    return (
      <aside className="right-panel" style={{ width }}>
        {/* EDGE HEADER */}
        <div className="panel-header">
          <div className="panel-title">
            <span className="panel-node-type" style={{background: '#3F4652', color: '#E5E7EB'}}>PIPE</span>
            <span className="panel-node-name">{selectedEdge.from} → {selectedEdge.to}</span>
          </div>
        </div>

        {/* EDGE TABS (Single inspector tab for edges) */}
        <div className="inspector-tabs">
           <button className="inspector-tab active">
             <TerminalIcon /> Inspector
           </button>
        </div>

        {/* EDGE CONTENT */}
        <div className="panel-content">
          <EdgeView 
            edge={selectedEdge} 
            throughputData={edgeThroughput}
            onUpdateEdge={onUpdateEdge!} 
          />
        </div>
      </aside>
    );
  }

  // --- RENDER GRAPH ROOT CONFIG (If no node or edge selected) ---
  if (!selectedNode) {
    return (
      <aside className="right-panel" style={{ width }}>
        {/* GRAPH HEADER */}
        <div className="panel-header">
          <div className="panel-title">
            <span className="panel-node-type" style={{background: '#4B5563', color: '#E5E7EB'}}>ROOT</span>
            <span className="panel-node-name">System Constitution</span>
          </div>
        </div>

        {/* GRAPH TABS */}
        <div className="inspector-tabs">
          <button 
            className={`inspector-tab ${activeGraphTab === "ENV" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("ENV")}
          >
            <GlobeIcon /> Env
          </button>
          <button 
            className={`inspector-tab ${activeGraphTab === "POLICY" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("POLICY")}
          >
            <ShieldIcon /> Policy
          </button>
          
          {/* [NEW] CONTRACT TAB BUTTON */}
          <button 
            className={`inspector-tab ${activeGraphTab === "CONTRACT" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("CONTRACT")}
          >
            <ContractIcon /> SLA
          </button>
          
          <button 
            className={`inspector-tab ${activeGraphTab === "META" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("META")}
          >
            <SettingsIcon /> Meta
          </button>
        </div>

        {/* GRAPH CONTENT */}
        <div className="panel-content">
          <GraphConfigView 
            activeTab={activeGraphTab} 
            config={graphConfig} 
            onUpdate={handleGraphUpdate} 
          />
        </div>
      </aside>
    );
  }

  // --- RENDER NODE INSPECTOR ---
  return (
    <aside className="right-panel" style={{ width }}>
      {/* HEADER */}
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-node-type">{selectedNode.type.toUpperCase()}</span>
          <span className="panel-node-name">{selectedNode.name}</span>
        </div>
        {selectedNode.attested && (
           <span className="attested-badge" title="Cryptographically Signed Policy">✓ Signed</span>
        )}
      </div>

      {/* 4-WAY TAB SWITCHER */}
      <div className="inspector-tabs">
        <button 
          className={`inspector-tab ${activeTab === "LOGIC" ? "active" : ""}`}
          onClick={() => setActiveTab("LOGIC")}
        >
          <BrainIcon /> Logic
        </button>
        <button 
          className={`inspector-tab ${activeTab === "LAW" ? "active" : ""}`}
          onClick={() => setActiveTab("LAW")}
        >
          <ShieldIcon /> Law
        </button>
        <button 
          className={`inspector-tab ${activeTab === "SIM" ? "active" : ""}`}
          onClick={() => setActiveTab("SIM")}
        >
          <TerminalIcon /> Run
        </button>
        <button 
          className={`inspector-tab ${activeTab === "DNA" ? "active" : ""}`}
          onClick={() => setActiveTab("DNA")}
          title="Evolutionary Lineage"
        >
          <DnaIcon /> DNA
        </button>
      </div>

      {/* CONTENT AREA */}
      <div className="panel-content">
        {activeTab === "LOGIC" && (
            <LogicView 
                node={selectedNode} 
                onUpdate={handleUpdate} 
                // [NEW] Pass upstream nodes for variable injection
                upstreamNodes={upstreamNodes}
            />
        )}
        {activeTab === "LAW" && <PolicyView node={selectedNode} onUpdate={handleUpdate} />}
        {activeTab === "SIM" && (
          <SimulationView 
            node={selectedNode} 
            upstreamData={upstreamData}
            onRunComplete={onRunComplete}
          />
        )}
        {activeTab === "DNA" && (
            <DnaView node={selectedNode} /> 
        )}
      </div>
    </aside>
  );
}