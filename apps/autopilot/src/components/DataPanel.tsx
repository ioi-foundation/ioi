// src/components/DataPanel.tsx
import { useState, useEffect } from "react";
import "./DataPanel.css";

interface DataPanelProps {
  height: number;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
  selectedNodeName?: string;
  // [NEW] Real execution artifact from Rust kernel
  artifact?: {
    output?: string;
    metrics?: any;
    timestamp: number;
  };
  // Keeping for backward compatibility if needed, though unused in new logic
  isRunning?: boolean; 
}

export function DataPanel({
  height,
  collapsed,
  onToggleCollapse,
  onResize,
  selectedNodeName,
  artifact,
}: DataPanelProps) {
  const [activeTab, setActiveTab] = useState("inspector");

  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = height;

    const handleMouseMove = (ev: MouseEvent) => {
      const delta = startY - ev.clientY;
      const newHeight = Math.max(100, Math.min(startHeight + delta, 600));
      onResize(newHeight);
    };

    const handleMouseUp = () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
  };

  // Safe parsing of JSON outputs
  const parsedOutput = artifact?.output ? tryParseJson(artifact.output) : null;

  return (
    <div
      className="data-panel"
      style={{ height: collapsed ? 32 : height }}
    >
      <div className="panel-resize-handle" onMouseDown={handleResizeStart} />

      {/* Header */}
      <div className="panel-tabbar">
        <div className="panel-context-label">
            {selectedNodeName ? `Node: ${selectedNodeName}` : "No Node Selected"}
        </div>
        <div className="vertical-sep" />
        <button
          className={`panel-tab ${activeTab === "inspector" ? "active" : ""}`}
          onClick={() => setActiveTab("inspector")}
        >
          <span>Data Inspector</span>
          {artifact && <span className="tab-badge">Updated</span>}
        </button>
        <button
          className={`panel-tab ${activeTab === "raw" ? "active" : ""}`}
          onClick={() => setActiveTab("raw")}
        >
          <span>Raw Output</span>
        </button>
        
        <div style={{ flex: 1 }} />
        
        {artifact?.metrics && (
            <div className="panel-metric">
                Latency: <span className="metric-val">{artifact.metrics.latency_ms}ms</span>
            </div>
        )}
        
        <button className="panel-tab" onClick={onToggleCollapse}>
          {collapsed ? "▲" : "▼"}
        </button>
      </div>

      {/* Content */}
      {!collapsed && (
        <div className="panel-content" style={{ height: "100%", overflow: "hidden" }}>
          {!selectedNodeName ? (
             <div className="empty-panel-state">Select a node to inspect its data artifacts.</div>
          ) : !artifact ? (
             <div className="empty-panel-state">No execution data available. Run the graph to generate artifacts.</div>
          ) : activeTab === "inspector" ? (
             <JsonInspector data={parsedOutput || artifact.output} />
          ) : (
             <RawViewer text={artifact.output || ""} />
          )}
        </div>
      )}
    </div>
  );
}

function tryParseJson(str: string) {
    try { return JSON.parse(str); } catch { return null; }
}

function JsonInspector({ data }: { data: any }) {
    if (typeof data === 'string') {
        return <div className="raw-text-view">{data}</div>;
    }

    return (
        <div className="json-tree-view">
            <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
    );
}

function RawViewer({ text }: { text: string }) {
    return (
        <textarea 
            readOnly 
            className="raw-output-area" 
            value={text} 
        />
    );
}