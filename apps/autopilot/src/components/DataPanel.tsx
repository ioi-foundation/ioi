// src/components/DataPanel.tsx
import { useState, useEffect } from "react";
import "./DataPanel.css";

interface DataPanelProps {
  height: number;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
  selectedNodeName?: string;
  artifact?: {
    output?: string;
    metrics?: any;
    timestamp: number;
    input_snapshot?: any;
    // [NEW] Explicit context slice from retrieval nodes
    context_slice?: any; 
  };
}

export function DataPanel({
  height,
  collapsed,
  onToggleCollapse,
  onResize,
  selectedNodeName,
  artifact,
}: DataPanelProps) {
  // [MODIFIED] Added 'context' to tab state options
  const [activeTab, setActiveTab] = useState("inspector");

  // Auto-switch to context tab if it's a retrieval node and context is available
  useEffect(() => {
    if (artifact?.context_slice) {
        setActiveTab("context");
    } else {
        // Reset if switching nodes
        setActiveTab("inspector");
    }
  }, [artifact?.context_slice, selectedNodeName]);

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
        
        {/* [NEW] Context Tab */}
        {artifact?.context_slice && (
            <button
            className={`panel-tab ${activeTab === "context" ? "active" : ""}`}
            onClick={() => setActiveTab("context")}
            >
            <span>Retrieved Context</span>
            <span className="tab-badge" style={{background: '#34D399', color: '#064E3B'}}>
                {Array.isArray(artifact.context_slice) ? artifact.context_slice.length : 0} Docs
            </span>
            </button>
        )}

        <button
          className={`panel-tab ${activeTab === "inputs" ? "active" : ""}`}
          onClick={() => setActiveTab("inputs")}
        >
          <span>Context Inputs</span>
        </button>

        <button
          className={`panel-tab ${activeTab === "inspector" ? "active" : ""}`}
          onClick={() => setActiveTab("inspector")}
        >
          <span>Data Inspector</span>
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
          ) : activeTab === "context" ? (
             // [NEW] Context Viewer
             <ContextViewer docs={artifact.context_slice} />
          ) : activeTab === "inputs" ? (
             artifact.input_snapshot ? (
                <JsonInspector data={artifact.input_snapshot} />
             ) : (
                <div className="empty-panel-state">No input snapshot captured.</div>
             )
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

// [NEW] Context Viewer Component
interface RetrievedDoc {
    content: string;
    score: number;
    frame_id: number;
    source?: string; // Optional metadata
}

function ContextViewer({ docs }: { docs: any }) {
    const docList = Array.isArray(docs) ? docs as RetrievedDoc[] : [];

    if (docList.length === 0) {
        return <div className="empty-panel-state">No documents retrieved.</div>;
    }

    return (
        <div className="context-viewer" style={{padding: 16, overflowY: 'auto', height: '100%'}}>
            {docList.map((doc, i) => (
                <div key={i} style={{marginBottom: 16, background: '#1F2329', border: '1px solid #2E333D', borderRadius: 6, overflow: 'hidden'}}>
                    <div style={{
                        padding: '8px 12px', 
                        background: '#252A33', 
                        borderBottom: '1px solid #2E333D',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                    }}>
                        <div style={{display: 'flex', gap: 8, alignItems: 'center'}}>
                            <span style={{fontSize: 12, fontWeight: 600, color: '#E5E7EB'}}>Result #{i + 1}</span>
                            <span style={{fontSize: 10, fontFamily: 'monospace', color: '#6B7280'}}>Frame: {doc.frame_id}</span>
                        </div>
                        <div style={{
                            fontSize: 10, 
                            fontWeight: 600, 
                            color: doc.score > 0.8 ? '#34D399' : '#F59E0B',
                            background: doc.score > 0.8 ? 'rgba(52, 211, 153, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                            padding: '2px 6px',
                            borderRadius: 4
                        }}>
                            {(doc.score * 100).toFixed(1)}% Match
                        </div>
                    </div>
                    <div style={{padding: 12, fontSize: 11, fontFamily: 'monospace', color: '#D1D5DB', whiteSpace: 'pre-wrap', lineHeight: 1.5}}>
                        {doc.content}
                    </div>
                </div>
            ))}
        </div>
    );
}