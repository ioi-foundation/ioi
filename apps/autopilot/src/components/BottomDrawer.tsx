import { useEffect, useRef, useState } from "react";
import "./BottomDrawer.css";
import { TraceViewer, TraceSpan } from "./TraceViewer";

// Shared types from the backend events
export interface ExecutionLog {
  id: string;
  timestamp: string;
  level: "info" | "warn" | "error" | "debug";
  message: string;
  source: string;
}

export interface ExecutionStep {
  id: string;
  name: string;
  status: "running" | "success" | "blocked" | "error" | "idle";
  duration?: string;
  dataCount?: number;
  timestamp: string;
}

// [MODIFIED] Removed 'diff' from types
export type DrawerTab = "timeline" | "receipts" | "console";

interface BottomDrawerProps {
  height: number;
  collapsed: boolean;
  activeTab: DrawerTab;
  onTabChange: (tab: DrawerTab) => void;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
  onTraceClick?: (spanId: string) => void;
  onTraceHover?: (spanId: string | null) => void;
  
  // Real Data Props
  logs: ExecutionLog[];
  traceData: TraceSpan[]; 
  steps: ExecutionStep[];
  selectedNodeId: string | null;
  selectedArtifact: any | null;
}

export function BottomDrawer({
  height,
  collapsed,
  activeTab,
  onTabChange,
  onToggleCollapse,
  onResize,
  onTraceClick,
  onTraceHover,
  logs,
  traceData,
  selectedNodeId,
  selectedArtifact,
}: BottomDrawerProps) {
  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = height;

    const handleMouseMove = (e: MouseEvent) => {
      const delta = startY - e.clientY;
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

  return (
    <div
      className={`bottom-drawer ${collapsed ? "collapsed" : ""}`}
      style={{ height: collapsed ? 32 : height }}
    >
      {!collapsed && (
        <div className="drawer-resize-handle" onMouseDown={handleResizeStart} />
      )}

      {/* Tab bar */}
      <div className="drawer-tabs">
        <div className="drawer-tabs-left">
          {/* [MODIFIED] Removed 'diff' from the map array */}
          {(["timeline", "receipts", "console"] as DrawerTab[]).map((tab) => (
            <button
              key={tab}
              className={`drawer-tab ${activeTab === tab ? "active" : ""}`}
              onClick={() => {
                onTabChange(tab);
                if (collapsed) onToggleCollapse();
              }}
            >
              {tab === "timeline" && "⏱️"}
              {tab === "receipts" && "🧾"}
              {tab === "console" && "▸"}
              <span>{tab.charAt(0).toUpperCase() + tab.slice(1)}</span>
              {tab === "console" && logs.length > 0 && (
                <span className="tab-badge" style={{background: '#3F4652', fontSize: 9, padding: '0 4px', borderRadius: 4, marginLeft: 4}}>
                  {logs.length}
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="drawer-tabs-right">
          <button className="drawer-collapse-btn" onClick={onToggleCollapse}>
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              style={{ transform: collapsed ? "rotate(180deg)" : undefined }}
            >
              <path d="m6 9 6 6 6-6" />
            </svg>
          </button>
        </div>
      </div>

      {/* Content */}
      {!collapsed && (
        <div className="drawer-content">
          {activeTab === "timeline" && (
            <TimelineContent
              traceData={traceData}
              onTraceClick={onTraceClick}
              onTraceHover={onTraceHover}
            />
          )}
          {activeTab === "receipts" && <ReceiptsContent nodeId={selectedNodeId} artifact={selectedArtifact} />}
          {activeTab === "console" && <ConsoleContent logs={logs} />}
        </div>
      )}
    </div>
  );
}

function TimelineContent({
  traceData,
  onTraceClick,
  onTraceHover,
}: {
  traceData: TraceSpan[];
  onTraceClick?: (spanId: string) => void;
  onTraceHover?: (spanId: string | null) => void;
}) {
  const [selectedSpan, setSelectedSpan] = useState<TraceSpan | null>(null);
  const hasData = traceData.length > 0;

  // Auto-select the first span if data arrives and nothing is selected
  useEffect(() => {
    if (hasData && !selectedSpan) {
        setSelectedSpan(traceData[0]);
    }
  }, [hasData, traceData]);

  return (
    <div className="timeline-container" style={{ display: 'flex', height: '100%' }}>
      <div style={{ flex: 1, borderRight: '1px solid #2E333D', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div className="execution-bar">
            <div className="execution-status">
            {/* Show a pulsing dot if running, static if complete/ready */}
            <span className={`exec-status-dot ${hasData && traceData[0]?.status === 'running' ? 'running' : 'success'}`} />
            <span className="exec-status-text">
              {hasData ? "Live Execution Trace" : "Ready"}
            </span>
            <span className="exec-timestamp">{new Date().toLocaleTimeString()}</span>
            </div>
            <div className="execution-controls">
            <button className="exec-btn">Live Follow</button>
            </div>
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
            {hasData ? (
                <TraceViewer 
                    spans={traceData} 
                    onSelectSpan={(span) => {
                      setSelectedSpan(span);
                      onTraceClick?.(span.id);
                    }}
                    selectedSpanId={selectedSpan?.id}
                    onHoverSpan={onTraceHover}
                />
            ) : (
                <div className="empty-panel-state">
                    Run the graph to see execution timeline.
                </div>
            )}
        </div>
      </div>
      
      {/* Right Detail Pane */}
      {selectedSpan && (
        <div style={{ width: 320, background: '#111418', overflowY: 'auto', padding: 16, borderLeft: '1px solid #2E333D' }}>
          <div className="trace-detail-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className={`status-badge status-${selectedSpan.status}`}>{selectedSpan.type.toUpperCase()}</span>
                <span style={{ fontSize: 10, color: '#6B7280', fontFamily: 'monospace' }}>
                ID: {selectedSpan.id.slice(0,8)}
                </span>
            </div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: '#E5E7EB', wordBreak: 'break-all' }}>
              {selectedSpan.name}
            </h3>
          </div>
          
          <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {selectedSpan.metadata?.model && (
                <div className="detail-group">
                    <span className="detail-label">Model</span>
                    <span className="detail-value">{selectedSpan.metadata.model}</span>
                </div>
            )}
            
            {selectedSpan.startTime && (
                <div className="detail-group">
                    <span className="detail-label">Duration</span>
                    <span className="detail-value">
                        {selectedSpan.endTime ? `${selectedSpan.endTime - selectedSpan.startTime}ms` : 'Running...'}
                    </span>
                </div>
            )}

            {selectedSpan.metadata?.tokens !== undefined && (
                <div className="detail-group">
                    <span className="detail-label">Tokens</span>
                    <span className="detail-value">{selectedSpan.metadata.tokens}</span>
                </div>
            )}

            {selectedSpan.metadata?.inputs && (
                <div className="detail-group">
                    <span className="detail-label">Inputs</span>
                    <div className="code-block">
                        {JSON.stringify(selectedSpan.metadata.inputs, null, 2)}
                    </div>
                </div>
            )}

            {selectedSpan.metadata?.outputs && (
                <div className="detail-group">
                    <span className="detail-label">Outputs</span>
                    <div className="code-block">
                        {JSON.stringify(selectedSpan.metadata.outputs, null, 2)}
                    </div>
                </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ReceiptsContent({ nodeId, artifact }: { nodeId: string | null, artifact: any }) {
  if (!nodeId || !artifact) {
    return (
      <div className="empty-panel-state">
        Select a node with execution results to view its Receipt.
      </div>
    );
  }

  const outputStr = typeof artifact.output === 'string' ? artifact.output : JSON.stringify(artifact.output, null, 2);
  const metrics = artifact.metrics || {};

  return (
    <div className="receipts-content">
      <div className="receipt-detail">
        <div className="receipt-detail-header">
          <span className="receipt-detail-title">Receipt: {nodeId}</span>
          <span className="receipt-detail-meta">
            Timestamp: {new Date(artifact.timestamp).toLocaleString()} • Latency: {metrics.latency_ms || 0}ms
          </span>
        </div>
        <div className="receipt-detail-grid">
          <div className="receipt-detail-section">
            <h4>Output Artifact</h4>
            <div className="raw-text-view" style={{ maxHeight: 200, overflow: 'auto' }}>
                {outputStr}
            </div>
          </div>
          <div className="receipt-detail-section">
            <h4>Telemetry & Governance</h4>
            <div>Status: <span style={{color: '#34D399'}}>Success</span></div>
            <div>Signed: ✅ (Simulated)</div>
            {metrics.risk && <div>Risk Score: {metrics.risk}</div>}
            {metrics.eval_count !== undefined && <div>Tokens: {metrics.eval_count}</div>}
          </div>
        </div>
        <div className="receipt-detail-actions">
          <button className="btn btn-ghost">Copy JSON</button>
          <button className="btn btn-ghost">Verify Signature</button>
        </div>
      </div>
    </div>
  );
}

function ConsoleContent({ logs }: { logs: ExecutionLog[] }) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="console-content">
      <div className="console-output">
        {logs.map((log) => (
          <div key={log.id} className="console-line">
            <span className="console-time">[{log.timestamp.split('T')[1]?.slice(0,8)}]</span>
            <span className={`console-level level-${log.level}`}>{log.level.toUpperCase()}</span>
            <span className="console-msg">
                <span style={{opacity: 0.6, marginRight: 8}}>{log.source}:</span>
                {log.message}
            </span>
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </div>
  );
}
