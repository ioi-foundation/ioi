import { useEffect, useRef } from "react";
import "./BottomDrawer.css";

// Shared types from the backend events
interface ExecutionLog {
  id: string;
  timestamp: string;
  level: "info" | "warn" | "error" | "debug";
  message: string;
  source: string;
}

interface ExecutionStep {
  id: string;
  name: string;
  status: "running" | "success" | "blocked" | "error" | "idle";
  duration?: string;
  dataCount?: number;
  timestamp: string;
}

export type DrawerTab = "timeline" | "receipts" | "diff" | "console";

interface BottomDrawerProps {
  height: number;
  collapsed: boolean;
  activeTab: DrawerTab;
  onTabChange: (tab: DrawerTab) => void;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
  
  // [NEW] Real Data Props
  logs: ExecutionLog[];
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
  logs,
  steps,
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
          {(["timeline", "receipts", "diff", "console"] as DrawerTab[]).map((tab) => (
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
              {tab === "diff" && "⎇"}
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
          {activeTab === "timeline" && <TimelineContent steps={steps} />}
          {activeTab === "receipts" && <ReceiptsContent nodeId={selectedNodeId} artifact={selectedArtifact} />}
          {activeTab === "diff" && <DiffContent />}
          {activeTab === "console" && <ConsoleContent logs={logs} />}
        </div>
      )}
    </div>
  );
}

function TimelineContent({ steps }: { steps: ExecutionStep[] }) {
  if (steps.length === 0) {
    return (
      <div className="empty-panel-state">
        Run the graph to generate an execution timeline.
      </div>
    );
  }

  return (
    <div className="timeline-content">
      <div className="execution-bar">
        <div className="execution-status">
          <span className="exec-status-dot success" />
          <span className="exec-status-text">Latest Run</span>
          <span className="exec-timestamp">{steps[steps.length - 1]?.timestamp}</span>
        </div>
        <div className="execution-controls">
          <button className="exec-btn">Export Trace</button>
        </div>
      </div>

      <div className="data-grid">
        <div className="grid-header">
          <div className="grid-cell cell-id">#</div>
          <div className="grid-cell cell-time">Time</div>
          <div className="grid-cell cell-node">Node</div>
          <div className="grid-cell cell-duration">Duration</div>
          <div className="grid-cell cell-data">Data</div>
          <div className="grid-cell cell-status">Status</div>
        </div>
        {steps.map((step, idx) => (
          <div key={step.id + idx} className={`grid-row row-${step.status}`}>
            <div className="grid-cell cell-id">{idx + 1}</div>
            <div className="grid-cell cell-time">{step.timestamp.split('T')[1]?.slice(0,12)}</div>
            <div className="grid-cell cell-node">{step.name}</div>
            <div className="grid-cell cell-duration">{step.duration || "—"}</div>
            <div className="grid-cell cell-data">{step.dataCount !== undefined ? `${step.dataCount} bytes` : "—"}</div>
            <div className="grid-cell cell-status">
              <span className={`status-badge status-${step.status}`}>
                {step.status.toUpperCase()}
              </span>
            </div>
          </div>
        ))}
      </div>
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

function DiffContent() {
  return (
    <div className="diff-content">
      <div className="empty-panel-state" style={{ padding: 40 }}>
        Comparison not available in Local Mode. 
        <br/><br/>
        Connect to IOI Kernel History to compare runs.
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