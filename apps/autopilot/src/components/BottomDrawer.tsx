import { DrawerTab } from "../App";
import "./BottomDrawer.css";

interface BottomDrawerProps {
  height: number;
  collapsed: boolean;
  activeTab: DrawerTab;
  onTabChange: (tab: DrawerTab) => void;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
}

// Mock execution data
const mockExecution = {
  runId: 128,
  timestamp: "2026-01-02 19:52:04",
  mode: "Local→Session",
  result: "success" as const,
  steps: [
    { id: 1, name: "Trigger: Cron", time: "00:00.0", status: "success", duration: "12ms", dataCount: 1 },
    { id: 2, name: "Read Invoices", time: "00:00.2", status: "success", duration: "240ms", dataCount: 3 },
    { id: 3, name: "Parse + Classify", time: "00:01.1", status: "success", duration: "1.2s", dataCount: 3 },
    { id: 4, name: "Policy Gate", time: "00:01.8", status: "success", duration: "8ms", dataCount: 1 },
    { id: 5, name: "Burst Router", time: "00:02.0", status: "success", duration: "340ms", dataCount: 1 },
    { id: 6, name: "Slack Alert", time: "00:03.4", status: "success", duration: "180ms", dataCount: 1 },
  ],
};

export function BottomDrawer({
  height,
  collapsed,
  activeTab,
  onTabChange,
  onToggleCollapse,
  onResize,
}: BottomDrawerProps) {
  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = height;

    const handleMouseMove = (e: MouseEvent) => {
      const delta = startY - e.clientY;
      const newHeight = Math.max(100, Math.min(startHeight + delta, 500));
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
      {/* Resize handle */}
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
          {activeTab === "timeline" && <TimelineContent />}
          {activeTab === "receipts" && <ReceiptsContent />}
          {activeTab === "diff" && <DiffContent />}
          {activeTab === "console" && <ConsoleContent />}
        </div>
      )}
    </div>
  );
}

function TimelineContent() {
  return (
    <div className="timeline-content">
      {/* Execution Bar */}
      <div className="execution-bar">
        <div className="execution-status">
          <span className="exec-status-dot success" />
          <span className="exec-status-text">Run #{mockExecution.runId} Complete</span>
          <span className="exec-timestamp">{mockExecution.timestamp}</span>
          <span className="exec-mode-badge">{mockExecution.mode}</span>
        </div>
        <div className="execution-controls">
          <button className="exec-btn">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M1 4v6h6M23 20v-6h-6" />
              <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" />
            </svg>
            Replay
          </button>
          <button className="exec-btn">Export</button>
          <button className="exec-btn primary">Promote to Settlement</button>
        </div>
      </div>

      {/* Data Grid (Palantir-style) */}
      <div className="data-grid">
        <div className="grid-header">
          <div className="grid-cell cell-id">#</div>
          <div className="grid-cell cell-time">Time</div>
          <div className="grid-cell cell-node">Node</div>
          <div className="grid-cell cell-duration">Duration</div>
          <div className="grid-cell cell-data">Data</div>
          <div className="grid-cell cell-status">Status</div>
        </div>
        {mockExecution.steps.map((step, idx) => (
          <div key={step.id} className={`grid-row row-${step.status}`}>
            <div className="grid-cell cell-id">{idx + 1}</div>
            <div className="grid-cell cell-time">{step.time}</div>
            <div className="grid-cell cell-node">{step.name}</div>
            <div className="grid-cell cell-duration">{step.duration || "—"}</div>
            <div className="grid-cell cell-data">{step.dataCount || 0} obj</div>
            <div className="grid-cell cell-status">
              <span className={`status-badge status-${step.status}`}>
                {step.status === "success" && "✓"}
                {step.status === "error" && "✗"}
                {step.status === "running" && "●"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReceiptsContent() {
  return (
    <div className="receipts-content">
      <div className="receipt-detail">
        <div className="receipt-detail-header">
          <span className="receipt-detail-title">Receipt: Parse + Classify</span>
          <span className="receipt-detail-meta">NodeID: n-42 • Hash: 0xabc… • Signed: ✅</span>
        </div>
        <div className="receipt-detail-grid">
          <div className="receipt-detail-section">
            <h4>Inputs</h4>
            <code>invoice.pdf hash: 0x111…</code>
          </div>
          <div className="receipt-detail-section">
            <h4>Outputs</h4>
            <code>vendor: "ACME" amount: 2400 risk: medium</code>
          </div>
          <div className="receipt-detail-section">
            <h4>Effects (scoped)</h4>
            <div>files:read /Invoices/inbox (3)</div>
            <div>network: none</div>
            <div>spend: none</div>
          </div>
          <div className="receipt-detail-section">
            <h4>Privacy</h4>
            <div>leak budget used: 0.12</div>
          </div>
        </div>
        <div className="receipt-detail-actions">
          <button className="btn btn-ghost">Copy JSON</button>
          <button className="btn btn-ghost">Export Receipt</button>
          <button className="btn btn-ghost">Pin as Evidence</button>
        </div>
      </div>
    </div>
  );
}

function DiffContent() {
  return (
    <div className="diff-content">
      <div className="diff-header">
        <span>Compare Run #128 vs #127</span>
      </div>
      <div className="diff-changes">
        <div className="diff-section">
          <h4>Changed nodes:</h4>
          <div className="diff-item">
            <span className="diff-bullet">•</span>
            <span>Provider Select: tier </span>
            <span className="diff-old">verified</span>
            <span> → </span>
            <span className="diff-new">community</span>
          </div>
          <div className="diff-item">
            <span className="diff-bullet">•</span>
            <span>Parse + Classify: model local LLM </span>
            <span className="diff-old">v2</span>
            <span> → </span>
            <span className="diff-new">v3</span>
          </div>
        </div>
        <div className="diff-section">
          <h4>Changed artifacts:</h4>
          <div className="diff-item">
            <span className="diff-bullet">•</span>
            <span>Receipt n-42 output risk: </span>
            <span className="diff-old">low</span>
            <span> → </span>
            <span className="diff-new">medium</span>
          </div>
        </div>
      </div>
      <div className="diff-actions">
        <button className="btn btn-ghost">Revert Node Version</button>
        <button className="btn btn-ghost">Lock Provider Tier</button>
        <button className="btn btn-ghost">Require Approval on change</button>
      </div>
    </div>
  );
}

function ConsoleContent() {
  return (
    <div className="console-content">
      <div className="console-output">
        <div className="console-line">
          <span className="console-time">[19:52:04]</span>
          <span className="console-level level-info">INFO</span>
          <span className="console-msg">Workflow started: Invoice Guard</span>
        </div>
        <div className="console-line">
          <span className="console-time">[19:52:04]</span>
          <span className="console-level level-debug">DEBUG</span>
          <span className="console-msg">Trigger fired: Cron</span>
        </div>
        <div className="console-line">
          <span className="console-time">[19:52:04]</span>
          <span className="console-level level-info">INFO</span>
          <span className="console-msg">Read 3 files from /Invoices/inbox</span>
        </div>
        <div className="console-line">
          <span className="console-time">[19:52:05]</span>
          <span className="console-level level-info">INFO</span>
          <span className="console-msg">Model inference complete: local LLM v3</span>
        </div>
        <div className="console-line">
          <span className="console-time">[19:52:05]</span>
          <span className="console-level level-info">INFO</span>
          <span className="console-msg">Policy gate passed: Spend? → NO</span>
        </div>
        <div className="console-line">
          <span className="console-time">[19:52:07]</span>
          <span className="console-level level-info">INFO</span>
          <span className="console-msg">Workflow completed successfully</span>
        </div>
      </div>
    </div>
  );
}
