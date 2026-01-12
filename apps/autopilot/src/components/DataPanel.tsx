import { useState, useEffect } from "react";
import "./DataPanel.css";

interface DataPanelProps {
  height: number;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onResize: (height: number) => void;
  selectedNodeName?: string;
  isRunning?: boolean; // Prop to drive animation
}

// Initial Data
const initialInputData = [
  { id: "INV-001", vendor: "Acme Corp", amount: 12500.00, status: "PENDING" },
  { id: "INV-002", vendor: "Globex", amount: 450.00, status: "PENDING" },
  { id: "INV-003", vendor: "Soylent", amount: 3200.50, status: "PENDING" },
];

export function DataPanel({
  height,
  collapsed,
  onToggleCollapse,
  onResize,
  selectedNodeName,
  isRunning = false,
}: DataPanelProps) {
  const [activeTab, setActiveTab] = useState("diff");
  const [outputData, setOutputData] = useState<any[]>(initialInputData);

  // Simulate Row-by-Row Processing
  useEffect(() => {
    if (!isRunning) {
      // Reset when stopped
      setOutputData(initialInputData.map(r => ({ ...r, status: "PENDING", risk: null })));
      return;
    }

    const processRow = (index: number) => {
      if (index >= outputData.length) return;

      // 1. Mark Processing
      setOutputData(prev => prev.map((r, i) => 
        i === index ? { ...r, status: "PROCESSING" } : r
      ));

      // 2. Mark Complete after delay
      setTimeout(() => {
        setOutputData(prev => prev.map((r, i) => {
          if (i === index) {
            const risk = r.amount > 5000 ? "LOW" : r.amount > 1000 ? "NONE" : "HIGH";
            return { ...r, status: "APPROVED", risk };
          }
          return r;
        }));
        
        // Trigger next row
        setTimeout(() => processRow(index + 1), 300);
      }, 800);
    };

    // Start sequence
    processRow(0);

  }, [isRunning]);

  return (
    <div
      className="data-panel"
      style={{ height: collapsed ? 32 : height }}
    >
      <div className="panel-resize-handle" onMouseDown={(e) => { /* reuse resize logic */ }} />

      {/* Header */}
      <div className="panel-tabbar">
        <button
          className={`panel-tab ${activeTab === "diff" ? "active" : ""}`}
          onClick={() => setActiveTab("diff")}
        >
          <span>Workbook Diff</span>
          <span className="tab-badge">Live</span>
        </button>
        <button
          className={`panel-tab ${activeTab === "schema" ? "active" : ""}`}
          onClick={() => setActiveTab("schema")}
        >
          <span>Schema</span>
        </button>
        <button
          className={`panel-tab ${activeTab === "logs" ? "active" : ""}`}
          onClick={() => setActiveTab("logs")}
        >
          <span>System Logs</span>
        </button>
        
        <div style={{ flex: 1 }} />
        
        <button className="panel-tab" onClick={onToggleCollapse}>
          {collapsed ? "▲" : "▼"}
        </button>
      </div>

      {/* Content */}
      {!collapsed && (
        <div className="panel-content" style={{ height: "100%" }}>
          {activeTab === "diff" && (
            <DataDiffView input={initialInputData} output={outputData} />
          )}
        </div>
      )}
    </div>
  );
}

function DataDiffView({ input, output }: { input: any[], output: any[] }) {
  return (
    <div className="diff-container">
      {/* Input Side */}
      <div className="diff-pane">
        <div className="pane-header">
          <span className="pane-title">Input Stream</span>
          <span className="pane-count">{input.length} Objects</span>
        </div>
        <DataTable data={input} />
      </div>

      {/* Center Divider */}
      <div className="diff-divider">
        <div className="diff-arrow">→</div>
      </div>

      {/* Output Side */}
      <div className="diff-pane">
        <div className="pane-header">
          <span className="pane-title output">Transformed Output</span>
          <span className="pane-count">{output.length} Objects</span>
        </div>
        <DataTable data={output} highlightDiff />
      </div>
    </div>
  );
}

function DataTable({ data, highlightDiff }: { data: any[], highlightDiff?: boolean }) {
  if (data.length === 0) return null;
  const cols = Object.keys(data[0]);

  return (
    <div className="data-table-wrapper">
      <table className="data-table">
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col}>{col}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => {
            const isApproved = row.status === "APPROVED";
            const isProcessing = row.status === "PROCESSING";
            
            return (
              <tr key={idx} className={isApproved && highlightDiff ? "diff-added" : ""}>
                {cols.map((col) => {
                  let val = row[col];
                  
                  // Render Status Badge
                  if (col === "status") {
                    val = (
                      <span className={`status-cell ${row.status.toLowerCase()}`}>
                        {row.status}
                      </span>
                    );
                  }
                  
                  // Render Risk (Diff Highlight)
                  if (col === "risk" && highlightDiff && val) {
                     // Keep simple text for risk
                  }

                  return (
                    <td key={col}>
                      {val ?? <span className="cell-null">null</span>}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}