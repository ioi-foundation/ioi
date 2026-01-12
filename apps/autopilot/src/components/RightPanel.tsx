import { useState, useEffect } from "react";
import { Node } from "../types";
import "./RightPanel.css";

interface RightPanelProps {
  width: number;
  selectedNode: Node | null;
}

type InspectorTab = "TELEMETRY" | "CONFIG" | "LOGS";

export function RightPanel({ width, selectedNode }: RightPanelProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("CONFIG");

  // Auto-switch to Telemetry when node is running
  useEffect(() => {
    if (selectedNode?.status === "running") {
      setActiveTab("TELEMETRY");
    }
  }, [selectedNode?.status]);

  if (!selectedNode) {
    return (
      <aside className="right-panel" style={{ width }}>
        <div className="panel-header">
          <h2 className="panel-title">Inspector</h2>
        </div>
        <div className="panel-empty">
          <div className="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M3 9h18M9 21V9" />
            </svg>
          </div>
          <p className="empty-text">Select a node to inspect</p>
          <p className="empty-hint">Click on any node in the canvas</p>
        </div>
      </aside>
    );
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "trigger": return "⚡";
      case "action": return "⚙️";
      case "gate": return "🛡️";
      case "model": return "🧠";
      case "receipt": return "🧾";
      default: return "📦";
    }
  };

  return (
    <aside className="right-panel" style={{ width }}>
      <div className="panel-header">
        <h2 className="panel-title">
          <span className="panel-title-icon">
            {getTypeIcon(selectedNode.type)}
          </span>
          <span style={{ fontFamily: 'monospace' }}>{selectedNode.name}</span>
          <span style={{ color: '#5F6B7C', fontWeight: 400, marginLeft: 4 }}>{selectedNode.id}</span>
        </h2>
        {selectedNode.status === "running" && (
          <span className="badge badge-success">Live</span>
        )}
      </div>

      {/* Tabs */}
      <div className="inspector-tabs">
        <button
          className={`inspector-tab ${activeTab === "TELEMETRY" ? "active" : ""}`}
          onClick={() => setActiveTab("TELEMETRY")}
        >
          Telemetry
        </button>
        <button
          className={`inspector-tab ${activeTab === "CONFIG" ? "active" : ""}`}
          onClick={() => setActiveTab("CONFIG")}
        >
          Config
        </button>
        <button
          className={`inspector-tab ${activeTab === "LOGS" ? "active" : ""}`}
          onClick={() => setActiveTab("LOGS")}
        >
          Logs
        </button>
      </div>

      <div className="panel-content">
        {activeTab === "TELEMETRY" && (
          <TelemetryTab node={selectedNode} />
        )}
        {activeTab === "CONFIG" && (
          <ConfigTab node={selectedNode} />
        )}
        {activeTab === "LOGS" && (
          <LogsTab node={selectedNode} />
        )}
      </div>
    </aside>
  );
}

// --- Live Telemetry Component ---
function TelemetryTab({ node }: { node: Node }) {
  // Simulate live data
  const [throughput, setThroughput] = useState<number[]>(Array(30).fill(5));
  const [latency, setLatency] = useState<number[]>(Array(30).fill(20));
  
  useEffect(() => {
    const isRunning = node.status === "running";
    
    const interval = setInterval(() => {
      setThroughput(prev => {
        const next = [...prev.slice(1)];
        // If running, high random value. If not, drop to 0.
        next.push(isRunning ? Math.random() * 60 + 20 : 0);
        return next;
      });
      
      setLatency(prev => {
        const next = [...prev.slice(1)];
        next.push(isRunning ? Math.random() * 40 + 80 : 0);
        return next;
      });
    }, 150); // Fast update rate for "Live" feel
    return () => clearInterval(interval);
  }, [node.status]);

  return (
    <>
      <div className="panel-section">
        <div className="panel-section-header">
          <span className="panel-section-title">Throughput (TPS)</span>
        </div>
        <div className="telemetry-graph">
          {throughput.map((val, i) => (
            <div 
              key={i} 
              className={`telemetry-bar ${val > 70 ? 'spike' : ''}`} 
              style={{ height: `${val}%` }} 
            />
          ))}
        </div>
        <div className="telemetry-stat">
          <span>Current</span>
          <span className="stat-value">{node.status === "running" ? "42 ops/s" : "0 ops/s"}</span>
        </div>
      </div>

      <div className="panel-section">
        <div className="panel-section-header">
          <span className="panel-section-title">Latency (P99)</span>
        </div>
        <div className="telemetry-graph">
          {latency.map((val, i) => (
            <div 
              key={i} 
              className="telemetry-bar" 
              style={{ height: `${val * 0.6}%`, background: '#34D399', opacity: 0.5 }} 
            />
          ))}
        </div>
        <div className="telemetry-stat">
          <span>Average</span>
          <span className="stat-value">{node.status === "running" ? "124ms" : "—"}</span>
        </div>
      </div>

      <div className="panel-section">
        <div className="panel-section-header">
          <span className="panel-section-title">Resources</span>
        </div>
        <div className="config-field">
          <span className="config-label">Memory Usage</span>
          <div style={{width: '100%', height: 6, background: '#252A33', marginTop: 4, borderRadius: 3, overflow: 'hidden'}}>
            <div style={{width: '34%', height: '100%', background: '#FBBF24'}} />
          </div>
          <div className="telemetry-stat">
            <span style={{fontSize: 10, color: '#5F6B7C'}}>Heap</span>
            <span style={{fontSize: 10, fontFamily: 'monospace'}}>256MB / 1024MB</span>
          </div>
        </div>
      </div>
    </>
  );
}

// --- Config Component (Polymorphic) ---
function ConfigTab({ node }: { node: Node }) {
  return (
    <div>
      {/* Node Identity */}
      <div className="panel-section">
        <div className="config-field">
          <span className="config-label">Node ID</span>
          <input type="text" className="input" value={node.id} readOnly />
        </div>
        <div className="config-field">
          <span className="config-label">Description</span>
          <input type="text" className="input" defaultValue={node.name} />
        </div>
      </div>

      {/* Specific Configs */}
      <div className="panel-section">
        <div className="panel-section-header">
          <span className="panel-section-title">Logic & Config</span>
        </div>
        
        {node.type === "trigger" && (
          <>
            <div className="config-field">
              <span className="config-label">Trigger Type</span>
              <select className="select" defaultValue="cron">
                <option value="cron">Cron Schedule</option>
                <option value="webhook">Webhook</option>
              </select>
            </div>
            <div className="config-field">
              <span className="config-label">Schedule</span>
              <input type="text" className="input" defaultValue="*/5 * * * *" style={{ fontFamily: 'monospace' }} />
              <span className="empty-hint">Every 5 minutes</span>
            </div>
          </>
        )}

        {node.type === "action" && (
          <>
            <div className="config-field">
              <span className="config-label">Timeout</span>
              <div style={{display: 'flex', gap: 8}}>
                <input type="number" className="input" defaultValue="30" style={{flex: 1}} />
                <span className="input-unit" style={{alignSelf: 'center', fontSize: 11, color: '#5F6B7C'}}>sec</span>
              </div>
            </div>
            <div className="config-field">
              <span className="config-label">Retry Policy</span>
              <select className="select" defaultValue="linear">
                <option value="none">None</option>
                <option value="linear">Linear Backoff</option>
                <option value="exponential">Exponential</option>
              </select>
            </div>
          </>
        )}

        {node.type === "gate" && (
          <>
             <div className="config-field">
              <span className="config-label">Gate Type</span>
              <select className="select" defaultValue="policy">
                <option value="policy">Policy Check</option>
                <option value="approval">Human Approval</option>
              </select>
            </div>
            <div className="config-field">
              <span className="config-label">Condition (Rego/CEL)</span>
              <textarea 
                className="input" 
                rows={3} 
                defaultValue="input.risk_score > 0.7" 
                style={{ fontFamily: 'monospace', resize: 'vertical' }}
              />
            </div>
          </>
        )}
      </div>

      {/* Security / Firewall */}
      <div className="panel-section" style={{ background: 'rgba(251, 191, 36, 0.03)' }}>
        <div className="panel-section-header">
          <span className="panel-section-title" style={{ color: '#FBBF24' }}>Agency Firewall</span>
        </div>
        
        <div className="config-field">
          <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: 4}}>
            <span className="config-label" style={{color: '#D1D5DB'}}>cap:network</span>
            <div className="toggle-switch active" />
          </div>
          <input type="text" className="input" defaultValue="api.stripe.com, github.com" />
        </div>

        <div className="config-field">
          <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: 4}}>
            <span className="config-label" style={{color: '#D1D5DB'}}>cap:spend</span>
            <span className="config-label" style={{color: '#FBBF24'}}>$0.50</span>
          </div>
          <input type="range" style={{width: '100%'}} />
        </div>
      </div>

      <div className="panel-section">
        <button className="btn btn-primary" style={{ width: '100%' }}>Apply Changes</button>
      </div>
    </div>
  );
}

// --- Logs Component ---
function LogsTab({ node }: { node: Node }) {
  return (
    <div className="panel-section">
      <div style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: '#9CA3AF', lineHeight: 1.6 }}>
        <div>[10:42:01] INFO  Initializing node context...</div>
        <div>[10:42:01] INFO  Input stream attached (sid-882)</div>
        <div>[10:42:01] DEBUG Loaded capability manifest</div>
        {node.status === "running" && (
          <>
            <div style={{marginTop: 8, borderTop: '1px dashed #2E333D', paddingTop: 8}} />
            <div>[10:42:02] DEBUG Processing batch #1049</div>
            <div style={{color: '#34D399'}}>[10:42:02] INFO  Transform successful (12ms)</div>
            <div>[10:42:02] DEBUG Emitting output event</div>
            <div>[10:42:03] DEBUG Processing batch #1050</div>
            <div style={{color: '#34D399'}}>[10:42:03] INFO  Transform successful (14ms)</div>
            <div style={{color: '#FBBF24'}}>[10:42:04] WARN  Latency spike detected (82ms)</div>
          </>
        )}
      </div>
    </div>
  );
}