import { Node } from "../types";
import "./PolicyInspector.css";

interface PolicyInspectorProps {
  width: number;
  node: Node | null;
}

export function PolicyInspector({ width, node }: PolicyInspectorProps) {
  if (!node) {
    return (
      <aside className="policy-inspector empty" style={{ width }}>
        <div className="empty-state">
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

  const nodeTypeConfig = getNodeTypeConfig(node.type);

  return (
    <aside className="policy-inspector" style={{ width }}>
      {/* Header */}
      <div className="inspector-header">
        <div className="header-main">
          <span className="header-icon">{nodeTypeConfig.icon}</span>
          <div className="header-info">
            <h2 className="header-title">{node.name}</h2>
            <span className="header-id">{node.id}</span>
          </div>
        </div>
        {node.attested && (
          <span className="attested-badge">✓ Attested</span>
        )}
      </div>

      <div className="inspector-scroll">
        {/* SECTION 1: LOGIC (The Brain) - Polymorphic */}
        <div className="inspector-section logic-section">
          <div className="section-header">
            <span className="section-icon">🧠</span>
            <span className="section-title">Logic & Config</span>
          </div>

          <div className="section-content">
            {node.type === "model" && <ModelLogicConfig node={node} />}
            {node.type === "tool" && <ToolLogicConfig node={node} />}
            {node.type === "trigger" && <TriggerLogicConfig node={node} />}
            {node.type === "gate" && <GateLogicConfig node={node} />}
            {node.type === "receipt" && <ReceiptLogicConfig node={node} />}
            
            {/* Fallback for unknown types */}
            {!["model", "tool", "trigger", "gate", "receipt"].includes(node.type) && (
              <GenericLogicConfig node={node} />
            )}
          </div>
        </div>

        {/* SECTION 2: LAW (The Firewall) - Universal */}
        <div className="inspector-section law-section">
          <div className="section-header danger">
            <span className="section-icon">🛡️</span>
            <span className="section-title">Agency Firewall</span>
          </div>

          <div className="section-content">
            <div className="law-card">
              {/* Network Capability */}
              <div className="capability-row">
                <div className="cap-header">
                  <span className="cap-name">cap:network</span>
                  <CapabilityToggle defaultEnabled={false} />
                </div>
                <div className="cap-body">
                  <label className="cap-label">Allowlist</label>
                  <input 
                    type="text" 
                    className="cap-input code" 
                    defaultValue="api.stripe.com, github.com" 
                    placeholder="domain1.com, domain2.com"
                  />
                </div>
              </div>

              {/* Spend Capability */}
              <div className="capability-row">
                <div className="cap-header">
                  <span className="cap-name">cap:spend</span>
                  <CapabilityToggle defaultEnabled={false} />
                </div>
                <div className="cap-body">
                  <label className="cap-label">Budget Limit</label>
                  <div className="budget-control">
                    <input 
                      type="range" 
                      className="budget-slider" 
                      min="0" 
                      max="100" 
                      defaultValue="10" 
                    />
                    <span className="budget-value">$0.50</span>
                  </div>
                </div>
              </div>

              {/* Files Capability */}
              <div className="capability-row">
                <div className="cap-header">
                  <span className="cap-name">cap:files</span>
                  <CapabilityToggle defaultEnabled={true} />
                </div>
                <div className="cap-body">
                  <label className="cap-label">Scope</label>
                  <select className="cap-select">
                    <option value="read">Read Only</option>
                    <option value="readwrite">Read/Write</option>
                    <option value="workspace">Workspace Only</option>
                  </select>
                </div>
              </div>

              {/* Approval Gate */}
              <div className="approval-section">
                <label className="checkbox-row">
                  <input type="checkbox" defaultChecked />
                  <span className="checkbox-label">Require Human Approval</span>
                </label>
                <p className="approval-hint">
                  Actions exceeding budget or accessing new domains will pause for 2FA confirmation
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* SECTION 3: Receipts (if applicable) */}
        <div className="inspector-section receipts-section">
          <div className="section-header">
            <span className="section-icon">🧾</span>
            <span className="section-title">Receipt Config</span>
          </div>
          
          <div className="section-content">
            <label className="checkbox-row">
              <input type="checkbox" defaultChecked />
              <span className="checkbox-label">Generate Signed Receipts</span>
            </label>
            <label className="checkbox-row">
              <input type="checkbox" defaultChecked />
              <span className="checkbox-label">Log to Timeline</span>
            </label>
          </div>
        </div>
      </div>

      {/* Footer Actions */}
      <div className="inspector-footer">
        <button className="btn btn-ghost">Reset</button>
        <button className="btn btn-primary">Apply</button>
      </div>
    </aside>
  );
}

// --- Capability Toggle Component ---
function CapabilityToggle({ defaultEnabled }: { defaultEnabled: boolean }) {
  return (
    <label className="cap-toggle">
      <input type="checkbox" defaultChecked={defaultEnabled} />
      <span className="toggle-track">
        <span className="toggle-thumb" />
      </span>
    </label>
  );
}

// --- Polymorphic Logic Configs ---
function ModelLogicConfig({ node }: { node: Node }) {
  return (
    <>
      <div className="form-group">
        <label className="form-label">System Prompt</label>
        <textarea 
          className="form-textarea code" 
          rows={5}
          placeholder="You are a helpful assistant..."
          defaultValue="You are a financial analyst. Analyze invoices for risk indicators and vendor verification."
        />
      </div>
      <div className="form-group">
        <label className="form-label">Model Source</label>
        <select className="form-select">
          <option value="local">Local (Llama-3.2-8b)</option>
          <option value="local-large">Local (Llama-3.1-70b)</option>
          <option value="burst">Burst to Provider</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Temperature</label>
        <div className="slider-row">
          <input type="range" className="form-slider" min="0" max="100" defaultValue="20" />
          <span className="slider-value">0.2</span>
        </div>
      </div>
    </>
  );
}

function ToolLogicConfig({ node }: { node: Node }) {
  return (
    <>
      <div className="form-group">
        <label className="form-label">Parameters (JSON)</label>
        <textarea 
          className="form-textarea code" 
          rows={4}
          defaultValue='{\n  "path": "/Invoices/inbox",\n  "filter": "*.pdf"\n}'
        />
      </div>
      <div className="form-group">
        <label className="form-label">Timeout</label>
        <div className="input-with-unit">
          <input type="number" className="form-input" defaultValue="30" />
          <span className="input-unit">seconds</span>
        </div>
      </div>
    </>
  );
}

function TriggerLogicConfig({ node }: { node: Node }) {
  return (
    <>
      <div className="form-group">
        <label className="form-label">Trigger Type</label>
        <select className="form-select">
          <option value="cron">Cron Schedule</option>
          <option value="webhook">Webhook</option>
          <option value="manual">Manual</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Schedule</label>
        <input 
          type="text" 
          className="form-input code" 
          defaultValue="*/5 * * * *" 
          placeholder="Cron expression"
        />
        <span className="form-hint">Every 5 minutes</span>
      </div>
    </>
  );
}

function GateLogicConfig({ node }: { node: Node }) {
  return (
    <>
      <div className="form-group">
        <label className="form-label">Gate Type</label>
        <select className="form-select">
          <option value="policy">Policy Gate</option>
          <option value="approval">Approval Gate</option>
          <option value="spend">Spend Gate</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Condition</label>
        <textarea 
          className="form-textarea code" 
          rows={3}
          defaultValue="input.risk_score < 0.5"
          placeholder="Boolean expression"
        />
      </div>
    </>
  );
}

function ReceiptLogicConfig({ node }: { node: Node }) {
  return (
    <div className="form-group">
      <label className="form-label">Receipt Format</label>
      <select className="form-select">
        <option value="json">JSON</option>
        <option value="cbor">CBOR (Signed)</option>
      </select>
    </div>
  );
}

function GenericLogicConfig({ node }: { node: Node }) {
  return (
    <div className="form-group">
      <label className="form-label">Node Type</label>
      <input type="text" className="form-input" value={node.type} readOnly />
    </div>
  );
}

// --- Helper ---
function getNodeTypeConfig(type: string) {
  const configs: Record<string, { icon: string; color: string }> = {
    trigger: { icon: "⚡", color: "#fbbf24" },
    tool: { icon: "🔧", color: "#60a5fa" },
    model: { icon: "🤖", color: "#a78bfa" },
    gate: { icon: "🛡️", color: "#34d399" },
    receipt: { icon: "🧾", color: "#f472b6" },
  };
  return configs[type] || { icon: "⬡", color: "#9ca3af" };
}