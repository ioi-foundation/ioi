import { Node, FirewallPolicy } from "../../../types";

interface PolicyViewProps {
  node: Node;
  onUpdate: (section: 'law', data: Partial<FirewallPolicy>) => void;
}

export function PolicyView({ node, onUpdate }: PolicyViewProps) {
  const law = node.config?.law || {};

  return (
    <div className="policy-view">
      <div className="law-card">
        <div className="capability-row">
          <div className="cap-header">
            <span className="cap-name">cap:network</span>
            <label className="cap-toggle">
              <input 
                type="checkbox" 
                checked={!!law.networkAllowlist && law.networkAllowlist.length > 0} 
                onChange={(e) => {
                  onUpdate('law', { networkAllowlist: e.target.checked ? ["*.example.com"] : [] });
                }} 
              />
              <span className="toggle-track"><span className="toggle-thumb" /></span>
            </label>
          </div>
          <div className="cap-body">
            <label className="cap-label">Allowlist (DNS)</label>
            <textarea 
              className="cap-input code" 
              rows={2} 
              value={(law.networkAllowlist || []).join(", ")}
              onChange={(e) => onUpdate('law', { networkAllowlist: e.target.value.split(",").map(s => s.trim()) })}
              placeholder="*.stripe.com, github.com" 
              disabled={!law.networkAllowlist || law.networkAllowlist.length === 0}
            />
          </div>
        </div>

        <div className="capability-row">
          <div className="cap-header">
            <span className="cap-name">cap:spend</span>
            <label className="cap-toggle">
              <input 
                type="checkbox" 
                checked={(law.budgetCap || 0) > 0} 
                onChange={(e) => onUpdate('law', { budgetCap: e.target.checked ? 1.0 : 0 })} 
              />
              <span className="toggle-track"><span className="toggle-thumb" /></span>
            </label>
          </div>
          <div className="cap-body">
            <label className="cap-label">Budget Limit (Daily)</label>
            <div className="budget-control">
              <input 
                type="range" 
                className="budget-slider" 
                min="0" max="50" step="0.5"
                value={law.budgetCap || 0} 
                onChange={(e) => onUpdate('law', { budgetCap: parseFloat(e.target.value) })}
                disabled={(law.budgetCap || 0) === 0}
              />
              <span className="budget-value">${(law.budgetCap || 0).toFixed(2)}</span>
            </div>
          </div>
        </div>

        <div className="approval-section">
          <label className="checkbox-row">
            <input 
              type="checkbox" 
              checked={law.requireHumanGate || false} 
              onChange={(e) => onUpdate('law', { requireHumanGate: e.target.checked })}
            />
            <span className="checkbox-label">Require Human Approval</span>
          </label>
          <p className="approval-hint">
            Execution will pause and request a signature via the Gate Window if thresholds are exceeded.
          </p>
        </div>
      </div>
    </div>
  );
}