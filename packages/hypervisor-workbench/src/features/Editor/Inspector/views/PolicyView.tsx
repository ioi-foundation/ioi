import { FirewallPolicy } from "../../../../types/graph";

interface PolicyViewProps {
  config: FirewallPolicy;
  onChange: (updates: Partial<FirewallPolicy>) => void;
}

export function PolicyView({ config, onChange }: PolicyViewProps) {
  return (
    <div className="inspector-view">
      <div className="law-card">
        <div className="capability-row">
            <div className="cap-header">
                <span className="cap-icon">💰</span>
                <span className="cap-title">Budget Cap</span>
            </div>
            <div className="cap-body">
                <input 
                    type="number" 
                    value={config.budgetCap || 0}
                    onChange={e => onChange({ budgetCap: parseFloat(e.target.value) })}
                />
                <span className="unit">USD</span>
            </div>
        </div>

        <div className="capability-row">
            <div className="cap-header">
                <span className="cap-icon">🌐</span>
                <span className="cap-title">Network Whitelist</span>
            </div>
            <div className="cap-body">
                <textarea 
                    rows={3}
                    placeholder="api.stripe.com, *.github.com"
                    value={(config.networkAllowlist || []).join(", ")}
                    onChange={e => onChange({ networkAllowlist: e.target.value.split(",").map(s => s.trim()) })}
                />
            </div>
        </div>

        <div className="capability-row">
            <label className="checkbox-row">
                <input 
                    type="checkbox"
                    checked={config.requireHumanGate || false}
                    onChange={e => onChange({ requireHumanGate: e.target.checked })}
                />
                <span>Require Human Approval</span>
            </label>
        </div>
      </div>
    </div>
  );
}