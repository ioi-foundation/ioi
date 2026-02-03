// packages/agent-ide/src/features/Editor/Inspector/views/GraphConfigView.tsx
import { GraphGlobalConfig } from "../../../../types/graph";

interface GraphConfigViewProps {
  config: GraphGlobalConfig;
  onChange: (updates: Partial<GraphGlobalConfig>) => void;
}

export function GraphConfigView({ config, onChange }: GraphConfigViewProps) {
  // Safe defaults
  const safeConfig = config || { env: "", policy: {}, meta: {} };

  return (
    <div className="inspector-view">
      <div className="section-header" style={{ marginBottom: 16 }}>
        <span style={{ fontWeight: 700 }}>GLOBAL CONFIG</span>
      </div>

      {/* Meta Section */}
      <div className="form-group">
        <label>Graph Name</label>
        <input 
            value={safeConfig.meta?.name || ""}
            onChange={e => onChange({ meta: { ...safeConfig.meta, name: e.target.value } })}
            placeholder="Untitled Agent"
        />
      </div>

      <div className="form-group">
        <label>Global Env (JSON)</label>
        <textarea 
            className="code-editor"
            rows={8}
            value={safeConfig.env || ""}
            onChange={e => onChange({ env: e.target.value })}
            placeholder='{"API_KEY": "..."}'
        />
      </div>

      {/* Policy Section - Styled like Law View */}
      <div className="form-group">
        <label>Global Policy</label>
        <div className="law-card">
            
            {/* Max Budget Row */}
            <div className="capability-row">
                <div className="cap-header">
                    <span className="cap-icon">💰</span>
                    <span className="cap-title">TOTAL BUDGET CAP</span>
                </div>
                <div className="cap-body" style={{flexDirection: 'column', alignItems: 'stretch', gap: 8}}>
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                        <input 
                            type="range" 
                            className="budget-slider"
                            min="0" max="50" step="0.5"
                            value={safeConfig.policy?.maxBudget || 0}
                            onChange={e => onChange({ policy: { ...safeConfig.policy, maxBudget: parseFloat(e.target.value) } })}
                        />
                        <span className="budget-value">${(safeConfig.policy?.maxBudget || 0).toFixed(2)}</span>
                    </div>
                </div>
            </div>

            {/* Recursion Limit Row */}
            <div className="capability-row">
                <div className="cap-header">
                    <span className="cap-icon">🔄</span>
                    <span className="cap-title">MAX STEPS</span>
                </div>
                <div className="cap-body">
                    <input 
                        type="number"
                        value={safeConfig.policy?.maxSteps || 50}
                        onChange={e => onChange({ policy: { ...safeConfig.policy, maxSteps: parseInt(e.target.value) } })}
                        style={{width: '100%'}}
                    />
                </div>
            </div>

        </div>
      </div>
    </div>
  );
}