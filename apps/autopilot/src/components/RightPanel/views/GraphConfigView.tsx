// apps/autopilot/src/components/RightPanel/views/GraphConfigView.tsx

import { GraphGlobalConfig } from "../types";

interface GraphConfigViewProps {
  // [UPDATED] Added CONTRACT to literal type
  activeTab: "ENV" | "POLICY" | "CONTRACT" | "META";
  config: GraphGlobalConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onUpdate: (section: keyof GraphGlobalConfig, updates: any) => void;
}

export function GraphConfigView({ activeTab, config, onUpdate }: GraphConfigViewProps) {
  // Ensure contract object exists (migration safety)
  const contractConfig = config.contract || { developerBond: 0, adjudicationRubric: "" };

  return (
    <>
      {activeTab === "ENV" && (
        <div className="properties-container">
          <div className="panel-section">
            <div className="section-title-row">
              <span className="section-title">Global Context</span>
              <span className="badge">JSON</span>
            </div>
            <div className="config-field">
              <label className="config-label">Environment Variables</label>
              <textarea 
                className="input code-editor" 
                rows={12}
                value={config.env}
                onChange={(e) => onUpdate('env', e.target.value)}
                spellCheck={false}
              />
              <div className="approval-hint" style={{marginLeft: 0, marginTop: 8}}>
                These variables are injected into every node's execution context.
                Access them using <code>{`{{key}}`}</code>.
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "POLICY" && (
        <div className="policy-view">
          <div className="law-card">
            <div className="capability-row">
              <div className="cap-header">
                <span className="cap-name">TOTAL_BUDGET_CAP</span>
              </div>
              <div className="cap-body">
                <label className="cap-label">Max Spend Per Run</label>
                <div className="budget-control">
                  <input 
                    type="range" 
                    className="budget-slider" 
                    min="0" max="20" step="0.5"
                    value={config.policy.maxBudget}
                    onChange={(e) => onUpdate('policy', { maxBudget: parseFloat(e.target.value) })}
                  />
                  <span className="budget-value">${config.policy.maxBudget.toFixed(2)}</span>
                </div>
              </div>
            </div>

            <div className="capability-row">
              <div className="cap-header">
                <span className="cap-name">MAX_STEPS</span>
              </div>
              <div className="cap-body">
                <label className="cap-label">Recursion Limit</label>
                <input 
                  type="number" 
                  className="cap-input code"
                  value={config.policy.maxSteps}
                  onChange={(e) => onUpdate('policy', { maxSteps: parseInt(e.target.value) })}
                />
              </div>
            </div>

            <div className="capability-row">
              <div className="cap-header">
                <span className="cap-name">TIMEOUT</span>
              </div>
              <div className="cap-body">
                <label className="cap-label">Global Timeout (ms)</label>
                <input 
                  type="number" 
                  className="cap-input code"
                  value={config.policy.timeoutMs}
                  onChange={(e) => onUpdate('policy', { timeoutMs: parseInt(e.target.value) })}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* [NEW] CONTRACT TAB */}
      {activeTab === "CONTRACT" && (
        <div className="properties-container">
          
          {/* Section: Bond (Liability) */}
          <div className="panel-section">
            <div className="section-title-row">
              <span className="section-title">Liability & Staking</span>
              <span className="badge" style={{background: 'rgba(245, 158, 11, 0.15)', color: '#F59E0B'}}>Tier 2</span>
            </div>
            
            <div className="config-field">
              <label className="config-label">Developer Bond (IOI)</label>
              <div className="budget-control">
                  <input 
                    type="number" 
                    className="input code-editor"
                    value={contractConfig.developerBond}
                    onChange={(e) => onUpdate('contract', { ...contractConfig, developerBond: parseFloat(e.target.value) })}
                    placeholder="0.00"
                  />
                  <div className="approval-hint" style={{marginLeft: 0, marginTop: 4}}>
                    Amount staked to underwrite this agent. Slashed if arbitration fails.
                  </div>
              </div>
            </div>
          </div>

          {/* Section: Rubric (Arbitration) */}
          <div className="panel-section">
            <div className="section-title-row">
              <span className="section-title">Adjudication Rubric</span>
              <span className="badge" style={{background: 'rgba(52, 211, 153, 0.15)', color: '#34D399'}}>Tier 4</span>
            </div>
            
            <div className="config-field">
              <label className="config-label">Success Criteria (Natural Language)</label>
              <textarea 
                className="input code-editor" 
                rows={12}
                value={contractConfig.adjudicationRubric}
                onChange={(e) => onUpdate('contract', { ...contractConfig, adjudicationRubric: e.target.value })}
                placeholder="- Output must be valid JSON&#10;- Tone must be professional&#10;- Must not hallucinate URLs"
              />
              <div className="approval-hint" style={{marginLeft: 0, marginTop: 8}}>
                Instructions for the <strong>Arbitration Node</strong> (LLM Judge) to decide disputes.
                <br/><br/>
                <em>Note: Agents with clear rubrics qualify for the "Fast Path" arbitration lane.</em>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "META" && (
        <div className="properties-container">
          <div className="panel-section">
            <div className="config-field">
              <label className="config-label">Graph Name</label>
              <input 
                className="input"
                value={config.meta.name}
                onChange={(e) => onUpdate('meta', { name: e.target.value })}
              />
            </div>
            <div className="config-field">
              <label className="config-label">Description</label>
              <textarea 
                className="input"
                rows={4}
                value={config.meta.description}
                onChange={(e) => onUpdate('meta', { description: e.target.value })}
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}