// apps/autopilot/src/components/RightPanel.tsx
import { useState, useEffect, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Node, NodeLogic, FirewallPolicy } from "../types"; // Updated import
import "./RightPanel.css";
import "./PolicyInspector.css"; // Reuse existing styles

// --- ICONS ---
const ShieldIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const BrainIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"/></svg>;
const TerminalIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;
const GlobeIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>;
const SettingsIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>;
const DnaIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="M17 22c-2.667-3.5-2.667-10.5 0-14"/><path d="M2 11c6.667 6 13.333 0 20 6"/><path d="M9 2c2.667 3.5 2.667 10.5 0 14"/></svg>;

// --- TYPES ---
export interface GraphGlobalConfig {
  env: string; // JSON string for global variables
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
  };
  meta: {
    name: string;
    description: string;
  };
}

interface RightPanelProps {
  width: number;
  selectedNode: Node | null;
  // Updater function passed from StudioWindow to sync ReactFlow state
  onUpdateNode?: (nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<FirewallPolicy>) => void;
  // [NEW] Global Graph Config Props
  graphConfig?: GraphGlobalConfig;
  onUpdateGraph?: (updates: Partial<GraphGlobalConfig> | any) => void; // Using any for nested partials flexibility
  // [NEW] Upstream data from the Orchestrator for Context-Aware Debugging
  upstreamData?: string;
  // [NEW] Callback for stateful debugging - updates graph state on successful run
  onRunComplete?: (nodeId: string, artifact: any) => void;
}

type InspectorTab = "LOGIC" | "LAW" | "SIM" | "DNA"; // [NEW] Added DNA tab
type GraphTab = "ENV" | "POLICY" | "META";

// Helper to extract variables {{var_name}} from template strings
function extractVariables(template: string): string[] {
  const regex = /{{([^}]+)}}/g;
  const matches = new Set<string>();
  let match;
  while ((match = regex.exec(template)) !== null) {
    matches.add(match[1].trim());
  }
  return Array.from(matches);
}

// Default Global Config if none provided
const DEFAULT_GRAPH_CONFIG: GraphGlobalConfig = {
  env: '{\n  "env": "production",\n  "api_base": "https://api.example.com"\n}',
  policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
  meta: { name: "Untitled Graph", description: "No description" }
};

export function RightPanel({ 
  width, 
  selectedNode, 
  onUpdateNode, 
  graphConfig = DEFAULT_GRAPH_CONFIG,
  onUpdateGraph,
  upstreamData, 
  onRunComplete 
}: RightPanelProps) {
  
  // State for Node Inspector
  const [activeTab, setActiveTab] = useState<InspectorTab>("LOGIC");
  
  // State for Graph Inspector (Root)
  const [activeGraphTab, setActiveGraphTab] = useState<GraphTab>("ENV");

  useEffect(() => {
    // Reset to Logic when selecting a new node
    if (selectedNode) setActiveTab("LOGIC");
  }, [selectedNode?.id]);

  // Helper wrapper for updates
  const handleUpdate = (section: 'logic' | 'law', updates: any) => {
    if (selectedNode && onUpdateNode) {
      onUpdateNode(selectedNode.id, section, updates);
    }
  };

  // Helper for graph updates
  const handleGraphUpdate = (section: keyof GraphGlobalConfig, updates: any) => {
    if (!onUpdateGraph) return;
    if (section === "env") {
      onUpdateGraph({ env: updates });
      return;
    }
    onUpdateGraph({ [section]: { ...(graphConfig[section] as object), ...updates } });
  };

  // --- RENDER GRAPH ROOT CONFIG (If no node selected) ---
  if (!selectedNode) {
    return (
      <aside className="right-panel" style={{ width }}>
        {/* GRAPH HEADER */}
        <div className="panel-header">
          <div className="panel-title">
            <span className="panel-node-type" style={{background: '#4B5563', color: '#E5E7EB'}}>ROOT</span>
            <span className="panel-node-name">System Constitution</span>
          </div>
        </div>

        {/* GRAPH TABS */}
        <div className="inspector-tabs">
          <button 
            className={`inspector-tab ${activeGraphTab === "ENV" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("ENV")}
          >
            <GlobeIcon /> Env
          </button>
          <button 
            className={`inspector-tab ${activeGraphTab === "POLICY" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("POLICY")}
          >
            <ShieldIcon /> Policy
          </button>
          <button 
            className={`inspector-tab ${activeGraphTab === "META" ? "active" : ""}`}
            onClick={() => setActiveGraphTab("META")}
          >
            <SettingsIcon /> Meta
          </button>
        </div>

        {/* GRAPH CONTENT */}
        <div className="panel-content">
          {activeGraphTab === "ENV" && (
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
                    value={graphConfig.env}
                    onChange={(e) => handleGraphUpdate('env', e.target.value)} // String replacement for env
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

          {activeGraphTab === "POLICY" && (
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
                        value={graphConfig.policy.maxBudget}
                        onChange={(e) => handleGraphUpdate('policy', { maxBudget: parseFloat(e.target.value) })}
                      />
                      <span className="budget-value">${graphConfig.policy.maxBudget.toFixed(2)}</span>
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
                      value={graphConfig.policy.maxSteps}
                      onChange={(e) => handleGraphUpdate('policy', { maxSteps: parseInt(e.target.value) })}
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
                      value={graphConfig.policy.timeoutMs}
                      onChange={(e) => handleGraphUpdate('policy', { timeoutMs: parseInt(e.target.value) })}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeGraphTab === "META" && (
            <div className="properties-container">
              <div className="panel-section">
                <div className="config-field">
                  <label className="config-label">Graph Name</label>
                  <input 
                    className="input"
                    value={graphConfig.meta.name}
                    onChange={(e) => handleGraphUpdate('meta', { name: e.target.value })}
                  />
                </div>
                <div className="config-field">
                  <label className="config-label">Description</label>
                  <textarea 
                    className="input"
                    rows={4}
                    value={graphConfig.meta.description}
                    onChange={(e) => handleGraphUpdate('meta', { description: e.target.value })}
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      </aside>
    );
  }

  // --- RENDER NODE INSPECTOR (Existing Logic) ---
  return (
    <aside className="right-panel" style={{ width }}>
      {/* HEADER */}
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-node-type">{selectedNode.type.toUpperCase()}</span>
          <span className="panel-node-name">{selectedNode.name}</span>
        </div>
        {selectedNode.attested && (
           <span className="attested-badge" title="Cryptographically Signed Policy">✓ Signed</span>
        )}
      </div>

      {/* 4-WAY TAB SWITCHER */}
      <div className="inspector-tabs">
        <button 
          className={`inspector-tab ${activeTab === "LOGIC" ? "active" : ""}`}
          onClick={() => setActiveTab("LOGIC")}
        >
          <BrainIcon /> Logic
        </button>
        <button 
          className={`inspector-tab ${activeTab === "LAW" ? "active" : ""}`}
          onClick={() => setActiveTab("LAW")}
        >
          <ShieldIcon /> Law
        </button>
        <button 
          className={`inspector-tab ${activeTab === "SIM" ? "active" : ""}`}
          onClick={() => setActiveTab("SIM")}
        >
          <TerminalIcon /> Run
        </button>
        {/* [NEW] DNA Tab */}
        <button 
          className={`inspector-tab ${activeTab === "DNA" ? "active" : ""}`}
          onClick={() => setActiveTab("DNA")}
          title="Evolutionary Lineage"
        >
          <DnaIcon /> DNA
        </button>
      </div>

      {/* CONTENT AREA */}
      <div className="panel-content">
        {activeTab === "LOGIC" && <LogicView node={selectedNode} onUpdate={handleUpdate} />}
        {activeTab === "LAW" && <PolicyView node={selectedNode} onUpdate={handleUpdate} />}
        {activeTab === "SIM" && (
          <SimulationView 
            node={selectedNode} 
            upstreamData={upstreamData}
            onRunComplete={onRunComplete}
          />
        )}
        {/* [NEW] DNA View */}
        {activeTab === "DNA" && (
            <div className="lineage-view">
                <div className="gene-header">
                    <span className="gene-title">Current Generation</span>
                    <span className="gene-badge">Gen 5</span>
                </div>
                <div className="mutation-log">
                    <div className="mutation-entry success">
                        <div className="mutation-meta">
                            <span>Gen 4 → 5</span>
                            <span className="timestamp">10m ago</span>
                        </div>
                        <div className="mutation-reason">Fixed JSON parsing error in `tool_call` regex.</div>
                        <div className="mutation-score positive">+15% Success Rate</div>
                    </div>
                    
                    <div className="mutation-entry success">
                        <div className="mutation-meta">
                            <span>Gen 3 → 4</span>
                            <span className="timestamp">1h ago</span>
                        </div>
                        <div className="mutation-reason">Added `net::fetch` error handling retry logic.</div>
                        <div className="mutation-score positive">+5% Success Rate</div>
                    </div>
                    
                    <div className="mutation-entry failed">
                        <div className="mutation-meta">
                            <span>Gen 2 → 3</span>
                            <span className="timestamp">2h ago</span>
                        </div>
                        <div className="mutation-reason">Attempted to remove budget cap.</div>
                        <div className="mutation-score negative">REJECTED BY SAFETY RATCHET</div>
                    </div>
                </div>
                
                <div className="gene-stats">
                    <div className="stat-box">
                        <div className="stat-label">Total Earnings</div>
                        <div className="stat-val">12.50 L-GAS</div>
                    </div>
                    <div className="stat-box">
                        <div className="stat-label">Fitness Score</div>
                        <div className="stat-val">0.92</div>
                    </div>
                </div>
            </div>
        )}
      </div>
    </aside>
  );
}

// =========================================
// VIEW 1: LOGIC (The Brain)
// Defines *what* the agent wants to do.
// =========================================

interface LogicViewProps {
  node: Node;
  onUpdate: (section: 'logic', data: Partial<NodeLogic>) => void;
}

function LogicView({ node, onUpdate }: LogicViewProps) {
  const config = node.config?.logic || {};
  
  // Auto-detect variables for UX feedback in the Logic tab
  const activeTemplate = config.systemPrompt || config.bodyTemplate || "";
  const variables = useMemo(() => extractVariables(activeTemplate), [activeTemplate]);
  
  // [NEW] Dynamic MCP Tool Handling
  // We use node.schema to detect if it's a dynamic tool
  const isDynamicTool = node.type === "tool" && !!node.schema;

  return (
    <div className="properties-container">
      {/* Dynamic Editor based on Node Type */}
      {node.type === "model" && (
        <div className="panel-section">
          <div className="section-title-row">
            <span className="section-title">Prompt Engineering</span>
            <span className="badge">{config.model || "GPT-4o"}</span>
          </div>
          
          <div className="config-field">
            <label className="config-label">Model</label>
            <select 
              className="input" 
              value={config.model || "gpt-4o"}
              onChange={(e) => onUpdate('logic', { model: e.target.value })}
            >
              <option value="gpt-4o">GPT-4o (Cloud)</option>
              <option value="llama3">Llama 3 (Local)</option>
              <option value="claude-3.5">Claude 3.5 Sonnet</option>
            </select>
          </div>

          <div className="config-field">
            <label className="config-label">
                System Prompt
                {variables.length > 0 && <span className="badge" style={{marginLeft: 8}}>{variables.length} vars</span>}
            </label>
            <textarea 
              className="input code-editor" 
              rows={8}
              value={config.systemPrompt || ""}
              onChange={(e) => onUpdate('logic', { systemPrompt: e.target.value })}
              placeholder="You are an expert analyst. Analyze the input: {{user_input}}..."
            />
            {/* Visual feedback for detected variables */}
            {variables.length > 0 && (
                <div style={{display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4}}>
                    {variables.map(v => (
                        <span key={v} style={{fontSize: 10, background: 'rgba(167, 139, 250, 0.1)', padding: '2px 6px', borderRadius: 4, color: '#A78BFA'}}>
                            {v}
                        </span>
                    ))}
                </div>
            )}
          </div>
          
          <div className="config-field">
            <label className="config-label">Temperature: {config.temperature || 0.2}</label>
            <input 
              type="range" 
              className="slider" 
              min="0" max="1" step="0.1" 
              value={config.temperature || 0.2} 
              onChange={(e) => onUpdate('logic', { temperature: parseFloat(e.target.value) })}
            />
          </div>
        </div>
      )}

      {/* [NEW] Dynamic Tool Config */}
      {isDynamicTool && node.schema && (
        <DynamicToolConfig 
          schemaStr={node.schema} 
          // @ts-ignore - arguments is dynamic
          currentArgs={config.arguments || {}}
          onChange={(newArgs) => onUpdate('logic', { arguments: newArgs })}
        />
      )}

      {!isDynamicTool && node.type === "tool" && (
        <div className="panel-section">
          <div className="section-title-row"><span className="section-title">Tool Config</span></div>
          
          <div className="config-field">
             <label className="config-label">Method</label>
             <select 
               className="input"
               value={config.method || "GET"}
               onChange={(e) => onUpdate('logic', { method: e.target.value as any })}
             >
               <option>GET</option>
               <option>POST</option>
               <option>PUT</option>
               <option>DELETE</option>
             </select>
          </div>

          <div className="config-field">
             <label className="config-label">Endpoint URL</label>
             <input 
               className="input code-editor" 
               value={config.endpoint || ""} 
               onChange={(e) => onUpdate('logic', { endpoint: e.target.value })}
               placeholder="https://api.example.com/v1/resource" 
             />
          </div>

          <div className="config-field">
            <label className="config-label">
                Body Template (JSON)
                {variables.length > 0 && <span className="badge" style={{marginLeft: 8}}>{variables.length} vars</span>}
            </label>
            <textarea 
              className="input code-editor" 
              rows={5}
              value={config.bodyTemplate || ""}
              onChange={(e) => onUpdate('logic', { bodyTemplate: e.target.value })}
              placeholder='{"query": "{{input}}"}'
            />
            {variables.length > 0 && (
                <div style={{display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4}}>
                    {variables.map(v => (
                        <span key={v} style={{fontSize: 10, background: 'rgba(167, 139, 250, 0.1)', padding: '2px 6px', borderRadius: 4, color: '#A78BFA'}}>
                            {v}
                        </span>
                    ))}
                </div>
            )}
          </div>
        </div>
      )}

      {node.type === "trigger" && (
        <div className="panel-section">
          <div className="section-title-row"><span className="section-title">Schedule</span></div>
          <div className="config-field">
            <label className="config-label">Cron Expression</label>
            <input 
              className="input code-editor" 
              value={config.cronSchedule || ""} 
              onChange={(e) => onUpdate('logic', { cronSchedule: e.target.value })}
              placeholder="*/5 * * * *"
            />
          </div>
        </div>
      )}
      
      {/* Fallback for generic nodes */}
      {!["model", "tool", "trigger"].includes(node.type) && (
        <div className="panel-empty" style={{ padding: 20 }}>
          <span className="empty-hint">No configurable logic for this node type.</span>
        </div>
      )}
    </div>
  );
}

// [NEW] Dynamic Tool Config Component
function DynamicToolConfig({ schemaStr, currentArgs, onChange }: { schemaStr: string, currentArgs: Record<string, any>, onChange: (args: any) => void }) {
  let schema;
  try {
    schema = JSON.parse(schemaStr);
  } catch {
    return <div className="panel-empty"><span className="empty-hint">Invalid Schema</span></div>;
  }

  const properties = schema.properties || {};
  const required = schema.required || [];

  const handleChange = (key: string, val: any) => {
    onChange({ ...currentArgs, [key]: val });
  };

  return (
    <div className="panel-section">
      <div className="section-title-row">
        <span className="section-title">Dynamic Tool Config</span>
      </div>
      
      {Object.keys(properties).map((key) => {
        const prop = properties[key];
        const isRequired = required.includes(key);
        
        return (
          <div key={key} className="config-field">
            <label className="config-label">
              {key} {isRequired && <span style={{color: '#F87171'}}>*</span>}
            </label>
            
            {prop.type === "boolean" ? (
               <select 
                 className="input"
                 value={currentArgs[key] === true ? "true" : "false"}
                 onChange={(e) => handleChange(key, e.target.value === "true")}
               >
                 <option value="true">True</option>
                 <option value="false">False</option>
               </select>
            ) : (
               <input 
                 className="input code-editor"
                 type={prop.type === "integer" || prop.type === "number" ? "number" : "text"}
                 value={currentArgs[key] || ""}
                 onChange={(e) => {
                    let val: any = e.target.value;
                    if (prop.type === "integer" || prop.type === "number") val = parseFloat(val);
                    handleChange(key, val);
                 }}
                 placeholder={prop.description || ""}
               />
            )}
            {prop.description && (
              <div className="approval-hint" style={{marginLeft: 0, marginTop: 4, color: '#6B7280'}}>
                {prop.description}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// =========================================
// VIEW 2: LAW (The Constitution)
// Defines *what* the agent is ALLOWED to do.
// =========================================

interface PolicyViewProps {
  node: Node;
  onUpdate: (section: 'law', data: Partial<FirewallPolicy>) => void;
}

function PolicyView({ node, onUpdate }: PolicyViewProps) {
  const law = node.config?.law || {};

  return (
    <div className="policy-view">
      {/* Network Capability */}
      <div className="law-card">
        <div className="capability-row">
          <div className="cap-header">
            <span className="cap-name">cap:network</span>
            {/* Toggle implies enabling egress */}
            <label className="cap-toggle">
              <input 
                type="checkbox" 
                checked={!!law.networkAllowlist && law.networkAllowlist.length > 0} 
                onChange={(e) => {
                  // If unchecked, clear allowlist to disable. If checked, init with default.
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

        {/* Spend Capability */}
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

        {/* Human in the Loop */}
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

// =========================================
// VIEW 3: SIMULATION (The Runtime)
// Unit tests the node in isolation.
// =========================================

function SimulationView({ 
  node, 
  upstreamData, 
  onRunComplete 
}: { 
  node: Node, 
  upstreamData?: string, 
  onRunComplete?: (id: string, result: any) => void 
}) {
  const [inputJson, setInputJson] = useState('{\n  "amount": 450.00,\n  "vendor": "Unknown"\n}');
  const [output, setOutput] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'form' | 'json'>('json');

  // Detect variables from the node configuration logic
  const promptTemplate = node.config?.logic?.systemPrompt || node.config?.logic?.bodyTemplate || "";
  const variables = useMemo(() => extractVariables(promptTemplate), [promptTemplate]);

  // Switch to Form view by default if variables exist
  useEffect(() => {
      if (variables.length > 0) setActiveTab('form');
  }, [variables.length]);

  // [NEW] Intelligent Context Hydration
  // Allows seamless transition from "Graph Run" to "Unit Test"
  useEffect(() => {
    // Only auto-hydrate if the input is effectively empty or contains only scaffold placeholders
    const isEmpty = !inputJson || inputJson.trim() === "" || inputJson === "{}" || inputJson === "{\n}";
    
    // Check if the current input is just a scaffold (keys exist, values are empty)
    let isScaffold = false;
    try {
        const currentObj = JSON.parse(inputJson);
        const keys = Object.keys(currentObj);
        if (variables.length > 0 && keys.length > 0) {
           isScaffold = variables.every(v => keys.includes(v) && (currentObj[v] === "" || currentObj[v] === "QUERY_UPSTREAM"));
        }
    } catch {}

    if (upstreamData && (isEmpty || isScaffold)) {
      try {
        // Validate it's proper JSON before setting
        const parsed = JSON.parse(upstreamData);
        setInputJson(JSON.stringify(parsed, null, 2));
      } catch {
        // If upstream isn't JSON (e.g. raw LLM text), wrap it for safety so test logic doesn't break
        setInputJson(JSON.stringify({ raw_input: upstreamData }, null, 2));
      }
    } else if ((isEmpty || isScaffold) && variables.length > 0 && !upstreamData) {
      // Fallback: Scaffold variables if no upstream data is available yet
      const scaffold: Record<string, string> = {};
      variables.forEach(v => scaffold[v] = ""); 
      setInputJson(JSON.stringify(scaffold, null, 2));
    }
  }, [upstreamData, node.id, variables]); 

  // Form Change Handlers
  const handleVarChange = (key: string, value: string) => {
    try {
        const current = JSON.parse(inputJson);
        current[key] = value;
        setInputJson(JSON.stringify(current, null, 2));
    } catch {
        // If JSON is broken, reconstruct it
        const newObj: Record<string, string> = {};
        newObj[key] = value;
        setInputJson(JSON.stringify(newObj, null, 2));
    }
  };

  const getVarValue = (key: string) => {
      try {
          const data = JSON.parse(inputJson);
          return data[key] || "";
      } catch { return ""; }
  };

  const handleTestRun = async () => {
    setLoading(true);
    setOutput(null);
    try {
      // Pass the fully hydrated config to the backend
      const configPayload = node.config?.logic || {};
      
      const result = await invoke<any>("test_node_execution", {
        nodeType: node.type,
        config: configPayload, 
        input: inputJson,
        nodeId: node.id
      });
      
      setOutput(JSON.stringify(result, null, 2));

      // [CRITICAL] Propagate result to Global Graph State if successful
      // This enables "Chain Reaction" debugging: Fixing Node A updates Node B's context instantly
      if (result.status === "success" && onRunComplete) {
        onRunComplete(node.id, result);
      }

    } catch (e) {
      setOutput(`Error: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel-section">
      <div className="section-title-row" style={{marginBottom: 8}}>
         <span className="section-title">Test Context</span>
         <div style={{display: 'flex', gap: 4}}>
            <button 
                className={`btn ${activeTab === 'form' ? 'btn-primary' : ''}`} 
                style={{padding: '2px 6px', fontSize: 10, height: 20}}
                onClick={() => setActiveTab('form')}
                disabled={variables.length === 0}
                title="Structured input for template variables"
            >
                Form
            </button>
            <button 
                className={`btn ${activeTab === 'json' ? 'btn-primary' : ''}`} 
                style={{padding: '2px 6px', fontSize: 10, height: 20}}
                onClick={() => setActiveTab('json')}
                title="Raw JSON input"
            >
                JSON
            </button>
         </div>
      </div>

      <div className="config-field">
        {activeTab === 'form' && variables.length > 0 ? (
            <div style={{display: 'flex', flexDirection: 'column', gap: 8, background: '#0D0F12', padding: 8, borderRadius: 4, border: '1px solid #3F4652'}}>
                {variables.map(v => (
                    <div key={v}>
                        <label className="config-label" style={{fontSize: 10, color: '#A78BFA'}}>{v}</label>
                        <input 
                            className="input" 
                            style={{padding: 6}}
                            value={getVarValue(v)}
                            onChange={(e) => handleVarChange(v, e.target.value)}
                            placeholder={`Value for ${v}...`}
                        />
                    </div>
                ))}
            </div>
        ) : (
            <textarea 
              className="input code-editor" 
              rows={6} 
              value={inputJson}
              onChange={(e) => setInputJson(e.target.value)}
              spellCheck={false}
            />
        )}
        
        {upstreamData && activeTab === 'json' && (
            <div style={{ color: '#34D399', fontSize: 10, marginTop: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                <span>●</span> Syncing with Upstream Graph Output
            </div>
        )}
      </div>
      
      <button className="btn btn-primary full-width" onClick={handleTestRun} disabled={loading} style={{marginTop: 8}}>
        {loading ? "Running..." : "Run Unit Test & Update Graph"}
      </button>
      
      <div className="divider" />
      
      <label className="config-label">Output Preview</label>
      <div className={`output-preview ${output ? '' : 'empty'}`}>
        {output ? <code style={{ color: '#A78BFA' }}>{output}</code> : <span className="text-muted">No run data yet...</span>}
      </div>
    </div>
  );
}