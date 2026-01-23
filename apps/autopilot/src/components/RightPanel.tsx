// src/components/RightPanel.tsx
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Node, NodeLogic, NodeLaw } from "../types";
import "./RightPanel.css";
import "./PolicyInspector.css"; // Reuse existing styles

// --- ICONS ---
const PlayIcon = () => <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>;
const ShieldIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const BrainIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"/></svg>;
const TerminalIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;

interface RightPanelProps {
  width: number;
  selectedNode: Node | null;
  // Updater function passed from StudioWindow to sync ReactFlow state
  onUpdateNode?: (nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<NodeLaw>) => void;
  // [NEW] Upstream data from the Orchestrator for Context-Aware Debugging
  upstreamData?: string;
  // [NEW] Callback for stateful debugging - updates graph state on successful run
  onRunComplete?: (nodeId: string, artifact: any) => void;
}

type InspectorTab = "LOGIC" | "LAW" | "SIM";

// [NEW] Helper to extract variables {{var_name}} from template strings
function extractVariables(template: string): string[] {
  const regex = /{{([^}]+)}}/g;
  const matches = new Set<string>();
  let match;
  while ((match = regex.exec(template)) !== null) {
    matches.add(match[1].trim());
  }
  return Array.from(matches);
}

export function RightPanel({ width, selectedNode, onUpdateNode, upstreamData, onRunComplete }: RightPanelProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("LOGIC");

  useEffect(() => {
    // Reset to Logic when selecting a new node
    setActiveTab("LOGIC");
  }, [selectedNode?.id]);

  if (!selectedNode) {
    return (
      <aside className="right-panel empty" style={{ width }}>
        <div className="panel-empty">
          <div className="empty-text">No Selection</div>
          <div className="empty-hint">Select a node to edit Logic or Law</div>
        </div>
      </aside>
    );
  }

  // Helper wrapper for updates
  const handleUpdate = (section: 'logic' | 'law', updates: any) => {
    if (onUpdateNode) {
      onUpdateNode(selectedNode.id, section, updates);
    }
  };

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

      {/* 3-WAY TAB SWITCHER: The Core of "Constitution Editor" */}
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
  const variables = extractVariables(activeTemplate);

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

      {node.type === "tool" && (
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

// =========================================
// VIEW 2: LAW (The Constitution)
// Defines *what* the agent is ALLOWED to do.
// =========================================

interface PolicyViewProps {
  node: Node;
  onUpdate: (section: 'law', data: Partial<NodeLaw>) => void;
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
  const variables = extractVariables(promptTemplate);

  // Switch to Form view by default if variables exist
  useEffect(() => {
      if (variables.length > 0) setActiveTab('form');
  }, [variables.length]);

  // [NEW] Context-Aware Debugging: Hydrate input from upstream artifacts
  useEffect(() => {
    if (upstreamData && upstreamData.trim() !== "") {
      setInputJson(upstreamData);
    } else {
      // If no upstream, try to scaffold the input based on variables
      if (variables.length > 0) {
          const scaffold: Record<string, string> = {};
          variables.forEach(v => scaffold[v] = "");
          setInputJson(JSON.stringify(scaffold, null, 2));
      }
    }
  }, [upstreamData, node.id, variables.length]);

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
        input: inputJson
      });
      
      setOutput(JSON.stringify(result, null, 2));

      // [CRITICAL] Propagate result to Global Graph State if successful
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