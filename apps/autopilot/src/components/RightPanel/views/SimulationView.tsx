// apps/autopilot/src/components/RightPanel/views/SimulationView.tsx
import { useState, useEffect, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Node } from "../../../types";
import { useAgentStore } from "../../../store/agentStore";
import { extractVariables } from "../utils";

interface SimulationViewProps {
  node: Node;
  upstreamData?: string;
  onRunComplete?: (id: string, result: any) => void;
}

// [NEW] Structured Result Types matching Rust ExecutionResult
interface ExecResult {
  status: "success" | "blocked" | "error" | "failed";
  output: string;
  metrics?: {
    latency_ms?: number;
    risk?: string;
    cost?: number;
    tokens?: number;
  };
  data?: any;
}

export function SimulationView({ node, upstreamData, onRunComplete }: SimulationViewProps) {
  const [inputJson, setInputJson] = useState('{\n  "amount": 450.00,\n  "vendor": "Unknown"\n}');
  // [MODIFIED] Store structured result object instead of string
  const [lastResult, setLastResult] = useState<ExecResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'form' | 'json'>('json');
  const [showRaw, setShowRaw] = useState(false);

  const { task } = useAgentStore();

  const promptTemplate = node.config?.logic?.systemPrompt || node.config?.logic?.bodyTemplate || "";
  const variables = useMemo(() => extractVariables(promptTemplate), [promptTemplate]);

  useEffect(() => {
      if (variables.length > 0) setActiveTab('form');
  }, [variables.length]);

  // Intelligent Context Hydration (Existing logic preserved)
  useEffect(() => {
    const isEmpty = !inputJson || inputJson.trim() === "" || inputJson === "{}" || inputJson === "{\n}";
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
        const parsed = JSON.parse(upstreamData);
        setInputJson(JSON.stringify(parsed, null, 2));
      } catch {
        setInputJson(JSON.stringify({ raw_input: upstreamData }, null, 2));
      }
    } else if ((isEmpty || isScaffold) && variables.length > 0 && !upstreamData) {
      const scaffold: Record<string, string> = {};
      variables.forEach(v => scaffold[v] = ""); 
      setInputJson(JSON.stringify(scaffold, null, 2));
    }
  }, [upstreamData, node.id, variables]); 

  const handleVarChange = (key: string, value: string) => {
    try {
        const current = JSON.parse(inputJson);
        current[key] = value;
        setInputJson(JSON.stringify(current, null, 2));
    } catch {
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
    setLastResult(null);
    try {
      const configPayload = node.config?.logic || {};
      
      const result = await invoke<ExecResult>("test_node_execution", {
        nodeType: node.type,
        config: configPayload, 
        input: inputJson,
        nodeId: node.id,
        session_id: task?.session_id || null
      });
      
      setLastResult(result);

      if (result.status === "success" && onRunComplete) {
        onRunComplete(node.id, result);
      }

    } catch (e) {
      // Handle IPC errors
      setLastResult({
          status: "error",
          output: `IPC Failure: ${e}`,
      });
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
            >
                Form
            </button>
            <button 
                className={`btn ${activeTab === 'json' ? 'btn-primary' : ''}`} 
                style={{padding: '2px 6px', fontSize: 10, height: 20}}
                onClick={() => setActiveTab('json')}
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
        {loading ? "Running Simulation..." : "Run Unit Test"}
      </button>
      
      <div className="divider" />
      
      {/* [NEW] Structured Result Visualization */}
      <div className="section-title-row" style={{justifyContent: 'space-between'}}>
        <span className="section-title">Result</span>
        {lastResult && (
            <label style={{fontSize: 9, color: '#6B7280', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer'}}>
                <input type="checkbox" checked={showRaw} onChange={e => setShowRaw(e.target.checked)} /> Raw JSON
            </label>
        )}
      </div>

      {!lastResult && (
          <div className="output-preview empty">
            <span className="text-muted">No run data yet...</span>
          </div>
      )}

      {lastResult && showRaw && (
          <div className="output-preview">
            <code style={{ color: '#A78BFA' }}>{JSON.stringify(lastResult, null, 2)}</code>
          </div>
      )}

      {lastResult && !showRaw && (
          <div style={{display: 'flex', flexDirection: 'column', gap: 8}}>
              {/* Status Header */}
              <div style={{
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 8, 
                  padding: '8px 12px', 
                  borderRadius: 6,
                  background: lastResult.status === 'success' ? 'rgba(52, 211, 153, 0.1)' : 
                              lastResult.status === 'blocked' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  border: `1px solid ${lastResult.status === 'success' ? 'rgba(52, 211, 153, 0.2)' : 
                                       lastResult.status === 'blocked' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
              }}>
                  <span style={{fontSize: 16}}>
                      {lastResult.status === 'success' ? '✅' : lastResult.status === 'blocked' ? '🛡️' : '❌'}
                  </span>
                  <div style={{display: 'flex', flexDirection: 'column'}}>
                      <span style={{
                          fontSize: 12, 
                          fontWeight: 700, 
                          color: lastResult.status === 'success' ? '#34D399' : 
                                 lastResult.status === 'blocked' ? '#FBBF24' : '#F87171',
                          textTransform: 'uppercase'
                      }}>
                          {lastResult.status === 'blocked' ? 'Policy Blocked' : 
                           lastResult.status === 'success' ? 'Execution Verified' : 'Runtime Error'}
                      </span>
                      {lastResult.status === 'blocked' && (
                          <span style={{fontSize: 10, color: '#D1D5DB'}}>Action violated Node Law constraints.</span>
                      )}
                  </div>
              </div>

              {/* Metrics Grid */}
              {lastResult.status === 'success' && lastResult.metrics && (
                  <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8}}>
                      <MetricBox label="Latency" value={`${lastResult.metrics.latency_ms || 0}ms`} />
                      <MetricBox label="Tokens" value={lastResult.metrics.tokens || '-'} />
                      <MetricBox label="Risk Score" value={lastResult.metrics.risk || 'Low'} />
                      <MetricBox label="Cost" value={lastResult.metrics.cost ? `$${lastResult.metrics.cost}` : '$0.00'} />
                  </div>
              )}

              {/* Output / Error Message */}
              <div className="config-field">
                  <label className="config-label">
                      {lastResult.status === 'success' ? 'Output Artifact' : 'Violation Reason'}
                  </label>
                  <div className="output-preview" style={{
                      minHeight: 60, 
                      maxHeight: 200, 
                      color: lastResult.status === 'success' ? '#D1D5DB' : '#F87171',
                      border: lastResult.status !== 'success' ? '1px solid #7F1D1D' : undefined
                  }}>
                      {lastResult.output}
                  </div>
              </div>
          </div>
      )}
    </div>
  );
}

function MetricBox({ label, value }: { label: string, value: string | number }) {
    return (
        <div style={{
            background: '#1F2329', 
            border: '1px solid #3F4652', 
            borderRadius: 4, 
            padding: '6px 8px',
            display: 'flex',
            flexDirection: 'column'
        }}>
            <span style={{fontSize: 9, color: '#9CA3AF', textTransform: 'uppercase'}}>{label}</span>
            <span style={{fontSize: 13, fontWeight: 600, color: '#E5E7EB', fontFamily: 'monospace'}}>{value}</span>
        </div>
    );
}