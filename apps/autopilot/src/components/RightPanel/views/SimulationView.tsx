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

export function SimulationView({ node, upstreamData, onRunComplete }: SimulationViewProps) {
  const [inputJson, setInputJson] = useState('{\n  "amount": 450.00,\n  "vendor": "Unknown"\n}');
  const [output, setOutput] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'form' | 'json'>('json');

  // [Governance Loop]: Inject Active Session ID so backend can validate approvals
  const { task } = useAgentStore();

  const promptTemplate = node.config?.logic?.systemPrompt || node.config?.logic?.bodyTemplate || "";
  const variables = useMemo(() => extractVariables(promptTemplate), [promptTemplate]);

  useEffect(() => {
      if (variables.length > 0) setActiveTab('form');
  }, [variables.length]);

  // Intelligent Context Hydration
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
    setOutput(null);
    try {
      const configPayload = node.config?.logic || {};
      
      const result = await invoke<any>("test_node_execution", {
        nodeType: node.type,
        config: configPayload, 
        input: inputJson,
        nodeId: node.id,
        // Pass Active Session ID for Governance Authorization
        session_id: task?.session_id || null
      });
      
      setOutput(JSON.stringify(result, null, 2));

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