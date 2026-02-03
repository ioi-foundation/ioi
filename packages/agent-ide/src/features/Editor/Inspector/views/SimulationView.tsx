// packages/agent-ide/src/features/Editor/Inspector/views/SimulationView.tsx
import { useState, useEffect } from "react";
import { Node } from "../../../../types/graph";
import { AgentRuntime } from "../../../../runtime/agent-runtime";

interface SimulationViewProps {
  node: Node;
  runtime: AgentRuntime;
  onRunComplete: (result: any) => void;
  // [NEW] Allows pre-filling context from upstream nodes
  upstreamContext?: any;
}

export function SimulationView({ node, runtime, onRunComplete, upstreamContext }: SimulationViewProps) {
  const [inputJson, setInputJson] = useState('{\n  "input": "test"\n}');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  // Auto-hydrate input when context changes
  useEffect(() => {
    if (upstreamContext) {
        try {
            const contextStr = typeof upstreamContext === 'string' 
                ? upstreamContext 
                : JSON.stringify(upstreamContext, null, 2);
            setInputJson(contextStr);
        } catch {
            // Keep default if serialization fails
        }
    }
  }, [upstreamContext]);

  const handleRun = async () => {
    setLoading(true);
    try {
      const res = await runtime.runNode(node.type, node.config?.logic || {}, inputJson);
      setResult(res);
      onRunComplete(res);
    } catch (e) {
      setResult({ status: 'error', output: String(e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="inspector-view">
      <div className="form-group">
        <label>Test Input (JSON)</label>
        <textarea 
          className="code-editor" 
          rows={6}
          value={inputJson}
          onChange={e => setInputJson(e.target.value)}
        />
        {upstreamContext && (
            <div style={{fontSize: 10, color: 'var(--status-success)', marginTop: 4}}>
                ✓ Hydrated from upstream context
            </div>
        )}
      </div>
      <button 
        className="btn-primary" 
        style={{width: '100%', marginBottom: 16, padding: '8px', background: 'var(--accent-blue)', border: 'none', borderRadius: '4px', color: 'white', fontWeight: 600, cursor: 'pointer', opacity: loading ? 0.7 : 1}}
        onClick={handleRun}
        disabled={loading}
      >
        {loading ? "Running..." : "Execute Node"}
      </button>

      {result && (
        <div className="form-group">
          <label>Result: <span style={{color: result.status === 'success' ? 'var(--status-success)' : 'var(--status-error)'}}>{result.status}</span></label>
          <div className="code-block" style={{padding: 8, background: 'var(--surface-3)', borderRadius: 4, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', maxHeight: '200px', overflow: 'auto'}}>
            {result.output || JSON.stringify(result, null, 2)}
          </div>
          {result.metrics && (
             <div style={{fontSize: 10, color: 'var(--text-tertiary)', marginTop: 4, display: 'flex', gap: 8}}>
                <span>Latency: {result.metrics.latency_ms || 0}ms</span>
                {result.metrics.tokens && <span>Tokens: {result.metrics.tokens}</span>}
             </div>
          )}
        </div>
      )}
    </div>
  );
}