import { useState, useEffect } from "react";
import { GraphGlobalConfig, Node } from "../../../../types/graph";
import { AgentRuntime } from "../../../../runtime/agent-runtime";

interface SimulationResult {
  status?: string;
  output?: string;
  data?: {
    image_base64?: string;
    audio_base64?: string;
    video_base64?: string;
    mime_type?: string;
  };
  metrics?: {
    latency_ms?: number;
    tokens?: number;
  };
}

interface SimulationViewProps {
  node: Node;
  globalConfig?: GraphGlobalConfig;
  runtime: AgentRuntime;
  onRunComplete?: (result: SimulationResult) => void;
  upstreamContext?: unknown;
}

export function SimulationView({
  node,
  globalConfig,
  runtime,
  onRunComplete,
  upstreamContext,
}: SimulationViewProps) {
  const [inputJson, setInputJson] = useState('{\n  "input": "test"\n}');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SimulationResult | null>(null);

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
      const res = await runtime.runNode(
        node.type,
        node.config?.logic || {},
        inputJson,
        globalConfig
      );
      setResult(res);
      onRunComplete?.(res);
    } catch (e) {
      setResult({ status: 'error', output: String(e) });
    } finally {
      setLoading(false);
    }
  };

  const imagePreviewBase64 = result?.data?.image_base64;
  const imagePreviewMimeType = result?.data?.mime_type || "image/png";
  const audioPreviewBase64 = result?.data?.audio_base64;
  const audioPreviewMimeType = result?.data?.mime_type || "audio/wav";
  const videoPreviewBase64 = result?.data?.video_base64;
  const videoPreviewMimeType = result?.data?.mime_type || "video/mp4";

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
        {upstreamContext != null && (
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
          {typeof imagePreviewBase64 === "string" && imagePreviewBase64.length > 0 ? (
            <div style={{ marginTop: 12 }}>
              <label style={{ display: "block", marginBottom: 6 }}>Artifact Preview</label>
              <img
                src={`data:${imagePreviewMimeType};base64,${imagePreviewBase64}`}
                alt="Node artifact preview"
                style={{
                  width: "100%",
                  maxHeight: 240,
                  objectFit: "contain",
                  borderRadius: 8,
                  border: "1px solid var(--border-subtle)",
                  background: "var(--surface-2)",
                }}
              />
            </div>
          ) : null}
          {typeof audioPreviewBase64 === "string" && audioPreviewBase64.length > 0 ? (
            <div style={{ marginTop: 12 }}>
              <label style={{ display: "block", marginBottom: 6 }}>Audio Preview</label>
              <audio
                controls
                src={`data:${audioPreviewMimeType};base64,${audioPreviewBase64}`}
                style={{ width: "100%" }}
              />
            </div>
          ) : null}
          {typeof videoPreviewBase64 === "string" && videoPreviewBase64.length > 0 ? (
            <div style={{ marginTop: 12 }}>
              <label style={{ display: "block", marginBottom: 6 }}>Video Preview</label>
              <video
                controls
                src={`data:${videoPreviewMimeType};base64,${videoPreviewBase64}`}
                style={{
                  width: "100%",
                  maxHeight: 260,
                  borderRadius: 8,
                  border: "1px solid var(--border-subtle)",
                  background: "var(--surface-2)",
                }}
              />
            </div>
          ) : null}
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
