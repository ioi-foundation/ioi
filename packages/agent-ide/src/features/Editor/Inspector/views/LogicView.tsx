import { NodeLogic } from "../../../../types/graph";

interface LogicViewProps {
  config: NodeLogic;
  onChange: (updates: Partial<NodeLogic>) => void;
  type: string;
}

export function LogicView({ config, onChange, type }: LogicViewProps) {
  return (
    <div className="inspector-view">
      {type === "model" && (
        <>
          <div className="form-group">
            <label>Model</label>
            <select 
              value={config.model || "gpt-4o"} 
              onChange={e => onChange({ model: e.target.value })}
            >
              <option value="gpt-4o">GPT-4o</option>
              <option value="claude-3-5-sonnet">Claude 3.5 Sonnet</option>
              <option value="llama-3-70b">Llama 3 (Local)</option>
            </select>
          </div>
          <div className="form-group">
            <label>System Prompt</label>
            <textarea 
              rows={6}
              value={config.systemPrompt || ""}
              onChange={e => onChange({ systemPrompt: e.target.value })}
              placeholder="You are a helpful assistant..."
            />
          </div>
          <div className="form-group">
            <label>Temperature: {config.temperature || 0.7}</label>
            <input 
              type="range" min="0" max="1" step="0.1"
              value={config.temperature || 0.7}
              onChange={e => onChange({ temperature: parseFloat(e.target.value) })}
            />
          </div>
        </>
      )}

      {type === "tool" && (
        <>
           <div className="form-group">
            <label>Tool Name</label>
            <input 
                disabled
                value={config.tool_name || "Generic"}
            />
          </div>
          <div className="form-group">
            <label>Arguments (JSON)</label>
            <textarea 
                rows={8}
                className="code-editor"
                value={JSON.stringify(config.arguments || {}, null, 2)}
                onChange={e => {
                    try { onChange({ arguments: JSON.parse(e.target.value) }); } catch {}
                }}
            />
          </div>
        </>
      )}
      
      {/* Fallback for other types */}
      {type !== "model" && type !== "tool" && (
          <div className="form-group">
             <label>Raw Configuration</label>
             <div className="text-xs text-gray-500 mb-2">JSON Editor</div>
             <textarea 
                rows={10}
                className="code-editor"
                value={JSON.stringify(config, null, 2)}
                onChange={e => {
                    try { onChange(JSON.parse(e.target.value)); } catch {}
                }}
            />
          </div>
      )}
    </div>
  );
}