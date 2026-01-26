// apps/autopilot/src/components/RightPanel/views/LogicView.tsx
import { useMemo, useRef } from "react";
import { Node, NodeLogic } from "../../../types";
import { extractVariables } from "../utils";

interface LogicViewProps {
  node: Node;
  onUpdate: (section: 'logic', data: Partial<NodeLogic>) => void;
  upstreamNodes?: Node[];
}

export function LogicView({ node, onUpdate, upstreamNodes = [] }: LogicViewProps) {
  const config = node.config?.logic || {};
  
  // Track the last active text area to know where to insert variables
  const lastActiveInputRef = useRef<"systemPrompt" | "bodyTemplate" | "query" | null>(null);

  // Helper to insert variable into the active field
  const insertVariable = (varName: string) => {
    const targetField = lastActiveInputRef.current || (node.type === "model" ? "systemPrompt" : "bodyTemplate");
    // @ts-ignore
    const currentVal = config[targetField] || "";
    const newVal = currentVal + ` {{${varName}}} `;
    onUpdate('logic', { [targetField]: newVal });
  };

  const activeTemplate = config.systemPrompt || config.bodyTemplate || config.query || "";
  const usedVariables = useMemo(() => extractVariables(activeTemplate), [activeTemplate]);
  const isDynamicTool = node.type === "tool" && !!node.schema;

  // Derive available variables from upstream nodes
  const availableContext = useMemo(() => {
    return upstreamNodes.map(n => ({
      id: n.id,
      name: n.name || n.id,
      // Default output key for now, could be dynamic based on ioTypes
      varKey: `${n.id}` // Using ID directly as per backend orchestrator map
    }));
  }, [upstreamNodes]);

  return (
    <div className="properties-container">
      {/* --- Context Source Strip (SimStudio DX) --- */}
      {availableContext.length > 0 && (
        <div className="panel-section" style={{ borderBottom: '1px solid #2E333D', paddingBottom: 12 }}>
          <div className="section-title-row">
            <span className="section-title">Available Context</span>
            <span className="badge">{availableContext.length} Sources</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {availableContext.map(ctx => (
              <button
                key={ctx.id}
                className="btn"
                style={{ 
                  fontSize: 10, 
                  padding: '4px 8px', 
                  background: '#1F2329', 
                  border: '1px solid #3F4652',
                  color: '#A78BFA'
                }}
                onClick={() => insertVariable(ctx.varKey)}
                title={`Insert output from ${ctx.name}`}
              >
                + {ctx.name}
              </button>
            ))}
          </div>
        </div>
      )}

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
            </label>
            <textarea 
              className="input code-editor" 
              rows={8}
              value={config.systemPrompt || ""}
              onFocus={() => lastActiveInputRef.current = "systemPrompt"}
              onChange={(e) => onUpdate('logic', { systemPrompt: e.target.value })}
              placeholder="You are an expert analyst. Analyze the input: {{input}}..."
            />
            {/* Variable Validation Badges */}
            {usedVariables.length > 0 && (
                <div style={{display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 6}}>
                    {usedVariables.map(v => {
                        // Check if variable exists in upstream context or standard inputs
                        const isBound = v === "input" || availableContext.some(c => c.varKey === v);
                        return (
                            <span 
                                key={v} 
                                style={{
                                    fontSize: 9, 
                                    background: isBound ? 'rgba(52, 211, 153, 0.1)' : 'rgba(248, 113, 113, 0.1)', 
                                    border: `1px solid ${isBound ? 'rgba(52, 211, 153, 0.2)' : 'rgba(248, 113, 113, 0.3)'}`,
                                    padding: '2px 6px', 
                                    borderRadius: 4, 
                                    color: isBound ? '#34D399' : '#F87171'
                                }}
                                title={isBound ? "Linked to valid source" : "Variable source missing"}
                            >
                                {v} {isBound ? '✓' : '?'}
                            </span>
                        );
                    })}
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

      {isDynamicTool && node.schema && (
        <DynamicToolConfig 
          schemaStr={node.schema} 
          // @ts-ignore
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
            </label>
            <textarea 
              className="input code-editor" 
              rows={5}
              value={config.bodyTemplate || ""}
              onFocus={() => lastActiveInputRef.current = "bodyTemplate"}
              onChange={(e) => onUpdate('logic', { bodyTemplate: e.target.value })}
              placeholder='{"query": "{{input}}"}'
            />
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

      {/* [NEW] Retrieval Logic */}
      {node.type === "retrieval" && (
        <RetrievalLogicConfig 
            node={node} 
            onUpdate={onUpdate} 
            variables={usedVariables}
            onFocus={() => lastActiveInputRef.current = "query"} 
        />
      )}

      {node.type === "code" && <CodeLogicConfig node={node} />}
      {node.type === "router" && <RouterLogicConfig node={node} />}
      {node.type === "wait" && <WaitLogicConfig node={node} />}
      {node.type === "context" && <VariableLogicConfig node={node} />}
      
      {!["model", "tool", "trigger", "code", "router", "wait", "context", "retrieval"].includes(node.type) && !isDynamicTool && (
        <div className="panel-empty" style={{ padding: 20 }}>
          <span className="empty-hint">No configurable logic for this node type.</span>
        </div>
      )}
    </div>
  );
}

// --- Sub-Components ---

function CodeLogicConfig({ node }: { node: Node }) {
  return (
    <div className="panel-section">
      <div className="section-title-row"><span className="section-title">Code Execution</span></div>
      <div className="config-field">
        <label className="config-label">Runtime</label>
        <select className="input" defaultValue={node.config?.logic?.language || "python"}>
          <option value="python">Python 3 (Sandboxed)</option>
          <option value="javascript">Node.js (Sandboxed)</option>
          <option value="shell">System Shell (Unsafe)</option>
        </select>
      </div>
      <div className="config-field">
        <label className="config-label">Script</label>
        <textarea 
          className="input code-editor" 
          rows={12}
          defaultValue={node.config?.logic?.code}
          placeholder="def main(input): ..."
          style={{ fontFamily: 'monospace', fontSize: 11 }}
        />
        <div className="approval-hint" style={{marginLeft: 0, marginTop: 4, color: '#6B7280'}}>
          Input available as <code>input</code> dictionary. Return JSON.
        </div>
      </div>
    </div>
  );
}

function RouterLogicConfig({ node }: { node: Node }) {
  const routes = node.config?.logic?.routes || [];
  return (
    <div className="panel-section">
      <div className="section-title-row"><span className="section-title">Semantic Routing</span></div>
      <div className="config-field">
        <label className="config-label">Instruction</label>
        <textarea 
          className="input" 
          rows={2}
          defaultValue={node.config?.logic?.routerInstruction}
        />
      </div>
      <div className="config-field">
        <label className="config-label">Routes (Outputs)</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {routes.map((r: string, i: number) => (
            <div key={i} style={{ display: 'flex', gap: 4 }}>
              <input className="input" defaultValue={r} />
              <button className="btn btn-primary" style={{ padding: '0 8px', background: 'transparent', border: '1px solid #3F4652', color: '#9CA3AF' }}>×</button>
            </div>
          ))}
          <button className="btn btn-primary full-width" style={{background: 'transparent', border: '1px solid #3D85C6', color: '#3D85C6'}}>+ Add Route</button>
        </div>
      </div>
    </div>
  );
}

function WaitLogicConfig({ node }: { node: Node }) {
  return (
    <div className="panel-section">
      <div className="section-title-row"><span className="section-title">Delay</span></div>
      <div className="config-field">
        <label className="config-label">Duration (ms)</label>
        <input type="number" className="input" defaultValue={node.config?.logic?.durationMs} />
      </div>
    </div>
  );
}

function VariableLogicConfig({ node }: { node: Node }) {
  return (
    <div className="panel-section">
      <div className="section-title-row"><span className="section-title">Context Variables</span></div>
      <div className="config-field">
        <label className="config-label">Key-Value Pairs (JSON)</label>
        <textarea 
          className="input code-editor" 
          rows={6}
          defaultValue={JSON.stringify(node.config?.logic?.variables || {}, null, 2)}
        />
      </div>
    </div>
  );
}

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

// [NEW] Retrieval Logic Config Component
function RetrievalLogicConfig({ node, onUpdate, variables, onFocus }: { node: Node, onUpdate: any, variables: string[], onFocus: () => void }) {
  const logic = node.config?.logic || {};

  return (
    <div className="panel-section">
      <div className="section-title-row">
        <span className="section-title">Vector Search</span>
        <span className="badge">mHNSW</span>
      </div>
      
      <div className="config-field">
        <label className="config-label">
            Search Query Template
        </label>
        <textarea 
          className="input code-editor" 
          rows={3}
          value={logic.query || ""}
          onFocus={onFocus}
          onChange={(e) => onUpdate('logic', { query: e.target.value })}
          placeholder="{{input.question}}"
        />
        <div className="approval-hint" style={{marginLeft: 0, marginTop: 4, color: '#6B7280'}}>
          The text to embed and match against the Sovereign Context Store.
        </div>
      </div>

      <div className="config-field">
        <label className="config-label">Max Results (Top K)</label>
        <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
            <input 
              type="range" 
              className="slider" 
              min="1" max="20" step="1"
              value={logic.limit || 3}
              onChange={(e) => onUpdate('logic', { limit: parseInt(e.target.value) })}
              style={{flex: 1}}
            />
            <span style={{fontFamily: 'monospace', fontSize: 12, color: '#E5E7EB', width: 20}}>
                {logic.limit || 3}
            </span>
        </div>
      </div>
    </div>
  );
}