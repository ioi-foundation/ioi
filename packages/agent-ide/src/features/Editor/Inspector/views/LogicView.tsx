import { NodeLogic } from "../../../../types/graph";

interface LogicViewProps {
  config: NodeLogic;
  onChange: (updates: Partial<NodeLogic>) => void;
  type: string;
  availableModelRefs?: string[];
}

export function LogicView({
  config,
  onChange,
  type,
  availableModelRefs = [],
}: LogicViewProps) {
  const currentModel = config.model || config.modelId || "gpt-4o";
  const currentModelRef = config.modelRef || "";
  const isResponsesNode = type === "model" || type === "responses";
  const preferredModelRefByType: Record<string, string[]> = {
    model: ["reasoning"],
    responses: ["reasoning"],
    embeddings: ["embedding"],
    rerank: ["reasoning", "embedding"],
    vision_read: ["vision"],
    generate_image: ["image"],
    edit_image: ["image"],
  };
  const allowedModelRefs =
    preferredModelRefByType[type]?.filter((ref) => availableModelRefs.includes(ref)) || [];
  const supportsModelBinding = allowedModelRefs.length > 0;
  const modelSelectorFields = supportsModelBinding ? (
    <>
      <div className="form-group">
        <label>Model Reference</label>
        <select
          value={currentModelRef}
          onChange={e => onChange({ modelRef: e.target.value || undefined })}
        >
          <option value="">Use explicit model id</option>
          {allowedModelRefs.map((modelRef) => (
            <option key={modelRef} value={modelRef}>
              {modelRef}
            </option>
          ))}
        </select>
        <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 6 }}>
          When set, this node resolves its concrete model from the graph&apos;s model bindings.
        </div>
      </div>
    </>
  ) : null;
  const explicitModelField = (
    <div className="form-group">
      <label>Explicit Model Fallback</label>
      <input
        value={currentModel}
        onChange={e => onChange({ model: e.target.value, modelId: e.target.value })}
        placeholder="gpt-4o, codex-oss, llama3..."
      />
    </div>
  );
  const modelBindingFields = (
    <>
      {modelSelectorFields}
      {explicitModelField}
    </>
  );

  return (
    <div className="inspector-view">
      {isResponsesNode && (
        <>
          {modelBindingFields}
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
            <label>Prompt Template</label>
            <textarea
              rows={6}
              value={config.prompt || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="Summarize {{input}} and preserve the evidence trail."
            />
          </div>
          <div className="form-group">
            <label>Temperature: {config.temperature ?? 0.2}</label>
            <input 
              type="range" min="0" max="1" step="0.1"
              value={config.temperature ?? 0.2}
              onChange={e => onChange({ temperature: parseFloat(e.target.value) })}
            />
          </div>
          <div className="form-group">
            <label>Max Tokens</label>
            <input
              type="number"
              min="1"
              step="1"
              value={config.maxTokens ?? 512}
              onChange={e => onChange({ maxTokens: parseInt(e.target.value || "512", 10) })}
            />
          </div>
          <div className="form-group">
            <label>
              <input
                type="checkbox"
                checked={config.stream ?? false}
                onChange={e => onChange({ stream: e.target.checked })}
              />
              Stream output when supported
            </label>
          </div>
          <div className="form-group">
            <label>
              <input
                type="checkbox"
                checked={config.jsonMode ?? false}
                onChange={e => onChange({ jsonMode: e.target.checked })}
              />
              Prefer JSON mode
            </label>
          </div>
        </>
      )}

      {type === "embeddings" && (
        <>
          {modelBindingFields}
          <div className="form-group">
            <label>Text Template</label>
            <textarea
              rows={6}
              value={config.text || config.query || ""}
              onChange={e => onChange({ text: e.target.value })}
              placeholder="{{input}}"
            />
          </div>
        </>
      )}

      {type === "rerank" && (
        <>
          {modelBindingFields}
          <div className="form-group">
            <label>Query Template</label>
            <textarea
              rows={4}
              value={config.query || ""}
              onChange={e => onChange({ query: e.target.value })}
              placeholder="Which candidate best matches {{input}}?"
            />
          </div>
          <div className="form-group">
            <label>Top K</label>
            <input
              type="number"
              min="1"
              step="1"
              value={config.topK ?? 3}
              onChange={e => onChange({ topK: parseInt(e.target.value || "3", 10) })}
            />
          </div>
          <div className="form-group">
            <label>Candidates</label>
            <textarea
              rows={8}
              value={config.candidatesText || ""}
              onChange={e => onChange({ candidatesText: e.target.value })}
              placeholder={"Candidate one\nCandidate two\nCandidate three"}
            />
          </div>
        </>
      )}

      {type === "transcribe_audio" && (
        <>
          {explicitModelField}
          <div className="form-group">
            <label>Audio Path</label>
            <input
              value={config.audioPath || ""}
              onChange={e => onChange({ audioPath: e.target.value })}
              placeholder="/path/to/audio.wav"
            />
          </div>
          <div className="form-group">
            <label>MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="audio/wav"
            />
          </div>
          <div className="form-group">
            <label>Language Hint</label>
            <input
              value={config.audioLanguage || config.language || ""}
              onChange={e => onChange({ audioLanguage: e.target.value })}
              placeholder="en"
            />
          </div>
        </>
      )}

      {type === "synthesize_speech" && (
        <>
          {explicitModelField}
          <div className="form-group">
            <label>Speech Text / Prompt</label>
            <textarea
              rows={5}
              value={config.prompt || config.text || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="Read the latest system status update in a calm operator voice."
            />
          </div>
          <div className="form-group">
            <label>Voice</label>
            <input
              value={config.voice || ""}
              onChange={e => onChange({ voice: e.target.value })}
              placeholder="alloy, nova, operator..."
            />
          </div>
          <div className="form-group">
            <label>Output MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="audio/wav"
            />
          </div>
        </>
      )}

      {type === "vision_read" && (
        <>
          {modelBindingFields}
          <div className="form-group">
            <label>Image Path</label>
            <input
              value={config.imagePath || ""}
              onChange={e => onChange({ imagePath: e.target.value })}
              placeholder="/path/to/screenshot.png"
            />
          </div>
          <div className="form-group">
            <label>MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="image/png"
            />
          </div>
          <div className="form-group">
            <label>Vision Prompt</label>
            <textarea
              rows={5}
              value={config.prompt || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="Describe the UI state and call out any blocking errors."
            />
          </div>
        </>
      )}

      {type === "generate_image" && (
        <>
          {modelBindingFields}
          <div className="form-group">
            <label>Image Prompt</label>
            <textarea
              rows={6}
              value={config.prompt || config.text || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="A precise studio render of the control plane as a brass instrument panel."
            />
          </div>
          <div className="form-group">
            <label>Output MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="image/png"
            />
          </div>
        </>
      )}

      {type === "edit_image" && (
        <>
          {modelBindingFields}
          <div className="form-group">
            <label>Source Image Path</label>
            <input
              value={config.imagePath || ""}
              onChange={e => onChange({ imagePath: e.target.value })}
              placeholder="/path/to/source.png"
            />
          </div>
          <div className="form-group">
            <label>Mask Image Path</label>
            <input
              value={config.maskImagePath || ""}
              onChange={e => onChange({ maskImagePath: e.target.value })}
              placeholder="/path/to/mask.png"
            />
          </div>
          <div className="form-group">
            <label>Source MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="image/png"
            />
          </div>
          <div className="form-group">
            <label>Edit Prompt</label>
            <textarea
              rows={6}
              value={config.prompt || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="Replace the blank panel with a readable amber status display."
            />
          </div>
        </>
      )}

      {type === "generate_video" && (
        <>
          {explicitModelField}
          <div className="form-group">
            <label>Video Prompt</label>
            <textarea
              rows={6}
              value={config.prompt || config.text || ""}
              onChange={e => onChange({ prompt: e.target.value })}
              placeholder="A slow orbital pass across the Local Engine control plane with amber status lights."
            />
          </div>
          <div className="form-group">
            <label>Output MIME Type</label>
            <input
              value={config.mimeType || ""}
              onChange={e => onChange({ mimeType: e.target.value })}
              placeholder="video/mp4"
            />
          </div>
          <div className="form-group">
            <label>Duration (ms)</label>
            <input
              type="number"
              min="500"
              step="500"
              value={config.durationMs ?? 4000}
              onChange={e => onChange({ durationMs: parseInt(e.target.value || "4000", 10) })}
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
      {!isResponsesNode &&
        type !== "embeddings" &&
        type !== "rerank" &&
        type !== "transcribe_audio" &&
        type !== "synthesize_speech" &&
        type !== "vision_read" &&
        type !== "generate_image" &&
        type !== "edit_image" &&
        type !== "generate_video" &&
        type !== "tool" && (
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
