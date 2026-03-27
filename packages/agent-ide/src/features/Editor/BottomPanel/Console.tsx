import { useState } from "react";
import { TraceViewer, TraceSpan } from "../Trace/TraceViewer";
import "./Console.css";

interface ConsoleProps {
  logs: any[];
  height: number;
  selectedArtifact?: any; 
  onCollapse?: () => void;
}

export function Console({ logs, height, selectedArtifact, onCollapse }: ConsoleProps) {
  const [activeTab, setActiveTab] = useState<'logs' | 'trace' | 'receipts'>('logs');
  const imagePreviewBase64 =
    typeof selectedArtifact?.data?.image_base64 === "string"
      ? selectedArtifact.data.image_base64
      : null;
  const imagePreviewMimeType =
    typeof selectedArtifact?.data?.mime_type === "string"
      ? selectedArtifact.data.mime_type
      : "image/png";
  const audioPreviewBase64 =
    typeof selectedArtifact?.data?.audio_base64 === "string"
      ? selectedArtifact.data.audio_base64
      : null;
  const audioPreviewMimeType =
    typeof selectedArtifact?.data?.mime_type === "string"
      ? selectedArtifact.data.mime_type
      : "audio/wav";
  const videoPreviewBase64 =
    typeof selectedArtifact?.data?.video_base64 === "string"
      ? selectedArtifact.data.video_base64
      : null;
  const videoPreviewMimeType =
    typeof selectedArtifact?.data?.mime_type === "string"
      ? selectedArtifact.data.mime_type
      : "video/mp4";
  const sanitizedArtifact =
    selectedArtifact
      ? {
          ...selectedArtifact,
          data: {
            ...selectedArtifact.data,
            ...(imagePreviewBase64
              ? {
                  image_base64: `[omitted ${imagePreviewBase64.length} base64 chars; preview rendered above]`,
                }
              : {}),
            ...(audioPreviewBase64
              ? {
                  audio_base64: `[omitted ${audioPreviewBase64.length} base64 chars; preview rendered above]`,
                }
              : {}),
            ...(videoPreviewBase64
              ? {
                  video_base64: `[omitted ${videoPreviewBase64.length} base64 chars; preview rendered above]`,
                }
              : {}),
          },
        }
      : selectedArtifact;

  // Convert logs to mock traces for visualization
  const traces: TraceSpan[] = logs.map(l => ({
      id: `${l.id}`, name: l.source, type: 'action', status: l.level === 'error' ? 'error' : 'success', startTime: l.id, endTime: l.id + 100
  }));

  return (
    <div className="console-panel" style={{ height }}>
      <div className="console-tabs">
        <div className="console-tab-strip">
          <button 
              className={`console-tab ${activeTab === 'logs' ? 'active' : ''}`}
              onClick={() => setActiveTab('logs')}
          >
              LOGS
          </button>
          <button 
              className={`console-tab ${activeTab === 'trace' ? 'active' : ''}`}
              onClick={() => setActiveTab('trace')}
          >
              TRACE
          </button>
          <button 
              className={`console-tab ${activeTab === 'receipts' ? 'active' : ''}`}
              onClick={() => setActiveTab('receipts')}
          >
              RECEIPTS
              {selectedArtifact && <span style={{background: 'var(--surface-4)', padding: '1px 4px', borderRadius: 4, fontSize: 9}}>1</span>}
          </button>
        </div>
        {onCollapse ? (
          <button className="console-collapse-btn" onClick={onCollapse} type="button">
            Hide
          </button>
        ) : null}
      </div>

      <div className="console-content">
        {activeTab === 'logs' && (
            <div>
                {logs.length === 0 && <div className="empty-logs">No logs yet. Run the graph to see activity.</div>}
                {logs.map(log => (
                    <div key={log.id} className={`log-entry ${log.level}`}>
                        <span className="log-time">[{new Date(log.id).toLocaleTimeString()}]</span>
                        <span className="log-source">{log.source}:</span>
                        {log.message}
                    </div>
                ))}
            </div>
        )}
        {activeTab === 'trace' && <TraceViewer spans={traces} />}
        {activeTab === 'receipts' && (
            <div style={{ padding: '8px', color: 'var(--text-primary)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                {selectedArtifact ? (
                    <>
                      {imagePreviewBase64 ? (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ marginBottom: 6, fontFamily: 'var(--font-sans, sans-serif)', fontSize: '12px' }}>
                            Artifact Preview
                          </div>
                          <img
                            src={`data:${imagePreviewMimeType};base64,${imagePreviewBase64}`}
                            alt="Receipt artifact preview"
                            style={{
                              width: '100%',
                              maxHeight: 240,
                              objectFit: 'contain',
                              borderRadius: 8,
                              border: '1px solid var(--border-subtle)',
                              background: 'var(--surface-2)',
                            }}
                          />
                        </div>
                      ) : null}
                      {audioPreviewBase64 ? (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ marginBottom: 6, fontFamily: 'var(--font-sans, sans-serif)', fontSize: '12px' }}>
                            Audio Preview
                          </div>
                          <audio
                            controls
                            src={`data:${audioPreviewMimeType};base64,${audioPreviewBase64}`}
                            style={{ width: '100%' }}
                          />
                        </div>
                      ) : null}
                      {videoPreviewBase64 ? (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ marginBottom: 6, fontFamily: 'var(--font-sans, sans-serif)', fontSize: '12px' }}>
                            Video Preview
                          </div>
                          <video
                            controls
                            src={`data:${videoPreviewMimeType};base64,${videoPreviewBase64}`}
                            style={{
                              width: '100%',
                              maxHeight: 260,
                              borderRadius: 8,
                              border: '1px solid var(--border-subtle)',
                              background: 'var(--surface-2)',
                            }}
                          />
                        </div>
                      ) : null}
                      <pre>{JSON.stringify(sanitizedArtifact, null, 2)}</pre>
                    </>
                ) : (
                    <div className="empty-logs">Select a node with execution results.</div>
                )}
            </div>
        )}
      </div>
    </div>
  );
}
