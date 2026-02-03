import { useState } from "react";
import { TraceViewer, TraceSpan } from "../Trace/TraceViewer";
import "./Console.css";

interface ConsoleProps {
  logs: any[];
  height: number;
  selectedArtifact?: any; 
}

export function Console({ logs, height, selectedArtifact }: ConsoleProps) {
  const [activeTab, setActiveTab] = useState<'logs' | 'trace' | 'receipts'>('logs');

  // Convert logs to mock traces for visualization
  const traces: TraceSpan[] = logs.map(l => ({
      id: `${l.id}`, name: l.source, type: 'action', status: l.level === 'error' ? 'error' : 'success', startTime: l.id, endTime: l.id + 100
  }));

  return (
    <div className="console-panel" style={{ height }}>
      <div className="console-tabs">
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
                    <pre>{JSON.stringify(selectedArtifact, null, 2)}</pre>
                ) : (
                    <div className="empty-logs">Select a node with execution results.</div>
                )}
            </div>
        )}
      </div>
    </div>
  );
}