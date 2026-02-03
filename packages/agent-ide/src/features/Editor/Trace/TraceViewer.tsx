// packages/agent-ide/src/features/Editor/Trace/TraceViewer.tsx
import "./TraceViewer.css";

export interface TraceSpan {
  id: string;
  name: string;
  type: string;
  status: "running" | "success" | "error";
  startTime: number;
  endTime?: number;
  children?: TraceSpan[];
}

interface TraceViewerProps {
  spans: TraceSpan[];
  onSelectSpan?: (spanId: string) => void;
}

export function TraceViewer({ spans, onSelectSpan }: TraceViewerProps) {
  const rootStart = spans.length > 0 ? Math.min(...spans.map(s => s.startTime)) : Date.now();
  
  const renderRow = (span: TraceSpan, depth: number) => {
    const startOffset = span.startTime - rootStart;
    const duration = (span.endTime || Date.now()) - span.startTime;
    
    return (
      <div key={span.id} 
           onClick={() => onSelectSpan?.(span.id)}
           style={{ 
             display: 'flex', padding: '4px 0', 
             borderBottom: '1px solid var(--border-subtle)',
             cursor: 'pointer' 
           }}>
        <div style={{ width: '200px', paddingLeft: depth * 12 + 8, fontSize: '11px', color: 'var(--text-primary)' }}>
          {span.name}
        </div>
        <div style={{ flex: 1, position: 'relative', height: '16px' }}>
          <div style={{
            position: 'absolute',
            left: `${Math.max(0, startOffset / 100)}%`, // Simplified scaling for mock
            width: `${Math.max(1, duration / 100)}%`, // Simplified scaling
            height: '100%',
            background: span.status === 'error' ? 'var(--status-error)' : 'var(--accent-blue)',
            borderRadius: '2px',
            opacity: 0.6
          }} />
        </div>
      </div>
    );
  };

  return (
    <div className="trace-viewer" style={{ height: '100%', overflowY: 'auto' }}>
      {spans.map(s => renderRow(s, 0))}
    </div>
  );
}