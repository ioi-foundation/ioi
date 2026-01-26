// src/components/TraceViewer.tsx
import type { ReactElement } from "react";
import "./TraceViewer.css";

export interface TraceSpan {
  id: string;
  parentId?: string;
  name: string;
  type: "agent" | "tool" | "chain" | "llm" | "http";
  status: "running" | "success" | "error";
  startTime: number;
  endTime?: number;
  metadata?: {
    model?: string;
    tokens?: number;
    inputs?: any;
    outputs?: any;
    status?: number;
    latency?: string;
    recipient?: string;
  };
  children?: TraceSpan[];
}

interface TraceViewerProps {
  spans: TraceSpan[];
  onSelectSpan: (span: TraceSpan) => void;
  selectedSpanId?: string;
  // [NEW] Hover Interaction
  onHoverSpan?: (spanId: string | null) => void;
}

// --- Icons (Existing map preserved) ---
const Icons: Record<TraceSpan["type"], ReactElement> = {
  agent: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 2a10 10 0 0 1 10 10 10 10 0 0 1-10 10A10 10 0 0 1 2 12 10 10 0 0 1 12 2z" />
      <path d="M12 16v-4" /><path d="M12 8h.01" />
    </svg>
  ),
  tool: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  ),
  http: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  chain: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10 13a5 5 0 0 1 0-7l2-2a5 5 0 1 1 7 7l-1 1" />
      <path d="M14 11a5 5 0 0 1 0 7l-2 2a5 5 0 1 1-7-7l1-1" />
    </svg>
  ),
  llm: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 18h6" />
      <path d="M10 22h4" />
      <path d="M12 2a7 7 0 0 0-4 12c.6.5 1 1.3 1 2.1V17h6v-.9c0-.8.4-1.6 1-2.1a7 7 0 0 0-4-12z" />
    </svg>
  ),
};

export function TraceViewer({ spans, onSelectSpan, selectedSpanId, onHoverSpan }: TraceViewerProps) {
  // Calculate global time range for relative width
  // Flatten tree to find min/max
  const getAllSpans = (nodes: TraceSpan[]): TraceSpan[] => {
      let acc: TraceSpan[] = [];
      for (const node of nodes) {
          acc.push(node);
          if (node.children) acc = acc.concat(getAllSpans(node.children));
      }
      return acc;
  };
  
  const allSpans = getAllSpans(spans);
  const rootStart = allSpans.length > 0 ? Math.min(...allSpans.map(s => s.startTime)) : Date.now();
  const rootEnd = allSpans.length > 0 ? Math.max(...allSpans.map(s => s.endTime || Date.now())) : Date.now();
  const totalDuration = Math.max(rootEnd - rootStart, 100); // Minimum 100ms scope

  const renderRow = (span: TraceSpan, depth: number) => {
    const duration = (span.endTime || Date.now()) - span.startTime;
    const startPct = ((span.startTime - rootStart) / totalDuration) * 100;
    const widthPct = Math.max((duration / totalDuration) * 100, 0.5); // Min width 0.5% for visibility

    const barColor = span.status === "error" ? "#EF4444" : 
                     span.type === "agent" ? "#3D85C6" : 
                     span.type === "tool" ? "#A78BFA" : "#34D399";

    return (
      <div key={span.id} className="trace-row-wrapper">
        <div 
          className={`trace-row ${selectedSpanId === span.id ? "selected" : ""}`}
          onClick={() => onSelectSpan(span)}
          onMouseEnter={() => onHoverSpan?.(span.id)}
          onMouseLeave={() => onHoverSpan?.(null)}
        >
          {/* Left: Name Tree */}
          <div className="trace-cell name" style={{ paddingLeft: `${depth * 16 + 8}px` }}>
            <span className="trace-icon">{Icons[span.type] || Icons.agent}</span>
            <span className="trace-name" title={span.name}>{span.name}</span>
            <span className="trace-duration-text">{duration}ms</span>
          </div>

          {/* Right: Gantt Bar */}
          <div className="trace-cell timeline">
            <div 
              className="timeline-bar-track" 
              style={{ left: `${startPct}%`, width: `${widthPct}%` }}
            >
              <div 
                className="timeline-bar" 
                style={{ background: barColor }} 
                title={`${span.name}: ${duration}ms`}
              />
            </div>
          </div>
          
          {/* [NEW] Quick Actions (Hover visible via CSS) */}
          <div className="trace-actions">
             <button className="icon-btn" title="Replay Step">⟲</button>
             <button className="icon-btn" title="View Source">code</button>
          </div>
        </div>
        
        {/* Recursion */}
        {span.children?.map(child => renderRow(child, depth + 1))}
      </div>
    );
  };

  return (
    <div className="trace-viewer">
      <div className="trace-header">
        <div className="header-cell name">Span Name</div>
        <div className="header-cell timeline">Execution Timeline</div>
      </div>
      <div className="trace-body">
        {spans.map(s => renderRow(s, 0))}
      </div>
    </div>
  );
}