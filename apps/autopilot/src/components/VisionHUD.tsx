import { useState, useEffect, useRef } from "react";
import "./VisionHUD.css";

interface BBox {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
}

interface LogEntry {
  id: string;
  ts: string;
  tag: string;
  msg: string;
}

const SIMULATED_LOGS = [
  { tag: "VIS", msg: "Scanning viewport (1920x1080)" },
  { tag: "DOM", msg: "Detected input field: #email" },
  { tag: "POL", msg: "Inferring context: User Login" },
  { tag: "NET", msg: "Observed XHR: POST /api/auth" },
  { tag: "VIS", msg: "Tracking cursor movement..." },
  { tag: "DOM", msg: "Click detected: button.submit" },
  { tag: "GEN", msg: "Synthesizing Policy Rule #4..." },
];

export function VisionHUD() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeBox, setActiveBox] = useState<BBox | null>(null);
  const [confidence, setConfidence] = useState(85);
  
  // Simulate "Scanning" behavior
  useEffect(() => {
    let step = 0;
    
    const interval = setInterval(() => {
      // Add Log
      const now = new Date();
      const ts = `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}.${Math.floor(now.getMilliseconds()/100)}`;
      const logData = SIMULATED_LOGS[step % SIMULATED_LOGS.length];
      
      setLogs(prev => [...prev.slice(-4), { // Keep last 5 lines
        id: `log-${Date.now()}`,
        ts,
        tag: logData.tag,
        msg: logData.msg
      }]);

      // Move Bounding Box (Simulate eye tracking)
      const mockBoxes = [
        { id: "b1", x: 20, y: 30, w: 40, h: 15, label: "INPUT" },
        { id: "b2", x: 65, y: 70, w: 20, h: 10, label: "BTN" },
        { id: "b3", x: 10, y: 10, w: 80, h: 80, label: "FORM" },
      ];
      setActiveBox(mockBoxes[step % mockBoxes.length]);

      // Fluctuate confidence
      setConfidence(prev => Math.min(99, Math.max(70, prev + (Math.random() * 10 - 5))));

      step++;
    }, 1200);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="vision-hud-container">
      {/* Header */}
      <div className="vision-header">
        <div className="vision-title">
          <div className="rec-dot" />
          <span>GHOST_VISION_V1</span>
        </div>
        <div className="vision-confidence">
          CONFIDENCE: {confidence.toFixed(0)}%
        </div>
      </div>

      {/* Viewport (The Eye) */}
      <div className="vision-viewport">
        <div className="scanline" />
        
        {/* Simulated Screen Content (Abstract) */}
        <div style={{ padding: 20, opacity: 0.3, filter: 'blur(1px)' }}>
           <div style={{ width: '60%', height: 10, background: '#333', marginBottom: 10 }} />
           <div style={{ width: '40%', height: 10, background: '#333', marginBottom: 20 }} />
           <div style={{ display: 'flex', gap: 10 }}>
              <div style={{ width: 80, height: 60, background: '#222' }} />
              <div style={{ flex: 1, height: 60, background: '#222' }} />
           </div>
        </div>

        {/* Active Bounding Box Overlay */}
        {activeBox && (
          <div 
            className="bbox"
            style={{
              left: `${activeBox.x}%`,
              top: `${activeBox.y}%`,
              width: `${activeBox.w}%`,
              height: `${activeBox.h}%`
            }}
          >
            <div className="bbox-label">{activeBox.label} {confidence > 90 ? "99%" : ""}</div>
          </div>
        )}

        {/* Minimap */}
        <div className="vision-minimap">
           {activeBox && (
             <div 
                className="minimap-dot" 
                style={{ left: `${activeBox.x}%`, top: `${activeBox.y}%` }} 
             />
           )}
        </div>
      </div>

      {/* Inference Log (The Brain) */}
      <div className="vision-log">
        {logs.map((log, i) => (
          <div key={log.id} className={`log-entry ${i === logs.length - 1 ? "active" : ""}`}>
            <span className="log-ts">{log.ts}</span>
            <span className="log-tag">[{log.tag}]</span>
            {log.msg}
          </div>
        ))}
        <div className="log-entry active">
           <span className="log-cursor" />
        </div>
      </div>
    </div>
  );
}