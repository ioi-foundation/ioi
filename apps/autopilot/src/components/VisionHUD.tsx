import { useState, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import "./VisionHUD.css";

// Represents a raw user action captured by the kernel drivers
interface GhostEvent {
  id: string;
  timestamp: number;
  type: "click" | "type" | "scroll" | "navigation";
  description: string;
  // Bounding box of the element interacted with (Visual Grounding)
  bbox?: { x: number, y: number, w: number, h: number };
  // The resulting graph node ID if synthesized
  synthesizedNodeId?: string;
  status: "capturing" | "analyzing" | "synthesized";
}

export function VisionHUD() {
  const [events, setEvents] = useState<GhostEvent[]>([]);
  const [isRecording, setIsRecording] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [activeInterlock, setActiveInterlock] = useState<{ x: number, y: number } | null>(null);

  // Listen for raw inputs captured by the Kernel (enigo/hooks)
  useEffect(() => {
    // 1. Ghost Input (User Action)
    const unlistenInput = listen<{ device: string, description: string }>("ghost-input", (e) => {
        if (!isRecording) return;
        
        let type: GhostEvent['type'] = "click";
        if (e.payload.device === "keyboard") type = "type";
        
        const newEvent: GhostEvent = {
            id: `evt-${Date.now()}`,
            timestamp: Date.now(),
            type,
            description: e.payload.description,
            status: "capturing",
            bbox: { x: 0, y: 0, w: 0, h: 0 } 
        };

        setEvents(prev => [...prev, newEvent]);

        // Simulate the "Synthesis" delay (Kernel mapping Action -> Graph Node)
        setTimeout(() => {
            setEvents(prev => prev.map(ev => 
                ev.id === newEvent.id 
                ? { ...ev, status: "synthesized", synthesizedNodeId: `node-${Math.floor(Math.random()*1000)}` } 
                : ev
            ));
        }, 800);
    });

    // 2. Visual Interlock (Kernel Intervention)
    // This event fires when the Kernel BLOCKS a click due to visual drift (TOCTOU).
    const unlistenInterlock = listen<{ verdict: string, request_hash: number[] }>("firewall-interception", (e) => {
         if (e.payload.verdict === "BLOCK" || e.payload.verdict === "VISUAL_DRIFT") {
             // Flash the viewport to show the user the kernel saved them
             setActiveInterlock({ x: 50, y: 50 }); // Center for now, real event would have coords
             setTimeout(() => setActiveInterlock(null), 1000);
         }
    });

    return () => { 
        unlistenInput.then(f => f()); 
        unlistenInterlock.then(f => f());
    };
  }, [isRecording]);

  // Auto-scroll the timeline
  useEffect(() => {
    if (scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  const activeEvent = events[events.length - 1];

  return (
    <div className="vision-hud-container">
      {/* 1. STATUS HEADER */}
      <div className={`vision-header ${activeInterlock ? 'interlock-active' : 'recording'}`}>
        <div className="vision-title">
          <div className={`rec-dot ${isRecording ? 'pulse' : ''}`} />
          <span>{activeInterlock ? "VISUAL_LOCK_ENGAGED" : "GHOST_RECORDER_ACTIVE"}</span>
        </div>
        <div className="vision-stats">
          <span>{events.length} ACTIONS CAPTURED</span>
        </div>
      </div>

      {/* 2. VISUAL OVERLAY (The "Targeting System") */}
      <div className="vision-viewport">
        <div className="scanline" />
        
        {/* Visual feedback for the *latest* user interaction */}
        {activeEvent && activeEvent.status === "capturing" && (
           <div className="interaction-ping" />
        )}
        
        {/* [NEW] Visual Interlock Feedback */}
        {activeInterlock && (
            <div className="interlock-overlay">
                <div className="lock-icon">🔒</div>
                <div className="lock-msg">Click Blocked: Screen Changed</div>
            </div>
        )}
        
        <div className="som-overlay-placeholder">
            <span className="som-hint">Visual Grounding Active</span>
        </div>
      </div>

      {/* 3. SYNTHESIS STREAM (The "Translation Layer") */}
      <div className="synthesis-panel">
        <div className="synthesis-header">
            <span>Workflow Translation</span>
        </div>
        <div className="synthesis-stream" ref={scrollRef}>
            {events.length === 0 && (
                <div className="empty-state">
                    Perform actions on your desktop to generate graph nodes...
                </div>
            )}
            {events.map((evt, i) => (
                <div key={evt.id} className={`synthesis-step ${evt.status}`}>
                    {/* Step Connector Line */}
                    {i < events.length - 1 && <div className="step-line" />}
                    
                    {/* Icon */}
                    <div className="step-icon">
                        {evt.type === 'click' && '🖱️'}
                        {evt.type === 'type' && '⌨️'}
                    </div>

                    {/* Content */}
                    <div className="step-content">
                        <div className="step-raw">{evt.description}</div>
                        
                        {evt.status === "synthesized" && (
                            <div className="step-node">
                                <span className="node-badge">Action Node</span>
                                <span className="node-id">{evt.synthesizedNodeId}</span>
                            </div>
                        )}
                        
                        {evt.status === "analyzing" && (
                            <div className="step-analyzing">Aligning with DOM...</div>
                        )}
                    </div>

                    {/* Status Indicator */}
                    <div className="step-status">
                        {evt.status === "synthesized" ? (
                            <span className="status-check">✓</span>
                        ) : (
                            <span className="status-spinner" />
                        )}
                    </div>
                </div>
            ))}
        </div>
      </div>
    </div>
  );
}