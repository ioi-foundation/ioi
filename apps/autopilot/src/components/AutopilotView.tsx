import { useState, useEffect } from "react";
import { useAgentStore } from "../store/agentStore";
import "./AutopilotView.css";

type AgentPhase = "Idle" | "Running" | "Gate" | "Complete" | "Failed";

interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: AgentPhase;
  progress: number;
  totalSteps: number;
  currentStep: string;
  startTime: Date;
  gateInfo?: {
    title: string;
    description: string;
    risk: "low" | "medium" | "high";
  };
  receipt?: {
    duration: string;
    actions: number;
    cost?: string;
  };
}

interface Receipt {
  id: string;
  intent: string;
  status: "success" | "failed" | "cancelled";
  timestamp: Date;
  duration: string;
  agent: string;
  actions: number;
}

interface AutopilotViewProps {
  onOpenStudio: () => void;
}

export function AutopilotView({ onOpenStudio }: AutopilotViewProps) {
  // Spotlight state
  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [intent, setIntent] = useState("");
  const { startTask } = useAgentStore();
  
  // Active task
  const [activeTask, setActiveTask] = useState<AgentTask | null>(null);
  
  // UI state
  const [pillExpanded, setPillExpanded] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  
  // Mock receipts
  const [receipts] = useState<Receipt[]>([
    {
      id: "r1",
      intent: "Find flights to NYC under $400 for Tuesday",
      status: "success",
      timestamp: new Date(Date.now() - 3600000),
      duration: "2m 34s",
      agent: "Travel Agent",
      actions: 47,
    },
    {
      id: "r2", 
      intent: "Summarize my unread emails",
      status: "success",
      timestamp: new Date(Date.now() - 7200000),
      duration: "45s",
      agent: "Email Assistant",
      actions: 12,
    },
  ]);

  // Keyboard shortcut to open spotlight
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === " ") {
        e.preventDefault();
        setSpotlightOpen(true);
      }
      if (e.key === "Escape") {
        setSpotlightOpen(false);
        setPillExpanded(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Handle user intent submission
  const handleSubmit = async () => {
    if (!intent.trim()) return;
    
    // We don't manually creating the task state here anymore.
    // We call the backend, and let the event stream update the UI.
    try {
        await startTask(intent, "Agent");
        setSpotlightOpen(false);
        setIntent("");
    } catch (e) {
        console.error("Failed to start task:", e);
    }
  };

  const handleGateApprove = () => {
    // Logic moved to src-tauri/src/lib.rs `gate_respond`
  };

  const handleGateDeny = () => {
    setActiveTask(prev => prev ? {
      ...prev,
      phase: "Failed",
      currentStep: "Cancelled by user (Policy Denied)",
    } : null);
  };

  const handleDismissTask = () => {
    setActiveTask(null);
    setPillExpanded(false);
  };

  const formatTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / 3600000);
    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  return (
    <div className="autopilot-shell">
      {/* Desktop Background / User's normal workspace */}
      <div className="desktop-workspace">
        <div className="workspace-placeholder">
          <div className="workspace-hint">
            <span className="hint-icon">💻</span>
            <span>Your desktop workspace</span>
          </div>
          <div className="workspace-subhint">
            Press <kbd>⌘</kbd><kbd>Space</kbd> to invoke Autopilot
          </div>
        </div>
      </div>

      {/* Studio Access */}
      <button className="studio-access" onClick={onOpenStudio} title="Open Studio">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="16 18 22 12 16 6"/>
          <polyline points="8 6 2 12 8 18"/>
        </svg>
      </button>

      {/* History Access */}
      <button className="history-access" onClick={() => setShowHistory(!showHistory)}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
        <span className="history-count">{receipts.length}</span>
      </button>

      {/* Quick Invoke Button (when no task active) */}
      {!activeTask && !spotlightOpen && (
        <button className="invoke-fab" onClick={() => setSpotlightOpen(true)}>
          <div className="fab-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2L2 7L12 12L22 7L12 2Z"/>
              <path d="M2 17L12 22L22 17"/>
              <path d="M2 12L12 17L22 12"/>
            </svg>
          </div>
        </button>
      )}

      {/* Spotlight Overlay */}
      {spotlightOpen && (
        <div className="spotlight-overlay" onClick={() => setSpotlightOpen(false)}>
          <div className="spotlight-container" onClick={e => e.stopPropagation()}>
            <div className="spotlight-box">
              <div className="spotlight-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2L2 7L12 12L22 7L12 2Z"/>
                  <path d="M2 17L12 22L22 17"/>
                  <path d="M2 12L12 17L22 12"/>
                </svg>
              </div>
              <input
                type="text"
                className="spotlight-input"
                placeholder="What would you like me to do?"
                value={intent}
                onChange={(e) => setIntent(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                autoFocus
              />
              <button 
                className="spotlight-submit"
                onClick={handleSubmit}
                disabled={!intent.trim()}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="22" y1="2" x2="11" y2="13"/>
                  <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
              </button>
            </div>
            <div className="spotlight-suggestions">
              <button onClick={() => setIntent("Book a flight to NYC under $400")}>
                ✈️ Book a flight
              </button>
              <button onClick={() => setIntent("Summarize my unread emails")}>
                📧 Summarize emails
              </button>
              <button onClick={() => setIntent("Research competitors in my industry")}>
                🔍 Research
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating Pill (when task is running) */}
      {activeTask && activeTask.phase !== "Gate" && (
        <div 
          className={`floating-pill ${pillExpanded ? "expanded" : ""} ${activeTask.phase}`}
          onClick={() => setPillExpanded(!pillExpanded)}
        >
          <div className="pill-header">
            <div className="pill-status">
              {activeTask.phase === "Running" && <div className="status-spinner" />}
              {activeTask.phase === "Complete" && <div className="status-check">✓</div>}
              {activeTask.phase === "Failed" && <div className="status-fail">✗</div>}
            </div>
            <div className="pill-info">
              <div className="pill-agent">{activeTask.agent}</div>
              <div className="pill-step">{activeTask.currentStep}</div>
            </div>
            <div className="pill-progress">
              {activeTask.progress}/{activeTask.totalSteps}
            </div>
          </div>
          
          {/* Expanded Content */}
          {pillExpanded && (
            <div className="pill-expanded">
              <div className="pill-intent">"{activeTask.intent}"</div>
              
              {/* Progress Bar */}
              <div className="pill-progress-bar">
                <div 
                  className="pill-progress-fill" 
                  style={{ width: `${(activeTask.progress / activeTask.totalSteps) * 100}%` }}
                />
              </div>

              {/* Receipt (if complete) */}
              {activeTask.phase === "Complete" && activeTask.receipt && (
                <div className="pill-receipt">
                  <div className="receipt-row">
                    <span>Duration</span>
                    <span>{activeTask.receipt.duration}</span>
                  </div>
                  <div className="receipt-row">
                    <span>Actions</span>
                    <span>{activeTask.receipt.actions}</span>
                  </div>
                  {activeTask.receipt.cost && (
                    <div className="receipt-row highlight">
                      <span>Cost</span>
                      <span>{activeTask.receipt.cost}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="pill-actions">
                {activeTask.phase === "Running" && (
                  <button className="pill-btn cancel" onClick={(e) => { e.stopPropagation(); handleDismissTask(); }}>
                    Cancel
                  </button>
                )}
                {(activeTask.phase === "Complete" || activeTask.phase === "Failed") && (
                  <>
                    <button className="pill-btn" onClick={(e) => { e.stopPropagation(); console.log("View receipt"); }}>
                      View Details
                    </button>
                    <button className="pill-btn primary" onClick={(e) => { e.stopPropagation(); handleDismissTask(); }}>
                      Dismiss
                    </button>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Gate Popup (demands attention) */}
      {activeTask && activeTask.phase === "Gate" && activeTask.gateInfo && (
        <div className="gate-overlay">
          <div className="gate-popup">
            <div className={`gate-header ${activeTask.gateInfo.risk}`}>
              <div className="gate-icon">🛡️</div>
              <div className="gate-title">Policy Gate</div>
              <div className={`gate-risk ${activeTask.gateInfo.risk}`}>
                {activeTask.gateInfo.risk.toUpperCase()} RISK
              </div>
            </div>
            
            <div className="gate-body">
              <div className="gate-context">
                <span className="context-label">Task:</span>
                <span className="context-value">"{activeTask.intent}"</span>
              </div>
              
              <div className="gate-action-title">{activeTask.gateInfo.title}</div>
              <div className="gate-description">{activeTask.gateInfo.description}</div>
              
              <div className="gate-agent">
                <span className="agent-avatar">🤖</span>
                <span>{activeTask.agent} is requesting approval</span>
              </div>
            </div>

            <div className="gate-footer">
              <button className="gate-btn deny" onClick={handleGateDeny}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"/>
                  <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
                Deny
              </button>
              <button className="gate-btn approve" onClick={handleGateApprove}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                Approve
              </button>
            </div>
          </div>
        </div>
      )}

      {/* History Panel */}
      {showHistory && (
        <div className="history-panel">
          <div className="history-header">
            <h3>Receipt History</h3>
            <button className="history-close" onClick={() => setShowHistory(false)}>×</button>
          </div>
          <div className="history-list">
            {receipts.map((receipt) => (
              <div key={receipt.id} className={`history-receipt ${receipt.status}`}>
                <div className="receipt-status-icon">
                  {receipt.status === "success" && "✓"}
                  {receipt.status === "failed" && "✗"}
                </div>
                <div className="receipt-content">
                  <div className="receipt-intent">{receipt.intent}</div>
                  <div className="receipt-meta">
                    <span>{receipt.agent}</span>
                    <span>•</span>
                    <span>{receipt.actions} actions</span>
                    <span>•</span>
                    <span>{receipt.duration}</span>
                    <span>•</span>
                    <span>{formatTime(receipt.timestamp)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
