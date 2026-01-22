import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import "./GateWindow.css";

// =========================================
// TYPES
// =========================================

type AgentPhase = "Idle" | "Running" | "Gate" | "Complete" | "Failed";

interface GateInfo {
  title: string;
  description: string;
  risk: string;
  context_export?: {
    provider: string;
    files: string[];
    summary?: string;
  };
  policy_rule?: string;
}

interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: AgentPhase;
  gate_info?: GateInfo;
}

// =========================================
// ICONS — Clean SVG Components
// =========================================

const CreditCardIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="1" y="4" width="22" height="16" rx="2" ry="2"/>
    <line x1="1" y1="10" x2="23" y2="10"/>
  </svg>
);

const FileIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
  </svg>
);

const GlobeIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="2" y1="12" x2="22" y2="12"/>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
);

const MailIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    <polyline points="22,6 12,13 2,6"/>
  </svg>
);

const ZapIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
  </svg>
);

const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);

// =========================================
// HELPER FUNCTIONS
// =========================================

function getEvidenceIcon(title: string, desc: string): React.ReactNode {
  const text = (title + desc).toLowerCase();
  
  if (text.includes("stripe") || text.includes("pay") || text.includes("card")) {
    return <CreditCardIcon />;
  }
  if (text.includes("file") || text.includes("write") || text.includes("save")) {
    return <FileIcon />;
  }
  if (text.includes("network") || text.includes("fetch") || text.includes("api")) {
    return <GlobeIcon />;
  }
  if (text.includes("email") || text.includes("mail") || text.includes("send")) {
    return <MailIcon />;
  }
  
  return <ZapIcon />;
}

function getRiskLabel(risk: string): string {
  switch (risk.toLowerCase()) {
    case "high": return "Critical Risk";
    case "medium": return "Sensitive";
    default: return "Standard";
  }
}

// =========================================
// MAIN COMPONENT
// =========================================

export function GateWindow() {
  const [task, setTask] = useState<AgentTask | null>(null);
  
  // Hold-to-Sign State
  const [holdProgress, setHoldProgress] = useState(0);
  const [holdActive, setHoldActive] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  
  const holdStartRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);

  // --- Load Current Task ---
  const loadTask = useCallback(async () => {
    try {
      const t = await invoke<AgentTask | null>("get_current_task");
      if (t && t.phase === "Gate") {
        setTask(t);
      } else {
        setTask(null);
      }
    } catch (e) {
      console.error("Failed to load task:", e);
    }
  }, []);

  // --- Event Listeners ---
  useEffect(() => {
    loadTask();
    const poll = setInterval(loadTask, 300);

    const unlisteners: UnlistenFn[] = [];
    
    const setup = async () => {
      unlisteners.push(
        await listen<AgentTask>("task-updated", (e) => {
          if (e.payload.phase === "Gate") {
            setTask(e.payload);
          } else {
            setTask(null);
          }
        })
      );
      unlisteners.push(
        await listen("task-dismissed", () => setTask(null))
      );
    };
    
    setup();

    return () => {
      clearInterval(poll);
      unlisteners.forEach((u) => u());
    };
  }, [loadTask]);

  // --- Reset State on Task Change ---
  useEffect(() => {
    setHoldProgress(0);
    setHoldActive(false);
    setConfirmed(false);
  }, [task?.id]);

  // --- Actions ---
  const handleApprove = async () => {
    setConfirmed(true);
    // Delay to allow stamp animation
    setTimeout(async () => {
      await invoke("gate_respond", { approved: true });
    }, 1500);
  };

  const handleDeny = async () => {
    await invoke("gate_respond", { approved: false });
  };

  // --- Hold-to-Sign Physics ---
  const startHold = () => {
    if (confirmed) return;
    setHoldActive(true);
    holdStartRef.current = performance.now();
    tickHold();
  };

  const cancelHold = () => {
    if (confirmed) return;
    setHoldActive(false);
    holdStartRef.current = null;
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    setHoldProgress(0);
  };

  const tickHold = () => {
    if (holdStartRef.current == null) return;
    
    const elapsed = performance.now() - holdStartRef.current;
    const progress = Math.min(elapsed / 700, 1); // 700ms hold time
    
    setHoldProgress(progress);
    
    if (progress >= 1) {
      setHoldActive(false);
      holdStartRef.current = null;
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      handleApprove();
      return;
    }
    
    rafRef.current = requestAnimationFrame(tickHold);
  };

  // --- Empty State ---
  if (!task?.gate_info) {
    return <div className="gate-empty" />;
  }

  const { gate_info } = task;
  const risk = gate_info.risk.toLowerCase();
  
  // Parse description for display values
  const amountMatch = gate_info.description.match(/\$\d+(\.\d{2})?/);
  const costDisplay = amountMatch ? amountMatch[0] : null;
  const targetHost = gate_info.description.match(/([a-z0-9-]+\.com)/)?.[0] || "api.gateway.io";

  // Build class names
  const cardClasses = ["gate-card", confirmed ? "signed" : ""].filter(Boolean).join(" ");
  const signBtnClasses = [
    "btn-sign",
    holdActive ? "holding" : "",
    confirmed ? "confirmed" : ""
  ].filter(Boolean).join(" ");

  return (
    <div className="gate-window">
      <div className={cardClasses}>
        
        {/* Stamp Overlay */}
        <div className={`stamp-overlay ${confirmed ? "visible" : ""}`}>
          <div className="approval-stamp">APPROVED</div>
        </div>

        {/* Header */}
        <div className="gate-header">
          <div className="gate-title-block">
            <h1>Authorization Request</h1>
            <div className="gate-subtitle">
              <span className="agent-dot" />
              <span>{task.agent}</span>
              <span style={{ opacity: 0.3 }}>|</span>
              <span>ID: {task.id.slice(0, 8)}</span>
            </div>
          </div>
          <div className={`risk-badge ${risk}`}>
            {getRiskLabel(risk)}
          </div>
        </div>

        {/* Body */}
        <div className="gate-body">
          {/* Evidence Card */}
          <div className="evidence-container">
            <div className="evidence-thumbnail">
              {getEvidenceIcon(gate_info.title, gate_info.description)}
            </div>
            <div className="evidence-details">
              <div className="evidence-title">{gate_info.title}</div>
              <div className="evidence-desc">{gate_info.description}</div>
            </div>
          </div>

          {/* Line Items */}
          <div className="line-items">
            <div className="line-item">
              <span className="li-label">Target Resource</span>
              <span className="li-value">{targetHost}</span>
            </div>
            {costDisplay && (
              <div className="line-item highlight">
                <span className="li-label">Transaction Value</span>
                <span className="li-value cost">{costDisplay}</span>
              </div>
            )}
            <div className="line-item">
              <span className="li-label">Policy Rule</span>
              <span className="li-value">{gate_info.policy_rule || "cap:spend limit"}</span>
            </div>
            <div className="line-item">
              <span className="li-label">Context Export</span>
              <span className="li-value">{gate_info.context_export?.files.length || 0} files</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="gate-footer">
          <button 
            className="btn-reject" 
            onClick={handleDeny}
            disabled={confirmed}
          >
            Reject
          </button>
          
          <button
            className={signBtnClasses}
            onPointerDown={startHold}
            onPointerUp={cancelHold}
            onPointerLeave={cancelHold}
            onPointerCancel={cancelHold}
            onTouchStart={(e) => { e.preventDefault(); startHold(); }}
            onTouchEnd={(e) => { e.preventDefault(); cancelHold(); }}
          >
            <div 
              className="sign-fill" 
              style={{ width: `${holdProgress * 100}%` }} 
            />
            <div className="sign-label">
              {confirmed ? (
                <>
                  Authorized
                  <CheckIcon />
                </>
              ) : (
                "Hold to Sign"
              )}
            </div>
          </button>
        </div>

      </div>
    </div>
  );
}