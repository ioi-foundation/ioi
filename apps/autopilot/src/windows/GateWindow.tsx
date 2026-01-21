import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import "./GateWindow.css";

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

// Determines the "Visual Thumbnail" for the evidence card
function getEvidenceIcon(title: string, desc: string): string {
  const t = (title + desc).toLowerCase();
  if (t.includes("stripe") || t.includes("pay")) return "💳";
  if (t.includes("file") || t.includes("write")) return "💾";
  if (t.includes("network") || t.includes("fetch")) return "🌐";
  if (t.includes("email")) return "✉️";
  return "⚡"; // Default Action
}

export function GateWindow() {
  const [task, setTask] = useState<AgentTask | null>(null);
  
  // Hold-to-Sign Physics
  const [holdProgress, setHoldProgress] = useState(0);
  const [holdActive, setHoldActive] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  
  const holdStartRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);

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

  useEffect(() => {
    loadTask();
    const poll = setInterval(loadTask, 300);

    const unlisteners: UnlistenFn[] = [];
    const setup = async () => {
      unlisteners.push(await listen<AgentTask>("task-updated", (e) => {
        if (e.payload.phase === "Gate") setTask(e.payload);
        else setTask(null);
      }));
      unlisteners.push(await listen("task-dismissed", () => setTask(null)));
    };
    setup();

    return () => {
      clearInterval(poll);
      unlisteners.forEach((u) => u());
    };
  }, [loadTask]);

  useEffect(() => {
    setHoldProgress(0);
    setHoldActive(false);
    setConfirmed(false);
  }, [task?.id]);

  const handleApprove = async () => {
    setConfirmed(true);
    // Delay actual response to allow stamp animation to play
    setTimeout(async () => {
      // COMMAND UPDATED HERE: submit_gate_decision -> gate_respond
      await invoke("gate_respond", { approved: true });
    }, 1500); 
  };

  const handleDeny = async () => {
    // COMMAND UPDATED HERE: submit_gate_decision -> gate_respond
    await invoke("gate_respond", { approved: false });
  };

  // --- Physics Engine for the Button ---
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
    
    // 700ms hold time - snappy but deliberate
    const progress = Math.min(elapsed / 700, 1);
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

  if (!task?.gate_info) {
    return <div className="gate-empty" />;
  }

  const { gate_info } = task;
  const risk = gate_info.risk.toLowerCase();
  
  // Heuristic parsing to make the "Receipt" look real
  const amountMatch = gate_info.description.match(/\$\d+(\.\d{2})?/);
  const costDisplay = amountMatch ? amountMatch[0] : null;
  const targetHost = gate_info.description.match(/([a-z0-9-]+\.com)/)?.[0] || "api.gateway.io";

  return (
    <div className="gate-window">
      <div className={`gate-card ${confirmed ? "signed" : ""}`}>
        
        {/* Stamp Animation Overlay */}
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
            {risk === "high" ? "Critical Risk" : risk === "medium" ? "Sensitive" : "Standard"}
          </div>
        </div>

        {/* Body */}
        <div className="gate-body">
          {/* 1. The Evidence (Visual Anchor) */}
          <div className="evidence-container">
            <div className="evidence-thumbnail">
              {getEvidenceIcon(gate_info.title, gate_info.description)}
            </div>
            <div className="evidence-details">
              <div className="evidence-title">{gate_info.title}</div>
              <div className="evidence-desc">{gate_info.description}</div>
            </div>
          </div>

          {/* 2. The Line Items (Structured Data) */}
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
            className={`btn-sign ${holdActive ? "holding" : ""} ${confirmed ? "confirmed" : ""}`}
            onPointerDown={startHold}
            onPointerUp={cancelHold}
            onPointerLeave={cancelHold}
            onPointerCancel={cancelHold}
            // Touch support for tablets
            onTouchStart={(e) => { e.preventDefault(); startHold(); }}
            onTouchEnd={(e) => { e.preventDefault(); cancelHold(); }}
          >
            <div 
              className="sign-fill" 
              style={{ width: `${holdProgress * 100}%` }} 
            />
            <div className="sign-label">
              <span>{confirmed ? "Authorized ✓" : "Hold to Sign"}</span>
            </div>
          </button>
        </div>

      </div>
    </div>
  );
}