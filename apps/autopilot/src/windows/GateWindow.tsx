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

export function GateWindow() {
  const [task, setTask] = useState<AgentTask | null>(null);
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
    return () => {
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
      }
    };
  }, []);

  useEffect(() => {
    setHoldProgress(0);
    setHoldActive(false);
    setConfirmed(false);
  }, [task?.id]);

  const handleApprove = async () => {
    console.log("Approving gate...");
    setConfirmed(true);
    await invoke("gate_respond", { approved: true });
  };

  const handleDeny = async () => {
    console.log("Denying gate...");
    await invoke("gate_respond", { approved: false });
  };

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
    const progress = Math.min(elapsed / 1400, 1);
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
  const contextExport = gate_info.context_export ?? {
    provider: "Provider Node X",
    files: ["invoices.pdf", "ledger.csv"],
    summary: "Exporting 2 files to external provider.",
  };
  const policyRule = gate_info.policy_rule ?? "cap:spend > $5.00";
  const exportSummary = gate_info.context_export?.summary
    ?? `Exporting ${contextExport.files.length} files to ${contextExport.provider}.`;

  return (
    <div className="gate-window">
      <div className="gate-card">
        <div className={`gate-head ${risk}`}>
          <span className="gate-icon">🛡️</span>
          <span className="gate-title">Policy Gate</span>
          <span className={`gate-tag ${risk}`}>{gate_info.risk.toUpperCase()}</span>
        </div>

        <div className="gate-body">
          <div className="gate-task">{task.intent}</div>
          <h3>{gate_info.title}</h3>
          <p>{gate_info.description}</p>

          <div className="gate-section">
            <div className="gate-section-title">Context Slicing</div>
            <div className="gate-context-card">
              <div className="context-summary">
                <span className="context-label">Export</span>
                <span className="context-value">{exportSummary}</span>
              </div>
              <div className="context-slices">
                <span className="slice file">Files</span>
                <span className="slice memory">Memory</span>
                <span className="slice meta">Metadata</span>
              </div>
              <div className="context-files">
                {contextExport.files.map((file) => (
                  <span key={file} className="context-chip">{file}</span>
                ))}
              </div>
              <div className="context-provider">
                <span>Provider</span>
                <strong>{contextExport.provider}</strong>
              </div>
            </div>
          </div>

          <div className="gate-section">
            <div className="gate-section-title">Policy Reference</div>
            <div className="gate-policy">Triggered by Rule: <span>{policyRule}</span></div>
          </div>
          <div className="gate-agent">🤖 {task.agent}</div>
        </div>

        <div className="gate-foot">
          <button className="btn-deny" onClick={handleDeny}>Deny</button>
          <button
            className={`btn-approve ${holdActive ? "holding" : ""} ${confirmed ? "confirmed" : ""}`}
            onPointerDown={startHold}
            onPointerUp={cancelHold}
            onPointerLeave={cancelHold}
            onPointerCancel={cancelHold}
            aria-label="Hold to sign"
          >
            <span className="signer-track" />
            <span className="signer-progress" style={{ width: `${holdProgress * 100}%` }} />
            <span className="signer-content">
              <span className="signer-title">{confirmed ? "Signed" : "Hold to Sign"}</span>
              <span className="signer-subtitle">Hardware-Interrupted Gate</span>
            </span>
            <span className="signer-status">{confirmed ? "✓" : "⇥"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
