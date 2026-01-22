import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import "./PillWindow.css";

// =========================================
// TYPES
// =========================================

type AgentPhase = "Idle" | "Running" | "Gate" | "Complete" | "Failed";
type LiabilityMode = "local" | "network" | "settlement";
type ActivityStage = "reasoning" | "actuating" | "settling";

interface Receipt {
  duration: string;
  actions: number;
  cost?: string;
}

interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: AgentPhase;
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: Receipt;
  liability_mode?: LiabilityMode;
  activity_stage?: ActivityStage;
}

// =========================================
// ICONS — Minimal SVG
// =========================================

const CheckIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const XIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

const PauseIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="6" y="4" width="4" height="16" />
    <rect x="14" y="4" width="4" height="16" />
  </svg>
);

// =========================================
// HELPER FUNCTIONS
// =========================================

function inferStage(step: string, phase: AgentPhase): ActivityStage {
  if (phase !== "Running") return "reasoning";
  
  const normalized = step.toLowerCase();
  
  if (
    normalized.includes("sign") || 
    normalized.includes("settle") || 
    normalized.includes("confirm")
  ) {
    return "settling";
  }
  
  if (
    normalized.includes("tool") ||
    normalized.includes("execute") ||
    normalized.includes("action") ||
    normalized.includes("processing") ||
    normalized.includes("running")
  ) {
    return "actuating";
  }
  
  return "reasoning";
}

function getStageLabel(stage: ActivityStage): string {
  switch (stage) {
    case "reasoning": return "Reasoning";
    case "actuating": return "Actuating";
    case "settling": return "Settling";
  }
}

// =========================================
// MAIN COMPONENT
// =========================================

export function PillWindow() {
  const [task, setTask] = useState<AgentTask | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [liveCost, setLiveCost] = useState(0);

  // --- Load Current Task ---
  const loadTask = useCallback(async () => {
    try {
      const currentTask = await invoke<AgentTask | null>("get_current_task");
      setTask(currentTask);
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
        await listen<AgentTask>("task-started", (e) => setTask(e.payload))
      );
      unlisteners.push(
        await listen<AgentTask>("task-updated", (e) => setTask(e.payload))
      );
      unlisteners.push(
        await listen<AgentTask>("task-completed", (e) => setTask(e.payload))
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

  // --- Resize Window on Expand ---
  useEffect(() => {
    invoke("resize_pill", { expanded }).catch(console.error);
  }, [expanded]);

  // --- Live Cost Tracking ---
  useEffect(() => {
    if (!task) return;

    const receiptCost = task.receipt?.cost 
      ? parseFloat(task.receipt.cost.replace(/[^0-9.]/g, "")) 
      : 0;
      
    if (!Number.isNaN(receiptCost) && receiptCost > 0) {
      setLiveCost(receiptCost);
    } else if (task.phase !== "Running") {
      setLiveCost(0);
    }
  }, [task]);

  const showLiveCost = task?.phase === "Running" && (task?.liability_mode ?? "local") === "network";

  useEffect(() => {
    if (!showLiveCost) return;

    const interval = setInterval(() => {
      setLiveCost((prev) => Number((prev + 0.0004).toFixed(4)));
    }, 800);

    return () => clearInterval(interval);
  }, [showLiveCost]);

  // --- Actions ---
  const handleDismiss = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await invoke("dismiss_task");
  };

  const openSpotlight = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await invoke("show_spotlight");
  };

  // --- Empty State ---
  if (!task) {
    return <div className="pill-empty" />;
  }

  // --- Derived State ---
  const isRunning = task.phase === "Running";
  const isComplete = task.phase === "Complete";
  const isFailed = task.phase === "Failed";
  const isGate = task.phase === "Gate";
  const progressPercent = (task.progress / task.total_steps) * 100;
  const liabilityMode: LiabilityMode = task.liability_mode ?? "local";
  const stage: ActivityStage = task.activity_stage ?? inferStage(task.current_step, task.phase);

  // --- Build Class Names ---
  const pillClasses = [
    "pill",
    task.phase.toLowerCase(),
    `liability-${liabilityMode}`,
    `stage-${stage}`,
    expanded ? "expanded" : "",
  ].filter(Boolean).join(" ");

  return (
    <div className={pillClasses} onClick={() => setExpanded(!expanded)}>
      {/* Progress Bar */}
      <div className="pill-bar" style={{ width: `${progressPercent}%` }} />
      
      {/* Main Row */}
      <div className="pill-row">
        {/* Status Indicator */}
        <div className="pill-status">
          {isRunning && <div className="spinner" />}
          {isGate && <span className="icon gate"><PauseIcon /></span>}
          {isComplete && <span className="icon ok"><CheckIcon /></span>}
          {isFailed && <span className="icon fail"><XIcon /></span>}
        </div>

        {/* Current Step Label */}
        <div className="pill-label">{task.current_step}</div>

        {/* Activity Stage Badge (Running Only) */}
        {isRunning && (
          <div className={`pill-stage ${stage}`}>
            <span className="stage-dot" />
            {getStageLabel(stage)}
          </div>
        )}

        {/* Step Counter */}
        <div className="pill-count">
          {task.progress}/{task.total_steps}
        </div>
      </div>

      {/* Expanded Panel */}
      {expanded && (
        <div className="pill-expand">
          {/* Intent */}
          <div className="pill-intent">{task.intent}</div>

          {/* Live Cost Meter (Network Mode) */}
          {showLiveCost && (
            <div className="pill-meter">
              <span>Labor Gas</span>
              <strong>${liveCost.toFixed(4)}</strong>
            </div>
          )}

          {/* Receipt Meta (Complete State) */}
          {isComplete && task.receipt && (
            <div className="pill-meta">
              {task.receipt.duration} • {task.receipt.actions} actions
            </div>
          )}

          {/* Action Buttons */}
          <div className="pill-btns">
            <button onClick={openSpotlight}>New</button>
            <button className="primary" onClick={handleDismiss}>
              {isComplete || isFailed ? "Done" : "Cancel"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}