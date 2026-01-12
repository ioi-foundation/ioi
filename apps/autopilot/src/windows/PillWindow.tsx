import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import "./PillWindow.css";

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

export function PillWindow() {
  const [task, setTask] = useState<AgentTask | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [liveCost, setLiveCost] = useState(0);

  const loadTask = useCallback(async () => {
    try {
      const currentTask = await invoke<AgentTask | null>("get_current_task");
      setTask(currentTask);
    } catch (e) {
      console.error("Failed to load task:", e);
    }
  }, []);

  useEffect(() => {
    loadTask();
    const poll = setInterval(loadTask, 300);

    const unlisteners: UnlistenFn[] = [];
    const setup = async () => {
      unlisteners.push(await listen<AgentTask>("task-started", (e) => setTask(e.payload)));
      unlisteners.push(await listen<AgentTask>("task-updated", (e) => setTask(e.payload)));
      unlisteners.push(await listen<AgentTask>("task-completed", (e) => setTask(e.payload)));
      unlisteners.push(await listen("task-dismissed", () => setTask(null)));
    };
    setup();

    return () => {
      clearInterval(poll);
      unlisteners.forEach((u) => u());
    };
  }, [loadTask]);

  useEffect(() => {
    invoke("resize_pill", { expanded }).catch(console.error);
  }, [expanded]);

  useEffect(() => {
    if (!task) return;

    const receiptCost = task.receipt?.cost ? parseFloat(task.receipt.cost.replace(/[^0-9.]/g, "")) : 0;
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

  const handleDismiss = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await invoke("dismiss_task");
  };

  const openSpotlight = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await invoke("show_spotlight");
  };

  if (!task) {
    return <div className="pill-empty" />;
  }

  const isRunning = task.phase === "Running";
  const isComplete = task.phase === "Complete";
  const isFailed = task.phase === "Failed";
  const isGate = task.phase === "Gate";
  const pct = (task.progress / task.total_steps) * 100;
  const liabilityMode: LiabilityMode = task.liability_mode ?? "local";
  const stage: ActivityStage = task.activity_stage ?? inferStage(task.current_step, task.phase);
  return (
    <div
      className={`pill ${task.phase.toLowerCase()} liability-${liabilityMode} stage-${stage} ${expanded ? "expanded" : ""}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="pill-bar" style={{ width: `${pct}%` }} />
      
      <div className="pill-row">
        <div className="pill-status">
          {isRunning && <div className="spinner" />}
          {isGate && <span className="icon gate">⏸</span>}
          {isComplete && <span className="icon ok">✓</span>}
          {isFailed && <span className="icon fail">✗</span>}
        </div>
        <div className="pill-label">{task.current_step}</div>
        {isRunning && (
          <div className={`pill-stage ${stage}`}>
            <span className="stage-dot" />
            {stage === "reasoning" && "Reasoning"}
            {stage === "actuating" && "Actuating"}
            {stage === "settling" && "Settling"}
          </div>
        )}
        <div className="pill-count">{task.progress}/{task.total_steps}</div>
      </div>

      {expanded && (
        <div className="pill-expand">
          <div className="pill-intent">{task.intent}</div>
          {showLiveCost && (
            <div className="pill-meter">
              <span>Labor Gas</span>
              <strong>${liveCost.toFixed(4)}</strong>
            </div>
          )}
          {isComplete && task.receipt && (
            <div className="pill-meta">{task.receipt.duration} • {task.receipt.actions} actions</div>
          )}
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

function inferStage(step: string, phase: AgentPhase): ActivityStage {
  if (phase !== "Running") return "reasoning";
  const normalized = step.toLowerCase();
  if (normalized.includes("sign") || normalized.includes("settle") || normalized.includes("confirm")) {
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
