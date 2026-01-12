import { useState } from "react";
import "./GodModeBar.css";

export type InterfaceMode = "GHOST" | "AGENT" | "COMPOSE";

interface GodModeBarProps {
  projectName: string;
  projectPath?: string;
  mode: InterfaceMode;
  onModeChange: (m: InterfaceMode) => void;
  onIntentSubmit?: (intent: string) => void;
  onRun: () => void;
  onPause: () => void;
  onReplay?: () => void;
  metrics: { risk: number; cost: number; privacy?: number };
}

export function GodModeBar({
  projectName,
  projectPath = "Projects",
  mode,
  onModeChange,
  onIntentSubmit,
  onRun,
  onPause,
  onReplay,
  metrics,
}: GodModeBarProps) {
  const [intent, setIntent] = useState("");

  const handleIntentSubmit = () => {
    if (intent.trim() && onIntentSubmit) {
      onIntentSubmit(intent);
      setIntent("");
    }
  };

  const getRiskLevel = (value: number) => {
    if (value < 0.33) return "green";
    if (value < 0.66) return "yellow";
    return "red";
  };

  return (
    <div className="god-bar-container">
      <div className="god-bar">
        {/* LEFT: Project Context */}
        <div className="god-section left">
          <div className="project-crumb">
            <span className="crumb-path">{projectPath} /</span>
            <span className="crumb-name">{projectName}</span>
          </div>
        </div>

        <div className="divider-vertical" />

        {/* CENTER: Mode Switcher + Intent */}
        <div className="god-section center">
          <div className="mode-switcher">
            <button
              className={`mode-btn ghost ${mode === "GHOST" ? "active" : ""}`}
              onClick={() => onModeChange("GHOST")}
              title="Ghost Mode: Trace-First Creation"
            >
              <div className="record-dot" />
            </button>
            <button
              className={`mode-btn ${mode === "AGENT" ? "active" : ""}`}
              onClick={() => onModeChange("AGENT")}
              title="Agent Mode: Execute"
            >
              Agent
            </button>
            <button
              className={`mode-btn ${mode === "COMPOSE" ? "active" : ""}`}
              onClick={() => onModeChange("COMPOSE")}
              title="Compose Mode: Edit Graph"
            >
              Compose
            </button>
          </div>

          <div className="intent-wrapper">
            <span className="intent-icon">
              {mode === "GHOST" ? "●" : "✨"}
            </span>
            <input
              type="text"
              className="intent-input"
              placeholder={
                mode === "GHOST"
                  ? "Recording actions..."
                  : mode === "AGENT"
                  ? "Describe your intent..."
                  : "Search or command (⌘K)..."
              }
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleIntentSubmit()}
              disabled={mode === "GHOST"}
            />
            {mode !== "GHOST" && intent && (
              <kbd className="kbd-shortcut">↵</kbd>
            )}
          </div>
        </div>

        <div className="divider-vertical" />

        {/* RIGHT: Metrics + Transport Controls */}
        <div className="god-section right">
          <div className="metrics-cluster">
            <div className="metric-dot" title={`Risk Score: ${(metrics.risk * 100).toFixed(0)}%`}>
              <span className={`dot ${getRiskLevel(metrics.risk)}`} />
              <span className="metric-label">RISK</span>
            </div>
            <div className="metric-dot" title={`Estimated Cost: $${metrics.cost.toFixed(2)}`}>
              <span className="dot blue" />
              <span className="metric-label">${metrics.cost.toFixed(2)}</span>
            </div>
            {metrics.privacy !== undefined && (
              <div className="metric-dot" title={`Privacy Leak: ${(metrics.privacy * 100).toFixed(0)}%`}>
                <span className={`dot ${getRiskLevel(metrics.privacy)}`} />
                <span className="metric-label">LEAK</span>
              </div>
            )}
          </div>

          <div className="transport-controls">
            <button 
              className="transport-btn play" 
              onClick={onRun}
              title="Run Workflow (⌘↵)"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
                <polygon points="5,3 19,12 5,21" />
              </svg>
            </button>
            <button 
              className="transport-btn pause" 
              onClick={onPause}
              title="Pause"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
                <rect x="6" y="4" width="4" height="16" />
                <rect x="14" y="4" width="4" height="16" />
              </svg>
            </button>
            {onReplay && (
              <button 
                className="transport-btn" 
                onClick={onReplay}
                title="Replay Last Run"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M1 4v6h6M23 20v-6h-6" />
                  <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" />
                </svg>
              </button>
            )}
          </div>

          <div className="status-leds">
            <div className="led-indicator" title="Local Runtime: Ready">
              <span className="led led-green" />
              <span className="led-label">LOCAL</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
