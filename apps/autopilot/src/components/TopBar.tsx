import { ExecutionMode, LiabilityMode } from "../types";
import { Logo } from "./Logo";
import "./TopBar.css";

interface TopBarProps {
  projectName: string;
  projectPath: string;
  mode: ExecutionMode;
  liability: LiabilityMode;
  receiptsEnabled: boolean;
  metrics: {
    cost: number;
    privacy: number;
    risk: number;
  };
  onModeChange: (mode: ExecutionMode) => void;
  onLiabilityChange: (liability: LiabilityMode) => void;
  onReceiptsToggle: () => void;
  onRun: () => void;
  onPause: () => void;
  onReplay: () => void;
  onOpenCommandPalette: () => void;
}

export function TopBar({
  projectName,
  projectPath,
  mode,
  liability,
  receiptsEnabled,
  metrics,
  onModeChange,
  onLiabilityChange,
  onReceiptsToggle,
  onRun,
  onPause,
  onReplay,
  onOpenCommandPalette,
}: TopBarProps) {
  const getMeterLevel = (value: number) => {
    if (value < 0.33) return "low";
    if (value < 0.66) return "medium";
    return "high";
  };

  return (
    <header className="topbar">
      {/* Row 1: Breadcrumb + Status */}
      <div className="topbar-row topbar-row-primary">
        <div className="topbar-left">
          <div className="topbar-logo">
            <Logo style={{ width: 20, height: 20 }} />
            <span className="topbar-brand">Autopilot</span>
          </div>
          <span className="topbar-sep">▸</span>
          <span className="topbar-path">{projectPath}</span>
          <span className="topbar-sep">▸</span>
          <span className="topbar-project">"{projectName}"</span>
        </div>
        <div className="topbar-right">
          <div className="topbar-status">
            <span className="status-dot status-ready"></span>
            <span className="status-text">Local Ready</span>
          </div>
        </div>
      </div>

      {/* Row 2: Controls + Metrics */}
      <div className="topbar-row topbar-row-secondary">
        <div className="topbar-left">
          {/* Search */}
          <button className="topbar-search" onClick={onOpenCommandPalette}>
            <kbd>⌘K</kbd>
            <span>Search…</span>
          </button>

          <div className="divider"></div>

          {/* Run Controls */}
          <div className="topbar-controls">
            <button className="btn btn-primary" onClick={onRun}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <polygon points="5,3 19,12 5,21" />
              </svg>
              Run
            </button>
            <button className="btn btn-ghost btn-icon" onClick={onPause} title="Pause">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <rect x="6" y="4" width="4" height="16" />
                <rect x="14" y="4" width="4" height="16" />
              </svg>
            </button>
            <button className="btn btn-ghost btn-icon" onClick={onReplay} title="Replay">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 4v6h6M23 20v-6h-6" />
                <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" />
              </svg>
            </button>
          </div>

          <div className="divider"></div>

          {/* Mode Selectors */}
          <div className="topbar-selectors">
            <label className="topbar-selector">
              <span className="selector-label">Mode:</span>
              <select
                className="select"
                value={mode}
                onChange={(e) => onModeChange(e.target.value as ExecutionMode)}
              >
                <option value="local">Local</option>
                <option value="session">Session</option>
                <option value="settlement">Settlement</option>
              </select>
            </label>
            <label className="topbar-selector">
              <span className="selector-label">Liability:</span>
              <select
                className="select"
                value={liability}
                onChange={(e) => onLiabilityChange(e.target.value as LiabilityMode)}
              >
                <option value="none">None</option>
                <option value="optional">Optional</option>
                <option value="required">Required</option>
              </select>
            </label>
          </div>
        </div>

        <div className="topbar-right">
          {/* Metrics */}
          <div className="topbar-metrics">
            <div className="metric">
              <span className="metric-label">Cost:</span>
              <span className="metric-value">${metrics.cost.toFixed(2)}/run</span>
            </div>

            <div className="metric">
              <span className="metric-label">Privacy:</span>
              <div className="meter">
                <div className="meter-bar">
                  <div
                    className={`meter-fill ${getMeterLevel(metrics.privacy)}`}
                    style={{ width: `${metrics.privacy * 100}%` }}
                  />
                </div>
                <span className="meter-label">
                  {metrics.privacy < 0.33 ? "Low" : metrics.privacy < 0.66 ? "Med" : "High"} leak
                </span>
              </div>
            </div>

            <div className="metric">
              <span className="metric-label">Risk:</span>
              <div className="meter">
                <div className="meter-bar">
                  <div
                    className={`meter-fill ${getMeterLevel(metrics.risk)}`}
                    style={{ width: `${metrics.risk * 100}%` }}
                  />
                </div>
                <span className="meter-label">
                  {metrics.risk < 0.33 ? "Low" : metrics.risk < 0.66 ? "Medium" : "High"}
                </span>
              </div>
            </div>

            <div className="metric metric-toggle">
              <span className="metric-label">Receipts:</span>
              <button
                className={`toggle ${receiptsEnabled ? "toggle-on" : ""}`}
                onClick={onReceiptsToggle}
              >
                <span className="toggle-knob"></span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}