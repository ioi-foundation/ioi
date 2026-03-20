import "./StatusBar.css";

interface StatusBarProps {
  metrics: {
    cost: number;
    privacy: number;
    risk: number;
  };
  status?: string;
  onOpenShield?: () => void;
}

export function StatusBar({ metrics, status = "Ready", onOpenShield }: StatusBarProps) {
  const getRiskColor = (val: number) => {
    if (val < 0.33) return "var(--status-success)";
    if (val < 0.66) return "var(--status-warning)";
    return "var(--status-error)";
  };

  return (
    <div className="status-bar">
      <div className="status-left">
        <div className="status-item">
          <span className="status-icon-dot" />
          <span>{status}</span>
        </div>
      </div>
      
      <div className="status-right">
        <div className="status-item">
          <span>Cost:</span>
          <strong>${metrics.cost.toFixed(2)}</strong>
        </div>
        <button
          type="button"
          className={`status-item status-button ${onOpenShield ? "clickable" : ""}`}
          title="Open Shield policy center"
          onClick={onOpenShield}
          disabled={!onOpenShield}
        >
          <span>Privacy:</span>
          <div className="status-meter">
            <div 
              className="meter-fill" 
              style={{ width: `${metrics.privacy * 100}%`, background: getRiskColor(metrics.privacy) }} 
            />
          </div>
        </button>
        <button
          type="button"
          className={`status-item status-button ${onOpenShield ? "clickable" : ""}`}
          title="Open Shield policy center"
          onClick={onOpenShield}
          disabled={!onOpenShield}
        >
          <span>Risk:</span>
          <div className="status-meter">
            <div 
              className="meter-fill" 
              style={{ width: `${metrics.risk * 100}%`, background: getRiskColor(metrics.risk) }} 
            />
          </div>
        </button>
        <div className="status-item clickable" title="Execution Environment">
          <span>Env: Default</span>
        </div>
        <div className="status-item clickable" title="Active Model">
          <span>Model: GPT-4o</span>
        </div>
      </div>
    </div>
  );
}
