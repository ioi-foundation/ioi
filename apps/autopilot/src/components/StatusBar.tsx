import "./StatusBar.css";

interface StatusBarProps {
  metrics: {
    cost: number;
    privacy: number;
    risk: number;
  };
  status?: string;
}

export function StatusBar({ metrics, status = "Ready" }: StatusBarProps) {
  const getRiskColor = (val: number) => {
    if (val < 0.33) return "#107c10";
    if (val < 0.66) return "#d18b0e";
    return "#a80000";
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
        <div className="status-item">
          <span>Privacy:</span>
          <div className="status-meter">
            <div 
              className="meter-fill" 
              style={{ width: `${metrics.privacy * 100}%`, background: getRiskColor(metrics.privacy) }} 
            />
          </div>
        </div>
        <div className="status-item">
          <span>Risk:</span>
          <div className="status-meter">
            <div 
              className="meter-fill" 
              style={{ width: `${metrics.risk * 100}%`, background: getRiskColor(metrics.risk) }} 
            />
          </div>
        </div>
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