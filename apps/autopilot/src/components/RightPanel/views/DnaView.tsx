export function DnaView() {
  return (
    <div className="lineage-view">
        <div className="gene-header">
            <span className="gene-title">Current Generation</span>
            <span className="gene-badge">Gen 5</span>
        </div>
        <div className="mutation-log">
            <div className="mutation-entry success">
                <div className="mutation-meta">
                    <span>Gen 4 → 5</span>
                    <span className="timestamp">10m ago</span>
                </div>
                <div className="mutation-reason">Fixed JSON parsing error in `tool_call` regex.</div>
                <div className="mutation-score positive">+15% Success Rate</div>
            </div>
            
            <div className="mutation-entry success">
                <div className="mutation-meta">
                    <span>Gen 3 → 4</span>
                    <span className="timestamp">1h ago</span>
                </div>
                <div className="mutation-reason">Added `net::fetch` error handling retry logic.</div>
                <div className="mutation-score positive">+5% Success Rate</div>
            </div>
            
            <div className="mutation-entry failed">
                <div className="mutation-meta">
                    <span>Gen 2 → 3</span>
                    <span className="timestamp">2h ago</span>
                </div>
                <div className="mutation-reason">Attempted to remove budget cap.</div>
                <div className="mutation-score negative">REJECTED BY SAFETY RATCHET</div>
            </div>
        </div>
        
        <div className="gene-stats">
            <div className="stat-box">
                <div className="stat-label">Total Earnings</div>
                <div className="stat-val">12.50 L-GAS</div>
            </div>
            <div className="stat-box">
                <div className="stat-label">Fitness Score</div>
                <div className="stat-val">0.92</div>
            </div>
        </div>
    </div>
  );
}