import { useState, useEffect } from "react";
import { AgentRuntime, MarketplaceAgent } from "../../runtime/agent-runtime";
import "./MarketplaceView.css";

interface MarketplaceViewProps {
  runtime: AgentRuntime;
  onInstall: (agent: MarketplaceAgent) => void;
}

export function MarketplaceView({ runtime, onInstall }: MarketplaceViewProps) {
  const [agents, setAgents] = useState<MarketplaceAgent[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    runtime.getMarketplaceAgents().then(setAgents);
  }, [runtime]);

  const filtered = agents.filter(a => a.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="marketplace-view">
      <div className="market-header">
        <h1>Agent Marketplace</h1>
        <input 
            type="text" 
            placeholder="Search agents..." 
            className="market-search" 
            value={search}
            onChange={e => setSearch(e.target.value)}
        />
      </div>
      
      <div className="market-grid">
        {filtered.map(agent => (
          <div key={agent.id} className="market-card" onClick={() => onInstall(agent)}>
            <div className="card-vis">
               <div className="card-icon">{agent.icon || "📦"}</div>
            </div>
            <div className="card-info">
              <h3>{agent.name}</h3>
              <p className="card-dev">by {agent.developer}</p>
              <p className="card-desc">{agent.description}</p>
              <div className="card-footer">
                <span className="price">{agent.price}</span>
                <span className="req">{agent.requirements}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}