import { useState } from "react";
import "./MarketplaceView.css";

interface MarketplaceViewProps {
  onInstallAgent: (agent: any) => void;
}

const featuredAgents = [
  { id: "a1", name: "DeFi Sentinel", dev: "QuantLabs", price: "$0.05/run", image: "linear-gradient(135deg, #1e293b, #0f172a)", req: "24GB VRAM" },
  { id: "a2", name: "Legal Reviewer", dev: "LawAI", price: "$29/mo", image: "linear-gradient(135deg, #475569, #334155)", req: "8GB VRAM" },
  { id: "a3", name: "Research Swarm", dev: "OpenSci", price: "Free", image: "linear-gradient(135deg, #2563eb, #1d4ed8)", req: "48GB VRAM" },
  { id: "a4", name: "Video Gen", dev: "CreativeX", price: "$0.10/min", image: "linear-gradient(135deg, #ec4899, #be185d)", req: "H100 GPU" },
];

export function MarketplaceView({ onInstallAgent }: MarketplaceViewProps) {
  return (
    <div className="marketplace-view">
      <div className="market-header">
        <h1>Agent Marketplace</h1>
        <input type="text" placeholder="Search agents..." className="market-search" />
      </div>
      
      <div className="market-grid">
        {featuredAgents.map(agent => (
          <div key={agent.id} className="market-card" onClick={() => onInstallAgent(agent)}>
            <div className="card-vis" style={{ background: agent.image }}>
              <div className="card-req">{agent.req}</div>
            </div>
            <div className="card-info">
              <h3>{agent.name}</h3>
              <p>by {agent.dev}</p>
              <div className="card-footer">
                <span className="price">{agent.price}</span>
                <button className="get-btn">Get</button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}