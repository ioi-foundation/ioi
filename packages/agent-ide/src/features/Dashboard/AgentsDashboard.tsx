import { useState, useEffect } from "react";
import { AgentRuntime, AgentSummary } from "../../runtime/agent-runtime";
import "./AgentsDashboard.css";

interface AgentsDashboardProps {
  runtime: AgentRuntime;
  onSelectAgent: (agent: AgentSummary | null) => void; 
}

export function AgentsDashboard({ runtime, onSelectAgent }: AgentsDashboardProps) {
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    runtime.getAgents().then(setAgents);
  }, [runtime]);

  const selectedAgent = agents.find(a => a.id === selectedId);

  return (
    <div className="agents-dashboard">
      {/* LEFT SIDEBAR: LIST */}
      <div className="agents-sidebar">
        <div className="agents-header">
          <h2>Agents</h2>
          <button 
            onClick={() => onSelectAgent(null)}
            className="create-btn"
          >
            + Create
          </button>
        </div>
        <div className="agents-list">
          {agents.map(agent => (
            <div 
              key={agent.id} 
              onClick={() => setSelectedId(agent.id)}
              className={`agent-item ${selectedId === agent.id ? 'active' : ''}`}
            >
              <div className="agent-icon">{agent.icon || '🤖'}</div>
              <div className="agent-info">
                <div className="agent-name">{agent.name}</div>
                <div className="agent-desc">{agent.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {/* RIGHT MAIN: DETAILS */}
      <div className="agents-main">
        {selectedAgent ? (
          <div className="agent-detail">
            <div className="detail-header">
                <div className="detail-icon">{selectedAgent.icon || '🤖'}</div>
                <div>
                    <h1>{selectedAgent.name}</h1>
                    <div className="detail-meta">
                        <span className="meta-badge">{selectedAgent.model || 'Unknown Model'}</span>
                    </div>
                </div>
            </div>
            <p className="detail-desc">{selectedAgent.description}</p>
            <button 
                onClick={() => onSelectAgent(selectedAgent)}
                className="open-btn"
            >
                Open in Editor
            </button>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🤖</div>
            <h3>No agent selected</h3>
            <p>Select an agent to view details or create a new one.</p>
          </div>
        )}
      </div>
    </div>
  );
}