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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    setLoading(true);
    setError(null);
    runtime
      .getAgents()
      .then((items) => {
        if (!active) return;
        setAgents(items);
      })
      .catch((nextError) => {
        if (!active) return;
        setError(String(nextError));
        setAgents([]);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });

    return () => {
      active = false;
    };
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
          {loading ? <div className="empty-state">Loading live agents…</div> : null}
          {error ? <div className="empty-state">{error}</div> : null}
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
            <h3>{error ? "Agents unavailable" : loading ? "Loading agents" : "No agent selected"}</h3>
            <p>
              {error
                ? "The live runtime did not return the current agent catalog."
                : loading
                  ? "Fetching the current agent catalog from the live runtime."
                  : "Select an agent to view details or create a new one."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
