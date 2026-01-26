// src/components/AgentsDashboard.tsx
import { useState } from "react";
import "./AgentsDashboard.css";

// Mock Data
export interface SimpleAgent {
  id: string;
  name: string;
  description: string;
  icon?: string;
  lastEdited?: string;
  model?: string;
}

const MOCK_AGENTS: SimpleAgent[] = [
  { id: 'a1', name: 'Invoice Analyst', description: 'Parses PDF invoices from emails and extracts vendor data into structured JSON.', icon: '📄', lastEdited: '2h ago', model: 'GPT-4o' },
  { id: 'a2', name: 'Support Triager', description: 'Routes incoming tickets to appropriate Slack channels based on urgency and topic.', icon: '📞', lastEdited: '1d ago', model: 'Claude 3.5' },
  { id: 'a3', name: 'Research Assistant', description: 'Scrapes web pages and summarizes findings into a digest.', icon: '🔍', lastEdited: '3d ago', model: 'Llama 3' },
];

interface AgentsDashboardProps {
  onSelectAgent: (agent: SimpleAgent | null) => void; 
}

export function AgentsDashboard({ onSelectAgent }: AgentsDashboardProps) {
  const [agents] = useState<SimpleAgent[]>(MOCK_AGENTS);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedAgent = agents.find(a => a.id === selectedId);

  return (
    <div className="agents-dashboard">
      {/* LEFT SIDEBAR: LIST */}
      <div className="agents-sidebar">
        <div className="agents-header">
          <h2>Agents</h2>
          <button className="create-btn-sm" onClick={() => onSelectAgent(null)}>+ Create</button>
        </div>
        <div className="agents-list">
          {agents.map(agent => (
            <div 
              key={agent.id} 
              className={`agent-item ${selectedId === agent.id ? 'active' : ''}`}
              onClick={() => setSelectedId(agent.id)}
            >
              <div className="agent-item-icon">{agent.icon}</div>
              <div className="agent-item-info">
                <div className="agent-item-name">{agent.name}</div>
                <div className="agent-item-desc">{agent.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {/* RIGHT MAIN: DETAILS OR EMPTY */}
      <div className="agents-main">
        {selectedAgent ? (
          <div className="agent-detail-view">
            <div className="detail-header">
                <div className="detail-icon">{selectedAgent.icon}</div>
                <div>
                    <h1>{selectedAgent.name}</h1>
                    <div className="detail-meta" style={{marginTop: 8}}>
                        <span className="meta-tag">{selectedAgent.model}</span>
                        <span className="meta-tag">Edited {selectedAgent.lastEdited}</span>
                    </div>
                </div>
            </div>
            
            <p className="detail-desc">{selectedAgent.description}</p>
            
            <div className="detail-actions">
                <button className="btn-primary" onClick={() => onSelectAgent(selectedAgent)}>Open in Builder</button>
                <button className="btn-secondary">Test in Playground</button>
            </div>
          </div>
        ) : (
          <div className="empty-selection">
            <div className="empty-icon">🤖</div>
            <h3>No agent selected</h3>
            <p>Select an agent from the list to view details or create a new one to get started.</p>
            <button className="btn-secondary" onClick={() => onSelectAgent(null)}>Create new agent</button>
          </div>
        )}
      </div>
    </div>
  );
}