import { useState } from 'react';
import { 
    AgentEditor, 
    ActivityBar, 
    AgentsDashboard, 
    BuilderView, 
    FleetView, 
    MarketplaceView,
    ConnectorsView
} from '@ioi/agent-ide';
import type { AgentSummary, MarketplaceAgent } from '@ioi/agent-ide';

import { WebMockRuntime } from './services/WebMockRuntime';
import "@ioi/agent-ide/dist/style.css";
import "./App.css"; 

const runtime = new WebMockRuntime();

function App() {
  const [activeView, setActiveView] = useState("compose");
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);

  const handleOpenAgent = (agent: AgentSummary | null) => {
    setEditingAgent(agent || { id: 'new', name: 'New Agent', description: '', model: 'GPT-4o' });
  };

  const handleInstallAgent = (agent: MarketplaceAgent) => {
      console.log("Installing from Web Marketplace:", agent.name);
      alert(`Simulating install for ${agent.name}...`);
  };

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', background: 'var(--surface-0)', color: 'var(--text-primary)' }}>
      <ActivityBar 
        activeView={activeView} 
        onViewChange={(view) => {
            setActiveView(view);
            if (view !== 'agents') setEditingAgent(null);
        }} 
      />

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        
        {/* Editor View */}
        {activeView === "compose" && (
            <AgentEditor runtime={runtime} />
        )}

        {/* Fleet View */}
        {activeView === "fleet" && (
            <FleetView runtime={runtime} />
        )}

        {/* Marketplace View - [NEW] */}
        {activeView === "marketplace" && (
            <MarketplaceView 
                runtime={runtime}
                onInstall={handleInstallAgent}
            />
        )}

        {/* Integrations View */}
        {activeView === "integrations" && (
            <ConnectorsView runtime={runtime} />
        )}

        {/* Agents Dashboard */}
        {activeView === "agents" && (
            <div style={{ width: '100%', height: '100%' }}>
                {!editingAgent ? (
                    <AgentsDashboard 
                        runtime={runtime} 
                        onSelectAgent={handleOpenAgent} 
                    />
                ) : (
                    <BuilderView 
                        runtime={runtime}
                        onBack={() => setEditingAgent(null)}
                        onAddToGraph={(config) => { 
                            console.log("Adding to graph:", config);
                            setActiveView('compose');
                            setEditingAgent(null);
                        }} 
                    />
                )}
            </div>
        )}

        {/* Fallback */}
        {(activeView !== "compose" &&
          activeView !== "agents" &&
          activeView !== "fleet" &&
          activeView !== "marketplace" &&
          activeView !== "integrations") && (
             <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-tertiary)' }}>
                View "{activeView}" not available in Web Demo
             </div>
        )}

      </div>
    </div>
  );
}

export default App;
