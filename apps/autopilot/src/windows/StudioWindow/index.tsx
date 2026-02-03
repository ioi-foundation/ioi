// apps/autopilot/src/windows/StudioWindow/index.tsx
import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { 
    AgentEditor, 
    ActivityBar, 
    AgentsDashboard, 
    BuilderView, 
    FleetView, 
    MarketplaceView
} from "@ioi/agent-ide";
import type { AgentSummary } from "@ioi/agent-ide";
import { TauriRuntime } from "../../services/TauriRuntime";

// Shell Components
import { StudioCopilotView } from "./components/StudioCopilot";
import { AgentInstallModal } from "../../components/AgentInstallModal";
import { CommandPalette } from "../../components/CommandPalette";
import { StatusBar } from "../../components/StatusBar";
import { VisionHUD } from "../../components/VisionHUD";

// Ensure shared CSS is loaded
import "@ioi/agent-ide/dist/style.css";
import "./StudioWindow.css";

// Instantiate the adapter once
const runtime = new TauriRuntime();

export function StudioWindow() {
  // --- Layout State ---
  const [activeView, setActiveView] = useState("compose");
  const [interfaceMode, setInterfaceMode] = useState<"GHOST" | "COMPOSE">("COMPOSE");
  
  // --- Feature State ---
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<any>(null); // For Marketplace modal
  
  // --- Modals ---
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);

  // --- Listeners ---
  useEffect(() => {
    // Allow other windows (Spotlight) to request a view change via backend event
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      setActiveView(event.payload);
    });
    return () => { unlistenPromise.then((unlisten) => unlisten()); };
  }, []);

  // Handler to open the Builder from the Dashboard
  const handleOpenAgent = (agent: AgentSummary | null) => {
    setEditingAgent(agent || { id: 'new', name: 'New Agent', description: '', model: 'GPT-4o' });
  };

  return (
    <div className="studio-window">
      {/* Shared Activity Bar from Agent IDE Package */}
      <ActivityBar 
        activeView={activeView} 
        onViewChange={(view) => { 
            setActiveView(view); 
            // Reset sub-views when switching main tabs
            if (view !== 'agents') setEditingAgent(null); 
        }}
        ghostMode={interfaceMode === "GHOST"}
        onToggleGhost={() => setInterfaceMode(prev => prev === "GHOST" ? "COMPOSE" : "GHOST")}
      />
      
      <div className="studio-main">
        
        <div className="studio-content">
          
          {/* VIEW: COMPOSE (The Graph Editor) */}
          {activeView === "compose" && (
            <div style={{ position: 'relative', width: '100%', height: '100%' }}>
              {/* Ghost Mode Overlay (Shell Feature) */}
              {interfaceMode === "GHOST" && (
                <>
                  <div className="ghost-overlay">
                    <div className="ghost-badge">
                        <span className="ghost-dot" />
                        <span>Ghost Mode Recording</span>
                    </div>
                  </div>
                  {/* VisionHUD floats on the left/top via CSS */}
                  <VisionHUD /> 
                </>
              )}
              
              {/* The Shared Package */}
              <AgentEditor runtime={runtime} />
            </div>
          )}

          {/* VIEW: FLEET */}
          {activeView === "fleet" && (
              <FleetView runtime={runtime} />
          )}

          {/* VIEW: COPILOT */}
          {activeView === "copilot" && <StudioCopilotView />}

          {/* VIEW: MARKETPLACE */}
          {activeView === "marketplace" && (
            <MarketplaceView 
                runtime={runtime}
                onInstall={(agent) => { 
                    setSelectedAgent(agent); 
                    setInstallModalOpen(true); 
                }} 
            />
          )}

          {/* VIEW: AGENTS (Dashboard + Builder) */}
          {activeView === "agents" && (
            <div className="studio-center-area">
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
                            // 1. Switch to Compose View
                            setActiveView('compose');
                            setEditingAgent(null);
                            console.log("Loading Agent Config into Graph:", config);
                            // TODO: runtime.loadConfig(config)
                        }} 
                    />
                )}
            </div>
          )}

        </div>
        
        {/* Global OS Status Bar */}
        <StatusBar 
            metrics={{ cost: 0.00, privacy: 0.0, risk: 0.0 }} 
            status={interfaceMode === "GHOST" ? "Recording..." : "Ready"} 
        />
      </div>

      {/* --- Global Modals --- */}
      {commandPaletteOpen && (
        <CommandPalette onClose={() => setCommandPaletteOpen(false)} />
      )}
      
      {installModalOpen && selectedAgent && (
        <AgentInstallModal 
            isOpen={installModalOpen} 
            onClose={() => setInstallModalOpen(false)} 
            agent={selectedAgent} 
        />
      )}
    </div>
  );
}