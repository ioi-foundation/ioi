import { useEffect, useState } from "react";
import {
  ActivityBar,
  AgentEditor,
  AgentsDashboard,
  BuilderView,
  ConnectorsView,
  FleetView,
  RuntimeCatalogView,
} from "@ioi/agent-ide";
import type { AgentSummary, RuntimeCatalogEntry } from "@ioi/agent-ide";

import { BrowserWorkspaceRuntime } from "./services/BrowserWorkspaceRuntime";
import "@ioi/agent-ide/dist/style.css";
import "./App.css";

const runtime = new BrowserWorkspaceRuntime();

type BrowserHomeSummary = {
  agents: number;
  connectors: number;
  catalog: number;
  fleet: number;
};

function App() {
  const [activeView, setActiveView] = useState("copilot");
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);
  const [runtimeRevision, setRuntimeRevision] = useState(0);
  const [bannerMessage, setBannerMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!bannerMessage) {
      return;
    }

    const timeout = window.setTimeout(() => setBannerMessage(null), 3600);
    return () => window.clearTimeout(timeout);
  }, [bannerMessage]);

  const handleOpenAgent = (agent: AgentSummary | null) => {
    setEditingAgent(
      agent || { id: "new", name: "New Agent", description: "", model: "GPT-4o" },
    );
  };

  const handleStageCatalogEntry = (entry: RuntimeCatalogEntry) => {
    void runtime
      .stageRuntimeCatalogEntry(
        entry.id,
        `Staged from Agent Chat at ${new Date().toISOString()}`,
      )
      .then(() => {
        setRuntimeRevision((current) => current + 1);
        setBannerMessage(`${entry.name} is now ready in this workspace.`);
        setEditingAgent(null);
        setActiveView("agents");
      })
      .catch((error) => {
        setBannerMessage(String(error));
      });
  };

  const resolvedView = activeView === "marketplace" ? "catalog" : activeView;
  const shellTitle =
    resolvedView === "copilot"
      ? "Operator workspace"
      : resolvedView === "catalog"
        ? "Runtime catalog"
        : resolvedView === "compose"
          ? "Graph compose"
          : resolvedView === "fleet"
            ? "Fleet posture"
            : resolvedView === "integrations"
              ? "Integrations"
              : "Agents";

  return (
    <div className="agent-studio-app-shell">
      <ActivityBar
        activeView={resolvedView}
        onViewChange={(view) => {
          setActiveView(view);
          if (view !== "agents") {
            setEditingAgent(null);
          }
        }}
      />

      <div className="agent-studio-workspace-shell">
        <header className="agent-studio-shell-header">
          <div>
            <span className="agent-studio-shell-kicker">Agent Chat</span>
            <h1>{shellTitle}</h1>
          </div>
          <div className="agent-studio-shell-meta">
            <span className="agent-studio-shell-chip">Workspace shell</span>
            <span className="agent-studio-shell-chip">Persistent state</span>
            <span className="agent-studio-shell-chip">Desktop handoff</span>
          </div>
        </header>

        {bannerMessage ? (
          <div className="agent-studio-banner" role="status">
            <span>{bannerMessage}</span>
            <button type="button" onClick={() => setBannerMessage(null)}>
              Dismiss
            </button>
          </div>
        ) : null}

        <div className="agent-studio-workspace-body">
          {resolvedView === "copilot" ? (
            <BrowserStudioHome
              runtime={runtime}
              runtimeRevision={runtimeRevision}
              onGoToCompose={() => setActiveView("compose")}
              onGoToCatalog={() => setActiveView("catalog")}
              onGoToAgents={() => setActiveView("agents")}
              onGoToIntegrations={() => setActiveView("integrations")}
              onGoToFleet={() => setActiveView("fleet")}
            />
          ) : null}

          {resolvedView === "compose" ? (
            <AgentEditor key={`compose-${runtimeRevision}`} runtime={runtime} />
          ) : null}

          {resolvedView === "catalog" ? (
            <RuntimeCatalogView
              key={`catalog-${runtimeRevision}`}
              runtime={runtime}
              onStageEntry={handleStageCatalogEntry}
            />
          ) : null}

          {resolvedView === "fleet" ? (
            <FleetView key={`fleet-${runtimeRevision}`} runtime={runtime} />
          ) : null}

          {resolvedView === "integrations" ? (
            <ConnectorsView
              key={`integrations-${runtimeRevision}`}
              runtime={runtime}
            />
          ) : null}

          {resolvedView === "agents" ? (
            <div className="agent-studio-agents-pane">
              {!editingAgent ? (
                <AgentsDashboard
                  key={`agents-${runtimeRevision}`}
                  runtime={runtime}
                  onSelectAgent={handleOpenAgent}
                />
              ) : (
                <BuilderView
                  runtime={runtime}
                  onBack={() => setEditingAgent(null)}
                  onAddToGraph={(config) => {
                    console.log("Adding to graph:", config);
                    setActiveView("compose");
                    setEditingAgent(null);
                  }}
                />
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function BrowserStudioHome({
  runtime,
  runtimeRevision,
  onGoToCompose,
  onGoToCatalog,
  onGoToAgents,
  onGoToIntegrations,
  onGoToFleet,
}: {
  runtime: BrowserWorkspaceRuntime;
  runtimeRevision: number;
  onGoToCompose: () => void;
  onGoToCatalog: () => void;
  onGoToAgents: () => void;
  onGoToIntegrations: () => void;
  onGoToFleet: () => void;
}) {
  const [summary, setSummary] = useState<BrowserHomeSummary>({
    agents: 0,
    connectors: 0,
    catalog: 0,
    fleet: 0,
  });

  useEffect(() => {
    let active = true;

    void Promise.all([
      runtime.getAgents(),
      runtime.getConnectors?.() ?? Promise.resolve([]),
      runtime.getRuntimeCatalogEntries(),
      runtime.getFleetState(),
    ]).then(([agents, connectors, catalogEntries, fleetState]) => {
      if (!active) {
        return;
      }
      setSummary({
        agents: agents.length,
        connectors: connectors.length,
        catalog: catalogEntries.length,
        fleet: fleetState.containers.length,
      });
    });

    return () => {
      active = false;
    };
  }, [runtime, runtimeRevision]);

  return (
    <section className="agent-studio-home">
      <div className="agent-studio-home-hero">
        <span className="agent-studio-home-kicker">Workspace shell</span>
        <h2>Shape the agent, stage the runtime, then hand off with context intact.</h2>
        <p>
          This workspace keeps compose, catalog staging, integrations, and fleet
          posture in one persisted shell. Use it to stage, inspect, and hand off
          work without losing state before execution moves into the desktop runtime.
        </p>
        <div className="agent-studio-home-actions">
          <button type="button" onClick={onGoToCompose}>
            Open compose
          </button>
          <button type="button" onClick={onGoToCatalog}>
            Stage from catalog
          </button>
          <button type="button" onClick={onGoToAgents}>
            Review agents
          </button>
        </div>
      </div>

      <div className="agent-studio-home-strip" aria-label="Workspace summary">
        <div>
          <strong>{summary.agents}</strong>
          <span>agents available</span>
        </div>
        <div>
          <strong>{summary.catalog}</strong>
          <span>catalog entries ready</span>
        </div>
        <div>
          <strong>{summary.connectors}</strong>
          <span>connector surfaces</span>
        </div>
        <div>
          <strong>{summary.fleet}</strong>
          <span>fleet targets visible</span>
        </div>
      </div>

      <div className="agent-studio-home-grid">
        <button
          type="button"
          className="agent-studio-home-panel"
          onClick={onGoToCatalog}
        >
          <span className="agent-studio-home-panel-eyebrow">Catalog</span>
          <strong>Stage runtime packs</strong>
          <p>
            Promote runtime packs into this workspace without detouring through
            one-off install flows.
          </p>
        </button>
        <button
          type="button"
          className="agent-studio-home-panel"
          onClick={onGoToIntegrations}
        >
          <span className="agent-studio-home-panel-eyebrow">Integrations</span>
          <strong>Check connector posture</strong>
          <p>
            Inspect provider posture and action coverage from the same workspace
            shell.
          </p>
        </button>
        <button
          type="button"
          className="agent-studio-home-panel"
          onClick={onGoToFleet}
        >
          <span className="agent-studio-home-panel-eyebrow">Fleet</span>
          <strong>Scan runtime capacity</strong>
          <p>
            Keep deploy targets and operator infrastructure visible before
            handing work off.
          </p>
        </button>
      </div>
    </section>
  );
}

export default App;
