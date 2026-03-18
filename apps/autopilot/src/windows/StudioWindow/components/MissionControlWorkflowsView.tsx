import {
  AgentEditor,
  AgentsDashboard,
  BuilderView,
  MarketplaceView,
  type AgentRuntime,
  type AgentSummary,
} from "@ioi/agent-ide";
import { VisionHUD } from "../../../components/VisionHUD";

interface MissionControlWorkflowsViewProps {
  runtime: AgentRuntime;
  interfaceMode: "GHOST" | "COMPOSE";
  surface: "canvas" | "agents" | "catalog";
  editingAgent: AgentSummary | null;
  onSurfaceChange: (surface: "canvas" | "agents" | "catalog") => void;
  onOpenAgent: (agent: AgentSummary | null) => void;
  onCloseAgent: () => void;
  onInstallAgent: (agent: any) => void;
  onAddBuilderConfigToCanvas: (config: any) => void;
}

function workflowSurfaceLabel(surface: MissionControlWorkflowsViewProps["surface"]): string {
  switch (surface) {
    case "agents":
      return "Agents";
    case "catalog":
      return "Catalog";
    default:
      return "Canvas";
  }
}

export function MissionControlWorkflowsView({
  runtime,
  interfaceMode,
  surface,
  editingAgent,
  onSurfaceChange,
  onOpenAgent,
  onCloseAgent,
  onInstallAgent,
  onAddBuilderConfigToCanvas,
}: MissionControlWorkflowsViewProps) {
  const surfaceLabel = workflowSurfaceLabel(surface);

  return (
    <div className="mission-control-view mission-control-view--workflows">
      <header className="mission-control-header mission-control-header--workflow">
        <div className="mission-control-header-copy mission-control-header-copy--workflow">
          <span className="mission-control-kicker">Encode</span>
          <div className="mission-control-workflow-title-row">
            <h2>Workflow authoring</h2>
            <span className="mission-control-workflow-surface">{surfaceLabel}</span>
          </div>
        </div>

        <div className="mission-control-header-actions">
          <div
            className="mission-control-tabs mission-control-tabs--workflow"
            role="tablist"
            aria-label="Workflow surfaces"
          >
            <button
              type="button"
              className={surface === "canvas" ? "is-active" : ""}
              onClick={() => onSurfaceChange("canvas")}
            >
              Canvas
            </button>
            <button
              type="button"
              className={surface === "agents" ? "is-active" : ""}
              onClick={() => onSurfaceChange("agents")}
            >
              Agents
            </button>
            <button
              type="button"
              className={surface === "catalog" ? "is-active" : ""}
              onClick={() => onSurfaceChange("catalog")}
            >
              Catalog
            </button>
          </div>
        </div>
      </header>

      <div className="mission-control-stage mission-control-stage--workflow">
        {surface === "canvas" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            <div className="mission-control-workflow-plane">
              {interfaceMode === "GHOST" ? (
                <>
                  <div className="ghost-overlay">
                    <div className="ghost-badge">
                      <span className="ghost-dot" />
                      <span>Ghost Mode Recording</span>
                    </div>
                  </div>
                  <VisionHUD />
                </>
              ) : null}

              <AgentEditor runtime={runtime} />
            </div>
          </div>
        ) : null}

        {surface === "agents" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            {!editingAgent ? (
              <AgentsDashboard runtime={runtime} onSelectAgent={onOpenAgent} />
            ) : (
              <BuilderView
                runtime={runtime}
                onBack={onCloseAgent}
                onAddToGraph={(config) => {
                  onSurfaceChange("canvas");
                  onCloseAgent();
                  onAddBuilderConfigToCanvas(config);
                }}
              />
            )}
          </div>
        ) : null}

        {surface === "catalog" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            <MarketplaceView runtime={runtime} onInstall={onInstallAgent} />
          </div>
        ) : null}
      </div>
    </div>
  );
}
