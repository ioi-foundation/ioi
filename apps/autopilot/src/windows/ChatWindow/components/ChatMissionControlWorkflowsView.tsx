import {
  AgentEditor,
  AgentsDashboard,
  BuilderView,
  type RuntimeCatalogEntry,
  type AgentWorkbenchRuntime,
  type ProjectFile,
  type AgentSummary,
  RuntimeCatalogView,
} from "@ioi/agent-ide";
import { ChatWelcomeView } from "./ChatWelcomeView";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ChatMissionControlWorkflowsViewProps {
  runtime: AgentWorkbenchRuntime;
  surface: "home" | "canvas" | "agents" | "catalog";
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  editingAgent: AgentSummary | null;
  onSurfaceChange: (surface: "home" | "canvas" | "agents" | "catalog") => void;
  onSelectProject: (projectId: string) => void;
  onOpenStudio: () => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: () => void;
  onOpenAgent: (agent: AgentSummary | null) => void;
  onCloseAgent: () => void;
  onStageCatalogEntry: (entry: RuntimeCatalogEntry) => void;
  composeSeedProject: ProjectFile | null;
  onConsumeComposeSeedProject: () => void;
  onAddBuilderConfigToCanvas: (config: any) => void;
}

function workflowSurfaceLabel(surface: ChatMissionControlWorkflowsViewProps["surface"]): string {
  switch (surface) {
    case "home":
      return "Home";
    case "agents":
      return "Agents";
    case "catalog":
      return "Runtime catalog";
    default:
      return "Canvas";
  }
}

export function ChatMissionControlWorkflowsView({
  runtime,
  surface,
  currentProject,
  projects,
  notificationCount,
  editingAgent,
  onOpenStudio,
  onSurfaceChange,
  onSelectProject,
  onOpenInbox,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenSettings,
  onOpenAgent,
  onCloseAgent,
  onStageCatalogEntry,
  composeSeedProject,
  onConsumeComposeSeedProject,
  onAddBuilderConfigToCanvas,
}: ChatMissionControlWorkflowsViewProps) {
  const surfaceLabel = workflowSurfaceLabel(surface);
  const title =
    surface === "home"
      ? "Builder internals"
      : "Workflow authoring";
  const kicker = surface === "home" ? "Internal" : "Encode";

  return (
    <div className="mission-control-view mission-control-view--workflows">
      <header className="mission-control-header mission-control-header--workflow">
        <div className="mission-control-header-copy mission-control-header-copy--workflow">
          <span className="mission-control-kicker">{kicker}</span>
          <div className="mission-control-workflow-title-row">
            <h2>{title}</h2>
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
              className={surface === "home" ? "is-active" : ""}
              onClick={() => onSurfaceChange("home")}
            >
              Home
            </button>
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
        {surface === "home" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
          <ChatWelcomeView
              currentProject={currentProject}
              projects={projects}
              notificationCount={notificationCount}
              onOpenCanvas={() => onSurfaceChange("canvas")}
              onOpenStudio={onOpenStudio}
              onOpenAgents={() => onSurfaceChange("agents")}
              onOpenCatalog={() => onSurfaceChange("catalog")}
              onOpenInbox={onOpenInbox}
              onOpenCapabilities={onOpenCapabilities}
              onOpenPolicy={onOpenPolicy}
              onSelectProject={onSelectProject}
            />
          </div>
        ) : null}

        {surface === "canvas" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            <div className="mission-control-workflow-plane">
              <AgentEditor
                runtime={runtime}
                initialFile={composeSeedProject ?? undefined}
                onInitialFileLoaded={onConsumeComposeSeedProject}
                onOpenSystemSettings={onOpenSettings}
              />
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
            <RuntimeCatalogView
              runtime={runtime}
              onStageEntry={onStageCatalogEntry}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}

export const MissionControlWorkflowsView = ChatMissionControlWorkflowsView;
