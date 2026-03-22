import { Suspense, lazy } from "react";
import {
  AgentEditor,
  AgentsDashboard,
  BuilderView,
  MarketplaceView,
  type AgentRuntime,
  type AgentSummary,
} from "@ioi/agent-ide";
import { StudioWelcomeView } from "./StudioWelcomeView";
import type { StudioEditorTab } from "./StudioCodeWorkbench";

const StudioCodeWorkbench = lazy(async () => {
  const module = await import("./StudioCodeWorkbench");
  return { default: module.StudioCodeWorkbench };
});

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface MissionControlWorkflowsViewProps {
  runtime: AgentRuntime;
  surface: "home" | "code" | "canvas" | "agents" | "catalog";
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  editingAgent: AgentSummary | null;
  editorTabs: StudioEditorTab[];
  activeEditorPath: string | null;
  onSurfaceChange: (surface: "home" | "code" | "canvas" | "agents" | "catalog") => void;
  onSelectProject: (projectId: string) => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onSelectEditorTab: (path: string) => void;
  onCloseEditorTab: (path: string) => void;
  onChangeEditorTabContent: (path: string, content: string) => void;
  onSaveEditorTab: (path: string) => void;
  onReloadEditorTab: (path: string) => void;
  onOpenAgent: (agent: AgentSummary | null) => void;
  onCloseAgent: () => void;
  onInstallAgent: (agent: any) => void;
  onAddBuilderConfigToCanvas: (config: any) => void;
}

function workflowSurfaceLabel(surface: MissionControlWorkflowsViewProps["surface"]): string {
  switch (surface) {
    case "home":
      return "Home";
    case "code":
      return "Code";
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
  surface,
  currentProject,
  projects,
  notificationCount,
  editingAgent,
  editorTabs,
  activeEditorPath,
  onSurfaceChange,
  onSelectProject,
  onOpenInbox,
  onOpenCapabilities,
  onOpenPolicy,
  onSelectEditorTab,
  onCloseEditorTab,
  onChangeEditorTabContent,
  onSaveEditorTab,
  onReloadEditorTab,
  onOpenAgent,
  onCloseAgent,
  onInstallAgent,
  onAddBuilderConfigToCanvas,
}: MissionControlWorkflowsViewProps) {
  const surfaceLabel = workflowSurfaceLabel(surface);
  const title =
    surface === "home"
      ? "Autopilot home"
      : surface === "code"
        ? "Workspace editor"
        : "Workflow authoring";
  const kicker = surface === "home" ? "Welcome" : surface === "code" ? "Code" : "Encode";

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
              className={surface === "code" ? "is-active" : ""}
              onClick={() => onSurfaceChange("code")}
              disabled={editorTabs.length === 0}
            >
              Code
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
            <StudioWelcomeView
              currentProject={currentProject}
              projects={projects}
              notificationCount={notificationCount}
              onOpenCanvas={() => onSurfaceChange("canvas")}
              onOpenAgents={() => onSurfaceChange("agents")}
              onOpenCatalog={() => onSurfaceChange("catalog")}
              onOpenInbox={onOpenInbox}
              onOpenCapabilities={onOpenCapabilities}
              onOpenPolicy={onOpenPolicy}
              onSelectProject={onSelectProject}
            />
          </div>
        ) : null}

        {surface === "code" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            <Suspense
              fallback={
                <section className="studio-code-workbench studio-code-workbench--empty">
                  <div className="studio-code-message">
                    <strong>Loading editor</strong>
                    <p>
                      Studio loads the editor surface on demand so the default
                      operator shell stays lighter until you open a file.
                    </p>
                  </div>
                </section>
              }
            >
              <StudioCodeWorkbench
                currentProject={currentProject}
                tabs={editorTabs}
                activePath={activeEditorPath}
                onSelectTab={onSelectEditorTab}
                onCloseTab={onCloseEditorTab}
                onChangeTabContent={onChangeEditorTabContent}
                onSaveTab={onSaveEditorTab}
                onReloadTab={onReloadEditorTab}
              />
            </Suspense>
          </div>
        ) : null}

        {surface === "canvas" ? (
          <div className="mission-control-stage-frame mission-control-stage-frame--workflow">
            <div className="mission-control-workflow-plane">
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
