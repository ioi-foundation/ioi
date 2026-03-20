import { useEffect, type ReactNode } from "react";
import {
  AutopilotIcon,
  ComposeIcon,
  FleetIcon,
  GhostIcon,
  IntegrationsIcon,
  NotificationsIcon,
  SettingsIcon,
  ShieldIcon,
} from "./ActivityBarIcons";

type ActivityView =
  | "workflows"
  | "runs"
  | "inbox"
  | "capabilities"
  | "policy"
  | "settings";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
}

interface ActivityBarProps {
  activeView: ActivityView;
  onViewChange: (view: ActivityView) => void;
  notificationCount: number;
  ghostMode: boolean;
  onToggleGhost: () => void;
  utilityPaneOpen: boolean;
  activeUtilityTab: "operator" | "explorer" | "artifacts";
  onToggleUtilityPane: () => void;
  workspaceName: string;
  currentProject: ProjectScope;
  projects: ProjectScope[];
  onSelectProject: (projectId: string) => void;
}

interface NavItem {
  id: string;
  label: string;
  icon: ReactNode;
  description: string;
  shortcut?: string;
  badgeCount?: number;
}

const NAV_ITEMS: Array<NavItem & { id: ActivityView }> = [
  {
    id: "workflows",
    label: "Workflows",
    icon: <ComposeIcon />,
    description: "Build workers, logic, and reusable procedures.",
    shortcut: "⌘1",
  },
  {
    id: "runs",
    label: "Runs",
    icon: <FleetIcon />,
    description: "Supervise runtime health, evidence, and receipts.",
    shortcut: "⌘2",
  },
  {
    id: "inbox",
    label: "Inbox",
    icon: <NotificationsIcon />,
    description: "Review ranked prompts, approvals, and interventions.",
    shortcut: "⌘3",
  },
  {
    id: "capabilities",
    label: "Capabilities",
    icon: <IntegrationsIcon />,
    description: "Equip workers with connections, skills, and extensions.",
    shortcut: "⌘4",
  },
  {
    id: "policy",
    label: "Policy",
    icon: <ShieldIcon />,
    description: "Set governance, approvals, and execution posture.",
    shortcut: "⌘5",
  },
  {
    id: "settings",
    label: "Settings",
    icon: <SettingsIcon />,
    description: "Manage shell identity, diagnostics, and local system state.",
    shortcut: "⌘6",
  },
];

function utilityTabLabel(
  tab: ActivityBarProps["activeUtilityTab"],
): string {
  if (tab === "explorer") {
    return "Explorer";
  }
  if (tab === "artifacts") {
    return "Artifacts";
  }
  return "Operator";
}

function isEditableElement(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return (
    target.isContentEditable ||
    tag === "input" ||
    tag === "textarea" ||
    tag === "select"
  );
}

export function LocalActivityBar({
  activeView,
  onViewChange,
  notificationCount,
  ghostMode,
  onToggleGhost,
  utilityPaneOpen,
  activeUtilityTab,
  onToggleUtilityPane,
  workspaceName,
  currentProject,
  projects,
  onSelectProject,
}: ActivityBarProps) {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (isEditableElement(event.target)) return;
      if (!event.metaKey && !event.ctrlKey) return;

      const num = Number.parseInt(event.key, 10);
      if (num >= 1 && num <= NAV_ITEMS.length) {
        event.preventDefault();
        onViewChange(NAV_ITEMS[num - 1].id);
        return;
      }

      if (event.key === "0") {
        event.preventDefault();
        onToggleUtilityPane();
        return;
      }

      if (event.key.toLowerCase() === "g") {
        event.preventDefault();
        onToggleGhost();
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onToggleGhost, onToggleUtilityPane, onViewChange]);

  return (
    <aside
      className="studio-shell-nav"
      role="navigation"
      aria-label="Studio navigation"
    >
      <div className="studio-shell-brand">
        <span className="studio-shell-brand-mark">
          <AutopilotIcon />
        </span>
        <div className="studio-shell-brand-copy">
          <strong>Autopilot</strong>
          <span>{workspaceName}</span>
        </div>
      </div>

      <section className="studio-shell-scope-card" aria-label="Current scope">
        <div className="studio-shell-section-head">
          <span>Scope</span>
          <span>{currentProject.environment}</span>
        </div>
        <div className="studio-shell-scope-block">
          <span className="studio-shell-scope-label">Workspace</span>
          <div className="studio-shell-scope-chip">
            <strong>{workspaceName}</strong>
            <span>Organization boundary</span>
          </div>
        </div>
        <div className="studio-shell-scope-block">
          <span className="studio-shell-scope-label">Project</span>
          <div className="studio-shell-scope-chip studio-shell-scope-chip--project">
            <div className="studio-shell-scope-copy">
              <strong>{currentProject.name}</strong>
              <span>{currentProject.description}</span>
            </div>
            <span className="studio-shell-scope-badge">
              {currentProject.environment}
            </span>
          </div>
        </div>
      </section>

      <section className="studio-shell-section" aria-label="Projects">
        <div className="studio-shell-section-head">
          <span>Projects</span>
          <span>{projects.length}</span>
        </div>
        <div className="studio-shell-project-list">
          {projects.map((project) => (
            <button
              key={project.id}
              type="button"
              className={`studio-shell-project-button ${
                project.id === currentProject.id ? "is-active" : ""
              }`}
              onClick={() => onSelectProject(project.id)}
            >
              <strong>{project.name}</strong>
              <span>{project.description}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="studio-shell-section" aria-label="Surface navigation">
        <div className="studio-shell-section-head">
          <span>Surfaces</span>
          <span>Project</span>
        </div>
        <div className="studio-shell-nav-list">
          {NAV_ITEMS.map((item) => {
            const isCapabilitiesItem = item.id === "capabilities";
            const icon = isCapabilitiesItem ? (
              <IntegrationsIcon
                disableHoverAnimation={activeView === "capabilities"}
              />
            ) : (
              item.icon
            );
            const badgeCount =
              item.id === "inbox" ? notificationCount : item.badgeCount;

            return (
              <button
                key={item.id}
                type="button"
                className={`studio-shell-nav-button ${
                  activeView === item.id ? "is-active" : ""
                }`}
                onClick={() => onViewChange(item.id)}
                aria-current={activeView === item.id ? "page" : undefined}
              >
                <span className="studio-shell-nav-icon">{icon}</span>
                <span className="studio-shell-nav-copy">
                  <strong>{item.label}</strong>
                  <span>{item.description}</span>
                </span>
                {badgeCount && badgeCount > 0 ? (
                  <span className="studio-shell-nav-badge">
                    {badgeCount > 9 ? "9+" : badgeCount}
                  </span>
                ) : (
                  <span className="studio-shell-nav-shortcut">
                    {item.shortcut}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </section>

      <div className="studio-shell-spacer" />

      <section className="studio-shell-section" aria-label="Shell utilities">
        <div className="studio-shell-section-head">
          <span>Utilities</span>
          <span>{utilityPaneOpen ? "Open" : "Hidden"}</span>
        </div>
        <button
          type="button"
          className={`studio-shell-nav-button studio-shell-nav-button--utility ${
            utilityPaneOpen ? "is-active" : ""
          }`}
          onClick={onToggleUtilityPane}
        >
          <span className="studio-shell-nav-icon">
            <AutopilotIcon />
          </span>
          <span className="studio-shell-nav-copy">
            <strong>Utility pane</strong>
            <span>{utilityTabLabel(activeUtilityTab)}</span>
          </span>
          <span className="studio-shell-nav-shortcut">⌘0</span>
        </button>
        <button
          type="button"
          className={`studio-shell-nav-button studio-shell-nav-button--ghost ${
            ghostMode ? "is-active" : ""
          }`}
          onClick={onToggleGhost}
        >
          <span className="studio-shell-nav-icon">
            <GhostIcon />
          </span>
          <span className="studio-shell-nav-copy">
            <strong>Ghost mode</strong>
            <span>
              {ghostMode ? "Recording interaction context" : "Ready to record"}
            </span>
          </span>
          <span className="studio-shell-nav-shortcut">⌘G</span>
        </button>
      </section>
    </aside>
  );
}
