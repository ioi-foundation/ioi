import { useEffect, type ReactNode } from "react";
import {
  ComposeIcon,
  FleetIcon,
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
  currentProject: ProjectScope;
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
  currentProject,
}: ActivityBarProps) {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (isEditableElement(event.target)) return;
      if (!event.metaKey && !event.ctrlKey) return;

      const num = Number.parseInt(event.key, 10);
      if (num >= 1 && num <= NAV_ITEMS.length) {
        event.preventDefault();
        onViewChange(NAV_ITEMS[num - 1].id);
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onViewChange]);

  const topNavItems = NAV_ITEMS.filter((item) => item.id !== "settings");
  const bottomNavItems = NAV_ITEMS.filter((item) => item.id === "settings");
  const projectInitials = currentProject.name
    .split(/\s+/)
    .map((segment) => segment[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <aside
      className="studio-activity-bar"
      role="navigation"
      aria-label="Studio navigation"
    >
      <div className="studio-activity-group" aria-label="Surface navigation">
        {topNavItems.map((item) => {
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
              className={`studio-activity-button ${
                activeView === item.id ? "is-active" : ""
              }`}
              onClick={() => onViewChange(item.id)}
              aria-current={activeView === item.id ? "page" : undefined}
              aria-label={item.label}
              title={`${item.label} ${item.shortcut ? `(${item.shortcut})` : ""}`}
            >
              <span className="studio-activity-button-icon">{icon}</span>
              {badgeCount && badgeCount > 0 ? (
                <span className="studio-activity-button-badge">
                  {badgeCount > 9 ? "9+" : badgeCount}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div className="studio-activity-spacer" />

      <div className="studio-activity-group studio-activity-group--bottom">
        <div
          className="studio-activity-project-indicator"
          title={`${currentProject.name} · ${currentProject.environment}`}
          aria-label={`${currentProject.name} project scope`}
        >
          <span>{projectInitials}</span>
        </div>

        {bottomNavItems.map((item) => {
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
              className={`studio-activity-button ${
                activeView === item.id ? "is-active" : ""
              }`}
              onClick={() => onViewChange(item.id)}
              aria-current={activeView === item.id ? "page" : undefined}
              aria-label={item.label}
              title={`${item.label} ${item.shortcut ? `(${item.shortcut})` : ""}`}
            >
              <span className="studio-activity-button-icon">{icon}</span>
              {badgeCount && badgeCount > 0 ? (
                <span className="studio-activity-button-badge">
                  {badgeCount > 9 ? "9+" : badgeCount}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>
    </aside>
  );
}
