import { useEffect, useState, type ReactNode } from "react";
import {
  FleetIcon,
  IntegrationsIcon,
  NotificationsIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  WorkspaceIcon,
} from "./ChatActivityBarIcons";
import type { PrimaryView } from "../chatWindowModel";
import { chatNavigationShortcutLabel } from "../../shared/shellShortcuts";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
}

interface ChatLocalActivityBarProps {
  activeView: PrimaryView;
  onViewChange: (view: PrimaryView) => void;
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

interface ActivityButtonProps {
  item: NavItem;
  icon: ReactNode;
  badgeCount?: number;
  isActive: boolean;
  onClick: () => void;
}

const NAV_ITEMS: Array<NavItem & { id: PrimaryView }> = [
  {
    id: "chat",
    label: "Chat",
    icon: <SparklesIcon />,
    description: "Control query outcomes, open artifact tabs, and only drop into renderer-specific lenses when the work requires it.",
    shortcut: chatNavigationShortcutLabel(1),
  },
  {
    id: "workspace",
    label: "Workspace",
    icon: <WorkspaceIcon />,
    description:
      "Open the workspace surface for terminal-style actions, artifact follow-through, and project-aware operations.",
    shortcut: chatNavigationShortcutLabel(2),
  },
  {
    id: "runs",
    label: "Runs",
    icon: <FleetIcon />,
    description: "Inspect runtime health, verification evidence, and supervised receipts.",
    shortcut: chatNavigationShortcutLabel(3),
  },
  {
    id: "inbox",
    label: "Inbox",
    icon: <NotificationsIcon />,
    description: "Review ranked prompts, approvals, and interventions.",
    shortcut: chatNavigationShortcutLabel(4),
  },
  {
    id: "capabilities",
    label: "Capabilities",
    icon: <IntegrationsIcon />,
    description: "Equip workers with connections, skills, and extension manifests.",
    shortcut: chatNavigationShortcutLabel(5),
  },
  {
    id: "policy",
    label: "Policy",
    icon: <ShieldIcon />,
    description: "Set governance, approvals, and execution posture.",
    shortcut: chatNavigationShortcutLabel(6),
  },
  {
    id: "settings",
    label: "Settings",
    icon: <SettingsIcon />,
    description: "Manage shell identity, diagnostics, and local system state.",
    shortcut: chatNavigationShortcutLabel(7),
  },
];

function ActivityButton({
  item,
  icon,
  badgeCount,
  isActive,
  onClick,
}: ActivityButtonProps) {
  const [hovered, setHovered] = useState(false);

  return (
    <button
      type="button"
      className={`chat-activity-button ${isActive ? "is-active" : ""}`}
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      aria-current={isActive ? "page" : undefined}
      aria-label={item.label}
      title={`${item.label} ${item.shortcut ? `(${item.shortcut})` : ""}`}
    >
      <span
        aria-hidden="true"
        className="chat-activity-button-indicator"
        style={{
          height: isActive ? 20 : hovered ? 8 : 0,
          transform: `translateY(-50%) translateX(${isActive || hovered ? "0px" : "-4px"})`,
          opacity: isActive || hovered ? 1 : 0,
        }}
      />
      <span
        className={`chat-activity-button-icon ${
          item.id === "capabilities" ? "is-capabilities" : ""
        }`}
      >
        {icon}
      </span>
      {badgeCount && badgeCount > 0 ? (
        <span className="chat-activity-button-badge">
          {badgeCount > 9 ? "9+" : badgeCount}
        </span>
      ) : null}
    </button>
  );
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

export function ChatLocalActivityBar({
  activeView,
  onViewChange,
  notificationCount,
  currentProject,
}: ChatLocalActivityBarProps) {
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
      className="chat-activity-bar"
      role="navigation"
      aria-label="Chat navigation"
    >
      <div className="chat-activity-group" aria-label="Surface navigation">
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
            <ActivityButton
              key={item.id}
              item={item}
              icon={icon}
              badgeCount={badgeCount}
              isActive={activeView === item.id}
              onClick={() => onViewChange(item.id)}
            />
          );
        })}
      </div>

      <div className="chat-activity-spacer" />

      <div className="chat-activity-group chat-activity-group--bottom">
        <div
          className="chat-activity-project-indicator"
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
            <ActivityButton
              key={item.id}
              item={item}
              icon={icon}
              badgeCount={badgeCount}
              isActive={activeView === item.id}
              onClick={() => onViewChange(item.id)}
            />
          );
        })}
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
