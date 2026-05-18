import { useEffect, useState, type ReactNode } from "react";
import {
  ChatLogoIcon,
  ComposeIcon,
  FleetIcon,
  HomeIcon,
  IntegrationsIcon,
  MountsIcon,
  NotificationsIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  WorkspaceIcon,
} from "./ChatActivityBarIcons";
import type { PrimaryView } from "../autopilotShellModel";
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
  id: PrimaryView;
  label: string;
  icon: ReactNode;
  description: string;
  shortcut?: string;
  badgeCount?: number;
}

interface ActivityButtonProps {
  item: NavItem;
  icon?: ReactNode;
  badgeCount?: number;
  isActive: boolean;
  onClick: () => void;
}

const CHAT_ACTIVITY_BAR_COLLAPSED_KEY =
  "autopilot.chatActivityBarCollapsed";

const NAV_ITEMS: NavItem[] = [
  {
    id: "chat",
    label: "Chat",
    icon: <SparklesIcon />,
    description:
      "Control query outcomes, open artifact tabs, and only drop into renderer-specific lenses when the work requires it.",
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
    id: "workflows",
    label: "Workflows",
    icon: <ComposeIcon />,
    description:
      "Open the workflow composer for graph editing, tests, proposals, and git-backed agent automation.",
    shortcut: chatNavigationShortcutLabel(3),
  },
  {
    id: "runs",
    label: "Runs",
    icon: <FleetIcon />,
    description: "Inspect runtime health, supervised run history, and operator actions.",
    shortcut: chatNavigationShortcutLabel(4),
  },
  {
    id: "mounts",
    label: "Model Mounts",
    icon: <MountsIcon />,
    description: "Open the model mounting surface.",
    shortcut: chatNavigationShortcutLabel(5),
  },
  {
    id: "inbox",
    label: "Inbox",
    icon: <NotificationsIcon />,
    description: "Review ranked prompts, approvals, and interventions.",
    shortcut: chatNavigationShortcutLabel(6),
  },
  {
    id: "capabilities",
    label: "Capabilities",
    icon: <IntegrationsIcon />,
    description: "Equip workers with connections, skills, and extension manifests.",
    shortcut: chatNavigationShortcutLabel(7),
  },
  {
    id: "policy",
    label: "Policy",
    icon: <ShieldIcon />,
    description: "Set governance, approvals, and execution posture.",
    shortcut: chatNavigationShortcutLabel(8),
  },
  {
    id: "settings",
    label: "Settings",
    icon: <SettingsIcon />,
    description: "Manage shell identity, diagnostics, and local system state.",
    shortcut: chatNavigationShortcutLabel(9),
  },
];

const HOME_NAV_ITEM: NavItem = {
  id: "home",
  label: "Home",
  icon: <HomeIcon />,
  description: "Open onboarding, recent project scope, runtime health, and next actions.",
};

const PRIMARY_NAV_IDS = new Set<PrimaryView>(["chat", "inbox"]);
const WORK_NAV_IDS = new Set<PrimaryView>([
  "workspace",
  "workflows",
  "runs",
  "mounts",
  "capabilities",
  "policy",
]);

function CollapseIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {collapsed ? (
        <>
          <path d="M6 4h7" />
          <path d="M6 8h7" />
          <path d="M6 12h7" />
          <path d="m2.5 5.5 2.5 2.5-2.5 2.5" />
        </>
      ) : (
        <>
          <path d="M5 4h8" />
          <path d="M5 8h8" />
          <path d="M5 12h8" />
          <path d="m3.5 5.5-2.5 2.5 2.5 2.5" />
        </>
      )}
    </svg>
  );
}

function ActivityButton({
  item,
  icon = item.icon,
  badgeCount,
  isActive,
  onClick,
}: ActivityButtonProps) {
  return (
    <button
      type="button"
      className={`chat-activity-button ${isActive ? "is-active" : ""}`}
      data-window-surface={item.id}
      onClick={onClick}
      aria-current={isActive ? "page" : undefined}
      aria-label={item.label}
      title={`${item.label}${item.shortcut ? ` (${item.shortcut})` : ""}`}
    >
      <span
        className={`chat-activity-button-icon ${
          item.id === "capabilities" ? "is-capabilities" : ""
        }`}
        aria-hidden="true"
      >
        {icon}
      </span>
      <span className="chat-activity-button-label">{item.label}</span>
      {item.shortcut ? (
        <span className="chat-activity-button-shortcut">{item.shortcut}</span>
      ) : null}
      {badgeCount && badgeCount > 0 ? (
        <span className="chat-activity-button-badge" aria-label={`${badgeCount} pending`}>
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
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    const stored = window.localStorage.getItem(CHAT_ACTIVITY_BAR_COLLAPSED_KEY);
    return stored === null ? true : stored === "true";
  });

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

  useEffect(() => {
    window.localStorage.setItem(
      CHAT_ACTIVITY_BAR_COLLAPSED_KEY,
      collapsed ? "true" : "false",
    );
  }, [collapsed]);

  const primaryNavItems = NAV_ITEMS.filter((item) =>
    PRIMARY_NAV_IDS.has(item.id),
  );
  const workNavItems = NAV_ITEMS.filter((item) => WORK_NAV_IDS.has(item.id));
  const bottomNavItems = NAV_ITEMS.filter((item) => item.id === "settings");
  const projectInitials = currentProject.name
    .split(/\s+/)
    .map((segment) => segment[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <aside
      className={`chat-activity-bar ${collapsed ? "is-collapsed" : ""}`}
      role="navigation"
      aria-label="Autopilot navigation"
      data-collapsed={collapsed ? "true" : "false"}
    >
      <div className="chat-activity-brand-row">
        <span className="chat-activity-brand" aria-hidden="true">
          <ChatLogoIcon />
        </span>
        <button
          type="button"
          className="chat-activity-collapse-button"
          aria-label={collapsed ? "Expand activity bar" : "Collapse activity bar"}
          aria-pressed={collapsed}
          title={collapsed ? "Expand activity bar" : "Collapse activity bar"}
          onClick={() => setCollapsed((value) => !value)}
        >
          <CollapseIcon collapsed={collapsed} />
        </button>
      </div>

      <div className="chat-activity-group" aria-label="Primary surfaces">
        <ActivityButton
          item={HOME_NAV_ITEM}
          isActive={activeView === "home"}
          onClick={() => onViewChange("home")}
        />

        {primaryNavItems.map((item) => (
          <ActivityButton
            key={item.id}
            item={item}
            badgeCount={item.id === "inbox" ? notificationCount : item.badgeCount}
            isActive={activeView === item.id}
            onClick={() => onViewChange(item.id)}
          />
        ))}
      </div>

      <div className="chat-activity-group" aria-label="Work surfaces">
        {workNavItems.map((item) => {
          const icon =
            item.id === "capabilities" ? (
              <IntegrationsIcon
                disableHoverAnimation={activeView === "capabilities"}
              />
            ) : (
              item.icon
            );

          return (
            <ActivityButton
              key={item.id}
              item={item}
              icon={icon}
              isActive={activeView === item.id}
              onClick={() => onViewChange(item.id)}
            />
          );
        })}
      </div>

      <div className="chat-activity-apps">
        <div className="chat-activity-section-label">Applications</div>
        <p>Your favorite Autopilot surfaces will appear here</p>
      </div>

      <div className="chat-activity-spacer" />

      <div className="chat-activity-group chat-activity-group--bottom">
        <div
          className="chat-activity-project-indicator"
          title={`${currentProject.name} · ${currentProject.environment}`}
          aria-label={`${currentProject.name} project scope`}
          data-window-surface="project"
        >
          <span className="chat-activity-project-avatar">{projectInitials}</span>
          <span className="chat-activity-project-label">
            {currentProject.name}
          </span>
        </div>

        {bottomNavItems.map((item) => (
          <ActivityButton
            key={item.id}
            item={item}
            isActive={activeView === item.id}
            onClick={() => onViewChange(item.id)}
          />
        ))}
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
