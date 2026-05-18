import { useEffect, useState, type ReactNode } from "react";
import {
  ChatLogoIcon,
  ComposeIcon,
  FleetIcon,
  HomeIcon,
  IntegrationsIcon,
  MountsIcon,
  NotificationsIcon,
  SearchIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  WorkspaceIcon,
} from "./ChatActivityBarIcons";
import type { PrimaryView } from "../autopilotShellModel";
import {
  buildOperatorActivityRailModel,
  type OperatorActivityRailItem,
  type OperatorSurfaceRoute,
} from "../operatorSubstrateModel";
import { chatCommandPaletteShortcutLabel } from "../../shared/shellShortcuts";
import type { AssistantUserProfile } from "../../../types";

interface ChatLocalActivityBarProps {
  activeView: PrimaryView;
  onViewChange: (view: PrimaryView) => void;
  onOpenCommandPalette: () => void;
  notificationCount: number;
  profile: AssistantUserProfile;
}

interface ActivityButtonProps {
  item: OperatorActivityRailItem;
  icon?: ReactNode;
  isActive: boolean;
  onClick: () => void;
}

interface SearchButtonProps {
  onClick: () => void;
}

const CHAT_ACTIVITY_BAR_COLLAPSED_KEY =
  "autopilot.chatActivityBarCollapsed";

const KEYBOARD_NAV_VIEWS: PrimaryView[] = [
  "chat",
  "workspace",
  "workflows",
  "runs",
  "mounts",
  "inbox",
  "capabilities",
  "policy",
  "settings",
];

const NAV_ICON_BY_SURFACE: Record<string, ReactNode> = {
  home: <HomeIcon />,
  chat: <SparklesIcon />,
  workspace: <WorkspaceIcon />,
  workflows: <ComposeIcon />,
  runs: <FleetIcon />,
  mounts: <MountsIcon />,
  inbox: <NotificationsIcon />,
  capabilities: <IntegrationsIcon />,
  policy: <ShieldIcon />,
  settings: <SettingsIcon />,
};

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
          <path d="M7 4h6" />
          <path d="M7 8h6" />
          <path d="M7 12h6" />
          <path d="m2.5 5.5 2.5 2.5-2.5 2.5" />
        </>
      ) : (
        <>
          <path d="M6 4h7" />
          <path d="M6 8h7" />
          <path d="M6 12h7" />
          <path d="m3.5 5.5-2.5 2.5 2.5 2.5" />
        </>
      )}
    </svg>
  );
}

function ActivityButton({
  item,
  icon = NAV_ICON_BY_SURFACE[item.dataWindowSurface],
  isActive,
  onClick,
}: ActivityButtonProps) {
  return (
    <button
      type="button"
      className={`chat-activity-button ${isActive ? "is-active" : ""}`}
      data-window-surface={item.dataWindowSurface}
      onClick={onClick}
      aria-current={isActive ? "page" : undefined}
      aria-label={item.label}
      title={item.label}
    >
      <span
        className={`chat-activity-button-icon ${
          item.dataWindowSurface === "capabilities" ? "is-capabilities" : ""
        }`}
        aria-hidden="true"
      >
        {icon}
      </span>
      <span className="chat-activity-button-label">{item.label}</span>
      {item.badgeCount && item.badgeCount > 0 ? (
        <span className="chat-activity-button-badge" aria-label={`${item.badgeCount} pending`}>
          {item.badgeCount > 9 ? "9+" : item.badgeCount}
        </span>
      ) : null}
    </button>
  );
}

function SearchButton({ onClick }: SearchButtonProps) {
  const shortcut = chatCommandPaletteShortcutLabel();

  return (
    <button
      type="button"
      className="chat-activity-button"
      data-window-surface="search"
      onClick={onClick}
      aria-label="Search"
      title={`Search (${shortcut})`}
    >
      <span className="chat-activity-button-icon" aria-hidden="true">
        <SearchIcon />
      </span>
      <span className="chat-activity-button-label">Search</span>
      <span className="chat-activity-button-shortcut">{shortcut}</span>
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

function isPrimaryViewRoute(
  route: OperatorSurfaceRoute,
): route is { kind: "primary-view"; view: PrimaryView } {
  return route.kind === "primary-view";
}

function resolveProfileDisplayName(profile: AssistantUserProfile): string {
  return (
    profile.displayName?.trim() ||
    profile.preferredName?.trim() ||
    profile.roleLabel?.trim() ||
    "Operator"
  );
}

function resolveProfileInitials(profile: AssistantUserProfile): string {
  const displayName = resolveProfileDisplayName(profile);
  const initials = displayName
    .split(/\s+/)
    .map((segment) => segment[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return initials || profile.avatarSeed?.trim().slice(0, 2).toUpperCase() || "OP";
}

export function ChatLocalActivityBar({
  activeView,
  onViewChange,
  onOpenCommandPalette,
  notificationCount,
  profile,
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
      if (num >= 1 && num <= KEYBOARD_NAV_VIEWS.length) {
        event.preventDefault();
        onViewChange(KEYBOARD_NAV_VIEWS[num - 1]);
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

  const railModel = buildOperatorActivityRailModel({
    activeView,
    collapsed,
    notificationCount,
  });
  const searchItem = railModel.items.find(
    (item) => item.dataWindowSurface === "search",
  );
  const primaryNavItems = railModel.items.filter(
    (item) => item.group === "primary",
  );
  const workNavItems = railModel.items.filter((item) => item.group === "work");
  const profileItem = railModel.items.find(
    (item) => item.dataWindowSurface === "profile",
  );
  const bottomNavItems = railModel.items.filter(
    (item) =>
      item.group === "bottom" && item.dataWindowSurface !== "profile",
  );
  const profileDisplayName = resolveProfileDisplayName(profile);
  const profileInitials = resolveProfileInitials(profile);
  const profileRoleLabel = profile.roleLabel?.trim() || "Profile";
  const activateRoute = (route: OperatorSurfaceRoute) => {
    if (isPrimaryViewRoute(route)) {
      onViewChange(route.view);
      return;
    }

    if (route.kind === "command-palette") {
      onOpenCommandPalette();
    }
  };
  const isActiveRailItem = (item: OperatorActivityRailItem) =>
    isPrimaryViewRoute(item.route) && item.route.view === activeView;

  return (
    <aside
      className={`chat-activity-bar ${collapsed ? "is-collapsed" : ""}`}
      role="navigation"
      aria-label="Autopilot navigation"
      data-collapsed={collapsed ? "true" : "false"}
      data-inspection-target="operator-activity-rail"
      data-operator-activity-rail={railModel.projectionId}
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
        {searchItem ? <SearchButton onClick={() => activateRoute(searchItem.route)} /> : null}

        {primaryNavItems.map((item) => (
          <ActivityButton
            key={item.id}
            item={item}
            isActive={isActiveRailItem(item)}
            onClick={() => activateRoute(item.route)}
          />
        ))}
      </div>

      <div className="chat-activity-group" aria-label="Work surfaces">
        {workNavItems.map((item) => {
          const icon =
            item.dataWindowSurface === "capabilities" ? (
              <IntegrationsIcon
                disableHoverAnimation={activeView === "capabilities"}
              />
            ) : (
              NAV_ICON_BY_SURFACE[item.dataWindowSurface]
            );

          return (
            <ActivityButton
              key={item.id}
              item={item}
              icon={icon}
              isActive={isActiveRailItem(item)}
              onClick={() => activateRoute(item.route)}
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
        {profileItem ? (
          <button
            type="button"
            className="chat-activity-profile-indicator"
            title={`${profileDisplayName} · ${profileRoleLabel}`}
            aria-label={`${profileDisplayName} profile`}
            data-window-surface={profileItem.dataWindowSurface}
            onClick={() => activateRoute(profileItem.route)}
          >
            <span className="chat-activity-profile-avatar">{profileInitials}</span>
            <span className="chat-activity-profile-label">
              {profileDisplayName}
            </span>
          </button>
        ) : null}

        {bottomNavItems.map((item) => (
          <ActivityButton
            key={item.id}
            item={item}
            isActive={isActiveRailItem(item)}
            onClick={() => activateRoute(item.route)}
          />
        ))}
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
