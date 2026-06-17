import { useEffect, useState, type ReactNode } from "react";
import {
  ChatLogoIcon,
  ComposeIcon,
  EnvironmentIcon,
  HomeIcon,
  IntegrationsIcon,
  MountsIcon,
  NotificationsIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  WorkspaceIcon,
} from "./ChatActivityBarIcons";
import type { PrimaryView } from "../hypervisorShellModel";
import {
  HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS,
  HYPERVISOR_PRIMARY_ACTION,
} from "../hypervisorShellNavigationModel";
import {
  buildOperatorActivityRailModel,
  getHypervisorSurfaceIdForPrimaryView,
  type OperatorActivityRailItem,
  type OperatorSurfaceRoute,
} from "../operatorSubstrateModel";
import type { AssistantUserProfile } from "../../../types";

interface ChatLocalActivityBarProps {
  activeView: PrimaryView;
  onViewChange: (view: PrimaryView) => void;
  onOpenNewSession: () => void;
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

const CHAT_ACTIVITY_BAR_COLLAPSED_KEY =
  "hypervisor.primaryRailCollapsed.v2";

const KEYBOARD_NAV_VIEWS: PrimaryView[] =
  [...HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS.leftNavSurfaceIds];

const REFERENCE_RECENT_SESSIONS = [
  {
    title: "Write Parent Harness Evidence Boundary Doc",
    meta: "main · 6h ago",
    status: "active",
    count: 3,
  },
  {
    title: "Write Harness Tool Call Documentation",
    meta: "main · 6h ago",
    status: "idle",
    count: 4,
  },
  {
    title: "Design Postquantum Computers Website",
    meta: "main · 6h ago",
    status: "idle",
    count: 5,
  },
] as const;

const NAV_ICON_BY_SURFACE: Record<string, ReactNode> = {
  home: <HomeIcon />,
  sessions: <SparklesIcon />,
  projects: <WorkspaceIcon />,
  missions: <NotificationsIcon />,
  workbench: <WorkspaceIcon />,
  automations: <ComposeIcon />,
  insights: <EnvironmentIcon />,
  agents: <IntegrationsIcon />,
  models: <MountsIcon />,
  privacy: <ShieldIcon />,
  providers: <EnvironmentIcon />,
  environments: <EnvironmentIcon />,
  foundry: <ComposeIcon />,
  authority: <ShieldIcon />,
  receipts: <NotificationsIcon />,
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
      className={`chat-activity-button ${isActive ? "is-active" : ""} ${
        item.routeState === "planned_surface" ? "is-planned" : ""
      }`}
      data-window-surface={item.dataWindowSurface}
      data-route-state={item.routeState}
      onClick={onClick}
      aria-current={isActive ? "page" : undefined}
      aria-label={item.label}
      title={
        item.routeState === "planned_surface"
          ? `${item.label}: ${item.description}`
          : item.label
      }
    >
      <span
        className={`chat-activity-button-icon ${
          item.dataWindowSurface === "agents" ? "is-capabilities" : ""
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
  onOpenNewSession,
  onOpenCommandPalette,
  notificationCount,
  profile,
}: ChatLocalActivityBarProps) {
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    const stored = window.localStorage.getItem(CHAT_ACTIVITY_BAR_COLLAPSED_KEY);
    return stored === "true";
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
  const referenceLeftNavSurfaceIds =
    HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS.leftNavSurfaceIds;
  const primaryNavItems = referenceLeftNavSurfaceIds.flatMap((surfaceId) => {
    const item = railModel.items.find(
      (candidate) => candidate.hypervisorSurfaceId === surfaceId,
    );
    return item ? [item] : [];
  });
  const topReferenceNavItems = primaryNavItems.filter(
    (item) => item.hypervisorSurfaceId !== "sessions",
  );
  const sessionsNavItem = primaryNavItems.find(
    (item) => item.hypervisorSurfaceId === "sessions",
  );
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
  const activeHypervisorSurfaceId = getHypervisorSurfaceIdForPrimaryView(activeView);
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
    item.routeState === "active_route" &&
    item.hypervisorSurfaceId === activeHypervisorSurfaceId;

  return (
    <aside
      className={`chat-activity-bar ${collapsed ? "is-collapsed" : ""}`}
      role="navigation"
      aria-label="Hypervisor navigation"
      data-collapsed={collapsed ? "true" : "false"}
      data-inspection-target="operator-activity-rail"
      data-operator-activity-rail={railModel.projectionId}
      data-ioi-reference-primary-rail="true"
      data-left-nav-surfaces={referenceLeftNavSurfaceIds.join(" ")}
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
        <button
          type="button"
          className="chat-activity-button chat-activity-button--new-session"
          data-window-surface="new-session"
          onClick={onOpenNewSession}
          aria-label={HYPERVISOR_PRIMARY_ACTION.label}
          title={HYPERVISOR_PRIMARY_ACTION.description}
        >
          <span
            className="chat-activity-button-icon chat-activity-button-icon--plus"
            aria-hidden="true"
          >
            +
          </span>
          <span className="chat-activity-button-label">
            {HYPERVISOR_PRIMARY_ACTION.label}
          </span>
          <span className="chat-activity-button-shortcuts" aria-hidden="true">
            <span className="chat-activity-button-shortcut">Ctrl</span>
            <span className="chat-activity-button-shortcut">O</span>
          </span>
        </button>

        {topReferenceNavItems.map((item) => (
          <ActivityButton
            key={item.id}
            item={item}
            isActive={isActiveRailItem(item)}
            onClick={() => activateRoute(item.route)}
          />
        ))}
      </div>

      <div className="chat-activity-group chat-activity-group--sessions" aria-label="Sessions">
        {sessionsNavItem ? (
          <ActivityButton
            key={sessionsNavItem.id}
            item={sessionsNavItem}
            isActive={isActiveRailItem(sessionsNavItem)}
            onClick={() => activateRoute(sessionsNavItem.route)}
          />
        ) : null}
        <div className="chat-activity-project-label">
          <span>From scratch</span>
          <span>Project</span>
        </div>
        <div
          className="chat-activity-session-list"
          aria-label="Recent session preview"
          data-ioi-reference-session-list="true"
        >
          {REFERENCE_RECENT_SESSIONS.map((session) => (
            <button
              type="button"
              key={session.title}
              className="chat-activity-session-row"
              data-session-status={session.status}
              title={session.title}
              onClick={() => onViewChange("sessions")}
            >
              <span className="chat-activity-session-row__dot" aria-hidden="true" />
              <span className="chat-activity-session-row__copy">
                <strong>{session.title}</strong>
                <em>{session.meta}</em>
              </span>
              <span
                className="chat-activity-session-row__badge"
                aria-label={`${session.count} pending items`}
              >
                {session.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="chat-activity-spacer" />

      <div className="chat-activity-group chat-activity-group--bottom">
        <button
          type="button"
          className="chat-activity-button chat-activity-button--organization"
          data-window-surface="organization-settings"
          onClick={() => {
            const settingsItem = bottomNavItems.find(
              (item) => item.dataWindowSurface === "settings",
            );
            if (settingsItem) {
              activateRoute(settingsItem.route);
            }
          }}
          aria-label="Organization settings"
          title="Organization settings"
        >
          <span className="chat-activity-button-icon" aria-hidden="true">
            <SettingsIcon />
          </span>
          <span className="chat-activity-button-label">Organization settings</span>
        </button>
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
	              <strong>IOI Workspace</strong>
	              <em>{profileDisplayName}</em>
	            </span>
	          </button>
        ) : null}
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
