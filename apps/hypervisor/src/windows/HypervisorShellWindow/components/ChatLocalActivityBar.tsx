import { useEffect, useState, type ReactNode } from "react";
import {
  ChatLogoIcon,
  ComposeIcon,
  EnvironmentIcon,
  HomeIcon,
  IntegrationsIcon,
  MountsIcon,
  NotificationsIcon,
  ProjectsIcon,
  SearchIcon,
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

interface ReferenceRailButtonProps {
  label: string;
  dataWindowSurface: string;
  icon: ReactNode;
  isActive?: boolean;
  badgeCount?: number;
  shortcutKeys?: string[];
  title?: string;
  onClick: () => void;
}

const CHAT_ACTIVITY_BAR_COLLAPSED_KEY =
  "hypervisor.primaryRailCollapsed.v2";

const KEYBOARD_NAV_VIEWS: PrimaryView[] =
  [...HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS.leftNavSurfaceIds];

const NAV_ICON_BY_SURFACE: Record<string, ReactNode> = {
  home: <HomeIcon />,
  sessions: <SparklesIcon />,
  projects: <ProjectsIcon />,
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
      fill="currentColor"
      aria-hidden="true"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d={
          collapsed
            ? "M14.6667 2.66663H1.33334V13.3333H14.6667V2.66663ZM5.66667 3.66663V12.3333H2.33334V3.66663H5.66667Z"
            : "M14.6667 2.66663H1.33334V13.3333H14.6667V2.66663ZM13.6667 3.66663V12.3333H7.66667V3.66663H13.6667Z"
        }
      />
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

function ReferenceRailButton({
  label,
  dataWindowSurface,
  icon,
  isActive = false,
  badgeCount,
  shortcutKeys = [],
  title = label,
  onClick,
}: ReferenceRailButtonProps) {
  return (
    <button
      type="button"
      className={`chat-activity-button chat-activity-button--reference ${
        isActive ? "is-active" : ""
      }`}
      data-window-surface={dataWindowSurface}
      onClick={onClick}
      aria-current={isActive ? "page" : undefined}
      aria-label={label}
      title={title}
    >
      <span className="chat-activity-button-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="chat-activity-button-label">{label}</span>
      {shortcutKeys.length > 0 ? (
        <span className="chat-activity-button-shortcuts" aria-hidden="true">
          {shortcutKeys.map((key) => (
            <span key={key} className="chat-activity-button-shortcut">
              {key}
            </span>
          ))}
        </span>
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
  const railItemBySurface = (surfaceId: PrimaryView) =>
    primaryNavItems.find((item) => item.hypervisorSurfaceId === surfaceId);
  const homeNavItem = railItemBySurface("home");
  const sessionsNavItem = railItemBySurface("sessions");
  const projectsNavItem = railItemBySurface("projects");
  const automationsNavItem = railItemBySurface("automations");
  const insightsNavItem = railItemBySurface("insights");
  const searchItem = railModel.items.find(
    (item) => item.dataWindowSurface === "search",
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
        <button
          type="button"
          className="chat-activity-brand"
          aria-label="Open Hypervisor home"
          onClick={() => onViewChange("home")}
        >
          <span className="chat-activity-brand-tick" aria-hidden="true" />
          <ChatLogoIcon />
          <span className="chat-activity-brand-tick" aria-hidden="true" />
        </button>
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
        {homeNavItem ? (
          <ActivityButton
            key={homeNavItem.id}
            item={homeNavItem}
            isActive={isActiveRailItem(homeNavItem)}
            onClick={() => activateRoute(homeNavItem.route)}
          />
        ) : null}
        {searchItem ? (
          <ReferenceRailButton
            label="Search..."
            dataWindowSurface={searchItem.dataWindowSurface}
            icon={<SearchIcon />}
            shortcutKeys={["ctrl", "J"]}
            title={searchItem.description}
            onClick={() => activateRoute(searchItem.route)}
          />
        ) : null}
        {sessionsNavItem ? (
          <ActivityButton
            key="notifications"
            item={{
              ...sessionsNavItem,
              id: "surface.notifications",
              label: "Notifications",
              dataWindowSurface: "notifications",
              badgeCount: notificationCount,
            }}
            icon={<NotificationsIcon />}
            isActive={false}
            onClick={() => onViewChange("missions")}
          />
        ) : null}
        {insightsNavItem ? (
          <ActivityButton
            key="whats-new"
            item={{
              ...insightsNavItem,
              id: "surface.whats-new",
              label: "What's New",
              dataWindowSurface: "whats-new",
            }}
            icon={<NotificationsIcon />}
            isActive={isActiveRailItem(insightsNavItem)}
            onClick={() => activateRoute(insightsNavItem.route)}
          />
        ) : null}
      </div>

      <div className="chat-activity-group chat-activity-group--reference-main" aria-label="Work surfaces">
        {sessionsNavItem ? (
          <ActivityButton
            key={sessionsNavItem.id}
            item={{ ...sessionsNavItem, label: "Recent" }}
            icon={<EnvironmentIcon />}
            isActive={isActiveRailItem(sessionsNavItem)}
            onClick={() => activateRoute(sessionsNavItem.route)}
          />
        ) : null}
        {projectsNavItem ? (
          <ActivityButton
            key={projectsNavItem.id}
            item={{ ...projectsNavItem, label: "Files" }}
            icon={<WorkspaceIcon />}
            isActive={isActiveRailItem(projectsNavItem)}
            onClick={() => activateRoute(projectsNavItem.route)}
          />
        ) : null}
        {automationsNavItem ? (
          <ActivityButton
            key={automationsNavItem.id}
            item={automationsNavItem}
            icon={<ComposeIcon />}
            isActive={isActiveRailItem(automationsNavItem)}
            onClick={() => activateRoute(automationsNavItem.route)}
          />
        ) : null}
        <ReferenceRailButton
          label="Applications"
          dataWindowSurface="applications"
          icon={<ProjectsIcon />}
          title="Open the application portal"
          onClick={() => onViewChange("home")}
        />
      </div>

      <div className="chat-activity-apps" aria-label="Favorite applications">
        <div className="chat-activity-section-label">Applications</div>
        <p>Your favorite apps will appear here</p>
      </div>

      <div className="chat-activity-spacer" />

      <div className="chat-activity-group chat-activity-group--bottom">
        <ReferenceRailButton
          label="IOI Assist"
          dataWindowSurface="hypervisor-assist"
          icon={<SparklesIcon />}
          shortcutKeys={["ctrl", "shift", "U"]}
          title={HYPERVISOR_PRIMARY_ACTION.description}
          onClick={onOpenNewSession}
        />
        <ReferenceRailButton
          label="Support"
          dataWindowSurface="support"
          icon={<SettingsIcon />}
          title="Open support commands"
          onClick={onOpenCommandPalette}
        />
        <button
          type="button"
          className="chat-activity-button chat-activity-button--account"
          data-window-surface="account"
          onClick={() => {
            onViewChange("settings");
          }}
          aria-label={`${profileDisplayName} account`}
          title={`${profileDisplayName} · ${profileRoleLabel}`}
        >
          <span className="chat-activity-button-icon" aria-hidden="true">
            <span className="chat-activity-profile-avatar">{profileInitials}</span>
          </span>
          <span className="chat-activity-button-label">Account</span>
        </button>
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
