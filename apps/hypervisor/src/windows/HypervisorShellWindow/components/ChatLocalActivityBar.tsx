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
  SessionReferenceIcon,
  SessionsFilterIcon,
  SettingsIcon,
  ShieldIcon,
  SparklesIcon,
  WorkspaceIcon,
} from "./ChatActivityBarIcons";
import type { PrimaryView } from "../hypervisorShellModel";
import { WORKSPACE_NAME } from "../hypervisorShellModel";
import {
  HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS,
  HYPERVISOR_PRIMARY_ACTION,
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  type HypervisorLaunchedSessionProjection,
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
  launchedSessions: readonly HypervisorLaunchedSessionProjection[];
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
  shortcutVariant?: "key" | "label";
  trailingIcon?: ReactNode;
  title?: string;
  onClick: () => void;
}

const CHAT_ACTIVITY_BAR_COLLAPSED_KEY =
  "hypervisor.primaryRailCollapsed.v2";
const GENERIC_HOME_NEW_SESSION_INTENT =
  "Open a governed Hypervisor session for this workspace.";

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
      data-hypervisor-quick-switcher-anchor={
        item.dataWindowSurface === "search" ? "true" : undefined
      }
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
  shortcutVariant = "key",
  trailingIcon,
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
      {shortcutKeys.length > 0 || trailingIcon ? (
        <span className="chat-activity-button-trailing" aria-hidden="true">
          {shortcutKeys.length > 0 ? (
            <span
              className={`chat-activity-button-shortcuts chat-activity-button-shortcuts--${shortcutVariant}`}
            >
              {shortcutKeys.map((key) => (
                <span
                  key={key}
                  className={`chat-activity-button-shortcut chat-activity-button-shortcut--${shortcutVariant}`}
                >
                  {key}
                </span>
              ))}
            </span>
          ) : null}
          {trailingIcon ? (
            <span className="chat-activity-button-trailing-icon">
              {trailingIcon}
            </span>
          ) : null}
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

function launchedSessionRailTitle(
  session: HypervisorLaunchedSessionProjection,
): string {
  const seedIntent = session.launch_summary.seed_intent?.trim();
  if (seedIntent && seedIntent !== GENERIC_HOME_NEW_SESSION_INTENT) {
    return seedIntent;
  }
  const recipe = HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
    (candidate) => candidate.recipe_id === session.recipe_ref,
  );
  if (recipe) {
    const projectLabel = session.project_label.trim() || "current project";
    return `${recipe.label} for ${projectLabel}`;
  }
  return (
    session.project_label.trim() ||
    "Hypervisor session"
  );
}

function launchedSessionRailMeta(
  session: HypervisorLaunchedSessionProjection,
): string {
  const branchLabel = session.branch_label?.trim() || "main";
  const relativeTimeLabel = session.relative_time_label?.trim();
  if (relativeTimeLabel) {
    return `${branchLabel} · ${relativeTimeLabel}`;
  }
  const recipeKind = session.recipe_kind.replace(/_/g, " ");
  const state =
    session.admission_state === "daemon_admitted"
      ? "admitted"
      : session.admission_state === "pending_daemon_admission"
        ? "pending"
        : session.admission_state === "daemon_unavailable"
          ? "daemon unavailable"
          : "blocked";

  return `${recipeKind} · ${state}`;
}

function launchedSessionRailBadge(
  session: HypervisorLaunchedSessionProjection,
): string {
  if (
    typeof session.activity_count === "number" &&
    Number.isFinite(session.activity_count) &&
    session.activity_count > 0
  ) {
    return String(Math.min(session.activity_count, 99));
  }
  switch (session.admission_state) {
    case "daemon_admitted":
      return "✓";
    case "daemon_blocked":
      return "!";
    case "daemon_unavailable":
      return "?";
    case "pending_daemon_admission":
      return "...";
  }
}

export function ChatLocalActivityBar({
  activeView,
  onViewChange,
  onOpenNewSession,
  onOpenCommandPalette,
  notificationCount,
  profile,
  launchedSessions,
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
  const sessionsNavItem = railItemBySurface("sessions");
  const topNavItems = primaryNavItems.filter(
    (item) => item.hypervisorSurfaceId !== "sessions",
  );
  const profileDisplayName = resolveProfileDisplayName(profile);
  const profileInitials = resolveProfileInitials(profile);
  const profileRoleLabel = profile.roleLabel?.trim() || "Profile";
  const workspaceLabel = WORKSPACE_NAME;
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
        <button
          type="button"
          className="chat-activity-button chat-activity-button--new-session"
          data-window-surface="new-session"
          onClick={onOpenNewSession}
          aria-label="New Session"
          title={HYPERVISOR_PRIMARY_ACTION.description}
        >
          <span
            className="chat-activity-button-icon chat-activity-button-icon--plus"
            aria-hidden="true"
          >
            +
          </span>
          <span className="chat-activity-button-label">New Session</span>
          <span className="chat-activity-button-shortcuts" aria-hidden="true">
            <span className="chat-activity-button-shortcut">Ctrl</span>
            <span className="chat-activity-button-shortcut">O</span>
          </span>
        </button>
        {topNavItems.map((item) => (
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
          <ReferenceRailButton
            label="Sessions"
            dataWindowSurface="sessions"
            icon={<SessionReferenceIcon />}
            shortcutKeys={["Project"]}
            shortcutVariant="label"
            trailingIcon={<SessionsFilterIcon />}
            isActive={isActiveRailItem(sessionsNavItem)}
            title={sessionsNavItem.description}
            onClick={() => activateRoute(sessionsNavItem.route)}
          />
        ) : null}
      </div>

      {launchedSessions.length > 0 ? (
        <div className="chat-activity-projects" aria-label="Session shortcuts">
          <div className="chat-activity-project-label">
            <span aria-hidden="true">⌄</span>
            <span>From scratch</span>
          </div>
          <div
            className="chat-activity-session-list"
            data-ioi-reference-session-list="from-launched-sessions"
          >
            {launchedSessions.slice(0, 3).map((session) => (
              <button
                type="button"
                key={session.session_ref}
                className="chat-activity-session-row"
                data-session-status={
                  session.admission_state === "daemon_admitted" ? "active" : "idle"
                }
                data-launched-session-ref={session.session_ref}
                data-launched-session-admission={session.admission_state}
                title={launchedSessionRailTitle(session)}
                onClick={() => onViewChange("sessions")}
              >
                <span className="chat-activity-session-row__dot" aria-hidden="true" />
                <span className="chat-activity-session-row__copy">
                  <strong>{launchedSessionRailTitle(session)}</strong>
                  <em>{launchedSessionRailMeta(session)}</em>
                </span>
                <span className="chat-activity-session-row__badge">
                  {launchedSessionRailBadge(session)}
                </span>
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div className="chat-activity-spacer" />

      <div className="chat-activity-group chat-activity-group--bottom">
        <ReferenceRailButton
          label="Organization settings"
          dataWindowSurface="organization-settings"
          icon={<SettingsIcon />}
          title="Open organization settings"
          onClick={() => onViewChange("settings")}
        />
        <button
          type="button"
          className="chat-activity-profile-indicator"
          data-window-surface="account"
          onClick={() => {
            onViewChange("settings");
          }}
          aria-label={`${workspaceLabel} account for ${profileDisplayName}`}
          title={`${workspaceLabel} · ${profileDisplayName} · ${profileRoleLabel}`}
        >
          <span className="chat-activity-profile-avatar" aria-hidden="true">
            {profileInitials}
          </span>
          <span className="chat-activity-profile-label">
            <strong>{workspaceLabel}</strong>
            <em>{profileDisplayName}</em>
          </span>
          <span className="chat-activity-profile-menu-indicator" aria-hidden="true">
            ⌄
          </span>
        </button>
      </div>
    </aside>
  );
}

export const LocalActivityBar = ChatLocalActivityBar;
