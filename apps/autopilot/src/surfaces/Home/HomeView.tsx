import {
  createElement,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentType,
} from "react";
import {
  ArrowRight,
  Bell,
  Bot,
  Boxes,
  Code2,
  Database,
  FileCode2,
  FolderOpen,
  LayoutDashboard,
  MessageCircle,
  Play,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  SquareTerminal,
} from "lucide-react";
import "./Home.css";
import {
  applyAutopilotAppearance,
  getAutopilotThemeOption,
  loadAutopilotAppearance,
  saveAutopilotAppearance,
  subscribeAutopilotAppearance,
  type AutopilotAppearanceState,
  type AutopilotThemeId,
} from "../../services/autopilotAppearance";
import type { SettingsSection } from "../../windows/ChatWindow/components/ChatSettingsView.shared";
import { HomeWalkthroughDocument } from "./HomeWalkthroughDocument";
import {
  FIRST_RUN_ONBOARDING_STEPS,
  HOME_ONBOARDING_FOCUS_EVENT,
  defaultOnboardingStepId,
  findOnboardingStep,
  normalizeOnboardingConditionState,
  resolveOnboardingRouteVisibility,
  type OnboardingActionId,
} from "./homeOnboardingModel";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface HomeViewProps {
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  onOpenChat: () => void;
  onOpenWorkspace: () => void;
  onOpenRuns: () => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: (section?: SettingsSection | null) => void;
  onOpenCommandPalette: () => void;
  onSelectProject: (projectId: string) => void;
}

interface HomeOnboardingState {
  selectedStepId: string;
  completedStepIds: string[];
  completedAtMs: number | null;
  skippedAtMs: number | null;
  actionReceipts: Array<{
    actionId: OnboardingActionId;
    stepId: string;
    timestampMs: number;
  }>;
}

const STORAGE_KEY = "autopilot.home.onboarding.v1";
const RESET_SESSION_KEY = "autopilot.home.onboarding.reset.applied.v1";
let resetAppliedThisPage = false;

function resetRequestedByEnv(): boolean {
  return (
    (import.meta.env.VITE_AUTOPILOT_RESET_HOME_ONBOARDING ?? "")
      .toString()
      .trim() === "1"
  );
}

function hasStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function applyProbeResetOnce(): boolean {
  if (!hasStorage() || !resetRequestedByEnv()) {
    return false;
  }
  try {
    if (resetAppliedThisPage || window.sessionStorage.getItem(RESET_SESSION_KEY) === "1") {
      return false;
    }
    window.localStorage.removeItem(STORAGE_KEY);
    window.sessionStorage.setItem(RESET_SESSION_KEY, "1");
    saveAutopilotAppearance({ themeId: "light-modern", density: "default" });
    resetAppliedThisPage = true;
    return true;
  } catch {
    return false;
  }
}

function loadState(): HomeOnboardingState {
  const fallback: HomeOnboardingState = {
    selectedStepId: defaultOnboardingStepId(),
    completedStepIds: [],
    completedAtMs: null,
    skippedAtMs: null,
    actionReceipts: [],
  };

  if (!hasStorage()) {
    return fallback;
  }

  try {
    if (applyProbeResetOnce()) {
      return fallback;
    }
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return fallback;
    }
    const parsed = JSON.parse(raw) as Partial<HomeOnboardingState>;
    const selectedStepId =
      typeof parsed.selectedStepId === "string" &&
      findOnboardingStep(parsed.selectedStepId)
        ? parsed.selectedStepId
        : fallback.selectedStepId;
    const completedStepIds = Array.isArray(parsed.completedStepIds)
      ? parsed.completedStepIds.filter(
          (stepId): stepId is string =>
            typeof stepId === "string" && Boolean(findOnboardingStep(stepId)),
        )
      : [];
    return {
      selectedStepId,
      completedStepIds: [...new Set(completedStepIds)],
      completedAtMs:
        typeof parsed.completedAtMs === "number" ? parsed.completedAtMs : null,
      skippedAtMs:
        typeof parsed.skippedAtMs === "number" ? parsed.skippedAtMs : null,
      actionReceipts: Array.isArray(parsed.actionReceipts)
        ? parsed.actionReceipts
            .filter(
              (receipt): receipt is HomeOnboardingState["actionReceipts"][number] =>
                Boolean(receipt) &&
                typeof receipt === "object" &&
                typeof (receipt as { actionId?: unknown }).actionId === "string" &&
                typeof (receipt as { stepId?: unknown }).stepId === "string" &&
                typeof (receipt as { timestampMs?: unknown }).timestampMs === "number",
            )
            .slice(-20)
        : [],
    };
  } catch {
    return fallback;
  }
}

function saveState(state: HomeOnboardingState): void {
  if (!hasStorage()) {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function formatDate(timestampMs: number | null): string {
  if (!timestampMs) {
    return "In progress";
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

function nextStepId(currentStepId: string, steps = FIRST_RUN_ONBOARDING_STEPS): string {
  const currentIndex = steps.findIndex(
    (step) => step.id === currentStepId,
  );
  const nextIndex =
    currentIndex >= 0
      ? (currentIndex + 1) % steps.length
      : 0;
  return steps[nextIndex]?.id ?? defaultOnboardingStepId();
}

function completionPercent(
  completedStepIds: string[],
  steps = FIRST_RUN_ONBOARDING_STEPS,
): number {
  if (steps.length === 0) {
    return 0;
  }
  return Math.round(
    (completedStepIds.filter((stepId) =>
      steps.some((step) => step.id === stepId),
    ).length /
      steps.length) *
      100,
  );
}

type RecentMode = "files" | "projects";

interface HomeDashboardViewProps {
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  selectedThemeLabel: string;
  completedAtMs: number | null;
  skippedAtMs: number | null;
  recentMode: RecentMode;
  onRecentModeChange: (mode: RecentMode) => void;
  onOpenChat: () => void;
  onOpenWorkspace: () => void;
  onOpenRuns: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: (section?: SettingsSection | null) => void;
  onOpenCommandPalette: () => void;
  onSelectProject: (projectId: string) => void;
  onReviewSetup: () => void;
}

interface DashboardSurface {
  id: string;
  label: string;
  detail: string;
  icon: unknown;
  tone: "neutral" | "blue" | "teal" | "orange" | "purple" | "green";
  onClick: () => void;
}

type IconProps = {
  size?: number;
  strokeWidth?: number;
  className?: string;
  "aria-hidden"?: boolean | "true" | "false";
};

function renderIcon(Icon: unknown, props: IconProps = {}) {
  return createElement(Icon as ComponentType<IconProps>, props);
}

function HomeBrandMark() {
  return (
    <span className="chat-home-zero-brand-mark" aria-hidden="true">
      {renderIcon(Sparkles, { size: 26, strokeWidth: 1.75 })}
    </span>
  );
}

function DashboardSurfaceButton({ surface }: { surface: DashboardSurface }) {
  const Icon = surface.icon;
  return (
    <button
      type="button"
      className={`chat-home-zero-app chat-home-zero-app--${surface.tone}`}
      data-home-dashboard-surface={surface.id}
      onClick={surface.onClick}
    >
      <span>
        {renderIcon(Icon, { size: 22, strokeWidth: 1.8 })}
      </span>
      <strong>{surface.label}</strong>
      <em>{surface.detail}</em>
    </button>
  );
}

function HomeDashboardView({
  currentProject,
  projects,
  notificationCount,
  selectedThemeLabel,
  completedAtMs,
  skippedAtMs,
  recentMode,
  onRecentModeChange,
  onOpenChat,
  onOpenWorkspace,
  onOpenRuns,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenSettings,
  onOpenCommandPalette,
  onSelectProject,
  onReviewSetup,
}: HomeDashboardViewProps) {
  const setupStatus = skippedAtMs
    ? `Setup skipped ${formatDate(skippedAtMs)}`
    : `Setup completed ${formatDate(completedAtMs)}`;
  const surfaces: DashboardSurface[] = [
    {
      id: "projects",
      label: "Projects & files",
      detail: "Local scope",
      icon: FolderOpen,
      tone: "neutral",
      onClick: () => onRecentModeChange("projects"),
    },
    {
      id: "workspace",
      label: "Workspace",
      detail: "Code workbench",
      icon: Code2,
      tone: "blue",
      onClick: onOpenWorkspace,
    },
    {
      id: "chat",
      label: "Chat",
      detail: "Agent runtime",
      icon: MessageCircle,
      tone: "teal",
      onClick: onOpenChat,
    },
    {
      id: "runs",
      label: "Runs",
      detail: "Execution history",
      icon: Play,
      tone: "orange",
      onClick: onOpenRuns,
    },
    {
      id: "evidence",
      label: "Evidence",
      detail: "Receipts",
      icon: FileCode2,
      tone: "green",
      onClick: onOpenRuns,
    },
    {
      id: "policy",
      label: "Policy",
      detail: "Approvals",
      icon: ShieldCheck,
      tone: "purple",
      onClick: onOpenPolicy,
    },
    {
      id: "capabilities",
      label: "Capabilities",
      detail: "Connectors",
      icon: Boxes,
      tone: "blue",
      onClick: onOpenCapabilities,
    },
    {
      id: "settings",
      label: "Settings",
      detail: selectedThemeLabel,
      icon: Settings,
      tone: "neutral",
      onClick: () => onOpenSettings("managed_settings"),
    },
  ];

  return (
    <section
      className="chat-home-zero"
      aria-label="Autopilot home"
      data-home-dashboard-variant="autopilot-zero-state"
    >
      <div className="chat-home-zero-shell">
        <header className="chat-home-zero-hero">
          <div className="chat-home-zero-title-row">
            <HomeBrandMark />
            <h1>Welcome back to Autopilot</h1>
          </div>
          <button
            type="button"
            className="chat-home-zero-search"
            onClick={onOpenCommandPalette}
            data-home-action="palette.open"
            aria-label="Search Autopilot, code, sessions, and commands"
          >
            {renderIcon(Search, { size: 17, strokeWidth: 1.8, "aria-hidden": true })}
            <span>Search Autopilot, code, sessions, and commands</span>
            <kbd>ctrl + K</kbd>
          </button>

          <div className="chat-home-zero-actions" aria-label="Suggested actions">
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(SquareTerminal, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Open your workspace</h2>
                <p>Browse and edit code in the contained OpenVSCode workbench.</p>
              </div>
              <button type="button" onClick={onOpenWorkspace}>
                <span>Open Workspace</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(Bot, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Ask about this codebase</h2>
                <p>Continue with shared project context and IOI runtime authority.</p>
              </div>
              <button type="button" onClick={onOpenChat}>
                <span>Open Chat</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(FileCode2, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Review retained proof</h2>
                <p>Inspect runs, receipts, artifacts, and evidence bundles.</p>
              </div>
              <button type="button" onClick={onOpenRuns}>
                <span>Open Runs</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
          </div>
        </header>

        <div className="chat-home-zero-body">
          <main className="chat-home-zero-main">
            <section className="chat-home-zero-recent" aria-label="Recent resources">
              <div className="chat-home-zero-section-heading">
                <h2>Recent</h2>
                <div className="chat-home-zero-filter" aria-label="Recent filter">
                  <button
                    type="button"
                    className={recentMode === "files" ? "is-active" : ""}
                    onClick={() => onRecentModeChange("files")}
                  >
                    Files
                  </button>
                  <button
                    type="button"
                    className={recentMode === "projects" ? "is-active" : ""}
                    onClick={() => onRecentModeChange("projects")}
                  >
                    Projects
                  </button>
                </div>
              </div>
              <div className="chat-home-zero-table" data-home-recent-mode={recentMode}>
                <div className="chat-home-zero-table-head">
                  <span>{recentMode === "files" ? "File name" : "Project"}</span>
                  <span>{recentMode === "files" ? "Last updated" : "Scope"}</span>
                </div>
                {recentMode === "projects" ? (
                  <div className="chat-home-zero-project-rows">
                    {projects.map((project) => (
                      <button
                        type="button"
                        key={project.id}
                        className={project.id === currentProject.id ? "is-active" : ""}
                        onClick={() => onSelectProject(project.id)}
                      >
                        <span>
                          <strong>{project.name}</strong>
                          <em>{project.description}</em>
                        </span>
                        <span>{project.environment} · {project.rootPath}</span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="chat-home-zero-empty">
                    {renderIcon(FolderOpen, { size: 46, strokeWidth: 1.35 })}
                    <strong>No recently viewed files</strong>
                    <button type="button" onClick={onOpenWorkspace}>
                      Explore your codebase
                    </button>
                  </div>
                )}
              </div>
            </section>

            <section className="chat-home-zero-assist" aria-label="Autopilot assistant">
              <div>
                <h2>Get help from your personal AI assistant</h2>
                <p>{currentProject.name} · {setupStatus}</p>
              </div>
              <div className="chat-home-zero-questions">
                <button type="button" onClick={onOpenChat}>
                  {renderIcon(MessageCircle, { size: 15, strokeWidth: 2 })}
                  What changed in this repo?
                </button>
                <button type="button" onClick={onOpenChat}>
                  {renderIcon(MessageCircle, { size: 15, strokeWidth: 2 })}
                  Where should I start?
                </button>
                <button type="button" onClick={onOpenRuns}>
                  {renderIcon(MessageCircle, { size: 15, strokeWidth: 2 })}
                  Summarize recent evidence
                </button>
                <button type="button" onClick={onOpenChat}>
                  Ask your question...
                </button>
              </div>
              {renderIcon(Bot, {
                className: "chat-home-zero-assist-mark",
                size: 138,
                strokeWidth: 1.2,
              })}
            </section>
          </main>

          <aside className="chat-home-zero-sidebar" aria-label="Autopilot surfaces">
            <section className="chat-home-zero-side-card">
              <div className="chat-home-zero-side-header">
                <h2>Recommended surfaces</h2>
                <button type="button" onClick={onOpenCommandPalette}>View all</button>
              </div>
              <div className="chat-home-zero-app-grid">
                {surfaces.map((surface) => (
                  <DashboardSurfaceButton key={surface.id} surface={surface} />
                ))}
              </div>
              <p>
                Pin the surfaces you use most from the activity bar. The runtime,
                evidence, and workbench all share the same project scope.
              </p>
            </section>

            <section className="chat-home-zero-side-card chat-home-zero-side-card--support">
              <h2>Get in touch</h2>
              <p>Use diagnostics when something looks off, or review setup again.</p>
              <button type="button" onClick={() => onOpenSettings("diagnostics")}>
                {renderIcon(Bell, { size: 15, strokeWidth: 2 })}
                Open diagnostics
              </button>
              <button type="button" onClick={onReviewSetup}>
                {renderIcon(LayoutDashboard, { size: 15, strokeWidth: 2 })}
                Review onboarding
              </button>
            </section>

            <section className="chat-home-zero-side-card chat-home-zero-side-card--status">
              <div>
                {renderIcon(Database, { size: 24, strokeWidth: 1.6 })}
                <h2>Runtime status</h2>
              </div>
              <dl>
                <div>
                  <dt>Project</dt>
                  <dd>{currentProject.name}</dd>
                </div>
                <div>
                  <dt>Root</dt>
                  <dd>{currentProject.rootPath}</dd>
                </div>
                <div>
                  <dt>Inbox</dt>
                  <dd>{notificationCount > 0 ? `${notificationCount} pending` : "Clear"}</dd>
                </div>
                <div>
                  <dt>Theme</dt>
                  <dd>{selectedThemeLabel}</dd>
                </div>
              </dl>
            </section>
          </aside>
        </div>
      </div>
    </section>
  );
}

export function HomeView({
  currentProject,
  projects,
  notificationCount,
  onOpenChat,
  onOpenWorkspace,
  onOpenRuns,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenSettings,
  onOpenCommandPalette,
  onSelectProject,
}: HomeViewProps) {
  const [state, setState] = useState<HomeOnboardingState>(() => loadState());
  const stateRef = useRef(state);
  const [appearance, setAppearance] = useState<AutopilotAppearanceState>(() =>
    loadAutopilotAppearance(),
  );
  const [reviewingCompletedSetup, setReviewingCompletedSetup] = useState(false);
  const [recentMode, setRecentMode] = useState<RecentMode>("files");
  const routeResolution = useMemo(() => {
    const hasProjectRoot = currentProject.rootPath.trim().length > 0;
    return resolveOnboardingRouteVisibility(
      normalizeOnboardingConditionState({
        workspaceFolderCount: hasProjectRoot ? 1 : 0,
        gitOpenRepositoryCount: hasProjectRoot ? 1 : 0,
      }),
    );
  }, [currentProject.rootPath]);
  const visibleOnboardingSteps =
    routeResolution.visibleSteps.length > 0
      ? routeResolution.visibleSteps
      : FIRST_RUN_ONBOARDING_STEPS;
  const selectedStep =
    visibleOnboardingSteps.find((step) => step.id === state.selectedStepId) ??
    visibleOnboardingSteps[0] ??
    FIRST_RUN_ONBOARDING_STEPS[0]!;
  const selectedTheme = getAutopilotThemeOption(appearance.themeId);
  const completedSet = useMemo(
    () => new Set(state.completedStepIds),
    [state.completedStepIds],
  );
  const allStepsComplete = visibleOnboardingSteps.every((step) =>
    completedSet.has(step.id),
  );
  const showDashboard = allStepsComplete && !reviewingCompletedSetup;
  const percentComplete = completionPercent(
    state.completedStepIds,
    visibleOnboardingSteps,
  );

  useEffect(() => {
    applyAutopilotAppearance(appearance);
    return subscribeAutopilotAppearance(setAppearance);
  }, []);

  useEffect(() => {
    saveState(state);
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    const handler = (event: Event) => {
      if (!(event instanceof CustomEvent)) {
        return;
      }
      const requestedStepId = event.detail?.stepId;
      if (
        typeof requestedStepId === "string" &&
        findOnboardingStep(requestedStepId)
      ) {
        setReviewingCompletedSetup(true);
        setState((current) => ({
          ...current,
          selectedStepId: requestedStepId,
        }));
      }
    };
    window.addEventListener(HOME_ONBOARDING_FOCUS_EVENT, handler);
    return () => window.removeEventListener(HOME_ONBOARDING_FOCUS_EVENT, handler);
  }, []);

  const patchState = (updater: (current: HomeOnboardingState) => HomeOnboardingState) => {
    const next = updater(stateRef.current);
    const complete =
      visibleOnboardingSteps.every((step) =>
        next.completedStepIds.includes(step.id),
      );
    const resolved = {
      ...next,
      completedAtMs: complete ? next.completedAtMs ?? Date.now() : null,
    };
    stateRef.current = resolved;
    saveState(resolved);
    setState(resolved);
  };

  const markStepDone = (stepId: string = selectedStep.id) => {
    patchState((current) => ({
      ...current,
      completedStepIds: [...new Set([...current.completedStepIds, stepId])],
    }));
  };

  const skipForNow = () => {
    const timestampMs = Date.now();
    patchState((current) => ({
      ...current,
      completedStepIds: [
        ...new Set([
          ...current.completedStepIds,
          ...visibleOnboardingSteps.map((step) => step.id),
        ]),
      ],
      completedAtMs: current.completedAtMs ?? timestampMs,
      skippedAtMs: current.skippedAtMs ?? timestampMs,
      actionReceipts: [
        ...current.actionReceipts.slice(-19),
        {
          actionId: "home.markDone",
          stepId: selectedStep.id,
          timestampMs,
        },
      ],
    }));
    setReviewingCompletedSetup(false);
  };

  const recordAction = (actionId: OnboardingActionId, stepId = selectedStep.id) => {
    patchState((current) => ({
      ...current,
      actionReceipts: [
        ...current.actionReceipts.slice(-19),
        { actionId, stepId, timestampMs: Date.now() },
      ],
    }));
  };

  const applyTheme = (themeId: AutopilotThemeId) => {
    const nextAppearance = saveAutopilotAppearance({ themeId });
    setAppearance(nextAppearance);
    markStepDone("setup-theme");
    recordAction("appearance.selectTheme", "setup-theme");
  };

  const executeAction = (actionId: OnboardingActionId) => {
    recordAction(actionId);
    switch (actionId) {
      case "appearance.selectTheme":
        markStepDone("setup-theme");
        return;
      case "project.openWorkspace":
      case "workspace.open":
      case "extensions.openPopularWeb":
      case "extensions.openLanguage":
      case "quickOpen.open":
      case "workbench.toggleMenuBar":
      case "workbench.openTerminal":
      case "workbench.openDebug":
      case "workbench.openGit":
      case "workbench.openShortcuts":
      case "workbench.workspaceTrust":
        markStepDone(selectedStep.id);
        onOpenWorkspace();
        return;
      case "workbench.runTasks":
        markStepDone(selectedStep.id);
        onOpenRuns();
        return;
      case "settings.sync":
        markStepDone(selectedStep.id);
        onOpenSettings("managed_settings");
        return;
      case "context.openCapabilities":
        markStepDone(selectedStep.id);
        onOpenCapabilities();
        return;
      case "runtime.openSettings":
        markStepDone(selectedStep.id);
        onOpenSettings("runtime");
        return;
      case "policy.openPolicy":
        markStepDone(selectedStep.id);
        onOpenPolicy();
        return;
      case "palette.open":
        markStepDone(selectedStep.id);
        onOpenCommandPalette();
        return;
      case "evidence.openRuns":
        markStepDone(selectedStep.id);
        onOpenRuns();
        return;
      case "accessibility.openSettings":
        markStepDone(selectedStep.id);
        onOpenSettings("diagnostics");
        return;
      case "notebook.profile":
        markStepDone(selectedStep.id);
        onOpenWorkspace();
        return;
      case "home.markDone":
        markStepDone(selectedStep.id);
        return;
      default:
        return;
    }
  };

  const goToNextStep = () => {
    patchState((current) => ({
      ...current,
      selectedStepId: nextStepId(current.selectedStepId, visibleOnboardingSteps),
    }));
  };

  const focusStep = (stepId: string) => {
    patchState((current) => ({
      ...current,
      selectedStepId: stepId,
    }));
  };

  if (showDashboard) {
    return (
      <section
        className="chat-home"
        aria-label="Autopilot home dashboard"
        data-home-onboarding-state="complete"
        data-home-selected-step={state.selectedStepId}
      >
        <HomeDashboardView
          currentProject={currentProject}
          projects={projects}
          notificationCount={notificationCount}
          selectedThemeLabel={selectedTheme.label}
          completedAtMs={state.completedAtMs}
          skippedAtMs={state.skippedAtMs}
          recentMode={recentMode}
          onRecentModeChange={setRecentMode}
          onOpenChat={onOpenChat}
          onOpenWorkspace={onOpenWorkspace}
          onOpenRuns={onOpenRuns}
          onOpenCapabilities={onOpenCapabilities}
          onOpenPolicy={onOpenPolicy}
          onOpenSettings={onOpenSettings}
          onOpenCommandPalette={onOpenCommandPalette}
          onSelectProject={onSelectProject}
          onReviewSetup={() => setReviewingCompletedSetup(true)}
        />
      </section>
    );
  }

  return (
    <section
      className="chat-home"
      aria-label="Autopilot onboarding"
      data-home-onboarding-state="onboarding"
      data-home-selected-step={selectedStep.id}
      data-home-progress={percentComplete}
      data-home-visible-step-count={visibleOnboardingSteps.length}
      data-home-conditional-visible-step-count={
        routeResolution.conditionalVisibleSteps.length
      }
    >
      <HomeWalkthroughDocument
        selectedStep={selectedStep}
        completedStepIds={completedSet}
        appearance={appearance}
        onBack={onOpenChat}
        onSkipForNow={skipForNow}
        onApplyTheme={applyTheme}
        onExecuteAction={executeAction}
        onFocusStep={focusStep}
        families={routeResolution.visibleFamilies}
        onMarkStepDone={markStepDone}
        onNextStep={goToNextStep}
      />
    </section>
  );
}
