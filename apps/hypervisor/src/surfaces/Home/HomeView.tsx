import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import "./Home.css";
import {
  applyHypervisorAppearance,
  getHypervisorThemeOption,
  loadHypervisorAppearance,
  saveHypervisorAppearance,
  subscribeHypervisorAppearance,
  type HypervisorAppearanceState,
  type HypervisorThemeId,
} from "../../services/hypervisorAppearance";
import {
  enqueueWorkspaceEditorAdapterBridgeCommand,
  ensureWorkspaceEditorAdapterSession,
} from "../../services/workspaceEditorAdapterBridge";
import type { SettingsSection } from "../Settings/settingsViewShared";
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

interface HomeNewSessionSeed {
  seedIntent?: string | null;
  recipeId?: string | null;
}

interface HomeViewProps {
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  onOpenChat: () => void;
  onOpenNewSession: (seed?: string | HomeNewSessionSeed | null) => void;
  onOpenWorkspace: () => void;
  onOpenRuns: () => void;
  onOpenModels: () => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: (section?: SettingsSection | null) => void;
  onOpenCommandPalette: () => void;
  onOpenCockpitSurface: (surfaceRef: string) => void;
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

const STORAGE_KEY = "hypervisor.home.onboarding.v1";
const RESET_SESSION_KEY = "hypervisor.home.onboarding.reset.applied.v1";
let resetAppliedThisPage = false;

function resetRequestedByEnv(): boolean {
  return (
    (import.meta.env.VITE_HYPERVISOR_RESET_HOME_ONBOARDING ?? "")
      .toString()
      .trim() === "1"
  );
}

function hasStorage(): boolean {
  return (
    typeof window !== "undefined" && typeof window.localStorage !== "undefined"
  );
}

function applyProbeResetOnce(): boolean {
  if (!hasStorage() || !resetRequestedByEnv()) {
    return false;
  }
  try {
    if (
      resetAppliedThisPage ||
      window.sessionStorage.getItem(RESET_SESSION_KEY) === "1"
    ) {
      return false;
    }
    window.localStorage.removeItem(STORAGE_KEY);
    window.sessionStorage.setItem(RESET_SESSION_KEY, "1");
    saveHypervisorAppearance({ themeId: "light-modern", density: "default" });
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
              (
                receipt,
              ): receipt is HomeOnboardingState["actionReceipts"][number] =>
                Boolean(receipt) &&
                typeof receipt === "object" &&
                typeof (receipt as { actionId?: unknown }).actionId ===
                  "string" &&
                typeof (receipt as { stepId?: unknown }).stepId === "string" &&
                typeof (receipt as { timestampMs?: unknown }).timestampMs ===
                  "number",
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

function nextStepId(
  currentStepId: string,
  steps = FIRST_RUN_ONBOARDING_STEPS,
): string {
  const currentIndex = steps.findIndex((step) => step.id === currentStepId);
  const nextIndex = currentIndex >= 0 ? (currentIndex + 1) % steps.length : 0;
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

const HOME_REFERENCE_SURFACES: Array<{
  label: string;
  detail: string;
  surface:
    | "workspace"
    | "automations"
    | "agents"
    | "models"
    | "foundry"
    | "authority"
    | "providers"
    | "receipts";
}> = [
  {
    label: "Workbench",
    detail: "Code, terminals, editor adapters",
    surface: "workspace",
  },
  {
    label: "Automations",
    detail: "Workflow graphs and scheduled runs",
    surface: "automations",
  },
  {
    label: "Agents",
    detail: "Workers, skills, memory, capabilities",
    surface: "agents",
  },
  {
    label: "Models",
    detail: "Routes, mounts, providers, custody",
    surface: "models",
  },
  {
    label: "Providers",
    detail: "Local, cloud, DePIN, storage",
    surface: "providers",
  },
  {
    label: "Authority",
    detail: "Policy, approvals, leases",
    surface: "authority",
  },
  {
    label: "Receipts",
    detail: "Activity, replay, evidence",
    surface: "receipts",
  },
] as const;

interface HomeDashboardViewProps {
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  selectedThemeLabel: string;
  completedAtMs: number | null;
  skippedAtMs: number | null;
  onOpenChat: () => void;
  onOpenNewSession: (seed?: string | HomeNewSessionSeed | null) => void;
  onOpenWorkspace: () => void;
  onOpenRuns: () => void;
  onOpenModels: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: (section?: SettingsSection | null) => void;
  onOpenCommandPalette: () => void;
  onOpenCockpitSurface: (surfaceRef: string) => void;
  onSelectProject: (projectId: string) => void;
  onReviewSetup: () => void;
}

function HomeDashboardView({
  currentProject,
  projects,
  onOpenNewSession,
  onOpenWorkspace,
  onOpenModels,
  onOpenPolicy,
  onOpenCommandPalette,
  onOpenCockpitSurface,
  onSelectProject,
}: HomeDashboardViewProps) {
  const seedIntent =
    "Open a governed Hypervisor session for this workspace with editor, terminal, model mount, policy, and receipts wired.";
  const openAppSurface = (
    surface: (typeof HOME_REFERENCE_SURFACES)[number]["surface"],
  ) => {
    switch (surface) {
      case "workspace":
        onOpenWorkspace();
        return;
      case "automations":
      case "agents":
      case "foundry":
      case "providers":
      case "receipts":
        onOpenCockpitSurface(`surface:${surface}`);
        return;
      case "models":
        onOpenModels();
        return;
      case "authority":
        onOpenPolicy();
        return;
      default:
        return;
    }
  };
  const visibleProjects = projects.length > 0 ? projects : [currentProject];
  const activeProjectCount = visibleProjects.length;

  return (
    <section
      className="chat-home-zero chat-home-zero--ioi-enterprise"
      aria-label="Hypervisor home"
      data-home-dashboard-variant="ioi-reference-home"
    >
      <div className="chat-home-zero-shell chat-home-zero-shell--sessions">
        <header className="chat-home-zero-reference-header">
          <div>
            <p>Home</p>
            <h1>Sessions and workspaces</h1>
          </div>
          <button
            type="button"
            className="chat-home-zero-primary-action"
            data-home-start-session="true"
            onClick={() =>
              onOpenNewSession({
                seedIntent,
                recipeId: "ioi-reference-home",
              })
            }
          >
            + New Session
          </button>
        </header>

        <div className="chat-home-zero-workplane">
          <main className="chat-home-zero-main" aria-label="Session workplane">
            <section className="chat-home-zero-panel chat-home-zero-panel--recent">
              <div className="chat-home-zero-section-heading">
                <div>
                  <h2>Recent sessions</h2>
                  <p>
                    Resume work across local projects, hosted workspaces, editor
                    adapters, browser sessions, and worker nodes.
                  </p>
                </div>
                <button
                  type="button"
                  className="chat-home-zero-link-button"
                  onClick={onOpenCommandPalette}
                >
                  Search
                </button>
              </div>
              <div className="chat-home-zero-table">
                <div className="chat-home-zero-table-head">
                  <span>Name</span>
                  <span>Class</span>
                  <span>Last updated</span>
                </div>
                <div className="chat-home-zero-project-rows">
                  {visibleProjects.slice(0, 4).map((project) => (
                    <button
                      type="button"
                      key={project.id}
                      className={project.id === currentProject.id ? "is-active" : ""}
                      onClick={() => {
                        onSelectProject(project.id);
                        onOpenWorkspace();
                      }}
                    >
                      <span className="chat-home-zero-project-name">
                        <strong>{project.name || "Current workspace"}</strong>
                        <em>{project.rootPath || project.description}</em>
                      </span>
                      <span>{project.environment || "Workspace"}</span>
                      <span>about 10 hours ago</span>
                    </button>
                  ))}
                </div>
              </div>
            </section>
          </main>

          <aside className="chat-home-zero-sidebar" aria-label="Workspace context">
            <section className="chat-home-zero-side-card chat-home-zero-side-card--updates">
              <div className="chat-home-zero-side-header">
                <h2>What's new?</h2>
                <button type="button" onClick={() => onOpenCockpitSurface("surface:activity")}>
                  See all
                </button>
              </div>
              <article className="chat-home-zero-update">
                <span>Feature</span>
                <time>Apr 21, 2026</time>
                <p>
                  Session views now surface editor adapters, hosted workers,
                  ports, tasks, and restore points from one place.
                </p>
                <button type="button" onClick={() => onOpenCockpitSurface("surface:sessions")}>
                  More
                </button>
              </article>
            </section>

            <section className="chat-home-zero-side-card">
              <div className="chat-home-zero-side-header">
                <h2>Surfaces</h2>
              </div>
              <div className="chat-home-zero-surface-list">
                {HOME_REFERENCE_SURFACES.map((surface) => (
                  <button
                    type="button"
                    key={surface.label}
                    onClick={() => openAppSurface(surface.surface)}
                  >
                    <span>
                      <strong>{surface.label}</strong>
                      <em>{surface.detail}</em>
                    </span>
                  </button>
                ))}
              </div>
            </section>

            <section className="chat-home-zero-side-card chat-home-zero-side-card--status">
              <h2>Workspace</h2>
              <dl>
                <div>
                  <dt>Projects</dt>
                  <dd>{activeProjectCount}</dd>
                </div>
                <div>
                  <dt>Selected</dt>
                  <dd>{currentProject.name || "Current workspace"}</dd>
                </div>
                <div>
                  <dt>Root</dt>
                  <dd>{currentProject.rootPath || "Not attached"}</dd>
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
  onOpenNewSession,
  onOpenWorkspace,
  onOpenRuns,
  onOpenModels,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenSettings,
  onOpenCommandPalette,
  onOpenCockpitSurface,
  onSelectProject,
}: HomeViewProps) {
  const [state, setState] = useState<HomeOnboardingState>(() => loadState());
  const stateRef = useRef(state);
  const [appearance, setAppearance] = useState<HypervisorAppearanceState>(() =>
    loadHypervisorAppearance(),
  );
  const [reviewingCompletedSetup, setReviewingCompletedSetup] = useState(false);
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
  const selectedTheme = getHypervisorThemeOption(appearance.themeId);
  const completedSet = useMemo(
    () => new Set(state.completedStepIds),
    [state.completedStepIds],
  );
  const showDashboard = !reviewingCompletedSetup;
  const percentComplete = completionPercent(
    state.completedStepIds,
    visibleOnboardingSteps,
  );

  useEffect(() => {
    applyHypervisorAppearance(appearance);
    return subscribeHypervisorAppearance(setAppearance);
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
    return () =>
      window.removeEventListener(HOME_ONBOARDING_FOCUS_EVENT, handler);
  }, []);

  const patchState = (
    updater: (current: HomeOnboardingState) => HomeOnboardingState,
  ) => {
    const next = updater(stateRef.current);
    const complete = visibleOnboardingSteps.every((step) =>
      next.completedStepIds.includes(step.id),
    );
    const resolved = {
      ...next,
      completedAtMs: complete ? (next.completedAtMs ?? Date.now()) : null,
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

  const recordAction = (
    actionId: OnboardingActionId,
    stepId = selectedStep.id,
  ) => {
    patchState((current) => ({
      ...current,
      actionReceipts: [
        ...current.actionReceipts.slice(-19),
        { actionId, stepId, timestampMs: Date.now() },
      ],
    }));
  };

  const applyTheme = (themeId: HypervisorThemeId) => {
    const nextAppearance = saveHypervisorAppearance({ themeId });
    setAppearance(nextAppearance);
    markStepDone("setup-theme");
    recordAction("appearance.selectTheme", "setup-theme");
  };

  const queueWorkbenchCommand = (
    command: string,
    options: { revealWorkspace?: boolean } = {},
  ) => {
    void (async () => {
      await ensureWorkspaceEditorAdapterSession(currentProject.rootPath);
      await enqueueWorkspaceEditorAdapterBridgeCommand({
        root: currentProject.rootPath,
        command,
      });
    })().catch((error) => {
      console.error(
        "[HomeOnboarding] Failed to queue workbench command:",
        error,
      );
    });

    if (options.revealWorkspace ?? true) {
      onOpenWorkspace();
    }
  };

  const executeAction = (actionId: OnboardingActionId) => {
    recordAction(actionId);
    switch (actionId) {
      case "appearance.selectTheme":
        markStepDone("setup-theme");
        return;
      case "project.openWorkbench":
      case "workspace.open":
        markStepDone(selectedStep.id);
        onOpenWorkspace();
        return;
      case "extensions.openPopularWeb":
      case "extensions.openLanguage":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.view.extensions");
        return;
      case "quickOpen.open":
        markStepDone(selectedStep.id);
        onOpenCommandPalette();
        return;
      case "workbench.toggleMenuBar":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.action.toggleMenuBar", {
          revealWorkspace: false,
        });
        return;
      case "workbench.openTerminal":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.action.terminal.toggleTerminal");
        return;
      case "workbench.openDebug":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.view.debug");
        return;
      case "workbench.openGit":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.view.scm");
        return;
      case "workbench.openShortcuts":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.action.openGlobalKeybindings");
        return;
      case "workbench.workspaceTrust":
        markStepDone(selectedStep.id);
        queueWorkbenchCommand("workbench.trust.manage");
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
      case "policy.openAuthority":
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
      selectedStepId: nextStepId(
        current.selectedStepId,
        visibleOnboardingSteps,
      ),
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
        aria-label="Hypervisor home dashboard"
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
          onOpenChat={onOpenChat}
          onOpenNewSession={onOpenNewSession}
          onOpenWorkspace={onOpenWorkspace}
          onOpenRuns={onOpenRuns}
          onOpenModels={onOpenModels}
          onOpenCapabilities={onOpenCapabilities}
          onOpenPolicy={onOpenPolicy}
          onOpenSettings={onOpenSettings}
          onOpenCommandPalette={onOpenCommandPalette}
          onOpenCockpitSurface={onOpenCockpitSurface}
          onSelectProject={onSelectProject}
          onReviewSetup={() => setReviewingCompletedSetup(true)}
        />
      </section>
    );
  }

  return (
    <section
      className="chat-home"
      aria-label="Hypervisor onboarding"
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
