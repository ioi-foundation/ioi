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
  ArrowUp,
  Atom,
  Bell,
  Bot,
  Boxes,
  Bug,
  Code2,
  Crosshair,
  Database,
  FileCode2,
  FolderOpen,
  CircleDashed,
  ChevronDown,
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
import { HYPERVISOR_NEW_SESSION_SETUP_MODEL } from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import {
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionRef,
} from "../../windows/HypervisorShellWindow/harnessAdapterModel";
import {
  HYPERVISOR_HOME_COCKPIT_PROJECTION,
  loadHypervisorHomeCockpitProjection,
} from "./homeCockpitModel";
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

type RecentMode = "files" | "projects";

const HOME_INTENT_QUICKSTARTS: Array<{
  label: string;
  seedIntent: string;
  recipeId: string;
  icon: unknown;
  tone: "blue" | "red" | "purple";
}> = [
  {
    label: "Automate env setup",
    seedIntent: "Automate env setup",
    recipeId: "automation.default",
    icon: CircleDashed,
    tone: "blue",
  },
  {
    label: "Fix a bug",
    seedIntent: "Fix a bug",
    recipeId: "workbench.default",
    icon: Bug,
    tone: "red",
  },
  {
    label: "Boost your test coverage",
    seedIntent: "Boost your test coverage",
    recipeId: "foundry.eval",
    icon: Atom,
    tone: "purple",
  },
];

const HOME_REFERENCE_RECENT_SESSIONS = [
  {
    title: "Write Parent Harness Evidence Boundary Doc",
    meta: "6h ago",
    status: "active",
  },
  {
    title: "Write Harness Tool Call Documentation",
    meta: "6h ago",
    status: "idle",
  },
  {
    title: "Design Postquantum Computers Website",
    meta: "6h ago",
    status: "idle",
  },
] as const;

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
      <span className="chat-home-zero-brand-mark__glyph">
        {renderIcon(Sparkles, { size: 12, strokeWidth: 1.9 })}
      </span>
      <span className="chat-home-zero-brand-mark__word">IOI</span>
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
      <span>{renderIcon(Icon, { size: 22, strokeWidth: 1.8 })}</span>
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
  onReviewSetup,
}: HomeDashboardViewProps) {
  const setupStatus = skippedAtMs
    ? `Setup skipped ${formatDate(skippedAtMs)}`
    : `Setup completed ${formatDate(completedAtMs)}`;
  const newSessionRequiredSections = HYPERVISOR_NEW_SESSION_SETUP_MODEL.sections
    .filter((section) => section.required)
    .slice(0, 5);
  const newSessionHarnessOptions =
    HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions.slice(0, 4);
  const harnessComparison = HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE;
  const [intentDraft, setIntentDraft] = useState("");
  const [intentRecipeId, setIntentRecipeId] = useState<string | null>(null);
  const [cockpitProjection, setCockpitProjection] = useState(
    HYPERVISOR_HOME_COCKPIT_PROJECTION,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorHomeCockpitProjection()
      .then((projection) => {
        if (!cancelled) {
          setCockpitProjection(projection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Home] cockpit projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
      id: "workbench",
      label: "Workbench",
      detail: "Code workbench",
      icon: Code2,
      tone: "blue",
      onClick: onOpenWorkspace,
    },
    {
      id: "sessions",
      label: "Sessions",
      detail: "Live work",
      icon: MessageCircle,
      tone: "teal",
      onClick: onOpenChat,
    },
    {
      id: "insights",
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
      id: "authority",
      label: "Authority",
      detail: "Approvals",
      icon: ShieldCheck,
      tone: "purple",
      onClick: onOpenPolicy,
    },
    {
      id: "agents",
      label: "Agents",
      detail: "Capabilities",
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
      className="chat-home-zero chat-home-zero--ioi-reference"
      aria-label="Hypervisor home"
      data-home-dashboard-variant="ioi-reference-portal"
    >
      <div className="chat-home-zero-shell">
        <header className="chat-home-zero-hero">
          <div className="chat-home-zero-title-row">
            <HomeBrandMark />
            <h1>Welcome back, Heath</h1>
          </div>
          <button
            type="button"
            className="chat-home-zero-search"
            onClick={onOpenCommandPalette}
            data-home-action="palette.open"
            aria-label="Search for anything in Hypervisor"
          >
            {renderIcon(Search, {
              size: 17,
              strokeWidth: 1.8,
              "aria-hidden": true,
            })}
            <span>Search for anything in Hypervisor</span>
            <kbd>ctrl + K</kbd>
          </button>

          <section
            className="chat-home-zero-intent-composer"
            aria-label="Start from intent"
            data-home-intent-composer="ioi-reference-primary"
          >
            <div className="chat-home-zero-intent-composer__heading">
              <span>New Session</span>
              <h2>Open a governed workspace</h2>
              <p>
                Describe the outcome. Hypervisor will bind the project,
                harness, model route, privacy posture, authority, and receipt
                preview before anything consequential runs.
              </p>
            </div>
            <form
              className="chat-home-zero-intent-composer__box"
              onSubmit={(event) => {
                event.preventDefault();
                onOpenNewSession({
                  seedIntent: intentDraft,
                  recipeId: intentRecipeId,
                });
              }}
            >
              <div className="chat-home-zero-intent-composer__frame">
                <textarea
                  value={intentDraft}
                  onChange={(event) => {
                    setIntentDraft(event.currentTarget.value);
                    setIntentRecipeId(null);
                  }}
                  aria-label="Describe your task or type slash for commands"
                  placeholder="Describe your task or type / for commands"
                  rows={4}
                />
                <div className="chat-home-zero-intent-composer__controls">
                  <button
                    type="button"
                    className="chat-home-zero-intent-composer__project"
                    data-home-intent-project={currentProject.id}
                    onClick={() => onRecentModeChange("projects")}
                  >
                    {renderIcon(Crosshair, { size: 15, strokeWidth: 1.8 })}
                    <span>Work in a project</span>
                    {renderIcon(ChevronDown, { size: 14, strokeWidth: 1.8 })}
                  </button>
                  <span className="chat-home-zero-intent-composer__spacer" />
                  <button
                    type="button"
                    className="chat-home-zero-intent-composer__add-context"
                    aria-label="Add context"
                    onClick={onOpenWorkspace}
                  >
                    +
                  </button>
                  <button
                    type="button"
                    className="chat-home-zero-intent-composer__model"
                    data-home-intent-model="default-model-route"
                    onClick={onOpenModels}
                  >
                    {renderIcon(Sparkles, { size: 15, strokeWidth: 1.8 })}
                    <span>5.5 Medium</span>
                    {renderIcon(ChevronDown, { size: 14, strokeWidth: 1.8 })}
                  </button>
                  <button
                    type="submit"
                    className="chat-home-zero-intent-composer__submit"
                    data-home-intent-submit="new-session"
                    aria-label="Start New Session"
                  >
                    {renderIcon(ArrowUp, { size: 16, strokeWidth: 2 })}
                  </button>
                </div>
              </div>
            </form>
            <div
              className="chat-home-zero-intent-composer__quickstarts"
              aria-label="Suggested intent templates"
            >
              {HOME_INTENT_QUICKSTARTS.map((quickstart) => (
                <button
                  type="button"
                  key={quickstart.label}
                  className={`chat-home-zero-intent-composer__quickstart chat-home-zero-intent-composer__quickstart--${quickstart.tone}`}
                  data-home-intent-recipe={quickstart.recipeId}
                  onClick={() => {
                    setIntentDraft(quickstart.seedIntent);
                    setIntentRecipeId(quickstart.recipeId);
                  }}
                >
                  <span
                    className="chat-home-zero-intent-composer__quickstart-icon"
                    aria-hidden="true"
                  >
                    {renderIcon(quickstart.icon, {
                      size: 14,
                      strokeWidth: 1.8,
                    })}
                  </span>
                  <span>{quickstart.label}</span>
                </button>
              ))}
            </div>
            <section
              className="chat-home-zero-recent-sessions"
              aria-label="Recent Sessions"
              data-home-reference-recent-sessions="true"
            >
              <h2>Recent Sessions</h2>
              <div>
                {HOME_REFERENCE_RECENT_SESSIONS.map((session) => (
                  <button
                    type="button"
                    key={session.title}
                    data-home-recent-session-status={session.status}
                    onClick={onOpenRuns}
                  >
                    <span
                      className="chat-home-zero-recent-sessions__dot"
                      aria-hidden="true"
                    />
                    <span className="chat-home-zero-recent-sessions__copy">
                      <strong>{session.title}</strong>
                      <em>{session.meta}</em>
                    </span>
                  </button>
                ))}
              </div>
            </section>
          </section>

          <div
            className="chat-home-zero-actions"
            aria-label="Suggested actions"
          >
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(SquareTerminal, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Get started</h2>
                <p>
                  Open a governed session with editor, terminal, model, and authority wired.
                </p>
              </div>
              <button type="button" onClick={onOpenWorkspace}>
                <span>Open workspace</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(Bot, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Install examples</h2>
                <p>
                  Start from reusable agents, automations, model mounts, and workspace templates.
                </p>
              </div>
              <button type="button" onClick={() => onOpenNewSession()}>
                <span>New session</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
            <article>
              <span className="chat-home-zero-action-icon">
                {renderIcon(FileCode2, { size: 23, strokeWidth: 1.8 })}
              </span>
              <div>
                <h2>Join community</h2>
                <p>Review runs, receipts, artifacts, adapters, and reusable worker packages.</p>
              </div>
              <button type="button" onClick={onOpenRuns}>
                <span>Open insights</span>
                {renderIcon(ArrowRight, { size: 15, strokeWidth: 2 })}
              </button>
            </article>
          </div>

          <section
            className="chat-home-zero-session-card"
            aria-label="New Session setup preview"
            data-home-new-session-contract="daemon-runtime"
          >
            <div className="chat-home-zero-session-card__copy">
              <span>New Session</span>
              <h2>Launch governed work through Hypervisor Core.</h2>
              <p>
                The launch contract binds harness selection, model route,
                privacy posture, wallet authority, and receipt preview before
                consequential execution.
              </p>
            </div>
            <div
              className="chat-home-zero-session-card__steps"
              aria-label="Required setup sections"
            >
              {newSessionRequiredSections.map((section) => (
                <span key={section.id}>{section.label}</span>
              ))}
            </div>
            <div
              className="chat-home-zero-session-card__harnesses"
              aria-label="Harness options"
            >
              {newSessionHarnessOptions.map((option) => {
                const verdict = buildHarnessCompatibilityVerdict(option, true);
                return (
                  <div key={getHarnessSelectionRef(option)}>
                    <strong>{option.label}</strong>
                    <span>{verdict.state.split("_").join(" ")}</span>
                  </div>
                );
              })}
            </div>
            <div
              className="chat-home-zero-session-card__comparison"
              aria-label="Harness comparison preview"
              data-home-harness-comparison-run={harnessComparison.run_id}
            >
              <div>
                <span>Comparison fixture</span>
                <strong>{harnessComparison.task_ref}</strong>
              </div>
              <div>
                <span>Mode</span>
                <strong>{harnessComparison.comparison_mode}</strong>
              </div>
              <div>
                <span>Candidates</span>
                <strong>{harnessComparison.candidate_selection_refs.length}</strong>
              </div>
              <div>
                <span>Receipt refs</span>
                <strong>{harnessComparison.receipt_refs.length}</strong>
              </div>
            </div>
            <div className="chat-home-zero-session-card__actions">
              <button type="button" onClick={() => onOpenNewSession()}>
                Start New Session
              </button>
              <button type="button" onClick={onOpenModels}>
                Configure Models
              </button>
              <button type="button" onClick={onOpenPolicy}>
                Review Authority
              </button>
            </div>
          </section>

          <section
            className="chat-home-zero-cockpit"
            aria-label="Hypervisor cockpit status"
            data-home-cockpit-projection={cockpitProjection.projection_id}
            data-home-cockpit-source={cockpitProjection.source}
            data-runtime-truth-source={cockpitProjection.runtimeTruthSource}
          >
            <div className="chat-home-zero-section-heading">
              <div>
                <h2>Core status</h2>
                <p>{cockpitProjection.boundary_invariant}</p>
              </div>
              <button type="button" onClick={onOpenRuns}>
                Open evidence
              </button>
            </div>
            <div className="chat-home-zero-cockpit-grid">
              {cockpitProjection.metrics.map((metric) => (
                <div
                  key={metric.metric_ref}
                  className="chat-home-zero-cockpit-card"
                  data-home-cockpit-metric={metric.metric_ref}
                  data-home-cockpit-surface={metric.surface_ref}
                >
                  <button
                    type="button"
                    className="chat-home-zero-cockpit-card__summary"
                    onClick={() => onOpenCockpitSurface(metric.surface_ref)}
                  >
                    <span>{metric.label}</span>
                    <strong>{metric.value}</strong>
                    <em>{metric.detail}</em>
                    <small>{metric.evidence_refs.slice(0, 2).join(" · ")}</small>
                  </button>
                  <div
                    className="chat-home-zero-cockpit-card__drill-refs"
                    aria-label={`${metric.label} drill-through refs`}
                  >
                    {metric.drill_refs.slice(0, 2).map((drillRef) => (
                      <button
                        type="button"
                        key={`${metric.metric_ref}:${drillRef.target_ref}`}
                        data-home-cockpit-drill-ref={drillRef.target_ref}
                        data-home-cockpit-drill-evidence={drillRef.evidence_ref}
                        data-home-cockpit-drill-surface={drillRef.surface_ref}
                        onClick={() => onOpenCockpitSurface(drillRef.surface_ref)}
                      >
                        <span>{drillRef.label}</span>
                        <em>{drillRef.target_ref}</em>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>
        </header>

        <div className="chat-home-zero-body">
          <main className="chat-home-zero-main">
            <section
              className="chat-home-zero-recent"
              aria-label="Recent resources"
            >
              <div className="chat-home-zero-section-heading">
                <h2>Recent</h2>
                <div
                  className="chat-home-zero-filter"
                  aria-label="Recent filter"
                >
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
              <div
                className="chat-home-zero-table"
                data-home-recent-mode={recentMode}
              >
                <div className="chat-home-zero-table-head">
                  <span>
                    {recentMode === "files" ? "File name" : "Project"}
                  </span>
                  <span>
                    {recentMode === "files" ? "Last updated" : "Scope"}
                  </span>
                </div>
                {recentMode === "projects" ? (
                  <div className="chat-home-zero-project-rows">
                    {projects.map((project) => (
                      <button
                        type="button"
                        key={project.id}
                        className={
                          project.id === currentProject.id ? "is-active" : ""
                        }
                        onClick={() => onSelectProject(project.id)}
                      >
                        <span>
                          <strong>{project.name}</strong>
                          <em>{project.description}</em>
                        </span>
                        <span>
                          {project.environment} · {project.rootPath}
                        </span>
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

            <section
              className="chat-home-zero-assist"
              aria-label="Hypervisor assistant"
            >
              <div>
                <h2>Operate this project with governed sessions</h2>
                <p>
                  {currentProject.name} · {setupStatus}
                </p>
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
                <button type="button" onClick={() => onOpenNewSession()}>
                  Start from intent...
                </button>
              </div>
              {renderIcon(Bot, {
                className: "chat-home-zero-assist-mark",
                size: 138,
                strokeWidth: 1.2,
              })}
            </section>
          </main>

          <aside
            className="chat-home-zero-sidebar"
            aria-label="Hypervisor surfaces"
          >
            <section className="chat-home-zero-side-card">
              <div className="chat-home-zero-side-header">
                <h2>Recommended applications</h2>
                <button type="button" onClick={onOpenCommandPalette}>
                  View all
                </button>
              </div>
              <div className="chat-home-zero-app-grid">
                {surfaces.map((surface) => (
                  <DashboardSurfaceButton key={surface.id} surface={surface} />
                ))}
              </div>
              <p>
                Pin the surfaces you use most from the activity bar. The
                runtime, evidence, and workbench share the same Hypervisor Core
                contract.
              </p>
            </section>

            <section className="chat-home-zero-side-card chat-home-zero-side-card--support">
              <h2>Get in touch</h2>
              <p>
                Use diagnostics when something looks off, or review setup again.
              </p>
              <button
                type="button"
                onClick={() => onOpenSettings("diagnostics")}
              >
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
                  <dd>
                    {notificationCount > 0
                      ? `${notificationCount} pending`
                      : "Clear"}
                  </dd>
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
          recentMode={recentMode}
          onRecentModeChange={setRecentMode}
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
