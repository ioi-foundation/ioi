import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "../../services/hypervisorHostBridge";
import { listen } from "../../services/hypervisorHostBridge";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "../../services/hypervisorHostBridge";
import type { WorkflowComposerPreflightSeed } from "@ioi/hypervisor-workbench";
import { bootstrapHypervisorSession, useHypervisorSessionStore } from "../../session/hypervisorSession";
import { listenForHypervisorDataReset } from "../../services/hypervisorReset";
import { safelyDisposeHostListener } from "../../services/hostListeners";
import {
  ackPendingHypervisorLaunchRequest,
  peekPendingHypervisorLaunchRequest,
  type PendingHypervisorLaunchEnvelope,
  recordHypervisorLaunchReceipt,
  summarizePendingHypervisorLaunchRequest,
} from "../../services/hypervisorLaunchState";
import type {
  AssistantNotificationRecord,
  AssistantUserProfile,
  ChatCapabilityDetailSection,
  InterventionRecord,
} from "../../types";
import {
  type CapabilityGovernanceRequest,
  fetchShieldPolicyStateFromRuntime,
  loadShieldPolicyState,
  persistShieldPolicyStateToRuntime,
  type ShieldPolicyState,
} from "../../surfaces/Policy/policyCenter";
import {
  DEFAULT_PROFILE,
  PROJECT_SCOPES,
  type PrimaryView,
  type ProjectScope,
} from "./hypervisorShellModel";
import {
  loadHypervisorLaunchedSessionProjections,
  mergeHypervisorLaunchedSessionProjection,
  persistHypervisorLaunchedSessionProjections,
} from "./hypervisorLaunchedSessionPersistence";
import {
  HYPERVISOR_DEFAULT_AGENT_SELECTION_REF,
  defaultHypervisorModelRefForHarness,
  getHypervisorModelOption,
} from "../../domain/harnessAdapterModel";
import {
  DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  buildHypervisorNewSessionLaunchRequest,
  buildHypervisorNewSessionLaunchSummary,
  buildHypervisorSessionLaunchRecipeAdmissionFailure,
  buildHypervisorSessionLaunchRecipeAdmissionRequest,
  buildHypervisorCodeEditorAdapterAdmissionFailure,
  buildHypervisorLaunchedSessionProjection,
  buildCodeEditorAdapterLaunchPlan,
  HYPERVISOR_CODE_EDITOR_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY,
  getCodeEditorAdapterPreferenceByRef,
  getCodeEditorAdapterPreferenceRef,
  isHypervisorSurfaceId,
  requestCodeEditorAdapterLaunchPlanAdmission,
  requestHypervisorSessionLaunchRecipeAdmission,
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchRequest,
} from "./hypervisorShellNavigationModel";
import {
  HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY,
  requestHypervisorSessionCreate,
} from "../../domain/hypervisorSessionOperationsModel";
import { shouldAttemptHypervisorDaemonProjectionFetch } from "./hypervisorDaemonEndpoint";
import type { CapabilitySurface } from "../../surfaces/Capabilities";
import type { SettingsSection } from "../../surfaces/Settings/settingsViewShared";
import {
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionOption,
  getHarnessSelectionRef,
  modelRouteSupportsHypervisorMountFromInventory,
} from "../../domain/harnessAdapterModel";
import type {
  HypervisorProjectStateProjection,
  HypervisorProjectStateRecord,
} from "./hypervisorProjectStateModel";

type ToastCandidate = Pick<
  InterventionRecord,
  "title" | "summary" | "reason" | "privacy"
> &
  Partial<
    Pick<
      InterventionRecord,
      "interventionType" | "sessionId" | "threadId" | "source"
    >
  >;

type NewSessionModalSeed =
  | string
  | {
      seedIntent?: string | null;
      recipeId?: string | null;
    }
  | null
  | undefined;
export interface HypervisorReceiptEvidenceTarget {
  source: "project" | "session" | "artifact" | "agent";
  projectId?: string | null;
  sessionRef?: string | null;
  receiptRef?: string | null;
}
const appliedHypervisorLaunchIds = new Set<string>();
const SCRATCH_PROJECT_SCOPE: ProjectScope = {
  id: "scratch:local",
  name: "From scratch",
  description: "Unscoped local session until a repository project is selected.",
  environment: "Local replay",
  rootPath: ".",
};

function projectScopeFromProjectStateRecord(
  record: HypervisorProjectStateRecord,
): ProjectScope {
  return {
    id: record.project_id,
    name: record.name,
    description:
      record.repository_url ??
      record.description ??
      "Repository-backed Hypervisor project.",
    environment: record.environment,
    rootPath: record.root_path || ".",
  };
}

function projectNameFromLaunchRequest(request: HypervisorNewSessionLaunchRequest): string {
  if (request.project_id.startsWith("url:")) {
    const leaf = request.project_id.split("-").filter(Boolean).at(-1);
    return leaf ? leaf.replace(/_/g, " ") : "URL session";
  }
  if (request.project_id.startsWith("scratch:")) {
    return "From scratch";
  }
  return request.project_id.replace(/^project:/, "").replace(/[-_]+/g, " ");
}

const HYPERVISOR_PATH_PRIMARY_VIEWS: readonly PrimaryView[] = [
  "home",
  "sessions",
  "projects",
  "applications",
  "missions",
  "workbench",
  "automations",
  "insights",
  "agents",
  "models",
  "privacy",
  "providers",
  "environments",
  "foundry",
  "authority",
  "receipts",
  "settings",
];

function isSupportedInitialPrimaryView(value: string | null): value is PrimaryView {
  return Boolean(
    value &&
      HYPERVISOR_PATH_PRIMARY_VIEWS.includes(value.toLowerCase() as PrimaryView),
  );
}

function resolvePathnamePrimaryView(pathname: string): PrimaryView | null {
  const segment = pathname
    .toLowerCase()
    .replace(/^\/+/, "")
    .split("/")[0]
    ?.trim();

  if (!segment) {
    return null;
  }

  if (segment === "ai") {
    return "home";
  }

  if (segment === "workspaces" || segment === "details" || segment === "logs") {
    return "sessions";
  }

  return isSupportedInitialPrimaryView(segment) ? segment : null;
}

function normalizeSettingsSection(value: string | null): SettingsSection | null {
  switch (value?.trim().toLowerCase().replace(/-/g, "_")) {
    case "account":
    case "identity":
    case "profile":
      return "identity";
    case "secret":
    case "secrets":
      return "secrets";
    case "git":
    case "git_auth":
    case "git_authentications":
      return "git_auth";
    case "pat":
    case "pats":
    case "personal_access_token":
    case "personal_access_tokens":
      return "personal_access_tokens";
    case "integration":
    case "integrations":
      return "integrations";
    default:
      return null;
  }
}

function resolveInitialSettingsSectionSeed(): SettingsSection | null {
  if (typeof window === "undefined") {
    return null;
  }

  const params = new URLSearchParams(window.location.search);
  return (
    normalizeSettingsSection(params.get("user-settings")) ??
    normalizeSettingsSection(params.get("settings"))
  );
}

function resolveInitialPrimaryView(): PrimaryView {
  if (typeof window !== "undefined") {
    const requested = new URLSearchParams(window.location.search).get("view");
    if (isSupportedInitialPrimaryView(requested)) {
      return requested;
    }

    if (resolveInitialSettingsSectionSeed()) {
      return "settings";
    }
  }

  const envRequestedView = (import.meta.env.VITE_HYPERVISOR_INITIAL_VIEW ?? "")
    .toString()
    .trim()
    .toLowerCase();
  if (isSupportedInitialPrimaryView(envRequestedView)) {
    return envRequestedView;
  }

  if (typeof window !== "undefined") {
    const pathnameView = resolvePathnamePrimaryView(window.location.pathname);
    if (pathnameView) {
      return pathnameView;
    }
  }

  return "home";
}

function waitForHypervisorSurfaceFrame(): Promise<void> {
  if (typeof window === "undefined") {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    const timeoutId = window.setTimeout(finish, 48);
    window.requestAnimationFrame(() => {
      window.clearTimeout(timeoutId);
      finish();
    });
  });
}

async function sendNativeHypervisorNotification(
  candidate: ToastCandidate,
): Promise<void> {
  if (
    candidate.source?.serviceName === "Hypervisor" &&
    candidate.source.workflowName === "workflow" &&
    (candidate.sessionId || candidate.threadId)
  ) {
    return;
  }

  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (!granted) return;

    const body =
      candidate.privacy.previewMode === "redacted" &&
      candidate.privacy.containsSensitiveData
        ? candidate.reason?.trim() || "Open Hypervisor for details."
        : candidate.summary;

    await sendNotification({
      title: candidate.title,
      body,
    });
  } catch {
    // Native notification delivery is best-effort.
  }
}

function isHypervisorClientRuntime(): boolean {
  return typeof window !== "undefined" && "__HYPERVISOR_HOST_BRIDGE__" in window;
}

function hypervisorBrowserStorage(): Storage | null {
  return typeof window !== "undefined" ? window.localStorage : null;
}

export function useHypervisorShellController() {
  const [activeView, setActiveView] = useState<PrimaryView>(resolveInitialPrimaryView);
  const [focusedPolicyConnectorId, setFocusedPolicyConnectorId] = useState<
    string | null
  >(null);
  const [capabilityGovernanceRequest, setCapabilityGovernanceRequest] =
    useState<CapabilityGovernanceRequest | null>(null);
  const [notificationBadgeCount, setNotificationBadgeCount] = useState(0);
  const [shieldPolicy, setShieldPolicy] = useState<ShieldPolicyState>(() =>
    loadShieldPolicyState(),
  );
  const [profile, setProfile] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileDraft, setProfileDraft] =
    useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [shieldPolicyHydrated, setShieldPolicyHydrated] = useState(false);
  const [currentProjectId, setCurrentProjectId] = useState("");
  const [repositoryProjectScopes, setRepositoryProjectScopes] = useState<
    ProjectScope[]
  >([]);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [commandPaletteMode, setCommandPaletteMode] =
    useState<"default" | "tools">("default");
  const [commandPaletteInitialQuery, setCommandPaletteInitialQuery] = useState("");
  const [newSessionModalOpen, setNewSessionModalOpen] = useState(false);
  const [newSessionSeedIntent, setNewSessionSeedIntent] = useState<string | null>(
    null,
  );
  const [newSessionRecipeId, setNewSessionRecipeId] = useState<string | null>(
    null,
  );
  const [selectedAgentSelectionRef, setSelectedAgentSelectionRef] = useState(
    HYPERVISOR_DEFAULT_AGENT_SELECTION_REF,
  );
  const [selectedModelRef, setSelectedModelRef] = useState(() =>
    defaultHypervisorModelRefForHarness(HYPERVISOR_DEFAULT_AGENT_SELECTION_REF),
  );

  // Harness and model are orthogonal selections; changing the harness resets the
  // model to that harness's default lane (its model options are harness-scoped).
  const selectAgentHarness = (harnessSelectionRef: string) => {
    setSelectedAgentSelectionRef(harnessSelectionRef);
    setSelectedModelRef(
      defaultHypervisorModelRefForHarness(harnessSelectionRef),
    );
  };
  const [launchedSessionProjections, setLaunchedSessionProjections] = useState<
    HypervisorLaunchedSessionProjection[]
  >(() => {
    return loadHypervisorLaunchedSessionProjections({
      storage: hypervisorBrowserStorage(),
    });
  });
  const [capabilitiesSurfaceSeed, setCapabilitiesSurfaceSeed] =
    useState<CapabilitySurface | null>(null);
  const [capabilitiesTargetConnectorId, setCapabilitiesTargetConnectorId] =
    useState<string | null>(null);
  const [capabilitiesTargetDetailSection, setCapabilitiesTargetDetailSection] =
    useState<ChatCapabilityDetailSection | null>(null);
  const [settingsSectionSeed, setSettingsSectionSeed] =
    useState<SettingsSection | null>(resolveInitialSettingsSectionSeed);
  const [workflowPreflightSeed, setWorkflowPreflightSeed] =
    useState<WorkflowComposerPreflightSeed | null>(null);
  const [receiptEvidenceTarget, setReceiptEvidenceTarget] =
    useState<HypervisorReceiptEvidenceTarget | null>(null);

  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );
  const hypervisorLaunchHydrationInFlightRef = useRef(false);
  const lastAppliedHypervisorLaunchIdRef = useRef<string | null>(null);
  const hypervisorHarnessTerminalPollingRef = useRef<Set<string>>(new Set());
  const hypervisorHarnessTerminalPollingCancelledRef = useRef(false);

  const currentProject =
    repositoryProjectScopes.find((project) => project.id === currentProjectId) ??
    repositoryProjectScopes[0] ??
    SCRATCH_PROJECT_SCOPE;

  const openRequestedSurface = (view: string) => {
    if (isHypervisorSurfaceId(view)) {
      setActiveView(view);
      return;
    }

    switch (view) {
      case "reply-composer":
        setActiveView("missions");
        return;
      case "meeting-prep":
        setActiveView("missions");
        return;
      case "catalog":
        setActiveView("agents");
        return;
      default:
        setActiveView("sessions");
    }
  };

  const openCapabilityTarget = (
    connectorId?: string | null,
    detailSection?: ChatCapabilityDetailSection | null,
  ) => {
    const resolvedConnectorId = connectorId ?? null;
    setCapabilitiesTargetConnectorId(resolvedConnectorId);
    setCapabilitiesTargetDetailSection(resolvedConnectorId ? "setup" : null);
    if (detailSection) {
      setCapabilitiesTargetDetailSection(detailSection);
    }
    setCapabilitiesSurfaceSeed("connections");
    setActiveView("agents");
  };

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setActiveView("authority");
  };

  const dismissCapabilityGovernanceRequest = () => {
    setCapabilityGovernanceRequest(null);
    void invoke("clear_capability_governance_request");
  };

  const applyCapabilityGovernanceRequest = (next: ShieldPolicyState) => {
    setShieldPolicy(next);
    setCapabilityGovernanceRequest(null);
    void invoke("clear_capability_governance_request");
  };

  const openHypervisorSessionWithIntent = (intent: string) => {
    setNewSessionSeedIntent(intent);
    setNewSessionRecipeId("mission.default");
    setNewSessionModalOpen(true);
    setActiveView("sessions");
  };

  const registerProjectStateProjection = useCallback((
    projection: HypervisorProjectStateProjection,
  ) => {
    const nextProjectScopes = projection.records.map(
      projectScopeFromProjectStateRecord,
    );
    setRepositoryProjectScopes(nextProjectScopes);
    setCurrentProjectId((current) => {
      if (current && nextProjectScopes.some((project) => project.id === current)) {
        return current;
      }
      return projection.selected_project_id || nextProjectScopes[0]?.id || "";
    });
  }, []);


  const launchNewSession = async (
    request: HypervisorNewSessionLaunchRequest,
  ): Promise<HypervisorLaunchedSessionProjection | null> => {
    // Inline-first launches use policy-safe defaults, but governance still gates:
    // if the requested harness/model/privacy combination is not a safe admitted
    // route, step up into the Configure/Advanced surface with the reason surfaced
    // instead of silently launching or silently downgrading the posture.
    const inlineVerdictState = request.launch_summary.harness_verdict_state;
    if (
      inlineVerdictState === "blocked" ||
      inlineVerdictState === "local_route_unavailable"
    ) {
      setNewSessionSeedIntent(request.seed_intent);
      setNewSessionRecipeId(request.recipe_id);
      setNewSessionModalOpen(true);
      setActiveView("sessions");
      await recordHypervisorLaunchReceipt(
        "hypervisor_inline_launch_stepped_up_to_advanced",
        {
          harnessVerdict: inlineVerdictState,
          harnessSelectionRef: request.harness_selection_ref,
          modelRouteRef: request.model_route_ref,
          privacyPostureRef: request.privacy_posture_ref,
        },
      );
      return null;
    }
    const recipe =
      HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
        (candidate) => candidate.recipe_id === request.recipe_id,
      ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
    const project =
      repositoryProjectScopes.find(
        (candidate) => candidate.id === request.project_id,
      ) ??
      PROJECT_SCOPES.find((candidate) => candidate.id === request.project_id) ?? {
        ...SCRATCH_PROJECT_SCOPE,
        id: request.project_id,
        name:
          request.project_context?.project_label ??
          projectNameFromLaunchRequest(request),
        rootPath: request.project_context?.root_path || ".",
      };
    const codeEditorAdapter = getCodeEditorAdapterPreferenceByRef(
      request.adapter_preference_ref,
    );
    const codeEditorAdapterLaunchPlan =
      buildCodeEditorAdapterLaunchPlan(codeEditorAdapter);
    const codeEditorAdapterAdmission =
      shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_CODE_EDITOR_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY,
      )
        ? await requestCodeEditorAdapterLaunchPlanAdmission(
            codeEditorAdapterLaunchPlan,
          ).catch((error: unknown) =>
            buildHypervisorCodeEditorAdapterAdmissionFailure({
              error,
              launchPlan: codeEditorAdapterLaunchPlan,
            }),
          )
        : buildHypervisorCodeEditorAdapterAdmissionFailure({
            error: new Error(
              "Attach a Hypervisor Daemon endpoint before requesting code-editor adapter launch admission.",
            ),
            launchPlan: codeEditorAdapterLaunchPlan,
          });
    const sessionLaunchRecipeAdmissionRequest =
      buildHypervisorSessionLaunchRecipeAdmissionRequest({
        recipe,
        launchSummary: request.launch_summary,
      });
    const sessionLaunchRecipeAdmission =
      shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_CODE_EDITOR_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY,
      )
        ? await requestHypervisorSessionLaunchRecipeAdmission(
            sessionLaunchRecipeAdmissionRequest,
          ).catch((error: unknown) =>
            buildHypervisorSessionLaunchRecipeAdmissionFailure({
              request: sessionLaunchRecipeAdmissionRequest,
              error,
            }),
          )
        : buildHypervisorSessionLaunchRecipeAdmissionFailure({
            request: sessionLaunchRecipeAdmissionRequest,
            error: new Error(
              "Attach a Hypervisor Daemon endpoint before requesting session launch recipe admission.",
            ),
          });
    // Provision the real Rust session (Lane A). The Rust hypervisor-daemon owns
    // workspace provisioning + the wallet-gated host-spawn lane + the served
    // preview; the cockpit subscribes the returned session_ref's /events stream
    // for the real environment_status / terminal / diffs / ports / receipts. The
    // retired JS harness launch/spawn/readiness/terminal-attach chain is gone.
    const hypervisorSession =
      sessionLaunchRecipeAdmission.decision === "admitted" &&
      shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY,
      )
        ? await requestHypervisorSessionCreate({
            project_ref: request.project_id,
            workspace_mount_policy: "public_trunk",
          }).catch((error: unknown) => {
            void recordHypervisorLaunchReceipt("hypervisor_session_create_failed", {
              projectRef: request.project_id,
              error: error instanceof Error ? error.message : String(error ?? ""),
            });
            return null;
          })
        : null;

    const launchedSession = buildHypervisorLaunchedSessionProjection({
      request,
      recipe,
      projectLabel: project.name,
      codeEditorAdapterAdmission,
      sessionLaunchRecipeAdmission,
      hypervisorSession,
      displayMeta: {
        branchLabel: "master",
        relativeTimeLabel: "Starting...",
        activityCount: 0,
      },
    });

    setCurrentProjectId(project.id);
    setNewSessionModalOpen(false);
    setNewSessionSeedIntent(null);
    setNewSessionRecipeId(null);
    setLaunchedSessionProjections((current) => {
      const next = mergeHypervisorLaunchedSessionProjection(
        current,
        launchedSession,
      );
      persistHypervisorLaunchedSessionProjections({
        storage: hypervisorBrowserStorage(),
        projections: next,
      });
      return next;
    });

    setActiveView(recipe.surface_id);
    return launchedSession;
  };

  const startInlineSession = (
    seedIntent: string | null,
    options?: { harnessSelectionRef?: string; recipeId?: string | null },
  ): Promise<HypervisorLaunchedSessionProjection | null> => {
    const project = currentProject;
    const recipeId =
      options?.recipeId && options.recipeId !== "ioi-reference-home"
        ? options.recipeId
        : undefined;
    const harnessSelectionRef =
      options?.harnessSelectionRef ?? selectedAgentSelectionRef;
    const modelOption = getHypervisorModelOption(
      harnessSelectionRef,
      selectedModelRef,
    );
    const request = buildHypervisorNewSessionLaunchRequest({
      seedIntent,
      recipeId,
      project: {
        id: project.id,
        name: project.name,
        rootPath: project.rootPath,
      },
      harnessSelectionRef,
      modelRouteRef: modelOption.model_route_ref,
      modelName: modelOption.model_name,
    });
    setActiveView("sessions");
    return launchNewSession(request);
  };

  const launchProjectSession = async (
    projectRecord: HypervisorProjectStateRecord,
  ): Promise<HypervisorLaunchedSessionProjection | null> => {
    const projectScope = projectScopeFromProjectStateRecord(projectRecord);
    setRepositoryProjectScopes((current) => {
      const withoutProject = current.filter(
        (project) => project.id !== projectScope.id,
      );
      return [projectScope, ...withoutProject];
    });
    const recipe =
      HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
        (candidate) => candidate.recipe_id === "mission.default",
      ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
    const harnessAdapterId =
      HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS[0] ?? "codex_cli";
    const harnessSelectionRef = `agent-harness-adapter:${harnessAdapterId}`;
    const selectedHarness = getHarnessSelectionOption(harnessSelectionRef);
    const selectedAdapterPreference = getCodeEditorAdapterPreferenceByRef(
      projectRecord.adapter_preference_ref || DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
    );
    const modelRouteRef = HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF;
    const privacyPostureRef = "privacy:redacted-projection";
    const modelRouteAvailability =
      modelRouteSupportsHypervisorMountFromInventory(
        modelRouteRef,
        HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
      );
    const harnessVerdict = buildHarnessCompatibilityVerdict(
      selectedHarness,
      modelRouteAvailability.available,
      privacyPostureRef,
    );
    const seedIntent = `Start ${projectRecord.repository_branch ?? "master"} in ${projectRecord.name}`;
    const receiptPreviewRef = [
      "receipt-preview:new-session",
      recipe.recipe_id,
      projectRecord.project_id,
      "project-click",
      DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
      getHarnessSelectionRef(selectedHarness),
    ].join("/");
    const launchSummary = buildHypervisorNewSessionLaunchSummary({
      recipe,
      seedIntent,
      projectId: projectRecord.project_id,
      codeEditorAdapter: selectedAdapterPreference,
      harness: selectedHarness,
      harnessVerdict,
      modelRouteAvailability,
      modelRouteRef,
      privacyPostureRef,
      authorityScopeRefs: recipe.authority_scope_templates,
      receiptPreviewRef,
    });

    return launchNewSession({
      recipe_id: recipe.recipe_id,
      seed_intent: seedIntent,
      project_id: projectRecord.project_id,
      adapter_preference_ref: getCodeEditorAdapterPreferenceRef(
        selectedAdapterPreference,
      ),
      harness_selection_ref: harnessSelectionRef,
      model_route_ref: modelRouteRef,
      privacy_posture_ref: privacyPostureRef,
      authority_scope_refs: recipe.authority_scope_templates,
      receipt_preview_ref: receiptPreviewRef,
      launch_summary: launchSummary,
      project_context: {
        schema_version: "ioi.hypervisor.new_session_project_context.v1",
        project_label: projectRecord.name,
        root_path: projectRecord.root_path || ".",
        repository_url: projectRecord.repository_url ?? null,
        repository_branch: projectRecord.repository_branch ?? "master",
        runtimeTruthSource: "daemon-runtime",
      },
      model_garden_configuration: {
        schema_version: "ioi.hypervisor.session_model_garden_configuration.v1",
        configuration_ref: `model-garden:${harnessAdapterId}/qwen`,
        model_name: "qwen",
        model_route_ref: modelRouteRef,
        endpoint_ref: "model-endpoint:hypervisor/default-local",
        provider_ref: "provider:hypervisor-local",
        custody_posture: "local_model_mount",
        runtimeTruthSource: "daemon-runtime",
      },
    });
  };

  const applyPendingHypervisorLaunchRequest = async (
    pendingLaunch: PendingHypervisorLaunchEnvelope | null,
    source: string,
  ) => {
    if (!pendingLaunch) {
      return;
    }

    const { launchId, request: pendingRequest } = pendingLaunch;
    if (appliedHypervisorLaunchIds.has(launchId)) {
      await recordHypervisorLaunchReceipt("hypervisor_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingHypervisorLaunchRequest(pendingRequest),
      });
      await ackPendingHypervisorLaunchRequest(launchId);
      return;
    }
    if (lastAppliedHypervisorLaunchIdRef.current === launchId) {
      await recordHypervisorLaunchReceipt("hypervisor_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingHypervisorLaunchRequest(pendingRequest),
      });
      await ackPendingHypervisorLaunchRequest(launchId);
      return;
    }

    const claimedLaunch = await ackPendingHypervisorLaunchRequest(launchId);
    if (!claimedLaunch) {
      await recordHypervisorLaunchReceipt("hypervisor_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingHypervisorLaunchRequest(pendingRequest),
        reason: "launch_already_claimed",
      });
      return;
    }

    appliedHypervisorLaunchIds.add(launchId);
    lastAppliedHypervisorLaunchIdRef.current = launchId;
    await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applying", {
      source,
      launchId,
      kind: pendingRequest.kind,
      request: summarizePendingHypervisorLaunchRequest(pendingRequest),
    });

    try {
      switch (pendingRequest.kind) {
        case "view":
          openRequestedSurface(pendingRequest.view);
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            view: pendingRequest.view,
          });
          return;
        case "session-target":
          await openSessionTarget(pendingRequest.sessionId);
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            sessionId: pendingRequest.sessionId,
          });
          return;
        case "artifact":
          setReceiptEvidenceTarget({
            source: "artifact",
            receiptRef: pendingRequest.artifactId,
          });
          setActiveView("receipts");
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            artifactId: pendingRequest.artifactId,
            target: "receipts",
          });
          return;
        case "capability":
          openCapabilityTarget(
            pendingRequest.connectorId ?? null,
            pendingRequest.detailSection ?? null,
          );
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
            detailSection: pendingRequest.detailSection ?? null,
          });
          return;
        case "policy":
          openPolicyCenter(pendingRequest.connectorId ?? null);
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
          });
          return;
        case "hypervisor-intent":
          if (pendingRequest.sessionId) {
            await bootstrapHypervisorSession({
              refreshCurrentTask: false,
            });
            setActiveView("sessions");
            await waitForHypervisorSurfaceFrame();
            await recordHypervisorLaunchReceipt(
              "hypervisor_session_followup_submit_dispatching",
              {
                source,
                launchId,
                sessionId: pendingRequest.sessionId,
                intentLength: pendingRequest.intent.length,
              },
            );
            await invoke("continue_task", {
              sessionId: pendingRequest.sessionId,
              userInput: pendingRequest.intent,
            });
            void openSessionTarget(pendingRequest.sessionId).catch((error) => {
              console.error(
                "[Hypervisor][Launch] retained session reopen after direct follow-up submit failed",
                error,
              );
            });
            await recordHypervisorLaunchReceipt(
              "hypervisor_session_followup_submit_resolved",
              {
                source,
                launchId,
                sessionId: pendingRequest.sessionId,
                intentLength: pendingRequest.intent.length,
              },
            );
            await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
              source,
              launchId,
              kind: pendingRequest.kind,
              intent: pendingRequest.intent,
              sessionId: pendingRequest.sessionId,
              submissionMode: "direct_continue_task",
            });
            return;
          }
          openHypervisorSessionWithIntent(pendingRequest.intent);
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            intent: pendingRequest.intent,
            sessionId: pendingRequest.sessionId ?? null,
            submissionMode: "seed_intent",
          });
          return;
        case "assistant-workbench":
          setActiveView("missions");
          await recordHypervisorLaunchReceipt("hypervisor_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            sessionKind: pendingRequest.session.kind,
            target: "missions",
          });
          return;
        default:
          return;
      }
    } catch (error) {
      appliedHypervisorLaunchIds.delete(launchId);
      lastAppliedHypervisorLaunchIdRef.current = null;
      await recordHypervisorLaunchReceipt("hypervisor_pending_launch_failed", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingHypervisorLaunchRequest(pendingRequest),
        error: error instanceof Error ? error.message : String(error ?? ""),
      });
    }
  };

  const hydratePendingHypervisorLaunchRequestIfPresent = async (source: string) => {
    if (hypervisorLaunchHydrationInFlightRef.current) {
      return;
    }
    hypervisorLaunchHydrationInFlightRef.current = true;

    try {
      const pendingLaunch = await peekPendingHypervisorLaunchRequest();
      if (!pendingLaunch) {
        await recordHypervisorLaunchReceipt("hypervisor_pending_launch_empty", {
          source,
        });
        return;
      }
      await applyPendingHypervisorLaunchRequest(pendingLaunch, source);
    } finally {
      hypervisorLaunchHydrationInFlightRef.current = false;
    }
  };

  useEffect(() => {
    hypervisorHarnessTerminalPollingCancelledRef.current = false;
    return () => {
      hypervisorHarnessTerminalPollingCancelledRef.current = true;
      hypervisorHarnessTerminalPollingRef.current.clear();
    };
  }, []);

  useEffect(() => {
    let active = true;
    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<PendingHypervisorLaunchEnvelope>("request-hypervisor-launch", (event) => {
          if (!active) {
            return;
          }
          void recordHypervisorLaunchReceipt("hypervisor_launch_event_received", {
            launchId: event.payload.launchId,
            kind: event.payload.request.kind,
            request: summarizePendingHypervisorLaunchRequest(event.payload.request),
          });
          void applyPendingHypervisorLaunchRequest(event.payload, "event");
        })
      : null;

    return () => {
      active = false;
      safelyDisposeHostListener(unlistenPromise);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    void invoke<AssistantUserProfile>("assistant_user_profile_get")
      .then((loadedProfile) => {
        if (cancelled) return;
        setProfile(loadedProfile);
        setProfileDraft(loadedProfile);
      })
      .catch(() => {
        // Best-effort bootstrap only.
      });

    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<AssistantUserProfile>("assistant-user-profile-updated", (event) => {
          if (cancelled) return;
          setProfile(event.payload);
          setProfileDraft(event.payload);
        })
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(unlistenPromise);
    };
  }, []);

  useEffect(() => {
    const resetUnlistenPromise = listenForHypervisorDataReset();

    return () => {
      safelyDisposeHostListener(resetUnlistenPromise);
    };
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      setCommandPaletteMode("default");
      setCommandPaletteInitialQuery("");
      setCommandPaletteOpen((open) => !open);
    };

    window.addEventListener("keydown", handler, true);
    return () => window.removeEventListener("keydown", handler, true);
  }, []);

  useEffect(() => {
    let cancelled = false;

    void invoke<number>("notification_badge_count_get")
      .then((count) => {
        if (!cancelled) {
          setNotificationBadgeCount(count);
        }
      })
      .catch(() => {
        // Best-effort bootstrap only.
      });

    const badgeUnlistenPromise = isHypervisorClientRuntime()
      ? listen<number>("notifications-badge-updated", (event) => {
          setNotificationBadgeCount(event.payload);
        })
      : null;
    const interventionToastUnlistenPromise = isHypervisorClientRuntime()
      ? listen<InterventionRecord>("intervention-toast-candidate", (event) => {
          void sendNativeHypervisorNotification(event.payload);
        })
      : null;
    const assistantToastUnlistenPromise = isHypervisorClientRuntime()
      ? listen<AssistantNotificationRecord>(
          "assistant-notification-toast-candidate",
          (event) => {
            void sendNativeHypervisorNotification(event.payload);
          },
        )
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(badgeUnlistenPromise);
      safelyDisposeHostListener(interventionToastUnlistenPromise);
      safelyDisposeHostListener(assistantToastUnlistenPromise);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    fetchShieldPolicyStateFromRuntime()
      .then((nextPolicy) => {
        if (cancelled) return;
        const serialized = JSON.stringify(nextPolicy);
        lastPersistedShieldPolicyRef.current = serialized;
        setShieldPolicy(nextPolicy);
      })
      .finally(() => {
        if (!cancelled) {
          setShieldPolicyHydrated(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    void invoke<CapabilityGovernanceRequest | null>(
      "get_capability_governance_request",
    )
      .then((request) => {
        if (!cancelled) {
          setCapabilityGovernanceRequest(request);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setCapabilityGovernanceRequest(null);
        }
      });

    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<CapabilityGovernanceRequest | null>(
          "capability-governance-request-updated",
          (event) => {
            if (!cancelled) {
              setCapabilityGovernanceRequest(event.payload);
            }
          },
        )
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(unlistenPromise);
    };
  }, []);

  useEffect(() => {
    if (!shieldPolicyHydrated) return;

    const serialized = JSON.stringify(shieldPolicy);
    if (serialized === lastPersistedShieldPolicyRef.current) {
      return;
    }

    let cancelled = false;
    persistShieldPolicyStateToRuntime(shieldPolicy).then((nextPolicy) => {
      if (cancelled) return;
      const nextSerialized = JSON.stringify(nextPolicy);
      lastPersistedShieldPolicyRef.current = nextSerialized;
      if (nextSerialized !== serialized) {
        setShieldPolicy(nextPolicy);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [shieldPolicy, shieldPolicyHydrated]);

  const changePrimaryView = (view: PrimaryView) => {
    if (view !== "receipts") {
      setReceiptEvidenceTarget(null);
    }
    setActiveView(view);
  };

  const openReceiptEvidenceTarget = (target: HypervisorReceiptEvidenceTarget) => {
    if (target.projectId) {
      setCurrentProjectId(target.projectId);
    }
    setReceiptEvidenceTarget(target);
    setActiveView("receipts");
  };

  const openSettingsSection = (section: SettingsSection | null = null) => {
    setSettingsSectionSeed(section);
    setActiveView("settings");
  };

  const openCapabilitiesSurface = (surface: CapabilitySurface | null = null) => {
    setCapabilitiesTargetConnectorId(null);
    setCapabilitiesTargetDetailSection(null);
    setCapabilitiesSurfaceSeed(surface);
    setActiveView("agents");
  };

  const openWorkflowPreflight = (
    seed: WorkflowComposerPreflightSeed | null = { panel: "readiness" },
  ) => {
    setWorkflowPreflightSeed(seed ?? { panel: "readiness" });
    setActiveView("automations");
  };

  const openSessionTarget = async (sessionId: string) => {
    await bootstrapHypervisorSession({
      refreshCurrentTask: false,
    });
    const store = useHypervisorSessionStore.getState();
    await store.loadSession(sessionId);
    await store.refreshSessionHistory();
    setActiveView("sessions");
  };

  useEffect(() => {
    let cancelled = false;

    void hydratePendingHypervisorLaunchRequestIfPresent("mount").then(() => {
      if (cancelled) {
        return;
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  const updateProfileDraft = <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => {
    setProfileDraft((current) => ({
      ...current,
      [key]: value,
    }));
  };

  const resetProfileDraft = () => {
    setProfileDraft(profile);
    setProfileError(null);
  };

  const saveProfileDraft = async () => {
    setProfileSaving(true);
    setProfileError(null);

    try {
      const savedProfile = await invoke<AssistantUserProfile>(
        "assistant_user_profile_set",
        {
          profile: {
            ...profileDraft,
            groundingAllowed: false,
          },
        },
      );
      setProfile(savedProfile);
      setProfileDraft(savedProfile);
    } catch (nextError) {
      setProfileError(String(nextError));
    } finally {
      setProfileSaving(false);
    }
  };

  return {
    activeView,
    notificationBadgeCount,
    currentProjectId,
    currentProject,
    projects: repositoryProjectScopes,
    projectState: {
      registerProjection: registerProjectStateProjection,
      launchProjectSession,
    },
    changePrimaryView,
    workflow: {
      openPreflight: openWorkflowPreflight,
      selectProject: setCurrentProjectId,
      preflightSeed: workflowPreflightSeed,
      consumePreflightSeed: () => setWorkflowPreflightSeed(null),
    },
    sessions: {
      launchedSessionProjections,
      selectedAgentRef: selectedAgentSelectionRef,
      selectAgent: selectAgentHarness,
      selectedModelRef,
      selectModel: setSelectedModelRef,
      startInlineSession,
    },
    receipts: {
      target: receiptEvidenceTarget,
      openTarget: openReceiptEvidenceTarget,
      clearTarget: () => setReceiptEvidenceTarget(null),
    },
    policy: {
      shieldPolicy,
      setShieldPolicy,
      governanceRequest: capabilityGovernanceRequest,
      focusedConnectorId: focusedPolicyConnectorId,
      focusConnector: setFocusedPolicyConnectorId,
      openPolicyCenter,
      dismissGovernanceRequest: dismissCapabilityGovernanceRequest,
      applyGovernanceRequest: applyCapabilityGovernanceRequest,
    },
    capabilities: {
      seedSurface: capabilitiesSurfaceSeed,
      targetConnectorId: capabilitiesTargetConnectorId,
      targetDetailSection: capabilitiesTargetDetailSection,
      openSurface: openCapabilitiesSurface,
      consumeSeedSurface: () => setCapabilitiesSurfaceSeed(null),
      consumeTarget: () => {
        setCapabilitiesTargetConnectorId(null);
        setCapabilitiesTargetDetailSection(null);
      },
    },
    settings: {
      seedSection: settingsSectionSeed,
      openSection: openSettingsSection,
      consumeSeedSection: () => setSettingsSectionSeed(null),
    },
    profile: {
      value: profile,
      draft: profileDraft,
      saving: profileSaving,
      error: profileError,
      updateDraft: updateProfileDraft,
      resetDraft: resetProfileDraft,
      saveDraft: saveProfileDraft,
    },
    modals: {
      commandPaletteOpen,
      commandPaletteMode,
      commandPaletteInitialQuery,
      openCommandPalette: (
        initialQuery = "",
        mode: "default" | "tools" = "default",
      ) => {
        setCommandPaletteMode(mode);
        setCommandPaletteInitialQuery(initialQuery);
        setCommandPaletteOpen(true);
      },
      closeCommandPalette: () => setCommandPaletteOpen(false),
      newSessionModalOpen,
      newSessionSeedIntent,
      newSessionRecipeId,
      openNewSessionModal: (seed?: NewSessionModalSeed) => {
        const seedIntent =
          typeof seed === "string" ? seed : seed?.seedIntent ?? null;
        const recipeId = typeof seed === "object" ? seed?.recipeId ?? null : null;
        const normalizedSeed =
          typeof seedIntent === "string" && seedIntent.trim()
            ? seedIntent.trim()
            : null;
        // Reference parity: starting a session no longer pops a separate
        // configuration window. A seeded intent launches inline on the Sessions
        // surface; an empty New Session just focuses the inline composer.
        if (normalizedSeed) {
          void startInlineSession(normalizedSeed, { recipeId });
          return;
        }
        setActiveView("sessions");
      },
      openNewSessionModalAdvanced: (seed?: NewSessionModalSeed) => {
        const seedIntent =
          typeof seed === "string" ? seed : seed?.seedIntent ?? null;
        const recipeId = typeof seed === "object" ? seed?.recipeId ?? null : null;
        setNewSessionSeedIntent(
          typeof seedIntent === "string" && seedIntent.trim()
            ? seedIntent.trim()
            : null,
        );
        setNewSessionRecipeId(
          typeof recipeId === "string" && recipeId.trim() ? recipeId.trim() : null,
        );
        setNewSessionModalOpen(true);
      },
      closeNewSessionModal: () => {
        setNewSessionModalOpen(false);
        setNewSessionSeedIntent(null);
        setNewSessionRecipeId(null);
      },
      launchNewSession,
    },
  };
}
