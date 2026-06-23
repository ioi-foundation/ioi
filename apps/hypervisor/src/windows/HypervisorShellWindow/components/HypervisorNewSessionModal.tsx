import { useEffect, useMemo, useState } from "react";

import {
  DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
  HYPERVISOR_NEW_SESSION_SETUP_MODEL,
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  buildHypervisorNewSessionLaunchSummary,
  getCodeEditorAdapterPreferenceByRef,
  getCodeEditorAdapterPreferenceRef,
  type HypervisorNewSessionLaunchRequest,
} from "../hypervisorShellNavigationModel";
import {
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS,
  HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionOption,
  getHarnessSelectionRef,
  isAgentHarnessAdapterOption,
  modelRouteSupportsHypervisorMountFromInventory,
  type HypervisorModelMountInventorySnapshot,
} from "../../../domain/harnessAdapterModel";

type SessionStartMode = "project" | "url" | "scratch";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface HypervisorNewSessionModalProps {
  isOpen: boolean;
  currentProject: ProjectScope;
  projects: ProjectScope[];
  modelMountInventory?: HypervisorModelMountInventorySnapshot;
  initialSeedIntent?: string | null;
  initialRecipeId?: string | null;
  onClose: () => void;
  onLaunch: (request: HypervisorNewSessionLaunchRequest) => Promise<unknown> | unknown;
}

const SCRATCH_PROJECT_SCOPE: ProjectScope = {
  id: "scratch:local",
  name: "From scratch",
  description: "Unscoped local session until a repository project is selected.",
  environment: "Local replay",
  rootPath: ".",
};

const MODEL_ROUTE_OPTIONS = [
  {
    ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    label: HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION.label,
    detail: HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION.description,
  },
  {
    ref: "model-route:adapter-native",
    label: "Adapter-native route",
    detail: "Disclosed provider-trust or harness-native model lane.",
  },
  {
    ref: "model-route:none",
    label: "No model required",
    detail: "Infrastructure or deterministic-only setup.",
  },
];

const PRIVACY_OPTIONS = [
  {
    ref: "privacy:redacted-projection",
    label: "Redacted projection",
    detail: "Adapters receive public trunk and redacted workspace context.",
  },
  {
    ref: "privacy:public-trunk",
    label: "Public trunk",
    detail: "Only non-sensitive files, kernels, or provider-safe inputs.",
  },
  {
    ref: "privacy:ctee-private-workspace",
    label: "cTEE private workspace",
    detail: "Protected state stays encrypted, redacted, or locally guarded.",
  },
];

const SESSION_START_CHOICES: Array<{
  id: SessionStartMode;
  label: string;
  tone: "project" | "url" | "scratch";
}> = [
  { id: "project", label: "Start from project", tone: "project" },
  { id: "url", label: "Start from URL", tone: "url" },
  { id: "scratch", label: "Start from scratch", tone: "scratch" },
];

function defaultHarnessSelectionRef(): string {
  const firstSessionAdapterId = HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS[0];
  if (firstSessionAdapterId) {
    return `agent-harness-adapter:${firstSessionAdapterId}`;
  }
  const option = HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions[0];
  return option ? getHarnessSelectionRef(option) : "harness-profile:default_harness_profile";
}

function readStoredCodeEditorAdapterPreferenceRef(): string {
  if (typeof window === "undefined") {
    return DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF;
  }
  const stored = window.localStorage.getItem(
    HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
  );
  if (
    stored &&
    HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.some(
      (preference) => getCodeEditorAdapterPreferenceRef(preference) === stored,
    )
  ) {
    return stored;
  }
  return DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF;
}

function initialRecipeSelectionRef(initialRecipeId: string | null | undefined): string {
  if (
    initialRecipeId &&
    HYPERVISOR_SESSION_LAUNCH_RECIPES.some(
      (recipe) => recipe.recipe_id === initialRecipeId,
    )
  ) {
    return initialRecipeId;
  }
  return "mission.default";
}

function safeProjectIdFragment(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\.git$/, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64) || "local"
  );
}

function projectNameFromUrl(value: string): string {
  const withoutGit = value.trim().replace(/\.git$/, "");
  const leaf = withoutGit.split("/").filter(Boolean).at(-1);
  return leaf || "URL session";
}

function launchProjectForMode({
  mode,
  selectedProject,
  url,
}: {
  mode: SessionStartMode;
  selectedProject: ProjectScope | null;
  url: string;
}): ProjectScope {
  if (mode === "project" && selectedProject) {
    return selectedProject;
  }
  if (mode === "url") {
    return {
      id: `url:${safeProjectIdFragment(url)}`,
      name: projectNameFromUrl(url),
      description: url.trim() || "URL session",
      environment: "Local replay",
      rootPath: ".",
    };
  }
  return SCRATCH_PROJECT_SCOPE;
}

export function HypervisorNewSessionModal({
  isOpen,
  currentProject,
  projects,
  modelMountInventory = HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  initialSeedIntent = null,
  initialRecipeId = null,
  onClose,
  onLaunch,
}: HypervisorNewSessionModalProps) {
  const firstSessionHarnessOptions = useMemo(
    () =>
      HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS.map((adapterId) =>
        getHarnessSelectionOption(`agent-harness-adapter:${adapterId}`),
      ),
    [],
  );
  const [startMode, setStartMode] = useState<SessionStartMode | null>(null);
  const [recipeId, setRecipeId] = useState(
    () => initialRecipeSelectionRef(initialRecipeId),
  );
  const [projectId, setProjectId] = useState(projects[0]?.id ?? currentProject.id);
  const [adapterPreferenceRef] = useState(
    readStoredCodeEditorAdapterPreferenceRef,
  );
  const [harnessSelectionRef, setHarnessSelectionRef] = useState(
    defaultHarnessSelectionRef(),
  );
  const [modelRouteRef, setModelRouteRef] = useState(MODEL_ROUTE_OPTIONS[0].ref);
  const [modelName, setModelName] = useState("qwen");
  const [urlSeed, setUrlSeed] = useState("https://github.com/ioi-foundation/ioi");
  const [privacyPostureRef, setPrivacyPostureRef] = useState(
    PRIVACY_OPTIONS[0].ref,
  );
  const [seedIntent, setSeedIntent] = useState(
    () => initialSeedIntent?.trim() ?? "",
  );

  useEffect(() => {
    if (!isOpen) {
      return;
    }
    setStartMode(null);
    setRecipeId(initialRecipeSelectionRef(initialRecipeId));
    setProjectId(projects[0]?.id ?? currentProject.id);
    setHarnessSelectionRef(defaultHarnessSelectionRef());
    setModelRouteRef(MODEL_ROUTE_OPTIONS[0].ref);
    setPrivacyPostureRef(PRIVACY_OPTIONS[0].ref);
    setModelName("qwen");
    setSeedIntent(initialSeedIntent?.trim() ?? "");
  }, [currentProject.id, initialRecipeId, initialSeedIntent, isOpen, projects]);

  const recipe =
    HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
      (candidate) => candidate.recipe_id === recipeId,
    ) ??
    HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
      (candidate) => candidate.recipe_id === "mission.default",
    ) ??
    HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const projectOptions = useMemo(() => [...projects], [projects]);
  const selectedProject =
    projectOptions.find((project) => project.id === projectId) ??
    projectOptions[0] ??
    null;
  const resolvedStartMode = startMode ?? "project";
  const launchProject = launchProjectForMode({
    mode: resolvedStartMode,
    selectedProject,
    url: urlSeed,
  });
  const selectedAdapterPreference =
    getCodeEditorAdapterPreferenceByRef(adapterPreferenceRef);
  const selectedHarness =
    firstSessionHarnessOptions.find(
      (option) => getHarnessSelectionRef(option) === harnessSelectionRef,
    ) ??
    firstSessionHarnessOptions[0] ??
    HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions[0]!;
  const selectedModelRoute =
    MODEL_ROUTE_OPTIONS.find((option) => option.ref === modelRouteRef) ??
    MODEL_ROUTE_OPTIONS[0];
  const selectedPrivacy =
    PRIVACY_OPTIONS.find((option) => option.ref === privacyPostureRef) ??
    PRIVACY_OPTIONS[0];
  const modelRouteAvailability =
    modelRouteSupportsHypervisorMountFromInventory(
      selectedModelRoute.ref,
      modelMountInventory,
    );
  const modelRouteSupportsHypervisorMount = modelRouteAvailability.available;
  const harnessVerdict = buildHarnessCompatibilityVerdict(
    selectedHarness,
    modelRouteSupportsHypervisorMount,
    selectedPrivacy.ref,
  );
  const launchBlockedByHarnessVerdict =
    harnessVerdict.state === "blocked" ||
    harnessVerdict.state === "local_route_unavailable";
  const launchBlockedByProject =
    resolvedStartMode === "project" && projectOptions.length === 0;
  const normalizedModelName = modelName.trim() || "qwen";
  const receiptPreviewRef = useMemo(
    () =>
      [
        "receipt-preview:new-session",
        recipe.recipe_id,
        launchProject.id,
        seedIntent.trim().replace(/[^a-z0-9_-]+/gi, "-").slice(0, 48) ||
          resolvedStartMode,
        adapterPreferenceRef.replace(/[^a-z0-9_-]+/gi, "-"),
        harnessSelectionRef.replace(/[^a-z0-9_-]+/gi, "-"),
      ].join("/"),
    [
      adapterPreferenceRef,
      harnessSelectionRef,
      launchProject.id,
      recipe.recipe_id,
      resolvedStartMode,
      seedIntent,
    ],
  );
  const launchSummary = useMemo(
    () =>
      buildHypervisorNewSessionLaunchSummary({
        recipe,
        seedIntent,
        projectId: launchProject.id,
        codeEditorAdapter: selectedAdapterPreference,
        harness: selectedHarness,
        harnessVerdict,
        modelRouteAvailability,
        modelRouteRef,
        privacyPostureRef,
        authorityScopeRefs: recipe.authority_scope_templates,
        receiptPreviewRef,
      }),
    [
      harnessVerdict,
      launchProject.id,
      modelRouteAvailability,
      modelRouteRef,
      privacyPostureRef,
      receiptPreviewRef,
      recipe,
      seedIntent,
      selectedAdapterPreference,
      selectedHarness,
    ],
  );
  const buildLaunchRequest = (
    launchRecipe = recipe,
    nextSeedIntent = seedIntent,
  ): HypervisorNewSessionLaunchRequest => {
    const nextReceiptPreviewRef = [
      "receipt-preview:new-session",
      launchRecipe.recipe_id,
      launchProject.id,
      nextSeedIntent.trim().replace(/[^a-z0-9_-]+/gi, "-").slice(0, 48) ||
        resolvedStartMode,
      adapterPreferenceRef.replace(/[^a-z0-9_-]+/gi, "-"),
      harnessSelectionRef.replace(/[^a-z0-9_-]+/gi, "-"),
    ].join("/");
    const nextLaunchSummary = buildHypervisorNewSessionLaunchSummary({
      recipe: launchRecipe,
      seedIntent: nextSeedIntent,
      projectId: launchProject.id,
      codeEditorAdapter: selectedAdapterPreference,
      harness: selectedHarness,
      harnessVerdict,
      modelRouteAvailability,
      modelRouteRef,
      privacyPostureRef,
      authorityScopeRefs: launchRecipe.authority_scope_templates,
      receiptPreviewRef: nextReceiptPreviewRef,
    });

    return {
      recipe_id: launchRecipe.recipe_id,
      seed_intent: nextLaunchSummary.seed_intent,
      project_id: launchProject.id,
      adapter_preference_ref: adapterPreferenceRef,
      harness_selection_ref: harnessSelectionRef,
      model_route_ref: modelRouteRef,
      privacy_posture_ref: privacyPostureRef,
      authority_scope_refs: launchRecipe.authority_scope_templates,
      receipt_preview_ref: nextReceiptPreviewRef,
      launch_summary: nextLaunchSummary,
      project_context: {
        schema_version: "ioi.hypervisor.new_session_project_context.v1",
        project_label: launchProject.name,
        root_path: launchProject.rootPath || ".",
        repository_url:
          resolvedStartMode === "url" ? urlSeed.trim() || null : null,
        repository_branch: "master",
        runtimeTruthSource: "daemon-runtime",
      },
      model_garden_configuration: {
        schema_version: "ioi.hypervisor.session_model_garden_configuration.v1",
        configuration_ref: `model-garden:${safeProjectIdFragment(
          harnessSelectionRef,
        )}/${safeProjectIdFragment(normalizedModelName)}`,
        model_name: normalizedModelName,
        model_route_ref: modelRouteRef,
        endpoint_ref: "model-endpoint:hypervisor/default-local",
        provider_ref: "provider:hypervisor-local",
        custody_posture: "local_model_mount",
        runtimeTruthSource: "daemon-runtime",
      },
    };
  };

  if (!isOpen) {
    return null;
  }

  const renderChoiceScreen = () => (
    <div
      className="hypervisor-new-session-modal__choice-list"
      aria-label="Session start choices"
      data-new-session-reference-start-choices="project url scratch"
      data-new-session-project-count={projectOptions.length}
    >
      {SESSION_START_CHOICES.map((choice) => (
        <button
          type="button"
          key={choice.id}
          data-new-session-start-mode={choice.id}
          className={[
            "hypervisor-new-session-modal__compact-choice",
            `hypervisor-new-session-modal__compact-choice--${choice.tone}`,
          ].join(" ")}
          onClick={() => setStartMode(choice.id)}
        >
          <span aria-hidden="true" />
          <strong>{choice.label}</strong>
          <b aria-hidden="true">&gt;</b>
        </button>
      ))}
    </div>
  );

  const renderConfigureScreen = () => (
    <>
      <div
        className="hypervisor-new-session-modal__configure"
        data-new-session-launch-cockpit="ioi-reference-governed-launch"
        data-new-session-start-mode={resolvedStartMode}
        data-new-session-receipt-preview={receiptPreviewRef}
        data-new-session-seed-intent={launchSummary.seed_intent ?? ""}
        data-new-session-harness-verdict={harnessVerdict.state}
        data-new-session-model-route-ref={selectedModelRoute.ref}
        data-new-session-project-ref={launchProject.id}
        data-new-session-model-name={normalizedModelName}
        data-new-session-model-route-inventory-state={
          modelRouteAvailability.state
        }
        data-new-session-launch-summary={launchSummary.schema_version}
        data-new-session-target-binding={
          launchSummary.target_binding.schema_version
        }
        data-new-session-target-binding-ref={launchSummary.target_binding_ref}
        data-new-session-target-kind={launchSummary.target_binding.target_kind}
        data-new-session-target-surface={launchSummary.target_binding.surface_id}
        data-new-session-target-session-route={
          launchSummary.target_binding.session_route_ref
        }
        data-new-session-harness-session-binding={
          launchSummary.harness_session_binding.schema_version
        }
        data-new-session-harness-session-binding-ref={
          launchSummary.harness_session_binding_ref
        }
        data-new-session-model-configuration-ref={
          launchSummary.harness_session_binding.model_configuration_ref
        }
        data-new-session-harness-launch-route-ref={
          launchSummary.harness_session_binding.harness_launch_route_ref
        }
        data-new-session-harness-workspace-mount-policy={
          launchSummary.harness_session_binding.workspace_mount_policy
        }
        data-new-session-code-editor-adapter-ref={
          launchSummary.code_editor_adapter_ref
        }
        data-new-session-code-editor-adapter-launch-plan-ref={
          launchSummary.code_editor_adapter_launch_plan_ref
        }
        data-new-session-code-editor-adapter-connection-contract-ref={
          launchSummary.code_editor_adapter_connection_contract_ref
        }
        data-new-session-harness-selection-kind={
          launchSummary.harness_selection_kind
        }
        data-new-session-harness-selection-ref={launchSummary.harness_selection_ref}
        data-new-session-harness-truth-boundary={
          launchSummary.harness_truth_boundary
        }
        data-new-session-privacy-posture-ref={privacyPostureRef}
        data-new-session-requires-daemon-gate={String(
          launchSummary.requires_daemon_gate,
        )}
      >
        <button
          type="button"
          className="hypervisor-new-session-modal__back"
          onClick={() => setStartMode(null)}
        >
          Back
        </button>

        {resolvedStartMode === "project" ? (
          <label>
            <span>Project</span>
            {projectOptions.length > 0 ? (
              <select
                value={selectedProject?.id ?? ""}
                onChange={(event) => setProjectId(event.currentTarget.value)}
              >
                {projectOptions.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            ) : (
              <p className="hypervisor-new-session-modal__empty-projects">
                No projects yet. Create a repository project first or start from URL.
              </p>
            )}
          </label>
        ) : null}

        {resolvedStartMode === "url" ? (
          <label>
            <span>Repository URL</span>
            <input
              value={urlSeed}
              onChange={(event) => setUrlSeed(event.currentTarget.value)}
              placeholder="https://github.com/org/repo"
            />
          </label>
        ) : null}

        <label>
          <span>Task</span>
          <textarea
            rows={3}
            value={seedIntent}
            onChange={(event) => setSeedIntent(event.currentTarget.value)}
            placeholder="Describe your task or type / for commands"
          />
        </label>

        <label>
          <span>Agent</span>
          <select
            value={harnessSelectionRef}
            onChange={(event) => setHarnessSelectionRef(event.currentTarget.value)}
          >
            {firstSessionHarnessOptions.map((option) => {
              const selectionRef = getHarnessSelectionRef(option);
              return (
                <option key={selectionRef} value={selectionRef}>
                  {option.label}
                </option>
              );
            })}
          </select>
        </label>

        <fieldset
          className="hypervisor-new-session-modal__model-garden"
          data-new-session-model-garden="local-qwen"
        >
          <legend>Model garden</legend>
          <label>
            <span>Model</span>
            <input
              value={modelName}
              onChange={(event) => setModelName(event.currentTarget.value)}
              placeholder="qwen"
            />
          </label>
          <label>
            <span>Route</span>
            <select
              value={modelRouteRef}
              onChange={(event) => setModelRouteRef(event.currentTarget.value)}
            >
              {MODEL_ROUTE_OPTIONS.map((option) => (
                <option key={option.ref} value={option.ref}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        </fieldset>

        <label>
          <span>Privacy</span>
          <select
            value={privacyPostureRef}
            onChange={(event) => setPrivacyPostureRef(event.currentTarget.value)}
          >
            {PRIVACY_OPTIONS.map((option) => (
              <option key={option.ref} value={option.ref}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>Launch type</span>
          <select
            value={recipe.recipe_id}
            onChange={(event) => setRecipeId(event.currentTarget.value)}
          >
            {HYPERVISOR_SESSION_LAUNCH_RECIPES.map((launchRecipe) => (
              <option key={launchRecipe.recipe_id} value={launchRecipe.recipe_id}>
                {launchRecipe.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div
        className="hypervisor-new-session-modal__verdict"
        data-new-session-harness-verdict-card={harnessVerdict.state}
      >
        <strong>{selectedHarness.label}</strong>
        <span>
          {isAgentHarnessAdapterOption(selectedHarness)
            ? "Agent Harness Adapter"
            : "Built-in session profile"}
        </span>
        <p>{harnessVerdict.summary}</p>
        <p>{selectedModelRoute.detail}</p>
        <p>{selectedPrivacy.detail}</p>
        {launchBlockedByProject ? (
          <em>Create a repository project before starting from project.</em>
        ) : harnessVerdict.privacyWarning ? (
          <em>{harnessVerdict.privacyWarning}</em>
        ) : null}
        <button
          type="button"
          data-new-session-start-selected="true"
          disabled={launchBlockedByHarnessVerdict || launchBlockedByProject}
          onClick={() => void onLaunch(buildLaunchRequest(recipe))}
        >
          Start selected session
        </button>
      </div>
    </>
  );

  return (
    <div
      className="hypervisor-new-session-modal__backdrop"
      role="presentation"
      onClick={onClose}
    >
      <section
        className="hypervisor-new-session-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="hypervisor-new-session-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="hypervisor-new-session-modal__header">
          <div className="hypervisor-new-session-modal__title-lockup">
            <h2 id="hypervisor-new-session-title">New session</h2>
            <p>Select how you want to start</p>
          </div>
          <button
            type="button"
            className="hypervisor-new-session-modal__close"
            onClick={onClose}
            aria-label="Close New Session"
          >
            x
          </button>
        </header>

        <div className="hypervisor-new-session-modal__body hypervisor-new-session-modal__body--compact">
          {startMode ? renderConfigureScreen() : renderChoiceScreen()}
        </div>
      </section>
    </div>
  );
}
