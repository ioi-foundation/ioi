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
  type HypervisorSessionLaunchRecipe,
} from "../hypervisorShellNavigationModel";
import {
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionRef,
  isAgentHarnessAdapterOption,
  modelRouteSupportsHypervisorMountFromInventory,
  type HypervisorModelMountInventorySnapshot,
} from "../harnessAdapterModel";

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
  onLaunch: (request: HypervisorNewSessionLaunchRequest) => Promise<void> | void;
}

const MODEL_ROUTE_OPTIONS = [
  {
    ref: "model-route:hypervisor/default-local",
    label: "Hypervisor model mount",
    detail: "Managed local or configured model route.",
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
    ref: "privacy:ctee-private-workspace",
    label: "cTEE private workspace",
    detail: "Protected state stays encrypted, redacted, or locally guarded.",
  },
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
];

function defaultHarnessSelectionRef(): string {
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
  return HYPERVISOR_SESSION_LAUNCH_RECIPES[0]?.recipe_id ?? "mission.default";
}

function launchRecipeTone(recipe: HypervisorSessionLaunchRecipe): string {
  return recipe.kind.replace(/_/g, "-");
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
  const [recipeId, setRecipeId] = useState(
    () => initialRecipeSelectionRef(initialRecipeId),
  );
  const [projectId, setProjectId] = useState(currentProject.id);
  const [adapterPreferenceRef] = useState(
    readStoredCodeEditorAdapterPreferenceRef,
  );
  const [harnessSelectionRef, setHarnessSelectionRef] = useState(
    defaultHarnessSelectionRef(),
  );
  const [modelRouteRef, setModelRouteRef] = useState(MODEL_ROUTE_OPTIONS[0].ref);
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
    setRecipeId(initialRecipeSelectionRef(initialRecipeId));
    setProjectId(currentProject.id);
    setSeedIntent(initialSeedIntent?.trim() ?? "");
  }, [currentProject.id, initialRecipeId, initialSeedIntent, isOpen]);

  const recipe =
    HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
      (candidate) => candidate.recipe_id === recipeId,
    ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const projectOptions = useMemo(() => {
    const options = projects.length ? [...projects] : [currentProject];
    if (!options.some((project) => project.id === currentProject.id)) {
      options.unshift(currentProject);
    }
    return options;
  }, [currentProject, projects]);
  const selectedProject =
    projectOptions.find((project) => project.id === projectId) ?? currentProject;
  const selectedAdapterPreference =
    getCodeEditorAdapterPreferenceByRef(adapterPreferenceRef);
  const selectedHarness =
    HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions.find(
      (option) => getHarnessSelectionRef(option) === harnessSelectionRef,
    ) ?? HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions[0]!;
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
  const receiptPreviewRef = useMemo(
    () =>
      [
        "receipt-preview:new-session",
        recipe.recipe_id,
        selectedProject.id,
        seedIntent.trim().replace(/[^a-z0-9_-]+/gi, "-").slice(0, 48) ||
          "no-intent",
        adapterPreferenceRef.replace(/[^a-z0-9_-]+/gi, "-"),
        harnessSelectionRef.replace(/[^a-z0-9_-]+/gi, "-"),
      ].join("/"),
    [
      adapterPreferenceRef,
      harnessSelectionRef,
      recipe.recipe_id,
      seedIntent,
      selectedProject.id,
    ],
  );
  const launchSummary = useMemo(
    () =>
      buildHypervisorNewSessionLaunchSummary({
        recipe,
        seedIntent,
        projectId: selectedProject.id,
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
      modelRouteAvailability,
      modelRouteRef,
      privacyPostureRef,
      receiptPreviewRef,
      recipe,
      seedIntent,
      selectedAdapterPreference,
      selectedHarness,
      selectedProject.id,
    ],
  );
  const buildLaunchRequest = (
    launchRecipe = recipe,
    nextSeedIntent = seedIntent,
  ): HypervisorNewSessionLaunchRequest => {
    const nextReceiptPreviewRef = [
      "receipt-preview:new-session",
      launchRecipe.recipe_id,
      selectedProject.id,
      nextSeedIntent.trim().replace(/[^a-z0-9_-]+/gi, "-").slice(0, 48) ||
        "no-intent",
      adapterPreferenceRef.replace(/[^a-z0-9_-]+/gi, "-"),
      harnessSelectionRef.replace(/[^a-z0-9_-]+/gi, "-"),
    ].join("/");
    const nextLaunchSummary = buildHypervisorNewSessionLaunchSummary({
      recipe: launchRecipe,
      seedIntent: nextSeedIntent,
      projectId: selectedProject.id,
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
      project_id: selectedProject.id,
      adapter_preference_ref: adapterPreferenceRef,
      harness_selection_ref: harnessSelectionRef,
      model_route_ref: modelRouteRef,
      privacy_posture_ref: privacyPostureRef,
      authority_scope_refs: launchRecipe.authority_scope_templates,
      receipt_preview_ref: nextReceiptPreviewRef,
      launch_summary: nextLaunchSummary,
    };
  };
  const compactLaunchChoices = HYPERVISOR_SESSION_LAUNCH_RECIPES.map(
    (launchRecipe) => ({
      label: launchRecipe.label,
      description: launchRecipe.description,
      recipe_id: launchRecipe.recipe_id,
      tone: launchRecipeTone(launchRecipe),
    }),
  );

  if (!isOpen) {
    return null;
  }

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
            ×
          </button>
        </header>

        <div
          className="hypervisor-new-session-modal__body hypervisor-new-session-modal__body--compact"
          data-new-session-launch-cockpit="ioi-reference-governed-launch"
        >
          <div
            className="hypervisor-new-session-modal__choice-list"
            aria-label="Session start choices"
            data-new-session-receipt-preview={receiptPreviewRef}
            data-new-session-seed-intent={launchSummary.seed_intent ?? ""}
            data-new-session-harness-verdict={harnessVerdict.state}
            data-new-session-model-route-ref={selectedModelRoute.ref}
            data-new-session-project-ref={selectedProject.id}
            data-new-session-model-route-inventory-state={
              modelRouteAvailability.state
            }
            data-new-session-launch-summary={launchSummary.schema_version}
            data-new-session-target-binding={
              launchSummary.target_binding.schema_version
            }
            data-new-session-target-binding-ref={
              launchSummary.target_binding_ref
            }
            data-new-session-target-kind={
              launchSummary.target_binding.target_kind
            }
            data-new-session-target-surface={
              launchSummary.target_binding.surface_id
            }
            data-new-session-target-session-route={
              launchSummary.target_binding.session_route_ref
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
            data-new-session-harness-selection-ref={
              launchSummary.harness_selection_ref
            }
            data-new-session-harness-truth-boundary={
              launchSummary.harness_truth_boundary
            }
            data-new-session-privacy-posture-ref={privacyPostureRef}
            data-new-session-requires-daemon-gate={String(
              launchSummary.requires_daemon_gate,
            )}
            data-new-session-recipe-count={compactLaunchChoices.length}
          >
            {compactLaunchChoices.map((choice) => {
              const launchRecipe =
                HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
                  (candidate) => candidate.recipe_id === choice.recipe_id,
                ) ?? recipe;
              return (
                <button
                  type="button"
                  key={choice.label}
                  data-new-session-recipe={choice.recipe_id}
                  className={[
                    "hypervisor-new-session-modal__compact-choice",
                    `hypervisor-new-session-modal__compact-choice--${choice.tone}`,
                    recipe.recipe_id === choice.recipe_id ? "is-selected" : "",
                  ].join(" ")}
                  disabled={launchBlockedByHarnessVerdict}
                  onClick={() => {
                    setRecipeId(launchRecipe.recipe_id);
                  }}
                >
                  <span aria-hidden="true" />
                  <strong>{choice.label}</strong>
                  <em>{choice.description}</em>
                  <b aria-hidden="true">&gt;</b>
                </button>
              );
            })}
          </div>

          <section
            className="hypervisor-new-session-modal__governance"
            aria-label="Session launch governance"
            data-new-session-governance="harness-model-privacy"
          >
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

            <label>
              <span>Project</span>
              <select
                value={selectedProject.id}
                onChange={(event) => setProjectId(event.currentTarget.value)}
              >
                {projectOptions.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>

            <label>
              <span>Harness</span>
              <select
                value={harnessSelectionRef}
                onChange={(event) =>
                  setHarnessSelectionRef(event.currentTarget.value)
                }
              >
                {HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions.map(
                  (option) => {
                    const selectionRef = getHarnessSelectionRef(option);
                    return (
                      <option key={selectionRef} value={selectionRef}>
                        {option.label}
                      </option>
                    );
                  },
                )}
              </select>
            </label>

            <label>
              <span>Model route</span>
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

            <label>
              <span>Privacy</span>
              <select
                value={privacyPostureRef}
                onChange={(event) =>
                  setPrivacyPostureRef(event.currentTarget.value)
                }
              >
                {PRIVACY_OPTIONS.map((option) => (
                  <option key={option.ref} value={option.ref}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <div
              className="hypervisor-new-session-modal__verdict"
              data-new-session-harness-verdict-card={harnessVerdict.state}
            >
              <strong>{selectedHarness.label}</strong>
              <span>
                {isAgentHarnessAdapterOption(selectedHarness)
                  ? "External agent interface"
                  : "Built-in session profile"}
              </span>
              <p>{harnessVerdict.summary}</p>
              {harnessVerdict.privacyWarning ? (
                <em>{harnessVerdict.privacyWarning}</em>
              ) : null}
              <button
                type="button"
                data-new-session-start-selected="true"
                disabled={launchBlockedByHarnessVerdict}
                onClick={() => void onLaunch(buildLaunchRequest(recipe))}
              >
                Start selected session
              </button>
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
