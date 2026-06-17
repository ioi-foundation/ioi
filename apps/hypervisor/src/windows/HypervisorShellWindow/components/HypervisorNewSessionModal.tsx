import { useEffect, useMemo, useState } from "react";

import {
  DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
  HYPERVISOR_NEW_SESSION_SETUP_MODEL,
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCE_STORAGE_KEY,
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  buildHypervisorNewSessionLaunchSummary,
  getWorkbenchAdapterPreferenceByRef,
  getWorkbenchAdapterPreferenceRef,
  type HypervisorNewSessionLaunchRequest,
} from "../hypervisorShellNavigationModel";
import {
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionRef,
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
    detail: "Daemon-mediated local or configured model route.",
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

function readStoredWorkbenchAdapterPreferenceRef(): string {
  if (typeof window === "undefined") {
    return DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF;
  }
  const stored = window.localStorage.getItem(
    HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCE_STORAGE_KEY,
  );
  if (
    stored &&
    HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.some(
      (preference) => getWorkbenchAdapterPreferenceRef(preference) === stored,
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
  const [projectId] = useState(currentProject.id);
  const [adapterPreferenceRef] = useState(
    readStoredWorkbenchAdapterPreferenceRef,
  );
  const [harnessSelectionRef] = useState(
    defaultHarnessSelectionRef(),
  );
  const [modelRouteRef] = useState(MODEL_ROUTE_OPTIONS[0].ref);
  const [privacyPostureRef] = useState(
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
    setSeedIntent(initialSeedIntent?.trim() ?? "");
  }, [initialRecipeId, initialSeedIntent, isOpen]);

  const recipe =
    HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
      (candidate) => candidate.recipe_id === recipeId,
    ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const selectedProject =
    projects.find((project) => project.id === projectId) ?? currentProject;
  const selectedAdapterPreference =
    getWorkbenchAdapterPreferenceByRef(adapterPreferenceRef);
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
        workbenchAdapter: selectedAdapterPreference,
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
      workbenchAdapter: selectedAdapterPreference,
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
  const compactLaunchChoices = [
    {
      label: "Start from project",
      description: selectedProject.name,
      recipe_id: "workbench.default",
      tone: "project",
    },
    {
      label: "Start from URL",
      description: "Attach a repository, issue, doc, or remote environment.",
      recipe_id: "environment.provider",
      tone: "url",
    },
    {
      label: "Start from scratch",
      description: "Open a blank governed mission.",
      recipe_id: "mission.default",
      tone: "scratch",
    },
  ];

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
            data-new-session-model-route-inventory-state={
              modelRouteAvailability.state
            }
            data-new-session-launch-summary={launchSummary.schema_version}
            data-new-session-workbench-adapter-ref={
              launchSummary.workbench_adapter_ref
            }
            data-new-session-workbench-adapter-launch-plan-ref={
              launchSummary.workbench_adapter_launch_plan_ref
            }
            data-new-session-workbench-adapter-connection-contract-ref={
              launchSummary.workbench_adapter_connection_contract_ref
            }
            data-new-session-harness-selection-kind={
              launchSummary.harness_selection_kind
            }
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
                  className={`hypervisor-new-session-modal__compact-choice hypervisor-new-session-modal__compact-choice--${choice.tone}`}
                  disabled={launchBlockedByHarnessVerdict}
                  onClick={() => onLaunch(buildLaunchRequest(launchRecipe))}
                >
                  <span aria-hidden="true" />
                  <strong>{choice.label}</strong>
                  <em>{choice.description}</em>
                  <b aria-hidden="true">&gt;</b>
                </button>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}
