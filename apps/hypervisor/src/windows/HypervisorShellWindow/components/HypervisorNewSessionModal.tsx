import { useMemo, useState } from "react";

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
  type HypervisorHarnessSelectionOption,
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
  onClose: () => void;
  onLaunch: (request: HypervisorNewSessionLaunchRequest) => void;
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

function setupSectionLabel(sectionId: string): string {
  return (
    HYPERVISOR_NEW_SESSION_SETUP_MODEL.sections.find(
      (section) => section.id === sectionId,
    )?.label ?? sectionId
  );
}

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

function harnessOptionLabel(option: HypervisorHarnessSelectionOption): string {
  return option.selection_kind === "harness_profile"
    ? option.label
    : `${option.label} - ${option.execution_lane}`;
}

export function HypervisorNewSessionModal({
  isOpen,
  currentProject,
  projects,
  modelMountInventory = HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  initialSeedIntent = null,
  onClose,
  onLaunch,
}: HypervisorNewSessionModalProps) {
  const [recipeId, setRecipeId] = useState(
    HYPERVISOR_SESSION_LAUNCH_RECIPES[0]?.recipe_id ?? "mission.default",
  );
  const [projectId, setProjectId] = useState(currentProject.id);
  const [adapterPreferenceRef, setAdapterPreferenceRef] = useState(
    readStoredWorkbenchAdapterPreferenceRef,
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

  if (!isOpen) {
    return null;
  }

  const launch = () => {
    onLaunch({
      recipe_id: recipe.recipe_id,
      seed_intent: launchSummary.seed_intent,
      project_id: selectedProject.id,
      adapter_preference_ref: adapterPreferenceRef,
      harness_selection_ref: harnessSelectionRef,
      model_route_ref: modelRouteRef,
      privacy_posture_ref: privacyPostureRef,
      authority_scope_refs: recipe.authority_scope_templates,
      receipt_preview_ref: receiptPreviewRef,
      launch_summary: launchSummary,
    });
  };

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
          <div>
            <span>Hypervisor Core</span>
            <h2 id="hypervisor-new-session-title">New Session</h2>
            <p>
              Bind intent, project, harness, model route, privacy, authority,
              and receipt preview before launching governed work.
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close New Session">
            x
          </button>
        </header>

        <div className="hypervisor-new-session-modal__grid">
          <section aria-label="Session recipes">
            <h3>Recipe</h3>
            <div className="hypervisor-new-session-modal__choice-list">
              {HYPERVISOR_SESSION_LAUNCH_RECIPES.map((candidate) => (
                <button
                  type="button"
                  key={candidate.recipe_id}
                  className={
                    candidate.recipe_id === recipe.recipe_id ? "is-selected" : ""
                  }
                  onClick={() => setRecipeId(candidate.recipe_id)}
                >
                  <strong>{candidate.label}</strong>
                  <span>{candidate.description}</span>
                </button>
              ))}
            </div>
          </section>

          <section aria-label="Session setup">
            <h3>Setup</h3>
            <label>
              <span>Intent</span>
              <textarea
                value={seedIntent}
                data-new-session-field="seed-intent"
                onChange={(event) => setSeedIntent(event.target.value)}
                placeholder="Describe the outcome, acceptance criteria, or operator notes."
                rows={4}
              />
            </label>
            <label>
              <span>Project</span>
              <select
                value={selectedProject.id}
                data-new-session-field="project"
                onChange={(event) => setProjectId(event.target.value)}
              >
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name} · {project.rootPath}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Workbench Adapter</span>
              <select
                value={adapterPreferenceRef}
                data-new-session-field="workbench-adapter"
                onChange={(event) => setAdapterPreferenceRef(event.target.value)}
              >
                {HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.map((preference) => {
                  const preferenceRef = getWorkbenchAdapterPreferenceRef(preference);
                  return (
                    <option key={preferenceRef} value={preferenceRef}>
                      {preference.label} - {preference.launch_mode}
                    </option>
                  );
                })}
              </select>
            </label>
            <label>
              <span>Harness</span>
              <select
                value={harnessSelectionRef}
                data-new-session-field="harness"
                onChange={(event) => setHarnessSelectionRef(event.target.value)}
              >
                {HYPERVISOR_NEW_SESSION_SETUP_MODEL.harnessOptions.map(
                  (option) => {
                    const selectionRef = getHarnessSelectionRef(option);
                    return (
                      <option key={selectionRef} value={selectionRef}>
                        {harnessOptionLabel(option)}
                      </option>
                    );
                  },
                )}
              </select>
            </label>
            <label>
              <span>Model Route</span>
              <select
                value={modelRouteRef}
                data-new-session-field="model-route"
                onChange={(event) => setModelRouteRef(event.target.value)}
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
                data-new-session-field="privacy"
                onChange={(event) => setPrivacyPostureRef(event.target.value)}
              >
                {PRIVACY_OPTIONS.map((option) => (
                  <option key={option.ref} value={option.ref}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
          </section>
        </div>

        <section
          className="hypervisor-new-session-modal__summary"
          aria-label="Receipt preview"
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
          <div>
            <span>Intent</span>
            <strong>{launchSummary.seed_intent ?? "No seed intent"}</strong>
          </div>
          <div>
            <span>Required inputs</span>
            <strong>{recipe.required_inputs.map(setupSectionLabel).join(" - ")}</strong>
          </div>
          <div>
            <span>Adapter target</span>
            <strong>{selectedAdapterPreference.label}</strong>
            <em>{selectedAdapterPreference.description}</em>
          </div>
          <div>
            <span>Adapter launch contract</span>
            <strong>
              {launchSummary.workbench_adapter_connection_contract_ref}
            </strong>
            <em>
              Access leases:{" "}
              {launchSummary.workbench_adapter_access_lease_refs.join(" - ")}
            </em>
            <em>
              Receipt policy:{" "}
              {launchSummary.workbench_adapter_receipt_refs.join(" - ")}
            </em>
          </div>
          <div>
            <span>Harness verdict</span>
            <strong>{harnessVerdict.state.split("_").join(" ")}</strong>
            <em>{harnessVerdict.summary}</em>
            {harnessVerdict.privacyWarning ? (
              <em>{harnessVerdict.privacyWarning}</em>
            ) : null}
          </div>
          <div>
            <span>Model route</span>
            <strong>{selectedModelRoute.label}</strong>
            <em>{selectedModelRoute.detail}</em>
            <em>{modelRouteAvailability.summary}</em>
          </div>
          <div>
            <span>Privacy posture</span>
            <strong>{selectedPrivacy.label}</strong>
            <em>{selectedPrivacy.detail}</em>
          </div>
          <div>
            <span>Authority scopes</span>
            <strong>{recipe.authority_scope_templates.join(" - ")}</strong>
          </div>
          <div>
            <span>Receipt preview</span>
            <strong>{receiptPreviewRef}</strong>
          </div>
        </section>

        <footer className="hypervisor-new-session-modal__footer">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="primary"
            data-new-session-action="launch"
            disabled={launchBlockedByHarnessVerdict}
            onClick={launch}
          >
            Launch governed session
          </button>
        </footer>
      </section>
    </div>
  );
}
