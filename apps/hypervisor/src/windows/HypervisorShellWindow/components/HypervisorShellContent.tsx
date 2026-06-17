import clsx from "clsx";
import { EnvironmentEstateView } from "@ioi/hypervisor-workbench";
import { useEffect, useState } from "react";

import { buildConnectorPolicySummary } from "../../../surfaces/Policy";
import { useHypervisorShellController } from "../useHypervisorShellController";
import { type HypervisorClientRuntime } from "../../../services/HypervisorClientRuntime";
import { buildConnectorTrustProfile } from "../../../surfaces/Capabilities";
import { ChatLocalActivityBar } from "./ChatLocalActivityBar";
import { CapabilitiesView } from "../../../surfaces/Capabilities";
import { InboxView } from "../../../surfaces/Inbox";
import {
  MissionControlControlView,
  MissionControlMountsView,
  MissionControlRunsView,
  MissionControlWorkflowsView,
} from "../../../surfaces/MissionControl";
import { HypervisorClientHeader } from "./HypervisorClientHeader";
import { ChatCopilotView } from "./ChatCopilot";
import { HomeView } from "../../../surfaces/Home";
import { ChatLeftUtilityPane } from "./ChatLeftUtilityPane";
import { ChatUtilityDrawer } from "./ChatUtilityDrawer";
import { WorkspaceShell } from "../../../surfaces/Workspace";
import {
  directWorkspaceWorkbenchHost,
  getDefaultWorkspaceWorkbenchHost,
  openVsCodeWorkbenchHost,
} from "../../../services/workspaceWorkbenchHostRegistry";
import { buildOperatorCommandCenterModel } from "../operatorSubstrateModel";
import { materializeWorkflowProject } from "../../../services/workflowProjectMaterialization";
import type { PrimaryView } from "../hypervisorShellModel";
import { HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE } from "../harnessAdapterModel";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "../hypervisorPrivacyPostureModel";
import {
  HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE,
  loadHypervisorProjectStateProjection,
} from "../hypervisorProjectStateModel";
import {
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  loadHypervisorProviderPlacementProjection,
} from "../hypervisorProviderPlacementModel";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "../hypervisorReceiptEvidenceModel";
import {
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  loadHypervisorSessionOperationsProjection,
} from "../hypervisorSessionOperationsModel";

interface HypervisorShellContentProps {
  controller: ReturnType<typeof useHypervisorShellController>;
  runtime: HypervisorClientRuntime;
}

const PLACEHOLDER_SURFACE_COPY: Partial<
  Record<PrimaryView, { eyebrow: string; title: string; body: string; tags: string[] }>
> = {
  providers: {
    eyebrow: "Provider posture",
    title: "Providers manage direct compute, storage, model, and node integrations.",
    body:
      "This surface is for local machines, customer clouds, DePIN compute, storage backends, confidential compute lanes, provider spend leases, and provider receipts.",
    tags: ["Local", "Cloud", "DePIN"],
  },
  environments: {
    eyebrow: "Environment estate",
    title: "Environments are governed resources behind sessions.",
    body:
      "This surface tracks VMs, containers, HypervisorOS nodes, ports, services, access leases, log leases, archive refs, restore refs, and provider placement evidence without making infrastructure truth.",
    tags: ["Sessions", "Ports", "Restore"],
  },
  foundry: {
    eyebrow: "Evals and promotion",
    title: "Foundry will govern evals, distillation, benchmarks, and package promotion.",
    body:
      "This is not the meta harness. It is the application surface for training, evaluation, scorecards, promotion candidates, and artifact-backed release evidence.",
    tags: ["Evals", "Benchmarks", "Promotion"],
  },
  receipts: {
    eyebrow: "Operational evidence",
    title: "Receipts will become the audit and replay console.",
    body:
      "This surface will index action receipts, Agentgres operation refs, artifact refs, trace refs, state roots, delivery evidence, and restore/import proof chains.",
    tags: ["Agentgres", "Replay", "State roots"],
  },
};

function isPlaceholderSurface(view: PrimaryView): boolean {
  return Boolean(PLACEHOLDER_SURFACE_COPY[view]);
}

function HypervisorSurfacePlaceholder({
  activeView,
}: {
  activeView: PrimaryView;
}) {
  const copy = PLACEHOLDER_SURFACE_COPY[activeView];
  if (!copy) {
    return null;
  }

  return (
    <section
      className="hypervisor-surface-placeholder"
      data-testid={`hypervisor-surface-placeholder-${activeView}`}
      data-hypervisor-surface={activeView}
      aria-label={copy.title}
    >
      <div className="hypervisor-surface-placeholder-eyebrow">
        {copy.eyebrow}
      </div>
      <h2>{copy.title}</h2>
      <p>{copy.body}</p>
      <div className="hypervisor-surface-placeholder-tags" aria-label="Surface primitives">
        {copy.tags.map((tag) => (
          <span key={tag}>{tag}</span>
        ))}
      </div>
    </section>
  );
}

function HypervisorHarnessComparisonDashboard() {
  const comparison = HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE;
  return (
    <section
      className="hypervisor-harness-comparison"
      aria-label="Harness comparison dashboard"
      data-hypervisor-harness-comparison-run={comparison.run_id}
    >
      <div className="hypervisor-harness-comparison__header">
        <span>Foundry comparison</span>
        <h2>Compare harness adapters against one public fixture.</h2>
        <p>
          Foundry reads the same daemon-runtime comparison contract as New
          Session, then makes output, cost, verification, receipts, and evidence
          visible before any adapter is treated as reliable.
        </p>
      </div>

      <div className="hypervisor-harness-comparison__summary" aria-label="Comparison summary">
        <div>
          <span>Fixture</span>
          <strong>{comparison.task_ref}</strong>
        </div>
        <div>
          <span>Mode</span>
          <strong>{comparison.comparison_mode}</strong>
        </div>
        <div>
          <span>Criteria</span>
          <strong>{comparison.acceptance_criteria_refs.length}</strong>
        </div>
        <div>
          <span>Receipts</span>
          <strong>{comparison.receipt_refs.length}</strong>
        </div>
      </div>

      <div className="hypervisor-harness-comparison__table" role="table">
        <div className="hypervisor-harness-comparison__row is-head" role="row">
          <span role="columnheader">Harness</span>
          <span role="columnheader">Output</span>
          <span role="columnheader">Cost</span>
          <span role="columnheader">Verification</span>
          <span role="columnheader">Receipt</span>
        </div>
        {comparison.candidate_reports.map((candidate) => (
          <div
            key={candidate.selection_ref}
            className="hypervisor-harness-comparison__row"
            role="row"
            data-harness-comparison-candidate={candidate.selection_ref}
          >
            <span role="cell">
              <strong>{candidate.label}</strong>
              <em>{candidate.execution_lane}</em>
            </span>
            <span role="cell">{candidate.output_summary}</span>
            <span role="cell">${candidate.estimated_cost_usd.toFixed(3)}</span>
            <span role="cell">{candidate.verification_status.split("_").join(" ")}</span>
            <span role="cell">{candidate.receipt_ref}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function HypervisorSessionOperationsCockpit() {
  const [projection, setProjection] = useState(
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorSessionOperationsProjection()
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Sessions] operations projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section
      className="hypervisor-session-operations"
      aria-label="Session operations cockpit"
      data-hypervisor-session-operations={projection.projection_id}
      data-session-operations-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-session-operations__header">
        <span>Sessions</span>
        <h2>{projection.selected_session_ref}</h2>
        <p>
          Session state, environment posture, leases, ports, tasks, terminal
          events, receipts, and restore refs are projected from Hypervisor Core
          and Agentgres. The client can inspect them, not become runtime truth.
        </p>
      </div>

      <div className="hypervisor-session-operations__rail" aria-label="Session rail">
        {projection.session_rail.map((railItem) => (
          <div
            key={railItem.state}
            className={clsx(
              "hypervisor-session-operations__rail-item",
              railItem.selected && "is-selected",
            )}
            data-session-rail-state={railItem.state}
          >
            <span>{railItem.state.split("_").join(" ")}</span>
            <strong>{railItem.count}</strong>
          </div>
        ))}
      </div>

      <div className="hypervisor-session-operations__tabs" role="tablist" aria-label="Session detail tabs">
        {projection.detail_tabs.map((tab) => (
          <button
            key={tab.tab_id}
            type="button"
            role="tab"
            aria-selected={tab.tab_id === "environment"}
            data-session-detail-tab={tab.tab_id}
          >
            <strong>{tab.label}</strong>
            <span>{tab.summary}</span>
          </button>
        ))}
      </div>

      <div className="hypervisor-session-operations__grid">
        <div className="hypervisor-session-operations__panel" aria-label="Right inspectors">
          <h3>Right Inspector</h3>
          {projection.right_inspector_panels.map((panel) => (
            <div
              key={panel.panel_id}
              className="hypervisor-session-operations__inspector"
              data-right-inspector-panel={panel.panel_id}
              data-panel-status={panel.status}
            >
              <strong>{panel.label}</strong>
              <span>{panel.summary}</span>
            </div>
          ))}
        </div>

        <div className="hypervisor-session-operations__panel" aria-label="Environment and restore">
          <h3>Environment</h3>
          <dl>
            <div>
              <dt>Lifecycle</dt>
              <dd>{projection.lifecycle_state}</dd>
            </div>
            <div>
              <dt>Environment</dt>
              <dd>{projection.environment_ref}</dd>
            </div>
            <div>
              <dt>Provider</dt>
              <dd>{projection.provider_candidate_ref}</dd>
            </div>
            <div>
              <dt>Adapter</dt>
              <dd>{projection.selected_adapter_ref}</dd>
            </div>
            <div>
              <dt>Access Lease</dt>
              <dd>{projection.access_lease_ref}</dd>
            </div>
            <div>
              <dt>Log Lease</dt>
              <dd>{projection.log_lease_ref}</dd>
            </div>
            <div>
              <dt>Archive</dt>
              <dd>{projection.archive_ref}</dd>
            </div>
            <div>
              <dt>Restore</dt>
              <dd>{projection.restore_ref}</dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="hypervisor-session-operations__bottom" aria-label="Bottom inspectors">
        <div className="hypervisor-session-operations__panel">
          <h3>Ports & Services</h3>
          {projection.ports_services.map((service) => (
            <div
              key={service.service_ref}
              className="hypervisor-session-operations__row"
              data-session-port-service={service.service_ref}
            >
              <strong>{service.label}</strong>
              <span>{service.protocol}:{service.port}</span>
              <em>{service.status}</em>
            </div>
          ))}
        </div>

        <div className="hypervisor-session-operations__panel">
          <h3>Tasks</h3>
          {projection.tasks.map((task) => (
            <div
              key={task.task_ref}
              className="hypervisor-session-operations__row"
              data-session-task={task.task_ref}
            >
              <strong>{task.label}</strong>
              <span>{task.status}</span>
              <em>{task.receipt_ref}</em>
            </div>
          ))}
        </div>

        <div className="hypervisor-session-operations__panel">
          <h3>Terminal</h3>
          {projection.terminal_events.map((event) => (
            <div
              key={event.event_ref}
              className="hypervisor-session-operations__row"
              data-session-terminal-event={event.event_ref}
            >
              <strong>{event.command_summary}</strong>
              <span>{event.status}</span>
              <em>{event.receipt_ref}</em>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HypervisorProjectStateSurface({
  selectedProjectId,
}: {
  selectedProjectId: string;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorProjectStateProjection({ projectId: selectedProjectId })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Projects] state projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId]);

  return (
    <section
      className="hypervisor-project-state"
      aria-label="Project state surface"
      data-hypervisor-project-state={projection.projection_id}
      data-project-state-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-project-state__header">
        <span>Projects</span>
        <h2>Workspace refs, sessions, restore posture, and state roots.</h2>
        <p>{projection.project_boundary_invariant}</p>
      </div>

      <div className="hypervisor-project-state__grid">
        {projection.records.map((project) => {
          const selected = project.project_id === selectedProjectId;
          return (
            <article
              key={project.project_id}
              className={clsx(
                "hypervisor-project-state__card",
                selected && "is-selected",
              )}
              data-project-state-record={project.project_id}
              data-project-restore-state={project.restore_state}
              data-project-custody-posture={project.custody_posture}
            >
              <div className="hypervisor-project-state__card-head">
                <span>{project.environment}</span>
                <strong>{project.restore_state.split("_").join(" ")}</strong>
              </div>
              <h3>{project.name}</h3>
              <p>{project.description}</p>
              <dl>
                <div>
                  <dt>Workspace</dt>
                  <dd>{project.workspace_ref}</dd>
                </div>
                <div>
                  <dt>Root</dt>
                  <dd>{project.root_path}</dd>
                </div>
                <div>
                  <dt>Session</dt>
                  <dd>{project.current_session_ref ?? "idle"}</dd>
                </div>
                <div>
                  <dt>Environment</dt>
                  <dd>{project.environment_ref ?? "not attached"}</dd>
                </div>
                <div>
                  <dt>Provider</dt>
                  <dd>{project.provider_candidate_ref ?? "not selected"}</dd>
                </div>
                <div>
                  <dt>Adapter</dt>
                  <dd>{project.adapter_preference_ref}</dd>
                </div>
                <div>
                  <dt>Object Head</dt>
                  <dd>{project.agentgres_object_head_ref}</dd>
                </div>
                <div>
                  <dt>State Root</dt>
                  <dd>{project.state_root_ref}</dd>
                </div>
                <div>
                  <dt>Archive</dt>
                  <dd>{project.archive_ref}</dd>
                </div>
                <div>
                  <dt>Restore</dt>
                  <dd>{project.restore_ref}</dd>
                </div>
              </dl>
              <div className="hypervisor-project-state__refs" aria-label="Project artifact and receipt refs">
                {[...project.artifact_refs, ...project.latest_receipt_refs].map(
                  (ref) => (
                    <span key={ref}>{ref}</span>
                  ),
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function HypervisorProviderPlacementDashboard() {
  const [projection, setProjection] = useState(
    HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorProviderPlacementProjection()
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Providers] placement projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section
      className="hypervisor-provider-placement"
      aria-label="Provider placement dashboard"
      data-hypervisor-provider-placement={projection.projection_id}
      data-provider-placement-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-provider-placement__header">
        <span>Providers</span>
        <h2>Direct provider integrations for governed sessions.</h2>
        <p>{projection.anti_gateway_invariant}</p>
      </div>

      <div className="hypervisor-provider-placement__grid">
        {projection.candidates.map((candidate) => (
          <article
            key={candidate.candidate_ref}
            className="hypervisor-provider-placement__card"
            data-provider-placement-candidate={candidate.candidate_ref}
            data-provider-privacy-posture={candidate.privacy_posture}
          >
            <div>
              <span>{candidate.integration_kind.split("_").join(" ")}</span>
              <h3>{candidate.label}</h3>
              <p>{candidate.workload_fit}</p>
            </div>
            <dl>
              <div>
                <dt>Provider</dt>
                <dd>{candidate.direct_provider_ref}</dd>
              </div>
              <div>
                <dt>Privacy</dt>
                <dd>{candidate.privacy_posture.split("_").join(" ")}</dd>
              </div>
              <div>
                <dt>Authority</dt>
                <dd>{candidate.wallet_authority_scope_refs.join(", ")}</dd>
              </div>
              <div>
                <dt>Receipt</dt>
                <dd>{candidate.agentgres_receipt_ref}</dd>
              </div>
              <div>
                <dt>Storage</dt>
                <dd>{candidate.storage_policy_ref}</dd>
              </div>
              <div>
                <dt>Restore</dt>
                <dd>{candidate.restore_policy_ref}</dd>
              </div>
            </dl>
            <div className="hypervisor-provider-placement__risks" aria-label="Provider risk labels">
              {candidate.risk_labels.map((riskLabel) => (
                <span key={riskLabel}>{riskLabel}</span>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function HypervisorEnvironmentEstateSurface({
  runtime,
}: {
  runtime: HypervisorClientRuntime;
}) {
  return (
    <section
      className="hypervisor-environment-estate-surface"
      aria-label="Environment estate surface"
      data-hypervisor-environment-estate="runtime-view"
    >
      <div className="hypervisor-environment-estate-surface__header">
        <span>Environments</span>
        <h2>Managed sessions, ports, services, tasks, and restore posture.</h2>
        <p>
          This view reads the live environment estate through Hypervisor Core.
          Provider resources are execution placements, while wallet.network
          authorizes spend and Agentgres records lifecycle and restore truth.
        </p>
      </div>
      <EnvironmentEstateView runtime={runtime} />
    </section>
  );
}

function HypervisorReceiptEvidenceSurface() {
  const projection = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE;
  return (
    <section
      className="hypervisor-receipt-evidence"
      aria-label="Receipt evidence surface"
      data-hypervisor-receipt-evidence={projection.projection_id}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-receipt-evidence__header">
        <span>Receipts</span>
        <h2>Operational evidence, replay, and state-root continuity.</h2>
        <p>{projection.receipt_boundary_invariant}</p>
      </div>

      <div className="hypervisor-receipt-evidence__grid">
        {projection.records.map((record) => (
          <article
            key={`${record.kind}:${record.receipt_ref}`}
            className="hypervisor-receipt-evidence__card"
            data-receipt-evidence-record={record.receipt_ref}
            data-receipt-evidence-kind={record.kind}
            data-receipt-evidence-status={record.status}
          >
            <div className="hypervisor-receipt-evidence__card-head">
              <span>{record.kind.split("_").join(" ")}</span>
              <strong>{record.status}</strong>
            </div>
            <h3>{record.receipt_ref}</h3>
            <p>{record.summary}</p>
            <dl>
              <div>
                <dt>Source</dt>
                <dd>{record.source_projection_ref}</dd>
              </div>
              <div>
                <dt>Agentgres</dt>
                <dd>{record.agentgres_operation_refs.join(", ")}</dd>
              </div>
              <div>
                <dt>Artifact</dt>
                <dd>{record.artifact_refs.join(", ")}</dd>
              </div>
              <div>
                <dt>Trace</dt>
                <dd>{record.trace_refs.join(", ")}</dd>
              </div>
              <div>
                <dt>State Root</dt>
                <dd>{record.state_root_ref}</dd>
              </div>
              <div>
                <dt>Replay</dt>
                <dd>{record.replay_ref}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function HypervisorPrivacyPostureSurface() {
  const projection = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  return (
    <section
      className="hypervisor-privacy-posture"
      aria-label="Privacy and cTEE posture surface"
      data-hypervisor-privacy-posture={projection.projection_id}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-privacy-posture__header">
        <span>Privacy / cTEE</span>
        <h2>Workspace custody, model custody, and provider admission.</h2>
        <p>{projection.invariant}</p>
      </div>

      <div className="hypervisor-privacy-posture__summary">
        <div>
          <span>Selected Privacy</span>
          <strong>{projection.selected_privacy_ref}</strong>
        </div>
        <div>
          <span>Model Route</span>
          <strong>{projection.default_model_route_ref}</strong>
        </div>
        <div>
          <span>Session</span>
          <strong>{projection.selected_session_ref}</strong>
        </div>
      </div>

      <div className="hypervisor-privacy-posture__grid">
        <section aria-label="Workspace custody segments">
          <h3>Workspace Custody</h3>
          {projection.workspace_segments.map((segment) => (
            <article
              key={segment.segment_ref}
              className="hypervisor-privacy-posture__row"
              data-privacy-workspace-segment={segment.segment_ref}
              data-node-plaintext-allowed={String(segment.node_plaintext_allowed)}
            >
              <div>
                <strong>{segment.label}</strong>
                <span>{segment.custody_class.split("_").join(" ")}</span>
              </div>
              <em>{segment.owner.split("_").join(".")}</em>
              <small>
                Node plaintext {segment.node_plaintext_allowed ? "allowed" : "blocked"}
              </small>
            </article>
          ))}
        </section>

        <section aria-label="Model-weight custody policies">
          <h3>Model Custody</h3>
          {projection.model_weight_policies.map((policy) => (
            <article
              key={policy.lane}
              className="hypervisor-privacy-posture__row"
              data-model-weight-custody-lane={policy.lane}
              data-protects-model-weights={String(
                policy.protects_model_weights_from_provider_root,
              )}
            >
              <div>
                <strong>{policy.label}</strong>
                <span>{policy.admission_summary}</span>
              </div>
              <em>
                weights{" "}
                {policy.protects_model_weights_from_provider_root
                  ? "protected"
                  : "exposed"}
              </em>
              <small>{policy.authority_scope_refs.join(", ")}</small>
            </article>
          ))}
        </section>

        <section aria-label="Provider privacy candidates">
          <h3>Provider Admission</h3>
          {projection.provider_candidates.map((candidate) => (
            <article
              key={candidate.candidate_ref}
              className="hypervisor-privacy-posture__row"
              data-provider-privacy-candidate={candidate.candidate_ref}
              data-execution-privacy-posture={candidate.posture}
              data-provider-root-plaintext-risk={
                candidate.provider_root_plaintext_risk
              }
            >
              <div>
                <strong>{candidate.label}</strong>
                <span>{candidate.admission_summary}</span>
              </div>
              <em>{candidate.posture.split("_").join(" ")}</em>
              <small>{candidate.model_weight_lane.split("_").join(" ")}</small>
            </article>
          ))}
        </section>

        <section aria-label="Privacy admission controls">
          <h3>Admission Controls</h3>
          {projection.admission_controls.map((control) => (
            <article
              key={control.control_ref}
              className="hypervisor-privacy-posture__row"
              data-privacy-admission-control={control.control_ref}
              data-admission-control-owner={control.owner}
            >
              <div>
                <strong>{control.label}</strong>
                <span>{control.receipt_ref}</span>
              </div>
              <em>{control.owner.split("_").join(".")}</em>
              <small>
                unsafe plaintext{" "}
                {control.blocks_unsafe_plaintext ? "blocked" : "allowed"}
              </small>
            </article>
          ))}
        </section>
      </div>
    </section>
  );
}

export function HypervisorShellContent({
  controller,
  runtime,
}: HypervisorShellContentProps) {
  const { activeView, currentProject, projects, notificationBadgeCount } =
    controller;
  const workspaceHost = getDefaultWorkspaceWorkbenchHost();
  const workspaceUsesNativeWorkbenchChat =
    workspaceHost === directWorkspaceWorkbenchHost ||
    workspaceHost === openVsCodeWorkbenchHost;
  const workspaceActive = activeView === "workbench";
  const workflowActive = activeView === "automations";
  const mountsActive = activeView === "models";
  const dedicatedWorkbenchActive = workflowActive || mountsActive;

  const auxiliaryChatVisible =
    !workspaceActive &&
    !dedicatedWorkbenchActive &&
    activeView !== "sessions" &&
    activeView !== "home" &&
    controller.chat.paneVisible;
  const utilityDrawerVisible =
    activeView !== "sessions" && activeView !== "home" && !dedicatedWorkbenchActive;
  const auxiliaryChatFullscreen =
    auxiliaryChatVisible && controller.chat.paneMaximized;
  const commandCenterModel = buildOperatorCommandCenterModel({
    activeView,
    workflowSurface: controller.workflow.surface,
    currentProject,
    notificationCount: notificationBadgeCount,
  });
  const [workspaceChatDismissed, setWorkspaceChatDismissed] = useState(false);

  useEffect(() => {
    if (!workspaceActive) {
      setWorkspaceChatDismissed(false);
    }
  }, [workspaceActive]);

  const workspaceOperatorChatPaneWidthPx = controller.chat.paneMaximized
    ? 560
    : 360;
  const workspaceOperatorChatPane =
    workspaceActive &&
    !workspaceUsesNativeWorkbenchChat &&
    !workspaceChatDismissed ? (
      <ChatLeftUtilityPane
        surface={controller.chat.surface}
        session={controller.chat.assistantWorkbench}
        runtime={runtime}
        maximized={controller.chat.paneMaximized}
        seedIntent={null}
        onConsumeSeedIntent={undefined}
        onClose={() => {
          setWorkspaceChatDismissed(true);
          controller.chat.hidePane();
        }}
        onToggleMaximize={controller.chat.toggleMaximize}
        onBackToInbox={() => {
          controller.chat.setSurface("chat");
          controller.changePrimaryView("missions");
        }}
        onOpenInbox={() => controller.changePrimaryView("missions")}
        onOpenHypervisor={controller.chat.openHypervisorSessionWithIntent}
      />
    ) : null;

  return (
    <div
      className={clsx(
        "chat-shell",
        workspaceActive && "chat-shell--workspace-mode",
      )}
    >
      <HypervisorClientHeader
        activeView={activeView}
        workflowSurface={controller.workflow.surface}
        commandCenter={commandCenterModel}
        onOpenCommandPalette={controller.modals.openCommandPalette}
      />

      <div
        className={clsx(
          "chat-workspace",
          workspaceActive && "chat-workspace--workspace-mode",
        )}
      >
        <ChatLocalActivityBar
          activeView={activeView}
          onViewChange={controller.changePrimaryView}
          onOpenNewSession={controller.modals.openNewSessionModal}
          onOpenCommandPalette={controller.modals.openCommandPalette}
          notificationCount={notificationBadgeCount}
          profile={controller.profile.value}
        />

        <div
          className={clsx(
            "chat-main",
            workspaceActive && "chat-main--workspace-mode",
          )}
        >
          <WorkspaceShell
            active={workspaceActive}
            currentProject={currentProject}
            projects={projects}
            runtime={runtime}
            host={workspaceHost}
            operatorChatPane={workspaceOperatorChatPane}
            operatorChatPaneWidthPx={workspaceOperatorChatPaneWidthPx}
            commandPaletteOpen={controller.modals.commandPaletteOpen}
            onOpenCommandPalette={controller.modals.openCommandPalette}
          />

          {!workspaceActive ? (
            <div
              className={clsx(
                "chat-content",
                auxiliaryChatFullscreen && "is-chat-fullscreen",
                dedicatedWorkbenchActive && "is-dedicated-workbench",
              )}
            >
              <div className="chat-center-area">
                <div
                  className={clsx(
                    "chat-content-main",
                    dedicatedWorkbenchActive &&
                      "chat-content-main--dedicated-workbench",
                  )}
                >
                  {activeView === "home" ? (
                    <HomeView
                      currentProject={currentProject}
                      projects={projects}
                      notificationCount={notificationBadgeCount}
                      onOpenChat={() => controller.changePrimaryView("sessions")}
                      onOpenNewSession={controller.modals.openNewSessionModal}
                      onOpenWorkspace={() =>
                        controller.changePrimaryView("workbench")
                      }
                      onOpenRuns={() => controller.changePrimaryView("insights")}
                      onOpenModels={() =>
                        controller.changePrimaryView("models")
                      }
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenCapabilities={() =>
                        controller.changePrimaryView("agents")
                      }
                      onOpenPolicy={() =>
                        controller.policy.openPolicyCenter(null)
                      }
                      onOpenSettings={controller.settings.openSection}
                      onOpenCommandPalette={
                        controller.modals.openCommandPalette
                      }
                      onSelectProject={controller.workflow.selectProject}
                    />
                  ) : null}

                  {activeView === "sessions" ? (
                    <>
                      <HypervisorSessionOperationsCockpit />
                      <ChatCopilotView
                        seedIntent={controller.chat.seedIntent}
                        onConsumeSeedIntent={controller.chat.consumeSeedIntent}
                        sessionRuntime={runtime}
                        workspaceRootHint={currentProject.rootPath}
                        workspaceNameHint={currentProject.name}
                      />
                    </>
                  ) : null}

                  {activeView === "projects" ? (
                    <HypervisorProjectStateSurface
                      selectedProjectId={currentProject.id}
                    />
                  ) : null}

                  {activeView === "automations" ? (
                    <MissionControlWorkflowsView
                      runtime={runtime}
                      surface={controller.workflow.surface}
                      currentProject={currentProject}
                      projects={projects}
                      notificationCount={notificationBadgeCount}
                      editingAgent={controller.agents.editingAgent}
                      onSurfaceChange={controller.workflow.setSurface}
                      onSelectProject={controller.workflow.selectProject}
                      onOpenChat={() => controller.changePrimaryView("sessions")}
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenCapabilities={() =>
                        controller.changePrimaryView("agents")
                      }
                      onOpenPolicy={() =>
                        controller.policy.openPolicyCenter(null)
                      }
                      onOpenSettings={() =>
                        controller.changePrimaryView("settings")
                      }
                      onOpenAgent={controller.agents.openBuilder}
                      onCloseAgent={controller.agents.closeBuilder}
                      onStageCatalogEntry={
                        controller.catalog.openStageModalForEntry
                      }
                      composeSeedProject={
                        controller.workflow.composeSeedProject
                      }
                      onConsumeComposeSeedProject={
                        controller.workflow.consumeComposeSeedProject
                      }
                      workflowPreflightSeed={controller.workflow.preflightSeed}
                      onConsumeWorkflowPreflightSeed={
                        controller.workflow.consumePreflightSeed
                      }
                      onMaterializeWorkflowProject={async (request) => {
                        const result =
                          await materializeWorkflowProject(request);
                        controller.changePrimaryView("workbench");
                        return result;
                      }}
                      onAddBuilderConfigToCanvas={(config) => {
                        controller.workflow.queueBuilderConfigToCanvas(config);
                      }}
                    />
                  ) : null}

                  {activeView === "insights" ? (
                    <MissionControlRunsView runtime={runtime} />
                  ) : null}

                  {activeView === "models" ? (
                    <MissionControlMountsView />
                  ) : null}

                  {activeView === "privacy" ? (
                    <HypervisorPrivacyPostureSurface />
                  ) : null}

                  {activeView === "foundry" ? (
                    <HypervisorHarnessComparisonDashboard />
                  ) : null}

                  {activeView === "providers" ? (
                    <HypervisorProviderPlacementDashboard />
                  ) : null}

                  {activeView === "environments" ? (
                    <HypervisorEnvironmentEstateSurface runtime={runtime} />
                  ) : null}

                  {activeView === "receipts" ? (
                    <HypervisorReceiptEvidenceSurface />
                  ) : null}

                  {activeView === "missions" ? (
                    <InboxView
                      onOpenHypervisor={() => {
                        controller.chat.setSurface("chat");
                        controller.chat.showPane();
                      }}
                      onOpenIntegrations={() =>
                        controller.capabilities.openSurface(null)
                      }
                      onOpenLocalEngine={() =>
                        controller.capabilities.openSurface("engine")
                      }
                      onOpenShield={(connectorId) =>
                        controller.policy.openPolicyCenter(connectorId)
                      }
                      onOpenSettings={() =>
                        controller.changePrimaryView("settings")
                      }
                      onOpenReplyComposer={controller.chat.openReplyComposer}
                      onOpenMeetingPrep={controller.chat.openMeetingPrep}
                    />
                  ) : null}

                  {activeView === "agents" ? (
                    <CapabilitiesView
                      runtime={runtime}
                      getConnectorPolicySummary={(connector) =>
                        buildConnectorPolicySummary(
                          controller.policy.shieldPolicy,
                          connector.id,
                        )
                      }
                      getConnectorTrustProfile={(connector, options) =>
                        buildConnectorTrustProfile(
                          connector,
                          controller.policy.shieldPolicy,
                          options,
                        )
                      }
                      onOpenPolicyCenter={(connector) =>
                        controller.policy.openPolicyCenter(
                          connector?.id ?? null,
                        )
                      }
                      onOpenInbox={() => controller.changePrimaryView("missions")}
                      onOpenSettings={() =>
                        controller.changePrimaryView("settings")
                      }
                      onOpenSkillSources={() =>
                        controller.settings.openSection("skill_sources")
                      }
                      seedSurface={controller.capabilities.seedSurface}
                      seedConnectorId={
                        controller.capabilities.targetConnectorId
                      }
                      seedConnectionDetailSection={
                        controller.capabilities.targetDetailSection
                      }
                      onConsumeSeedSurface={
                        controller.capabilities.consumeSeedSurface
                      }
                      onConsumeSeedConnector={
                        controller.capabilities.consumeTarget
                      }
                    />
                  ) : null}

                  {activeView === "authority" || activeView === "settings" ? (
                    <MissionControlControlView
                      runtime={runtime}
                      surface={activeView === "settings" ? "system" : "policy"}
                      policyState={controller.policy.shieldPolicy}
                      profile={controller.profile.value}
                      profileDraft={controller.profile.draft}
                      profileSaving={controller.profile.saving}
                      profileError={controller.profile.error}
                      governanceRequest={controller.policy.governanceRequest}
                      focusedConnectorId={controller.policy.focusedConnectorId}
                      onSurfaceChange={(surface) =>
                        controller.changePrimaryView(
                          surface === "policy" ? "authority" : "settings",
                        )
                      }
                      settingsSeedSection={controller.settings.seedSection}
                      onConsumeSettingsSeedSection={
                        controller.settings.consumeSeedSection
                      }
                      onPolicyChange={controller.policy.setShieldPolicy}
                      onProfileDraftChange={controller.profile.updateDraft}
                      onResetProfileDraft={controller.profile.resetDraft}
                      onSaveProfile={controller.profile.saveDraft}
                      onFocusConnector={controller.policy.focusConnector}
                      onApplyGovernanceRequest={
                        controller.policy.applyGovernanceRequest
                      }
                      onDismissGovernanceRequest={
                        controller.policy.dismissGovernanceRequest
                      }
                      onOpenConnections={() =>
                        controller.changePrimaryView("agents")
                      }
                      onOpenModelRoutes={() =>
                        controller.changePrimaryView("models")
                      }
                      onOpenWorkflowPreflight={(seed) =>
                        controller.workflow.openPreflight(
                          seed ?? {
                            panel: "readiness",
                            source: "authority-center",
                          },
                        )
                      }
                    />
                  ) : null}

                  {isPlaceholderSurface(activeView) &&
                  activeView !== "projects" &&
                  activeView !== "foundry" &&
                  activeView !== "privacy" &&
                  activeView !== "providers" &&
                  activeView !== "environments" &&
                  activeView !== "receipts" ? (
                    <HypervisorSurfacePlaceholder activeView={activeView} />
                  ) : null}
                </div>

                {utilityDrawerVisible ? (
                  <ChatUtilityDrawer
                    runtime={runtime}
                    activeView={activeView}
                    chatSurface={controller.chat.surface}
                    operatorPaneOpen={controller.chat.paneVisible}
                    notificationCount={notificationBadgeCount}
                    shieldPolicy={controller.policy.shieldPolicy}
                    currentProject={currentProject}
                    focusedPolicyConnectorId={
                      controller.policy.focusedConnectorId
                    }
                    assistantWorkbench={controller.chat.assistantWorkbench}
                    onOpenChatConversation={() =>
                      controller.changePrimaryView("sessions")
                    }
                  />
                ) : null}
              </div>

              {auxiliaryChatVisible ? (
                <ChatLeftUtilityPane
                  surface={controller.chat.surface}
                  session={controller.chat.assistantWorkbench}
                  runtime={runtime}
                  maximized={controller.chat.paneMaximized}
                  seedIntent={null}
                  onConsumeSeedIntent={undefined}
                  onClose={controller.chat.hidePane}
                  onToggleMaximize={controller.chat.toggleMaximize}
                  onBackToInbox={() => {
                    controller.chat.setSurface("chat");
                    controller.changePrimaryView("missions");
                  }}
                  onOpenInbox={() => controller.changePrimaryView("missions")}
                  onOpenHypervisor={controller.chat.openHypervisorSessionWithIntent}
                />
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
