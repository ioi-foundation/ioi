import clsx from "clsx";
import { EnvironmentEstateView } from "@ioi/hypervisor-workbench";
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { buildConnectorPolicySummary } from "../../../surfaces/Policy";
import { useHypervisorShellController } from "../useHypervisorShellController";
import { type HypervisorClientRuntime } from "../../../services/HypervisorClientRuntime";
import { buildConnectorTrustProfile } from "../../../surfaces/Capabilities";
import { ChatLocalActivityBar } from "./ChatLocalActivityBar";
import { CapabilitiesView } from "../../../surfaces/Capabilities";
import { InboxView } from "../../../surfaces/Inbox";
import { SettingsView } from "../../../surfaces/Settings";
import {
  MissionControlControlView,
  MissionControlMountsView,
  MissionControlRunsView,
  MissionControlWorkflowsView,
} from "../../../surfaces/MissionControl";
import { HypervisorClientHeader } from "./HypervisorClientHeader";
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
import {
  HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE,
  loadHypervisorAutomationCompositorProjection,
  type HypervisorAutomationCompositorProjection,
  type HypervisorAutomationRun,
  type HypervisorAutomationRunStatus,
  type HypervisorAutomationTemplate,
} from "../hypervisorAutomationCompositorModel";
import {
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  requestHarnessPublicFixtureRun,
} from "../harnessAdapterModel";
import {
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE,
  loadHypervisorModelInfrastructureProjection,
} from "../hypervisorModelInfrastructureModel";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "../hypervisorPrivacyPostureModel";
import {
  HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE,
  loadHypervisorProjectStateProjection,
} from "../hypervisorProjectStateModel";
import {
  buildHypervisorProviderOperationProposal,
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  HYPERVISOR_PROVIDER_OPERATION_KINDS,
  loadHypervisorProviderPlacementProjection,
  proposeHypervisorProviderOperation,
  type HypervisorProviderOperationKind,
  type HypervisorProviderOperationProposal,
  type HypervisorProviderPlacementCandidate,
} from "../hypervisorProviderPlacementModel";
import {
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  loadHypervisorReceiptEvidenceProjection,
} from "../hypervisorReceiptEvidenceModel";
import {
  buildHypervisorSessionOperationProposal,
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  HYPERVISOR_SESSION_OPERATION_KINDS,
  loadHypervisorSessionOperationsProjection,
  proposeHypervisorSessionOperation,
  type HypervisorSessionOperationKind,
  type HypervisorSessionOperationProposal,
} from "../hypervisorSessionOperationsModel";
import {
  HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES,
  HYPERVISOR_SESSION_WORKSPACE_MODES,
  isHypervisorSurfaceId,
  type HypervisorLaunchedSessionProjection,
} from "../hypervisorShellNavigationModel";

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
  const [comparison, setComparison] = useState(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  );
  const [runState, setRunState] = useState<
    "fixture" | "requesting_daemon" | "daemon_admitted" | "daemon_unavailable"
  >("fixture");
  const [runMessage, setRunMessage] = useState(
    "Fixture projection is loaded until a daemon run is requested.",
  );

  async function handleDaemonFixtureRun() {
    setRunState("requesting_daemon");
    setRunMessage("Requesting daemon-mediated public fixture run...");
    try {
      const nextComparison = await requestHarnessPublicFixtureRun();
      setComparison(nextComparison);
      setRunState("daemon_admitted");
      setRunMessage(
        `Daemon returned ${nextComparison.receipt_refs.length} receipt refs for ${nextComparison.candidate_reports.length} harness candidates.`,
      );
    } catch (error) {
      setRunState("daemon_unavailable");
      setRunMessage(
        error instanceof Error
          ? error.message
          : "Harness public fixture run could not reach the daemon route.",
      );
    }
  }

  return (
    <section
      className="hypervisor-harness-comparison"
      aria-label="Harness comparison dashboard"
      data-hypervisor-harness-comparison-run={comparison.run_id}
      data-hypervisor-harness-comparison-state={runState}
    >
      <div className="hypervisor-harness-comparison__header">
        <div>
          <span>Foundry comparison</span>
          <h2>Compare harness adapters against one public fixture.</h2>
          <p>
            Foundry reads the same daemon-runtime comparison contract as New
            Session, then makes output, cost, verification, receipts, and evidence
            visible before any adapter is treated as reliable.
          </p>
        </div>
        <button
          type="button"
          data-harness-comparison-action="request-daemon-run"
          disabled={runState === "requesting_daemon"}
          onClick={handleDaemonFixtureRun}
        >
          {runState === "requesting_daemon" ? "Requesting..." : "Run daemon fixture"}
        </button>
      </div>
      <p
        className="hypervisor-harness-comparison__daemon-state"
        data-harness-comparison-daemon-state={runState}
      >
        {runMessage}
      </p>

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

function HypervisorAutomationCompositorSurface({
  currentProjectId,
  workflowSurface,
  children,
}: {
  currentProjectId: string;
  workflowSurface: string;
  children: ReactNode;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorAutomationCompositorProjection({
      projectId: currentProjectId,
    })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Automations] compositor projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, [currentProjectId]);

  const completedRuns = projection.runs.filter(
    (run) => run.status === "completed",
  ).length;
  const failedRuns = projection.runs.filter((run) =>
    ["blocked"].includes(run.status),
  ).length;
  const rowTemplates = projection.templates.slice(0, 5);
  const suggestedTemplates = projection.templates.slice().reverse().slice(0, 5);

  return (
    <section
      className="hypervisor-automation-compositor hypervisor-automation-compositor--ioi-reference"
      aria-label="Automation compositor projection"
      data-hypervisor-automation-compositor={projection.projection_id}
      data-automation-compositor-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
      data-workflow-compositor-surface={workflowSurface}
    >
      <header className="hypervisor-automation-compositor__topbar">
        <h2>Automations</h2>
        <button type="button" className="hypervisor-automation-compositor__new">
          <span aria-hidden="true">+</span>
          <span>New</span>
        </button>
      </header>

      <div className="hypervisor-automation-compositor__layout">
        <main className="hypervisor-automation-compositor__main">
          <div
            className="hypervisor-automation-compositor__metrics"
            aria-label="Automation compositor summary"
          >
            <AutomationMetric
              active
              label="Total Automations"
              value={projection.workflow_template_refs.length}
            />
            <AutomationMetric label="Successful - 7d" value={completedRuns} />
            <AutomationMetric label="Failed - 7d" value={failedRuns} />
          </div>

          <div
            className="hypervisor-automation-compositor__filters"
            aria-label="Automation filters"
          >
            <label>
              <span aria-hidden="true">Search</span>
              <input type="search" placeholder="Search..." />
            </label>
            <button type="button">Status: All</button>
            <button type="button">Sort: Recently completed</button>
            <div role="group" aria-label="Automation ownership filter">
              <button type="button" className="is-active">
                Yours ({projection.templates.length})
              </button>
              <button type="button">All ({projection.runs.length})</button>
            </div>
          </div>

          <section
            className="hypervisor-automation-compositor__table"
            aria-label="Workflow templates"
          >
            {rowTemplates.map((template, index) => {
              const run = findAutomationRunForTemplate(projection, template);
              return (
                <article
                  key={template.template_ref}
                  className="hypervisor-automation-compositor__row"
                  data-workflow-template-ref={template.template_ref}
                  data-workflow-graph-ref={template.graph_ref}
                  data-workflow-run-ref={run?.run_ref ?? ""}
                  data-workflow-run-status={run?.status ?? "draft"}
                >
                  <span className="hypervisor-automation-compositor__row-icon">
                    {index === 0 ? ">" : "[]"}
                  </span>
                  <div className="hypervisor-automation-compositor__row-copy">
                    <strong>{template.label}</strong>
                    <em>{formatAutomationRunState(run)}</em>
                  </div>
                  <button
                    type="button"
                    className="hypervisor-automation-compositor__row-run"
                  >
                    Run
                  </button>
                  <button
                    type="button"
                    className="hypervisor-automation-compositor__row-menu"
                    aria-label={`Open ${template.label} automation actions`}
                  >
                    ...
                  </button>
                </article>
              );
            })}
          </section>
        </main>

        <aside
          className="hypervisor-automation-compositor__suggested"
          aria-label="Suggested templates"
        >
          <div className="hypervisor-automation-compositor__suggested-heading">
            <h3>Suggested templates</h3>
            <p>Try these automations for common autonomous-work workflows.</p>
          </div>
          {suggestedTemplates.map((template) => (
            <button
              type="button"
              key={template.template_ref}
              className="hypervisor-automation-compositor__suggested-card"
              data-workflow-template-suggestion={template.template_ref}
            >
              <span className="hypervisor-automation-compositor__suggested-icon">
                {template.label.slice(0, 1)}
              </span>
              <span>
                <strong>{template.label}</strong>
                <em>{template.description}</em>
              </span>
              <span aria-hidden="true">&gt;</span>
            </button>
          ))}
        </aside>
      </div>

      <div
        className="hypervisor-automation-compositor__editor"
        data-workflow-compositor-editor-boundary="projection-client"
        hidden
      >
        {children}
      </div>
    </section>
  );
}

function AutomationMetric({
  active = false,
  label,
  value,
}: {
  active?: boolean;
  label: string;
  value: number;
}) {
  return (
    <div
      className={clsx("hypervisor-automation-compositor__metric", {
        "is-active": active,
      })}
    >
      <span>{label}</span>
      <strong>{value}</strong>
      {active ? (
        <svg aria-hidden="true" viewBox="0 0 112 42" preserveAspectRatio="none">
          <path d="M1 31 L19 7 L38 31 L56 8 L75 31 L94 8 L111 31" />
        </svg>
      ) : null}
    </div>
  );
}

function findAutomationRunForTemplate(
  projection: HypervisorAutomationCompositorProjection,
  template: HypervisorAutomationTemplate,
): HypervisorAutomationRun | undefined {
  return projection.runs.find((run) => run.template_ref === template.template_ref);
}

function formatAutomationStatus(status: HypervisorAutomationRunStatus): string {
  if (status === "completed") return "Successful";
  if (status === "blocked") return "Failed";
  if (status === "running") return "Running";
  if (status === "scheduled") return "Scheduled";
  if (status === "ready") return "Ready";
  return "Never ran";
}

function formatAutomationRunState(run: HypervisorAutomationRun | undefined): string {
  if (!run || run.status === "draft") {
    return "Never ran";
  }
  return formatAutomationStatus(run.status);
}

function formatSessionDisplayTitle(sessionRef: string): string {
  const rawTitle = sessionRef.split("/").pop() || sessionRef;
  return rawTitle
    .split(/[-_:]+/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatSessionOperationLabel(
  operationKind: HypervisorSessionOperationKind,
): string {
  switch (operationKind) {
    case "request_access_lease":
      return "Request access";
    case "request_log_lease":
      return "Request logs";
    case "open_port":
      return "Open port";
    case "run_task":
      return "Run task";
    case "propose_terminal_command":
      return "Review command";
    case "archive_session":
      return "Archive";
    case "restore_session":
      return "Restore";
    default:
      return String(operationKind).split("_").join(" ");
  }
}

function formatSessionLifecycleLabel(lifecycleState: string): string {
  if (lifecycleState === "active") {
    return "running";
  }
  return lifecycleState.split("_").join(" ");
}

function HypervisorSessionOperationsCockpit({
  launchedSessions,
  onOpenSurface,
}: {
  launchedSessions: HypervisorLaunchedSessionProjection[];
  onOpenSurface: (surface: PrimaryView) => void;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  );
  const [operationProposal, setOperationProposal] =
    useState<HypervisorSessionOperationProposal | null>(null);

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

  function handleSessionOperation(
    operationKind: HypervisorSessionOperationKind,
    targetRef?: string,
  ) {
    proposeHypervisorSessionOperation({
      projection,
      operationKind,
      targetRef,
    })
      .then(setOperationProposal)
      .catch((error) => {
        console.warn(
          "[Hypervisor][Sessions] operation proposal unavailable",
          error,
        );
        setOperationProposal(
          buildHypervisorSessionOperationProposal(projection, operationKind, {
            targetRef,
            source: "unverified",
          }),
        );
      });
  }

  function canOpenLaunchedSessionSurface(
    session: HypervisorLaunchedSessionProjection,
  ): boolean {
    return session.admission_state === "daemon_admitted";
  }

  function launchedSessionAdmissionLabel(
    session: HypervisorLaunchedSessionProjection,
  ): string {
    switch (session.admission_state) {
      case "daemon_admitted":
        return "Daemon admitted";
      case "daemon_blocked":
        return "Daemon blocked";
      case "daemon_unavailable":
        return "Daemon unavailable";
      case "pending_daemon_admission":
      default:
        return "Pending daemon admission";
    }
  }

  function launchedSessionAdmissionDetail(
    session: HypervisorLaunchedSessionProjection,
  ): string {
    const admission = session.workbench_adapter_admission;
    if (!admission) {
      return "No adapter launch admission record has been attached yet.";
    }
    if (admission.decision === "admitted") {
      const receiptRefs = admission.receipt_refs.join(" - ") || "receipt pending";
      return `${admission.admission_id} / ${receiptRefs}`;
    }
    return admission.error_message;
  }

  const startupSteps = [
    {
      label: "Started governed workspace",
      detail: projection.provider_candidate_ref,
    },
    {
      label: "Initialized project state",
      detail: projection.project_ref,
    },
    {
      label: "Loaded authority scopes",
      detail: projection.authority_scope_refs.join(" / "),
    },
    {
      label: "Connected adapter",
      detail: projection.selected_adapter_ref,
    },
    {
      label: "Bound archive and restore refs",
      detail: projection.restore_ref,
    },
  ];

  return (
    <section
      className="hypervisor-session-operations hypervisor-session-operations--ioi-reference-session hypervisor-session-detail-shell"
      aria-label="Session operations cockpit"
      data-ioi-reference-session-cockpit="true"
      data-hypervisor-session-operations={projection.projection_id}
      data-session-operations-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-session-operations__header">
        <span>Sessions</span>
        <h2>{formatSessionDisplayTitle(projection.selected_session_ref)}</h2>
        <code>{projection.selected_session_ref}</code>
        <p>
          Environment posture, leases, ports, tasks, terminal events, receipts,
          and restore refs are projected from Hypervisor Core and Agentgres.
        </p>
      </div>

      {launchedSessions.length > 0 ? (
        <div
          className="hypervisor-session-operations__launches"
          aria-label="Recently launched governed sessions"
          data-launched-session-count={launchedSessions.length}
        >
          {launchedSessions.map((session) => {
            const canOpenSurface = canOpenLaunchedSessionSurface(session);
            return (
              <article
                key={session.session_ref}
                className={clsx(
                  "hypervisor-session-operations__launch",
                  !canOpenSurface && "is-admission-blocked",
                )}
                data-launched-session-ref={session.session_ref}
                data-launched-session-surface={session.surface_id}
                data-launched-session-state={session.admission_state}
                data-launched-session-admission-ref={
                  session.workbench_adapter_admission_ref ?? ""
                }
                data-launched-session-admission-decision={
                  session.workbench_adapter_admission?.decision ?? "pending"
                }
                data-launched-session-open-disabled={!canOpenSurface}
              >
                <div>
                  <span>{session.surface_id}</span>
                  <h3>{session.project_label}</h3>
                  <p>{session.recipe_ref}</p>
                  <button
                    type="button"
                    data-launched-session-open-surface={session.surface_id}
                    disabled={!canOpenSurface}
                    onClick={() => {
                      if (canOpenSurface) {
                        onOpenSurface(session.surface_id);
                      }
                    }}
                  >
                    Open surface
                  </button>
                </div>
                <dl>
                  <div>
                    <dt>Adapter admission</dt>
                    <dd>
                      <strong>{launchedSessionAdmissionLabel(session)}</strong>
                      <span>{launchedSessionAdmissionDetail(session)}</span>
                    </dd>
                  </div>
                  <div>
                    <dt>Harness</dt>
                    <dd>{session.launch_summary.harness_label}</dd>
                  </div>
                  <div>
                    <dt>Adapter</dt>
                    <dd>{session.launch_summary.workbench_adapter_ref}</dd>
                  </div>
                  <div>
                    <dt>Receipt</dt>
                    <dd>{session.launch_receipt_ref}</dd>
                  </div>
                </dl>
              </article>
            );
          })}
        </div>
      ) : null}

      <div
        className="hypervisor-session-operations__reference-page"
        aria-label="Selected session detail"
        data-session-reference-page="environment-detail"
      >
        <header className="hypervisor-session-operations__session-topbar">
          <button
            type="button"
            className="hypervisor-session-operations__branch-picker"
            data-session-branch="main"
          >
            <span className="hypervisor-session-operations__status-dot" />
            <strong>main</strong>
            <span aria-hidden="true">⌄</span>
          </button>
          <div className="hypervisor-session-operations__top-actions">
            <button
              type="button"
              data-session-adapter-ref={projection.selected_adapter_ref}
            >
              <span aria-hidden="true">⌘</span>
              <strong>{projection.selected_adapter_ref.replace(/^workbench-adapter:/, "")}</strong>
              <span aria-hidden="true">⌄</span>
            </button>
            <button
              type="button"
              aria-label="Request session access lease"
              data-session-operation-kind="request_access_lease"
              data-session-operation-session={projection.selected_session_ref}
              onClick={() => handleSessionOperation("request_access_lease")}
            >
              ...
            </button>
          </div>
        </header>

        <div
          className="hypervisor-session-operations__session-tabs"
          aria-label="Session workspace and detail tabs"
          data-session-reference-detail="code-conversation"
        >
          <div
            className="hypervisor-session-operations__workspace-modes"
            role="tablist"
            aria-label="Session workspace modes"
            data-session-workspace-mode-list={HYPERVISOR_SESSION_WORKSPACE_MODES.map(
              (mode) => mode.mode_id,
            ).join(" ")}
          >
            {HYPERVISOR_SESSION_WORKSPACE_MODES.map((mode) => (
              <button
                key={mode.mode_id}
                type="button"
                role="tab"
                aria-selected={mode.mode_id === "code"}
                data-session-workspace-mode={mode.mode_id}
              >
                <strong>{mode.label}</strong>
              </button>
            ))}
          </div>
          <button
            type="button"
            className="hypervisor-session-operations__session-title"
            data-session-ref={projection.selected_session_ref}
          >
            <strong>{formatSessionDisplayTitle(projection.selected_session_ref)}</strong>
            <code>{projection.selected_session_ref}</code>
            <span aria-hidden="true">⌄</span>
          </button>
          <div className="hypervisor-session-operations__detail-tabs" role="tablist" aria-label="Session detail tabs">
            {projection.detail_tabs.map((tab) => (
              <button
                key={tab.tab_id}
                type="button"
                role="tab"
                aria-selected={tab.tab_id === "environment"}
                data-session-detail-tab={tab.tab_id}
              >
                <strong>{tab.label}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="hypervisor-session-operations__body">
          <main
            className="hypervisor-session-operations__environment"
            aria-label="Environment lifecycle"
          >
            <div className="hypervisor-session-operations__environment-header">
              <div>
                <span
                  className="hypervisor-session-operations__toggle"
                  aria-hidden="true"
                />
                <h2>
                  Environment {formatSessionLifecycleLabel(projection.lifecycle_state)}
                </h2>
              </div>
              <dl>
                <div>
                  <dt>Auto-stop after</dt>
                  <dd>30m of inactivity</dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>5h ago</dd>
                </div>
                <div>
                  <dt>Last started</dt>
                  <dd>5h ago</dd>
                </div>
                <div>
                  <dt>Resource usage</dt>
                  <dd>
                    <span className="hypervisor-session-operations__health-pill">
                      Healthy
                    </span>
                  </dd>
                </div>
              </dl>
            </div>

            <ol className="hypervisor-session-operations__startup-list">
              {startupSteps.map((step) => (
                <li key={step.label}>
                  <span className="hypervisor-session-operations__check-dot">✓</span>
                  <div>
                    <strong>{step.label}</strong>
                    <span>{step.detail}</span>
                  </div>
                </li>
              ))}
            </ol>
          </main>

          <aside
            className="hypervisor-session-operations__right-pane"
            aria-label="Changes, files, comments, and session inspectors"
            data-session-change-inspector="changes-files-comments"
            data-session-change-mode-list={HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map(
              (mode) => mode.mode_id,
            ).join(" ")}
          >
            <header className="hypervisor-session-operations__right-header">
              <h3>Changes</h3>
              <div className="hypervisor-session-operations__change-inspector">
                {HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map((mode) => (
                  <button
                    key={mode.mode_id}
                    type="button"
                    aria-pressed={mode.mode_id === "changes"}
                    data-session-change-mode={mode.mode_id}
                    title={mode.summary}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </header>

            <label className="hypervisor-session-operations__search">
              <span>Search files...</span>
              <input
                type="search"
                aria-label="Search changed files"
                placeholder="Search files..."
              />
            </label>

            <div className="hypervisor-session-operations__change-list">
              <div>
                <span className="hypervisor-session-operations__folder">
                  Agentgres refs
                </span>
                {projection.latest_receipt_refs.map((receiptRef, index) => (
                  <button type="button" key={receiptRef}>
                    <code>{receiptRef}</code>
                    <span>+{(index + 1) * 12}</span>
                  </button>
                ))}
              </div>
              <div>
                <span className="hypervisor-session-operations__folder">
                  Inspectors
                </span>
                {projection.right_inspector_panels.map((panel) => (
                  <button
                    type="button"
                    key={panel.panel_id}
                    data-right-inspector-panel={panel.panel_id}
                    data-panel-status={panel.status}
                  >
                    <strong>{panel.label}</strong>
                    <span>{panel.status}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="hypervisor-session-operations__bottom-dock">
              <div
                className="hypervisor-session-operations__bottom-tabs"
                role="tablist"
                aria-label="Bottom inspectors"
              >
                {projection.bottom_inspector_panels.map((panel, index) => (
                  <button
                    key={panel.panel_id}
                    type="button"
                    role="tab"
                    aria-selected={index === 0}
                    data-bottom-inspector-panel={panel.panel_id}
                    title={panel.summary}
                  >
                    {panel.label}
                  </button>
                ))}
              </div>
              <div className="hypervisor-session-operations__bottom-content">
                <div className="hypervisor-session-operations__panel">
                  <h3>Ports</h3>
                  {projection.ports_services.map((service) => (
                    <div
                      key={service.service_ref}
                      className="hypervisor-session-operations__row"
                      data-session-port-service={service.service_ref}
                    >
                      <strong>{service.label}</strong>
                      <span>{service.protocol}:{service.port}</span>
                      <em>{service.status}</em>
                      <button
                        type="button"
                        data-session-service-open-port={service.service_ref}
                        onClick={() =>
                          handleSessionOperation("open_port", service.service_ref)
                        }
                      >
                        Add port
                      </button>
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
                      <button
                        type="button"
                        data-session-task-run={task.task_ref}
                        onClick={() => handleSessionOperation("run_task", task.task_ref)}
                      >
                        Run
                      </button>
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
                      <button
                        type="button"
                        data-session-terminal-propose={event.event_ref}
                        onClick={() =>
                          handleSessionOperation(
                            "propose_terminal_command",
                            event.event_ref,
                          )
                        }
                      >
                        Review
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </aside>
        </div>

        <div className="hypervisor-session-operations__metadata" aria-label="Environment refs">
          <dl>
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

      <div
        className="hypervisor-session-operations__reference-detail"
        aria-label="Code and conversation workspace"
        data-session-reference-detail="code-conversation"
      >
        <div
          className="hypervisor-session-operations__workspace-modes"
          role="tablist"
          aria-label="Session workspace modes"
          data-session-workspace-mode-list={HYPERVISOR_SESSION_WORKSPACE_MODES.map(
            (mode) => mode.mode_id,
          ).join(" ")}
        >
          {HYPERVISOR_SESSION_WORKSPACE_MODES.map((mode) => (
            <button
              key={mode.mode_id}
              type="button"
              role="tab"
              aria-selected={mode.mode_id === "code"}
              data-session-workspace-mode={mode.mode_id}
            >
              <strong>{mode.label}</strong>
              <span>{mode.summary}</span>
            </button>
          ))}
        </div>

        <aside
          className="hypervisor-session-operations__change-inspector"
          aria-label="Changes, files, and comments inspector"
          data-session-change-inspector="changes-files-comments"
          data-session-change-mode-list={HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map(
            (mode) => mode.mode_id,
          ).join(" ")}
        >
          {HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map((mode) => (
            <button
              key={mode.mode_id}
              type="button"
              aria-pressed={mode.mode_id === "changes"}
              data-session-change-mode={mode.mode_id}
            >
              <strong>{mode.label}</strong>
              <span>{mode.summary}</span>
            </button>
          ))}
        </aside>
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

      <div
        className="hypervisor-session-operations__actions"
        aria-label="Session operation proposals"
      >
        <span className="hypervisor-session-operations__actions-heading">
          Session actions
        </span>
        {HYPERVISOR_SESSION_OPERATION_KINDS.map((operationKind) => (
          <button
            key={operationKind}
            type="button"
            data-session-operation-kind={operationKind}
            data-session-operation-session={projection.selected_session_ref}
            onClick={() => handleSessionOperation(operationKind)}
          >
            {formatSessionOperationLabel(operationKind)}
          </button>
        ))}
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
              <button
                type="button"
                data-session-service-open-port={service.service_ref}
                onClick={() => handleSessionOperation("open_port", service.service_ref)}
              >
                Propose port lease
              </button>
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
              <button
                type="button"
                data-session-task-run={task.task_ref}
                onClick={() => handleSessionOperation("run_task", task.task_ref)}
              >
                Propose task run
              </button>
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
              <button
                type="button"
                data-session-terminal-propose={event.event_ref}
                onClick={() =>
                  handleSessionOperation("propose_terminal_command", event.event_ref)
                }
              >
                Review command
              </button>
            </div>
          ))}
        </div>
      </div>
      {operationProposal ? (
        <aside
          className="hypervisor-session-operations__proposal"
          aria-label="Session operation proposal"
          data-session-operation-proposal={operationProposal.proposal_ref}
          data-session-operation-admission={operationProposal.admission_state}
          data-session-operation-target={operationProposal.target_ref}
        >
          <div>
            <span>Session proposal</span>
            <h3>{operationProposal.operation_kind.split("_").join(" ")}</h3>
            <p>{operationProposal.custody_invariant}</p>
          </div>
          <dl>
            <div>
              <dt>Wallet lease</dt>
              <dd>{operationProposal.wallet_lease_ref}</dd>
            </div>
            <div>
              <dt>Scopes</dt>
              <dd>{operationProposal.required_scope_refs.join(", ")}</dd>
            </div>
            <div>
              <dt>Agentgres op</dt>
              <dd>{operationProposal.agentgres_operation_ref}</dd>
            </div>
            <div>
              <dt>Receipt</dt>
              <dd>{operationProposal.receipt_ref}</dd>
            </div>
            <div>
              <dt>State root</dt>
              <dd>{operationProposal.state_root_ref}</dd>
            </div>
            <div>
              <dt>Restore</dt>
              <dd>{operationProposal.restore_ref}</dd>
            </div>
          </dl>
        </aside>
      ) : null}
    </section>
  );
}

function HypervisorProjectStateSurface({
  selectedProjectId,
  onSelectProject,
  onOpenSurface,
}: {
  selectedProjectId: string;
  onSelectProject: (projectId: string) => void;
  onOpenSurface: (surface: PrimaryView) => void;
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
              <div
                className="hypervisor-project-state__actions"
                aria-label={`Project actions for ${project.name}`}
              >
                <button
                  type="button"
                  data-project-select-action={project.project_id}
                  onClick={() => onSelectProject(project.project_id)}
                >
                  Select project
                </button>
                {project.current_session_ref ? (
                  <button
                    type="button"
                    data-project-open-session={project.current_session_ref}
                    onClick={() => onOpenSurface("sessions")}
                  >
                    Open session
                  </button>
                ) : null}
                {project.provider_candidate_ref ? (
                  <button
                    type="button"
                    data-project-open-provider={project.provider_candidate_ref}
                    onClick={() => onOpenSurface("providers")}
                  >
                    Open provider
                  </button>
                ) : null}
                {project.restore_state === "restore_ready" ? (
                  <button
                    type="button"
                    data-project-open-restore={project.restore_ref}
                    onClick={() => onOpenSurface("receipts")}
                  >
                    Review restore
                  </button>
                ) : null}
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
  const [operationProposal, setOperationProposal] =
    useState<HypervisorProviderOperationProposal | null>(null);

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

  function handleProviderOperation(
    candidate: HypervisorProviderPlacementCandidate,
    operationKind: HypervisorProviderOperationKind,
  ) {
    proposeHypervisorProviderOperation({
      projectRef: projection.selected_project_ref,
      candidate,
      operationKind,
    })
      .then(setOperationProposal)
      .catch((error) => {
        console.warn(
          "[Hypervisor][Providers] operation proposal unavailable",
          error,
        );
        setOperationProposal(
          buildHypervisorProviderOperationProposal(candidate, operationKind, {
            projectRef: projection.selected_project_ref,
            source: "unverified",
          }),
        );
      });
  }

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
            <div
              className="hypervisor-provider-placement__actions"
              aria-label={`Provider operation proposals for ${candidate.label}`}
            >
              {HYPERVISOR_PROVIDER_OPERATION_KINDS.map((operationKind) => (
                <button
                  key={operationKind}
                  type="button"
                  data-provider-operation-kind={operationKind}
                  data-provider-operation-candidate={candidate.candidate_ref}
                  onClick={() => handleProviderOperation(candidate, operationKind)}
                >
                  {operationKind.split("_").join(" ")}
                </button>
              ))}
            </div>
          </article>
        ))}
      </div>
      {operationProposal ? (
        <aside
          className="hypervisor-provider-placement__proposal"
          aria-label="Provider operation proposal"
          data-provider-operation-proposal={operationProposal.proposal_ref}
          data-provider-operation-admission={operationProposal.admission_state}
        >
          <div>
            <span>Operation proposal</span>
            <h3>{operationProposal.operation_kind.split("_").join(" ")}</h3>
            <p>{operationProposal.custody_invariant}</p>
          </div>
          <dl>
            <div>
              <dt>Wallet lease</dt>
              <dd>{operationProposal.wallet_lease_ref}</dd>
            </div>
            <div>
              <dt>Agentgres op</dt>
              <dd>{operationProposal.agentgres_operation_ref}</dd>
            </div>
            <div>
              <dt>Receipt</dt>
              <dd>{operationProposal.receipt_ref}</dd>
            </div>
            <div>
              <dt>State root</dt>
              <dd>{operationProposal.state_root_ref}</dd>
            </div>
            <div>
              <dt>Restore</dt>
              <dd>{operationProposal.restore_ref}</dd>
            </div>
          </dl>
        </aside>
      ) : null}
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

function HypervisorReceiptEvidenceSurface({
  currentProjectId,
}: {
  currentProjectId: string;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorReceiptEvidenceProjection({
      projectId: currentProjectId,
      sessionRef: HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref,
    })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Receipts] evidence projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, [currentProjectId]);

  return (
    <section
      className="hypervisor-receipt-evidence"
      aria-label="Receipt evidence surface"
      data-hypervisor-receipt-evidence={projection.projection_id}
      data-receipt-evidence-source={projection.source}
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

function HypervisorModelInfrastructureSurface({
  currentProjectId,
  children,
}: {
  currentProjectId: string;
  children: ReactNode;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE,
  );

  useEffect(() => {
    let cancelled = false;
    loadHypervisorModelInfrastructureProjection({
      projectId: currentProjectId,
      sessionRef: projection.selected_session_ref,
    })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][Models] infrastructure projection unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, [currentProjectId, projection.selected_session_ref]);

  return (
    <section
      className="hypervisor-model-infrastructure"
      aria-label="Model infrastructure projection"
      data-hypervisor-model-infrastructure={projection.projection_id}
      data-model-infrastructure-source={projection.source}
      data-model-infrastructure-inventory-source={projection.inventory_source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-model-infrastructure__header">
        <span>Models</span>
        <h2>Model routes, providers, custody lanes, and session bindings.</h2>
        <p>{projection.infrastructure_boundary_invariant}</p>
      </div>

      <div
        className="hypervisor-model-infrastructure__summary"
        aria-label="Model infrastructure summary"
      >
        <div>
          <span>Routes</span>
          <strong>{projection.model_route_refs.length}</strong>
        </div>
        <div>
          <span>Endpoints</span>
          <strong>{projection.endpoint_refs.length}</strong>
        </div>
        <div>
          <span>Instances</span>
          <strong>{projection.loaded_instance_refs.length}</strong>
        </div>
        <div>
          <span>Receipts</span>
          <strong>{projection.latest_receipt_refs.length}</strong>
        </div>
      </div>

      <div className="hypervisor-model-infrastructure__grid">
        <section aria-label="Model route bindings">
          <h3>Routes</h3>
          {projection.routes.map((route) => (
            <article
              key={route.route_ref}
              className="hypervisor-model-infrastructure__card"
              data-model-route-ref={route.route_ref}
              data-model-route-status={route.status}
              data-model-weight-custody-lane={route.model_weight_custody_lane}
            >
              <div>
                <span>{route.role}</span>
                <h4>{route.route_ref}</h4>
                <p>{route.privacy_posture}</p>
              </div>
              <dl>
                <div>
                  <dt>Provider</dt>
                  <dd>{route.provider_ref}</dd>
                </div>
                <div>
                  <dt>Endpoints</dt>
                  <dd>{route.endpoint_refs.join(", ")}</dd>
                </div>
                <div>
                  <dt>Scopes</dt>
                  <dd>{route.authority_scope_refs.join(", ")}</dd>
                </div>
              </dl>
            </article>
          ))}
        </section>

        <section aria-label="Session model bindings">
          <h3>Session Bindings</h3>
          {projection.session_bindings.map((binding) => (
            <article
              key={binding.session_ref}
              className="hypervisor-model-infrastructure__card"
              data-model-session-binding={binding.session_ref}
              data-model-session-route={binding.selected_model_route_ref}
            >
              <div>
                <span>{binding.policy_ref}</span>
                <h4>{binding.session_ref}</h4>
                <p>{binding.custody_profile_ref}</p>
              </div>
              <dl>
                <div>
                  <dt>Endpoint</dt>
                  <dd>{binding.selected_endpoint_ref}</dd>
                </div>
                <div>
                  <dt>Instance</dt>
                  <dd>{binding.selected_instance_ref}</dd>
                </div>
                <div>
                  <dt>Receipt</dt>
                  <dd>{binding.receipt_ref}</dd>
                </div>
              </dl>
            </article>
          ))}
        </section>
      </div>

      <div
        className="hypervisor-model-infrastructure__mounts"
        data-model-mounting-ui-boundary="configuration-client"
      >
        {children}
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
  const settingsActive = activeView === "settings";
  const workflowActive = activeView === "automations";
  const mountsActive = activeView === "models";
  const dedicatedWorkbenchActive = workflowActive || mountsActive;

  const auxiliaryChatVisible =
    !settingsActive &&
    !workspaceActive &&
    !dedicatedWorkbenchActive &&
    activeView !== "sessions" &&
    activeView !== "home" &&
    controller.chat.paneVisible;
  const utilityDrawerVisible =
    !settingsActive &&
    activeView !== "sessions" &&
    activeView !== "home" &&
    !dedicatedWorkbenchActive;
  const auxiliaryChatFullscreen =
    auxiliaryChatVisible && controller.chat.paneMaximized;
  const commandCenterModel = buildOperatorCommandCenterModel({
    activeView,
    workflowSurface: controller.workflow.surface,
    currentProject,
    notificationCount: notificationBadgeCount,
  });
  const contentMainRef = useRef<HTMLDivElement | null>(null);
  const [workspaceChatDismissed, setWorkspaceChatDismissed] = useState(false);

  useLayoutEffect(() => {
    const node = contentMainRef.current;
    if (!node) {
      return undefined;
    }

    const resetScroll = () => {
      node.scrollTop = 0;
    };

    resetScroll();
    const animationFrame =
      typeof window !== "undefined"
        ? window.requestAnimationFrame(resetScroll)
        : 0;
    const timeout =
      typeof window !== "undefined" ? window.setTimeout(resetScroll, 0) : 0;

    return () => {
      if (typeof window !== "undefined") {
        window.cancelAnimationFrame(animationFrame);
        window.clearTimeout(timeout);
      }
    };
  }, [activeView]);

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
                  ref={contentMainRef}
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
                      onOpenCockpitSurface={(surfaceRef) => {
                        const surfaceId = surfaceRef.replace(/^surface:/, "");
                        if (isHypervisorSurfaceId(surfaceId)) {
                          controller.changePrimaryView(surfaceId);
                        }
                      }}
                      onSelectProject={controller.workflow.selectProject}
                    />
                  ) : null}

                  {activeView === "sessions" ? (
                    <HypervisorSessionOperationsCockpit
                      launchedSessions={
                        controller.sessions.launchedSessionProjections
                      }
                      onOpenSurface={controller.changePrimaryView}
                    />
                  ) : null}

                  {activeView === "projects" ? (
                    <HypervisorProjectStateSurface
                      selectedProjectId={currentProject.id}
                      onSelectProject={controller.workflow.selectProject}
                      onOpenSurface={controller.changePrimaryView}
                    />
                  ) : null}

                  {activeView === "automations" ? (
                    <HypervisorAutomationCompositorSurface
                      currentProjectId={currentProject.id}
                      workflowSurface={controller.workflow.surface}
                    >
                      <MissionControlWorkflowsView
                        runtime={runtime}
                        surface={controller.workflow.surface}
                        currentProject={currentProject}
                        projects={projects}
                        notificationCount={notificationBadgeCount}
                        editingAgent={controller.agents.editingAgent}
                        onSurfaceChange={controller.workflow.setSurface}
                        onSelectProject={controller.workflow.selectProject}
                        onOpenChat={() =>
                          controller.changePrimaryView("sessions")
                        }
                        onOpenInbox={() =>
                          controller.changePrimaryView("missions")
                        }
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
                        workflowPreflightSeed={
                          controller.workflow.preflightSeed
                        }
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
                          controller.workflow.queueBuilderConfigToCanvas(
                            config,
                          );
                        }}
                      />
                    </HypervisorAutomationCompositorSurface>
                  ) : null}

                  {activeView === "insights" ? (
                    <MissionControlRunsView runtime={runtime} />
                  ) : null}

                  {activeView === "models" ? (
                    <HypervisorModelInfrastructureSurface
                      currentProjectId={currentProject.id}
                    >
                      <MissionControlMountsView />
                    </HypervisorModelInfrastructureSurface>
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
                    <HypervisorReceiptEvidenceSurface
                      currentProjectId={currentProject.id}
                    />
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

                  {activeView === "authority" ? (
                    <MissionControlControlView
                      runtime={runtime}
                      surface="policy"
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

                  {settingsActive ? (
                    <SettingsView
                      runtime={runtime}
                      profile={controller.profile.value}
                      profileDraft={controller.profile.draft}
                      profileSaving={controller.profile.saving}
                      profileError={controller.profile.error}
                      policyState={controller.policy.shieldPolicy}
                      governanceRequest={controller.policy.governanceRequest}
                      seedSection={controller.settings.seedSection}
                      onConsumeSeedSection={
                        controller.settings.consumeSeedSection
                      }
                      onProfileDraftChange={controller.profile.updateDraft}
                      onResetProfileDraft={controller.profile.resetDraft}
                      onSaveProfile={controller.profile.saveDraft}
                      onPolicyChange={controller.policy.setShieldPolicy}
                      onOpenPolicySurface={() =>
                        controller.changePrimaryView("authority")
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
                            source: "settings",
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
