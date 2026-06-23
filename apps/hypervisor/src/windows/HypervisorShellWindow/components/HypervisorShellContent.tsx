import clsx from "clsx";
import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { buildConnectorPolicySummary } from "../../../surfaces/Policy";
import { HypervisorApplicationsCatalogSurface } from "../../../surfaces/Applications/ApplicationsCatalogView";
import { applicationViewForId } from "../../../surfaces/Applications/applicationSurfaceCatalog";
import {
  useHypervisorShellController,
  type HypervisorReceiptEvidenceTarget,
} from "../useHypervisorShellController";
import { type HypervisorClientRuntime } from "../../../services/HypervisorClientRuntime";
import { buildConnectorTrustProfile } from "../../../surfaces/Capabilities";
import { shouldAttemptHypervisorDaemonProjectionFetch } from "../hypervisorDaemonEndpoint";
import { HypervisorActivityRail } from "./HypervisorActivityRail";
import { CapabilitiesView } from "../../../surfaces/Capabilities";
import { EnvironmentEstateView } from "../../../surfaces/Environments/EnvironmentEstateView";
import { InboxView } from "../../../surfaces/Inbox";
import { SettingsView } from "../../../surfaces/Settings";
import { AuthoritySettingsSurfaceView } from "../../../surfaces/Authority";
import { AutomationsWorkflowComposerView } from "../../../surfaces/Automations";
import { RuntimeInsightsView } from "../../../surfaces/Insights";
import { ModelMountsSurfaceView } from "../../../surfaces/Models";
import { HomeView } from "../../../surfaces/Home";
import { WorkspaceShell } from "../../../surfaces/Workspace";
import { getDefaultWorkspaceSessionHost } from "../../../services/workspaceSessionHostRegistry";
import {
  HYPERVISOR_AGENTS_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_AGENTS_PROJECTION_FIXTURE,
  loadHypervisorAgentsProjection,
  requestWorkerPackageInstallAdmission,
  type HypervisorAgentRecord,
  type HypervisorAgentsProjection,
  type HypervisorWorkerPackageInstallAdmission,
} from "../../../domain/hypervisorAgentsModel";
import {
  buildHypervisorAutomationRunProposal,
  HYPERVISOR_AUTOMATION_COMPOSITOR_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION,
  loadHypervisorAutomationCompositorProjection,
  proposeHypervisorAutomationRun,
  type HypervisorAutomationGraph,
  type HypervisorAutomationRunProposal,
  type HypervisorAutomationRunRecipe,
  type HypervisorAutomationTemplate,
} from "../hypervisorAutomationCompositorModel";
import {
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY,
  buildHypervisorAgentSelectorOptions,
  buildHypervisorModelOptions,
  requestHarnessPublicFixtureRun,
  type HypervisorAgentSelectorOption,
  type HypervisorModelOption,
} from "../../../domain/harnessAdapterModel";
import { AgentModelSelector, ModelRouteSelector } from "./AgentModelSelector";
import {
  HYPERVISOR_MODEL_INFRASTRUCTURE_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_MODEL_INFRASTRUCTURE_PROJECTION_FIXTURE,
  loadHypervisorModelInfrastructureProjection,
  requestHypervisorModelRouteMutationAdmission,
  type HypervisorModelInfrastructureProvider,
  type HypervisorModelInfrastructureRoute,
  type HypervisorModelInfrastructureSessionBinding,
  type HypervisorModelRouteMutationAdmission,
} from "../../../domain/hypervisorModelInfrastructureModel";
import {
  HYPERVISOR_PRIVACY_POSTURE_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE,
  loadHypervisorPrivacyPostureProjection,
  modelWeightCustodyAdmissionAction,
  requestHypervisorModelWeightCustodyAdmission,
  requestHypervisorPrivateWorkspaceMountAdmission,
  type HypervisorModelWeightCustodyAdmission,
  type HypervisorModelWeightCustodyPolicy,
  type HypervisorPrivateWorkspaceMountAdmission,
  type HypervisorWorkspaceCustodySegment,
} from "../hypervisorPrivacyPostureModel";
import {
  buildHypervisorProjectOperationProposal,
  HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION,
  HYPERVISOR_PROJECT_STATE_DAEMON_ENDPOINT_STORAGE_KEY,
  loadHypervisorProjectStateProjection,
  proposeHypervisorProjectOperation,
  requestHypervisorProjectCreate,
  type HypervisorProjectOperationKind,
  type HypervisorProjectOperationProposal,
  type HypervisorProjectStateProjection,
  type HypervisorProjectStateRecord,
} from "../hypervisorProjectStateModel";
import {
  buildHypervisorProviderOperationProposal,
  HYPERVISOR_PROVIDER_PLACEMENT_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  HYPERVISOR_PROVIDER_OPERATION_KINDS,
  loadHypervisorProviderPlacementProjection,
  proposeHypervisorProviderOperation,
  type HypervisorProviderOperationKind,
  type HypervisorProviderOperationProposal,
  type HypervisorProviderPlacementCandidate,
} from "../../../domain/hypervisorProviderPlacementModel";
import {
  HYPERVISOR_RECEIPT_EVIDENCE_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  loadHypervisorReceiptEvidenceProjection,
  type HypervisorReceiptEvidenceKind,
  type HypervisorReceiptEvidenceRecord,
} from "../hypervisorReceiptEvidenceModel";
import {
  buildHypervisorSessionOperationProposal,
  HYPERVISOR_ENVIRONMENT_COMPONENT_LABELS,
  HYPERVISOR_ENVIRONMENT_COMPONENT_ORDER,
  HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  loadHypervisorSessionOperationsProjection,
  proposeHypervisorSessionOperation,
  type HypervisorSessionOperationKind,
  type HypervisorSessionOperationProposal,
} from "../../../domain/hypervisorSessionOperationsModel";
import { useHypervisorSessionOperationsProjectionSubscription } from "../useHypervisorSessionOperationsProjectionSubscription";
import {
  HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES,
  HYPERVISOR_SESSION_WORKSPACE_MODES,
  buildHypervisorNewSessionLaunchRequest,
  isHypervisorSurfaceId,
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchRequest,
} from "../hypervisorShellNavigationModel";

const insightsDashboardPreviewUrl = new URL(
  "../../../assets/reference/insights-dashboard.webp",
  import.meta.url,
).href;

interface HypervisorShellContentProps {
  controller: ReturnType<typeof useHypervisorShellController>;
  runtime: HypervisorClientRuntime;
}

const HYPERVISOR_PROJECT_ENVIRONMENT_CLASS_OPTIONS = [
  {
    ref: "environment-class:ona-cloud-us01-small",
    label: "Small Ona Cloud (US01)",
    details: "2 vCPU / 8 GiB / 50 GiB disk",
  },
  {
    ref: "environment-class:ona-cloud-us01-regular",
    label: "Regular Ona Cloud (US01)",
    details: "4 vCPU / 16 GiB / 80 GiB disk",
  },
  {
    ref: "environment-class:ona-cloud-us01-large",
    label: "Large Ona Cloud (US01)",
    details: "8 vCPU / 32 GiB / 100 GiB disk",
  },
  {
    ref: "environment-class:local-dev-replay",
    label: "Local dev replay",
    details: "No provider auth required",
  },
] as const;

function isGitRepositoryUrl(value: string): boolean {
  return /^https?:\/\/[^/\s]+\/[^/\s]+\/[^/\s]+/i.test(value.trim());
}

function projectNameFromRepositoryUrl(value: string): string {
  const normalized = value.trim().replace(/\/+$/, "");
  return (
    normalized
      .split("/")
      .pop()
      ?.replace(/\.git$/i, "")
      .trim() || ""
  );
}

function HypervisorHarnessComparisonDashboard() {
  const [comparison, setComparison] = useState(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  );
  const [runState, setRunState] = useState<
    "loading" | "requesting" | "admitted" | "unavailable"
  >("loading");
  const [runMessage, setRunMessage] = useState(
    "Loading governed replay comparison from the local daemon-shaped route.",
  );

  async function requestComparisonRun() {
    setRunState("requesting");
    setRunMessage("Requesting governed comparison run...");
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      setRunState("unavailable");
      setRunMessage(
        "Attach a Hypervisor Daemon endpoint before refreshing the governed comparison route.",
      );
      return;
    }
    try {
      const nextComparison = await requestHarnessPublicFixtureRun();
      setComparison(nextComparison);
      setRunState("admitted");
      setRunMessage(
        `Run returned ${nextComparison.receipt_refs.length} receipt refs for ${nextComparison.candidate_reports.length} harness candidates.`,
      );
    } catch (error) {
      setRunState("unavailable");
      setRunMessage(
        error instanceof Error
          ? error.message
          : "Harness comparison could not reach the governed route.",
      );
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadInitialComparison() {
      if (
        !shouldAttemptHypervisorDaemonProjectionFetch(
          HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY,
        )
      ) {
        setRunState("unavailable");
        setRunMessage(
          "Attach a Hypervisor Daemon endpoint before refreshing the governed comparison route.",
        );
        return;
      }

      try {
        const nextComparison = await requestHarnessPublicFixtureRun();
        if (cancelled) return;
        setComparison(nextComparison);
        setRunState("admitted");
        setRunMessage(
          `Route-backed comparison loaded ${nextComparison.candidate_reports.length} harness candidates with ${nextComparison.receipt_refs.length} receipt refs.`,
        );
      } catch (error) {
        if (cancelled) return;
        setRunState("unavailable");
        setRunMessage(
          error instanceof Error
            ? error.message
            : "Harness comparison could not reach the governed route.",
        );
      }
    }

    void loadInitialComparison();

    return () => {
      cancelled = true;
    };
  }, []);

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
            Foundry reads the same comparison contract as New Session, then
            makes output, cost, verification, receipts, and evidence visible
            before any adapter is treated as reliable.
          </p>
        </div>
        <button
          type="button"
          data-harness-comparison-action="request-run"
          disabled={runState === "requesting" || runState === "loading"}
          onClick={requestComparisonRun}
        >
          {runState === "requesting" || runState === "loading"
            ? "Requesting..."
            : "Refresh comparison"}
        </button>
      </div>
      <p
        className="hypervisor-harness-comparison__runtime-state"
        data-harness-comparison-state={runState}
      >
        {runMessage}
      </p>

      <div className="hypervisor-harness-comparison__summary" aria-label="Comparison summary">
        <div>
          <span>Task</span>
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

function HypervisorAgentsSurface({
  currentProjectId,
  children,
  onOpenSessions,
  onOpenReceipts,
  onOpenAuthority,
}: {
  currentProjectId: string;
  children: ReactNode;
  onOpenSessions: () => void;
  onOpenReceipts: () => void;
  onOpenAuthority: () => void;
}) {
  const [projection, setProjection] = useState<HypervisorAgentsProjection>(
    HYPERVISOR_AGENTS_PROJECTION_FIXTURE,
  );
  const [installAdmissionState, setInstallAdmissionState] =
    useState<HypervisorWorkerPackageInstallAdmissionState>({
      status: "idle",
    });

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_AGENTS_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
    let cancelled = false;
    loadHypervisorAgentsProjection({ projectId: currentProjectId })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn("[Hypervisor][Agents] projection unavailable", error);
      });
    return () => {
      cancelled = true;
    };
  }, [currentProjectId]);

  const activeAgents = projection.records.filter(
    (agent) => agent.status === "running",
  ).length;
  const blockedAgents = projection.records.filter(
    (agent) => agent.status === "blocked",
  ).length;
  const activeLeases = projection.records.reduce(
    (count, agent) =>
      count +
      agent.capability_leases.filter((lease) => lease.status === "active")
        .length,
    0,
  );
  const reviewLeases = projection.records.reduce(
    (count, agent) =>
      count +
      agent.capability_leases.filter(
        (lease) =>
          lease.status === "requires_step_up" || lease.status === "expiring",
      ).length,
    0,
  );
  const [selectedAgentRef, setSelectedAgentRef] = useState<string | null>(
    projection.records[0]?.agent_ref ?? null,
  );
  const selectedAgent =
    projection.records.find((agent) => agent.agent_ref === selectedAgentRef) ??
    projection.records[0] ??
    null;

  useEffect(() => {
    setInstallAdmissionState({ status: "idle" });
  }, [selectedAgent?.agent_ref]);

  useEffect(() => {
    if (
      !selectedAgentRef ||
      !projection.records.some((agent) => agent.agent_ref === selectedAgentRef)
    ) {
      setSelectedAgentRef(projection.records[0]?.agent_ref ?? null);
    }
  }, [projection.records, selectedAgentRef]);

  const requestSelectedAgentInstallAdmission = async () => {
    if (!selectedAgent) return;
    setInstallAdmissionState({ status: "requesting" });
    try {
      const admission = await requestWorkerPackageInstallAdmission({
        agent: selectedAgent,
      });
      setInstallAdmissionState({ status: "admitted", admission });
    } catch (error) {
      const hasHttpStatus = Boolean(
        typeof error === "object" &&
          error !== null &&
          "status" in error &&
          Number.isFinite(Number((error as { status?: unknown }).status)),
      );
      const status: "blocked" | "unavailable" = hasHttpStatus
        ? "blocked"
        : "unavailable";
      setInstallAdmissionState({
        status,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  };

  return (
    <section
      className="hypervisor-agents"
      aria-label="Hypervisor agents"
      data-hypervisor-agents={projection.projection_id}
      data-hypervisor-agents-source={projection.source}
    >
      <div className="hypervisor-agents__header">
        <div>
          <h2>Agents</h2>
        </div>
        <div className="hypervisor-agents__header-actions">
          <button type="button" onClick={onOpenAuthority}>
            New agent
          </button>
        </div>
      </div>

      <div className="hypervisor-agents__workplane">
        <div className="hypervisor-agents__primary">
          <div className="hypervisor-agents__filters" aria-label="Agent controls">
            <div className="hypervisor-agents__tabs" aria-label="Agent filters">
              <button type="button" className="is-active">
                All <span>{projection.records.length}</span>
              </button>
              <button type="button">
                Running <span>{activeAgents}</span>
              </button>
              <button type="button">
                Review <span>{blockedAgents}</span>
              </button>
            </div>
            <label className="hypervisor-agents__search">
              <span aria-hidden="true">⌕</span>
              <input type="search" placeholder="Search agents..." readOnly />
            </label>
            <button type="button">Sort: Updated</button>
          </div>

          <dl
            className="hypervisor-agents__summary-strip"
            aria-label="Agent access summary"
          >
            <div>
              <dt>Active access</dt>
              <dd>{activeLeases}</dd>
            </div>
            <div>
              <dt>Needs review</dt>
              <dd>{reviewLeases}</dd>
            </div>
            <div>
              <dt>Selected</dt>
              <dd>{selectedAgent ? selectedAgent.label : "None"}</dd>
            </div>
          </dl>

          <div className="hypervisor-agents__list" role="list" aria-label="Agents list">
            <div className="hypervisor-agents__list-head" role="presentation">
              <span>Agent</span>
              <span>Interface</span>
              <span>Access</span>
              <span>Updated</span>
            </div>
            {projection.records.map((agent) => (
              <HypervisorAgentRow
                key={agent.agent_ref}
                agent={agent}
                selected={selectedAgent?.agent_ref === agent.agent_ref}
                onSelect={() => setSelectedAgentRef(agent.agent_ref)}
              />
            ))}
          </div>
        </div>

        <aside className="hypervisor-agents__side" aria-label="Agent setup">
          <div className="hypervisor-agents__side-head">
            <h3>Agent setup</h3>
            <p>
              Choose how this agent works, what it can access, and when
              approvals are required.
            </p>
          </div>

          {selectedAgent ? (
            <div
              className="hypervisor-agents__inline-inspector"
              aria-label="Selected agent"
            >
              <HypervisorAgentDetail
                agent={selectedAgent}
                installAdmission={installAdmissionState}
                onRequestInstallAdmission={requestSelectedAgentInstallAdmission}
                onOpenSessions={onOpenSessions}
                onOpenReceipts={onOpenReceipts}
                onOpenAuthority={onOpenAuthority}
              />
            </div>
          ) : null}
        </aside>
      </div>

      <div
        className="hypervisor-agents__capability-client"
        data-agent-capability-management-boundary="capability-client"
        hidden
      >
        {children}
      </div>
    </section>
  );
}

type HypervisorWorkerPackageInstallAdmissionState =
  | { status: "idle" }
  | { status: "requesting" }
  | {
      status: "admitted";
      admission: HypervisorWorkerPackageInstallAdmission;
    }
  | { status: "blocked" | "unavailable"; message: string };

function formatWorkerPackageInstallAdmission(
  state: HypervisorWorkerPackageInstallAdmissionState,
): string {
  if (state.status === "admitted") {
    return "Daemon admitted";
  }
  if (state.status === "blocked") {
    return "Daemon blocked";
  }
  if (state.status === "unavailable") {
    return "Daemon unavailable";
  }
  if (state.status === "requesting") {
    return "Requesting";
  }
  return "Not requested";
}

function firstCapabilityLease(agent: HypervisorAgentRecord) {
  return agent.capability_leases[0] ?? null;
}

function formatAgentHarnessLabel(label: string): string {
  if (/default harness profile/i.test(label)) {
    return "Built-in";
  }
  if (/generic cli harness/i.test(label)) {
    return "Terminal";
  }
  if (/cli/i.test(label)) {
    return "Code tool";
  }
  return label.replace(/\s+harness$/i, "").replace(/\s+adapter$/i, "");
}

function formatCapabilityRef(ref: string): string {
  return ref
    .replace(/^scope:/, "")
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatModelRouteRef(ref: string): string {
  if (ref === "model-route:hypervisor/default-local") {
    return "Local model";
  }
  if (ref === "model-route:adapter-native") {
    return "Adapter model";
  }
  if (ref.startsWith("model-route:provider/")) {
    return `${ref.replace("model-route:provider/", "")} provider`;
  }
  return ref.replace(/^model-route:/, "").replace(/[/:_-]+/g, " ");
}

function formatProviderRef(ref: string): string {
  if (ref.includes("hypervisor-local") || ref.includes("local")) {
    return "Local provider";
  }
  if (ref.includes("customer")) {
    return "Customer cloud";
  }
  if (ref.includes("tee")) {
    return "Confidential compute";
  }
  if (ref.includes("hosted")) {
    return "Hosted API";
  }
  return ref
    .replace(/^provider:/, "")
    .replace(/[/:_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatPrivacyPostureRef(ref: string): string {
  if (ref === "privacy:ctee-private-workspace") {
    return "Private workspace";
  }
  if (ref === "privacy:redacted-projection") {
    return "Redacted projection";
  }
  return ref
    .replace(/^privacy:/, "")
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatCustodyLane(value: string): string {
  if (value === "public_trunk") {
    return "Public trunk";
  }
  if (value === "redacted_projection") {
    return "Redacted projection";
  }
  if (value === "encrypted_blob_ref") {
    return "Encrypted state";
  }
  if (value === "private_head") {
    return "Private head";
  }
  if (value === "capability_exit") {
    return "Capability exit";
  }
  if (value === "custody-profile:model/local") {
    return "Local model";
  }
  if (value === "local_or_open_weight" || value === "open_or_local_weights") {
    return "Local or open weights";
  }
  if (value === "remote_api_capability") {
    return "Remote API";
  }
  if (value === "tee_or_customer_cloud_mount") {
    return "Confidential mount";
  }
  if (value === "provider_trust_mount") {
    return "Provider-trust mount";
  }
  if (value === "forbidden_plaintext_mount") {
    return "Plaintext blocked";
  }
  if (value === "provider_trust_remote_mount") {
    return "Provider trust";
  }
  if (value === "private_native") {
    return "Private native";
  }
  if (value === "ctee_split") {
    return "Private workspace";
  }
  if (value === "encrypted_storage_only") {
    return "Encrypted storage";
  }
  if (value === "confidential_compute") {
    return "Confidential compute";
  }
  if (value === "remote_api_provider_trust") {
    return "Remote API";
  }
  return value
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatModelWeightProtection(
  policy: { lane: string; protects_model_weights_from_provider_root: boolean },
): string {
  if (policy.lane === "forbidden_plaintext_mount") {
    return "Plaintext blocked";
  }
  return policy.protects_model_weights_from_provider_root
    ? "Weights protected"
    : "Provider trust required";
}

function formatPrivacyOwner(value: string): string {
  if (value === "wallet_network") {
    return "Wallet authority";
  }
  if (value === "hypervisor_core" || value === "hypervisor_daemon") {
    return "Hypervisor";
  }
  if (value === "agentgres") {
    return "State log";
  }
  if (value === "storage_backend") {
    return "Storage";
  }
  return value
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatWorkspaceRef(ref: string): string {
  return ref
    .replace(/^workspace:\/\/ioi\//, "")
    .replace(/^workspace:\/\//, "")
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatLeaseExpiry(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return `Until ${new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date)}`;
}

function statusLabel(status: string): string {
  return status.replace(/_/g, " ");
}

function formatAgentUpdatedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function HypervisorAgentRow({
  agent,
  selected,
  onSelect,
}: {
  agent: HypervisorAgentRecord;
  selected: boolean;
  onSelect: () => void;
}) {
  const lease = firstCapabilityLease(agent);

  return (
    <button
      type="button"
      className="hypervisor-agents__row"
      role="listitem"
      aria-current={selected ? "true" : undefined}
      data-hypervisor-agent-record={agent.agent_ref}
      data-agent-status={agent.status}
      data-agent-harness-boundary={agent.runtime.truth_boundary}
      onClick={onSelect}
    >
      <span className="hypervisor-agents__row-agent">
        <i aria-hidden="true" />
        <span>
          <strong>{agent.label}</strong>
          <em>{statusLabel(agent.status)}</em>
        </span>
      </span>
      <span className="hypervisor-agents__row-harness">
        {formatAgentHarnessLabel(agent.runtime.harness_label)}
      </span>
      <span
        className="hypervisor-agents__row-lease"
        data-agent-capability-lease={lease?.lease_ref ?? "none"}
        data-agent-capability-lease-status={lease?.status ?? "none"}
      >
        {lease ? formatCapabilityRef(lease.capability_ref) : "No active scope"}
      </span>
      <span className="hypervisor-agents__row-receipt">
        {formatAgentUpdatedAt(agent.updated_at)}
      </span>
    </button>
  );
}

function HypervisorAgentDetail({
  agent,
  installAdmission,
  onRequestInstallAdmission,
  onOpenSessions,
  onOpenReceipts,
  onOpenAuthority,
}: {
  agent: HypervisorAgentRecord;
  installAdmission: HypervisorWorkerPackageInstallAdmissionState;
  onRequestInstallAdmission: () => void;
  onOpenSessions: () => void;
  onOpenReceipts: () => void;
  onOpenAuthority: () => void;
}) {
  return (
    <section
      className="hypervisor-agents__detail"
      aria-label={`${agent.label} details`}
      data-hypervisor-agent-detail={agent.agent_ref}
      data-agent-status={agent.status}
      data-agent-harness-boundary={agent.runtime.truth_boundary}
      data-agent-model-route-ref={agent.runtime.model_route_ref}
      data-agent-privacy-posture-ref={agent.runtime.privacy_posture_ref}
      data-agent-workspace-ref={agent.workspace_ref}
      data-agent-state-root-ref={agent.state_root_ref}
      data-agent-latest-receipt-ref={agent.latest_receipt_refs[0] ?? ""}
    >
      <div className="hypervisor-agents__detail-column">
        <div className="hypervisor-agents__detail-head">
          <span className="hypervisor-agents__detail-label">Selected agent</span>
          <span>{statusLabel(agent.status)}</span>
          <h3>{agent.label}</h3>
          <p>{agent.objective}</p>
        </div>
      </div>

      <div className="hypervisor-agents__detail-column">
        <dl className="hypervisor-agents__runtime">
          <div>
            <dt>Interface</dt>
            <dd>
              <span>{formatAgentHarnessLabel(agent.runtime.harness_label)}</span>
            </dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd>
              <span>{formatModelRouteRef(agent.runtime.model_route_ref)}</span>
            </dd>
          </div>
          <div>
            <dt>Privacy</dt>
            <dd>
              <span>{formatPrivacyPostureRef(agent.runtime.privacy_posture_ref)}</span>
            </dd>
          </div>
          <div>
            <dt>Workspace</dt>
            <dd>
              <span>{formatWorkspaceRef(agent.workspace_ref)}</span>
            </dd>
          </div>
        </dl>

        <section className="hypervisor-agents__detail-section">
          <h4>Skills</h4>
          <div className="hypervisor-agents__chips" aria-label="Agent skills">
            {agent.skill_bindings.slice(0, 3).map((skill) => (
              <span key={skill.skill_ref} data-agent-skill-ref={skill.skill_ref}>
                {skill.label}
              </span>
            ))}
          </div>
        </section>
      </div>

      <div className="hypervisor-agents__detail-column">
        <section className="hypervisor-agents__detail-section">
          <h4>Access</h4>
          <div className="hypervisor-agents__lease-list" aria-label="Agent access">
            {agent.capability_leases.slice(0, 2).map((lease) => (
              <span
                key={lease.lease_ref}
                data-agent-capability-lease={lease.lease_ref}
                data-agent-capability-lease-status={lease.status}
              >
                <strong>{formatCapabilityRef(lease.capability_ref)}</strong>
                <em>{lease.status.replace(/_/g, " ")}</em>
                <small>{formatLeaseExpiry(lease.expires_at)}</small>
              </span>
            ))}
          </div>
        </section>

        <dl className="hypervisor-agents__refs">
          <div>
            <dt>Evidence</dt>
            <dd>{agent.latest_receipt_refs.length} receipts</dd>
          </div>
          <div>
            <dt>Checkpoint</dt>
            <dd>Current</dd>
          </div>
          <div
            data-agent-worker-package-install-admission={
              installAdmission.status
            }
          >
            <dt>Install admission</dt>
            <dd>{formatWorkerPackageInstallAdmission(installAdmission)}</dd>
          </div>
        </dl>

        <div className="hypervisor-agents__actions">
          <button type="button" onClick={onOpenSessions}>
            Open session
          </button>
          <button
            type="button"
            onClick={onRequestInstallAdmission}
            disabled={installAdmission.status === "requesting"}
          >
            {installAdmission.status === "requesting"
              ? "Requesting"
              : "Admit package"}
          </button>
          <button type="button" onClick={onOpenAuthority}>
            Manage access
          </button>
          <button type="button" onClick={onOpenReceipts}>
            Receipts
          </button>
        </div>
      </div>
    </section>
  );
}

function HypervisorAutomationCompositorSurface({
  currentProjectId,
  children,
}: {
  currentProjectId: string;
  children: ReactNode;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION,
  );
  const [runProposal, setRunProposal] =
    useState<HypervisorAutomationRunProposal | null>(null);

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_AUTOMATION_COMPOSITOR_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
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

  const referenceTemplates = [
    {
      label: "Scan recent commits for bugs",
      description:
        "Finds likely bugs in recent commits and opens a draft PR with proposed fixes.",
      icon: "Q",
      tone: "orange",
    },
    {
      label: "Draft weekly release notes",
      description:
        "Turns merged PRs into categorized release notes with concise summaries.",
      icon: "D",
      tone: "blue",
    },
    {
      label: "Add optimized AGENTS.md",
      description:
        "Creates or updates AGENTS.md with project-specific guidance for coding agents.",
      icon: "A",
      tone: "gray",
    },
    {
      label: "10x engineer",
      description:
        "Picks your highest-priority Linear issue, implements it, runs tests, and opens a draft PR.",
      icon: "10",
      tone: "blue",
    },
    {
      label: "Daily standup generator",
      description:
        "Combines Linear and Git activity into a daily standup update.",
      icon: "D",
      tone: "green",
    },
    {
      label: "Tech spec from Linear issue",
      description:
        "Turns a Linear issue into an implementation-ready spec with technical design and execution details.",
      icon: "T",
      tone: "blue",
    },
    {
      label: "Automated dev environment setup",
      description:
        "Standardizes your development environment and opens a PR with the required updates.",
      icon: "A",
      tone: "green",
    },
    {
      label: "CVE mitigation & dependency updates",
      description:
        "Fixes vulnerable or outdated dependencies, validates changes, and opens a PR.",
      icon: "C",
      tone: "purple",
    },
  ];
  const referenceAutomationTotal = 4;
  const automationRows = useMemo(() => {
    if (projection.source !== "daemon-automation-compositor-projection") {
      return [];
    }
    return projection.templates.flatMap((template) => {
      const recipe =
        projection.run_recipes.find(
          (candidate) => candidate.run_recipe_ref === template.recipe_ref,
        ) ?? null;
      if (!recipe) {
        return [];
      }
      const graph =
        projection.graphs.find(
          (candidate) => candidate.graph_ref === template.graph_ref,
        ) ?? null;
      const run = projection.runs.find(
        (candidate) => candidate.template_ref === template.template_ref,
      );
      return [
        {
          template,
          recipe,
          graph,
          label: template.label,
          status: run?.status ?? "ready",
          icon:
            recipe.schedule_ref === "schedule:manual"
              ? ("play" as const)
              : ("calendar" as const),
          runnable:
            (run?.status ?? "ready") === "ready" ||
            (run?.status ?? "ready") === "scheduled",
        },
      ];
    });
  }, [projection]);

  const onRunAutomation = (
    template: HypervisorAutomationTemplate,
    recipe: HypervisorAutomationRunRecipe,
    graph: HypervisorAutomationGraph | null,
  ) => {
    proposeHypervisorAutomationRun({
      projection,
      template,
      recipe,
      graph,
    })
      .then((proposal) => setRunProposal(proposal))
      .catch((error) => {
        console.warn(
          "[Hypervisor][Automations] run proposal unavailable",
          error,
        );
        setRunProposal(
          buildHypervisorAutomationRunProposal(projection, template, recipe, graph, {
            source: "unverified",
          }),
        );
      });
  };

  const onProposeSuggestedTemplate = (index: number) => {
    const row = automationRows[index] ?? automationRows[0];
    if (!row) {
      return;
    }
    onRunAutomation(row.template, row.recipe, row.graph);
  };

  return (
    <section
      className="hypervisor-automation-compositor hypervisor-automation-compositor--ioi-reference"
      aria-label="Automation compositor projection"
      data-hypervisor-automation-compositor={projection.projection_id}
      data-automation-compositor-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
      data-workflow-compositor-surface="workflow-composer"
    >
      <header className="hypervisor-automation-compositor__topbar">
        <h2>Automations</h2>
        <div className="hypervisor-automation-compositor__topbar-actions">
          <button
            type="button"
            className="hypervisor-automation-compositor__webhooks"
          >
            <span aria-hidden="true">{"<>"}</span>
            <span>Webhooks</span>
          </button>
          <button type="button" className="hypervisor-automation-compositor__new">
            <span aria-hidden="true">+</span>
            <span>New</span>
          </button>
        </div>
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
              value={referenceAutomationTotal}
            />
            <AutomationMetric label="Successful - 7d" value={0} />
            <AutomationMetric label="Failed - 7d" value={0} />
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
                Yours
              </button>
              <button type="button">All ({referenceAutomationTotal})</button>
            </div>
          </div>

          <section
            className="hypervisor-automation-compositor__table"
            aria-label="Workflow templates"
          >
            {automationRows.length > 0 ? (
              automationRows.map((row) => (
                <article
                  key={row.template.template_ref}
                  className="hypervisor-automation-compositor__row"
                  data-workflow-template-ref={row.template.template_ref}
                  data-workflow-run-recipe-ref={row.recipe.run_recipe_ref}
                  data-workflow-graph-ref={row.graph?.graph_ref ?? row.template.graph_ref}
                >
                  <span className="hypervisor-automation-compositor__row-icon">
                    <AutomationRowIcon kind={row.icon} />
                  </span>
                  <span className="hypervisor-automation-compositor__row-copy">
                    <strong>{row.label}</strong>
                    <em>{row.status}</em>
                  </span>
                  {row.runnable ? (
                    <button
                      type="button"
                      className="hypervisor-automation-compositor__row-run"
                      data-automation-run-proposal-template={
                        row.template.template_ref
                      }
                      onClick={() =>
                        onRunAutomation(row.template, row.recipe, row.graph)
                      }
                    >
                      Run
                    </button>
                  ) : (
                    <span aria-hidden="true" />
                  )}
                  <button
                    type="button"
                    aria-label={`Open ${row.label} actions`}
                    className="hypervisor-automation-compositor__row-menu"
                  >
                    ...
                  </button>
                </article>
              ))
            ) : (
              <div className="hypervisor-automation-compositor__empty">
                <strong>No automations yet</strong>
                <span>
                  You haven't created any automations yet. Choose a template or
                  click + New to get started.
                </span>
              </div>
            )}
          </section>

          {runProposal ? (
            <section
              className="hypervisor-automation-compositor__proposal"
              aria-label="Automation run proposal"
              data-automation-run-proposal={runProposal.proposal_ref}
              data-automation-run-proposal-source={runProposal.source}
              data-automation-run-admission-state={
                runProposal.admission_state
              }
            >
              <strong>Run proposal</strong>
              <span>{runProposal.operation_kind}</span>
              <span>{runProposal.admission_state.replace(/_/g, " ")}</span>
              <span>{runProposal.receipt_ref}</span>
            </section>
          ) : null}
        </main>

        <aside
          className="hypervisor-automation-compositor__suggested"
          aria-label="Suggested templates"
        >
          <div className="hypervisor-automation-compositor__suggested-heading">
            <h3>Suggested templates</h3>
            <p>Try these automations for common engineering workflows.</p>
          </div>
          {referenceTemplates.map((template, index) => (
            <button
              type="button"
              key={template.label}
              className="hypervisor-automation-compositor__suggested-card"
              data-workflow-template-suggestion={template.label}
              data-automation-run-proposal-template={
                automationRows[index]?.template.template_ref ??
                automationRows[0]?.template.template_ref ??
                ""
              }
              data-template-tone={template.tone}
              disabled={automationRows.length === 0}
              onClick={() => onProposeSuggestedTemplate(index)}
            >
              <span className="hypervisor-automation-compositor__suggested-icon">
                {template.icon}
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

function HypervisorInsightsReferenceSurface({
  children,
}: {
  children: ReactNode;
}) {
  const useCases = [
    {
      marker: "01",
      title: "Analyze usage across your organization",
      description:
        "Monitor session usage patterns in real time. See resource consumption for users, projects, and environment classes.",
    },
    {
      marker: "02",
      title: "Maximize ROI and manage costs",
      description:
        "Find optimization opportunities across user activity, project activity, and resource allocation.",
    },
    {
      marker: "03",
      title: "Drive team productivity through insights",
      description:
        "Review adoption trends, agent activity, and usage patterns across users and projects.",
    },
  ];

  return (
    <section
      className="hypervisor-insights-reference"
      aria-label="Hypervisor insights"
      data-hypervisor-insights-reference="ioi-reference-enterprise"
    >
      <div className="hypervisor-insights-reference__hero">
        <span className="hypervisor-insights-reference__badge">
          Available on Enterprise
        </span>
        <h2>Turn Insights into actionable intelligence</h2>
        <p>
          Hypervisor Insights provides analytics to monitor, understand, and
          optimize autonomous workspace usage, improving team productivity and
          cost effectiveness.
        </p>
        <div className="hypervisor-insights-reference__actions">
          <button type="button">Request trial</button>
          <a href="https://ioi.com/docs/ioi/organizations/insights">
            Learn more
          </a>
        </div>
      </div>

      <div className="hypervisor-insights-reference__body">
        <div className="hypervisor-insights-reference__use-cases">
          <h3>Use Insights to:</h3>
          {useCases.map((useCase) => (
            <article key={useCase.title}>
              <span>{useCase.marker}</span>
              <div>
                <h4>{useCase.title}</h4>
                <p>{useCase.description}</p>
              </div>
            </article>
          ))}
        </div>

        <figure className="hypervisor-insights-reference__preview">
          <img
            src={insightsDashboardPreviewUrl}
            alt="Hypervisor Insights dashboard"
          />
        </figure>
      </div>

      <div
        className="hypervisor-insights-reference__analytics-client"
        data-insights-runtime-projection-boundary="hidden-runs-client"
        hidden
      >
        {children}
      </div>
    </section>
  );
}

function AutomationRowIcon({ kind }: { kind: "play" | "calendar" }) {
  if (kind === "play") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <path
          d="M6 4.75v6.5L11 8 6 4.75Z"
          fill="currentColor"
        />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M4 2.75v2M12 2.75v2M3.25 6.25h9.5M4.25 4h7.5c.83 0 1.5.67 1.5 1.5v6.25c0 .83-.67 1.5-1.5 1.5h-7.5c-.83 0-1.5-.67-1.5-1.5V5.5c0-.83.67-1.5 1.5-1.5Z"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.25"
      />
      <circle cx="11" cy="10.75" r="1" fill="currentColor" />
    </svg>
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
      <strong>
        {value}
        {active ? <em aria-label="Updated">U</em> : null}
      </strong>
      {active ? (
        <svg aria-hidden="true" viewBox="0 0 112 42" preserveAspectRatio="none">
          <path d="M1 31 L19 7 L38 31 L56 8 L75 31 L94 8 L111 31" />
        </svg>
      ) : null}
    </div>
  );
}

function formatChangedFileStatus(status: string): string {
  const statusLabel: Record<string, string> = {
    added: "A",
    modified: "M",
    deleted: "D",
    untracked: "U",
  };
  return statusLabel[status] ?? status.charAt(0).toUpperCase();
}

function SessionCodeIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M13.69 3.2 11.17 1.98a.78.78 0 0 0-.87.15L5.47 6.53 3.37 4.94a.5.5 0 0 0-.65.03l-.68.61a.52.52 0 0 0 0 .75L3.87 8l-1.83 1.66a.52.52 0 0 0 0 .76l.68.61c.18.17.46.18.65.03l2.1-1.6 4.83 4.41c.23.23.58.29.87.15l2.52-1.22c.27-.13.44-.4.44-.69V3.88c0-.29-.17-.56-.44-.68Zm-2.63 7.58L7.4 8l3.66-2.78v5.56Z"
        fill="currentColor"
      />
    </svg>
  );
}

function SessionOctagonIcon() {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path
        d="M30.95 9.86A3.55 3.55 0 0 1 32 12.38v8.29c0 1-.41 1.88-1.05 2.52l-8.29 8.28A3.55 3.55 0 0 1 20.14 32h-8.28a3.55 3.55 0 0 1-2.57-1.05L1.01 22.66A3.55 3.55 0 0 1 0 20.14v-8.28c0-1 .37-1.88 1.01-2.57l8.28-8.28A3.55 3.55 0 0 1 11.86 0h8.28c.96 0 1.88.41 2.52 1.1l8.29 8.76ZM24.4 21.36v-9.68a3.59 3.59 0 0 0-3.57-3.61h-9.67a3.6 3.6 0 0 0-3.62 3.61v9.68a3.58 3.58 0 0 0 3.62 3.57h9.67a3.57 3.57 0 0 0 3.57-3.57Z"
        fill="currentColor"
      />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="m5 6.75 2.47 2.47a.75.75 0 0 0 1.06 0L11 6.75"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.35"
      />
    </svg>
  );
}

function CompactEditorIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M17.02 23.84c.38.15.81.14 1.19-.05l4.94-2.38A1.5 1.5 0 0 0 24 20.06V3.94c0-.58-.33-1.1-.85-1.35L18.21.21a1.5 1.5 0 0 0-1.71.29L7.05 9.13 2.92 6a1 1 0 0 0-1.27.06L.33 7.26a1 1 0 0 0 0 1.48L3.9 12 .33 15.26a1 1 0 0 0 0 1.48l1.32 1.2a1 1 0 0 0 1.27.06l4.13-3.13 9.45 8.63c.15.15.32.26.52.34ZM18 6.55 10.83 12 18 17.45V6.55Z"
        fill="currentColor"
      />
    </svg>
  );
}

function EyeIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M1.75 8s2.25-4 6.25-4 6.25 4 6.25 4-2.25 4-6.25 4-6.25-4-6.25-4Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
      />
      <circle cx="8" cy="8" r="1.7" fill="currentColor" />
    </svg>
  );
}

function BranchIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M5 3.5v6.25A2.75 2.75 0 0 0 7.75 12.5H11M11 12.5l-1.75-1.75M11 12.5l-1.75 1.75M5 5.5h4.25A1.75 1.75 0 0 0 11 3.75V2.5"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.35"
      />
    </svg>
  );
}

function SplitPanelIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <rect x="2.5" y="3" width="11" height="10" fill="none" stroke="currentColor" strokeWidth="1.25" />
      <path d="M10 3.5v9" stroke="currentColor" strokeWidth="1.25" />
    </svg>
  );
}

function AddPanelIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M3 3h7v10H3zM12.5 6v4M10.5 8h4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.25" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M2.5 4.5h4l1.2 1.5h5.8v5.5h-11v-7Z"
        fill="none"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.15"
      />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M4.5 2.75h5L12 5.25v8H4.5v-10.5Z" fill="none" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.15" />
      <path d="M9.5 2.75v2.5H12" fill="none" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.15" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="m20 20-3.87-3.87m0 0A7.25 7.25 0 1 0 3.75 11a7.25 7.25 0 0 0 12.38 5.13Z"
        fill="none"
        stroke="currentColor"
        strokeLinecap="square"
        strokeWidth="1.5"
      />
    </svg>
  );
}

function PortEmptyIcon() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M5.5 10.5a3.5 3.5 0 0 1 0-5M10.5 5.5a3.5 3.5 0 0 1 0 5M7 9.25 9 6.75"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.2"
      />
    </svg>
  );
}

const HYPERVISOR_SESSION_AGENT_SELECTOR_OPTIONS =
  buildHypervisorAgentSelectorOptions();

// The session init panel is driven by the daemon-projected
// HypervisorEnvironmentStatus (component sub-phases), not a hardcoded timed
// animation. Component order + labels live in hypervisorSessionOperationsModel.

function HypervisorSessionOperationsCockpit({
  launchedSessions,
  currentProject,
  agentOptions,
  agentSelectionRef,
  onSelectAgent,
  modelOptions,
  modelSelectionRef,
  onSelectModel,
  onLaunchSession,
  onConfigureLaunch,
  onOpenReceiptEvidence,
}: {
  launchedSessions: readonly HypervisorLaunchedSessionProjection[];
  currentProject: { id: string; name: string; rootPath: string };
  agentOptions: readonly HypervisorAgentSelectorOption[];
  agentSelectionRef: string;
  onSelectAgent: (selectionRef: string) => void;
  modelOptions: readonly HypervisorModelOption[];
  modelSelectionRef: string;
  onSelectModel: (modelRef: string) => void;
  onLaunchSession: (
    request: HypervisorNewSessionLaunchRequest,
  ) => Promise<unknown> | unknown;
  onConfigureLaunch: (seedIntent: string | null) => void;
  onOpenReceiptEvidence: (target: HypervisorReceiptEvidenceTarget) => void;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  );
  const [operationProposal, setOperationProposal] =
    useState<HypervisorSessionOperationProposal | null>(null);
  const [composerText, setComposerText] = useState("");
  const [submittedIntents, setSubmittedIntents] = useState<
    Array<{
      intent_ref: string;
      text: string;
      receipt_ref: string;
      session_ref: string;
    }>
  >([]);
  const [conversation, setConversation] = useState<
    Array<{
      id: string;
      role: "user" | "assistant";
      text: string;
      streaming?: boolean;
      source?: string;
      receipt_ref?: string;
    }>
  >([]);
  const conversationSessionRef = useRef<string | null>(null);
  const autoTurnStartedRef = useRef<string | null>(null);
  const turnInFlightRef = useRef(false);
  const [turnStreaming, setTurnStreaming] = useState(false);
  const selectedModel =
    modelOptions.find((option) => option.model_ref === modelSelectionRef) ??
    modelOptions[0] ??
    null;
  const selectedModelName = selectedModel?.model_name ?? "qwen";
  const selectedHarnessLabel =
    agentOptions.find((option) => option.selection_ref === agentSelectionRef)
      ?.label ?? "Agent";

  // The Sessions cockpit projection is driven live by the session-events SSE
  // subscription (useHypervisorSessionOperationsProjectionSubscription, wired
  // below once activeSessionRef is known): a baseline load then folded
  // environment_status / workspace_change / terminal_chunk / receipt_projection
  // deltas, replacing the one-shot fetch.

  function handleSessionOperation(
    operationKind: HypervisorSessionOperationKind,
    targetRef?: string,
  ) {
    if (operationKind === "request_access_lease" && !canOpenSessionSurface) {
      return;
    }
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

  const canOpenSessionSurface =
    projection.selected_adapter_admission_state === "daemon_admitted";
  const sessionOpenSurfaceLabel = canOpenSessionSurface
    ? "Open admitted adapter"
    : "Adapter admission required";
  const launchedHarnessSession =
    launchedSessions.find(
      (session) => session.admission_state === "daemon_admitted",
    ) ??
    launchedSessions[0] ??
    null;
  const activeSessionRef =
    launchedHarnessSession?.session_ref ?? projection.selected_session_ref;
  // Phase 3: subscribe the cockpit to live session events (terminal, diffs,
  // ports, status). Baseline load via loadHypervisorSessionOperationsProjection,
  // then SSE deltas; degrades silently offline.
  useHypervisorSessionOperationsProjectionSubscription({
    enabled: shouldAttemptHypervisorDaemonProjectionFetch(
      HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY,
    ),
    sessionRef: activeSessionRef,
    onProjection: setProjection,
    load: loadHypervisorSessionOperationsProjection,
  });
  const activeBranchLabel =
    launchedHarnessSession?.branch_label ?? projection.branch_label;
  const activeProjectLabel =
    launchedHarnessSession?.project_label ||
    projection.project_ref.replace(/^project:/, "");
  const activeSessionContextLabel = launchedHarnessSession
    ? `${activeProjectLabel} / ${activeBranchLabel}`
    : activeBranchLabel;
  const launchedHarnessSpawn =
    launchedHarnessSession?.harness_session_spawn &&
    "command_contract" in launchedHarnessSession.harness_session_spawn
      ? launchedHarnessSession.harness_session_spawn
      : null;
  const launchedHarnessReadiness =
    launchedHarnessSession?.harness_session_readiness ?? null;
  const launchedHarnessTerminalAttach =
    launchedHarnessSession?.harness_session_terminal_attach &&
    "client_attach_contract" in
      launchedHarnessSession.harness_session_terminal_attach
      ? launchedHarnessSession.harness_session_terminal_attach
      : null;
  const launchedHarnessCommand =
    launchedHarnessTerminalAttach?.client_attach_contract.command_line ??
    launchedHarnessSpawn?.command_contract.resolved_command_line ??
    "";
  const launchedHarnessPtyTransport =
    launchedHarnessTerminalAttach?.client_attach_contract.pty_transport ??
    launchedHarnessSpawn?.command_contract.pty_transport ??
    "";
  const launchedHarnessAttachState =
    launchedHarnessTerminalAttach?.attach_state ?? "";
  const launchedHarnessTranscriptState =
    launchedHarnessTerminalAttach?.terminal_transcript_projection
      .transcript_state ?? "";
  const launchedHarnessTranscriptCursor =
    launchedHarnessTerminalAttach?.terminal_transcript_projection.cursor ?? 0;
  const launchedHarnessTranscriptLineCount =
    launchedHarnessTerminalAttach?.terminal_transcript_projection.lines.length ??
    0;
  const launchedHarnessTranscriptRef =
    launchedHarnessTerminalAttach?.client_attach_contract
      .transcript_stream_ref ?? "";
  const launchedHarnessReadinessState =
    launchedHarnessReadiness?.readiness_state ?? "";
  const launchedHarnessNextAction =
    launchedHarnessTerminalAttach
      ? "Client PTY attach is admitted; stream transcript through the Hypervisor terminal adapter."
      : launchedHarnessReadiness && "operator_next_action" in launchedHarnessReadiness
      ? launchedHarnessReadiness.operator_next_action
      : "Attach terminal when ready.";

  // Reference-parity inline initialization: when a session is launched the init
  // panel reflects the daemon-projected HypervisorEnvironmentStatus component
  // sub-phases (provisioner -> workspace_content -> sandbox -> secrets ->
  // automations -> model_mount -> harness) instead of a timed animation. The
  // session is "initializing" until the aggregate environment phase is running.
  const environmentStatus = projection.environment_status;
  const environmentComponents = HYPERVISOR_ENVIRONMENT_COMPONENT_ORDER.map(
    (key) => {
      const component = environmentStatus.components[key];
      return {
        key,
        label: HYPERVISOR_ENVIRONMENT_COMPONENT_LABELS[key] ?? key,
        phase: component?.phase ?? "pending",
        evidence_ref: component?.evidence_ref ?? "",
      };
    },
  );
  const environmentReady = environmentStatus.phase === "running";
  const environmentFailed = environmentStatus.phase === "failed";
  const readyEnvironmentComponentCount = environmentComponents.filter(
    (component) => component.phase === "ready",
  ).length;
  const activeEnvironmentComponent =
    environmentComponents.find(
      (component) =>
        component.phase !== "ready" &&
        component.phase !== "degraded" &&
        component.phase !== "failed",
    ) ?? environmentComponents[environmentComponents.length - 1];
  const sessionInitializing =
    Boolean(launchedHarnessSession) && !environmentReady;

  // Mirror the conversation in a ref so streamed turns read prior context
  // without stale closures.
  const conversationStateRef = useRef(conversation);
  useEffect(() => {
    conversationStateRef.current = conversation;
  }, [conversation]);

  // Seed the conversation from the launched session's task, once per session.
  useEffect(() => {
    if (!launchedHarnessSession) {
      return;
    }
    if (conversationSessionRef.current === launchedHarnessSession.session_ref) {
      return;
    }
    conversationSessionRef.current = launchedHarnessSession.session_ref;
    autoTurnStartedRef.current = null;
    const seed = launchedHarnessSession.launch_summary?.seed_intent ?? "";
    setConversation(
      seed
        ? [
            {
              id: `user:seed:${launchedHarnessSession.session_ref}`,
              role: "user",
              text: seed,
            },
          ]
        : [],
    );
  }, [launchedHarnessSession]);

  async function streamTurn(
    text: string,
    options?: { skipUserMessage?: boolean },
  ) {
    if (turnInFlightRef.current) {
      return;
    }
    const daemonEndpoint =
      typeof window !== "undefined"
        ? window.localStorage.getItem("ioi.hypervisor.daemonEndpoint")
        : null;
    // Without a configured daemon/replay endpoint there is no model route to
    // stream from; skip the turn instead of emitting failed requests.
    if (!daemonEndpoint) {
      return;
    }
    turnInFlightRef.current = true;
    setTurnStreaming(true);
    const assistantId = `assistant:${Date.now()}`;
    const priorMessages = conversationStateRef.current
      .filter((message) => message.text.trim().length > 0)
      .map((message) => ({ role: message.role, content: message.text }));
    const messages = options?.skipUserMessage
      ? priorMessages
      : [...priorMessages, { role: "user", content: text }];
    setConversation((current) => [
      ...current,
      ...(options?.skipUserMessage
        ? []
        : [{ id: `user:${Date.now()}`, role: "user" as const, text }]),
      { id: assistantId, role: "assistant" as const, text: "", streaming: true },
    ]);
    try {
      const response = await fetch(
        `${daemonEndpoint.replace(/\/+$/, "")}/v1/hypervisor/session-turns`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "text/event-stream",
          },
          body: JSON.stringify({
            session_ref: activeSessionRef,
            harness_selection_ref: agentSelectionRef,
            model_name: selectedModelName,
            messages: messages.length
              ? messages
              : [{ role: "user", content: text }],
          }),
        },
      );
      if (!response.ok || !response.body) {
        throw new Error(`session turn responded ${response.status}`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let streaming = true;
      while (streaming) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() ?? "";
        for (const block of blocks) {
          const lines = block.split("\n");
          const event =
            lines.find((line) => line.startsWith("event: "))?.slice(7) ??
            "message";
          const dataLine = lines
            .find((line) => line.startsWith("data: "))
            ?.slice(6);
          if (!dataLine) continue;
          let data: {
            text?: string;
            source?: string;
            receipt_ref?: string;
            message?: string;
            code?: string;
          };
          try {
            data = JSON.parse(dataLine);
          } catch {
            continue;
          }
          if (event === "token" && data.text) {
            const delta = data.text;
            setConversation((current) =>
              current.map((message) =>
                message.id === assistantId
                  ? { ...message, text: message.text + delta }
                  : message,
              ),
            );
          } else if (event === "error") {
            // The daemon reports no reachable model route (and replay mode is
            // off). Render the actionable message instead of an empty bubble.
            const noticeText =
              data.message ||
              "The model route did not respond. Start a local model (Ollama with a Qwen model on :11434) or set IOI_HYPERVISOR_MODEL_UPSTREAM to stream real completions.";
            setConversation((current) =>
              current.map((message) =>
                message.id === assistantId
                  ? {
                      ...message,
                      streaming: false,
                      source: data.code ?? "no_model_route",
                      text: noticeText,
                    }
                  : message,
              ),
            );
          } else if (event === "done") {
            setConversation((current) =>
              current.map((message) =>
                message.id === assistantId
                  ? {
                      ...message,
                      streaming: false,
                      source: data.source,
                      receipt_ref: data.receipt_ref,
                    }
                  : message,
              ),
            );
            streaming = false;
          }
        }
      }
      setConversation((current) =>
        current.map((message) =>
          message.id === assistantId && message.streaming
            ? { ...message, streaming: false }
            : message,
        ),
      );
    } catch {
      setConversation((current) =>
        current.map((message) =>
          message.id === assistantId
            ? {
                ...message,
                streaming: false,
                text:
                  message.text ||
                  "The model route did not respond. Start a local model (Ollama with a Qwen model on :11434) or set IOI_HYPERVISOR_MODEL_UPSTREAM to stream real completions.",
              }
            : message,
        ),
      );
    } finally {
      turnInFlightRef.current = false;
      setTurnStreaming(false);
    }
  }

  // Once the daemon reports the environment ready (workspace/model/harness
  // provisioned), the harness answers the task.
  useEffect(() => {
    if (!launchedHarnessSession || !environmentReady) {
      return;
    }
    const seed = launchedHarnessSession.launch_summary?.seed_intent ?? "";
    if (!seed) {
      return;
    }
    if (autoTurnStartedRef.current === launchedHarnessSession.session_ref) {
      return;
    }
    autoTurnStartedRef.current = launchedHarnessSession.session_ref;
    void streamTurn(seed, { skipUserMessage: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [launchedHarnessSession, environmentReady]);

  const hasConversation = conversation.length > 0;

  function submitComposerIntent() {
    const text = composerText.trim();
    if (!text) {
      return;
    }
    setComposerText("");
    // First task on an empty Sessions surface launches a governed session inline;
    // the harness then answers automatically once the environment is ready.
    if (!launchedHarnessSession) {
      const modelOption =
        modelOptions.find((option) => option.model_ref === modelSelectionRef) ??
        modelOptions[0];
      const request = buildHypervisorNewSessionLaunchRequest({
        seedIntent: text,
        project: {
          id: currentProject.id,
          name: currentProject.name,
          rootPath: currentProject.rootPath,
        },
        harnessSelectionRef: agentSelectionRef,
        modelRouteRef: modelOption?.model_route_ref,
        modelName: modelOption?.model_name,
      });
      void onLaunchSession(request);
      return;
    }
    // Follow-up tasks stream a governed model turn into the conversation.
    const intentRef = `session-intent:${activeSessionRef.replace(
      /[^a-z0-9_-]+/gi,
      "-",
    )}/${Date.now()}`;
    setSubmittedIntents((current) => [
      {
        intent_ref: intentRef,
        text,
        receipt_ref: `receipt://hypervisor/session-intent/${intentRef.replace(
          /[^a-z0-9_-]+/gi,
          "-",
        )}`,
        session_ref: activeSessionRef,
      },
      ...current,
    ]);
    handleSessionOperation("propose_terminal_command", intentRef);
    void streamTurn(text);
  }

  return (
    <section
      className="hypervisor-session-operations--ioi-reference-session hypervisor-session-detail-shell"
      aria-label="Session operations cockpit"
      data-ioi-reference-session-cockpit="true"
      data-hypervisor-session-operations={projection.projection_id}
      data-session-operations-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div
        className="hypervisor-session-operations__reference-page"
        aria-label="Selected session detail"
        data-session-reference-page="workspace-detail"
      >
        <header className="hypervisor-session-operations__session-topbar">
          <button
            type="button"
	            className="hypervisor-session-operations__branch-picker"
	            data-session-branch={activeBranchLabel}
	            data-session-project-label={activeProjectLabel}
	            data-session-context-label={activeSessionContextLabel}
	          >
	            <span className="hypervisor-session-operations__status-dot" />
	            <strong>{activeSessionContextLabel}</strong>
            <span className="hypervisor-session-operations__inline-icon" aria-hidden="true">
              <ChevronDownIcon />
            </span>
          </button>
          <div className="hypervisor-session-operations__top-actions">
            <button
              type="button"
              aria-label={`${sessionOpenSurfaceLabel}: ${projection.selected_adapter_ref.replace(/^code-editor-adapter:/, "")}`}
              data-session-adapter-ref={projection.selected_adapter_ref}
              data-session-operation-kind="request_access_lease"
              data-session-operation-session={projection.selected_session_ref}
              data-session-open-surface-admission-state={
                projection.selected_adapter_admission_state
              }
              data-session-open-surface-enabled={
                canOpenSessionSurface ? "true" : "false"
              }
              disabled={!canOpenSessionSurface}
              onClick={() => handleSessionOperation("request_access_lease")}
            >
              <span className="hypervisor-session-operations__editor-logo" aria-hidden="true">
                <CompactEditorIcon />
              </span>
              <span className="hypervisor-session-operations__inline-icon" aria-hidden="true">
                <ChevronDownIcon />
              </span>
            </button>
            <button
              type="button"
              aria-label={`Open receipts for ${projection.selected_session_ref}`}
              data-session-open-receipts={projection.latest_receipt_refs[0] ?? ""}
              data-session-open-receipts-session={projection.selected_session_ref}
              onClick={() =>
                onOpenReceiptEvidence({
                  source: "session",
                  sessionRef: projection.selected_session_ref,
                  receiptRef: projection.latest_receipt_refs[0] ?? null,
                })
              }
            >
              Receipts
            </button>
          </div>
        </header>

        <div
          className="hypervisor-session-operations__session-tabs"
          aria-label="Session workspace and detail tabs"
          data-session-reference-detail="code-workspace"
        >
          <div
            className="hypervisor-session-operations__workspace-modes"
            role="tablist"
            aria-label="Session workspace modes"
            data-session-workspace-mode-list={HYPERVISOR_SESSION_WORKSPACE_MODES.map(
              (mode) => mode.mode_id,
            ).join(" ")}
          >
            {HYPERVISOR_SESSION_WORKSPACE_MODES.filter(
              (mode) => mode.mode_id === "code",
            ).map((mode) => (
              <button
                key={mode.mode_id}
                type="button"
                role="tab"
                aria-selected="false"
                data-session-workspace-mode={mode.mode_id}
              >
                <span className="hypervisor-session-operations__tab-icon" aria-hidden="true">
                  <SessionCodeIcon />
                </span>
                <strong>{mode.label}</strong>
              </button>
            ))}
          </div>
          <button
            type="button"
            className="hypervisor-session-operations__session-title"
            data-session-detail-tab="agent"
	            data-session-ref={activeSessionRef}
            aria-selected="true"
          >
            <span className="hypervisor-session-operations__tab-icon" aria-hidden="true">
              <SessionOctagonIcon />
            </span>
            <strong>Agent</strong>
          </button>
          <button
            type="button"
            className="hypervisor-session-operations__session-title"
            data-session-detail-tab="environment"
            data-session-ref={projection.environment_ref}
            aria-selected="false"
          >
            <span className="hypervisor-session-operations__tab-icon" aria-hidden="true">
              <SessionOctagonIcon />
            </span>
            <strong>Environment</strong>
          </button>
          <span
            hidden
            data-session-detail-tab-list={projection.detail_tabs
              .map((tab) => tab.tab_id)
              .join(" ")}
            data-session-selected-ref={projection.selected_session_ref}
            data-session-lifecycle-state={projection.lifecycle_state}
          />
          <button
            type="button"
            className="hypervisor-session-operations__add-panel"
            aria-label="Open split view"
          >
            <AddPanelIcon />
          </button>
        </div>

        <div className="hypervisor-session-operations__body">
          <main
            className="hypervisor-session-operations__workspace"
            aria-label="Session workspace cockpit"
	            data-session-workspace-cockpit={activeSessionRef}
            data-session-environment-lifecycle-state={projection.lifecycle_state}
          >
            <div
              className="hypervisor-session-operations__workspace-center"
              data-session-has-conversation={hasConversation ? "true" : "false"}
            >
              {!hasConversation ? (
                <>
                  <div
                    className="hypervisor-session-operations__workspace-mark"
                    aria-hidden="true"
                  >
                    <span />
                    <span className="hypervisor-session-operations__workspace-mark-symbol" />
                    <span />
                  </div>
                  <h2>What do you want to get done today?</h2>
                  <p>Here are some suggestions to get you started</p>
                  <div className="hypervisor-session-operations__workspace-suggestions">
                    {[
                      { label: "Automate env setup", tone: "blue" },
                      { label: "Fix a bug", tone: "red" },
                      { label: "Boost your test coverage", tone: "purple" },
                    ].map((suggestion) => (
                      <button
                        type="button"
                        key={suggestion.label}
                        data-session-suggestion={suggestion.label
                          .toLowerCase()
                          .replace(/[^a-z0-9]+/g, "-")
                          .replace(/^-+|-+$/g, "")}
                        data-session-suggestion-tone={suggestion.tone}
                        onClick={() => onLaunchSession(
                          buildHypervisorNewSessionLaunchRequest({
                            seedIntent: suggestion.label,
                            project: {
                              id: currentProject.id,
                              name: currentProject.name,
                              rootPath: currentProject.rootPath,
                            },
                            harnessSelectionRef: agentSelectionRef,
                            modelRouteRef: selectedModel?.model_route_ref,
                            modelName: selectedModel?.model_name,
                          }),
                        )}
                      >
                        <span aria-hidden="true" />
                        {suggestion.label}
                      </button>
                    ))}
                  </div>
                </>
              ) : null}
              {hasConversation ? (
                <div
                  className="hypervisor-session-operations__conversation"
                  aria-label="Session conversation"
                  data-session-conversation-count={conversation.length}
                >
                  {conversation.map((message) => (
                    <article
                      key={message.id}
                      className={`hypervisor-session-operations__message hypervisor-session-operations__message--${message.role}`}
                      data-session-message-role={message.role}
                      data-session-message-streaming={
                        message.streaming ? "true" : "false"
                      }
                      data-session-message-source={message.source ?? ""}
                    >
                      <span className="hypervisor-session-operations__message-role">
                        {message.role === "user" ? "You" : selectedHarnessLabel}
                      </span>
                      <div className="hypervisor-session-operations__message-text">
                        {message.text}
                        {message.streaming ? (
                          <span
                            className="hypervisor-session-operations__cursor"
                            aria-hidden="true"
                          />
                        ) : null}
                      </div>
                      {message.receipt_ref ? (
                        <small>{message.receipt_ref}</small>
                      ) : null}
                    </article>
                  ))}
                </div>
              ) : null}
              {sessionInitializing ? (
                <section
                  className="hypervisor-session-operations__init"
                  aria-label="Session initialization"
                  data-session-init-sequence={
                    launchedHarnessSession?.session_ref ?? ""
                  }
                  data-session-init-step={activeEnvironmentComponent?.key ?? ""}
                  data-session-init-step-index={readyEnvironmentComponentCount}
                  data-session-environment-phase={environmentStatus.phase}
                >
                  <header className="hypervisor-session-operations__init-head">
                    <span
                      className="hypervisor-session-operations__init-spinner"
                      aria-hidden="true"
                    />
                    <div>
                      <strong>
                        Step {readyEnvironmentComponentCount + 1} of{" "}
                        {environmentComponents.length}
                      </strong>
                      <p>
                        {activeEnvironmentComponent?.label ??
                          "Preparing environment"}
                        …
                      </p>
                      <small>
                        {environmentFailed
                          ? (environmentStatus.failure_message ??
                            "Environment provisioning failed")
                          : `Custody: ${
                              environmentStatus.components.workspace_content
                                .custody_posture ?? "public_trunk"
                            }`}
                      </small>
                    </div>
                  </header>
                  <ol className="hypervisor-session-operations__init-steps">
                    {environmentComponents.map((component) => (
                      <li
                        key={component.key}
                        data-session-init-step-ref={component.key}
                        data-session-init-step-phase={component.phase}
                        data-session-init-step-state={
                          component.phase === "ready"
                            ? "completed"
                            : component.phase === "failed" ||
                                component.phase === "degraded"
                              ? "blocked"
                              : component.phase === "pending"
                                ? "waiting"
                                : "running"
                        }
                      >
                        <span aria-hidden="true" />
                        {component.label}
                      </li>
                    ))}
                  </ol>
                  <div
                    className="hypervisor-session-operations__init-logs"
                    role="log"
                    aria-label="Environment status evidence"
                  >
                    <span className="hypervisor-session-operations__init-logs-title">
                      === Environment status ===
                    </span>
                    {environmentComponents.map((component) => (
                      <code key={`evidence-${component.key}`}>
                        {component.key}: {component.phase} —{" "}
                        {component.evidence_ref}
                      </code>
                    ))}
                  </div>
                </section>
              ) : null}
              {launchedHarnessSession && !sessionInitializing ? (
                <section
                  className="hypervisor-session-operations__harness-drill-in"
                  aria-label="Launched harness session"
                  data-session-harness-drill-in={
                    launchedHarnessSession.session_ref
                  }
                  data-session-harness-drill-in-admission={
                    launchedHarnessSession.admission_state
                  }
                  data-session-harness-drill-in-recipe-admission={
                    launchedHarnessSession.session_launch_recipe_admission_ref ??
                    ""
                  }
                  data-session-harness-drill-in-spawn={
                    launchedHarnessSession.harness_session_spawn_ref ?? ""
                  }
                  data-session-harness-drill-in-spawn-state={
                    launchedHarnessSpawn?.spawn_state ?? ""
                  }
                  data-session-harness-drill-in-model-name={
                    launchedHarnessSpawn?.model_name ?? ""
                  }
                  data-session-harness-drill-in-readiness={
                    launchedHarnessReadiness?.decision ?? ""
                  }
                  data-session-harness-drill-in-readiness-state={
                    launchedHarnessReadinessState
                  }
                  data-session-harness-drill-in-pty-transport={
                    launchedHarnessPtyTransport
                  }
                  data-session-harness-drill-in-terminal-attach={
                    launchedHarnessTerminalAttach?.attach_id ?? ""
                  }
                  data-session-harness-drill-in-terminal-attach-state={
                    launchedHarnessAttachState
                  }
                  data-session-harness-drill-in-terminal-transcript={
                    launchedHarnessTranscriptRef
                  }
                  data-session-harness-drill-in-terminal-transcript-state={
                    launchedHarnessTranscriptState
                  }
                  data-session-harness-drill-in-terminal-transcript-cursor={
                    launchedHarnessTranscriptCursor
                  }
                  data-session-harness-drill-in-terminal-transcript-lines={
                    launchedHarnessTranscriptLineCount
                  }
                  data-session-harness-drill-in-command={
                    launchedHarnessCommand
                  }
                >
                  <header>
                    <span>Harness ready</span>
                    <strong>
                      {
                        launchedHarnessSession.harness_session_binding
                          .harness_label
                      }
                    </strong>
                  </header>
                  <dl>
                    <div>
                      <dt>Model</dt>
                      <dd>{launchedHarnessSpawn?.model_name ?? "pending"}</dd>
                    </div>
                    <div>
                      <dt>Transport</dt>
                      <dd>{launchedHarnessPtyTransport || "pending"}</dd>
                    </div>
                    <div>
                      <dt>Attach</dt>
                      <dd>{launchedHarnessAttachState || "pending"}</dd>
                    </div>
                    <div>
                      <dt>Readiness</dt>
                      <dd>{launchedHarnessReadinessState || "pending"}</dd>
                    </div>
                  </dl>
                  {launchedHarnessCommand ? (
                    <code>{launchedHarnessCommand}</code>
                  ) : null}
                  {launchedHarnessTranscriptRef ? (
                    <small>
                      {launchedHarnessTranscriptRef} | cursor{" "}
                      {launchedHarnessTranscriptCursor} |{" "}
                      {launchedHarnessTranscriptLineCount} lines
                    </small>
                  ) : null}
	                  <p>{launchedHarnessNextAction}</p>
	                  {submittedIntents.length > 0 ? (
	                    <div
	                      className="hypervisor-session-operations__submitted-intents"
	                      data-session-composer-submission-count={
	                        submittedIntents.length
	                      }
	                    >
	                      {submittedIntents.map((intent) => (
	                        <article
	                          key={intent.intent_ref}
	                          data-session-composer-submission={intent.intent_ref}
	                          data-session-composer-submission-receipt={
	                            intent.receipt_ref
	                          }
	                        >
	                          <strong>
	                            Queued for{" "}
	                            {launchedHarnessSession?.harness_session_binding
	                              .harness_label ?? "selected agent"}
	                          </strong>
	                          <p>{intent.text}</p>
	                          <small>{intent.receipt_ref}</small>
	                        </article>
	                      ))}
	                    </div>
	                  ) : null}
	                </section>
	              ) : null}
            </div>
	            <form
	              className="hypervisor-session-operations__composer"
	              aria-label="Describe session task"
	              data-session-composer-session={activeSessionRef}
	              onSubmit={(event) => {
	                event.preventDefault();
	                submitComposerIntent();
	              }}
	            >
	              <textarea
	                rows={3}
	                value={composerText}
	                onChange={(event) => setComposerText(event.currentTarget.value)}
	                onKeyDown={(event) => {
	                  if (event.key === "Enter" && !event.shiftKey) {
	                    event.preventDefault();
	                    submitComposerIntent();
	                  }
	                }}
	                placeholder="Describe your task or type / for commands"
	              />
              <div className="hypervisor-session-operations__composer-controls">
                <button
                  type="button"
                  className="hypervisor-session-operations__composer-attach"
                  aria-label="Attach context"
                >
                  +
                </button>
                <button
                  type="button"
                  className="hypervisor-session-operations__composer-configure"
                  data-session-new-session-configure="true"
                  aria-label="Configure launch (advanced)"
                  title="Configure harness, model route, privacy posture, and authority"
                  onClick={() => onConfigureLaunch(composerText.trim() || null)}
                >
                  Configure
                </button>
                <span
                  hidden
                  data-session-environment-steps={projection.environment_lifecycle_steps
                    .map((step) => step.step_ref)
                    .join(" ")}
                />
                <AgentModelSelector
                  options={agentOptions}
                  selectedRef={agentSelectionRef}
                  onSelect={onSelectAgent}
                  surface="session"
                  align="right"
                />
                <ModelRouteSelector
                  options={modelOptions}
                  selectedRef={modelSelectionRef}
                  onSelect={onSelectModel}
                  surface="session"
                  align="right"
                />
	                <button
	                  type="submit"
	                  aria-label="Send task"
	                  disabled={!composerText.trim() || turnStreaming}
	                >
                  ↑
                </button>
              </div>
            </form>
          </main>
        </div>

        <aside
          className="hypervisor-session-operations__right-pane"
          aria-label="Changes, files, comments, and session inspectors"
          data-session-change-inspector="changes-files-comments"
          data-session-change-mode-list={HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map(
            (mode) => mode.mode_id,
          ).join(" ")}
        >
          <header className="hypervisor-session-operations__right-header">
            <div
              className="hypervisor-session-operations__change-inspector"
              role="tablist"
              aria-label="Change inspector modes"
            >
              {HYPERVISOR_SESSION_CHANGE_INSPECTOR_MODES.map((mode, index) => (
                <button
                  key={mode.mode_id}
                  type="button"
                  role="tab"
                  aria-selected={index === 0}
                  data-session-change-mode={mode.mode_id}
                  title={mode.summary}
                >
                  {mode.label}
                </button>
              ))}
            </div>
            <div className="hypervisor-session-operations__right-actions">
              {[
                { label: "Preview", icon: <EyeIcon />, variant: "icon" },
                { label: "Create PR", icon: <BranchIcon />, variant: "primary" },
                { label: "Split", icon: <SplitPanelIcon />, variant: "icon" },
              ].map((action, index) => (
                <button
                  key={action.label}
                  type="button"
                  aria-pressed={index === 1}
                  aria-label={`${action.label} changes inspector`}
                  data-session-review-action={action.label
                    .toLowerCase()
                    .replace(/[^a-z0-9]+/g, "-")
                    .replace(/^-+|-+$/g, "")}
                  data-session-review-action-variant={action.variant}
                >
                  {action.icon}
                  {action.variant === "primary" ? <strong>{action.label}</strong> : null}
                </button>
              ))}
            </div>
          </header>

            <div className="hypervisor-session-operations__change-filter-row">
              <label className="hypervisor-session-operations__search">
                <span>Search files...</span>
                <span
                  className="hypervisor-session-operations__search-icon"
                  aria-hidden="true"
                >
                  <SearchIcon />
                </span>
                <input
                  type="search"
                  aria-label="Search changed files"
                placeholder="Search files..."
              />
            </label>
            <button type="button" className="hypervisor-session-operations__status-filter">
              Uncommitted
              <span className="hypervisor-session-operations__inline-icon" aria-hidden="true">
                <ChevronDownIcon />
              </span>
            </button>
          </div>

          <div className="hypervisor-session-operations__change-list">
            {projection.changed_file_groups.map((group) => (
              <div
                key={group.group_ref}
                className="hypervisor-session-operations__file-group"
                data-session-changed-file-group={group.group_ref}
              >
                <span className="hypervisor-session-operations__folder">
                  <span className="hypervisor-session-operations__inline-icon" aria-hidden="true">
                    <ChevronDownIcon />
                  </span>
                  <span className="hypervisor-session-operations__file-icon" aria-hidden="true">
                    <FolderIcon />
                  </span>
                  {group.folder}
                  <em>{group.files.length}</em>
                </span>
                {group.files.map((file) => (
                  <button
                    type="button"
                    key={file.file_ref}
                    data-session-changed-file={`${group.folder}${file.name}`}
                    data-session-changed-file-receipt={file.receipt_ref}
                    data-session-changed-file-status={file.status}
                  >
                    <span className="hypervisor-session-operations__file-name">
                      <span className="hypervisor-session-operations__file-icon" aria-hidden="true">
                        <FileIcon />
                      </span>
                      <code>{file.name}</code>
                    </span>
                    <span className="hypervisor-session-operations__delta">{file.delta}</span>
                    <span className="hypervisor-session-operations__file-status">
                      {formatChangedFileStatus(file.status)}
                    </span>
                  </button>
                ))}
              </div>
            ))}
          </div>

          <div className="hypervisor-session-operations__bottom-dock">
            <div
              className="hypervisor-session-operations__bottom-tabs"
              role="tablist"
              aria-label="Bottom inspectors"
            >
              {projection.bottom_inspector_panels
                .filter((panel) => panel.panel_id !== "logs")
                .map((panel, index) => (
                  <button
                    key={panel.panel_id}
                    type="button"
                    role="tab"
                    aria-selected={index === 0}
                    data-bottom-inspector-panel={panel.panel_id}
                    title={panel.summary}
                  >
                    {panel.panel_id === "ports_services"
                      ? "Ports & Services"
                      : panel.label}
                  </button>
                ))}
            </div>
            <div className="hypervisor-session-operations__bottom-content">
              <div className="hypervisor-session-operations__panel">
                <div className="hypervisor-session-operations__panel-heading">
                  <h3>Ports</h3>
                  <button
                    type="button"
                    data-session-service-open-port={projection.ports_services[0]?.service_ref}
                    onClick={() =>
                      handleSessionOperation(
                        "open_port",
                        projection.ports_services[0]?.service_ref,
                      )
                    }
                  >
                    + Add port
                  </button>
                </div>
                <div
                  className={clsx("hypervisor-session-operations__empty-state", {
                    "has-session-services": projection.ports_services.length > 0,
                  })}
                  data-session-port-services-count={projection.ports_services.length}
                >
                  {projection.ports_services.length === 0 ? (
                    <>
                      <span aria-hidden="true">
                        <PortEmptyIcon />
                      </span>
                      <p>No open ports</p>
                    </>
                  ) : (
                    projection.ports_services.map((service) => (
                      <div
                        key={service.service_ref}
                        className="hypervisor-session-operations__row"
                        data-session-port-service={service.service_ref}
                        data-session-port-service-status={service.status}
                      >
                        <strong>{service.label}</strong>
                        <span>
                          {service.protocol.toUpperCase()}:{service.port}
                        </span>
                        <em>{service.lease_ref}</em>
                        <button
                          type="button"
                          data-session-service-open-port={service.service_ref}
                          onClick={() =>
                            handleSessionOperation("open_port", service.service_ref)
                          }
                        >
                          {service.status === "available" ? "Open" : "Lease"}
                        </button>
                      </div>
                    ))
                  )}
                </div>
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
            <p>
              Review the requested lease, scope, receipt, and restore refs
              before this operation is allowed to run.
            </p>
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
              <dt>State record</dt>
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
  onOpenReceiptEvidence,
  onProjectStateProjection,
  onLaunchProjectSession,
}: {
  selectedProjectId: string;
  onOpenReceiptEvidence: (target: HypervisorReceiptEvidenceTarget) => void;
  onProjectStateProjection: (projection: HypervisorProjectStateProjection) => void;
  onLaunchProjectSession: (
    record: HypervisorProjectStateRecord,
  ) => Promise<HypervisorLaunchedSessionProjection | null>;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION,
  );
  const [operationProposal, setOperationProposal] =
    useState<HypervisorProjectOperationProposal | null>(null);
  const [isCreateProjectOpen, setIsCreateProjectOpen] = useState(false);
  const [repositorySource, setRepositorySource] = useState<
    "manual_url" | "repository_picker"
  >("manual_url");
  const [repositoryUrl, setRepositoryUrl] = useState(
    "https://github.com/ioi-foundation/ioi",
  );
  const [projectName, setProjectName] = useState("");
  const [environmentClassRef, setEnvironmentClassRef] = useState("");
  const [projectCreateError, setProjectCreateError] = useState("");
  const [isCreatingProject, setIsCreatingProject] = useState(false);
  const [projectCreateNotice, setProjectCreateNotice] = useState("");

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_PROJECT_STATE_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
    let cancelled = false;
	    loadHypervisorProjectStateProjection({ projectId: selectedProjectId })
	      .then((nextProjection) => {
	        if (!cancelled) {
	          setProjection(nextProjection);
	          onProjectStateProjection(nextProjection);
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
	  }, [onProjectStateProjection, selectedProjectId]);

  const selectedProject =
    projection.records.find(
      (project) => project.project_id === projection.selected_project_id,
    ) ??
    projection.records.find((project) => project.project_id === selectedProjectId) ??
    projection.records[0] ??
    null;
  const visibleProjects = projection.records;
  const activeProjectCount = visibleProjects.filter(
    (project) => project.restore_state === "active",
  ).length;
  const restoreReadyCount = visibleProjects.filter(
    (project) => project.restore_state === "restore_ready",
  ).length;
  const suggestedProjectName = projectNameFromRepositoryUrl(repositoryUrl);
  const resolvedProjectName = projectName.trim() || suggestedProjectName;
  const repositoryUrlIsValid = isGitRepositoryUrl(repositoryUrl);

  async function onProjectOperation(
    project: HypervisorProjectStateRecord,
    operationKind: HypervisorProjectOperationKind,
  ) {
    try {
      const proposal = await proposeHypervisorProjectOperation({
        record: project,
        operationKind,
      });
      setOperationProposal(proposal);
    } catch (error) {
      console.warn("[Hypervisor][Projects] operation proposal unavailable", error);
      setOperationProposal(
        buildHypervisorProjectOperationProposal(project, operationKind, {
          source: "unverified",
        }),
      );
    }
  }

  async function onCreateProject() {
    setProjectCreateError("");
    setProjectCreateNotice("");
    if (!repositoryUrlIsValid) {
      setProjectCreateError("The URL must point to a Git repository.");
      return;
    }
    if (!resolvedProjectName) {
      setProjectCreateError("Project name is required.");
      return;
    }

    setIsCreatingProject(true);
    try {
      const nextProjection = await requestHypervisorProjectCreate({
        request: {
          repository_url: repositoryUrl.trim(),
          project_name: resolvedProjectName,
          source: repositorySource,
          environment_class_refs: environmentClassRef
            ? [environmentClassRef]
            : [],
        },
	      });
	      setProjection(nextProjection);
	      onProjectStateProjection(nextProjection);
	      setOperationProposal(null);
	      setIsCreateProjectOpen(false);
      setProjectName("");
      setProjectCreateNotice(`Project "${resolvedProjectName}" created.`);
    } catch (error) {
      setProjectCreateError(
        error instanceof Error
          ? error.message
          : "Project could not be created through the daemon route.",
      );
    } finally {
      setIsCreatingProject(false);
    }
	  }

	  async function onOpenProjectSession(project: HypervisorProjectStateRecord) {
	    try {
	      const launchedSession = await onLaunchProjectSession(project);
      if (!launchedSession) {
        // Launch stepped up into Configure/Advanced; no inline session created.
        return;
      }
	      setProjection((current) => {
	        const nextProjection: HypervisorProjectStateProjection = {
	          ...current,
	          selected_project_id: project.project_id,
	          records: current.records.map((record) =>
	            record.project_id === project.project_id
	              ? {
	                  ...record,
	                  restore_state: "active",
	                  environment: record.environment || "Local dev replay",
	                  current_session_ref: launchedSession.session_ref,
	                  latest_receipt_refs: [
	                    launchedSession.launch_receipt_ref,
	                    ...record.latest_receipt_refs.filter(
	                      (receiptRef) =>
	                        receiptRef !== launchedSession.launch_receipt_ref,
	                    ),
	                  ],
	                }
	              : record,
	          ),
	        };
	        onProjectStateProjection(nextProjection);
	        return nextProjection;
	      });
	    } catch (error) {
	      setProjectCreateNotice("");
	      setProjectCreateError(
	        error instanceof Error
	          ? error.message
	          : "Project session could not be launched.",
	      );
	    }
	  }

	  return (
    <section
      className="hypervisor-project-state"
      aria-label="Project state surface"
      data-hypervisor-project-state={projection.projection_id}
      data-project-state-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
      data-project-state-record-count={projection.records.length}
    >
      <div className="hypervisor-project-state__content">
        <header className="hypervisor-project-state__header">
          <div>
            <h2>Projects</h2>
            {visibleProjects.length > 0 ? (
              <p>
                Repository workspaces, environment classes, sessions, archives,
                and receipts admitted by the Hypervisor Daemon.
              </p>
            ) : null}
          </div>
          {visibleProjects.length > 0 ? (
            <button
              type="button"
              className="hypervisor-project-state__new"
              onClick={() => {
                setIsCreateProjectOpen(true);
                setProjectCreateError("");
                setProjectCreateNotice("");
              }}
            >
              New project
            </button>
          ) : null}
        </header>

        <div
          className={clsx("hypervisor-project-state__toolbar", {
            "hypervisor-project-state__toolbar--empty":
              visibleProjects.length === 0,
          })}
        >
          <label className="hypervisor-project-state__search">
            <span aria-hidden="true">
              <SearchIcon />
            </span>
            <input type="search" placeholder="Search projects" readOnly />
          </label>
          {visibleProjects.length > 0 ? (
            <div
              className="hypervisor-project-state__filters"
              aria-label="Project filters"
            >
              <button type="button">All ({visibleProjects.length})</button>
              <button type="button">Active ({activeProjectCount})</button>
              <button type="button">Restore ready ({restoreReadyCount})</button>
            </div>
          ) : null}
        </div>

        {visibleProjects.length > 0 ? (
          <div className="hypervisor-project-state__layout">
            <section
              className="hypervisor-project-state__table"
              aria-label="Project state records"
              data-project-state-records
            >
              <div
                className="hypervisor-project-state__table-head"
                aria-hidden="true"
              >
                <span>Project</span>
                <span>Environment</span>
                <span>Restore</span>
                <span>Custody</span>
              </div>
              {visibleProjects.map((project) => {
                const isSelected =
                  selectedProject?.project_id === project.project_id;
                return (
	                  <button
	                    type="button"
	                    key={project.project_id}
	                    className={clsx("hypervisor-project-state__record", {
	                      "is-selected": isSelected,
	                    })}
	                    aria-label={`Open ${project.name} session`}
	                    data-project-state-record={project.project_id}
	                    data-project-restore-state={project.restore_state}
	                    data-project-custody-posture={project.custody_posture}
                    data-project-workspace-ref={project.workspace_ref}
                    data-project-object-head-ref={project.agentgres_object_head_ref}
	                    data-project-state-root-ref={project.state_root_ref}
	                    data-project-archive-ref={project.archive_ref}
	                    data-project-restore-ref={project.restore_ref}
	                    data-project-session-launch="local-qwen"
	                    onClick={() => {
	                      void onOpenProjectSession(project);
	                    }}
	                  >
	                    <div>
	                      <strong>{project.name}</strong>
                      <span>{project.repository_url ?? project.description}</span>
                    </div>
	                    <span>{project.environment}</span>
	                    <span>{project.restore_state.split("_").join(" ")}</span>
	                    <span>{project.custody_posture.split("_").join(" ")}</span>
	                  </button>
                );
              })}
            </section>

            <aside
              className="hypervisor-project-state__inspector"
              aria-label="Selected project restore context"
            >
              <h3>{selectedProject?.name ?? "Selected project"}</h3>
              <p>
                Agentgres owns project truth. Storage backends only hold the
                encrypted archive and payload bytes referenced here.
              </p>
              <dl>
                <div>
                  <dt>Repository</dt>
                  <dd>{selectedProject?.repository_url ?? "unlinked"}</dd>
                </div>
                <div>
                  <dt>Branch</dt>
                  <dd>{selectedProject?.repository_branch ?? "unconfigured"}</dd>
                </div>
                <div>
                  <dt>Workspace</dt>
                  <dd>{selectedProject?.workspace_ref ?? "unavailable"}</dd>
                </div>
                <div>
                  <dt>Session</dt>
                  <dd>{selectedProject?.current_session_ref ?? "idle"}</dd>
                </div>
                <div>
                  <dt>Adapter</dt>
                  <dd>{selectedProject?.adapter_preference_ref ?? "unbound"}</dd>
                </div>
                <div>
                  <dt>State root</dt>
                  <dd>{selectedProject?.state_root_ref ?? "unavailable"}</dd>
                </div>
                <div>
                  <dt>Archive</dt>
                  <dd>{selectedProject?.archive_ref ?? "unavailable"}</dd>
                </div>
                <div>
                  <dt>Restore</dt>
                  <dd>{selectedProject?.restore_ref ?? "unavailable"}</dd>
                </div>
              </dl>
              {selectedProject ? (
                <div
                  className="hypervisor-project-state__actions"
                  aria-label="Project archive and restore proposals"
                >
                  <button
                    type="button"
                    data-project-operation-kind="archive"
                    data-project-operation-project={selectedProject.project_id}
                    onClick={() => {
                      void onProjectOperation(selectedProject, "archive");
                    }}
                  >
                    Archive
                  </button>
                  <button
                    type="button"
                    data-project-operation-kind="restore"
                    data-project-operation-project={selectedProject.project_id}
                    disabled={selectedProject.restore_state === "active"}
                    onClick={() => {
                      void onProjectOperation(selectedProject, "restore");
                    }}
                  >
                    Restore
                  </button>
                  <button
                    type="button"
                    data-project-open-receipts={
                      selectedProject.latest_receipt_refs[0] ?? ""
                    }
                    data-project-open-receipts-project={
                      selectedProject.project_id
                    }
                    data-project-open-receipts-session={
                      selectedProject.current_session_ref
                    }
                    onClick={() =>
                      onOpenReceiptEvidence({
                        source: "project",
                        projectId: selectedProject.project_id,
                        sessionRef: selectedProject.current_session_ref,
                        receiptRef:
                          selectedProject.latest_receipt_refs[0] ?? null,
                      })
                    }
                  >
                    View receipts
                  </button>
                </div>
              ) : null}
              {operationProposal ? (
                <div
                  className="hypervisor-project-state__proposal"
                  data-project-operation-proposal={operationProposal.proposal_ref}
                  data-project-operation-proposal-source={
                    operationProposal.source
                  }
                  data-project-operation-admission-state={
                    operationProposal.admission_state
                  }
                >
                  <strong>{operationProposal.operation_kind} proposal</strong>
                  <span>{operationProposal.receipt_ref}</span>
                </div>
              ) : null}
            </aside>
          </div>
        ) : (
          <section
            className="hypervisor-project-state__empty"
            aria-label="Project empty state"
          >
            <span
              className="hypervisor-project-state__empty-icon"
              aria-hidden="true"
            >
              <span />
              <span />
              <span />
              <span />
            </span>
            <h3>No projects</h3>
            <p>
              Projects bundle your repo, secrets, and other configuration into
              a shareable template, prebuilt in the background for faster startup
              times.
            </p>
            <a href="/projects" aria-label="Learn more about projects in IOI">
              Learn more about projects in IOI.
            </a>
            <button
              type="button"
              className="hypervisor-project-state__new"
              onClick={() => {
                setIsCreateProjectOpen(true);
                setProjectCreateError("");
                setProjectCreateNotice("");
              }}
            >
              New project
            </button>
          </section>
        )}
        {projectCreateNotice ? (
          <p className="hypervisor-project-state__notice" role="status">
            {projectCreateNotice}
          </p>
        ) : null}
      </div>
      {isCreateProjectOpen ? (
        <div
          className="hypervisor-project-create"
          role="dialog"
          aria-modal="true"
          aria-labelledby="hypervisor-project-create-title"
        >
          <div className="hypervisor-project-create__backdrop" />
          <form
            className="hypervisor-project-create__panel"
            onSubmit={(event) => {
              event.preventDefault();
              void onCreateProject();
            }}
          >
            <header>
              <div>
                <h3 id="hypervisor-project-create-title">New Project</h3>
                <p>
                  Link a Git repository so Hypervisor can launch sessions,
                  configure environments, and attach receipts to repo work.
                </p>
              </div>
              <button
                type="button"
                aria-label="Close new project"
                onClick={() => setIsCreateProjectOpen(false)}
              >
                x
              </button>
            </header>
            <fieldset className="hypervisor-project-create__source">
              <legend>Repository source</legend>
              <label>
                <input
                  type="radio"
                  name="hypervisor-project-source"
                  checked={repositorySource === "repository_picker"}
                  onChange={() => setRepositorySource("repository_picker")}
                />
                <span>Select a repository</span>
              </label>
              <label>
                <input
                  type="radio"
                  name="hypervisor-project-source"
                  checked={repositorySource === "manual_url"}
                  onChange={() => setRepositorySource("manual_url")}
                />
                <span>Enter URL manually</span>
              </label>
            </fieldset>
            {repositorySource === "repository_picker" ? (
              <div className="hypervisor-project-create__picker">
                <span>Connect to GitHub to browse repositories</span>
                <button type="button">Connect to GitHub</button>
                <small>
                  Dev replay keeps this as a proposal; wallet.network will own
                  real source-control authorization.
                </small>
              </div>
            ) : null}
            <label className="hypervisor-project-create__field">
              <span>Repository URL</span>
              <input
                value={repositoryUrl}
                onChange={(event) => {
                  setRepositoryUrl(event.target.value);
                  setProjectCreateError("");
                }}
                placeholder="https://github.com/org/repo"
              />
            </label>
            {!repositoryUrlIsValid && repositoryUrl.trim() ? (
              <p className="hypervisor-project-create__error">
                The URL must point to a Git repository.
              </p>
            ) : null}
            <label className="hypervisor-project-create__field">
              <span>Project name</span>
              <input
                value={projectName}
                onChange={(event) => setProjectName(event.target.value)}
                placeholder={suggestedProjectName || "My Project"}
              />
            </label>
            <label className="hypervisor-project-create__field">
              <span>Environment Classes</span>
              <select
                value={environmentClassRef}
                onChange={(event) => setEnvironmentClassRef(event.target.value)}
              >
                <option value="">Add environment class</option>
                {HYPERVISOR_PROJECT_ENVIRONMENT_CLASS_OPTIONS.map((option) => (
                  <option key={option.ref} value={option.ref}>
                    {option.label} - {option.details}
                  </option>
                ))}
              </select>
            </label>
            {projectCreateError ? (
              <p className="hypervisor-project-create__error" role="alert">
                {projectCreateError}
              </p>
            ) : null}
            <footer>
              <button
                type="button"
                onClick={() => setIsCreateProjectOpen(false)}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={
                  isCreatingProject || !repositoryUrlIsValid || !resolvedProjectName
                }
              >
                {isCreatingProject ? "Creating..." : "Create"}
              </button>
            </footer>
          </form>
        </div>
      ) : null}
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
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_PROVIDER_PLACEMENT_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
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
        <h2>Choose where sessions can run.</h2>
        <p>
          Compare local, cloud, DePIN, storage, and confidential-compute options
          before attaching a workspace to infrastructure.
        </p>
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
                <dd>{candidate.wallet_authority_scope_refs.length} controls</dd>
              </div>
              <div>
                <dt>Receipt</dt>
                <dd>{candidate.agentgres_receipt_ref ? "Available" : "Pending"}</dd>
              </div>
              <div>
                <dt>Storage</dt>
                <dd>{candidate.storage_policy_ref ? "Configured" : "Not set"}</dd>
              </div>
              <div>
                <dt>Restore</dt>
                <dd>{candidate.restore_policy_ref ? "Configured" : "Not set"}</dd>
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
            <p>
              Review the selected provider, lease, receipt, restore, and state
              refs before approving this infrastructure operation.
            </p>
          </div>
          <dl>
            <div>
              <dt>Wallet lease</dt>
              <dd>{operationProposal.wallet_lease_ref}</dd>
            </div>
            <div>
              <dt>State record</dt>
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
          Monitor active workspaces, services, ports, leases, tasks, logs, and
          restore posture across the infrastructure attached to this workspace.
        </p>
      </div>
      <EnvironmentEstateView runtime={runtime} />
    </section>
  );
}

function HypervisorReceiptEvidenceSurface({
  currentProjectId,
  target,
}: {
  currentProjectId: string;
  target: HypervisorReceiptEvidenceTarget | null;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  );
  const [kindFilter, setKindFilter] = useState<
    "all" | HypervisorReceiptEvidenceKind
  >("all");
  const [statusFilter, setStatusFilter] = useState<
    "all" | HypervisorReceiptEvidenceRecord["status"]
  >("all");
  const [selectedReceiptRef, setSelectedReceiptRef] = useState<string | null>(
    null,
  );
  const [receiptPageCursor, setReceiptPageCursor] = useState<string | null>(
    null,
  );

  useEffect(() => {
    setReceiptPageCursor(null);
  }, [target?.projectId, target?.receiptRef, target?.sessionRef, target?.source]);

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_RECEIPT_EVIDENCE_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
    let cancelled = false;
    loadHypervisorReceiptEvidenceProjection({
      projectId: target?.projectId ?? currentProjectId,
      sessionRef:
        target?.sessionRef ??
        HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref,
      pageCursor: receiptPageCursor,
      pageSize: 25,
    })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
          setSelectedReceiptRef(target?.receiptRef ?? null);
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
  }, [
    currentProjectId,
    receiptPageCursor,
    target?.projectId,
    target?.receiptRef,
    target?.sessionRef,
    target?.source,
  ]);

  const kindOptions = useMemo(
    () => Array.from(new Set(projection.records.map((record) => record.kind))),
    [projection.records],
  );
  const statusOptions = useMemo(
    () =>
      Array.from(new Set(projection.records.map((record) => record.status))),
    [projection.records],
  );
  const filteredRecords = useMemo(
    () =>
      projection.records.filter(
        (record) =>
          (kindFilter === "all" || record.kind === kindFilter) &&
          (statusFilter === "all" || record.status === statusFilter),
      ),
    [kindFilter, projection.records, statusFilter],
  );
  const selectedRecord =
    filteredRecords.find((record) => record.receipt_ref === selectedReceiptRef) ??
    filteredRecords[0] ??
    null;

  return (
    <section
      className="hypervisor-receipt-evidence"
      aria-label="Receipt evidence surface"
      data-hypervisor-receipt-evidence={projection.projection_id}
      data-receipt-evidence-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
      data-receipt-evidence-kind-filter={kindFilter}
      data-receipt-evidence-status-filter={statusFilter}
      data-receipt-evidence-filtered-count={filteredRecords.length}
      data-receipt-evidence-selected-ref={selectedRecord?.receipt_ref ?? ""}
      data-receipt-evidence-page-cursor={projection.page_cursor ?? ""}
      data-receipt-evidence-next-page-cursor={projection.next_page_cursor ?? ""}
      data-receipt-evidence-page-size={projection.page_size}
      data-receipt-evidence-has-more={projection.has_more ? "true" : "false"}
      data-receipt-evidence-target-source={target?.source ?? ""}
      data-receipt-evidence-target-project={target?.projectId ?? currentProjectId}
      data-receipt-evidence-target-session={target?.sessionRef ?? ""}
      data-receipt-evidence-target-ref={target?.receiptRef ?? ""}
    >
      <div className="hypervisor-receipt-evidence__header">
        <span>Receipts</span>
        <h2>Operational evidence, replay, and state-root continuity.</h2>
        <p>
          Review the activity trail, evidence refs, replay handles, and state
          continuity for recent work.
        </p>
      </div>

      <div
        className="hypervisor-receipt-evidence__toolbar"
        aria-label="Receipt evidence filters"
        data-receipt-evidence-filter-controls="true"
      >
        <label>
          <span>Kind</span>
          <select
            value={kindFilter}
            onChange={(event) =>
              setKindFilter(event.currentTarget.value as typeof kindFilter)
            }
          >
            <option value="all">All receipts</option>
            {kindOptions.map((kind) => (
              <option key={kind} value={kind}>
                {kind.split("_").join(" ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Status</span>
          <select
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(event.currentTarget.value as typeof statusFilter)
            }
          >
            <option value="all">All states</option>
            {statusOptions.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
        <strong>{filteredRecords.length} shown</strong>
        <button
          type="button"
          data-receipt-evidence-first-page="true"
          disabled={!projection.page_cursor}
          onClick={() => setReceiptPageCursor(null)}
        >
          First page
        </button>
        <button
          type="button"
          data-receipt-evidence-next-page={projection.next_page_cursor ?? ""}
          disabled={!projection.has_more || !projection.next_page_cursor}
          onClick={() => setReceiptPageCursor(projection.next_page_cursor)}
        >
          Next page
        </button>
      </div>

      <div className="hypervisor-receipt-evidence__grid">
        {filteredRecords.map((record) => (
          <article
            key={`${record.kind}:${record.receipt_ref}`}
            className="hypervisor-receipt-evidence__card"
            data-receipt-evidence-record={record.receipt_ref}
            data-receipt-evidence-kind={record.kind}
            data-receipt-evidence-status={record.status}
            data-receipt-evidence-selected={
              selectedRecord?.receipt_ref === record.receipt_ref
                ? "true"
                : "false"
            }
          >
            <div className="hypervisor-receipt-evidence__card-head">
              <span>{record.kind.split("_").join(" ")}</span>
              <strong>{record.status}</strong>
            </div>
            <h3>{record.receipt_ref}</h3>
            <p>{record.summary}</p>
            <button
              type="button"
              className="hypervisor-receipt-evidence__review"
              data-receipt-evidence-review={record.receipt_ref}
              onClick={() => setSelectedReceiptRef(record.receipt_ref)}
            >
              Review evidence
            </button>
            <dl>
              <div>
                <dt>Source</dt>
                <dd>{record.source_projection_ref}</dd>
              </div>
              <div>
                <dt>State records</dt>
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

      {selectedRecord ? (
        <aside
          className="hypervisor-receipt-evidence__detail"
          aria-label="Selected receipt evidence"
          data-receipt-evidence-detail={selectedRecord.receipt_ref}
          data-receipt-evidence-replay-ref={selectedRecord.replay_ref}
        >
          <div>
            <span>Selected receipt</span>
            <h3>{selectedRecord.receipt_ref}</h3>
            <p>{selectedRecord.summary}</p>
          </div>
          <dl>
            <div>
              <dt>Replay</dt>
              <dd>{selectedRecord.replay_ref}</dd>
            </div>
            <div>
              <dt>State root</dt>
              <dd>{selectedRecord.state_root_ref}</dd>
            </div>
            <div>
              <dt>Operations</dt>
              <dd>{selectedRecord.agentgres_operation_refs.join(", ")}</dd>
            </div>
            <div>
              <dt>Artifacts</dt>
              <dd>{selectedRecord.artifact_refs.join(", ")}</dd>
            </div>
            <div>
              <dt>Traces</dt>
              <dd>{selectedRecord.trace_refs.join(", ")}</dd>
            </div>
          </dl>
        </aside>
      ) : (
        <p
          className="hypervisor-receipt-evidence__empty"
          data-receipt-evidence-empty="true"
        >
          No receipts match the selected filters.
        </p>
      )}
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
  const [routeMutationAdmission, setRouteMutationAdmission] =
    useState<HypervisorModelRouteMutationAdmission | null>(null);
  const [routeMutationAdmissionError, setRouteMutationAdmissionError] =
    useState<string | null>(null);

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_MODEL_INFRASTRUCTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
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
  const [selectedRouteRef, setSelectedRouteRef] = useState<string | null>(
    projection.routes[0]?.route_ref ?? null,
  );
  const selectedRoute =
    projection.routes.find((route) => route.route_ref === selectedRouteRef) ??
    projection.routes[0] ??
    null;

  useEffect(() => {
    if (
      !selectedRouteRef ||
      !projection.routes.some((route) => route.route_ref === selectedRouteRef)
    ) {
      setSelectedRouteRef(projection.routes[0]?.route_ref ?? null);
    }
  }, [projection.routes, selectedRouteRef]);

  function onRequestRouteMutationAdmission(
    route: HypervisorModelInfrastructureRoute,
  ) {
    setRouteMutationAdmission(null);
    setRouteMutationAdmissionError(null);
    requestHypervisorModelRouteMutationAdmission(projection, route)
      .then((admission) => {
        setRouteMutationAdmission(admission);
      })
      .catch((error) => {
        setRouteMutationAdmissionError(
          error instanceof Error ? error.message : "Model route mutation blocked",
        );
      });
  }

  return (
    <section
      className="hypervisor-model-infrastructure"
      aria-label="Models"
      data-hypervisor-model-infrastructure={projection.projection_id}
      data-model-infrastructure-source={projection.source}
      data-model-infrastructure-inventory-source={projection.inventory_source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-model-infrastructure__header">
        <span>Models</span>
        <h2>Models</h2>
        <p>
          Choose the model path a session should use and review custody before
          it starts.
        </p>
      </div>

      <div
        className="hypervisor-model-infrastructure__tabs"
        aria-label="Model filters"
      >
        <button type="button" className="is-active">
          Routes <span>{projection.model_route_refs.length}</span>
        </button>
        <button type="button">
          Endpoints <span>{projection.endpoint_refs.length}</span>
        </button>
        <button type="button">
          Instances <span>{projection.loaded_instance_refs.length}</span>
        </button>
        <button type="button">
          Receipts <span>{projection.latest_receipt_refs.length}</span>
        </button>
      </div>

      <div className="hypervisor-model-infrastructure__workplane">
        <div
          className="hypervisor-model-infrastructure__list"
          role="list"
          aria-label="Model routes"
        >
          <div
            className="hypervisor-model-infrastructure__list-head"
            role="presentation"
          >
            <span>Route</span>
            <span>Provider</span>
            <span>Custody</span>
            <span>Scopes</span>
          </div>
          {projection.routes.map((route) => (
            <HypervisorModelRouteRow
              key={route.route_ref}
              route={route}
              selected={selectedRoute?.route_ref === route.route_ref}
              onSelect={() => setSelectedRouteRef(route.route_ref)}
            />
          ))}
        </div>

        {selectedRoute ? (
          <HypervisorModelRouteDetail
            route={selectedRoute}
            providers={projection.providers}
            sessionBindings={projection.session_bindings}
            policyRefs={projection.model_weight_custody_policy_refs}
            receiptRefs={projection.latest_receipt_refs}
            routeMutationAdmission={routeMutationAdmission}
            routeMutationAdmissionError={routeMutationAdmissionError}
            onRequestRouteMutationAdmission={onRequestRouteMutationAdmission}
          />
        ) : null}
      </div>

      <div
        className="hypervisor-model-infrastructure__mounts"
        data-model-mounting-ui-boundary="configuration-client"
        hidden
      >
        {children}
      </div>
    </section>
  );
}

function HypervisorModelRouteRow({
  route,
  selected,
  onSelect,
}: {
  route: HypervisorModelInfrastructureRoute;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      className="hypervisor-model-infrastructure__row"
      role="listitem"
      aria-current={selected ? "true" : undefined}
      data-model-route-ref={route.route_ref}
      data-model-route-status={route.status}
      data-model-weight-custody-lane={route.model_weight_custody_lane}
      onClick={onSelect}
    >
      <span className="hypervisor-model-infrastructure__row-route">
        <i aria-hidden="true" />
        <span>
          <strong>{formatModelRouteRef(route.route_ref)}</strong>
          <em>{route.role}</em>
        </span>
      </span>
      <span className="hypervisor-model-infrastructure__row-provider">
        {formatProviderRef(route.provider_ref)}
      </span>
      <span className="hypervisor-model-infrastructure__row-custody">
        {formatCustodyLane(route.model_weight_custody_lane)}
      </span>
      <span className="hypervisor-model-infrastructure__row-scopes">
        {route.authority_scope_refs.map(formatCapabilityRef).join(", ")}
      </span>
    </button>
  );
}

function HypervisorModelRouteDetail({
  route,
  providers,
  sessionBindings,
  policyRefs,
  receiptRefs,
  routeMutationAdmission,
  routeMutationAdmissionError,
  onRequestRouteMutationAdmission,
}: {
  route: HypervisorModelInfrastructureRoute;
  providers: HypervisorModelInfrastructureProvider[];
  sessionBindings: HypervisorModelInfrastructureSessionBinding[];
  policyRefs: string[];
  receiptRefs: string[];
  routeMutationAdmission: HypervisorModelRouteMutationAdmission | null;
  routeMutationAdmissionError: string | null;
  onRequestRouteMutationAdmission: (
    route: HypervisorModelInfrastructureRoute,
  ) => void;
}) {
  const routeProviders = providers.filter(
    (provider) => provider.provider_ref === route.provider_ref,
  );
  const bindings = sessionBindings.filter(
    (binding) => binding.selected_model_route_ref === route.route_ref,
  );

  return (
    <aside
      className="hypervisor-model-infrastructure__detail"
      aria-label={`${route.route_ref} details`}
      data-model-route-detail={route.route_ref}
      data-model-route-status={route.status}
      data-model-weight-custody-lane={route.model_weight_custody_lane}
    >
      <div className="hypervisor-model-infrastructure__detail-head">
        <span>{route.status}</span>
        <h3>{formatModelRouteRef(route.route_ref)}</h3>
        <p>{formatPrivacyPostureRef(`privacy:${route.privacy_posture}`)}</p>
        <button
          type="button"
          data-model-route-mutation-admission-request={route.route_ref}
          onClick={() => onRequestRouteMutationAdmission(route)}
        >
          Bind route
        </button>
      </div>

      {routeMutationAdmission || routeMutationAdmissionError ? (
        <section
          className="hypervisor-model-infrastructure__detail-section"
          data-model-route-mutation-admission={
            routeMutationAdmission?.admission_id ?? "error"
          }
          data-model-route-mutation-runtime-truth={
            routeMutationAdmission?.runtimeTruthSource ?? "blocked"
          }
        >
          <h4>
            {routeMutationAdmission
              ? "Route mutation admitted"
              : "Route mutation blocked"}
          </h4>
          <span>
            <strong>
              {routeMutationAdmission?.admission_state ??
                routeMutationAdmissionError}
            </strong>
            <em>
              {routeMutationAdmission?.wallet_lease_ref ??
                "wallet/model-router admission required"}
            </em>
          </span>
        </section>
      ) : null}

      <dl className="hypervisor-model-infrastructure__detail-list">
        <div>
          <dt>Provider</dt>
          <dd>{formatProviderRef(route.provider_ref)}</dd>
        </div>
        <div>
          <dt>Endpoints</dt>
          <dd>{route.endpoint_refs.length || "none"}</dd>
        </div>
        <div>
          <dt>Instances</dt>
          <dd>{route.loaded_instance_refs.length || "none"}</dd>
        </div>
        <div>
          <dt>Scopes</dt>
          <dd>{route.authority_scope_refs.map(formatCapabilityRef).join(", ")}</dd>
        </div>
      </dl>

      <section className="hypervisor-model-infrastructure__detail-section">
        <h4>Provider posture</h4>
        {routeProviders.length > 0 ? (
          routeProviders.map((provider) => (
            <span
              key={provider.provider_ref}
              data-model-provider-ref={provider.provider_ref}
              data-model-provider-kind={provider.provider_kind}
            >
              <strong>{provider.label}</strong>
              <em>{provider.privacy_posture}</em>
              <small>Receipt recorded</small>
            </span>
          ))
        ) : (
          <span data-model-provider-ref="unmatched">
            <strong>No matched provider</strong>
            <em>{route.provider_ref}</em>
          </span>
        )}
      </section>

      <section className="hypervisor-model-infrastructure__detail-section">
        <h4>Session bindings</h4>
        {bindings.length > 0 ? (
          bindings.map((binding) => (
            <span
              key={binding.session_ref}
              data-model-session-binding={binding.session_ref}
              data-model-session-route={binding.selected_model_route_ref}
            >
              <strong>Active session</strong>
              <em>{formatCustodyLane(binding.custody_profile_ref)}</em>
              <small>Receipt recorded</small>
            </span>
          ))
        ) : (
          <span data-model-session-binding="none">
            <strong>No session binding</strong>
            <em>Available for New Session setup</em>
          </span>
        )}
      </section>

      <section className="hypervisor-model-infrastructure__chips">
        <span>{policyRefs.length} custody policies</span>
        <span>{receiptRefs.length} receipts</span>
      </section>
    </aside>
  );
}

function HypervisorPrivacyPostureSurface({
  currentProjectId,
}: {
  currentProjectId: string;
}) {
  const [projection, setProjection] = useState(
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE,
  );
  const [modelWeightAdmission, setModelWeightAdmission] =
    useState<HypervisorModelWeightCustodyAdmission | null>(null);
  const [modelWeightAdmissionError, setModelWeightAdmissionError] =
    useState<string | null>(null);
  const [workspaceMountAdmission, setWorkspaceMountAdmission] =
    useState<HypervisorPrivateWorkspaceMountAdmission | null>(null);
  const [workspaceMountAdmissionError, setWorkspaceMountAdmissionError] =
    useState<string | null>(null);

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_PRIVACY_POSTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
    let cancelled = false;
    loadHypervisorPrivacyPostureProjection({
      projectId: currentProjectId,
      sessionRef: projection.selected_session_ref,
    })
      .then((nextProjection) => {
        if (!cancelled) {
          setProjection(nextProjection);
        }
      })
      .catch((error) => {
        console.warn("[Hypervisor][Privacy] posture projection unavailable", error);
      });
    return () => {
      cancelled = true;
    };
  }, [currentProjectId, projection.selected_session_ref]);

  async function onRequestModelWeightAdmission(
    policy: HypervisorModelWeightCustodyPolicy,
  ) {
    setModelWeightAdmissionError(null);
    try {
      const admission = await requestHypervisorModelWeightCustodyAdmission(
        projection,
        policy,
      );
      setModelWeightAdmission(admission);
    } catch (error) {
      setModelWeightAdmission(null);
      setModelWeightAdmissionError(
        error instanceof Error ? error.message : "Model-weight admission failed",
      );
    }
  }

  async function onRequestWorkspaceMountAdmission(
    segment: HypervisorWorkspaceCustodySegment,
  ) {
    setWorkspaceMountAdmissionError(null);
    try {
      const admission = await requestHypervisorPrivateWorkspaceMountAdmission(
        projection,
        segment,
      );
      setWorkspaceMountAdmission(admission);
    } catch (error) {
      setWorkspaceMountAdmission(null);
      setWorkspaceMountAdmissionError(
        error instanceof Error
          ? error.message
          : "Private workspace mount admission failed",
      );
    }
  }

  return (
    <section
      className="hypervisor-privacy-posture"
      aria-label="Privacy and cTEE posture surface"
      data-hypervisor-privacy-posture={projection.projection_id}
      data-privacy-posture-source={projection.source}
      data-runtime-truth-source={projection.runtimeTruthSource}
    >
      <div className="hypervisor-privacy-posture__header">
        <span>Workspace</span>
        <h2>Private workspace</h2>
        <p>
          Decide what can run locally, what can run remotely, and what must
          stay sealed.
        </p>
      </div>

      <div className="hypervisor-privacy-posture__summary">
        <div>
          <span>Workspace</span>
          <strong>{formatPrivacyPostureRef(projection.selected_privacy_ref)}</strong>
        </div>
        <div>
          <span>Model</span>
          <strong>{formatModelRouteRef(projection.default_model_route_ref)}</strong>
        </div>
        <div>
          <span>Session</span>
          <strong>Current</strong>
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
                <span>{formatCustodyLane(segment.custody_class)}</span>
              </div>
              <em>{formatPrivacyOwner(segment.owner)}</em>
              <small>
                Remote plaintext{" "}
                {segment.node_plaintext_allowed ? "allowed" : "blocked"}
              </small>
              <button
                type="button"
                data-private-workspace-mount-admission-request={segment.segment_ref}
                title="Request daemon admission for this workspace custody segment"
                onClick={() => {
                  void onRequestWorkspaceMountAdmission(segment);
                }}
              >
                Request mount
              </button>
            </article>
          ))}
        </section>

        <section aria-label="Model-weight custody policies">
          <h3>Model Custody</h3>
          {projection.model_weight_policies.map((policy) => {
            const action = modelWeightCustodyAdmissionAction(policy);
            return (
              <article
                key={policy.lane}
                className="hypervisor-privacy-posture__row"
                data-model-weight-custody-lane={policy.lane}
                data-model-weight-custody-admission-action={action.state}
                data-protects-model-weights={String(
                  policy.protects_model_weights_from_provider_root,
                )}
              >
                <div>
                  <strong>{policy.label}</strong>
                  <span>{policy.admission_summary}</span>
                </div>
                <em>{formatModelWeightProtection(policy)}</em>
                <small>{policy.authority_scope_refs.map(formatCapabilityRef).join(", ")}</small>
                <button
                  type="button"
                  data-model-weight-custody-admission-request={policy.lane}
                  disabled={action.state !== "daemon_admissible"}
                  title={action.disabled_reason ?? action.label}
                  onClick={() => {
                    void onRequestModelWeightAdmission(policy);
                  }}
                >
                  {action.label}
                </button>
              </article>
            );
          })}
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
              <em>{formatCustodyLane(candidate.posture)}</em>
              <small>{formatCustodyLane(candidate.model_weight_lane)}</small>
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
                <span>Receipt recorded</span>
              </div>
              <em>{formatPrivacyOwner(control.owner)}</em>
              <small>
                Unsafe plaintext{" "}
                {control.blocks_unsafe_plaintext ? "blocked" : "allowed"}
              </small>
            </article>
          ))}
        </section>
      </div>
      {(modelWeightAdmission || modelWeightAdmissionError) && (
        <div
          className="hypervisor-privacy-posture__admission"
          data-model-weight-custody-admission={
            modelWeightAdmission?.admission_id ?? "error"
          }
          data-model-weight-custody-admission-runtime-truth={
            modelWeightAdmission?.runtimeTruthSource ?? "daemon-runtime"
          }
        >
          {modelWeightAdmission ? (
            <>
              <strong>Daemon admission recorded</strong>
              <span>{modelWeightAdmission.receipt_ref}</span>
            </>
          ) : (
            <>
              <strong>Daemon admission blocked</strong>
              <span>{modelWeightAdmissionError}</span>
            </>
          )}
        </div>
      )}
      {(workspaceMountAdmission || workspaceMountAdmissionError) && (
        <div
          className="hypervisor-privacy-posture__admission"
          data-private-workspace-mount-admission={
            workspaceMountAdmission?.admission_id ?? "error"
          }
          data-private-workspace-mount-admission-runtime-truth={
            workspaceMountAdmission?.runtimeTruthSource ?? "daemon-runtime"
          }
        >
          {workspaceMountAdmission ? (
            <>
              <strong>Workspace mount admitted</strong>
              <span>{workspaceMountAdmission.receipt_ref}</span>
            </>
          ) : (
            <>
              <strong>Workspace mount blocked</strong>
              <span>{workspaceMountAdmissionError}</span>
            </>
          )}
        </div>
      )}
    </section>
  );
}

export function HypervisorShellContent({
  controller,
  runtime,
}: HypervisorShellContentProps) {
  const {
    activeView,
    currentProjectId,
    currentProject,
    projects,
    notificationBadgeCount,
  } =
    controller;
  const workspaceHost = getDefaultWorkspaceSessionHost();
  const workspaceActive = activeView === "workbench";
  const settingsActive = activeView === "settings";
  const workflowActive = activeView === "automations";
  const mountsActive = activeView === "models";
  const dedicatedWorkbenchActive = workflowActive || mountsActive;
  const contentMainRef = useRef<HTMLDivElement | null>(null);

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

  return (
    <div
      className={clsx(
        "hypervisor-shell",
        workspaceActive && "hypervisor-shell--workspace-mode",
      )}
    >
      <div
        className={clsx(
          "hypervisor-workspace",
          workspaceActive && "hypervisor-workspace--workspace-mode",
        )}
      >
        <HypervisorActivityRail
          activeView={activeView}
          onViewChange={controller.changePrimaryView}
          onOpenNewSession={controller.modals.openNewSessionModal}
          onOpenCommandPalette={controller.modals.openCommandPalette}
          notificationCount={notificationBadgeCount}
          profile={controller.profile.value}
          launchedSessions={controller.sessions.launchedSessionProjections}
        />

        <div
          className={clsx(
            "hypervisor-main",
            workspaceActive && "hypervisor-main--workspace-mode",
          )}
        >
          {workspaceActive ? (
            <WorkspaceShell
              active
              currentProject={currentProject}
              projects={projects}
              runtime={runtime}
              host={workspaceHost}
            />
          ) : null}

          {!workspaceActive ? (
            <div
              className={clsx(
                "hypervisor-content",
                dedicatedWorkbenchActive && "is-dedicated-workbench",
              )}
            >
              <div className="hypervisor-center-area">
                <div
                  ref={contentMainRef}
                  className={clsx(
                    "hypervisor-content-main",
                    dedicatedWorkbenchActive &&
                      "hypervisor-content-main--dedicated-workbench",
                  )}
                >
                  {activeView === "home" ? (
                    <HomeView
                      currentProject={currentProject}
                      recentSessions={
                        controller.sessions.launchedSessionProjections
                      }
                      notificationCount={notificationBadgeCount}
                      onOpenChat={() => controller.changePrimaryView("sessions")}
                      onOpenNewSession={controller.modals.openNewSessionModal}
                      onOpenWorkspace={() =>
                        controller.changePrimaryView("workbench")
                      }
                      onOpenRuns={() =>
                        controller.changePrimaryView("applications")
                      }
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
                    />
                  ) : null}

                  {activeView === "sessions" ? (
                    <HypervisorSessionOperationsCockpit
                      launchedSessions={
                        controller.sessions.launchedSessionProjections
                      }
                      currentProject={{
                        id: currentProject.id,
                        name: currentProject.name,
                        rootPath: currentProject.rootPath,
                      }}
                      agentOptions={HYPERVISOR_SESSION_AGENT_SELECTOR_OPTIONS}
                      agentSelectionRef={controller.sessions.selectedAgentRef}
                      onSelectAgent={controller.sessions.selectAgent}
                      modelOptions={buildHypervisorModelOptions(
                        controller.sessions.selectedAgentRef,
                      )}
                      modelSelectionRef={controller.sessions.selectedModelRef}
                      onSelectModel={controller.sessions.selectModel}
                      onLaunchSession={controller.modals.launchNewSession}
                      onConfigureLaunch={(seed) =>
                        controller.modals.openNewSessionModalAdvanced(
                          seed ?? undefined,
                        )
                      }
                      onOpenReceiptEvidence={controller.receipts.openTarget}
                    />
                  ) : null}

                  {activeView === "projects" ? (
	                    <HypervisorProjectStateSurface
	                      selectedProjectId={currentProjectId}
	                      onOpenReceiptEvidence={controller.receipts.openTarget}
	                      onProjectStateProjection={
	                        controller.projectState.registerProjection
	                      }
	                      onLaunchProjectSession={
	                        controller.projectState.launchProjectSession
	                      }
	                    />
                  ) : null}

                  {activeView === "automations" ? (
                    <HypervisorAutomationCompositorSurface
                      currentProjectId={currentProject.id}
                    >
                      <AutomationsWorkflowComposerView
                        runtime={runtime}
                        currentProject={currentProject}
                        workflowPreflightSeed={
                          controller.workflow.preflightSeed
                        }
                        onConsumeWorkflowPreflightSeed={
                          controller.workflow.consumePreflightSeed
                        }
                      />
                    </HypervisorAutomationCompositorSurface>
                  ) : null}

                  {activeView === "applications" ? (
                    <HypervisorApplicationsCatalogSurface
                      onLaunchApplication={(applicationId) => {
                        const view = applicationViewForId(applicationId);
                        if (view) controller.changePrimaryView(view);
                      }}
                    />
                  ) : null}

                  {activeView === "insights" ? (
                    <HypervisorInsightsReferenceSurface>
                      <RuntimeInsightsView runtime={runtime} />
                    </HypervisorInsightsReferenceSurface>
                  ) : null}

                  {activeView === "models" ? (
                    <HypervisorModelInfrastructureSurface
                      currentProjectId={currentProject.id}
                    >
                      <ModelMountsSurfaceView />
                    </HypervisorModelInfrastructureSurface>
                  ) : null}

                  {activeView === "privacy" ? (
                    <HypervisorPrivacyPostureSurface
                      currentProjectId={currentProject.id}
                    />
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
                      target={controller.receipts.target}
                    />
                  ) : null}

                  {activeView === "missions" ? (
                    <InboxView
                      onOpenHypervisor={() => {
                        controller.changePrimaryView("sessions");
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
                    />
                  ) : null}

                  {activeView === "agents" ? (
                    <HypervisorAgentsSurface
                      currentProjectId={currentProject.id}
                      onOpenSessions={() =>
                        controller.changePrimaryView("sessions")
                      }
                      onOpenReceipts={() =>
                        controller.changePrimaryView("receipts")
                      }
                      onOpenAuthority={() =>
                        controller.changePrimaryView("authority")
                      }
                    >
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
                        onOpenInbox={() =>
                          controller.changePrimaryView("missions")
                        }
                        onOpenSettings={() =>
                          controller.changePrimaryView("settings")
                        }
                        onOpenSkillSources={() =>
                          controller.settings.openSection("integrations")
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
                    </HypervisorAgentsSurface>
                  ) : null}

                  {activeView === "authority" ? (
                    <AuthoritySettingsSurfaceView
                      runtime={runtime}
                      surface="policy"
                      policyState={controller.policy.shieldPolicy}
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
                      seedSection={controller.settings.seedSection}
                      onConsumeSeedSection={
                        controller.settings.consumeSeedSection
                      }
                    />
                  ) : null}

                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
