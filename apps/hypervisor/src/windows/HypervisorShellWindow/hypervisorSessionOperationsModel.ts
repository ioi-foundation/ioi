import {
  HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL,
  HYPERVISOR_SESSION_DETAIL_TABS,
  type HypervisorInspectorPanelId,
  type HypervisorSessionDetailTab,
} from "./hypervisorShellNavigationModel";

export type HypervisorSessionLifecycleState =
  | "active"
  | "waiting_for_approval"
  | "blocked"
  | "idle"
  | "archived";

export interface HypervisorSessionRailProjection {
  state: (typeof HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL)[number];
  count: number;
  selected: boolean;
}

export interface HypervisorSessionTabProjection {
  tab_id: HypervisorSessionDetailTab;
  label: string;
  summary: string;
  evidence_refs: string[];
}

export interface HypervisorInspectorPanelProjection {
  panel_id: HypervisorInspectorPanelId;
  label: string;
  summary: string;
  status: "clear" | "attention" | "blocked";
  evidence_refs: string[];
}

export interface HypervisorServicePortProjection {
  service_ref: string;
  label: string;
  port: number;
  protocol: "http" | "grpc" | "ssh" | "tcp";
  lease_ref: string;
  status: "available" | "lease_required" | "blocked";
}

export interface HypervisorTaskProjection {
  task_ref: string;
  label: string;
  status: "running" | "waiting_for_approval" | "blocked" | "completed";
  receipt_ref: string;
}

export interface HypervisorTerminalEventProjection {
  event_ref: string;
  command_summary: string;
  status: "executed" | "proposed" | "blocked";
  receipt_ref: string;
}

export interface HypervisorSessionOperationsProjection {
  schema_version: "ioi.hypervisor.session_operations_projection.v1";
  projection_id: string;
  selected_session_ref: string;
  lifecycle_state: HypervisorSessionLifecycleState;
  project_ref: string;
  environment_ref: string;
  provider_candidate_ref: string;
  selected_adapter_ref: string;
  authority_scope_refs: string[];
  access_lease_ref: string;
  log_lease_ref: string;
  archive_ref: string;
  restore_ref: string;
  session_rail: HypervisorSessionRailProjection[];
  detail_tabs: HypervisorSessionTabProjection[];
  right_inspector_panels: HypervisorInspectorPanelProjection[];
  bottom_inspector_panels: HypervisorInspectorPanelProjection[];
  ports_services: HypervisorServicePortProjection[];
  tasks: HypervisorTaskProjection[];
  terminal_events: HypervisorTerminalEventProjection[];
  latest_receipt_refs: string[];
  runtimeTruthSource: "daemon-runtime";
}

function formatPanelLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" / ");
}

export const HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE: HypervisorSessionOperationsProjection =
  {
    schema_version: "ioi.hypervisor.session_operations_projection.v1",
    projection_id: "hypervisor-session-operations:active-mission",
    selected_session_ref: "session:mission/hypervisor-core-refine-architecture",
    lifecycle_state: "active",
    project_ref: "project:hypervisor-core",
    environment_ref: "environment:local-workspace/hypervisor-core",
    provider_candidate_ref: "provider:local-workstation",
    selected_adapter_ref: "workbench-adapter:embedded_workbench",
    authority_scope_refs: [
      "scope:workspace.read",
      "scope:workspace.patch",
      "scope:receipt.write",
    ],
    access_lease_ref: "lease:access/hypervisor-core/workbench",
    log_lease_ref: "lease:logs/hypervisor-core/session",
    archive_ref: "artifact://agentgres/archive/hypervisor-core/latest",
    restore_ref: "agentgres://restore/hypervisor-core/latest",
    session_rail: HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL.map((state, index) => ({
      state,
      count: [2, 1, 1, 0, 4][index] ?? 0,
      selected: state === "active",
    })),
    detail_tabs: HYPERVISOR_SESSION_DETAIL_TABS.map((tab_id) => ({
      tab_id,
      label: formatPanelLabel(tab_id),
      summary:
        tab_id === "environment"
          ? "Provider, ports, services, leases, archive refs, and restore posture."
          : `${formatPanelLabel(tab_id)} state is projected from daemon and Agentgres receipts.`,
      evidence_refs: [
        `agentgres://projection/session-detail/${tab_id}`,
        `receipt://session-detail/${tab_id}`,
      ],
    })),
    right_inspector_panels: HYPERVISOR_RIGHT_INSPECTOR_PANELS.map((panel_id) => ({
      panel_id,
      label: formatPanelLabel(panel_id),
      summary:
        panel_id === "authority"
          ? "wallet.network scopes, leases, and approvals remain the action gate."
          : `${formatPanelLabel(panel_id)} evidence is read-only until a daemon operation admits an update.`,
      status: panel_id === "authority" ? "attention" : "clear",
      evidence_refs: [
        `agentgres://projection/right-inspector/${panel_id}`,
        `receipt://right-inspector/${panel_id}`,
      ],
    })),
    bottom_inspector_panels: HYPERVISOR_BOTTOM_INSPECTOR_PANELS.map((panel_id) => ({
      panel_id,
      label: formatPanelLabel(panel_id),
      summary:
        panel_id === "terminal"
          ? "Terminal access is lease-bound and command receipts are required."
          : `${formatPanelLabel(panel_id)} stream is bounded by the selected session environment.`,
      status: panel_id === "terminal" ? "attention" : "clear",
      evidence_refs: [
        `agentgres://projection/bottom-inspector/${panel_id}`,
        `receipt://bottom-inspector/${panel_id}`,
      ],
    })),
    ports_services: [
      {
        service_ref: "service:hypervisor-daemon",
        label: "Hypervisor daemon",
        port: 17380,
        protocol: "http",
        lease_ref: "lease:access/hypervisor-daemon/http",
        status: "available",
      },
      {
        service_ref: "service:workbench-adapter",
        label: "Workbench adapter host",
        port: 17381,
        protocol: "grpc",
        lease_ref: "lease:access/workbench-adapter/grpc",
        status: "lease_required",
      },
    ],
    tasks: [
      {
        task_ref: "task:refine-architecture/session-inspector",
        label: "Project session cockpit projection",
        status: "running",
        receipt_ref: "receipt://task/session-inspector/running",
      },
      {
        task_ref: "task:refine-architecture/authority-review",
        label: "Authority and privacy review",
        status: "waiting_for_approval",
        receipt_ref: "receipt://task/authority-review/pending",
      },
    ],
    terminal_events: [
      {
        event_ref: "terminal-event:latest/status",
        command_summary: "git status --short --branch",
        status: "executed",
        receipt_ref: "receipt://terminal/status/latest",
      },
      {
        event_ref: "terminal-event:proposed/build",
        command_summary: "npm --workspace apps/hypervisor run build",
        status: "proposed",
        receipt_ref: "receipt://terminal/build/proposed",
      },
    ],
    latest_receipt_refs: [
      "receipt://session/lifecycle/active",
      "receipt://authority/scope/workspace-patch",
      "receipt://environment/lease/logs",
    ],
    runtimeTruthSource: "daemon-runtime",
  };
