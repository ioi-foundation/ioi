import {
  HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL,
  HYPERVISOR_SESSION_DETAIL_TABS,
  type HypervisorInspectorPanelId,
  type HypervisorSessionDetailTab,
} from "./hypervisorShellNavigationModel.ts";

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

export interface HypervisorSessionActivitySignalProjection {
  signal_ref: string;
  kind: "scm" | "service" | "task" | "approval" | "receipt" | "restore";
  label: string;
  detail: string;
  status: "normal" | "attention" | "blocked";
  receipt_ref: string;
}

export interface HypervisorSessionLeaseProjection {
  lease_ref: string;
  label: string;
  scope_ref: string;
  status: "active" | "requires_renewal" | "blocked";
  expires_label: string;
  receipt_ref: string;
}

export interface HypervisorEnvironmentLifecycleStepProjection {
  step_ref: string;
  label: string;
  detail: string;
  status: "completed" | "running" | "waiting_for_approval" | "blocked";
  evidence_ref: string;
}

export interface HypervisorChangedFileProjection {
  file_ref: string;
  name: string;
  delta: string;
  status: "added" | "modified" | "deleted" | "untracked";
  receipt_ref: string;
}

export interface HypervisorChangedFileGroupProjection {
  group_ref: string;
  folder: string;
  files: HypervisorChangedFileProjection[];
}

export interface HypervisorSessionOperationsProjection {
  schema_version: "ioi.hypervisor.session_operations_projection.v1";
  projection_id: string;
  source: "daemon-session-operations-projection" | "fixture" | "unverified";
  selected_session_ref: string;
  display_title: string;
  branch_label: string;
  lifecycle_state: HypervisorSessionLifecycleState;
  auto_stop_label: string;
  created_label: string;
  last_started_label: string;
  resource_health_label: string;
  resource_health_state: "healthy" | "attention" | "blocked";
  project_ref: string;
  environment_ref: string;
  provider_candidate_ref: string;
  selected_adapter_ref: string;
  selected_adapter_admission_state:
    | "daemon_admitted"
    | "daemon_blocked"
    | "daemon_unavailable"
    | "pending_daemon_admission";
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
  activity_signals: HypervisorSessionActivitySignalProjection[];
  access_log_leases: HypervisorSessionLeaseProjection[];
  environment_lifecycle_steps: HypervisorEnvironmentLifecycleStepProjection[];
  changed_file_groups: HypervisorChangedFileGroupProjection[];
  latest_receipt_refs: string[];
  runtimeTruthSource: "daemon-runtime";
}

export type HypervisorSessionOperationKind =
  | "request_access_lease"
  | "request_log_lease"
  | "open_port"
  | "run_task"
  | "propose_terminal_command"
  | "archive_session"
  | "restore_session";

export interface HypervisorSessionOperationProposal {
  schema_version: "ioi.hypervisor.session_operation_proposal.v1";
  proposal_ref: string;
  source: "daemon-session-operation-proposal" | "fixture" | "unverified";
  project_ref: string;
  session_ref: string;
  environment_ref: string;
  provider_candidate_ref: string;
  operation_kind: HypervisorSessionOperationKind;
  target_ref: string;
  admission_state:
    | "requires_wallet_lease"
    | "ready_for_daemon_admission"
    | "blocked";
  wallet_lease_ref: string;
  required_scope_refs: string[];
  agentgres_operation_ref: string;
  receipt_ref: string;
  state_root_ref: string;
  archive_ref: string;
  restore_ref: string;
  custody_invariant: string;
}

export const HYPERVISOR_SESSION_OPERATION_KINDS: HypervisorSessionOperationKind[] =
  [
    "request_access_lease",
    "request_log_lease",
    "open_port",
    "run_task",
    "propose_terminal_command",
    "archive_session",
    "restore_session",
  ];

export const HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_SESSION_OPERATIONS_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH =
  "/v1/hypervisor/session-operations";
export const HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH =
  "/v1/hypervisor/session-operations/proposals";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeSessionOperationsProjectionOptions {
  source?: HypervisorSessionOperationsProjection["source"];
}

interface LoadSessionOperationsProjectionOptions
  extends NormalizeSessionOperationsProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
  sessionRef?: string | null;
}

interface NormalizeSessionOperationProposalOptions {
  projection?: HypervisorSessionOperationsProjection;
  operationKind?: HypervisorSessionOperationKind;
  targetRef?: string;
  source?: HypervisorSessionOperationProposal["source"];
}

interface ProposeSessionOperationOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projection: HypervisorSessionOperationsProjection;
  operationKind: HypervisorSessionOperationKind;
  targetRef?: string;
  source?: HypervisorSessionOperationProposal["source"];
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
    projection_id: "hypervisor-session-operations:active-session",
    source: "fixture",
    selected_session_ref: "session:project/write-parent-harness-evidence-boundary",
    display_title: "Write Parent Harness Evidence Boundary Doc",
    branch_label: "main",
    lifecycle_state: "active",
    auto_stop_label: "30m of inactivity",
    created_label: "5h ago",
    last_started_label: "5h ago",
    resource_health_label: "Healthy",
    resource_health_state: "healthy",
    project_ref: "project:ioi",
    environment_ref: "environment:remote-vm/hypervisor-us01",
    provider_candidate_ref: "provider:hypervisor-cloud/us01",
    selected_adapter_ref: "code-editor-adapter:embedded_code_editor",
    selected_adapter_admission_state: "daemon_admitted",
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
          : `${formatPanelLabel(tab_id)} state is available for the selected session.`,
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
          : `${formatPanelLabel(panel_id)} evidence is read-only until an approved update is available.`,
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
    ports_services: [],
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
    activity_signals: [
      {
        signal_ref: "signal:scm/uncommitted",
        kind: "scm",
        label: "3 changed files",
        detail: "SCM changes are linked to receipt-backed patch evidence.",
        status: "attention",
        receipt_ref: "receipt://activity/scm/uncommitted",
      },
      {
        signal_ref: "signal:service/workspace-control",
        kind: "service",
        label: "No open ports",
        detail: "Ports stay closed until an approved lease opens a service.",
        status: "normal",
        receipt_ref: "receipt://activity/service/visibility",
      },
      {
        signal_ref: "signal:approval/authority-review",
        kind: "approval",
        label: "1 approval pending",
        detail: "Authority review waits for approval before execution.",
        status: "attention",
        receipt_ref: "receipt://activity/approval/pending",
      },
      {
        signal_ref: "signal:restore/latest",
        kind: "restore",
        label: "Restore material ready",
        detail: "Encrypted archive material is available for a recorded restore.",
        status: "normal",
        receipt_ref: "receipt://activity/restore/ready",
      },
    ],
    access_log_leases: [
      {
        lease_ref: "lease:access/hypervisor-core/workbench",
        label: "Workbench access",
        scope_ref: "scope:session.access",
        status: "active",
        expires_label: "30m",
        receipt_ref: "receipt://lease/access/workbench",
      },
      {
        lease_ref: "lease:logs/hypervisor-core/session",
        label: "Session logs",
        scope_ref: "scope:logs.read",
        status: "requires_renewal",
        expires_label: "5m",
        receipt_ref: "receipt://lease/logs/session",
      },
    ],
    environment_lifecycle_steps: [
      {
        step_ref: "session-step:workspace",
        label: "Started remote environment",
        detail: "Hypervisor Cloud (US01)",
        status: "completed",
        evidence_ref: "receipt://environment/remote-vm/started",
      },
      {
        step_ref: "session-step:repository",
        label: "Initialized repository",
        detail: "ioi",
        status: "completed",
        evidence_ref: "agentgres://projection/repository/ioi",
      },
      {
        step_ref: "session-step:secrets",
        label: "Loaded secrets",
        detail: "1 project secret",
        status: "completed",
        evidence_ref: "receipt://wallet/secret-lease/workspace",
      },
      {
        step_ref: "session-step:automations",
        label: "Loaded automations",
        detail: ".ioi/automations.yaml",
        status: "completed",
        evidence_ref: "receipt://workflow-compositor/templates/loaded",
      },
      {
        step_ref: "session-step:devcontainer",
        label: "Started dev container",
        detail: ".devcontainer/devcontainer.json",
        status: "completed",
        evidence_ref: "receipt://environment/devcontainer/started",
      },
    ],
    changed_file_groups: [
      {
        group_ref: "changed-group:devcontainer",
        folder: ".devcontainer/",
        files: [
          {
            file_ref: "changed-file:devcontainer-json",
            name: "devcontainer.json",
            delta: "+20",
            status: "untracked",
            receipt_ref: "receipt://changes/devcontainer-json",
          },
          {
            file_ref: "changed-file:dockerfile",
            name: "Dockerfile",
            delta: "+5",
            status: "untracked",
            receipt_ref: "receipt://changes/dockerfile",
          },
        ],
      },
      {
        group_ref: "changed-group:docs",
        folder: "docs/",
        files: [
          {
            file_ref: "changed-file:parent-harness-evidence",
            name: "parent-harness-evidence-boundary.md",
            delta: "+138",
            status: "modified",
            receipt_ref: "receipt://changes/parent-harness-evidence",
          },
        ],
      },
    ],
    latest_receipt_refs: [
      "receipt://session/lifecycle/active",
      "receipt://authority/scope/workspace-patch",
      "receipt://environment/lease/logs",
    ],
    runtimeTruthSource: "daemon-runtime",
  };

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function enumValue<T extends string>(
  value: unknown,
  fallback: T,
  allowed: readonly T[],
): T {
  return typeof value === "string" && allowed.includes(value as T)
    ? (value as T)
    : fallback;
}

function sessionOperationKindValue(
  value: unknown,
  fallback: HypervisorSessionOperationKind,
): HypervisorSessionOperationKind {
  return enumValue(value, fallback, HYPERVISOR_SESSION_OPERATION_KINDS);
}

function sessionOperationTargetRef(
  projection: HypervisorSessionOperationsProjection,
  operationKind: HypervisorSessionOperationKind,
  targetRef?: string,
): string {
  if (targetRef) {
    return targetRef;
  }
  switch (operationKind) {
    case "request_access_lease":
      return projection.access_lease_ref;
    case "request_log_lease":
      return projection.log_lease_ref;
    case "open_port":
      return projection.ports_services[0]?.service_ref ?? projection.environment_ref;
    case "run_task":
      return projection.tasks[0]?.task_ref ?? projection.selected_session_ref;
    case "propose_terminal_command":
      return projection.terminal_events[0]?.event_ref ?? projection.selected_session_ref;
    case "archive_session":
      return projection.archive_ref;
    case "restore_session":
      return projection.restore_ref;
    default:
      return projection.selected_session_ref;
  }
}

function sessionOperationRequiredScopes(
  projection: HypervisorSessionOperationsProjection,
  operationKind: HypervisorSessionOperationKind,
): string[] {
  const scopeByKind: Record<HypervisorSessionOperationKind, string[]> = {
    request_access_lease: ["scope:session.access"],
    request_log_lease: ["scope:logs.read"],
    open_port: ["scope:port.expose"],
    run_task: ["scope:task.run"],
    propose_terminal_command: ["scope:shell.exec"],
    archive_session: ["scope:archive.write"],
    restore_session: ["scope:restore.apply"],
  };
  return Array.from(
    new Set([...projection.authority_scope_refs, ...scopeByKind[operationKind]]),
  );
}

function sessionOperationAdmissionState(
  operationKind: HypervisorSessionOperationKind,
): HypervisorSessionOperationProposal["admission_state"] {
  return operationKind === "run_task" || operationKind === "archive_session"
    ? "ready_for_daemon_admission"
    : "requires_wallet_lease";
}

function proposalRefSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.:-]+/g, "-");
}

function normalizeRailProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorSessionRailProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.session_rail[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.session_rail[0]!;
  return {
    state: enumValue(item.state, fallback.state, HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL),
    count: numberValue(item.count, fallback.count),
    selected:
      typeof item.selected === "boolean" ? item.selected : fallback.selected,
  };
}

function normalizeTabProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorSessionTabProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.detail_tabs[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.detail_tabs[0]!;
  return {
    tab_id: enumValue(item.tab_id, fallback.tab_id, HYPERVISOR_SESSION_DETAIL_TABS),
    label: stringValue(item.label, fallback.label),
    summary: stringValue(item.summary, fallback.summary),
    evidence_refs: stringList(item.evidence_refs, fallback.evidence_refs),
  };
}

function normalizeInspectorPanelProjection(
  item: Record<string, unknown>,
  index: number,
  fallbackPanels: HypervisorInspectorPanelProjection[],
): HypervisorInspectorPanelProjection {
  const fallback = fallbackPanels[index] ?? fallbackPanels[0]!;
  return {
    panel_id: enumValue(
      item.panel_id,
      fallback.panel_id,
      [...HYPERVISOR_RIGHT_INSPECTOR_PANELS, ...HYPERVISOR_BOTTOM_INSPECTOR_PANELS],
    ),
    label: stringValue(item.label, fallback.label),
    summary: stringValue(item.summary, fallback.summary),
    status: enumValue(item.status, fallback.status, ["clear", "attention", "blocked"]),
    evidence_refs: stringList(item.evidence_refs, fallback.evidence_refs),
  };
}

function normalizeServicePortProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorServicePortProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.ports_services[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.ports_services[0] ??
    ({
      service_ref: "service:unverified",
      label: "Unverified service",
      port: 0,
      protocol: "tcp",
      lease_ref: "lease:access/unverified",
      status: "lease_required",
    } satisfies HypervisorServicePortProjection);
  return {
    service_ref: stringValue(item.service_ref, fallback.service_ref),
    label: stringValue(item.label, fallback.label),
    port: numberValue(item.port, fallback.port),
    protocol: enumValue(item.protocol, fallback.protocol, ["http", "grpc", "ssh", "tcp"]),
    lease_ref: stringValue(item.lease_ref, fallback.lease_ref),
    status: enumValue(item.status, fallback.status, [
      "available",
      "lease_required",
      "blocked",
    ]),
  };
}

function normalizeTaskProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorTaskProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.tasks[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.tasks[0]!;
  return {
    task_ref: stringValue(item.task_ref, fallback.task_ref),
    label: stringValue(item.label, fallback.label),
    status: enumValue(item.status, fallback.status, [
      "running",
      "waiting_for_approval",
      "blocked",
      "completed",
    ]),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeTerminalEventProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorTerminalEventProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.terminal_events[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.terminal_events[0]!;
  return {
    event_ref: stringValue(item.event_ref, fallback.event_ref),
    command_summary: stringValue(item.command_summary, fallback.command_summary),
    status: enumValue(item.status, fallback.status, ["executed", "proposed", "blocked"]),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeActivitySignalProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorSessionActivitySignalProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.activity_signals[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.activity_signals[0]!;
  return {
    signal_ref: stringValue(item.signal_ref, fallback.signal_ref),
    kind: enumValue(item.kind, fallback.kind, [
      "scm",
      "service",
      "task",
      "approval",
      "receipt",
      "restore",
    ]),
    label: stringValue(item.label, fallback.label),
    detail: stringValue(item.detail, fallback.detail),
    status: enumValue(item.status, fallback.status, [
      "normal",
      "attention",
      "blocked",
    ]),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeSessionLeaseProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorSessionLeaseProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.access_log_leases[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.access_log_leases[0]!;
  return {
    lease_ref: stringValue(item.lease_ref, fallback.lease_ref),
    label: stringValue(item.label, fallback.label),
    scope_ref: stringValue(item.scope_ref, fallback.scope_ref),
    status: enumValue(item.status, fallback.status, [
      "active",
      "requires_renewal",
      "blocked",
    ]),
    expires_label: stringValue(item.expires_label, fallback.expires_label),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeEnvironmentLifecycleStepProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorEnvironmentLifecycleStepProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.environment_lifecycle_steps[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.environment_lifecycle_steps[0]!;
  return {
    step_ref: stringValue(item.step_ref, fallback.step_ref),
    label: stringValue(item.label, fallback.label),
    detail: stringValue(item.detail, fallback.detail),
    status: enumValue(item.status, fallback.status, [
      "completed",
      "running",
      "waiting_for_approval",
      "blocked",
    ]),
    evidence_ref: stringValue(item.evidence_ref, fallback.evidence_ref),
  };
}

function normalizeChangedFileProjection(
  item: Record<string, unknown>,
  index: number,
  fallbackFiles: HypervisorChangedFileProjection[],
): HypervisorChangedFileProjection {
  const fallback = fallbackFiles[index] ?? fallbackFiles[0]!;
  return {
    file_ref: stringValue(item.file_ref, fallback.file_ref),
    name: stringValue(item.name, fallback.name),
    delta: stringValue(item.delta, fallback.delta),
    status: enumValue(item.status, fallback.status, [
      "added",
      "modified",
      "deleted",
      "untracked",
    ]),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizeChangedFileGroupProjection(
  item: Record<string, unknown>,
  index: number,
): HypervisorChangedFileGroupProjection {
  const fallback =
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.changed_file_groups[index] ??
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.changed_file_groups[0]!;
  const files = arrayOf(item.files).map((file, fileIndex) =>
    normalizeChangedFileProjection(file, fileIndex, fallback.files),
  );
  return {
    group_ref: stringValue(item.group_ref, fallback.group_ref),
    folder: stringValue(item.folder, fallback.folder),
    files: files.length > 0 ? files : fallback.files,
  };
}

export function readHypervisorSessionOperationsDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_SESSION_OPERATIONS_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_SESSION_OPERATIONS_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_SESSION_OPERATIONS_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorSessionOperationsProjection(
  snapshot: unknown,
  options: NormalizeSessionOperationsProjectionOptions = {},
): HypervisorSessionOperationsProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  const sessionRail = arrayOf(value.session_rail).map(normalizeRailProjection);
  const detailTabs = arrayOf(value.detail_tabs).map(normalizeTabProjection);
  const rightPanels = arrayOf(value.right_inspector_panels).map((panel, index) =>
    normalizeInspectorPanelProjection(panel, index, fallback.right_inspector_panels),
  );
  const bottomPanels = arrayOf(value.bottom_inspector_panels).map((panel, index) =>
    normalizeInspectorPanelProjection(panel, index, fallback.bottom_inspector_panels),
  );
  const portsServices = arrayOf(value.ports_services).map(
    normalizeServicePortProjection,
  );
  const tasks = arrayOf(value.tasks).map(normalizeTaskProjection);
  const terminalEvents = arrayOf(value.terminal_events).map(
    normalizeTerminalEventProjection,
  );
  const activitySignals = arrayOf(value.activity_signals).map(
    normalizeActivitySignalProjection,
  );
  const accessLogLeases = arrayOf(value.access_log_leases).map(
    normalizeSessionLeaseProjection,
  );
  const environmentLifecycleSteps = arrayOf(value.environment_lifecycle_steps).map(
    normalizeEnvironmentLifecycleStepProjection,
  );
  const changedFileGroups = arrayOf(value.changed_file_groups).map(
    normalizeChangedFileGroupProjection,
  );
  return {
    schema_version: "ioi.hypervisor.session_operations_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-session-operations-projection",
    selected_session_ref: stringValue(
      value.selected_session_ref,
      fallback.selected_session_ref,
    ),
    display_title: stringValue(value.display_title, fallback.display_title),
    branch_label: stringValue(value.branch_label, fallback.branch_label),
    lifecycle_state: enumValue(value.lifecycle_state, fallback.lifecycle_state, [
      "active",
      "waiting_for_approval",
      "blocked",
      "idle",
      "archived",
    ]),
    auto_stop_label: stringValue(value.auto_stop_label, fallback.auto_stop_label),
    created_label: stringValue(value.created_label, fallback.created_label),
    last_started_label: stringValue(
      value.last_started_label,
      fallback.last_started_label,
    ),
    resource_health_label: stringValue(
      value.resource_health_label,
      fallback.resource_health_label,
    ),
    resource_health_state: enumValue(
      value.resource_health_state,
      fallback.resource_health_state,
      ["healthy", "attention", "blocked"],
    ),
    project_ref: stringValue(value.project_ref, fallback.project_ref),
    environment_ref: stringValue(value.environment_ref, fallback.environment_ref),
    provider_candidate_ref: stringValue(
      value.provider_candidate_ref,
      fallback.provider_candidate_ref,
    ),
    selected_adapter_ref: stringValue(
      value.selected_adapter_ref,
      fallback.selected_adapter_ref,
    ),
    selected_adapter_admission_state: enumValue(
      value.selected_adapter_admission_state,
      fallback.selected_adapter_admission_state,
      [
        "daemon_admitted",
        "daemon_blocked",
        "daemon_unavailable",
        "pending_daemon_admission",
      ],
    ),
    authority_scope_refs: stringList(
      value.authority_scope_refs,
      fallback.authority_scope_refs,
    ),
    access_lease_ref: stringValue(value.access_lease_ref, fallback.access_lease_ref),
    log_lease_ref: stringValue(value.log_lease_ref, fallback.log_lease_ref),
    archive_ref: stringValue(value.archive_ref, fallback.archive_ref),
    restore_ref: stringValue(value.restore_ref, fallback.restore_ref),
    session_rail: sessionRail.length > 0 ? sessionRail : fallback.session_rail,
    detail_tabs: detailTabs.length > 0 ? detailTabs : fallback.detail_tabs,
    right_inspector_panels:
      rightPanels.length > 0 ? rightPanels : fallback.right_inspector_panels,
    bottom_inspector_panels:
      bottomPanels.length > 0 ? bottomPanels : fallback.bottom_inspector_panels,
    ports_services:
      portsServices.length > 0 ? portsServices : fallback.ports_services,
    tasks: tasks.length > 0 ? tasks : fallback.tasks,
    terminal_events:
      terminalEvents.length > 0 ? terminalEvents : fallback.terminal_events,
    activity_signals:
      activitySignals.length > 0 ? activitySignals : fallback.activity_signals,
    access_log_leases:
      accessLogLeases.length > 0 ? accessLogLeases : fallback.access_log_leases,
    environment_lifecycle_steps:
      environmentLifecycleSteps.length > 0
        ? environmentLifecycleSteps
        : fallback.environment_lifecycle_steps,
    changed_file_groups:
      changedFileGroups.length > 0
        ? changedFileGroups
        : fallback.changed_file_groups,
    latest_receipt_refs: stringList(
      value.latest_receipt_refs,
      fallback.latest_receipt_refs,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function loadHypervisorSessionOperationsProjection(
  options: LoadSessionOperationsProjectionOptions = {},
): Promise<HypervisorSessionOperationsProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorSessionOperationsDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor session operations projection");
  }
  const query = new URLSearchParams();
  if (options.projectId) {
    query.set("project_id", options.projectId);
  }
  if (options.sessionRef) {
    query.set("session_ref", options.sessionRef);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH}${suffix}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Session operations projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorSessionOperationsProjection(value, {
    source: options.source ?? "daemon-session-operations-projection",
  });
}

export function buildHypervisorSessionOperationProposal(
  projection: HypervisorSessionOperationsProjection,
  operationKind: HypervisorSessionOperationKind,
  options: {
    targetRef?: string;
    source?: HypervisorSessionOperationProposal["source"];
  } = {},
): HypervisorSessionOperationProposal {
  const targetRef = sessionOperationTargetRef(
    projection,
    operationKind,
    options.targetRef,
  );
  const targetSegment = proposalRefSegment(targetRef);
  return {
    schema_version: "ioi.hypervisor.session_operation_proposal.v1",
    proposal_ref: `session-operation:${operationKind}/${targetSegment}`,
    source: options.source ?? "fixture",
    project_ref: projection.project_ref,
    session_ref: projection.selected_session_ref,
    environment_ref: projection.environment_ref,
    provider_candidate_ref: projection.provider_candidate_ref,
    operation_kind: operationKind,
    target_ref: targetRef,
    admission_state: sessionOperationAdmissionState(operationKind),
    wallet_lease_ref: `lease:wallet/session/${proposalRefSegment(
      projection.selected_session_ref,
    )}/${operationKind}`,
    required_scope_refs: sessionOperationRequiredScopes(projection, operationKind),
    agentgres_operation_ref: `agentgres://operation/session/${proposalRefSegment(
      projection.selected_session_ref,
    )}/${operationKind}`,
    receipt_ref: `receipt://session/${proposalRefSegment(
      projection.selected_session_ref,
    )}/${operationKind}`,
    state_root_ref: `agentgres://state-root/session/${proposalRefSegment(
      projection.selected_session_ref,
    )}`,
    archive_ref: projection.archive_ref,
    restore_ref: projection.restore_ref,
    custody_invariant:
      "Session operations are proposals until wallet.network grants any required lease and Agentgres admits lifecycle, lease, task, terminal, archive, restore, receipt, and state-root refs.",
  };
}

export function normalizeHypervisorSessionOperationProposal(
  snapshot: unknown,
  options: NormalizeSessionOperationProposalOptions = {},
): HypervisorSessionOperationProposal {
  const projection =
    options.projection ?? HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  const fallback = buildHypervisorSessionOperationProposal(
    projection,
    options.operationKind ?? "request_access_lease",
    {
      targetRef: options.targetRef,
      source: options.source ?? "daemon-session-operation-proposal",
    },
  );
  const value = objectRecord(snapshot);
  return {
    schema_version: "ioi.hypervisor.session_operation_proposal.v1",
    proposal_ref: stringValue(value.proposal_ref, fallback.proposal_ref),
    source: enumValue(value.source, fallback.source, [
      "daemon-session-operation-proposal",
      "fixture",
      "unverified",
    ]),
    project_ref: stringValue(value.project_ref, fallback.project_ref),
    session_ref: stringValue(value.session_ref, fallback.session_ref),
    environment_ref: stringValue(value.environment_ref, fallback.environment_ref),
    provider_candidate_ref: stringValue(
      value.provider_candidate_ref,
      fallback.provider_candidate_ref,
    ),
    operation_kind: sessionOperationKindValue(
      value.operation_kind,
      fallback.operation_kind,
    ),
    target_ref: stringValue(value.target_ref, fallback.target_ref),
    admission_state: enumValue(value.admission_state, fallback.admission_state, [
      "requires_wallet_lease",
      "ready_for_daemon_admission",
      "blocked",
    ]),
    wallet_lease_ref: stringValue(value.wallet_lease_ref, fallback.wallet_lease_ref),
    required_scope_refs: stringList(
      value.required_scope_refs,
      fallback.required_scope_refs,
    ),
    agentgres_operation_ref: stringValue(
      value.agentgres_operation_ref,
      fallback.agentgres_operation_ref,
    ),
    receipt_ref: stringValue(value.receipt_ref, fallback.receipt_ref),
    state_root_ref: stringValue(value.state_root_ref, fallback.state_root_ref),
    archive_ref: stringValue(value.archive_ref, fallback.archive_ref),
    restore_ref: stringValue(value.restore_ref, fallback.restore_ref),
    custody_invariant: stringValue(
      value.custody_invariant,
      fallback.custody_invariant,
    ),
  };
}

export async function proposeHypervisorSessionOperation(
  options: ProposeSessionOperationOptions,
): Promise<HypervisorSessionOperationProposal> {
  const endpoint =
    options.endpoint ?? readHypervisorSessionOperationsDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor session operation proposal");
  }
  const targetRef = sessionOperationTargetRef(
    options.projection,
    options.operationKind,
    options.targetRef,
  );
  const response = await fetchImpl(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        project_ref: options.projection.project_ref,
        session_ref: options.projection.selected_session_ref,
        environment_ref: options.projection.environment_ref,
        provider_candidate_ref: options.projection.provider_candidate_ref,
        operation_kind: options.operationKind,
        target_ref: targetRef,
        authority_scope_refs: sessionOperationRequiredScopes(
          options.projection,
          options.operationKind,
        ),
        access_lease_ref: options.projection.access_lease_ref,
        log_lease_ref: options.projection.log_lease_ref,
        archive_ref: options.projection.archive_ref,
        restore_ref: options.projection.restore_ref,
      }),
    },
  );
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Session operation proposal request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorSessionOperationProposal(value, {
    projection: options.projection,
    operationKind: options.operationKind,
    targetRef,
    source: options.source ?? "daemon-session-operation-proposal",
  });
}
