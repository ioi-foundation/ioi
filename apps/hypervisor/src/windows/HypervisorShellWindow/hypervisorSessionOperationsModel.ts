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

export interface HypervisorSessionOperationsProjection {
  schema_version: "ioi.hypervisor.session_operations_projection.v1";
  projection_id: string;
  source: "daemon-session-operations-projection" | "fixture" | "unverified";
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

export const HYPERVISOR_SESSION_OPERATIONS_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_SESSION_OPERATIONS_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH =
  "/v1/hypervisor/session-operations";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
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
    source: "fixture",
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
    HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.ports_services[0]!;
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
  return {
    schema_version: "ioi.hypervisor.session_operations_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-session-operations-projection",
    selected_session_ref: stringValue(
      value.selected_session_ref,
      fallback.selected_session_ref,
    ),
    lifecycle_state: enumValue(value.lifecycle_state, fallback.lifecycle_state, [
      "active",
      "waiting_for_approval",
      "blocked",
      "idle",
      "archived",
    ]),
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
