export type HypervisorWorkbenchAdapterId =
  | "embedded_workbench"
  | "external_editor"
  | "vscode_insiders"
  | "cursor"
  | "windsurf"
  | "devin"
  | "vscode_browser"
  | "jetbrains_idea"
  | "jetbrains_goland"
  | "jetbrains_pycharm"
  | "jetbrains_phpstorm"
  | "jetbrains_rubymine"
  | "jetbrains_webstorm"
  | "jetbrains_clion"
  | "jetbrains_rustrover"
  | "jetbrains_rider"
  | "browser_workspace"
  | "terminal_workspace"
  | "remote_vm"
  | "hypervisor_node";

export type HypervisorWorkbenchAdapterLaunchMode =
  | "embedded"
  | "external"
  | "remote_url"
  | "headless";

export type HypervisorWorkbenchAdapterCustodyPosture =
  | "local_projection"
  | "redacted_projection"
  | "provider_session"
  | "headless_session";

export type HypervisorWorkbenchAdapterConnectionKind =
  | "embedded_host"
  | "desktop_bridge"
  | "browser_workspace_url"
  | "terminal_session"
  | "provider_workspace"
  | "hypervisor_node_session";

export type HypervisorWorkbenchAdapterExecutorLane =
  | "embedded_workbench_host"
  | "desktop_bridge"
  | "browser_workspace"
  | "terminal_session"
  | "provider_environment"
  | "hypervisor_node";

export type HypervisorWorkbenchAdapterControlAction =
  | "open_embedded_workbench"
  | "request_desktop_bridge"
  | "open_browser_workspace"
  | "attach_terminal_session"
  | "attach_provider_workspace"
  | "attach_hypervisor_node";

export interface WorkbenchAdapterPreference {
  adapter_id: HypervisorWorkbenchAdapterId;
  label: string;
  description: string;
  launch_mode: HypervisorWorkbenchAdapterLaunchMode;
  target_ref: string;
  custody_posture: HypervisorWorkbenchAdapterCustodyPosture;
  icon_label?: string;
  settings_group?: "editor" | "browser" | "terminal" | "environment";
  settings_visible?: boolean;
  default_for_project?: boolean;
}

export interface WorkbenchAdapterLaunchPlan {
  schema_version: "ioi.hypervisor.workbench_adapter_launch_plan.v1";
  launch_plan_ref: string;
  adapter_ref: string;
  target_ref: string;
  launch_mode: HypervisorWorkbenchAdapterLaunchMode;
  connection_kind: HypervisorWorkbenchAdapterConnectionKind;
  connection_contract_ref: string;
  executor_lane: HypervisorWorkbenchAdapterExecutorLane;
  control_action: HypervisorWorkbenchAdapterControlAction;
  control_channel_ref: string;
  required_access_lease_refs: string[];
  required_authority_scope_refs: string[];
  required_receipt_refs: string[];
  custody_posture: HypervisorWorkbenchAdapterCustodyPosture;
  secret_release_policy: "no_durable_secret_release";
  restore_archive_policy: "not_required" | "required_for_remote_persistence";
  provider_posture_required: boolean;
  requires_daemon_gate: true;
  runtimeTruthSource: "daemon-runtime";
}

export interface WorkbenchAdapterLaunchAdmission {
  schema_version: "ioi.runtime.workbench_adapter_launch_plan_admission.v1";
  admission_id: string;
  launch_plan_ref: string;
  adapter_ref: string;
  target_ref: string;
  launch_mode: HypervisorWorkbenchAdapterLaunchMode;
  connection_kind: HypervisorWorkbenchAdapterConnectionKind;
  connection_contract_ref: string;
  executor_lane: HypervisorWorkbenchAdapterExecutorLane;
  control_action: HypervisorWorkbenchAdapterControlAction;
  control_channel_ref: string;
  required_access_lease_refs: string[];
  required_authority_scope_refs: string[];
  required_receipt_refs: string[];
  custody_posture: HypervisorWorkbenchAdapterCustodyPosture;
  secret_release_policy: "no_durable_secret_release";
  restore_archive_policy: WorkbenchAdapterLaunchPlan["restore_archive_policy"];
  provider_posture_required: boolean;
  provider_posture_ref: string | null;
  wallet_approval_ref: string | null;
  archive_ref: string | null;
  restore_ref: string | null;
  agentgres_operation_refs: string[];
  receipt_refs: string[];
  state_root: string | null;
  adapter_runtime_truth_claimed: false;
  decision: "admitted";
  requiresDaemonGate: true;
  runtimeTruthSource: "daemon-runtime";
  admitted_at: string;
}

export class WorkbenchAdapterLaunchAdmissionError extends Error {
  readonly endpoint: string;
  readonly responseBody: string;
  readonly status: number;

  constructor({
    endpoint,
    responseBody,
    status,
  }: {
    endpoint: string;
    responseBody: string;
    status: number;
  }) {
    super(`Workbench adapter launch admission failed with ${status}`);
    this.name = "WorkbenchAdapterLaunchAdmissionError";
    this.endpoint = endpoint;
    this.responseBody = responseBody;
    this.status = status;
  }
}

export const HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCE_STORAGE_KEY =
  "hypervisor.workbench.adapterPreferenceRef";
export const HYPERVISOR_WORKBENCH_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_WORKBENCH_ADAPTER_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_PATH =
  "/v1/hypervisor/workbench-adapter-launch-plans";

export const HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES: WorkbenchAdapterPreference[] =
  [
    {
      adapter_id: "embedded_workbench",
      label: "VS Code",
      description:
        "Open Hypervisor's packaged Workbench host with VS Code-compatible panes.",
      launch_mode: "embedded",
      target_ref: "adapter-target:vscode-embedded",
      custody_posture: "local_projection",
      icon_label: "VS",
      settings_group: "editor",
      default_for_project: true,
    },
    {
      adapter_id: "external_editor",
      label: "External Editor",
      description:
        "Open this workspace in a compatible desktop editor.",
      launch_mode: "external",
      target_ref: "adapter-target:external-editor",
      custody_posture: "redacted_projection",
      icon_label: "ED",
      settings_group: "editor",
      settings_visible: false,
    },
    {
      adapter_id: "vscode_insiders",
      label: "VS Code Insiders",
      description:
        "Open this workspace in the Insiders desktop editor.",
      launch_mode: "external",
      target_ref: "adapter-target:vscode-insiders",
      custody_posture: "redacted_projection",
      icon_label: "VI",
      settings_group: "editor",
    },
    {
      adapter_id: "cursor",
      label: "Cursor",
      description:
        "Open this workspace in Cursor with limited workspace access.",
      launch_mode: "external",
      target_ref: "adapter-target:cursor",
      custody_posture: "redacted_projection",
      icon_label: "CU",
      settings_group: "editor",
    },
    {
      adapter_id: "windsurf",
      label: "Windsurf",
      description:
        "Open this workspace in Windsurf with limited workspace access.",
      launch_mode: "external",
      target_ref: "adapter-target:windsurf",
      custody_posture: "redacted_projection",
      icon_label: "WS",
      settings_group: "editor",
    },
    {
      adapter_id: "devin",
      label: "Devin",
      description:
        "Open a hosted coding workspace from the browser.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:devin-workspace",
      custody_posture: "provider_session",
      icon_label: "DV",
      settings_group: "browser",
    },
    {
      adapter_id: "vscode_browser",
      label: "VS Code Browser",
      description:
        "Open a browser-hosted VS Code-compatible workspace.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:vscode-browser",
      custody_posture: "provider_session",
      icon_label: "VB",
      settings_group: "browser",
    },
    {
      adapter_id: "jetbrains_idea",
      label: "IntelliJ IDEA Ultimate",
      description:
        "Open this workspace in IntelliJ IDEA.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-idea",
      custody_posture: "redacted_projection",
      icon_label: "IJ",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_goland",
      label: "GoLand",
      description: "Open this workspace in GoLand.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-goland",
      custody_posture: "redacted_projection",
      icon_label: "GO",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_pycharm",
      label: "PyCharm Professional",
      description:
        "Open this workspace in PyCharm.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-pycharm",
      custody_posture: "redacted_projection",
      icon_label: "PY",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_phpstorm",
      label: "PhpStorm",
      description:
        "Open this workspace in PhpStorm.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-phpstorm",
      custody_posture: "redacted_projection",
      icon_label: "PS",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_rubymine",
      label: "RubyMine",
      description:
        "Open this workspace in RubyMine.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-rubymine",
      custody_posture: "redacted_projection",
      icon_label: "RM",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_webstorm",
      label: "WebStorm",
      description:
        "Open this workspace in WebStorm.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-webstorm",
      custody_posture: "redacted_projection",
      icon_label: "WB",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_clion",
      label: "CLion",
      description: "Open this workspace in CLion.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-clion",
      custody_posture: "redacted_projection",
      icon_label: "CL",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_rustrover",
      label: "RustRover",
      description:
        "Open this workspace in RustRover.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-rustrover",
      custody_posture: "redacted_projection",
      icon_label: "RR",
      settings_group: "editor",
    },
    {
      adapter_id: "jetbrains_rider",
      label: "Rider",
      description: "Open this workspace in Rider.",
      launch_mode: "external",
      target_ref: "adapter-target:jetbrains-rider",
      custody_posture: "redacted_projection",
      icon_label: "RD",
      settings_group: "editor",
    },
    {
      adapter_id: "browser_workspace",
      label: "Browser Workspace",
      description:
        "Open a browser-hosted workspace with workspace access prompts.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:browser-workspace",
      custody_posture: "provider_session",
      icon_label: "BR",
      settings_group: "browser",
      settings_visible: false,
    },
    {
      adapter_id: "terminal_workspace",
      label: "Terminal Workspace",
      description:
        "Open shell, tmux, and harness CLI activity in a terminal session.",
      launch_mode: "headless",
      target_ref: "adapter-target:terminal-workspace",
      custody_posture: "headless_session",
      icon_label: ">_",
      settings_group: "terminal",
      settings_visible: false,
    },
    {
      adapter_id: "remote_vm",
      label: "Remote VM Workspace",
      description:
        "Launch or attach a VM or container workspace.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:remote-vm-workspace",
      custody_posture: "provider_session",
      icon_label: "VM",
      settings_group: "environment",
      settings_visible: false,
    },
    {
      adapter_id: "hypervisor_node",
      label: "HypervisorOS Node",
      description:
        "Attach a persistent node session with lifecycle controls.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:hypervisoros-node",
      custody_posture: "provider_session",
      icon_label: "HN",
      settings_group: "environment",
      settings_visible: false,
    },
  ];

export function getWorkbenchAdapterPreferenceRef(
  preference: Pick<WorkbenchAdapterPreference, "adapter_id">,
): string {
  return `workbench-adapter:${preference.adapter_id}`;
}

export const DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF =
  getWorkbenchAdapterPreferenceRef(
    HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
      (preference) => preference.default_for_project,
    ) ?? HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES[0]!,
  );

export function getWorkbenchAdapterPreferenceByRef(
  preferenceRef: string,
): WorkbenchAdapterPreference {
  return (
    HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
      (preference) =>
        getWorkbenchAdapterPreferenceRef(preference) === preferenceRef,
    ) ?? HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES[0]!
  );
}

export function buildWorkbenchAdapterLaunchPlan(
  workbenchAdapter: WorkbenchAdapterPreference,
): WorkbenchAdapterLaunchPlan {
  const adapterRef = getWorkbenchAdapterPreferenceRef(workbenchAdapter);
  const base = {
    schema_version: "ioi.hypervisor.workbench_adapter_launch_plan.v1" as const,
    launch_plan_ref: `${adapterRef}/launch-plan`,
    adapter_ref: adapterRef,
    target_ref: workbenchAdapter.target_ref,
    launch_mode: workbenchAdapter.launch_mode,
    custody_posture: workbenchAdapter.custody_posture,
    secret_release_policy: "no_durable_secret_release" as const,
    requires_daemon_gate: true as const,
    runtimeTruthSource: "daemon-runtime" as const,
  };

  switch (workbenchAdapter.adapter_id) {
    case "external_editor":
    case "vscode_insiders":
    case "cursor":
    case "windsurf":
    case "jetbrains_idea":
    case "jetbrains_goland":
    case "jetbrains_pycharm":
    case "jetbrains_phpstorm":
    case "jetbrains_rubymine":
    case "jetbrains_webstorm":
    case "jetbrains_clion":
    case "jetbrains_rustrover":
    case "jetbrains_rider":
      return {
        ...base,
        connection_kind: "desktop_bridge",
        connection_contract_ref:
          "connection-contract:workbench-adapter/desktop-bridge",
        executor_lane: "desktop_bridge",
        control_action: "request_desktop_bridge",
        control_channel_ref: "control-channel:workbench-adapter/desktop-bridge",
        required_access_lease_refs: ["lease:workbench-adapter/desktop-bridge"],
        required_authority_scope_refs: [
          "scope:workspace.read",
          "scope:workspace.patch",
          "scope:receipt.write",
        ],
        required_receipt_refs: [
          "receipt-policy:workbench-adapter/desktop-bridge",
        ],
        restore_archive_policy: "not_required",
        provider_posture_required: false,
      };
    case "devin":
    case "vscode_browser":
    case "browser_workspace":
      return {
        ...base,
        connection_kind: "browser_workspace_url",
        connection_contract_ref:
          "connection-contract:workbench-adapter/browser-workspace",
        executor_lane: "browser_workspace",
        control_action: "open_browser_workspace",
        control_channel_ref: "control-channel:workbench-adapter/browser-workspace",
        required_access_lease_refs: [
          "lease:workbench-adapter/browser-url",
          "lease:workspace/logs-read",
        ],
        required_authority_scope_refs: [
          "scope:workspace.read",
          "scope:provider.session.attach",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/browser"],
        restore_archive_policy: "required_for_remote_persistence",
        provider_posture_required: true,
      };
    case "terminal_workspace":
      return {
        ...base,
        connection_kind: "terminal_session",
        connection_contract_ref:
          "connection-contract:workbench-adapter/terminal-session",
        executor_lane: "terminal_session",
        control_action: "attach_terminal_session",
        control_channel_ref: "control-channel:workbench-adapter/terminal-session",
        required_access_lease_refs: [
          "lease:workbench-adapter/terminal",
          "lease:workspace/logs-read",
        ],
        required_authority_scope_refs: [
          "scope:shell.exec",
          "scope:workspace.read",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/terminal"],
        restore_archive_policy: "not_required",
        provider_posture_required: false,
      };
    case "remote_vm":
      return {
        ...base,
        connection_kind: "provider_workspace",
        connection_contract_ref:
          "connection-contract:workbench-adapter/provider-workspace",
        executor_lane: "provider_environment",
        control_action: "attach_provider_workspace",
        control_channel_ref: "control-channel:workbench-adapter/provider-workspace",
        required_access_lease_refs: [
          "lease:provider/workspace-access",
          "lease:provider/ports-read",
          "lease:workspace/logs-read",
        ],
        required_authority_scope_refs: [
          "scope:provider.workspace.attach",
          "scope:ports.expose",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/provider"],
        restore_archive_policy: "required_for_remote_persistence",
        provider_posture_required: true,
      };
    case "hypervisor_node":
      return {
        ...base,
        connection_kind: "hypervisor_node_session",
        connection_contract_ref:
          "connection-contract:workbench-adapter/hypervisor-node",
        executor_lane: "hypervisor_node",
        control_action: "attach_hypervisor_node",
        control_channel_ref: "control-channel:workbench-adapter/hypervisor-node",
        required_access_lease_refs: [
          "lease:hypervisor-node/session-access",
          "lease:workspace/logs-read",
        ],
        required_authority_scope_refs: [
          "scope:hypervisor.node.attach",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/node"],
        restore_archive_policy: "required_for_remote_persistence",
        provider_posture_required: true,
      };
    case "embedded_workbench":
    default:
      return {
        ...base,
        connection_kind: "embedded_host",
        connection_contract_ref:
          "connection-contract:workbench-adapter/embedded-host",
        executor_lane: "embedded_workbench_host",
        control_action: "open_embedded_workbench",
        control_channel_ref: "control-channel:workbench-adapter/embedded-host",
        required_access_lease_refs: ["lease:workbench-adapter/embedded-host"],
        required_authority_scope_refs: [
          "scope:workspace.read",
          "scope:workspace.patch",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/embedded"],
        restore_archive_policy: "not_required",
        provider_posture_required: false,
      };
  }
}

type FetchLike = (
  input: string,
  init?: {
    body?: string;
    headers?: Record<string, string>;
    method?: string;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface WorkbenchAdapterLaunchAdmissionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
}

function readHypervisorWorkbenchAdapterDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_WORKBENCH_ADAPTER_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_WORKBENCH_ADAPTER_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_WORKBENCH_ADAPTER_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_WORKBENCH_ADAPTER_DEFAULT_DAEMON_ENDPOINT;
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function normalizeWorkbenchAdapterLaunchAdmission(
  value: unknown,
): WorkbenchAdapterLaunchAdmission {
  const record = objectRecord(value);
  return {
    schema_version: "ioi.runtime.workbench_adapter_launch_plan_admission.v1",
    admission_id: nullableString(record.admission_id) ?? "admission:unknown",
    launch_plan_ref:
      nullableString(record.launch_plan_ref) ?? "workbench-adapter:unknown",
    adapter_ref: nullableString(record.adapter_ref) ?? "workbench-adapter:unknown",
    target_ref: nullableString(record.target_ref) ?? "adapter-target:unknown",
    launch_mode:
      (nullableString(record.launch_mode) as HypervisorWorkbenchAdapterLaunchMode) ??
      "embedded",
    connection_kind:
      (nullableString(
        record.connection_kind,
      ) as HypervisorWorkbenchAdapterConnectionKind) ?? "embedded_host",
    connection_contract_ref:
      nullableString(record.connection_contract_ref) ??
      "connection-contract:workbench-adapter/unknown",
    executor_lane:
      (nullableString(
        record.executor_lane,
      ) as HypervisorWorkbenchAdapterExecutorLane) ?? "embedded_workbench_host",
    control_action:
      (nullableString(
        record.control_action,
      ) as HypervisorWorkbenchAdapterControlAction) ??
      "open_embedded_workbench",
    control_channel_ref:
      nullableString(record.control_channel_ref) ??
      "control-channel:workbench-adapter/unknown",
    required_access_lease_refs: stringArray(record.required_access_lease_refs),
    required_authority_scope_refs: stringArray(
      record.required_authority_scope_refs,
    ),
    required_receipt_refs: stringArray(record.required_receipt_refs),
    custody_posture:
      (nullableString(
        record.custody_posture,
      ) as HypervisorWorkbenchAdapterCustodyPosture) ?? "local_projection",
    secret_release_policy: "no_durable_secret_release",
    restore_archive_policy:
      record.restore_archive_policy === "required_for_remote_persistence"
        ? "required_for_remote_persistence"
        : "not_required",
    provider_posture_required: record.provider_posture_required === true,
    provider_posture_ref: nullableString(record.provider_posture_ref),
    wallet_approval_ref: nullableString(record.wallet_approval_ref),
    archive_ref: nullableString(record.archive_ref),
    restore_ref: nullableString(record.restore_ref),
    agentgres_operation_refs: stringArray(record.agentgres_operation_refs),
    receipt_refs: stringArray(record.receipt_refs),
    state_root: nullableString(record.state_root),
    adapter_runtime_truth_claimed: false,
    decision: "admitted",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: nullableString(record.admitted_at) ?? new Date().toISOString(),
  };
}

export async function requestWorkbenchAdapterLaunchPlanAdmission(
  launchPlan: WorkbenchAdapterLaunchPlan,
  options: WorkbenchAdapterLaunchAdmissionOptions = {},
): Promise<WorkbenchAdapterLaunchAdmission> {
  const endpoint =
    options.endpoint ?? readHypervisorWorkbenchAdapterDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Workbench adapter launch admission");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_WORKBENCH_ADAPTER_LAUNCH_PLAN_ADMISSION_PATH}`;
  const response = await fetchImpl(url, {
    body: JSON.stringify(launchPlan),
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    method: "POST",
  });
  const text = await response.text();
  if (!response.ok) {
    throw new WorkbenchAdapterLaunchAdmissionError({
      endpoint: url,
      responseBody: text,
      status: response.status,
    });
  }
  return normalizeWorkbenchAdapterLaunchAdmission(text ? JSON.parse(text) : {});
}
