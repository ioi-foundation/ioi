export type HypervisorWorkbenchAdapterId =
  | "embedded_workbench"
  | "external_editor"
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

export interface WorkbenchAdapterPreference {
  adapter_id: HypervisorWorkbenchAdapterId;
  label: string;
  description: string;
  launch_mode: HypervisorWorkbenchAdapterLaunchMode;
  target_ref: string;
  custody_posture: HypervisorWorkbenchAdapterCustodyPosture;
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

export const HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCE_STORAGE_KEY =
  "hypervisor.workbench.adapterPreferenceRef";

export const HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES: WorkbenchAdapterPreference[] =
  [
    {
      adapter_id: "embedded_workbench",
      label: "Embedded Workbench",
      description:
        "Use Hypervisor's packaged workbench host for code, IOI panes, and extension-backed project work.",
      launch_mode: "embedded",
      target_ref: "adapter-target:embedded-workbench",
      custody_posture: "local_projection",
      default_for_project: true,
    },
    {
      adapter_id: "external_editor",
      label: "External Editor",
      description:
        "Attach a compatible desktop editor as a governed adapter target without making it runtime truth.",
      launch_mode: "external",
      target_ref: "adapter-target:external-editor",
      custody_posture: "redacted_projection",
    },
    {
      adapter_id: "browser_workspace",
      label: "Browser Workspace",
      description:
        "Open a browser-hosted workspace through daemon-mediated workspace, auth, and receipt policy.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:browser-workspace",
      custody_posture: "provider_session",
    },
    {
      adapter_id: "terminal_workspace",
      label: "Terminal Workspace",
      description:
        "Route shell, tmux, and harness CLI activity through command mediation and session receipts.",
      launch_mode: "headless",
      target_ref: "adapter-target:terminal-workspace",
      custody_posture: "headless_session",
    },
    {
      adapter_id: "remote_vm",
      label: "Remote VM Workspace",
      description:
        "Launch or attach a VM/container workspace with explicit provider, port, service, and restore posture.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:remote-vm-workspace",
      custody_posture: "provider_session",
    },
    {
      adapter_id: "hypervisor_node",
      label: "HypervisorOS Node",
      description:
        "Attach a persistent node session as a governed workbench target with lifecycle and receipt projection.",
      launch_mode: "remote_url",
      target_ref: "adapter-target:hypervisoros-node",
      custody_posture: "provider_session",
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
      return {
        ...base,
        connection_kind: "desktop_bridge",
        connection_contract_ref:
          "connection-contract:workbench-adapter/desktop-bridge",
        required_access_lease_refs: ["lease:workbench-adapter/desktop-bridge"],
        required_authority_scope_refs: [
          "scope:workspace.read",
          "scope:workspace.patch",
          "scope:receipt.write",
        ],
        required_receipt_refs: ["receipt-policy:workbench-adapter/desktop-bridge"],
        restore_archive_policy: "not_required",
        provider_posture_required: false,
      };
    case "browser_workspace":
      return {
        ...base,
        connection_kind: "browser_workspace_url",
        connection_contract_ref:
          "connection-contract:workbench-adapter/browser-workspace",
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
