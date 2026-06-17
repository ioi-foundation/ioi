import { invoke } from "./hypervisorHostBridge";

import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";

export interface WorkspaceEditorAdapterSessionInfo {
  rootPath: string;
  workbenchUrl: string;
  version: string;
  processId: number;
  port: number;
  bridgePort: number;
  bridgeUrl: string;
  bridgePath: string;
  logPath: string;
}

export interface WorkspaceEditorAdapterBridgeCommand {
  commandId: string;
  command: string;
  args: unknown[];
  timestampMs: number;
}

export async function ensureWorkspaceEditorAdapterSession(
  root: string,
): Promise<WorkspaceEditorAdapterSessionInfo> {
  return invoke<WorkspaceEditorAdapterSessionInfo>(
    "ensure_workbench_adapter_session",
    { root },
  );
}

export async function stopWorkspaceEditorAdapterSession(): Promise<void> {
  await invoke("stop_workbench_adapter_session");
}

export async function writeWorkspaceEditorAdapterBridgeState(
  root: string,
  state: Record<string, unknown>,
): Promise<void> {
  await invoke("write_workbench_adapter_bridge_state", { root, state });
}

export async function enqueueWorkspaceEditorAdapterBridgeCommand(params: {
  root: string;
  command: string;
  args?: unknown[];
}): Promise<WorkspaceEditorAdapterBridgeCommand> {
  const commandId =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `workspace-command-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return invoke<WorkspaceEditorAdapterBridgeCommand>(
    "enqueue_workbench_adapter_bridge_command",
    {
      root: params.root,
      commandId,
      command: params.command,
      args: params.args ?? [],
    },
  );
}

export async function takeWorkspaceEditorAdapterBridgeRequests(
  root: string,
): Promise<WorkspaceBridgeRouteRequest[]> {
  return invoke<WorkspaceBridgeRouteRequest[]>(
    "take_workbench_adapter_bridge_requests",
    {
      root,
    },
  );
}
