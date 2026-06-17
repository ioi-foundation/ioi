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
  // Host command ids retain their legacy names until the host bridge protocol
  // itself is renamed; this facade is the active Hypervisor adapter boundary.
  return invoke<WorkspaceEditorAdapterSessionInfo>(
    "ensure_workspace_ide_session",
    { root },
  );
}

export async function stopWorkspaceEditorAdapterSession(): Promise<void> {
  await invoke("stop_workspace_ide_session");
}

export async function writeWorkspaceEditorAdapterBridgeState(
  root: string,
  state: Record<string, unknown>,
): Promise<void> {
  await invoke("write_workspace_ide_bridge_state", { root, state });
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
    "enqueue_workspace_ide_bridge_command",
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
    "take_workspace_ide_bridge_requests",
    {
      root,
    },
  );
}
