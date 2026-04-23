import { invoke } from "@tauri-apps/api/core";

import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";

export interface WorkspaceIdeSessionInfo {
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

export async function ensureWorkspaceIdeSession(
  root: string,
): Promise<WorkspaceIdeSessionInfo> {
  return invoke<WorkspaceIdeSessionInfo>("ensure_workspace_ide_session", { root });
}

export async function stopWorkspaceIdeSession(): Promise<void> {
  await invoke("stop_workspace_ide_session");
}

export async function writeWorkspaceIdeBridgeState(
  root: string,
  state: Record<string, unknown>,
): Promise<void> {
  await invoke("write_workspace_ide_bridge_state", { root, state });
}

export async function takeWorkspaceIdeBridgeRequests(
  root: string,
): Promise<WorkspaceBridgeRouteRequest[]> {
  return invoke<WorkspaceBridgeRouteRequest[]>("take_workspace_ide_bridge_requests", {
    root,
  });
}
