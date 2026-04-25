import { invoke } from "@tauri-apps/api/core";

export interface WorkspaceDirectWebviewBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface WorkspaceDirectWebviewReadyEvent {
  surfaceId: string;
  url: string;
  label: string;
  mode: string;
  parentWindowLabel: string;
  bounds: WorkspaceDirectWebviewBounds;
  screenBounds?: WorkspaceDirectWebviewBounds | null;
}

export interface WorkspaceDirectWebviewState {
  surfaceId: string;
  label: string;
  parentWindowLabel: string;
  url: string;
  mode: string;
  bounds: WorkspaceDirectWebviewBounds;
  screenBounds?: WorkspaceDirectWebviewBounds | null;
  createdAtMs: number;
  showCount: number;
  reuseCount: number;
  hideCount: number;
  boundsUpdateCount: number;
}

export interface WorkspaceDirectWebviewShowResult {
  state: WorkspaceDirectWebviewState;
}

export async function showWorkspaceDirectWebview(params: {
  surfaceId: string;
  parentWindowLabel: string;
  url: string;
  bounds: WorkspaceDirectWebviewBounds;
  screenBounds?: WorkspaceDirectWebviewBounds | null;
  visible?: boolean;
}): Promise<WorkspaceDirectWebviewShowResult> {
  return invoke("workspace_direct_webview_show", params);
}

export async function updateWorkspaceDirectWebviewBounds(params: {
  surfaceId: string;
  bounds: WorkspaceDirectWebviewBounds;
  screenBounds?: WorkspaceDirectWebviewBounds | null;
}): Promise<void> {
  await invoke("workspace_direct_webview_update_bounds", params);
}

export async function focusWorkspaceDirectWebview(surfaceId: string): Promise<void> {
  await invoke("workspace_direct_webview_focus", { surfaceId });
}

export async function getWorkspaceDirectWebviewState(
  surfaceId: string,
): Promise<WorkspaceDirectWebviewState | null> {
  return invoke("workspace_direct_webview_get_state", { surfaceId });
}

export async function openWorkspaceDirectWebviewDevtools(
  surfaceId: string,
): Promise<WorkspaceDirectWebviewState> {
  return invoke("workspace_direct_webview_open_devtools", { surfaceId });
}

export async function hideWorkspaceDirectWebview(surfaceId: string): Promise<void> {
  await invoke("workspace_direct_webview_hide", { surfaceId });
}

export async function destroyWorkspaceDirectWebview(surfaceId: string): Promise<void> {
  await invoke("workspace_direct_webview_destroy", { surfaceId });
}
