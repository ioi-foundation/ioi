import type { WorkspacePersistedState, WorkspaceSnapshot } from "@ioi/workspace-substrate";

export type WorkspaceOperatorSurface =
  | "chat"
  | "workflows"
  | "runs"
  | "artifacts"
  | "policy"
  | "connections";

export interface WorkspaceShellPersistedState {
  dockSurface: WorkspaceOperatorSurface;
  shellState: WorkspacePersistedState | null;
  lastActivePath: string | null;
  snapshot: WorkspaceSnapshot | null;
}

const STORAGE_PREFIX = "autopilot.workspace-shell.v1";

function storageAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function keyForRoot(rootPath: string): string {
  return `${STORAGE_PREFIX}:${rootPath}`;
}

export function loadWorkspaceShellState(
  rootPath: string,
): WorkspaceShellPersistedState | null {
  if (!storageAvailable()) {
    return null;
  }

  try {
    const raw = window.localStorage.getItem(keyForRoot(rootPath));
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as Partial<WorkspaceShellPersistedState>;
    return {
      dockSurface: parsed.dockSurface ?? "chat",
      shellState: parsed.shellState ?? null,
      lastActivePath:
        typeof parsed.lastActivePath === "string" ? parsed.lastActivePath : null,
      snapshot: parsed.snapshot ?? null,
    };
  } catch {
    window.localStorage.removeItem(keyForRoot(rootPath));
    return null;
  }
}

export function persistWorkspaceShellState(
  rootPath: string,
  state: WorkspaceShellPersistedState,
): void {
  if (!storageAvailable()) {
    return;
  }

  window.localStorage.setItem(keyForRoot(rootPath), JSON.stringify(state));
}
