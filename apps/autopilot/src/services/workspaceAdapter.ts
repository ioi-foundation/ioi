import { invoke } from "@tauri-apps/api/core";
import type {
  WorkspaceAdapter,
  WorkspaceCommitResult,
  WorkspaceDeleteResult,
  WorkspaceDiffDocument,
  WorkspaceFileDocument,
  WorkspaceLanguageCodeAction,
  WorkspaceLanguageLocation,
  WorkspaceLanguageServiceSnapshot,
  WorkspaceNode,
  WorkspacePathMutationResult,
  WorkspacePathStat,
  WorkspaceSearchResult,
  WorkspaceSnapshot,
  WorkspaceSourceControlState,
  WorkspaceTerminalReadResult,
  WorkspaceTerminalSession,
} from "@ioi/workspace-substrate";

type SnapshotCacheEntry = {
  snapshot: WorkspaceSnapshot;
  cachedAtMs: number;
};

const workspaceSnapshotCache = new Map<string, SnapshotCacheEntry>();
const workspaceSnapshotInflight = new Map<string, Promise<WorkspaceSnapshot>>();

async function loadWorkspaceSnapshot(root: string): Promise<WorkspaceSnapshot> {
  const cached = workspaceSnapshotCache.get(root);
  if (cached) {
    workspaceSnapshotCache.delete(root);
    return cached.snapshot;
  }

  const inFlight = workspaceSnapshotInflight.get(root);
  if (inFlight) {
    return inFlight;
  }

  const request = invoke<WorkspaceSnapshot>("chat_workspace_inspect", { root })
    .then((snapshot) => {
      workspaceSnapshotInflight.delete(root);
      return snapshot;
    })
    .catch((error) => {
      workspaceSnapshotInflight.delete(root);
      throw error;
    });

  workspaceSnapshotInflight.set(root, request);
  return request;
}

function cacheWorkspaceSnapshot(root: string, snapshot: WorkspaceSnapshot): WorkspaceSnapshot {
  workspaceSnapshotCache.set(root, {
    snapshot,
    cachedAtMs: Date.now(),
  });
  return snapshot;
}

export const tauriWorkspaceAdapter: WorkspaceAdapter = {
  inspectWorkspace(root) {
    return loadWorkspaceSnapshot(root);
  },
  listDirectory(root, path) {
    return invoke<WorkspaceNode[]>("chat_workspace_list_directory", { root, path });
  },
  readFile(root, path) {
    return invoke<WorkspaceFileDocument>("chat_workspace_read_file", { root, path });
  },
  getLanguageServiceSnapshot(root, path, content) {
    return invoke<WorkspaceLanguageServiceSnapshot>("chat_workspace_lsp_snapshot", {
      root,
      path,
      content,
    });
  },
  getLanguageDefinition(root, path, line, column, content) {
    return invoke<WorkspaceLanguageLocation[]>("chat_workspace_lsp_definition", {
      root,
      path,
      line,
      column,
      content,
    });
  },
  getLanguageReferences(root, path, line, column, content) {
    return invoke<WorkspaceLanguageLocation[]>("chat_workspace_lsp_references", {
      root,
      path,
      line,
      column,
      content,
    });
  },
  getLanguageCodeActions(root, path, line, column, endLine, endColumn, content) {
    return invoke<WorkspaceLanguageCodeAction[]>("chat_workspace_lsp_code_actions", {
      root,
      path,
      line,
      column,
      endLine,
      endColumn,
      content,
    });
  },
  writeFile(root, path, content) {
    return invoke<WorkspaceFileDocument>("chat_workspace_write_file", {
      root,
      path,
      content,
    });
  },
  createFile(root, path) {
    return invoke<WorkspaceFileDocument>("chat_workspace_create_file", { root, path });
  },
  createDirectory(root, path) {
    return invoke<WorkspacePathMutationResult>("chat_workspace_create_directory", {
      root,
      path,
    });
  },
  statPath(root, path) {
    return invoke<WorkspacePathStat>("chat_workspace_stat_path", {
      root,
      path,
    });
  },
  renamePath(root, from, to) {
    return invoke<WorkspacePathMutationResult>("chat_workspace_rename_path", {
      root,
      from,
      to,
    });
  },
  deletePath(root, path) {
    return invoke<WorkspaceDeleteResult>("chat_workspace_delete_path", { root, path });
  },
  searchText(root, query) {
    return invoke<WorkspaceSearchResult>("chat_workspace_search_text", { root, query });
  },
  getSourceControlState(root) {
    return invoke<WorkspaceSourceControlState>("chat_workspace_git_status", { root });
  },
  getDiff(root, path, staged) {
    return invoke<WorkspaceDiffDocument>("chat_workspace_git_diff", { root, path, staged });
  },
  commitChanges(root, message) {
    return invoke<WorkspaceCommitResult>("chat_workspace_git_commit", {
      root,
      headline: message.headline,
      body: message.body ?? null,
    });
  },
  stagePaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("chat_workspace_git_stage", { root, paths });
  },
  unstagePaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("chat_workspace_git_unstage", { root, paths });
  },
  discardPaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("chat_workspace_git_discard", { root, paths });
  },
  createTerminalSession(root, cols, rows) {
    return invoke<WorkspaceTerminalSession>("chat_workspace_terminal_create", {
      root,
      cols,
      rows,
    });
  },
  readTerminalSession(sessionId, cursor) {
    return invoke<WorkspaceTerminalReadResult>("chat_workspace_terminal_read", {
      sessionId,
      cursor,
    });
  },
  writeTerminalSession(sessionId, data) {
    return invoke<void>("chat_workspace_terminal_write", { sessionId, data });
  },
  resizeTerminalSession(sessionId, cols, rows) {
    return invoke<void>("chat_workspace_terminal_resize", {
      sessionId,
      cols,
      rows,
    });
  },
  closeTerminalSession(sessionId) {
    return invoke<void>("chat_workspace_terminal_close", { sessionId });
  },
};

export function peekCachedWorkspaceSnapshot(root: string): WorkspaceSnapshot | null {
  const cached = workspaceSnapshotCache.get(root);
  if (cached && Date.now() - cached.cachedAtMs < 30_000) {
    return cached.snapshot;
  }
  return null;
}

export async function warmWorkspaceRoot(root: string): Promise<WorkspaceSnapshot> {
  const cached = peekCachedWorkspaceSnapshot(root);
  if (cached) {
    return cached;
  }

  const inFlight = workspaceSnapshotInflight.get(root);
  if (inFlight) {
    return inFlight;
  }

  const snapshot = await invoke<WorkspaceSnapshot>("chat_workspace_inspect", {
    root,
  });
  return cacheWorkspaceSnapshot(root, snapshot);
}

export async function prewarmWorkspaceRoot(root: string): Promise<void> {
  await warmWorkspaceRoot(root);
}
