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

export const tauriWorkspaceAdapter: WorkspaceAdapter = {
  inspectWorkspace(root) {
    return invoke<WorkspaceSnapshot>("studio_workspace_inspect", { root });
  },
  listDirectory(root, path) {
    return invoke<WorkspaceNode[]>("studio_workspace_list_directory", { root, path });
  },
  readFile(root, path) {
    return invoke<WorkspaceFileDocument>("studio_workspace_read_file", { root, path });
  },
  getLanguageServiceSnapshot(root, path, content) {
    return invoke<WorkspaceLanguageServiceSnapshot>("studio_workspace_lsp_snapshot", {
      root,
      path,
      content,
    });
  },
  getLanguageDefinition(root, path, line, column, content) {
    return invoke<WorkspaceLanguageLocation[]>("studio_workspace_lsp_definition", {
      root,
      path,
      line,
      column,
      content,
    });
  },
  getLanguageReferences(root, path, line, column, content) {
    return invoke<WorkspaceLanguageLocation[]>("studio_workspace_lsp_references", {
      root,
      path,
      line,
      column,
      content,
    });
  },
  getLanguageCodeActions(root, path, line, column, endLine, endColumn, content) {
    return invoke<WorkspaceLanguageCodeAction[]>("studio_workspace_lsp_code_actions", {
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
    return invoke<WorkspaceFileDocument>("studio_workspace_write_file", {
      root,
      path,
      content,
    });
  },
  createFile(root, path) {
    return invoke<WorkspaceFileDocument>("studio_workspace_create_file", { root, path });
  },
  createDirectory(root, path) {
    return invoke<WorkspacePathMutationResult>("studio_workspace_create_directory", {
      root,
      path,
    });
  },
  statPath(root, path) {
    return invoke<WorkspacePathStat>("studio_workspace_stat_path", {
      root,
      path,
    });
  },
  renamePath(root, from, to) {
    return invoke<WorkspacePathMutationResult>("studio_workspace_rename_path", {
      root,
      from,
      to,
    });
  },
  deletePath(root, path) {
    return invoke<WorkspaceDeleteResult>("studio_workspace_delete_path", { root, path });
  },
  searchText(root, query) {
    return invoke<WorkspaceSearchResult>("studio_workspace_search_text", { root, query });
  },
  getSourceControlState(root) {
    return invoke<WorkspaceSourceControlState>("studio_workspace_git_status", { root });
  },
  getDiff(root, path, staged) {
    return invoke<WorkspaceDiffDocument>("studio_workspace_git_diff", { root, path, staged });
  },
  commitChanges(root, message) {
    return invoke<WorkspaceCommitResult>("studio_workspace_git_commit", {
      root,
      headline: message.headline,
      body: message.body ?? null,
    });
  },
  stagePaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("studio_workspace_git_stage", { root, paths });
  },
  unstagePaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("studio_workspace_git_unstage", { root, paths });
  },
  discardPaths(root, paths) {
    return invoke<WorkspaceSourceControlState>("studio_workspace_git_discard", { root, paths });
  },
  createTerminalSession(root, cols, rows) {
    return invoke<WorkspaceTerminalSession>("studio_workspace_terminal_create", {
      root,
      cols,
      rows,
    });
  },
  readTerminalSession(sessionId, cursor) {
    return invoke<WorkspaceTerminalReadResult>("studio_workspace_terminal_read", {
      sessionId,
      cursor,
    });
  },
  writeTerminalSession(sessionId, data) {
    return invoke<void>("studio_workspace_terminal_write", { sessionId, data });
  },
  resizeTerminalSession(sessionId, cols, rows) {
    return invoke<void>("studio_workspace_terminal_resize", {
      sessionId,
      cols,
      rows,
    });
  },
  closeTerminalSession(sessionId) {
    return invoke<void>("studio_workspace_terminal_close", { sessionId });
  },
};
