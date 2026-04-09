import { invoke } from "@tauri-apps/api/core";
import type { SessionFileContext } from "../types";

export interface SessionFileContextQuery {
  sessionId?: string | null;
  workspaceRoot?: string | null;
}

export interface SessionFileContextMutation extends SessionFileContextQuery {
  path: string;
}

function withQuery(query: SessionFileContextQuery) {
  return {
    sessionId: query.sessionId ?? null,
    workspaceRoot: query.workspaceRoot ?? null,
  };
}

function withMutation(input: SessionFileContextMutation) {
  return {
    ...withQuery(input),
    path: input.path,
  };
}

type SessionFileContextTransport = Partial<SessionFileContext> & {
  sessionId?: string | null;
  workspaceRoot?: string | null;
  pinnedFiles?: string[] | null;
  recentFiles?: string[] | null;
  explicitIncludes?: string[] | null;
  explicitExcludes?: string[] | null;
  updatedAtMs?: number | null;
};

function normalizePathList(value: string[] | null | undefined) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : [];
}

export function normalizeSessionFileContext(
  value: SessionFileContextTransport | null | undefined,
): SessionFileContext {
  const snapshot = value ?? {};
  return {
    session_id: snapshot.session_id ?? snapshot.sessionId ?? null,
    workspace_root: snapshot.workspace_root ?? snapshot.workspaceRoot ?? ".",
    pinned_files: normalizePathList(snapshot.pinned_files ?? snapshot.pinnedFiles),
    recent_files: normalizePathList(snapshot.recent_files ?? snapshot.recentFiles),
    explicit_includes: normalizePathList(
      snapshot.explicit_includes ?? snapshot.explicitIncludes,
    ),
    explicit_excludes: normalizePathList(
      snapshot.explicit_excludes ?? snapshot.explicitExcludes,
    ),
    updated_at_ms: snapshot.updated_at_ms ?? snapshot.updatedAtMs ?? Date.now(),
  };
}

export function getSessionFileContext(query: SessionFileContextQuery) {
  return invoke<SessionFileContextTransport>(
    "get_session_file_context",
    withQuery(query),
  ).then(normalizeSessionFileContext);
}

export function pinSessionFileContextPath(input: SessionFileContextMutation) {
  return invoke<SessionFileContextTransport>(
    "pin_session_file_context_path",
    withMutation(input),
  ).then(normalizeSessionFileContext);
}

export function includeSessionFileContextPath(input: SessionFileContextMutation) {
  return invoke<SessionFileContextTransport>(
    "include_session_file_context_path",
    withMutation(input),
  ).then(normalizeSessionFileContext);
}

export function excludeSessionFileContextPath(input: SessionFileContextMutation) {
  return invoke<SessionFileContextTransport>(
    "exclude_session_file_context_path",
    withMutation(input),
  ).then(normalizeSessionFileContext);
}

export function removeSessionFileContextPath(input: SessionFileContextMutation) {
  return invoke<SessionFileContextTransport>(
    "remove_session_file_context_path",
    withMutation(input),
  ).then(normalizeSessionFileContext);
}

export function recordSessionFileContextRecentPath(
  input: SessionFileContextMutation,
) {
  return invoke<SessionFileContextTransport>(
    "record_session_file_context_recent_path",
    withMutation(input),
  ).then(normalizeSessionFileContext);
}

export function clearSessionFileContext(query: SessionFileContextQuery) {
  return invoke<SessionFileContextTransport>(
    "clear_session_file_context",
    withQuery(query),
  ).then(normalizeSessionFileContext);
}
