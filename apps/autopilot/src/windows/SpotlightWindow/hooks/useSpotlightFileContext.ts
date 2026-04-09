import { useCallback, useEffect, useMemo, useState } from "react";
import type { WorkspaceNode } from "@ioi/workspace-substrate";
import { tauriWorkspaceAdapter } from "../../../services/workspaceAdapter";
import {
  clearSessionFileContext,
  excludeSessionFileContextPath,
  getSessionFileContext,
  includeSessionFileContextPath,
  pinSessionFileContextPath,
  recordSessionFileContextRecentPath,
  removeSessionFileContextPath,
  type SessionFileContextQuery,
} from "../../../services/sessionFileContext";
import type { SessionFileContext } from "../../../types";

export type SpotlightFileContextStatus = "idle" | "loading" | "ready" | "error";

interface UseSpotlightFileContextOptions {
  enabled: boolean;
  sessionId?: string | null;
  workspaceRoot?: string | null;
}

function normalizePath(path: string | null | undefined) {
  const value = (path ?? "").trim().replace(/\\/g, "/");
  if (!value || value === ".") {
    return ".";
  }
  return value.replace(/^\.\/+/, "");
}

function buildQuery(
  sessionId?: string | null,
  workspaceRoot?: string | null,
): SessionFileContextQuery {
  return {
    sessionId: sessionId ?? null,
    workspaceRoot: workspaceRoot ?? null,
  };
}

export function useSpotlightFileContext({
  enabled,
  sessionId,
  workspaceRoot,
}: UseSpotlightFileContextOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [context, setContext] = useState<SessionFileContext | null>(null);
  const [status, setStatus] = useState<SpotlightFileContextStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [browsePath, setBrowsePath] = useState(".");
  const [browseEntries, setBrowseEntries] = useState<WorkspaceNode[]>([]);
  const [browseStatus, setBrowseStatus] =
    useState<SpotlightFileContextStatus>("idle");
  const [browseError, setBrowseError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    const nextContext = await getSessionFileContext(query);
    setContext(nextContext);
    setStatus("ready");
    setError(null);
    return nextContext;
  }, [query]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void getSessionFileContext(query)
      .then((nextContext) => {
        if (cancelled) {
          return;
        }
        setContext(nextContext);
        setStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) {
          return;
        }
        setContext(null);
        setStatus("error");
        setError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });

    return () => {
      cancelled = true;
    };
  }, [enabled, query]);

  useEffect(() => {
    setBrowsePath(".");
  }, [context?.workspace_root, context?.session_id]);

  useEffect(() => {
    if (!enabled || !context?.workspace_root) {
      return;
    }

    let cancelled = false;
    setBrowseStatus("loading");
    setBrowseError(null);

    void tauriWorkspaceAdapter
      .listDirectory(context.workspace_root, browsePath)
      .then((entries) => {
        if (cancelled) {
          return;
        }
        setBrowseEntries(entries);
        setBrowseStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) {
          return;
        }
        setBrowseEntries([]);
        setBrowseStatus("error");
        setBrowseError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });

    return () => {
      cancelled = true;
    };
  }, [browsePath, context?.workspace_root, enabled]);

  const mutateWithPath = useCallback(
    async (
      path: string,
      mutate: (input: {
        path: string;
        sessionId?: string | null;
        workspaceRoot?: string | null;
      }) => Promise<SessionFileContext>,
    ) => {
      const nextContext = await mutate({
        ...query,
        path,
      });
      setContext(nextContext);
      setStatus("ready");
      setError(null);
      return nextContext;
    },
    [query],
  );

  const rememberPath = useCallback(
    async (path: string) =>
      mutateWithPath(path, recordSessionFileContextRecentPath),
    [mutateWithPath],
  );

  const pinPath = useCallback(
    async (path: string) => mutateWithPath(path, pinSessionFileContextPath),
    [mutateWithPath],
  );

  const includePath = useCallback(
    async (path: string) => mutateWithPath(path, includeSessionFileContextPath),
    [mutateWithPath],
  );

  const excludePath = useCallback(
    async (path: string) => mutateWithPath(path, excludeSessionFileContextPath),
    [mutateWithPath],
  );

  const removePath = useCallback(
    async (path: string) => mutateWithPath(path, removeSessionFileContextPath),
    [mutateWithPath],
  );

  const clear = useCallback(async () => {
    const nextContext = await clearSessionFileContext(query);
    setContext(nextContext);
    setStatus("ready");
    setError(null);
    return nextContext;
  }, [query]);

  const openDirectory = useCallback((path: string) => {
    setBrowsePath(normalizePath(path));
  }, []);

  const browseParent = useCallback(() => {
    setBrowsePath((current) => {
      const normalized = normalizePath(current);
      if (normalized === ".") {
        return ".";
      }
      const segments = normalized.split("/").filter(Boolean);
      segments.pop();
      return segments.length > 0 ? segments.join("/") : ".";
    });
  }, []);

  const fileContextCount = useMemo(() => {
    const snapshot = context;
    if (!snapshot) {
      return 0;
    }
    const pinnedFiles = Array.isArray(snapshot.pinned_files)
      ? snapshot.pinned_files
      : [];
    const recentFiles = Array.isArray(snapshot.recent_files)
      ? snapshot.recent_files
      : [];
    const explicitIncludes = Array.isArray(snapshot.explicit_includes)
      ? snapshot.explicit_includes
      : [];
    const explicitExcludes = Array.isArray(snapshot.explicit_excludes)
      ? snapshot.explicit_excludes
      : [];
    return (
      pinnedFiles.length +
      recentFiles.length +
      explicitIncludes.length +
      explicitExcludes.length
    );
  }, [context]);

  return {
    context,
    status,
    error,
    refresh,
    browsePath,
    browseEntries,
    browseStatus,
    browseError,
    openDirectory,
    browseParent,
    rememberPath,
    pinPath,
    includePath,
    excludePath,
    removePath,
    clear,
    fileContextCount,
  };
}
