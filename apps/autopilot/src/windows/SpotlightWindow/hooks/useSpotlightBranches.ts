import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SessionBranchSnapshot } from "../../../types";

export type SpotlightBranchesStatus = "idle" | "loading" | "ready" | "error";

interface UseSpotlightBranchesOptions {
  enabled: boolean;
  sessionId?: string | null;
  workspaceRoot?: string | null;
}

function buildQuery(sessionId?: string | null, workspaceRoot?: string | null) {
  return {
    sessionId: sessionId ?? null,
    workspaceRoot: workspaceRoot ?? null,
  };
}

export function useSpotlightBranches({
  enabled,
  sessionId,
  workspaceRoot,
}: UseSpotlightBranchesOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [snapshot, setSnapshot] = useState<SessionBranchSnapshot | null>(null);
  const [status, setStatus] = useState<SpotlightBranchesStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const runSnapshotCommand = useCallback(
    async (command: string, extraArgs?: Record<string, unknown>) => {
      setStatus("loading");
      setError(null);
      try {
        const nextSnapshot = await invoke<SessionBranchSnapshot>(command, {
          ...query,
          ...(extraArgs ?? {}),
        });
        setSnapshot(nextSnapshot);
        setStatus("ready");
        return nextSnapshot;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setStatus("error");
        setError(message);
        throw nextError;
      }
    },
    [query],
  );

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextSnapshot = await invoke<SessionBranchSnapshot>(
        "get_session_branch_snapshot",
        query,
      );
      setSnapshot(nextSnapshot);
      setStatus("ready");
      return nextSnapshot;
    } catch (nextError) {
      const message =
        nextError instanceof Error ? nextError.message : String(nextError ?? "");
      setSnapshot(null);
      setStatus("error");
      setError(message);
      throw nextError;
    }
  }, [query]);

  const createWorktree = useCallback(
    async (
      branchName: string,
      options?: {
        startPoint?: string | null;
        worktreeName?: string | null;
      },
    ) =>
      runSnapshotCommand("create_session_worktree", {
        branchName,
        startPoint: options?.startPoint ?? null,
        worktreeName: options?.worktreeName ?? null,
      }),
    [runSnapshotCommand],
  );

  const switchWorktree = useCallback(
    async (targetWorkspaceRoot: string) =>
      runSnapshotCommand("switch_session_worktree", {
        targetWorkspaceRoot,
      }),
    [runSnapshotCommand],
  );

  const removeWorktree = useCallback(
    async (targetWorkspaceRoot: string) =>
      runSnapshotCommand("remove_session_worktree", {
        targetWorkspaceRoot,
      }),
    [runSnapshotCommand],
  );

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void invoke<SessionBranchSnapshot>("get_session_branch_snapshot", query)
      .then((nextSnapshot) => {
        if (cancelled) {
          return;
        }
        setSnapshot(nextSnapshot);
        setStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) {
          return;
        }
        setSnapshot(null);
        setStatus("error");
        setError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });

    const unlistenPromise = listen("session-projection-updated", () => {
      if (cancelled) {
        return;
      }
      void refresh().catch(() => {
        // keep the last good branch snapshot visible if mid-session refresh fails
      });
    });

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled, query, refresh]);

  return {
    snapshot,
    status,
    error,
    refresh,
    createWorktree,
    switchWorktree,
    removeWorktree,
  };
}
