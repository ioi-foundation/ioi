import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlEntry,
  WorkspaceSourceControlState,
} from "@ioi/workspace-substrate";
import { tauriWorkspaceAdapter } from "../../../services/workspaceAdapter";

export type ChatSourceControlStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error"
  | "mutating"
  | "committing";

interface UseChatSourceControlOptions {
  enabled: boolean;
  workspaceRoot?: string | null;
}

function normalizeRoot(workspaceRoot?: string | null) {
  const value = workspaceRoot?.trim() || "";
  return value.length > 0 ? value : null;
}

function stagedPaths(entries: WorkspaceSourceControlEntry[]) {
  return entries
    .filter((entry) => entry.x !== " " && entry.x !== "?")
    .map((entry) => entry.path);
}

function discardablePaths(entries: WorkspaceSourceControlEntry[]) {
  return entries
    .filter((entry) => entry.y !== " " || entry.x === "?")
    .map((entry) => entry.path);
}

export function useChatSourceControl({
  enabled,
  workspaceRoot,
}: UseChatSourceControlOptions) {
  const root = useMemo(() => normalizeRoot(workspaceRoot), [workspaceRoot]);
  const [state, setState] = useState<WorkspaceSourceControlState | null>(null);
  const [status, setStatus] = useState<ChatSourceControlStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [lastCommitReceipt, setLastCommitReceipt] =
    useState<WorkspaceCommitResult | null>(null);

  const refresh = useCallback(async () => {
    if (!root) {
      setState(null);
      setStatus("idle");
      setError(null);
      return null;
    }

    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextState = await tauriWorkspaceAdapter.getSourceControlState(root);
      setState(nextState);
      setStatus("ready");
      return nextState;
    } catch (nextError) {
      const message =
        nextError instanceof Error ? nextError.message : String(nextError ?? "");
      setState(null);
      setStatus("error");
      setError(message);
      throw nextError;
    }
  }, [root]);

  useEffect(() => {
    setLastCommitReceipt(null);
  }, [root]);

  useEffect(() => {
    if (!enabled || !root) {
      setState(null);
      setStatus(enabled ? "idle" : "idle");
      setError(null);
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void tauriWorkspaceAdapter
      .getSourceControlState(root)
      .then((nextState) => {
        if (cancelled) {
          return;
        }
        setState(nextState);
        setStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) {
          return;
        }
        setState(null);
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
        // Keep the last good source control state visible if refresh fails.
      });
    });

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled, refresh, root]);

  const mutate = useCallback(
    async (
      action: (workspaceRoot: string, paths: string[]) => Promise<WorkspaceSourceControlState>,
      paths: string[],
    ) => {
      if (!root || paths.length === 0) {
        return state;
      }

      setStatus("mutating");
      setError(null);
      try {
        const nextState = await action(root, paths);
        setState(nextState);
        setStatus("ready");
        return nextState;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setStatus("error");
        setError(message);
        throw nextError;
      }
    },
    [root, state],
  );

  const stagePath = useCallback(
    async (path: string) => mutate(tauriWorkspaceAdapter.stagePaths, [path]),
    [mutate],
  );

  const stageAll = useCallback(async () => {
    const paths = state?.entries.map((entry) => entry.path) ?? [];
    return mutate(tauriWorkspaceAdapter.stagePaths, paths);
  }, [mutate, state?.entries]);

  const unstagePath = useCallback(
    async (path: string) => mutate(tauriWorkspaceAdapter.unstagePaths, [path]),
    [mutate],
  );

  const unstageAll = useCallback(async () => {
    const paths = stagedPaths(state?.entries ?? []);
    return mutate(tauriWorkspaceAdapter.unstagePaths, paths);
  }, [mutate, state?.entries]);

  const discardPath = useCallback(
    async (path: string) => mutate(tauriWorkspaceAdapter.discardPaths, [path]),
    [mutate],
  );

  const discardAllWorking = useCallback(async () => {
    const paths = discardablePaths(state?.entries ?? []);
    return mutate(tauriWorkspaceAdapter.discardPaths, paths);
  }, [mutate, state?.entries]);

  const commit = useCallback(
    async (headline: string, body?: string | null) => {
      if (!root) {
        return null;
      }

      setStatus("committing");
      setError(null);
      try {
        const receipt = await tauriWorkspaceAdapter.commitChanges(root, {
          headline,
          body: body ?? null,
        });
        setState(receipt.state);
        setLastCommitReceipt(receipt);
        setStatus("ready");
        return receipt;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setStatus("error");
        setError(message);
        throw nextError;
      }
    },
    [root],
  );

  return {
    state,
    status,
    error,
    lastCommitReceipt,
    refresh,
    stagePath,
    stageAll,
    unstagePath,
    unstageAll,
    discardPath,
    discardAllWorking,
    commit,
  };
}
