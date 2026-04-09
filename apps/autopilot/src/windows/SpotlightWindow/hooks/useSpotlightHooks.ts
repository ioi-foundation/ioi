import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SessionHookSnapshot } from "../../../types";

export type SpotlightHooksStatus = "idle" | "loading" | "ready" | "error";

interface UseSpotlightHooksOptions {
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

export function useSpotlightHooks({
  enabled,
  sessionId,
  workspaceRoot,
}: UseSpotlightHooksOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [snapshot, setSnapshot] = useState<SessionHookSnapshot | null>(null);
  const [status, setStatus] = useState<SpotlightHooksStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextSnapshot = await invoke<SessionHookSnapshot>(
        "get_session_hook_snapshot",
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

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void invoke<SessionHookSnapshot>("get_session_hook_snapshot", query)
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
        // keep the last good snapshot visible if a mid-session refresh fails
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
  };
}
