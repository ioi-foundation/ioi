import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SessionServerSnapshot } from "../../../types";

export type ChatServerModeStatus = "idle" | "loading" | "ready" | "error";

interface UseChatServerModeOptions {
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

export function useChatServerMode({
  enabled,
  sessionId,
  workspaceRoot,
}: UseChatServerModeOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [snapshot, setSnapshot] = useState<SessionServerSnapshot | null>(null);
  const [status, setStatus] = useState<ChatServerModeStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);

    try {
      const nextSnapshot = await invoke<SessionServerSnapshot>(
        "get_session_server_snapshot",
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

    void invoke<SessionServerSnapshot>("get_session_server_snapshot", query)
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

    const projectionPromise = listen("session-projection-updated", () => {
      if (cancelled) {
        return;
      }
      void refresh().catch(() => {
        // Keep the last good server snapshot visible if a refresh fails.
      });
    });

    const localEnginePromise = listen("local-engine-updated", () => {
      if (cancelled) {
        return;
      }
      void refresh().catch(() => {
        // Keep the last good server snapshot visible if a refresh fails.
      });
    });

    return () => {
      cancelled = true;
      void projectionPromise.then((unlisten) => unlisten());
      void localEnginePromise.then((unlisten) => unlisten());
    };
  }, [enabled, query, refresh]);

  return {
    snapshot,
    status,
    error,
    refresh,
  };
}
