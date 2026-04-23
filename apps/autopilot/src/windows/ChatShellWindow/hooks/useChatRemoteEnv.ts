import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SessionRemoteEnvSnapshot } from "../../../types";

export type ChatRemoteEnvStatus = "idle" | "loading" | "ready" | "error";

interface UseChatRemoteEnvOptions {
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

export function useChatRemoteEnv({
  enabled,
  sessionId,
  workspaceRoot,
}: UseChatRemoteEnvOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [snapshot, setSnapshot] = useState<SessionRemoteEnvSnapshot | null>(null);
  const [status, setStatus] = useState<ChatRemoteEnvStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextSnapshot = await invoke<SessionRemoteEnvSnapshot>(
        "get_session_remote_env_snapshot",
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

    void invoke<SessionRemoteEnvSnapshot>("get_session_remote_env_snapshot", query)
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
        // keep the last good snapshot visible if a mid-session refresh fails
      });
    });

    const localEnginePromise = listen("local-engine-updated", () => {
      if (cancelled) {
        return;
      }
      void refresh().catch(() => {
        // keep the last good snapshot visible if a local-engine refresh fails
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
