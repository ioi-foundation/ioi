import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  getSessionOperatorRuntime,
  type SessionOperatorRuntime,
} from "../../../services/sessionRuntime";
import type { LocalEngineSnapshot } from "../../../types";

export type ChatLocalEngineStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error";

async function loadSnapshot(
  runtime: SessionOperatorRuntime,
): Promise<LocalEngineSnapshot> {
  return runtime.getLocalEngineSnapshot();
}

export function useChatLocalEngine(enabled = true) {
  const [snapshot, setSnapshot] = useState<LocalEngineSnapshot | null>(null);
  const [status, setStatus] = useState<ChatLocalEngineStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);

    try {
      const nextSnapshot = await loadSnapshot(getSessionOperatorRuntime());
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
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void loadSnapshot(getSessionOperatorRuntime())
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

    const unlistenPromise = listen("local-engine-updated", () => {
      if (cancelled) {
        return;
      }
      void refresh().catch(() => {
        // Keep the last good snapshot visible if a mid-session refresh fails.
      });
    });

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled, refresh]);

  return {
    snapshot,
    status,
    error,
    refresh,
  };
}
