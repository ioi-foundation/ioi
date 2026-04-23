import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useState } from "react";
import type { TeamMemorySyncSnapshot } from "../../../types";

export type ChatTeamMemoryStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error"
  | "syncing"
  | "forgetting";

export function useChatTeamMemory({
  enabled = true,
  sessionId,
}: {
  enabled?: boolean;
  sessionId?: string | null;
}) {
  const [snapshot, setSnapshot] = useState<TeamMemorySyncSnapshot | null>(null);
  const [status, setStatus] = useState<ChatTeamMemoryStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [includeGovernanceCritical, setIncludeGovernanceCritical] =
    useState(false);

  const refresh = useCallback(async () => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextSnapshot = await invoke<TeamMemorySyncSnapshot>(
        "get_team_memory_snapshot",
        {
          sessionId: sessionId ?? null,
        },
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
  }, [sessionId]);

  const sync = useCallback(async () => {
    setStatus("syncing");
    setError(null);
    try {
      const nextSnapshot = await invoke<TeamMemorySyncSnapshot>("sync_team_memory", {
        sessionId: sessionId ?? null,
        actorLabel: "Chat",
        actorRole: "operator",
        includeGovernanceCritical,
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
  }, [includeGovernanceCritical, sessionId]);

  const forget = useCallback(
    async (entryId: string) => {
      setStatus("forgetting");
      setError(null);
      try {
        const nextSnapshot = await invoke<TeamMemorySyncSnapshot>(
          "forget_team_memory_entry",
          {
            entryId,
            sessionId: sessionId ?? null,
          },
        );
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
    [sessionId],
  );

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void invoke<TeamMemorySyncSnapshot>("get_team_memory_snapshot", {
      sessionId: sessionId ?? null,
    })
      .then((nextSnapshot) => {
        if (cancelled) return;
        setSnapshot(nextSnapshot);
        setStatus("ready");
      })
      .catch((nextError) => {
        if (cancelled) return;
        setSnapshot(null);
        setStatus("error");
        setError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });

    const unlistenProjection = listen("session-projection-updated", () => {
      if (cancelled) return;
      void refresh().catch(() => {
        // Keep the last snapshot visible if refresh fails.
      });
    });
    const unlistenTeamMemory = listen("team-memory-updated", () => {
      if (cancelled) return;
      void refresh().catch(() => {
        // Keep the last snapshot visible if refresh fails.
      });
    });

    return () => {
      cancelled = true;
      void unlistenProjection.then((unlisten) => unlisten());
      void unlistenTeamMemory.then((unlisten) => unlisten());
    };
  }, [enabled, refresh, sessionId]);

  return {
    snapshot,
    status,
    error,
    includeGovernanceCritical,
    setIncludeGovernanceCritical,
    refresh,
    sync,
    forget,
  };
}
