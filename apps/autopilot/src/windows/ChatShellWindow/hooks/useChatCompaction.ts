import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import type {
  SessionCompactionPolicy,
  SessionCompactionSnapshot,
} from "../../../types";

export type ChatCompactionStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error"
  | "compacting";

function defaultCompactionPolicy(): SessionCompactionPolicy {
  return {
    carryPinnedOnly: false,
    preserveChecklistState: true,
    preserveBackgroundTasks: true,
    preserveLatestOutputExcerpt: true,
    preserveGovernanceBlockers: true,
    aggressiveTranscriptPruning: false,
  };
}

export function useChatCompaction(enabled = true) {
  const [snapshot, setSnapshot] = useState<SessionCompactionSnapshot | null>(null);
  const [status, setStatus] = useState<ChatCompactionStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<SessionCompactionPolicy>(
    defaultCompactionPolicy,
  );
  const policyRef = useRef<SessionCompactionPolicy>(defaultCompactionPolicy());

  const fetchSnapshot = useCallback(async (effectivePolicy: SessionCompactionPolicy) => {
    setStatus((current) => (current === "ready" ? "loading" : current));
    setError(null);
    try {
      const nextSnapshot = await invoke<SessionCompactionSnapshot>(
        "get_session_compaction_snapshot",
        { policy: effectivePolicy },
      );
      const nextPolicy = nextSnapshot.policyForActive ?? effectivePolicy;
      policyRef.current = nextPolicy;
      setPolicy(nextPolicy);
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

  const refresh = useCallback(
    async (nextPolicy?: SessionCompactionPolicy) => {
      const effectivePolicy = nextPolicy ?? policyRef.current;
      return fetchSnapshot(effectivePolicy);
    },
    [fetchSnapshot],
  );

  const compact = useCallback(
    async (
      sessionId?: string | null,
      nextPolicy?: SessionCompactionPolicy,
    ) => {
      const effectivePolicy = nextPolicy ?? policyRef.current;
      policyRef.current = effectivePolicy;
      setPolicy(effectivePolicy);
      setStatus("compacting");
      setError(null);
      try {
        const nextSnapshot = await invoke<SessionCompactionSnapshot>(
          "compact_session",
          {
            sessionId: sessionId || null,
            policy: effectivePolicy,
          },
        );
        const nextPolicy = nextSnapshot.policyForActive ?? effectivePolicy;
        policyRef.current = nextPolicy;
        setPolicy(nextPolicy);
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
    [],
  );

  const updatePolicy = useCallback(
    async (nextPolicy: SessionCompactionPolicy) => {
      policyRef.current = nextPolicy;
      setPolicy(nextPolicy);
      return refresh(nextPolicy);
    },
    [refresh],
  );

  const resetPolicy = useCallback(async () => {
    const nextPolicy = defaultCompactionPolicy();
    policyRef.current = nextPolicy;
    setPolicy(nextPolicy);
    return refresh(nextPolicy);
  }, [refresh]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void invoke<SessionCompactionSnapshot>("get_session_compaction_snapshot", {
      policy: policyRef.current,
    })
      .then((nextSnapshot) => {
        if (cancelled) return;
        const nextPolicy =
          nextSnapshot.policyForActive ?? defaultCompactionPolicy();
        policyRef.current = nextPolicy;
        setPolicy(nextPolicy);
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
        // Keep the current compaction snapshot visible if refresh fails.
      });
    });
    const unlistenCompaction = listen("session-compaction-updated", () => {
      if (cancelled) return;
      void refresh().catch(() => {
        // Keep the current compaction snapshot visible if refresh fails.
      });
    });

    return () => {
      cancelled = true;
      void unlistenProjection.then((unlisten) => unlisten());
      void unlistenCompaction.then((unlisten) => unlisten());
    };
  }, [enabled, refresh]);

  return {
    snapshot,
    status,
    error,
    policy,
    refresh,
    compact,
    updatePolicy,
    resetPolicy,
  };
}
