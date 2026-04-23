import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SessionPluginSnapshot } from "../../../types";

export type ChatPluginsStatus = "idle" | "loading" | "ready" | "error";

interface UseChatPluginsOptions {
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

export function useChatPlugins({
  enabled,
  sessionId,
  workspaceRoot,
}: UseChatPluginsOptions) {
  const query = useMemo(
    () => buildQuery(sessionId, workspaceRoot),
    [sessionId, workspaceRoot],
  );
  const [snapshot, setSnapshot] = useState<SessionPluginSnapshot | null>(null);
  const [status, setStatus] = useState<ChatPluginsStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const runSnapshotCommand = useCallback(
    async (command: string, extraArgs?: Record<string, unknown>) => {
      setStatus("loading");
      setError(null);
      try {
        const nextSnapshot = await invoke<SessionPluginSnapshot>(command, {
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
      const nextSnapshot = await invoke<SessionPluginSnapshot>(
        "get_session_plugin_snapshot",
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

  const trustPlugin = useCallback(
    async (pluginId: string, enableAfterTrust = true) =>
      runSnapshotCommand("trust_session_plugin", { pluginId, enableAfterTrust }),
    [runSnapshotCommand],
  );

  const setPluginEnabled = useCallback(
    async (pluginId: string, enabled: boolean) =>
      runSnapshotCommand("set_session_plugin_enabled", { pluginId, enabled }),
    [runSnapshotCommand],
  );

  const reloadPlugin = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("reload_session_plugin", { pluginId }),
    [runSnapshotCommand],
  );

  const refreshPluginCatalog = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("refresh_session_plugin_catalog", { pluginId }),
    [runSnapshotCommand],
  );

  const revokePluginTrust = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("revoke_session_plugin_trust", { pluginId }),
    [runSnapshotCommand],
  );

  const installPluginPackage = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("install_session_plugin_package", { pluginId }),
    [runSnapshotCommand],
  );

  const updatePluginPackage = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("update_session_plugin_package", { pluginId }),
    [runSnapshotCommand],
  );

  const removePluginPackage = useCallback(
    async (pluginId: string) =>
      runSnapshotCommand("remove_session_plugin_package", { pluginId }),
    [runSnapshotCommand],
  );

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setStatus("loading");
    setError(null);

    void invoke<SessionPluginSnapshot>("get_session_plugin_snapshot", query)
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

    const unlistenPromises = [
      listen("session-projection-updated", () => {
        if (cancelled) {
          return;
        }
        void refresh().catch(() => {
          // keep the last good snapshot visible if a mid-session refresh fails
        });
      }),
      listen("local-engine-updated", () => {
        if (cancelled) {
          return;
        }
        void refresh().catch(() => {
          // keep the last good snapshot visible if a runtime-side refresh fails
        });
      }),
    ];

    return () => {
      cancelled = true;
      for (const promise of unlistenPromises) {
        void promise.then((unlisten) => unlisten());
      }
    };
  }, [enabled, query, refresh]);

  return {
    snapshot,
    status,
    error,
    refresh,
    trustPlugin,
    setPluginEnabled,
    reloadPlugin,
    refreshPluginCatalog,
    revokePluginTrust,
    installPluginPackage,
    updatePluginPackage,
    removePluginPackage,
  };
}
