import { useEffect, useMemo, useRef, useState } from "react";

import type { TauriRuntime } from "./TauriRuntime";
import { markWorkspaceMetric } from "./workspacePerf";
import {
  type WorkspaceWorkbenchHost,
  type WorkspaceWorkbenchHostSession,
  type WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";

export type WorkspaceStatus = "idle" | "starting" | "ready" | "error";

export function useWorkspaceWorkbenchSession(params: {
  active: boolean;
  enabled?: boolean;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  runtime: TauriRuntime;
  host: WorkspaceWorkbenchHost;
}) {
  const { active, currentProject, runtime, host } = params;
  const enabled = params.enabled ?? true;
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [session, setSession] = useState<WorkspaceWorkbenchHostSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [surfaceReady, setSurfaceReady] = useState(false);
  const [bootPhase, setBootPhase] = useState("idle");
  const lastHandledRestartNonceRef = useRef(0);

  useEffect(() => {
    setBootPhase(
      enabled
        ? `effect:begin enabled root=${currentProject.rootPath} refresh=${refreshNonce}`
        : "effect:disabled",
    );
    if (import.meta.env.DEV) {
      console.info("[WorkspaceBoot] session bootstrap", {
        visible: active,
        enabled,
        rootPath: currentProject.rootPath,
        refreshNonce,
      });
    }

    if (!enabled) {
      setSession(null);
      setError(null);
      setSurfaceReady(false);
      setBootPhase("effect:disabled-reset");
      return;
    }

    let cancelled = false;
    const forceRestart =
      refreshNonce > 0 && lastHandledRestartNonceRef.current !== refreshNonce;
    if (forceRestart) {
      lastHandledRestartNonceRef.current = refreshNonce;
    }

    setSession(null);
    setError(null);
    setSurfaceReady(false);
    setBootPhase(
      forceRestart ? "effect:reset-for-restart" : "effect:reset-for-start",
    );

    void (async () => {
      try {
        setBootPhase("ensureSession:started");
        const nextSession = await host.ensureSession({
          rootPath: currentProject.rootPath,
          runtime,
          forceRestart,
        });
        if (cancelled) {
          setBootPhase("ensureSession:cancelled-after-resolve");
          return;
        }
        setBootPhase(`ensureSession:resolved root=${nextSession.rootPath}`);
        if (import.meta.env.DEV) {
          console.info("[WorkspaceBoot] session ready", {
            rootPath: nextSession.rootPath,
            mode: host.describeSession(nextSession).metricDetails?.mode ?? "unknown",
          });
        }
        setSession(nextSession);
      } catch (sessionError) {
        if (cancelled) {
          setBootPhase("ensureSession:cancelled-after-error");
          return;
        }
        if (import.meta.env.DEV) {
          console.error("[WorkspaceBoot] session failed", {
            rootPath: currentProject.rootPath,
            error:
              sessionError instanceof Error
                ? sessionError.message
                : String(sessionError),
          });
        }
        setSession(null);
        setError(
          sessionError instanceof Error
            ? sessionError.message
            : "The workspace runtime did not initialize cleanly.",
        );
        setBootPhase(
          `ensureSession:failed ${
            sessionError instanceof Error
              ? sessionError.message
              : String(sessionError)
          }`,
        );
      }
    })();

    return () => {
      cancelled = true;
      setBootPhase("effect:cleanup");
    };
  }, [currentProject.rootPath, enabled, host, refreshNonce, runtime]);

  const surface = useMemo(
    () =>
      session
        ? host.buildSurface(session, {
            projectName: currentProject.name,
            refreshNonce,
          })
        : null,
    [currentProject.name, host, refreshNonce, session],
  );

  useEffect(() => {
    if (!active || !session || error) {
      return;
    }

    const sessionDescriptor = host.describeSession(session);
    markWorkspaceMetric("workspace_view_revealed", {
      projectId: currentProject.id,
      rootPath: currentProject.rootPath,
      mode: sessionDescriptor.metricDetails?.mode ?? "direct",
    });
    markWorkspaceMetric("workbench_mounted", {
      projectId: currentProject.id,
      rootPath: currentProject.rootPath,
      ...sessionDescriptor.metricDetails,
    });
  }, [active, currentProject.id, currentProject.rootPath, error, host, session]);

  useEffect(() => {
    if (!session) {
      return;
    }
    return host.startStateSync({
      runtime,
      currentProject,
      session,
      refreshMs: host.describeLifecyclePolicy().bridgeStateRefreshMs,
    });
  }, [currentProject, host, runtime, session]);

  useEffect(() => {
    if (!active || !session) {
      return;
    }
    return host.startRequestPolling({
      active: enabled,
      runtime,
      session,
      pollMs: host.describeLifecyclePolicy().bridgeRequestPollMs,
      recordMetric: markWorkspaceMetric,
    });
  }, [enabled, host, runtime, session]);

  const status: WorkspaceStatus = !enabled
    ? "idle"
    : error
      ? "error"
      : session && surface
        ? "ready"
        : "starting";

  return {
    status,
    session,
    error,
    surfaceReady,
    surface,
    bootPhase,
    markSurfaceReady() {
      setSurfaceReady(true);
      setBootPhase("surface:ready");
    },
    restartWorkspace() {
      setRefreshNonce((value) => value + 1);
    },
  };
}
