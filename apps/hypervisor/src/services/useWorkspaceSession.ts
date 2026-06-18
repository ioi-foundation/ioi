import { useEffect, useMemo, useRef, useState } from "react";
import {
  workflowRuntimeUnavailableCopy,
  type WorkflowRuntimeUnavailableCopy,
} from "@ioi/hypervisor-workbench";

import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import {
  type WorkspaceSessionHost,
  type WorkspaceSessionHostSession,
  type WorkspaceSessionProjectDescriptor,
} from "./workspaceSessionHost";

export type WorkspaceStatus = "idle" | "starting" | "ready" | "error";
export type WorkspaceSessionError = WorkflowRuntimeUnavailableCopy;

export function useWorkspaceSession(params: {
  active: boolean;
  enabled?: boolean;
  currentProject: WorkspaceSessionProjectDescriptor;
  runtime: HypervisorClientRuntime;
  host: WorkspaceSessionHost;
}) {
  const { active, currentProject, runtime, host } = params;
  const enabled = params.enabled ?? true;
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [session, setSession] = useState<WorkspaceSessionHostSession | null>(null);
  const [error, setError] = useState<WorkspaceSessionError | null>(null);
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
        const copy = workflowRuntimeUnavailableCopy(
          sessionError,
          "workspace_runtime",
        );
        setError(copy);
        setBootPhase(`ensureSession:failed ${copy.code}`);
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
