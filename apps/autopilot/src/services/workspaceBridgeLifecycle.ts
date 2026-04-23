import type { TauriRuntime } from "./TauriRuntime";
import { buildWorkspaceBridgeState } from "./workspaceBridgeState";
import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";
import {
  routeWorkspaceBridgeRequest,
} from "./workspaceRuntimeNavigation";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchHostSession,
  WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";

type MetricRecorder = (name: string, detail?: Record<string, unknown>) => void;

export function startWorkspaceBridgeStateSync(params: {
  host: WorkspaceWorkbenchHost;
  runtime: TauriRuntime;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  session: WorkspaceWorkbenchHostSession;
  refreshMs: number;
}) {
  let cancelled = false;
  let intervalHandle: number | null = null;

  const syncBridgeState = async () => {
    try {
      const snapshot = await buildWorkspaceBridgeState(
        params.runtime,
        params.host,
        params.currentProject,
        params.session,
      );
      if (cancelled) {
        return;
      }
      await params.host.publishState(params.session, snapshot);
    } catch (error) {
      console.error("[Workspace] Failed to sync bridge snapshot:", error);
    }
  };

  void syncBridgeState();
  intervalHandle = window.setInterval(syncBridgeState, params.refreshMs);

  return () => {
    cancelled = true;
    if (intervalHandle !== null) {
      window.clearInterval(intervalHandle);
    }
  };
}

export function startWorkspaceBridgeRequestPolling(params: {
  active: boolean;
  host: WorkspaceWorkbenchHost;
  runtime: TauriRuntime;
  session: WorkspaceWorkbenchHostSession;
  pollMs: number;
  recordMetric?: MetricRecorder;
}) {
  if (!params.active) {
    return () => {};
  }

  let cancelled = false;
  let intervalHandle: number | null = null;

  const pollRequests = async () => {
    try {
      const requests = await params.host.takeRequests(params.session);
      if (cancelled || requests.length === 0) {
        return;
      }
      for (const request of requests as WorkspaceBridgeRouteRequest[]) {
        await routeWorkspaceBridgeRequest(
          params.runtime,
          request,
          params.recordMetric,
        );
      }
    } catch (error) {
      console.error("[Workspace] Failed to process bridge requests:", error);
    }
  };

  void pollRequests();
  intervalHandle = window.setInterval(pollRequests, params.pollMs);

  return () => {
    cancelled = true;
    if (intervalHandle !== null) {
      window.clearInterval(intervalHandle);
    }
  };
}
