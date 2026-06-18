import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import { buildWorkspaceBridgeState } from "./workspaceBridgeState";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchHostSession,
  WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";

export function startWorkspaceBridgeStateSync(params: {
  host: WorkspaceWorkbenchHost;
  runtime: HypervisorClientRuntime;
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
