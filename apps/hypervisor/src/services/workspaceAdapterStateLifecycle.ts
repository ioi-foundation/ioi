import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import { buildWorkspaceAdapterState } from "./workspaceAdapterState";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchHostSession,
  WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";

export function startWorkspaceAdapterStateSync(params: {
  host: WorkspaceWorkbenchHost;
  runtime: HypervisorClientRuntime;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  session: WorkspaceWorkbenchHostSession;
  refreshMs: number;
}) {
  let cancelled = false;
  let intervalHandle: number | null = null;

  const syncAdapterState = async () => {
    try {
      const snapshot = await buildWorkspaceAdapterState(
        params.runtime,
        params.host,
        params.currentProject,
        params.session,
      );
      if (cancelled) {
        return;
      }
      await params.host.publishAdapterState(params.session, snapshot);
    } catch (error) {
      console.error("[Workspace] Failed to sync adapter state snapshot:", error);
    }
  };

  void syncAdapterState();
  intervalHandle = window.setInterval(syncAdapterState, params.refreshMs);

  return () => {
    cancelled = true;
    if (intervalHandle !== null) {
      window.clearInterval(intervalHandle);
    }
  };
}
