import {
  peekCachedWorkspaceSnapshot,
  prewarmWorkspaceRoot,
  tauriWorkspaceAdapter,
} from "./workspaceAdapter";
import type { WorkspaceWorkbenchHost } from "./workspaceWorkbenchHost";

export const directWorkspaceWorkbenchHost: WorkspaceWorkbenchHost = {
  async ensureSession({ rootPath }) {
    const initialSnapshot = peekCachedWorkspaceSnapshot(rootPath);
    void prewarmWorkspaceRoot(rootPath).catch(() => {
      // The direct host should reveal immediately even if the background
      // snapshot warm-up fails; WorkspaceHost surfaces errors later.
    });
    return {
      rootPath,
      internal: {
        kind: "direct",
        createdAtMs: Date.now(),
        initialSnapshot,
      },
    };
  },
  async publishState() {
    return;
  },
  async takeRequests() {
    return [];
  },
  describeLifecyclePolicy() {
    return {
      idlePrewarmDelayMs: 900,
      bridgeStateRefreshMs: 10_000,
      bridgeRequestPollMs: 10_000,
    };
  },
  startStateSync() {
    return () => {};
  },
  startRequestPolling() {
    return () => {};
  },
  buildSurface(session, { projectName, refreshNonce }) {
    const internal = session.internal as
      | {
          kind?: string;
          initialSnapshot?: Awaited<
            ReturnType<typeof tauriWorkspaceAdapter.inspectWorkspace>
          >;
        }
      | undefined;
    return {
      kind: "direct" as const,
      key: `${session.rootPath}:${refreshNonce}`,
      title: `Workspace for ${projectName}`,
      rootPath: session.rootPath,
      adapter: tauriWorkspaceAdapter,
      layoutMode: "full" as const,
      defaultPane: "files" as const,
      showHeader: false,
      showBottomPanel: true,
      initialSnapshot: internal?.initialSnapshot ?? null,
    };
  },
  describeBridgeWorkspace(_session, project) {
    return {
      id: project.id,
      name: project.name,
      rootPath: project.rootPath,
    };
  },
  describeSession(session) {
    return {
      startupEyebrow: "Direct workspace workbench",
      startupDescription:
        "Starting the native Workspace workbench for this project.",
      startupFailureDescription:
        "The native Workspace workbench did not initialize cleanly.",
      runtimeLabel: `Direct Workspace workbench for ${session.rootPath}`,
      metricDetails: {
        mode: "direct",
      },
    };
  },
};
