import {
  peekCachedWorkspaceSnapshot,
  prewarmWorkspaceRoot,
  hostWorkspaceAdapter,
} from "./workspaceAdapter";
import type { WorkspaceWorkbenchHost } from "./workspaceWorkbenchHost";

export const substratePreviewWorkspaceWorkbenchHost: WorkspaceWorkbenchHost = {
  async ensureSession({ rootPath }) {
    const initialSnapshot = peekCachedWorkspaceSnapshot(rootPath);
    void prewarmWorkspaceRoot(rootPath).catch(() => {
      // The preview host should reveal immediately even if the background
      // snapshot warm-up fails; WorkspaceHost surfaces errors later.
    });
    return {
      rootPath,
      internal: {
        kind: "substrate-preview",
        createdAtMs: Date.now(),
        initialSnapshot,
      },
    };
  },
  async publishState() {
    return;
  },
  describeLifecyclePolicy() {
    return {
      idlePrewarmDelayMs: 900,
      bridgeStateRefreshMs: 10_000,
    };
  },
  startStateSync() {
    return () => {};
  },
  buildSurface(session, { projectName, refreshNonce }) {
    const internal = session.internal as
      | {
          kind?: string;
          initialSnapshot?: Awaited<
            ReturnType<typeof hostWorkspaceAdapter.inspectWorkspace>
          >;
        }
      | undefined;
    return {
      kind: "substrate-preview" as const,
      key: `${session.rootPath}:${refreshNonce}`,
      title: `Workspace for ${projectName}`,
      rootPath: session.rootPath,
      adapter: hostWorkspaceAdapter,
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
      startupEyebrow: "Workspace adapter hub",
      startupDescription:
        "Opening the governed code-editor adapter hub for this project.",
      startupFailureDescription:
        "The Workspace adapter hub did not initialize cleanly.",
      runtimeLabel: `Workspace adapter hub for ${session.rootPath}`,
      metricDetails: {
        mode: "workspace-adapter-hub",
      },
    };
  },
};
