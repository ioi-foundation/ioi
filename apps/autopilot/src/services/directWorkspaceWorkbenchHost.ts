import {
  peekCachedWorkspaceSnapshot,
  prewarmWorkspaceRoot,
  tauriWorkspaceAdapter,
} from "./workspaceAdapter";
import {
  buildOpenVsCodeSurfaceId,
  describeOpenVsCodeLifecyclePolicy,
  ensureOpenVsCodeWorkbenchSession,
  publishOpenVsCodeBridgeState,
  readOpenVsCodeSessionInfo,
  startOpenVsCodeBridgeRequestPolling,
  startOpenVsCodeBridgeStateSync,
  takeOpenVsCodeBridgeRequests,
} from "./openVsCodeWorkbenchSession";
import type { WorkspaceWorkbenchHost } from "./workspaceWorkbenchHost";

export const directWorkspaceWorkbenchHost: WorkspaceWorkbenchHost = {
  async ensureSession({ rootPath, forceRestart = false }) {
    return ensureOpenVsCodeWorkbenchSession({ rootPath, forceRestart });
  },
  async publishState(session, state) {
    await publishOpenVsCodeBridgeState(session, state);
  },
  async takeRequests(session) {
    return takeOpenVsCodeBridgeRequests(session);
  },
  describeLifecyclePolicy() {
    return describeOpenVsCodeLifecyclePolicy();
  },
  startStateSync(params) {
    return startOpenVsCodeBridgeStateSync(directWorkspaceWorkbenchHost, params);
  },
  startRequestPolling(params) {
    return startOpenVsCodeBridgeRequestPolling(directWorkspaceWorkbenchHost, params);
  },
  buildSurface(session, { projectName, refreshNonce }) {
    const info = readOpenVsCodeSessionInfo(session);
    const surfaceId = buildOpenVsCodeSurfaceId("direct-openvscode", info);
    return {
      kind: "openvscode-direct" as const,
      key: `${surfaceId}:${refreshNonce}`,
      surfaceId: `${surfaceId}-${refreshNonce}`,
      title: `Workspace for ${projectName}`,
      rootPath: info.rootPath,
      workbenchUrl: info.workbenchUrl,
      version: info.version,
      port: info.port,
      bridgePort: info.bridgePort,
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
    const info = readOpenVsCodeSessionInfo(session);
    return {
      startupEyebrow: "Direct OpenVSCode workbench",
      startupDescription:
        "Starting the full OpenVSCode workbench for this project.",
      startupFailureDescription:
        "The direct OpenVSCode workbench did not start cleanly.",
      runtimeLabel: `OpenVSCode ${info.version}`,
      metricDetails: {
        mode: "direct-openvscode",
        runtime: "openvscode",
        version: info.version,
        port: info.port,
        bridgePort: info.bridgePort,
      },
    };
  },
};

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
      kind: "substrate-preview" as const,
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
      startupEyebrow: "Substrate workspace preview",
      startupDescription:
        "Starting the legacy Workspace substrate preview for this project.",
      startupFailureDescription:
        "The legacy Workspace substrate preview did not initialize cleanly.",
      runtimeLabel: `Substrate preview for ${session.rootPath}`,
      metricDetails: {
        mode: "substrate-preview",
      },
    };
  },
};
