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
import type {
  WorkspaceWorkbenchHost,
} from "./workspaceWorkbenchHost";

export const openVsCodeWorkbenchHost: WorkspaceWorkbenchHost = {
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
    return startOpenVsCodeBridgeStateSync(openVsCodeWorkbenchHost, params);
  },
  startRequestPolling(params) {
    return startOpenVsCodeBridgeRequestPolling(openVsCodeWorkbenchHost, params);
  },
  buildSurface(session, { projectName, refreshNonce }) {
    const info = readOpenVsCodeSessionInfo(session);
    return {
      kind: "frame" as const,
      key: `${buildOpenVsCodeSurfaceId("iframe", info)}:${refreshNonce}`,
      title: `Workspace for ${projectName}`,
      src: info.workbenchUrl,
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
      startupEyebrow: "OpenVSCode workbench",
      startupDescription:
        "Starting the full Workspace workbench for this project.",
      startupFailureDescription:
        "The Workspace workbench did not start cleanly.",
      runtimeLabel: `OpenVSCode ${info.version}`,
      metricDetails: {
        mode: "iframe",
        runtime: "openvscode",
        version: info.version,
        port: info.port,
        bridgePort: info.bridgePort,
      },
    };
  },
};
