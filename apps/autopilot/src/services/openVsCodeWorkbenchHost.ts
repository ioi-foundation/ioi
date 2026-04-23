import {
  ensureWorkspaceIdeSession,
  stopWorkspaceIdeSession,
  takeWorkspaceIdeBridgeRequests,
  type WorkspaceIdeSessionInfo,
  writeWorkspaceIdeBridgeState,
} from "./workspaceIde";
import {
  startWorkspaceBridgeRequestPolling,
  startWorkspaceBridgeStateSync,
} from "./workspaceBridgeLifecycle";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchHostSession,
} from "./workspaceWorkbenchHost";

type OpenVsCodeWorkbenchSession = WorkspaceWorkbenchHostSession & {
  internal: {
    kind: "openvscode";
    info: WorkspaceIdeSessionInfo;
  };
};

function readOpenVsCodeSessionInfo(
  session: WorkspaceWorkbenchHostSession,
): WorkspaceIdeSessionInfo {
  const internal = session.internal as OpenVsCodeWorkbenchSession["internal"] | undefined;
  if (!internal || internal.kind !== "openvscode") {
    throw new Error("Workspace session is missing OpenVSCode runtime metadata.");
  }
  return internal.info;
}

export const openVsCodeWorkbenchHost: WorkspaceWorkbenchHost = {
  async ensureSession({ rootPath, forceRestart = false }) {
    if (forceRestart) {
      await stopWorkspaceIdeSession();
    }

    const info = await ensureWorkspaceIdeSession(rootPath);
    return {
      rootPath: info.rootPath,
      internal: {
        kind: "openvscode",
        info,
      },
    };
  },
  async publishState(session, state) {
    await writeWorkspaceIdeBridgeState(readOpenVsCodeSessionInfo(session).rootPath, state);
  },
  async takeRequests(session) {
    return takeWorkspaceIdeBridgeRequests(readOpenVsCodeSessionInfo(session).rootPath);
  },
  describeLifecyclePolicy() {
    return {
      idlePrewarmDelayMs: 900,
      bridgeStateRefreshMs: 2_500,
      bridgeRequestPollMs: 750,
    };
  },
  startStateSync(params) {
    return startWorkspaceBridgeStateSync({
      ...params,
      host: openVsCodeWorkbenchHost,
    });
  },
  startRequestPolling(params) {
    return startWorkspaceBridgeRequestPolling({
      ...params,
      host: openVsCodeWorkbenchHost,
    });
  },
  buildSurface(session, { projectName, refreshNonce }) {
    const info = readOpenVsCodeSessionInfo(session);
    return {
      kind: "frame" as const,
      key: `${info.rootPath}:${info.processId}:${refreshNonce}`,
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
