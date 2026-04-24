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

export type OpenVsCodeWorkbenchSession = WorkspaceWorkbenchHostSession & {
  internal: {
    kind: "openvscode";
    info: WorkspaceIdeSessionInfo;
  };
};

export function readOpenVsCodeSessionInfo(
  session: WorkspaceWorkbenchHostSession,
): WorkspaceIdeSessionInfo {
  const internal = session.internal as OpenVsCodeWorkbenchSession["internal"] | undefined;
  if (!internal || internal.kind !== "openvscode") {
    throw new Error("Workspace session is missing OpenVSCode runtime metadata.");
  }
  return internal.info;
}

export async function ensureOpenVsCodeWorkbenchSession(params: {
  rootPath: string;
  forceRestart?: boolean;
}): Promise<OpenVsCodeWorkbenchSession> {
  if (params.forceRestart) {
    await stopWorkspaceIdeSession();
  }

  const info = await ensureWorkspaceIdeSession(params.rootPath);
  return {
    rootPath: info.rootPath,
    internal: {
      kind: "openvscode",
      info,
    },
  };
}

export async function publishOpenVsCodeBridgeState(
  session: WorkspaceWorkbenchHostSession,
  state: Record<string, unknown>,
): Promise<void> {
  await writeWorkspaceIdeBridgeState(readOpenVsCodeSessionInfo(session).rootPath, state);
}

export async function takeOpenVsCodeBridgeRequests(
  session: WorkspaceWorkbenchHostSession,
) {
  return takeWorkspaceIdeBridgeRequests(readOpenVsCodeSessionInfo(session).rootPath);
}

export function describeOpenVsCodeLifecyclePolicy() {
  return {
    idlePrewarmDelayMs: 900,
    bridgeStateRefreshMs: 2_500,
    bridgeRequestPollMs: 750,
  };
}

export function startOpenVsCodeBridgeStateSync(
  host: WorkspaceWorkbenchHost,
  params: Parameters<WorkspaceWorkbenchHost["startStateSync"]>[0],
) {
  return startWorkspaceBridgeStateSync({
    ...params,
    host,
  });
}

export function startOpenVsCodeBridgeRequestPolling(
  host: WorkspaceWorkbenchHost,
  params: Parameters<WorkspaceWorkbenchHost["startRequestPolling"]>[0],
) {
  return startWorkspaceBridgeRequestPolling({
    ...params,
    host,
  });
}

export function buildOpenVsCodeSurfaceId(
  mode: "iframe-oracle" | "direct-openvscode",
  info: WorkspaceIdeSessionInfo,
): string {
  return [
    "openvscode",
    mode,
    info.processId,
    info.port,
    info.bridgePort,
  ].join("-");
}
