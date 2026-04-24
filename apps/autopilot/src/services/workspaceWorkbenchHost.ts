import type { TauriRuntime } from "./TauriRuntime";
import type { WorkspaceBridgeRouteRequest } from "./workspaceBridgeTypes";
import type {
  WorkspaceAdapter,
  WorkspaceLayoutMode,
  WorkspacePane,
  WorkspaceSnapshot,
} from "@ioi/workspace-substrate";

export interface WorkspaceWorkbenchHostSession {
  rootPath: string;
  internal: unknown;
}

export interface WorkspaceWorkbenchProjectDescriptor {
  id: string;
  name: string;
  rootPath: string;
}

export interface WorkspaceWorkbenchFrameModel {
  kind: "frame";
  key: string;
  title: string;
  src: string;
}

export interface WorkspaceWorkbenchOpenVsCodeDirectModel {
  kind: "openvscode-direct";
  key: string;
  surfaceId: string;
  title: string;
  rootPath: string;
  workbenchUrl: string;
  version: string;
  port: number;
  bridgePort: number;
}

export interface WorkspaceWorkbenchDirectModel {
  kind: "direct";
  key: string;
  title: string;
  rootPath: string;
  adapter: WorkspaceAdapter;
  layoutMode?: WorkspaceLayoutMode;
  defaultPane?: WorkspacePane;
  showHeader?: boolean;
  showBottomPanel?: boolean;
  initialSnapshot?: WorkspaceSnapshot | null;
}

export type WorkspaceWorkbenchSurfaceModel =
  | WorkspaceWorkbenchFrameModel
  | WorkspaceWorkbenchOpenVsCodeDirectModel
  | WorkspaceWorkbenchDirectModel;

export interface WorkspaceWorkbenchBridgeWorkspaceModel {
  id: string;
  name: string;
  rootPath: string;
}

export interface WorkspaceWorkbenchSessionDescriptor {
  startupEyebrow: string;
  startupDescription: string;
  startupFailureDescription: string;
  runtimeLabel: string;
  metricDetails?: Record<string, unknown>;
}

export interface WorkspaceWorkbenchLifecyclePolicy {
  idlePrewarmDelayMs: number;
  bridgeStateRefreshMs: number;
  bridgeRequestPollMs: number;
}

export interface WorkspaceWorkbenchHost {
  ensureSession(params: {
    rootPath: string;
    runtime: TauriRuntime;
    forceRestart?: boolean;
  }): Promise<WorkspaceWorkbenchHostSession>;
  publishState(
    session: WorkspaceWorkbenchHostSession,
    state: Record<string, unknown>,
  ): Promise<void>;
  takeRequests(
    session: WorkspaceWorkbenchHostSession,
  ): Promise<WorkspaceBridgeRouteRequest[]>;
  describeLifecyclePolicy(): WorkspaceWorkbenchLifecyclePolicy;
  startStateSync(params: {
    runtime: TauriRuntime;
    currentProject: WorkspaceWorkbenchProjectDescriptor;
    session: WorkspaceWorkbenchHostSession;
    refreshMs: number;
  }): () => void;
  startRequestPolling(params: {
    active: boolean;
    runtime: TauriRuntime;
    session: WorkspaceWorkbenchHostSession;
    pollMs: number;
    recordMetric?: (name: string, detail?: Record<string, unknown>) => void;
  }): () => void;
  buildSurface(
    session: WorkspaceWorkbenchHostSession,
    options: {
      projectName: string;
      refreshNonce: number;
    },
  ): WorkspaceWorkbenchSurfaceModel;
  describeBridgeWorkspace(
    session: WorkspaceWorkbenchHostSession,
    project: WorkspaceWorkbenchProjectDescriptor,
  ): WorkspaceWorkbenchBridgeWorkspaceModel;
  describeSession(
    session: WorkspaceWorkbenchHostSession,
  ): WorkspaceWorkbenchSessionDescriptor;
}
