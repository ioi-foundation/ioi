import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
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

export interface WorkspaceWorkbenchSubstratePreviewModel {
  kind: "substrate-preview";
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
  WorkspaceWorkbenchSubstratePreviewModel;

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
}

export interface WorkspaceWorkbenchHost {
  ensureSession(params: {
    rootPath: string;
    runtime: HypervisorClientRuntime;
    forceRestart?: boolean;
  }): Promise<WorkspaceWorkbenchHostSession>;
  publishState(
    session: WorkspaceWorkbenchHostSession,
    state: Record<string, unknown>,
  ): Promise<void>;
  describeLifecyclePolicy(): WorkspaceWorkbenchLifecyclePolicy;
  startStateSync(params: {
    runtime: HypervisorClientRuntime;
    currentProject: WorkspaceWorkbenchProjectDescriptor;
    session: WorkspaceWorkbenchHostSession;
    refreshMs: number;
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
