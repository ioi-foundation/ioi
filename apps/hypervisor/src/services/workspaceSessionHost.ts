import type { HypervisorClientRuntime } from "./HypervisorClientRuntime";
import type {
  WorkspaceAdapter,
  WorkspaceLayoutMode,
  WorkspacePane,
  WorkspaceSnapshot,
} from "@ioi/workspace-substrate";

export interface WorkspaceSessionHostSession {
  rootPath: string;
  internal: unknown;
}

export interface WorkspaceSessionProjectDescriptor {
  id: string;
  name: string;
  rootPath: string;
}

export interface WorkspaceSessionSubstratePreviewModel {
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

export type WorkspaceSessionSurfaceModel =
  WorkspaceSessionSubstratePreviewModel;

export interface WorkspaceCodeEditorAdapterWorkspaceModel {
  id: string;
  name: string;
  rootPath: string;
}

export interface WorkspaceSessionDescriptor {
  startupEyebrow: string;
  startupDescription: string;
  startupFailureDescription: string;
  runtimeLabel: string;
  metricDetails?: Record<string, unknown>;
}

export interface WorkspaceSessionLifecyclePolicy {
  idlePrewarmDelayMs: number;
}

export interface WorkspaceSessionHost {
  ensureSession(params: {
    rootPath: string;
    runtime: HypervisorClientRuntime;
    forceRestart?: boolean;
  }): Promise<WorkspaceSessionHostSession>;
  describeLifecyclePolicy(): WorkspaceSessionLifecyclePolicy;
  buildSurface(
    session: WorkspaceSessionHostSession,
    options: {
      projectName: string;
      refreshNonce: number;
    },
  ): WorkspaceSessionSurfaceModel;
  describeAdapterWorkspace(
    session: WorkspaceSessionHostSession,
    project: WorkspaceSessionProjectDescriptor,
  ): WorkspaceCodeEditorAdapterWorkspaceModel;
  describeSession(
    session: WorkspaceSessionHostSession,
  ): WorkspaceSessionDescriptor;
}
