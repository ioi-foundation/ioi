import {
  peekCachedWorkspaceSnapshot,
  prewarmWorkspaceRoot,
  hostWorkspaceAdapter,
} from "./workspaceAdapter";
import type { WorkspaceSessionHost } from "./workspaceSessionHost";

export const substratePreviewWorkspaceSessionHost: WorkspaceSessionHost = {
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
  describeLifecyclePolicy() {
    return {
      idlePrewarmDelayMs: 900,
    };
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
  describeAdapterWorkspace(_session, project) {
    return {
      id: project.id,
      name: project.name,
      rootPath: project.rootPath,
    };
  },
  describeSession(session) {
    return {
      startupEyebrow: "Workspace session",
      startupDescription:
        "Opening the current project in the governed code-editor workspace.",
      startupFailureDescription:
        "The workspace session did not initialize cleanly.",
      runtimeLabel: `Workspace session for ${session.rootPath}`,
      metricDetails: {
        mode: "workspace-session",
      },
    };
  },
};
