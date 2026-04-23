import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import {
  WorkspaceHost,
  type WorkspaceExtensionsModel,
  type WorkspaceOperatorModel,
  type WorkspaceOperatorSurface,
  type WorkspacePersistedState,
  type WorkspaceRunDebugModel,
  type WorkspaceSnapshot,
} from "@ioi/workspace-substrate";

import type { TauriRuntime } from "./TauriRuntime";
import {
  loadWorkspaceShellState,
  persistWorkspaceShellState,
} from "./workspaceShellState";
import {
  createExtensionsModel,
  createOperatorModel,
  createRunDebugModel,
  loadDirectWorkspaceWorkbenchData,
  type DirectWorkspaceBridgeState,
} from "./workspaceDirectWorkbenchModel";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchProjectDescriptor,
} from "./workspaceWorkbenchHost";
import { useWorkspaceWorkbenchSession } from "./useWorkspaceWorkbenchSession";

interface WorkspaceShellProps {
  active: boolean;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  runtime: TauriRuntime;
  host: WorkspaceWorkbenchHost;
  fullBleed?: boolean;
}

function defaultWorkspaceShellState(): WorkspacePersistedState {
  return {
    activePane: "files",
    activeBottomPanel: "output",
    bottomPanelOpen: false,
    expandedPaths: {},
    documents: [],
    activeDocumentPath: null,
  };
}

export function WorkspaceShell({
  active,
  currentProject,
  runtime,
  host,
  fullBleed = false,
}: WorkspaceShellProps) {
  const {
    status,
    session,
    error,
    surfaceReady,
    surface,
    bootPhase,
    markSurfaceReady,
    restartWorkspace,
  } = useWorkspaceWorkbenchSession({
    active,
    currentProject,
    runtime,
    host,
  });
  const sessionDescriptor = session ? host.describeSession(session) : null;
  const [persistedState, setPersistedState] = useState(() =>
    loadWorkspaceShellState(currentProject.rootPath),
  );
  const [bridgeState, setBridgeState] = useState<DirectWorkspaceBridgeState | null>(null);
  const [extensionManifests, setExtensionManifests] = useState<
    Awaited<ReturnType<typeof loadDirectWorkspaceWorkbenchData>>["extensionManifests"]
  >([]);

  useEffect(() => {
    setPersistedState(loadWorkspaceShellState(currentProject.rootPath));
  }, [currentProject.rootPath]);

  const initialWorkspaceState = useMemo<WorkspacePersistedState | null>(
    () => persistedState?.shellState ?? defaultWorkspaceShellState(),
    [persistedState],
  );
  const initialWorkspaceSnapshot = persistedState?.snapshot ?? null;
  const activeOperatorSurface: WorkspaceOperatorSurface =
    persistedState?.dockSurface ?? "chat";

  const directSurfaceVisible = Boolean(surface && surface.kind === "direct");
  const overlayVisible =
    Boolean(error) || status !== "ready" || (!directSurfaceVisible && !surfaceReady);

  useEffect(() => {
    if (!import.meta.env.DEV || !active) {
      return;
    }
    console.info("[WorkspaceBoot] shell state", {
      rootPath: currentProject.rootPath,
      status,
      surfaceKind: surface?.kind ?? null,
      surfaceReady,
      overlayVisible,
      error,
    });
  }, [
    active,
    currentProject.rootPath,
    error,
    overlayVisible,
    status,
    surface,
    surfaceReady,
  ]);

  const persistShellState = (
    nextShellState: WorkspacePersistedState | null,
    nextActivePath?: string | null,
  ) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface: current?.dockSurface ?? "chat",
        shellState: nextShellState,
        lastActivePath:
          nextActivePath === undefined
            ? (current?.lastActivePath ?? null)
            : nextActivePath,
        snapshot: current?.snapshot ?? null,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
  };

  const persistOperatorSurface = (dockSurface: WorkspaceOperatorSurface) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface,
        shellState: current?.shellState ?? initialWorkspaceState,
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: current?.snapshot ?? initialWorkspaceSnapshot,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
  };

  const persistSnapshot = (nextSnapshot: WorkspaceSnapshot | null) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface: current?.dockSurface ?? "chat",
        shellState: current?.shellState ?? initialWorkspaceState,
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: nextSnapshot,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
  };

  useEffect(() => {
    if (!active || !session || !surface || surface.kind !== "direct") {
      setBridgeState(null);
      setExtensionManifests([]);
      return;
    }

    let cancelled = false;
    let intervalHandle: number | null = null;

    const refresh = async () => {
      try {
        const next = await loadDirectWorkspaceWorkbenchData({
          runtime,
          host,
          currentProject,
          session,
        });
        if (cancelled) {
          return;
        }
        setBridgeState(next.bridgeState);
        setExtensionManifests(next.extensionManifests);
      } catch (error) {
        if (!cancelled) {
          console.error("[Workspace] Failed to load direct workbench model:", error);
        }
      }
    };

    void refresh();
    intervalHandle = window.setInterval(refresh, 12_000);

    return () => {
      cancelled = true;
      if (intervalHandle !== null) {
        window.clearInterval(intervalHandle);
      }
    };
  }, [active, currentProject, host, runtime, session, surface]);

  const activeFilePath = persistedState?.lastActivePath ?? null;

  const runDebugModel = useMemo<WorkspaceRunDebugModel>(
    () =>
      createRunDebugModel({
        bridgeState,
        runtime,
        rootPath: currentProject.rootPath,
        activeFilePath,
      }),
    [activeFilePath, bridgeState, currentProject.rootPath, runtime],
  );

  const extensionsModel = useMemo<WorkspaceExtensionsModel>(
    () =>
      createExtensionsModel({
        bridgeState,
        extensionManifests,
        runtime,
      }),
    [bridgeState, extensionManifests, runtime],
  );

  const operatorModel = useMemo<WorkspaceOperatorModel>(
    () =>
      createOperatorModel({
        bridgeState,
        activeSurface: activeOperatorSurface,
        onSelectSurface: persistOperatorSurface,
        runtime,
        rootPath: currentProject.rootPath,
        activeFilePath,
      }),
    [
      activeFilePath,
      activeOperatorSurface,
      bridgeState,
      currentProject.rootPath,
      runtime,
    ],
  );

  return (
    <section
      className={clsx(
        "chat-workspace-oss-shell",
        active && "is-active",
        fullBleed && "is-full-bleed",
      )}
      aria-label="Workspace"
      aria-hidden={!active}
    >
      {session && surface ? (
        surface.kind === "frame" ? (
          <iframe
            key={surface.key}
            className={clsx(
              "chat-workspace-oss-shell__frame",
              surfaceReady && "is-ready",
            )}
            title={surface.title}
            src={surface.src}
            onLoad={() => {
              markSurfaceReady();
            }}
          />
        ) : (
          <WorkspaceHost
            key={surface.key}
            className="chat-workspace-host"
            adapter={surface.adapter}
            root={surface.rootPath}
            layoutMode={surface.layoutMode}
            defaultPane={surface.defaultPane}
            title={surface.title}
            showHeader={surface.showHeader}
            showBottomPanel={surface.showBottomPanel}
            initialSnapshot={surface.initialSnapshot ?? initialWorkspaceSnapshot}
            initialState={initialWorkspaceState}
            runDebugModel={runDebugModel}
            extensionsModel={extensionsModel}
            operatorModel={operatorModel}
            onStateChange={(nextState) => {
              persistShellState(nextState);
            }}
            onSnapshotChange={persistSnapshot}
            onActivePathChange={(path) => {
              persistShellState(
                persistedState?.shellState ?? initialWorkspaceState,
                path,
              );
            }}
          />
        )
      ) : null}

      {overlayVisible ? (
        <div className="chat-workspace-oss-shell__overlay">
          <div className="chat-workspace-oss-shell__overlay-card">
            <span className="chat-workspace-oss-shell__eyebrow">
              {sessionDescriptor?.startupEyebrow ?? "Workspace runtime"}
            </span>
            <h2>{currentProject.name}</h2>
            <p>
              {error
                ? (sessionDescriptor?.startupFailureDescription ??
                  "The workspace runtime did not start cleanly.")
                : (sessionDescriptor?.startupDescription ??
                  "Starting the workspace runtime for this workspace.")}
            </p>
            <div className="chat-workspace-oss-shell__meta">
              <span>Root</span>
              <code>{currentProject.rootPath}</code>
            </div>
            {session ? (
              <div className="chat-workspace-oss-shell__meta">
                <span>Runtime</span>
                <code>{sessionDescriptor?.runtimeLabel}</code>
              </div>
            ) : null}
            {import.meta.env.DEV ? (
              <>
                <div className="chat-workspace-oss-shell__meta">
                  <span>Debug</span>
                  <code>
                    {`status=${status} session=${session ? "yes" : "no"} surface=${surface?.kind ?? "none"}`}
                  </code>
                </div>
                <div className="chat-workspace-oss-shell__meta">
                  <span>Flags</span>
                  <code>
                    {`surfaceReady=${surfaceReady} overlay=${overlayVisible ? "yes" : "no"}`}
                  </code>
                </div>
                <div className="chat-workspace-oss-shell__meta">
                  <span>Phase</span>
                  <code>{bootPhase}</code>
                </div>
              </>
            ) : null}
            {error ? (
              <pre className="chat-workspace-oss-shell__error">{error}</pre>
            ) : (
              <div className="chat-workspace-oss-shell__spinner" aria-hidden="true" />
            )}
            <div className="chat-workspace-oss-shell__actions">
              <button
                type="button"
                className="chat-workspace-oss-shell__button"
                onClick={() => {
                  restartWorkspace();
                }}
              >
                {error ? "Retry workspace runtime" : "Force reveal now"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
