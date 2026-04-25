import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useCallback, useEffect, useRef, useState } from "react";

import type { WorkspaceWorkbenchOpenVsCodeDirectModel } from "../../services/workspaceWorkbenchHost";
import {
  destroyWorkspaceDirectWebview,
  focusWorkspaceDirectWebview,
  getWorkspaceDirectWebviewState,
  hideWorkspaceDirectWebview,
  openWorkspaceDirectWebviewDevtools,
  showWorkspaceDirectWebview,
  updateWorkspaceDirectWebviewBounds,
  type WorkspaceDirectWebviewBounds,
  type WorkspaceDirectWebviewReadyEvent,
  type WorkspaceDirectWebviewState,
} from "../../services/workspaceDirectWebview";

interface OpenVsCodeDirectSurfaceProps {
  active: boolean;
  surface: WorkspaceWorkbenchOpenVsCodeDirectModel;
  onReady: () => void;
  onError: (message: string) => void;
}

declare global {
  interface Window {
    __AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__?: () => Promise<WorkspaceDirectWebviewState>;
    __AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__?: () => Promise<WorkspaceDirectWebviewState | null>;
    __AUTOPILOT_WORKBENCH_SURFACE__?: WorkspaceDirectWebviewState | null;
  }
}

function boundsEqual(
  left: WorkspaceDirectWebviewBounds | null,
  right: WorkspaceDirectWebviewBounds | null,
): boolean {
  if (!left || !right) {
    return false;
  }
  return (
    left.x === right.x &&
    left.y === right.y &&
    left.width === right.width &&
    left.height === right.height
  );
}

function readElementBounds(element: HTMLElement): WorkspaceDirectWebviewBounds | null {
  const rect = element.getBoundingClientRect();
  const width = Math.round(rect.width);
  const height = Math.round(rect.height);
  if (width <= 0 || height <= 0) {
    return null;
  }
  return {
    x: Math.round(rect.left),
    y: Math.round(rect.top),
    width,
    height,
  };
}

async function readElementScreenBounds(
  element: HTMLElement,
): Promise<WorkspaceDirectWebviewBounds | null> {
  const bounds = readElementBounds(element);
  if (!bounds) {
    return null;
  }
  let nativeCorrectionX = 0;
  let nativeCorrectionY = 0;
  try {
    const nativeOuterPosition = await getCurrentWindow().outerPosition();
    nativeCorrectionX = window.screenX - nativeOuterPosition.x;
    nativeCorrectionY = window.screenY - nativeOuterPosition.y;
  } catch {
    nativeCorrectionX = 0;
    nativeCorrectionY = 0;
  }
  return {
    ...bounds,
    x: Math.round(window.screenX + bounds.x + nativeCorrectionX),
    y: Math.round(window.screenY + bounds.y + nativeCorrectionY),
  };
}

function readParentViewport() {
  if (typeof window === "undefined") {
    return null;
  }
  return {
    width: Math.round(window.innerWidth),
    height: Math.round(window.innerHeight),
  };
}

export function OpenVsCodeDirectSurface({
  active,
  surface,
  onReady,
  onError,
}: OpenVsCodeDirectSurfaceProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const shownRef = useRef(false);
  const prewarmedRef = useRef(false);
  const lastBoundsRef = useRef<WorkspaceDirectWebviewBounds | null>(null);
  const lastScreenBoundsRef = useRef<WorkspaceDirectWebviewBounds | null>(null);
  const frameRef = useRef<number | null>(null);
  const timeoutRefs = useRef<number[]>([]);
  const [nativeState, setNativeState] = useState<WorkspaceDirectWebviewState | null>(null);
  const [parentViewport, setParentViewport] = useState(readParentViewport);

  const syncBounds = useCallback(async () => {
    const container = containerRef.current;
    if (!active || !container) {
      return;
    }

    const bounds = readElementBounds(container);
    if (!bounds) {
      return;
    }
    const screenBounds = await readElementScreenBounds(container);
    setParentViewport(readParentViewport());

    try {
      if (!shownRef.current) {
        const result = await showWorkspaceDirectWebview({
          surfaceId: surface.surfaceId,
          parentWindowLabel: getCurrentWindow().label,
          url: surface.workbenchUrl,
          bounds,
          screenBounds,
          visible: true,
        });
        prewarmedRef.current = true;
        shownRef.current = true;
        lastBoundsRef.current = bounds;
        lastScreenBoundsRef.current = screenBounds;
        setNativeState(result.state);
        return;
      }

      if (
        boundsEqual(lastBoundsRef.current, bounds) &&
        boundsEqual(lastScreenBoundsRef.current, screenBounds)
      ) {
        return;
      }

      await updateWorkspaceDirectWebviewBounds({
        surfaceId: surface.surfaceId,
        bounds,
        screenBounds,
      });
      lastBoundsRef.current = bounds;
      lastScreenBoundsRef.current = screenBounds;
      setNativeState((current) =>
        current ? { ...current, bounds, screenBounds } : current,
      );
    } catch (error) {
      onError(
        error instanceof Error
          ? error.message
          : "The direct OpenVSCode workbench surface failed to initialize.",
      );
    }
  }, [active, onError, surface.surfaceId, surface.workbenchUrl]);

  const prewarmHiddenSurface = useCallback(async () => {
    const container = containerRef.current;
    if (active || !container || prewarmedRef.current) {
      return;
    }

    const bounds = readElementBounds(container);
    if (!bounds) {
      return;
    }
    const screenBounds = await readElementScreenBounds(container);
    setParentViewport(readParentViewport());

    try {
      const result = await showWorkspaceDirectWebview({
        surfaceId: surface.surfaceId,
        parentWindowLabel: getCurrentWindow().label,
        url: surface.workbenchUrl,
        bounds,
        screenBounds,
        visible: false,
      });
      prewarmedRef.current = true;
      shownRef.current = false;
      lastBoundsRef.current = bounds;
      lastScreenBoundsRef.current = screenBounds;
      setNativeState(result.state);
    } catch (error) {
      onError(
        error instanceof Error
          ? error.message
          : "The direct OpenVSCode workbench surface failed to prewarm.",
      );
    }
  }, [active, onError, surface.surfaceId, surface.workbenchUrl]);

  const scheduleSyncBounds = useCallback(() => {
    if (frameRef.current !== null) {
      window.cancelAnimationFrame(frameRef.current);
    }
    frameRef.current = window.requestAnimationFrame(() => {
      frameRef.current = null;
      void syncBounds();
    });
  }, [syncBounds]);

  const clearDeferredSyncBounds = useCallback(() => {
    for (const timeout of timeoutRefs.current) {
      window.clearTimeout(timeout);
    }
    timeoutRefs.current = [];
  }, []);

  const scheduleSettledSyncBounds = useCallback(() => {
    clearDeferredSyncBounds();
    scheduleSyncBounds();
    for (const delayMs of [75, 180, 360, 720, 1200]) {
      const timeout = window.setTimeout(scheduleSyncBounds, delayMs);
      timeoutRefs.current.push(timeout);
    }
  }, [clearDeferredSyncBounds, scheduleSyncBounds]);

  useEffect(() => {
    const readyPromise = listen<WorkspaceDirectWebviewReadyEvent>(
      "workspace-direct-webview-ready",
      (event) => {
        if (event.payload.surfaceId === surface.surfaceId) {
          setNativeState({
            surfaceId: event.payload.surfaceId,
            label: event.payload.label,
            parentWindowLabel: event.payload.parentWindowLabel,
            url: event.payload.url,
            mode: event.payload.mode,
            bounds: event.payload.bounds,
            screenBounds: event.payload.screenBounds,
            createdAtMs: Date.now(),
            showCount: 1,
            reuseCount: 0,
            hideCount: 0,
            boundsUpdateCount: 0,
          });
          onReady();
          scheduleSettledSyncBounds();
        }
      },
    );

    return () => {
      void readyPromise.then((unlisten) => {
        unlisten();
      });
    };
  }, [onReady, scheduleSettledSyncBounds, surface.surfaceId]);

  useEffect(() => {
    window.__AUTOPILOT_WORKBENCH_SURFACE__ = nativeState;
    window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__ = () =>
      getWorkspaceDirectWebviewState(surface.surfaceId);
    window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__ = () =>
      openWorkspaceDirectWebviewDevtools(surface.surfaceId);

    return () => {
      if (window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__) {
        delete window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__;
      }
      if (window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__) {
        delete window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__;
      }
      if (window.__AUTOPILOT_WORKBENCH_SURFACE__) {
        delete window.__AUTOPILOT_WORKBENCH_SURFACE__;
      }
    };
  }, [nativeState, surface.surfaceId]);

  useEffect(() => {
    return () => {
      void hideWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      void destroyWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
    };
  }, [surface.surfaceId]);

  useEffect(() => {
    if (active) {
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      void prewarmHiddenSurface();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [active, prewarmHiddenSurface]);

  useEffect(() => {
    const container = containerRef.current;
    if (!active || !container) {
      void hideWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      shownRef.current = false;
      return;
    }

    const observer = new ResizeObserver(scheduleSyncBounds);
    observer.observe(container);
    const currentWindow = getCurrentWindow();
    let cancelled = false;
    let unlistenMoved: (() => void) | null = null;
    let unlistenResized: (() => void) | null = null;
    const handleBoundsInvalidated = () => {
      scheduleSettledSyncBounds();
    };
    void currentWindow.onMoved(handleBoundsInvalidated).then((unlisten) => {
      if (cancelled) {
        unlisten();
        return;
      }
      unlistenMoved = unlisten;
    });
    void currentWindow.onResized(handleBoundsInvalidated).then((unlisten) => {
      if (cancelled) {
        unlisten();
        return;
      }
      unlistenResized = unlisten;
    });
    window.addEventListener("resize", handleBoundsInvalidated);
    window.addEventListener("scroll", scheduleSyncBounds, true);
    window.visualViewport?.addEventListener("resize", handleBoundsInvalidated);
    window.visualViewport?.addEventListener("scroll", scheduleSyncBounds);

    scheduleSettledSyncBounds();

    return () => {
      cancelled = true;
      clearDeferredSyncBounds();
      unlistenMoved?.();
      unlistenResized?.();
      observer.disconnect();
      window.removeEventListener("resize", handleBoundsInvalidated);
      window.removeEventListener("scroll", scheduleSyncBounds, true);
      window.visualViewport?.removeEventListener("resize", handleBoundsInvalidated);
      window.visualViewport?.removeEventListener("scroll", scheduleSyncBounds);
      if (frameRef.current !== null) {
        window.cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      }
      void hideWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      shownRef.current = false;
      lastBoundsRef.current = null;
      lastScreenBoundsRef.current = null;
    };
  }, [
    active,
    clearDeferredSyncBounds,
    scheduleSettledSyncBounds,
    scheduleSyncBounds,
    surface.surfaceId,
  ]);

  return (
    <div
      ref={containerRef}
      className="chat-workspace-oss-shell__direct-surface"
      data-workspace-surface-kind="openvscode-direct"
      data-workspace-surface-id={surface.surfaceId}
      data-workspace-native-host-mode={nativeState?.mode ?? "pending"}
      data-workspace-native-host-label={nativeState?.label ?? ""}
      data-workspace-native-bounds={
        nativeState ? JSON.stringify(nativeState.bounds) : ""
      }
      data-workspace-native-screen-bounds={
        nativeState?.screenBounds ? JSON.stringify(nativeState.screenBounds) : ""
      }
      data-workspace-parent-viewport={
        parentViewport ? JSON.stringify(parentViewport) : ""
      }
      role="presentation"
      onFocus={() => {
        void focusWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      }}
      onPointerDown={() => {
        void focusWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      }}
    />
  );
}
