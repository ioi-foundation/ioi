import { listen } from "../../services/hypervisorHostBridge";
import { getCurrentWindow } from "../../services/hypervisorHostBridge";
import { useCallback, useEffect, useRef, useState } from "react";

import darkPng from "../../assets/openvscode-walkthrough/dark.png";
import darkHcPng from "../../assets/openvscode-walkthrough/dark-hc.png";
import lightPng from "../../assets/openvscode-walkthrough/light.png";
import lightHcPng from "../../assets/openvscode-walkthrough/light-hc.png";

import type { WorkspaceWorkbenchOpenVsCodeDirectModel } from "../../services/workspaceWorkbenchHost";
import {
  buildWorkspaceSubstrateTargetIndex,
  type WorkspaceSubstrateTargetIndex,
} from "../../windows/AutopilotShellWindow/operatorSubstrateModel";
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
  suspended?: boolean;
  surface: WorkspaceWorkbenchOpenVsCodeDirectModel;
  reservedRightPx?: number;
  onReady: () => void;
  onError: (message: string) => void;
}

declare global {
  interface Window {
    __AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__?: () => Promise<WorkspaceDirectWebviewState>;
    __AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__?: () => Promise<WorkspaceDirectWebviewState | null>;
    __AUTOPILOT_GET_WORKBENCH_TARGET_INDEX__?: () => WorkspaceSubstrateTargetIndex;
    __AUTOPILOT_WORKBENCH_SURFACE__?: WorkspaceDirectWebviewState | null;
    __AUTOPILOT_WORKBENCH_TARGET_INDEX__?: WorkspaceSubstrateTargetIndex | null;
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

function readReservedRightWidth(
  element: HTMLElement,
  explicitReservedRightPx?: number,
): number {
  if (explicitReservedRightPx && explicitReservedRightPx > 0) {
    return Math.round(explicitReservedRightPx);
  }

  const workbenchSurface = element.closest(
    ".chat-workspace-oss-shell__workbench-surface",
  );
  if (!(workbenchSurface instanceof HTMLElement)) {
    return 0;
  }

  const reservedSlot = workbenchSurface.querySelector(
    ".chat-workspace-oss-shell__operator-chat-slot",
  );
  if (!(reservedSlot instanceof HTMLElement)) {
    return 0;
  }

  const reservedWidth = Math.round(reservedSlot.getBoundingClientRect().width);
  return reservedWidth > 0 ? reservedWidth : 0;
}

function constrainBoundsForReservedRight(
  element: HTMLElement,
  bounds: WorkspaceDirectWebviewBounds,
  explicitReservedRightPx?: number,
): WorkspaceDirectWebviewBounds {
  const reservedRightWidth = readReservedRightWidth(
    element,
    explicitReservedRightPx,
  );
  if (reservedRightWidth <= 0) {
    return bounds;
  }

  const workbenchSurface = element.closest(
    ".chat-workspace-oss-shell__workbench-surface",
  );
  if (!(workbenchSurface instanceof HTMLElement)) {
    return bounds;
  }

  const surfaceWidth = Math.round(workbenchSurface.getBoundingClientRect().width);
  const availableWidth = Math.max(1, surfaceWidth - reservedRightWidth);
  if (bounds.width <= availableWidth + 1) {
    return bounds;
  }

  return {
    ...bounds,
    width: availableWidth,
  };
}

function readElementBoundsWithReservedRight(
  element: HTMLElement,
  explicitReservedRightPx?: number,
): WorkspaceDirectWebviewBounds | null {
  const rect = element.getBoundingClientRect();
  const width = Math.round(rect.width);
  const height = Math.round(rect.height);
  if (width <= 0 || height <= 0) {
    return null;
  }
  return constrainBoundsForReservedRight(element, {
    x: Math.round(rect.left),
    y: Math.round(rect.top),
    width,
    height,
  }, explicitReservedRightPx);
}

async function readElementScreenBounds(
  element: HTMLElement,
  explicitReservedRightPx?: number,
): Promise<WorkspaceDirectWebviewBounds | null> {
  const bounds = readElementBoundsWithReservedRight(
    element,
    explicitReservedRightPx,
  );
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
  suspended = false,
  surface,
  reservedRightPx = 0,
  onReady,
  onError,
}: OpenVsCodeDirectSurfaceProps) {
  const visible = active && !suspended;
  const [localMenuOpen, setLocalMenuOpen] = useState(false);
  const [themeId, setThemeId] = useState<string>(() => {
    if (typeof document !== "undefined") {
      return document.documentElement.dataset.autopilotTheme ?? "dark-modern";
    }
    return "dark-modern";
  });

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const handleToggle = (event: Event) => {
      const customEvent = event as CustomEvent<{ open: boolean }>;
      setLocalMenuOpen(customEvent.detail?.open ?? false);
    };
    window.addEventListener("spot-command-menu-toggled", handleToggle);
    return () => {
      window.removeEventListener("spot-command-menu-toggled", handleToggle);
    };
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const observer = new MutationObserver(() => {
      setThemeId(document.documentElement.dataset.autopilotTheme ?? "dark-modern");
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-autopilot-theme"],
    });
    return () => observer.disconnect();
  }, []);

  const isWebviewVisible = visible && !localMenuOpen;

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
    if (!isWebviewVisible || !container) {
      return;
    }

    const bounds = readElementBoundsWithReservedRight(
      container,
      reservedRightPx,
    );
    if (!bounds) {
      return;
    }
    const screenBounds = await readElementScreenBounds(
      container,
      reservedRightPx,
    );
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
  }, [onError, reservedRightPx, surface.surfaceId, surface.workbenchUrl, visible, isWebviewVisible]);

  const prewarmHiddenSurface = useCallback(async () => {
    const container = containerRef.current;
    if (isWebviewVisible || !container || prewarmedRef.current) {
      return;
    }

    const bounds = readElementBoundsWithReservedRight(
      container,
      reservedRightPx,
    );
    if (!bounds) {
      return;
    }
    const screenBounds = await readElementScreenBounds(
      container,
      reservedRightPx,
    );
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
  }, [onError, reservedRightPx, surface.surfaceId, surface.workbenchUrl, visible, isWebviewVisible]);

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
    const directWebview =
      nativeState && nativeState.bounds
        ? {
            surfaceId: nativeState.surfaceId,
            label: nativeState.label,
            bounds: nativeState.bounds,
            screenBounds: nativeState.screenBounds ?? null,
          }
        : null;
    const targetIndex = buildWorkspaceSubstrateTargetIndex({
      directWebview,
    });
    window.__AUTOPILOT_WORKBENCH_SURFACE__ = nativeState;
    window.__AUTOPILOT_WORKBENCH_TARGET_INDEX__ = targetIndex;
    window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__ = () =>
      getWorkspaceDirectWebviewState(surface.surfaceId);
    window.__AUTOPILOT_GET_WORKBENCH_TARGET_INDEX__ = () => targetIndex;
    window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__ = () =>
      openWorkspaceDirectWebviewDevtools(surface.surfaceId);

    return () => {
      if (window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__) {
        delete window.__AUTOPILOT_GET_WORKBENCH_SURFACE_STATE__;
      }
      if (window.__AUTOPILOT_GET_WORKBENCH_TARGET_INDEX__) {
        delete window.__AUTOPILOT_GET_WORKBENCH_TARGET_INDEX__;
      }
      if (window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__) {
        delete window.__AUTOPILOT_OPEN_WORKBENCH_DEVTOOLS__;
      }
      if (window.__AUTOPILOT_WORKBENCH_SURFACE__) {
        delete window.__AUTOPILOT_WORKBENCH_SURFACE__;
      }
      if (window.__AUTOPILOT_WORKBENCH_TARGET_INDEX__) {
        delete window.__AUTOPILOT_WORKBENCH_TARGET_INDEX__;
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
    if (isWebviewVisible) {
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      void prewarmHiddenSurface();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [prewarmHiddenSurface, isWebviewVisible]);

  useEffect(() => {
    if (!isWebviewVisible) {
      return;
    }

    scheduleSettledSyncBounds();
  }, [reservedRightPx, scheduleSettledSyncBounds, visible]);

  useEffect(() => {
    const container = containerRef.current;
    if (!isWebviewVisible || !container) {
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
    clearDeferredSyncBounds,
    scheduleSettledSyncBounds,
    scheduleSyncBounds,
    surface.surfaceId,
    visible,
    isWebviewVisible,
  ]);

  let editorBg = "#1f1f1f";
  if (themeId === "light-modern") editorBg = "#f3f3f3";
  else if (themeId === "dark-high-contrast") editorBg = "#000000";
  else if (themeId === "light-high-contrast") editorBg = "#ffffff";

  let bgImage = darkPng;
  if (themeId === "light-modern") bgImage = lightPng;
  else if (themeId === "dark-high-contrast") bgImage = darkHcPng;
  else if (themeId === "light-high-contrast") bgImage = lightHcPng;

  return (
    <div
      ref={containerRef}
      className="chat-workspace-oss-shell__direct-surface"
      data-workspace-surface-kind="openvscode-direct"
      data-workspace-surface-id={surface.surfaceId}
      data-inspection-target="direct-openvscode-webview"
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
      role="application"
      aria-label="Direct OpenVSCode workbench webview"
      onFocus={() => {
        void focusWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      }}
      onPointerDown={() => {
        void focusWorkspaceDirectWebview(surface.surfaceId).catch(() => {});
      }}
      style={{ position: "relative" }}
    >
      {!isWebviewVisible && (
        <div
          className="chat-workspace-oss-shell__direct-surface-placeholder-container"
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            backgroundColor: editorBg,
            zIndex: 1,
            pointerEvents: "none",
            gap: "16px",
          }}
        >
          <img
            className="chat-workspace-oss-shell__direct-surface-placeholder"
            src={bgImage}
            alt="Workspace theme placeholder"
            style={{
              width: "280px",
              height: "180px",
              objectFit: "contain",
              borderRadius: "8px",
              border: themeId.includes("high-contrast")
                ? "2px solid #ffffff"
                : themeId.includes("light")
                ? "1px solid rgba(0, 0, 0, 0.1)"
                : "1px solid rgba(255, 255, 255, 0.1)",
              boxShadow: "0 10px 30px rgba(0, 0, 0, 0.25)",
              filter: "brightness(0.65) blur(0.5px)",
            }}
          />
          <div
            style={{
              color: themeId.includes("light") ? "rgba(0, 0, 0, 0.4)" : "rgba(255, 255, 255, 0.4)",
              fontSize: "12px",
              fontFamily: "var(--vscode-font-family, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif)",
              letterSpacing: "0.5px",
              textTransform: "uppercase",
            }}
          >
            Workspace Active ({themeId.replace("-", " ")})
          </div>
        </div>
      )}
    </div>
  );
}
