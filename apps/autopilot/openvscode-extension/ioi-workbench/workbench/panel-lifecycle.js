"use strict";

function createWorkbenchPanelLifecycle({
  AUTOPILOT_MODE_BY_ID,
  AUTOPILOT_MODE_BY_VIEW_ID,
  MODE_VISIBILITY_REQUEST_TYPES,
  buildWorkspaceActionContext,
  clearIntervalFn = clearInterval,
  consoleRef = console,
  renderHtml,
  setIntervalFn = setInterval,
  setTimeoutFn = setTimeout,
  vscode,
  workspaceSummary,
  writeBridgeRequest,
}) {
  const modeVisibilityProjectionLastAtMs = new Map();
  let lastAppliedColorTheme = null;

  function closePrimarySidebarAfterActivityLaunch() {
    for (const delayMs of [125, 350, 800, 1400]) {
      setTimeoutFn(() => {
        void vscode.commands
          .executeCommand("workbench.action.closeSidebar")
          .catch((error) => {
            consoleRef.error(
              "[IOI Workbench] Failed to close activity launcher sidebar:",
              error,
            );
          });
      }, delayMs);
    }
  }

  function writeModeVisibilityProjection(modeId, output, reason = "panel-visible") {
    const requestType = MODE_VISIBILITY_REQUEST_TYPES[modeId];
    const mode = AUTOPILOT_MODE_BY_ID[modeId];
    if (!requestType || !mode) {
      return false;
    }
    const now = Date.now();
    const lastAt = modeVisibilityProjectionLastAtMs.get(modeId) || 0;
    if (now - lastAt < 450) {
      return false;
    }
    modeVisibilityProjectionLastAtMs.set(modeId, now);
    const actionContext = buildWorkspaceActionContext(`${modeId}-${reason}`);
    void writeBridgeRequest(requestType, {
      workspaceRoot: workspaceSummary().path,
      sourceCommand: mode.command,
      source: reason,
      phase: mode.phase,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
    }, actionContext).catch((error) => {
      output?.appendLine?.(
        `[ioi-${modeId}] visible projection unavailable: ${error?.message || String(error)}`,
      );
    });
    return true;
  }

  function registerModePanelVisibilityProjection(panel, modeId, output) {
    const disposable = panel.onDidChangeViewState((event) => {
      if (event.webviewPanel.active) {
        writeModeVisibilityProjection(modeId, output);
      }
    });
    panel.onDidDispose(() => {
      disposable.dispose();
    });
    return disposable;
  }

  async function syncWorkbenchAppearance(state) {
    const colorTheme = state?.appearance?.openVsCodeColorTheme;
    if (typeof colorTheme !== "string" || !colorTheme.trim()) {
      return false;
    }
    const normalized = colorTheme.trim();
    if (normalized === lastAppliedColorTheme) {
      return false;
    }
    lastAppliedColorTheme = normalized;
    try {
      await vscode.workspace
        .getConfiguration("workbench")
        .update("colorTheme", normalized, vscode.ConfigurationTarget.Global);
      return true;
    } catch (error) {
      consoleRef.error("[IOI Workbench] Failed to apply bridge appearance:", error);
      return false;
    }
  }

  function watchBridgeState(onChange) {
    const handle = setIntervalFn(() => {
      void onChange();
    }, 2_000);
    return {
      dispose() {
        clearIntervalFn(handle);
      },
    };
  }

  class IOIViewProvider {
    constructor(definition, getState) {
      this.definition = definition;
      this.getState = getState;
      this.webviewView = null;
      this.lastRenderedHtml = null;
      this.primaryOpenInFlight = false;
      this.lastPrimaryOpenAtMs = 0;
    }

    resolveWebviewView(webviewView) {
      this.webviewView = webviewView;
      this.lastRenderedHtml = null;
      webviewView.webview.options = {
        enableScripts: true,
        enableForms: true,
      };
      void this.render();
      this.maybeAutoOpenPrimarySurface();
      webviewView.webview.onDidReceiveMessage(async (message) => {
        if (
          message?.type === "bridgeRequest" &&
          typeof message.requestType === "string"
        ) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("ioi.chat"),
          );
          return;
        }
        if (message?.type !== "command" || typeof message.command !== "string") {
          return;
        }
        await vscode.commands.executeCommand(message.command, message.payload);
      });
      const visibilityDisposable = webviewView.onDidChangeVisibility(() => {
        if (webviewView.visible) {
          this.maybeAutoOpenPrimarySurface();
        }
      });
      webviewView.onDidDispose(() => {
        visibilityDisposable.dispose();
        this.webviewView = null;
      });
    }

    maybeAutoOpenPrimarySurface() {
      const mode = AUTOPILOT_MODE_BY_VIEW_ID[this.definition.id];
      const primarySurface = mode
        ? {
            command: mode.command,
            payload: {
              source: "activitybar",
              phase: mode.phase,
            },
          }
        : null;
      if (!primarySurface) {
        return false;
      }
      const now = Date.now();
      if (this.primaryOpenInFlight || now - this.lastPrimaryOpenAtMs < 800) {
        return false;
      }
      this.primaryOpenInFlight = true;
      this.lastPrimaryOpenAtMs = now;
      setTimeoutFn(() => {
        void (async () => {
          try {
            closePrimarySidebarAfterActivityLaunch();
            await vscode.commands.executeCommand(
              primarySurface.command,
              primarySurface.payload,
            );
            closePrimarySidebarAfterActivityLaunch();
          } catch (error) {
            consoleRef.error(
              "[IOI Workbench] Failed to auto-open primary activity surface:",
              error,
            );
          } finally {
            this.primaryOpenInFlight = false;
          }
        })();
      }, 0);
      return true;
    }

    async render() {
      if (!this.webviewView) {
        return false;
      }
      const state = await this.getState();
      await syncWorkbenchAppearance(state);
      const html = renderHtml(this.definition, state);
      if (html === this.lastRenderedHtml) {
        return false;
      }
      this.lastRenderedHtml = html;
      this.webviewView.webview.html = html;
      return true;
    }
  }

  return {
    IOIViewProvider,
    closePrimarySidebarAfterActivityLaunch,
    registerModePanelVisibilityProjection,
    syncWorkbenchAppearance,
    watchBridgeState,
    writeModeVisibilityProjection,
  };
}

module.exports = {
  createWorkbenchPanelLifecycle,
};
