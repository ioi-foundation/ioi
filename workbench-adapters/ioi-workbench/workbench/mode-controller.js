"use strict";

function createAutopilotModeController({
  AUTOPILOT_MODE_BY_ID,
  AUTOPILOT_MODE_BY_PANEL_VIEW_ID,
  AUTOPILOT_MODE_BY_VIEW_ID,
  vscode,
  initialModeId = "home",
} = {}) {
  let currentAutopilotModeId = initialModeId;
  let lastAutopilotModeBeforeCode = initialModeId === "code" ? "home" : initialModeId;

  function modeIdForViewId(viewId) {
    return (
      AUTOPILOT_MODE_BY_VIEW_ID[viewId]?.id ||
      AUTOPILOT_MODE_BY_PANEL_VIEW_ID[viewId]?.id ||
      null
    );
  }

  function currentModeId() {
    return currentAutopilotModeId;
  }

  function lastModeBeforeCode() {
    return lastAutopilotModeBeforeCode;
  }

  function setActiveAutopilotMode(modeId) {
    if (!AUTOPILOT_MODE_BY_ID[modeId]) {
      return;
    }
    if (modeId !== "code") {
      lastAutopilotModeBeforeCode = modeId;
    }
    currentAutopilotModeId = modeId;
  }

  async function applyWorkbenchChromeForMode(modeId, output) {
    const menuBarVisibility = modeId === "code" ? "classic" : "hidden";
    await vscode.commands
      .executeCommand("setContext", "ioi.autopilotMode", modeId !== "code")
      .catch(() => undefined);
    await vscode.commands
      .executeCommand("setContext", "ioi.codeMode", modeId === "code")
      .catch(() => undefined);
    await vscode.workspace
      .getConfiguration("window")
      .update("menuBarVisibility", menuBarVisibility, vscode.ConfigurationTarget.Global)
      .catch((error) => {
        output?.appendLine(
          `[ioi-workbench] unable to update global VS Code menu bar visibility: ${
            error?.message || String(error)
          }`,
        );
      });
  }

  async function enterAutopilotMode(modeId, output) {
    setActiveAutopilotMode(modeId);
    await applyWorkbenchChromeForMode(modeId, output);
  }

  return {
    applyWorkbenchChromeForMode,
    currentModeId,
    enterAutopilotMode,
    lastModeBeforeCode,
    modeIdForViewId,
    setActiveAutopilotMode,
  };
}

module.exports = {
  createAutopilotModeController,
};
