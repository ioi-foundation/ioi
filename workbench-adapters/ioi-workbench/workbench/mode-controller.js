"use strict";

function createHypervisorModeController({
  HYPERVISOR_MODE_BY_ID,
  HYPERVISOR_MODE_BY_PANEL_VIEW_ID,
  HYPERVISOR_MODE_BY_VIEW_ID,
  vscode,
  initialModeId = "home",
} = {}) {
  let currentHypervisorModeId = initialModeId;
  let lastHypervisorModeBeforeCode = initialModeId === "code" ? "home" : initialModeId;

  function modeIdForViewId(viewId) {
    return (
      HYPERVISOR_MODE_BY_VIEW_ID[viewId]?.id ||
      HYPERVISOR_MODE_BY_PANEL_VIEW_ID[viewId]?.id ||
      null
    );
  }

  function currentModeId() {
    return currentHypervisorModeId;
  }

  function lastModeBeforeCode() {
    return lastHypervisorModeBeforeCode;
  }

  function setActiveHypervisorMode(modeId) {
    if (!HYPERVISOR_MODE_BY_ID[modeId]) {
      return;
    }
    if (modeId !== "code") {
      lastHypervisorModeBeforeCode = modeId;
    }
    currentHypervisorModeId = modeId;
  }

  async function applyWorkbenchChromeForMode(modeId, output) {
    const menuBarVisibility = modeId === "code" ? "classic" : "hidden";
    await vscode.commands
      .executeCommand("setContext", "ioi.hypervisorMode", modeId !== "code")
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

  async function enterHypervisorMode(modeId, output) {
    setActiveHypervisorMode(modeId);
    await applyWorkbenchChromeForMode(modeId, output);
  }

  return {
    applyWorkbenchChromeForMode,
    currentModeId,
    enterHypervisorMode,
    lastModeBeforeCode,
    modeIdForViewId,
    setActiveHypervisorMode,
  };
}

module.exports = {
  createHypervisorModeController,
};
