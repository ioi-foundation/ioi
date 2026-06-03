"use strict";

function testHooksEnabled() {
  return process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS === "1";
}

function registerStudioTestHookCommands({
  vscode,
  output,
  status,
  enterStudio,
  openStudioPanel,
  refreshStudioPanelHtml,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  applyStudioAgentTurnEvents,
  firstArray,
  stringValue,
  normalizeReceiptRefs,
  studioRuntimeProjection,
  refreshStudioReplayStepsFromProjection,
  exerciseStudioPolicyLeaseLifecycle,
  exerciseStudioSessionBrainLifecycle,
  exerciseStudioTrajectoryReplayReconnect,
  exerciseStudioManagedSessionReconnect,
  exerciseStudioStage2WebRepairLoop,
  exerciseStudioStage5StopHookRepairLoop,
  exerciseStudioStage5StopCancelRecoverLifecycle,
  exerciseStudioStage7DelegationLifecycle,
}) {
  const requireHooks = (message) => {
    if (testHooksEnabled()) return true;
    output.appendLine(message);
    return false;
  };
  return [
    vscode.commands.registerCommand("ioi.studio.injectParityPlusEvents", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] parity-plus event injection refused outside test hooks.")) {
        return;
      }
      const events = firstArray(payload?.events);
      const turns = firstArray(payload?.turns);
      if (events.length === 0 && turns.length === 0) {
        output.appendLine("[ioi-studio] parity-plus event injection skipped: no events or turns provided.");
        return;
      }
      const contextSnapshot = buildWorkspaceActionContext("studio-parity-plus-hydration");
      await enterStudio();
      await openStudioPanel();
      applyStudioAgentTurnEvents(events);
      for (const turn of turns) {
        if (turn && typeof turn === "object") {
          studioRuntimeProjection.turns.push({
            role: stringValue(turn.role, "assistant"),
            content: stringValue(turn.content || turn.text, ""),
            createdAt: stringValue(turn.createdAt || turn.created_at, new Date().toISOString()),
            outputRenderers: firstArray(turn.outputRenderers || turn.output_renderers),
            receiptRefs: normalizeReceiptRefs(turn),
          });
        }
      }
      refreshStudioReplayStepsFromProjection();
      studioRuntimeProjection.status = payload?.status || "completed";
      await refreshStudioPanelHtml();
      await writeBridgeRequest("studio.parityPlusEvents.injected", {
        sourceCommand: "ioi.studio.injectParityPlusEvents",
        eventCount: events.length,
        turnCount: turns.length,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] parity-plus injection bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Injected Agent Studio parity-plus runtime events.");
    }),
    vscode.commands.registerCommand("ioi.studio.exercisePolicyLeaseLifecycle", async () => {
      if (!requireHooks("[ioi-studio] policy lease lifecycle exercise refused outside test hooks.")) {
        return;
      }
      const contextSnapshot = buildWorkspaceActionContext("studio-policy-lease-lifecycle");
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioPolicyLeaseLifecycle(output);
      await refreshStudioPanelHtml();
      await writeBridgeRequest("studio.policyLeaseLifecycle.exercised", {
        sourceCommand: "ioi.studio.exercisePolicyLeaseLifecycle",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        ...lifecycleProof,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] policy lease lifecycle bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status(lifecycleProof.passed ? "Exercised Studio policy lease lifecycle." : "Studio policy lease lifecycle proof is incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseSessionBrainLifecycle", async () => {
      if (!requireHooks("[ioi-studio] session brain lifecycle exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioSessionBrainLifecycle(output);
      await refreshStudioPanelHtml();
      status(lifecycleProof.passed
        ? "Exercised Agent Studio run brain lifecycle."
        : "Agent Studio run brain lifecycle proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseTrajectoryReplayReconnect", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] trajectory replay reconnect exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioTrajectoryReplayReconnect(output, payload);
      await refreshStudioPanelHtml();
      status(lifecycleProof.passed
        ? "Exercised Agent Studio trajectory replay reconnect."
        : "Agent Studio trajectory replay reconnect proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseManagedSessionReconnect", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] managed session reconnect exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioManagedSessionReconnect(output, payload);
      await refreshStudioPanelHtml();
      status(lifecycleProof.passed
        ? "Exercised Agent Studio managed session reconnect."
        : "Agent Studio managed session reconnect proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage2WebRepairLoop", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] stage2 web repair loop exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const repairProof = await exerciseStudioStage2WebRepairLoop(output, payload);
      await refreshStudioPanelHtml();
      status(repairProof.passed
        ? "Exercised Agent Studio Stage 2 web repair loop."
        : "Agent Studio Stage 2 web repair loop proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage5StopHookRepairLoop", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] stage5 stop-hook repair loop exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const repairProof = await exerciseStudioStage5StopHookRepairLoop(output, payload);
      await refreshStudioPanelHtml();
      status(repairProof.passed
        ? "Exercised Agent Studio Stage 5 stop-hook repair loop."
        : "Agent Studio Stage 5 stop-hook repair loop proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage5StopCancelRecoverLifecycle", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] stage5 stop/cancel/recover exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioStage5StopCancelRecoverLifecycle(output, payload);
      await refreshStudioPanelHtml();
      status(lifecycleProof.passed
        ? "Exercised Agent Studio Stage 5 stop/cancel/recover lifecycle."
        : "Agent Studio Stage 5 stop/cancel/recover proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage7DelegationLifecycle", async (payload = {}) => {
      if (!requireHooks("[ioi-studio] stage7 delegation exercise refused outside test hooks.")) {
        return;
      }
      await enterStudio();
      await openStudioPanel();
      const lifecycleProof = await exerciseStudioStage7DelegationLifecycle(output, payload);
      await refreshStudioPanelHtml();
      status(lifecycleProof.passed
        ? "Exercised Agent Studio Stage 7 delegation lifecycle."
        : "Agent Studio Stage 7 delegation proof incomplete.");
    }),
  ];
}

module.exports = {
  registerStudioTestHookCommands,
};
