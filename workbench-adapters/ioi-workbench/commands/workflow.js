"use strict";

function registerWorkflowCommands({
  crypto,
  vscode,
  status,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  workspaceSummary,
  pickString,
  enterWorkflows,
  openWorkflowComposerPanel,
  closePrimarySidebarAfterActivityLaunch,
  buildRuntimeRefs,
}) {
  return [
    vscode.commands.registerCommand("ioi.workflow.openComposer", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("workflow-composer");
      const scenarioId = pickString(payload, "scenarioId");
      const phase = pickString(payload, "phase") || "canvas";
      await enterWorkflows();
      openWorkflowComposerPanel({
        scenarioId,
        phase,
      });
      await writeBridgeRequest("workflow.composer.open", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        realWorkflowComposerMounted: true,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        externalAction: false,
      }, contextSnapshot);
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Hypervisor Workflow Composer.");
    }),
    vscode.commands.registerCommand("ioi.workflow.compositor.runScenario", async (payload = {}) => {
      const scenarioId = pickString(payload, "scenarioId") || "sequential";
      const phase = pickString(payload, "phase") || "canvas";
      const contextSnapshot = {
        ...buildWorkspaceActionContext("workflow-compositor-parity"),
        scenarioId,
        phase,
      };
      await enterWorkflows();
      openWorkflowComposerPanel({
        scenarioId,
        phase,
      });
      await writeBridgeRequest("workflowCompositor.scenarioCommand", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        createdThroughGui: true,
        manualFileEdits: false,
        externalAction: false,
      }, contextSnapshot);
      status(`Running Workflow Composer scenario: ${scenarioId}.`);
    }),
    vscode.commands.registerCommand("ioi.workflow.compositor.capturePhase", async (payload = {}) => {
      const phase = pickString(payload, "phase") || "canvas";
      const scenarioId = pickString(payload, "scenarioId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("workflow-compositor-parity"),
        scenarioId,
        phase,
      };
      await enterWorkflows();
      openWorkflowComposerPanel({
        scenarioId,
        phase,
        capturePhase: phase,
      });
      await writeBridgeRequest("workflowCompositor.capturePhaseCommand", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        externalAction: false,
      }, contextSnapshot);
      status(`Capturing Workflow Composer phase: ${phase}.`);
    }),
    vscode.commands.registerCommand("ioi.workflow.new", async (payload = {}) => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterWorkflows();
      openWorkflowComposerPanel({
        scenarioId: pickString(payload, "scenarioId"),
        phase: pickString(payload, "phase") || "canvas",
      });
      await writeBridgeRequest("workflow.open", {
        workspaceRoot: workspaceSummary().path,
        workflowId: pickString(payload, "workflowId"),
        realWorkflowComposerMounted: true,
      }, actionContext);
      status("Opened IOI workflow composer.");
    }),
    vscode.commands.registerCommand("ioi.workflow.generateCode", async (payload) => {
      const workflowRef =
        pickString(payload, "workflowRef") ||
        pickString(payload, "workflowId") ||
        "workflow:active";
      const packageRef = pickString(payload, "packageRef") || "package:active";
      const modelCapabilityRef =
        pickString(payload, "modelCapabilityRef") || "model-capability:unbound";
      const toolCapabilityRefs = Array.isArray(payload?.toolCapabilityRefs)
        ? payload.toolCapabilityRefs.filter((value) => typeof value === "string")
        : [];
      const request = {
        schemaVersion: "ioi.workbench-integration.v1",
        requestId: crypto.randomUUID(),
        runtimeTruthSource: "daemon-runtime",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        requestedAtMs: Date.now(),
        workflowRef,
        packageRef,
        goal:
          pickString(payload, "goal") ||
          "Generate a proposal-first code change from this workflow.",
        boundModelCapabilityRef: modelCapabilityRef,
        boundToolCapabilityRefs: toolCapabilityRefs,
        targetWorkspace: workspaceSummary().path,
        authorityScope: "workspace.fs.proposal",
        evalProfileRef: pickString(payload, "evalProfileRef"),
        proposalOnly: true,
        runtimeRefs: buildRuntimeRefs(),
      };
      const context = {
        ...buildWorkspaceActionContext("workflow-code-generation"),
        workflowRef,
        packageRef,
      };
      await writeBridgeRequest("workflow.codeGenerationRequest", request, context);
      status("Queued proposal-first workflow code generation.");
    }),
  ];
}

module.exports = {
  registerWorkflowCommands,
};
