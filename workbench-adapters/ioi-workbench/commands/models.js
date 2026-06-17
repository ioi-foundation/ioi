"use strict";

function registerModelCommands({
  vscode,
  status,
  buildWorkspaceActionContext,
  writeBridgeRequest,
  workspaceSummary,
  pickString,
  pickPayloadString,
  daemonEndpoint,
  enterModels,
  enterWorkflows,
  openModelsPanel,
  openWorkflowComposerPanel,
  closePrimarySidebarAfterActivityLaunch,
  runDaemonModelWorkbenchAction,
  runDaemonModelCatalogSearch,
  runDaemonModelCatalogProviderConfig,
  runDaemonModelCatalogDownload,
}) {
  return [
    vscode.commands.registerCommand("ioi.models.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      const phase = pickString(payload, "phase") || "model-library";
      await enterModels();
      await openModelsPanel({ phase });
      await writeBridgeRequest("models.open", {
        workspaceRoot: workspaceSummary().path,
        phase,
        daemonEndpointConfigured: Boolean(daemonEndpoint()),
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        tauriUsed: false,
      }, contextSnapshot);
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Hypervisor Models.");
    }),
    vscode.commands.registerCommand("ioi.models.openLoader", async (payload = {}) => {
      const modelId = pickString(payload, "modelId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models"),
        modelId,
      };
      await enterModels();
      await openModelsPanel({ phase: "model-mount-drawer" });
      await writeBridgeRequest("models.loader.open", {
        workspaceRoot: workspaceSummary().path,
        modelId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        webviewExecutesModel: false,
        extensionHostOwnsDurableRuntime: false,
      }, contextSnapshot);
      status("Opened daemon model loader.");
    }),
    vscode.commands.registerCommand("ioi.models.selectForWorkflow", async (payload = {}) => {
      const modelId = pickString(payload, "modelId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models-workflow-binding"),
        modelId,
      };
      await writeBridgeRequest("models.workflowBinding.select", {
        workspaceRoot: workspaceSummary().path,
        modelId,
        routeId: pickString(payload, "routeId") || "route.native-local",
        runtimeAuthority: "daemon-owned",
        externalConnectorAction: false,
      }, contextSnapshot);
      await enterWorkflows();
      openWorkflowComposerPanel({
        scenarioId: "model-backed-dry-run",
        phase: "model-binding",
      });
      status("Queued live model route binding for Workflow Composer.");
    }),
    vscode.commands.registerCommand("ioi.models.capturePhase", async (payload = {}) => {
      const phase = pickString(payload, "phase") || "model-library";
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models"),
        phase,
      };
      await enterModels();
      await openModelsPanel({ phase });
      await writeBridgeRequest("models.capturePhase", {
        workspaceRoot: workspaceSummary().path,
        phase,
        externalAction: false,
      }, contextSnapshot);
      status(`Capturing Models phase: ${phase}.`);
    }),
    vscode.commands.registerCommand("ioi.models.searchCatalog", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-search");
      await enterModels();
      const result = await runDaemonModelCatalogSearch(payload);
      await writeBridgeRequest("models.catalog.search", {
        workspaceRoot: workspaceSummary().path,
        query: pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "",
        resultCount: Array.isArray(result?.results) ? result.results.length : 0,
        providers: Array.isArray(result?.providers) ? result.providers : [],
        daemonOwned: true,
        externalAction: false,
      }, contextSnapshot);
      await openModelsPanel({ phase: "model-discovery-surface" });
      status("Daemon model catalog search complete.");
    }),
    vscode.commands.registerCommand("ioi.models.configureCatalogProvider", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-source-config");
      await enterModels();
      const result = await runDaemonModelCatalogProviderConfig(payload);
      const query = pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "";
      let searchResult = null;
      if (query) {
        searchResult = await runDaemonModelCatalogSearch({ query }).catch((error) => ({
          error: error?.message || String(error),
          results: [],
        }));
      }
      await writeBridgeRequest("models.catalog.provider.configure", {
        workspaceRoot: workspaceSummary().path,
        providerId: pickPayloadString(payload, "providerId") || pickPayloadString(payload, "provider_id") || "catalog.huggingface",
        result,
        searchResultCount: Array.isArray(searchResult?.results) ? searchResult.results.length : 0,
        daemonOwned: true,
        externalAction: false,
      }, contextSnapshot);
      await openModelsPanel({ phase: query ? "model-discovery-surface" : "model-catalog-sources-surface" });
      status("Daemon catalog source configuration saved.");
    }),
    vscode.commands.registerCommand("ioi.models.downloadCatalog", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-download");
      await enterModels();
      const result = await runDaemonModelCatalogDownload(payload);
      await writeBridgeRequest("models.catalog.download", {
        workspaceRoot: workspaceSummary().path,
        modelId: pickPayloadString(payload, "modelId") || null,
        catalogEntryId: pickPayloadString(payload, "catalogEntryId") || null,
        result,
        receiptId: result?.receiptId ?? result?.receipt?.id ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel({ phase: "model-discovery-surface" });
      status("Daemon model catalog download queued.");
    }),
    vscode.commands.registerCommand("ioi.models.estimateNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterModels();
      const result = await runDaemonModelWorkbenchAction("estimate", payload);
      await writeBridgeRequest("models.estimateLoad", {
        workspaceRoot: workspaceSummary().path,
        result,
        receiptId: result?.receiptId ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel({ phase: "model-load-estimate" });
      status("Daemon model load estimate complete.");
    }),
    vscode.commands.registerCommand("ioi.models.loadNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterModels();
      const result = await runDaemonModelWorkbenchAction("load", payload);
      await writeBridgeRequest("models.load", {
        workspaceRoot: workspaceSummary().path,
        result,
        instanceId: result?.id ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel({ phase: "model-instance-ready" });
      status("Daemon model load complete.");
    }),
    vscode.commands.registerCommand("ioi.models.unloadNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterModels();
      const result = await runDaemonModelWorkbenchAction("unload", payload);
      await writeBridgeRequest("models.unload", {
        workspaceRoot: workspaceSummary().path,
        result,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel({ phase: "model-instance-ready" });
      status("Daemon model unload complete.");
    }),
  ];
}

module.exports = {
  registerModelCommands,
};
