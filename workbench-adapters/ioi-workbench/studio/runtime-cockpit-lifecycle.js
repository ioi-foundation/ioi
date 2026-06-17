"use strict";

function createStudioRuntimeCockpitLifecycle({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  commandOutputFromToolResponse,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection,
  invokeStudioDaemonTool,
  normalizeReceiptRefs,
  openStudioNativeDiffPreview,
  patchPreviewHunkFromToolResponse,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioReplayStepsFromProjection,
  requestAndDenyStudioPolicyLease,
  requestJson,
  studioApprovalTurnPayload,
  studioRuntimeCockpitPatchTargetFromPrompt,
  STUDIO_APPROVAL_ID = "studio-inline-diff-approval",
  STUDIO_POLICY_LEASE_ID = "studio-policy-lease",
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const receipts = typeof normalizeReceiptRefs === "function" ? normalizeReceiptRefs : () => [];

  async function projectStudioRuntimeCockpit(prompt, streamResult, output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const threadId = studioRuntimeProjection.threadId;
    if (!threadId) {
      appendStudioTimeline("Runtime cockpit blocked", "Daemon thread is not available.", "blocked");
      return;
    }
    const runtimeRefs = receipts(streamResult, streamResult?.turn, ...array(streamResult?.events));
    studioRuntimeProjection.runtimeCockpit.modelBackedStreamingObserved = Boolean(
      (streamResult?.providerStream && streamResult?.chunkCount > 0) ||
        runtimeRefs.length > 0 ||
        array(streamResult?.events).length > 0 ||
        studioRuntimeProjection.turnId,
    );
    try {
      await requestAndDenyStudioPolicyLease(threadId, output);
    } catch (error) {
      studioRuntimeProjection.policyLeases.push({
        id: STUDIO_POLICY_LEASE_ID,
        title: "Permission check blocked",
        status: "blocked",
        action: "shell.exec.destructive",
        reason: "Agent could not complete the permission check. Details are in Tracing.",
        didExecute: false,
        receiptRefs: [],
      });
      appendStudioTimeline("Policy lease blocked", error?.message || String(error), "blocked");
    }

    try {
      const diagnostics = await invokeStudioDaemonTool(
        threadId,
        "lsp.diagnostics",
        {
          commandId: "node.check",
          paths: ["workbench-adapters/ioi-workbench/extension.js"],
          timeoutMs: 15000,
          maxOutputBytes: 6000,
        },
        output,
        {
          title: "Sandbox diagnostics",
          detail: "Run node --check through daemon-owned diagnostics tooling.",
        },
      );
      const command = commandOutputFromToolResponse("lsp.diagnostics", diagnostics);
      studioRuntimeProjection.commandOutputs.push(command);
      studioRuntimeProjection.diagnosticGates.push({
        id: command.id,
        title: "Node syntax diagnostics gate",
        status: diagnostics.status || command.status || "completed",
        detail: `Exit ${command.exitCode ?? "recorded"} for ${command.label}.`,
        receiptRefs: command.receiptRefs,
      });
      studioRuntimeProjection.runtimeCockpit.sandboxCommandOutputStreamObserved = true;
      studioRuntimeProjection.runtimeCockpit.sandboxCommandReceiptObserved = command.receiptRefs.length > 0;
      studioRuntimeProjection.runtimeCockpit.diagnosticsTestGateObserved = true;
    } catch (error) {
      studioRuntimeProjection.commandOutputs.push({
        id: `diagnostics.blocked.${Date.now()}`,
        toolId: "lsp.diagnostics",
        label: "Diagnostics blocked",
        status: "blocked",
        stdout: "",
        stderr: error?.message || String(error),
        exitCode: 1,
        durationMs: null,
        receiptRefs: [],
      });
      appendStudioTimeline("Diagnostics blocked", error?.message || String(error), "blocked");
    }

    try {
      const patchTargetPath = studioRuntimeCockpitPatchTargetFromPrompt(prompt);
      const patchResponse = await invokeStudioDaemonTool(
        threadId,
        "file.apply_patch",
        {
          path: patchTargetPath,
          dryRun: true,
          edits: [
            {
              type: "append",
              text: [
                "",
                "function capitalize(part) {",
                "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
                "}",
                "",
                "export function normalizeRunStatusLabel(status) {",
                "  return String(status || 'unknown')",
                "    .split('_')",
                "    .filter(Boolean)",
                "    .map(capitalize)",
                "    .join(' ');",
                "}",
                "",
              ].join("\n"),
            },
          ],
        },
        output,
        {
          title: "Patch proposal dry-run",
          detail: "Daemon generated a dry-run patch preview; no workspace mutation occurred.",
        },
      );
      const existingHunkApproval = studioRuntimeProjection.approvals.find(
        (approvalItem) =>
          approvalItem.id === (studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID) &&
          /waiting|preview|pending/i.test(String(approvalItem.status || "")),
      );
      const approval = existingHunkApproval
        ? { approval_id: existingHunkApproval.id, receipt_refs: [] }
        : await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
            method: "POST",
            token: daemonRequestToken(),
            payload: {
              approval_id: STUDIO_APPROVAL_ID,
              reason: "Native inline diff preview requires explicit hunk decision.",
              action: "patch.apply.preview",
              tool_id: "studio.inline-diff",
              effect_class: "workspace_patch",
              risk_domain: "workspace",
              source: "agent_studio_runtime_cockpit",
              ...studioApprovalTurnPayload(),
            },
          });
      studioRuntimeProjection.hunkApprovalId = approval?.approval_id || approval?.approvalId || STUDIO_APPROVAL_ID;
      const hunk = patchPreviewHunkFromToolResponse(patchResponse, patchTargetPath);
      hunk.approvalId = studioRuntimeProjection.hunkApprovalId;
      studioRuntimeProjection.diffHunks = [hunk];
      await openStudioNativeDiffPreview(hunk, output);
      appendStudioReceiptsFromResponse(patchResponse, "patch_preview", "Daemon dry-run patch preview receipt.");
      appendStudioReceiptsFromResponse(approval, "approval_required", "Daemon requested hunk decision approval.");
    } catch (error) {
      studioRuntimeProjection.diffHunks = [
        {
          file: "README.md",
          title: "Patch preview blocked",
          status: "blocked",
          before: "- Native hunk loop unavailable.",
          after: `+ ${error?.message || String(error)}`,
        },
      ];
      appendStudioTimeline("Patch preview blocked", error?.message || String(error), "blocked");
    }

    try {
      const browserStatus = await requestJson(daemonEndpoint(), "/v1/computer-use/browser-discovery?probe=false&include_tabs=false", {
        token: daemonRequestToken(),
      });
      studioRuntimeProjection.browserCards.push({
        title: "Browser status",
        status: "observed",
        detail: `Daemon browser discovery projected ${array(browserStatus?.browsers).length || browserStatus?.count || 0} candidate browser surface(s).`,
      });
      studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
    } catch (error) {
      studioRuntimeProjection.browserCards.push({
        title: "Browser status blocker",
        status: "blocked",
        detail: error?.message || String(error),
      });
    }

    try {
      const worker = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          role: "reviewer",
          prompt: "Summarize Agent Studio runtime cockpit readiness without external connector action.",
          parent_turn_id: studioRuntimeProjection.turnId,
          model: studioRuntimeProjection.modelRoute,
        },
      });
      const refs = receipts(worker);
      studioRuntimeProjection.workerCards.push({
        title: "Worker / subagent status",
        status: worker?.status || "spawned",
        detail: `${worker?.id || worker?.subagent_id || "subagent"} spawned under daemon authority.`,
        receiptRefs: refs,
      });
      appendStudioReceiptsFromResponse(worker, "worker_spawn", "Daemon spawned runtime worker/subagent.");
      studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
    } catch (error) {
      studioRuntimeProjection.workerCards.push({
        title: "Worker / subagent blocker",
        status: "blocked",
        detail: error?.message || String(error),
        receiptRefs: [],
      });
    }

    refreshStudioReplayStepsFromProjection();
    recomputeStudioRuntimeCockpitAchieved();
    appendStudioTimeline(
      studioRuntimeProjection.runtimeCockpit.achieved ? "Runtime cockpit evidence ready" : "Runtime cockpit evidence incomplete",
      `prompt: ${prompt.slice(0, 80)}`,
      studioRuntimeProjection.runtimeCockpit.achieved ? "completed" : "blocked",
    );
  }

  return {
    projectStudioRuntimeCockpit,
  };
}

module.exports = {
  createStudioRuntimeCockpitLifecycle,
};
