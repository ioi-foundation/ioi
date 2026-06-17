"use strict";

function createStudioHunkLifecycle({
  appendStudioReceipts,
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  ensureStudioDaemonThread,
  firstArray,
  getStudioRuntimeProjection,
  invokeStudioDaemonTool,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  refreshStudioWorkspaceChangeReviewsFromDaemon,
  requestJson,
  stringValue,
  studioApprovalTurnPayload,
  STUDIO_APPROVAL_ID = "studio-inline-diff-approval",
  uniqueStrings,
  vscode,
  writeBridgeRequest,
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const text = typeof stringValue === "function" ? stringValue : (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
  };
  const unique = typeof uniqueStrings === "function"
    ? uniqueStrings
    : (values = []) => [...new Set(array(values).filter((value) => typeof value === "string" && value.length > 0))];

  async function handleStudioHunkDecision(decision, payload = {}, output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const requestedDecision = text(decision).toLowerCase();
    const normalizedDecision = requestedDecision === "reject" || requestedDecision === "rollback"
      ? requestedDecision
      : "approve";
    try {
      await ensureStudioDaemonThread({ model: studioRuntimeProjection.modelRoute }, output);
      const endpoint = daemonEndpoint();
      const threadId = studioRuntimeProjection.threadId;
      const approvalId =
        text(payload.approvalId, studioRuntimeProjection.approvalId || STUDIO_APPROVAL_ID);
      const changeId = text(payload.changeId || payload.change_id);
      if (changeId) {
        const toolId = normalizedDecision === "rollback"
          ? "workspace_change__rollback"
          : normalizedDecision === "reject"
            ? "workspace_change__reject"
            : "workspace_change__accept";
        const result = await invokeStudioDaemonTool(
          threadId,
          toolId,
          normalizedDecision === "rollback"
            ? { change_id: changeId }
            : normalizedDecision === "approve"
              ? { change_id: changeId }
              : {
                  change_id: changeId,
                  reason: "Operator rejected the Studio inline diff hunk.",
                },
          output,
          {
            title: normalizedDecision === "rollback"
              ? "Rollback workspace hunk"
              : normalizedDecision === "approve"
                ? "Accept workspace hunk"
                : "Reject workspace hunk",
            detail: normalizedDecision === "rollback"
              ? "Daemon rolled back the selected workspace change."
              : normalizedDecision === "approve"
                ? "Daemon accepted the selected workspace change."
                : "Daemon rejected the selected workspace change.",
          },
        );
        studioRuntimeProjection.hunkDecision = normalizedDecision;
        studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
          ...hunk,
          status: hunk.changeId === changeId || hunk.change_id === changeId
            ? normalizedDecision === "approve"
              ? "approved"
              : normalizedDecision === "rollback"
              ? "rolled_back"
              : "rejected"
            : hunk.status,
        }));
        studioRuntimeProjection.approvals = [
          {
            id: approvalId,
            status: normalizedDecision === "approve"
              ? "approved"
              : normalizedDecision === "rollback"
                ? "rolled_back"
                : "rejected",
            label: normalizedDecision === "approve"
              ? "Workspace hunk accepted"
              : normalizedDecision === "rollback"
                ? "Workspace hunk rolled back"
                : "Workspace hunk rejected",
            detail: "Daemon workspace change lifecycle action completed.",
          },
        ];
        appendStudioReceiptsFromResponse(result, `workspace_change_${normalizedDecision}`, "Daemon workspace change lifecycle receipt.");
        studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
        recomputeStudioRuntimeCockpitAchieved();
        await writeBridgeRequest(
          "chat.hunkDecision",
          {
            ...payload,
            decision: normalizedDecision,
            approvalId,
            changeId,
            threadId,
            turnId: studioRuntimeProjection.turnId,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            ownsRuntimeState: false,
          },
          buildWorkspaceActionContext("agent-studio-inline-diff"),
        ).catch((error) => {
          output?.appendLine?.(`[ioi-studio] bridge hunk decision route unavailable: ${error?.message || String(error)}`);
        });
        await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
        await refreshStudioPanelHtml(output);
        return;
      }
      const result = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(approvalId)}/decision`,
        {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            decision: normalizedDecision,
            source: "agent_studio_inline_diff",
            reason: `Operator ${normalizedDecision === "approve" ? "accepted" : "rejected"} the Studio inline diff preview.`,
            ...studioApprovalTurnPayload(),
          },
        },
      );
      studioRuntimeProjection.hunkDecision = normalizedDecision;
      studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
        ...hunk,
        status: normalizedDecision === "approve" ? "approved" : "rejected",
      }));
      studioRuntimeProjection.approvals = [
        {
          id: approvalId,
          status: normalizedDecision === "approve" ? "approved" : "rejected",
          label: "Inline diff decision",
          detail: "Daemon approval decision receipt emitted; no direct webview mutation occurred.",
        },
      ];
      studioRuntimeProjection.timeline.push({
        label: "Hunk decision receipted",
        detail: `${approvalId} · ${normalizedDecision}`,
        status: normalizedDecision === "approve" ? "completed" : "blocked",
      });
      appendStudioReceipts(
        unique([
          ...array(result?.receipt_refs),
          ...array(result?.receiptRefs),
        ]).map((id) => ({
          id,
          kind: `approval_${normalizedDecision}`,
          summary: "Daemon approval decision receipt for Studio inline diff hunk.",
        })),
      );
      studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
      recomputeStudioRuntimeCockpitAchieved();
      await writeBridgeRequest(
        "chat.hunkDecision",
        {
          ...payload,
          decision: normalizedDecision,
          approvalId,
          threadId,
          turnId: studioRuntimeProjection.turnId,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
          ownsRuntimeState: false,
        },
        buildWorkspaceActionContext("agent-studio-inline-diff"),
      ).catch((error) => {
        output?.appendLine?.(`[ioi-studio] bridge hunk decision route unavailable: ${error?.message || String(error)}`);
      });
    } catch (error) {
      studioRuntimeProjection.timeline.push({
        label: "Hunk decision blocked",
        detail: error?.message || String(error),
        status: "blocked",
      });
    }
    await refreshStudioPanelHtml(output);
  }

  async function navigateStudioHunk(direction, output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
    const command = direction === "previous"
      ? "workbench.action.compareEditor.previousChange"
      : "workbench.action.compareEditor.nextChange";
    await vscode.commands.executeCommand(command).catch((error) => {
      output?.appendLine?.(`[ioi-studio] native hunk navigation unavailable: ${error?.message || String(error)}`);
    });
    studioRuntimeProjection.runtimeCockpit.hunkNavigationObserved = true;
    recomputeStudioRuntimeCockpitAchieved();
    appendStudioTimeline("Native hunk navigation", direction === "previous" ? "previous change" : "next change", "completed");
    await refreshStudioPanelHtml(output);
  }

  return {
    handleStudioHunkDecision,
    navigateStudioHunk,
  };
}

module.exports = {
  createStudioHunkLifecycle,
};
