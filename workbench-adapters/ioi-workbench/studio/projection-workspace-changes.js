"use strict";

function createStudioWorkspaceChangeProjection({
  compactStudioWhitespace,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection,
  requestJson,
  stringValue,
  workspaceSummary,
}) {
  function applyStudioWorkspaceChangeReviewInspection(inspection = {}) {
    const projection = getStudioRuntimeProjection();
    const previews = firstArray(inspection.hunkPreviews || inspection.hunk_previews)
      .map((hunk, index) => ({
        id: stringValue(hunk.id, `workspace-hunk-${index}`),
        changeId: stringValue(hunk.changeId || hunk.change_id),
        hunkIndex: Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index,
        file: stringValue(hunk.file || hunk.path, "workspace"),
        title: stringValue(hunk.title, `Workspace hunk ${index + 1}`),
        status: stringValue(hunk.status || hunk.lifecycle, "needs_review"),
        lifecycle: stringValue(hunk.lifecycle),
        kind: stringValue(hunk.kind, "edit"),
        before: String(hunk.before ?? hunk.searchText ?? hunk.search_text ?? ""),
        after: String(hunk.after ?? hunk.replaceText ?? hunk.replace_text ?? hunk.contentText ?? hunk.content_text ?? ""),
        beforeContent: String(hunk.beforeContent ?? hunk.before ?? ""),
        afterContent: String(hunk.afterContent ?? hunk.after ?? ""),
        acceptAvailable: Boolean(hunk.acceptAvailable ?? hunk.accept_available),
        rejectAvailable: Boolean(hunk.rejectAvailable ?? hunk.reject_available),
        rollbackAvailable: Boolean(hunk.rollbackAvailable ?? hunk.rollback_available),
        stale: Boolean(hunk.stale),
        staleReason: stringValue(hunk.staleReason || hunk.stale_reason),
      }))
      .filter((hunk) => hunk.changeId || hunk.before || hunk.after);
    if (!previews.length) {
      return [];
    }
    projection.diffHunks = previews;
    projection.runtimeCockpit = projection.runtimeCockpit || {};
    projection.runtimeCockpit.inlineDiffOverlayObserved = true;
    projection.runtimeCockpit.hunkNavigationObserved = true;
    return previews;
  }

  async function refreshStudioWorkspaceChangeReviewsFromDaemon(output) {
    const endpoint = daemonEndpoint();
    const projection = getStudioRuntimeProjection();
    const threadId = stringValue(projection.threadId);
    if (!endpoint || !threadId) {
      return [];
    }
    try {
      const workspaceRoot = compactStudioWhitespace(workspaceSummary().path);
      const query = workspaceRoot && !/^open a workspace/i.test(workspaceRoot)
        ? `?workspaceRoot=${encodeURIComponent(workspaceRoot)}`
        : "";
      const inspection = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/workspace-change-reviews${query}`,
        {
          token: daemonRequestToken(),
          timeoutMs: 10000,
        },
      );
      return applyStudioWorkspaceChangeReviewInspection(inspection);
    } catch (error) {
      output?.appendLine?.(
        `[ioi-studio] workspace change review inspection unavailable: ${error?.message || String(error)}`,
      );
      return [];
    }
  }

  return {
    applyStudioWorkspaceChangeReviewInspection,
    refreshStudioWorkspaceChangeReviewsFromDaemon,
  };
}

module.exports = {
  createStudioWorkspaceChangeProjection,
};
