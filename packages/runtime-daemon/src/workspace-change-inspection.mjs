const WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION = "ioi.runtime.workspace-change-review.daemon.v1";

export function emptyWorkspaceChangeReviewSnapshot(threadId, sessionId) {
  return {
    schema_version: WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION,
    schemaVersion: WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION,
    thread_id: threadId,
    threadId,
    session_id: sessionId,
    sessionId,
    status: "empty",
    source: "daemon",
    workspace_change_reviews: [],
    workspaceChangeReviews: [],
    hunk_previews: [],
    hunkPreviews: [],
  };
}

export function normalizeWorkspaceChangeReviewInspection({
  bridgeResult,
  agent,
  threadId,
  sessionId,
} = {}) {
  const rawReviews = normalizeArray(bridgeResult?.workspace_change_reviews ?? bridgeResult?.workspaceChangeReviews);
  const rawChanges = normalizeArray(
    bridgeResult?.latest_trajectory?.workspace_changes ??
      bridgeResult?.latestTrajectory?.workspaceChanges ??
      bridgeResult?.workspace_changes ??
      bridgeResult?.workspaceChanges ??
      bridgeResult?.trajectory?.workspace_changes ??
      bridgeResult?.trajectory?.workspaceChanges,
  );
  const changesById = new Map(rawChanges.map((change) => [optionalString(change?.change_id ?? change?.changeId), change]));
  const hunkPreviews = rawReviews
    .map((review) => {
      const changeId = optionalString(review?.change_id ?? review?.changeId);
      const change = changesById.get(changeId) ?? rawChanges.find((candidate) => {
        const path = optionalString(candidate?.path);
        return path && path === optionalString(review?.path);
      });
      return hunkPreviewForReview(review, change);
    })
    .flat()
    .filter(Boolean);

  const status = hunkPreviews.length ? "ready" : rawReviews.length ? "metadata_only" : "empty";
  return {
    schema_version: WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION,
    schemaVersion: WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION,
    thread_id: threadId,
    threadId,
    session_id: sessionId,
    sessionId,
    runtime_profile: agent?.runtimeProfile ?? agent?.runtime_profile ?? "unknown",
    runtimeProfile: agent?.runtimeProfile ?? agent?.runtime_profile ?? "unknown",
    source: "daemon",
    status,
    workspace_change_reviews: rawReviews.map((review) => publicReviewState(review)),
    workspaceChangeReviews: rawReviews.map((review) => publicReviewState(review)),
    hunk_previews: hunkPreviews,
    hunkPreviews,
  };
}

function publicReviewState(review = {}) {
  return {
    change_id: optionalString(review.change_id ?? review.changeId),
    changeId: optionalString(review.change_id ?? review.changeId),
    lifecycle: optionalString(review.lifecycle),
    path: optionalString(review.path) || null,
    hunk_count: boundedInteger(review.hunk_count ?? review.hunkCount),
    hunkCount: boundedInteger(review.hunk_count ?? review.hunkCount),
    accept_available: Boolean(review.accept_available ?? review.acceptAvailable),
    acceptAvailable: Boolean(review.accept_available ?? review.acceptAvailable),
    reject_available: Boolean(review.reject_available ?? review.rejectAvailable),
    rejectAvailable: Boolean(review.reject_available ?? review.rejectAvailable),
    rollback_available: Boolean(review.rollback_available ?? review.rollbackAvailable),
    rollbackAvailable: Boolean(review.rollback_available ?? review.rollbackAvailable),
    stale: Boolean(review.stale),
    stale_reason: optionalString(review.stale_reason ?? review.staleReason) || null,
    staleReason: optionalString(review.stale_reason ?? review.staleReason) || null,
  };
}

function hunkPreviewForReview(review = {}, change = {}) {
  const publicReview = publicReviewState(review);
  const changeId = publicReview.changeId || optionalString(change?.change_id ?? change?.changeId);
  const file = publicReview.path || optionalString(change?.path) || "workspace";
  const lifecycle = publicReview.lifecycle || optionalString(change?.lifecycle, "proposed");
  const status = publicReview.stale
    ? "stale"
    : publicReview.acceptAvailable || publicReview.rejectAvailable
      ? "needs_review"
      : publicReview.rollbackAvailable
        ? "applied"
        : lifecycle || "observed";
  return normalizeArray(change?.hunks).map((hunk, index) => {
    const hunkIndex = boundedInteger(hunk?.hunk_index ?? hunk?.hunkIndex ?? index);
    const before = compactHunkText(hunk?.search_text ?? hunk?.searchText ?? "");
    const after = compactHunkText(hunk?.replace_text ?? hunk?.replaceText ?? hunk?.content_text ?? hunk?.contentText ?? "");
    const kind = optionalString(hunk?.kind, "edit");
    return {
      id: `${changeId || file}:hunk:${hunkIndex}`,
      change_id: changeId,
      changeId,
      file,
      title: `${humanizeLifecycle(status)} hunk ${hunkIndex + 1}`,
      status,
      lifecycle,
      kind,
      hunk_index: hunkIndex,
      hunkIndex,
      line_start: nullableInteger(hunk?.line_start ?? hunk?.lineStart),
      lineStart: nullableInteger(hunk?.line_start ?? hunk?.lineStart),
      line_end: nullableInteger(hunk?.line_end ?? hunk?.lineEnd),
      lineEnd: nullableInteger(hunk?.line_end ?? hunk?.lineEnd),
      before,
      after,
      beforeContent: before,
      afterContent: after,
      accept_available: publicReview.acceptAvailable,
      acceptAvailable: publicReview.acceptAvailable,
      reject_available: publicReview.rejectAvailable,
      rejectAvailable: publicReview.rejectAvailable,
      rollback_available: publicReview.rollbackAvailable,
      rollbackAvailable: publicReview.rollbackAvailable,
      stale: publicReview.stale,
      stale_reason: publicReview.staleReason,
      staleReason: publicReview.staleReason,
    };
  });
}

function humanizeLifecycle(value = "") {
  const normalized = optionalString(value, "workspace").replace(/[_-]+/g, " ");
  return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : "Workspace";
}

function compactHunkText(value = "") {
  const text = String(value ?? "");
  if (text.length <= 8000) return text;
  return `${text.slice(0, 8000)}\n...`;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function optionalString(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function boundedInteger(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : fallback;
}

function nullableInteger(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}
