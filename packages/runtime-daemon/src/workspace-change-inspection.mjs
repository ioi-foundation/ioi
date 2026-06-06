const WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION = "ioi.runtime.workspace-change-review.daemon.v1";

export function emptyWorkspaceChangeReviewSnapshot(threadId, sessionId) {
  return {
    schema_version: WORKSPACE_CHANGE_REVIEW_SCHEMA_VERSION,
    thread_id: threadId,
    session_id: sessionId,
    status: "empty",
    source: "daemon",
    workspace_change_reviews: [],
    hunk_previews: [],
  };
}

export function normalizeWorkspaceChangeReviewInspection({
  bridge_result,
  agent,
  threadId,
  sessionId,
} = {}) {
  const rawReviews = normalizeArray(bridge_result?.workspace_change_reviews);
  const rawChanges = normalizeArray(
    bridge_result?.latest_trajectory?.workspace_changes ??
      bridge_result?.trajectory?.workspace_changes,
  );
  const changesById = new Map(rawChanges.map((change) => [optionalString(change?.change_id), change]));
  const hunkPreviews = rawReviews
    .map((review) => {
      const changeId = optionalString(review?.change_id);
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
    thread_id: threadId,
    session_id: sessionId,
    runtime_profile: agent?.runtime_profile ?? "unknown",
    source: "daemon",
    status,
    workspace_change_reviews: rawReviews.map((review) => publicReviewState(review)),
    hunk_previews: hunkPreviews,
  };
}

function publicReviewState(review = {}) {
  return {
    change_id: optionalString(review.change_id),
    lifecycle: optionalString(review.lifecycle),
    path: optionalString(review.path) || null,
    hunk_count: boundedInteger(review.hunk_count),
    accept_available: Boolean(review.accept_available),
    reject_available: Boolean(review.reject_available),
    rollback_available: Boolean(review.rollback_available),
    stale: Boolean(review.stale),
    stale_reason: optionalString(review.stale_reason) || null,
  };
}

function hunkPreviewForReview(review = {}, change = {}) {
  const publicReview = publicReviewState(review);
  const changeId = publicReview.change_id || optionalString(change?.change_id);
  const file = publicReview.path || optionalString(change?.path) || "workspace";
  const lifecycle = publicReview.lifecycle || optionalString(change?.lifecycle, "proposed");
  const status = publicReview.stale
    ? "stale"
    : publicReview.accept_available || publicReview.reject_available
      ? "needs_review"
      : publicReview.rollback_available
        ? "applied"
        : lifecycle || "observed";
  return normalizeArray(change?.hunks).map((hunk, index) => {
    const hunkIndex = boundedInteger(hunk?.hunk_index ?? index);
    const before = compactHunkText(hunk?.search_text ?? "");
    const after = compactHunkText(hunk?.replace_text ?? hunk?.content_text ?? "");
    const kind = optionalString(hunk?.kind, "edit");
    return {
      id: `${changeId || file}:hunk:${hunkIndex}`,
      change_id: changeId,
      file,
      title: `${humanizeLifecycle(status)} hunk ${hunkIndex + 1}`,
      status,
      lifecycle,
      kind,
      hunk_index: hunkIndex,
      line_start: nullableInteger(hunk?.line_start),
      line_end: nullableInteger(hunk?.line_end),
      before,
      after,
      accept_available: publicReview.accept_available,
      reject_available: publicReview.reject_available,
      rollback_available: publicReview.rollback_available,
      stale: publicReview.stale,
      stale_reason: publicReview.stale_reason,
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
