import type {
  ExecutionEnvelope,
  SwarmChangeReceipt,
  SwarmWorkerReceipt,
} from "../../../types";

export type ChatExecutionPreview = {
  label: string;
  content: string;
  status: string;
  kind?: string | null;
  language?: string | null;
  isFinal: boolean;
} | null;

function formatStatusLabel(value: string | null | undefined): string {
  const normalized = (value || "").trim().replace(/[_-]+/g, " ");
  if (!normalized) {
    return "";
  }
  return normalized.replace(/\b\w/g, (character) => character.toUpperCase());
}

export function formatChatExecutionPreviewPhase(
  preview:
    | {
        kind?: string | null;
        status?: string | null;
        isFinal?: boolean | null;
      }
    | null
    | undefined,
): string {
  const status = formatStatusLabel(preview?.status) || "Streaming";
  const normalized = String(preview?.status || "").trim().toLowerCase();
  if (!preview) {
    return "";
  }
  if ((preview.kind || "").trim().toLowerCase() === "token_stream") {
    if (normalized === "completed") {
      return "Completed stream";
    }
    if (normalized === "interrupted") {
      return "Interrupted stream";
    }
    if (normalized === "continuing") {
      return "Completing draft";
    }
    if (normalized === "repairing") {
      return "Repairing draft";
    }
    if (normalized === "recovered") {
      return "Recovered stream";
    }
    if (normalized === "failed") {
      return "Stream recovery failed";
    }
  }
  if (normalized === "completed") {
    return preview.isFinal ? `${status} final` : status;
  }
  if (normalized === "streaming") {
    return preview.isFinal ? status : `${status} live`;
  }
  return status;
}

function mapExecutionPreview(preview: {
  label?: string | null;
  content?: string | null;
  status?: string | null;
  kind?: string | null;
  language?: string | null;
  isFinal?: boolean | null;
} | null | undefined): ChatExecutionPreview {
  if (typeof preview?.content !== "string" || preview.content.trim().length === 0) {
    return null;
  }
  return {
    label: preview.label || "Live coding stream",
    content: preview.content,
    status: formatStatusLabel(preview.status) || "Streaming",
    kind: preview.kind || null,
    language: preview.language || null,
    isFinal: Boolean(preview.isFinal),
  };
}

function latestSortedLivePreviews(executionEnvelope?: ExecutionEnvelope | null) {
  return [...(executionEnvelope?.livePreviews ?? [])]
    .filter(
      (preview) =>
        typeof preview?.content === "string" && preview.content.trim().length > 0,
    )
    .sort((left, right) =>
      String(left?.updatedAt || "").localeCompare(String(right?.updatedAt || "")),
    );
}

function latestCanonicalExecutionPreview(executionEnvelope?: ExecutionEnvelope | null) {
  return latestSortedLivePreviews(executionEnvelope)
    .filter((preview) => preview.kind === "change_preview")
    .at(-1);
}

export function resolveChatExecutionStreamPreview({
  executionEnvelope,
  workerReceipts = [],
  changeReceipts = [],
}: {
  executionEnvelope?: ExecutionEnvelope | null;
  workerReceipts?: SwarmWorkerReceipt[] | null;
  changeReceipts?: SwarmChangeReceipt[] | null;
}): ChatExecutionPreview {
  const latestCanonicalPreview = latestCanonicalExecutionPreview(executionEnvelope);
  const latestLivePreview = latestSortedLivePreviews(executionEnvelope)
    .filter((preview) => preview.kind !== "change_preview")
    .at(-1);
  if (
    latestCanonicalPreview &&
    latestLivePreview?.kind === "token_stream" &&
    latestLivePreview.isFinal
  ) {
    return null;
  }
  const latestWorkerPreview = [...(workerReceipts ?? [])]
    .reverse()
    .find(
      (receipt) =>
        typeof receipt?.outputPreview === "string" &&
        receipt.outputPreview.trim().length > 0,
    );
  const latestChangePreview = [...(changeReceipts ?? [])]
    .reverse()
    .find(
      (receipt) =>
        typeof receipt?.preview === "string" && receipt.preview.trim().length > 0,
    );

  return (
    mapExecutionPreview(latestLivePreview) ??
    mapExecutionPreview(
      latestWorkerPreview
        ? {
            label:
              `${formatStatusLabel(latestWorkerPreview.role)} output` ||
              "Latest worker output",
            content: latestWorkerPreview.outputPreview,
            status: latestWorkerPreview.status,
            kind: "worker_output",
            language: latestWorkerPreview.previewLanguage,
            isFinal: true,
          }
        : null,
    ) ??
    mapExecutionPreview(
      latestChangePreview
        ? {
            label: `${latestChangePreview.workItemId} change preview`,
            content: latestChangePreview.preview,
            status: latestChangePreview.status,
            kind: "change_preview",
            language: latestChangePreview.previewLanguage,
            isFinal: true,
          }
        : null,
    )
  );
}

export function resolveChatExecutionCodePreview({
  executionEnvelope,
  workerReceipts = [],
  changeReceipts = [],
}: {
  executionEnvelope?: ExecutionEnvelope | null;
  workerReceipts?: SwarmWorkerReceipt[] | null;
  changeReceipts?: SwarmChangeReceipt[] | null;
}): ChatExecutionPreview {
  const latestCanonicalPreview = latestCanonicalExecutionPreview(executionEnvelope);
  const latestChangePreview = [...(changeReceipts ?? [])]
    .reverse()
    .find(
      (receipt) =>
        typeof receipt?.preview === "string" && receipt.preview.trim().length > 0,
    );
  const latestWorkerPreview = [...(workerReceipts ?? [])]
    .reverse()
    .find(
      (receipt) =>
        typeof receipt?.outputPreview === "string" &&
        receipt.outputPreview.trim().length > 0,
    );

  return (
    mapExecutionPreview(latestCanonicalPreview) ??
    mapExecutionPreview(
      latestChangePreview
        ? {
            label: `${latestChangePreview.workItemId} merged code`,
            content: latestChangePreview.preview,
            status: latestChangePreview.status,
            kind: "change_preview",
            language: latestChangePreview.previewLanguage,
            isFinal: true,
          }
        : null,
    ) ??
    mapExecutionPreview(
      latestWorkerPreview
        ? {
            label:
              `${formatStatusLabel(latestWorkerPreview.role)} output` ||
              "Latest worker output",
            content: latestWorkerPreview.outputPreview,
            status: latestWorkerPreview.status,
            kind: "worker_output",
            language: latestWorkerPreview.previewLanguage,
            isFinal: true,
          }
        : null,
    )
  );
}

export function resolveChatExecutionPreview({
  executionEnvelope,
  workerReceipts = [],
  changeReceipts = [],
}: {
  executionEnvelope?: ExecutionEnvelope | null;
  workerReceipts?: SwarmWorkerReceipt[] | null;
  changeReceipts?: SwarmChangeReceipt[] | null;
}): ChatExecutionPreview {
  return (
    resolveChatExecutionCodePreview({
      executionEnvelope,
      workerReceipts,
      changeReceipts,
    }) ??
    resolveChatExecutionStreamPreview({
      executionEnvelope,
      workerReceipts,
      changeReceipts,
    })
  );
}
