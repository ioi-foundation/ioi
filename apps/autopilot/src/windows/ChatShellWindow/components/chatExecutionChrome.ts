import type {
  ExecutionEnvelope,
  WorkGraphChangeReceipt,
  WorkGraphExecutionSummary,
  WorkGraphPlan,
  WorkGraphWorkerReceipt,
} from "../../../types";
import {
  resolveChatExecutionCodePreview,
  resolveChatExecutionStreamPreview,
  type ChatExecutionPreview,
} from "./chatExecutionPreview";

export type ChatExecutionMetrics = {
  stage?: string | null;
  activeRole?: string | null;
  progress?: string | null;
  verification?: string | null;
} | null;

export type ChatExecutionProcess = {
  id: string;
  label: string;
  status: string;
  summary: string;
  isActive?: boolean;
  iconKey?: string | null;
};

export type ChatExecutionChrome = {
  metrics: ChatExecutionMetrics;
  processes: ChatExecutionProcess[];
  livePreview: ChatExecutionPreview;
  codePreview: ChatExecutionPreview;
};

export function formatRuntimeStatusLabel(value: string | null | undefined): string {
  const normalized = (value || "").trim().replace(/[_-]+/g, " ");
  if (!normalized) {
    return "";
  }
  return normalized.replace(/\b\w/g, (character) => character.toUpperCase());
}

function studioWorkItemPriority(status: string): number {
  switch ((status || "").trim().toLowerCase()) {
    case "running":
      return 0;
    case "blocked":
      return 1;
    case "pending":
      return 2;
    case "rejected":
      return 3;
    case "failed":
      return 4;
    case "succeeded":
      return 5;
    case "skipped":
      return 6;
    default:
      return 7;
  }
}

function latestPreviewWorkItemId(executionEnvelope?: ExecutionEnvelope | null): string | null {
  const latestLivePreview = [...(executionEnvelope?.livePreviews ?? [])]
    .filter(
      (preview) =>
        typeof preview?.content === "string" && preview.content.trim().length > 0,
    )
    .sort((left, right) =>
      String(left?.updatedAt || "").localeCompare(String(right?.updatedAt || "")),
    )
    .at(-1);
  return latestLivePreview?.workItemId ?? null;
}

function invariantProcesses(
  executionEnvelope?: ExecutionEnvelope | null,
): ChatExecutionProcess[] {
  const invariant = executionEnvelope?.completionInvariant;
  if (!invariant) {
    return [];
  }

  const requiredWorkItems = invariant.requiredWorkItemIds ?? [];
  const satisfiedWorkItems = new Set(invariant.satisfiedWorkItemIds ?? []);
  const prunedWorkItems = new Set(invariant.prunedWorkItemIds ?? []);
  const remainingObligations = new Set(invariant.remainingObligations ?? []);
  const invariantBlocked =
    String(invariant.status || "").trim().toLowerCase() === "blocked";

  const workItemProcesses = requiredWorkItems.map((id) => {
    const status = prunedWorkItems.has(id)
      ? "Pruned"
      : satisfiedWorkItems.has(id)
        ? "Complete"
        : invariantBlocked
          ? "Blocked"
        : remainingObligations.has(`work_item:${id}`)
          ? "Pending"
          : "Ready";
    return {
      id: `work-item:${id}`,
      label: formatRuntimeStatusLabel(id) || id,
      status,
      summary:
        status === "Complete"
          ? "This required work item is satisfied."
          : status === "Pruned"
            ? "This work item was pruned after the completion invariant narrowed."
            : status === "Blocked"
              ? "This obligation was left unsatisfied when the execution invariant blocked."
            : "This obligation is still in the active execution frontier.",
      isActive: status === "Pending" || status === "Ready",
    };
  });

  const verificationProcesses = (invariant.requiredVerificationIds ?? []).map((id) => {
    const satisfied = (invariant.satisfiedVerificationIds ?? []).includes(id);
    const status = satisfied ? "Complete" : invariantBlocked ? "Blocked" : "Pending";
    return {
      id: `verification:${id}`,
      label: formatRuntimeStatusLabel(id) || id,
      status,
      summary: satisfied
        ? "This verification requirement is satisfied."
        : invariantBlocked
          ? "This verification requirement remained unsatisfied when execution blocked."
          : "This verification requirement is still gating completion.",
      isActive: !satisfied && !invariantBlocked,
    };
  });

  return [...workItemProcesses, ...verificationProcesses].slice(0, 5);
}

export function deriveChatExecutionChrome({
  executionEnvelope,
  workGraphExecution,
  workGraphPlan,
  workerReceipts,
  changeReceipts,
}: {
  executionEnvelope?: ExecutionEnvelope | null;
  workGraphExecution?: WorkGraphExecutionSummary | null;
  workGraphPlan?: WorkGraphPlan | null;
  workerReceipts?: WorkGraphWorkerReceipt[] | null;
  changeReceipts?: WorkGraphChangeReceipt[] | null;
}): ChatExecutionChrome {
  const visibleWorkGraphExecution = workGraphExecution?.enabled === false ? null : workGraphExecution;
  const activePreviewWorkItemId = latestPreviewWorkItemId(executionEnvelope);
  const processes = Array.isArray(workGraphPlan?.workItems)
    ? [...workGraphPlan.workItems]
        .filter(
          (item) =>
            item?.status === "running" ||
            item?.status === "blocked" ||
            item?.status === "pending" ||
            item?.id === activePreviewWorkItemId,
        )
        .sort((left, right) => {
          const statusDelta =
            studioWorkItemPriority(left?.status || "") -
            studioWorkItemPriority(right?.status || "");
          if (statusDelta !== 0) {
            return statusDelta;
          }
          return String(left?.title || left?.id || "").localeCompare(
            String(right?.title || right?.id || ""),
          );
        })
        .slice(0, 5)
        .map((item) => ({
          id: item.id,
          label: item.title || formatRuntimeStatusLabel(item.role) || item.id,
          status: formatRuntimeStatusLabel(item.status) || "Pending",
          summary: item.summary || "Working the assigned scope.",
          isActive:
            item.id === activePreviewWorkItemId ||
            item.role === visibleWorkGraphExecution?.activeWorkerRole,
        }))
    : invariantProcesses(executionEnvelope);

  const livePreview = resolveChatExecutionStreamPreview({
    executionEnvelope,
    workerReceipts,
    changeReceipts,
  });
  const codePreview = resolveChatExecutionCodePreview({
    executionEnvelope,
    workerReceipts,
    changeReceipts,
  });

  return {
    metrics: visibleWorkGraphExecution
      ? {
          stage:
            formatRuntimeStatusLabel(
              visibleWorkGraphExecution.executionStage ||
                visibleWorkGraphExecution.currentStage,
            ) || null,
          activeRole: visibleWorkGraphExecution.activeWorkerRole
            ? formatRuntimeStatusLabel(visibleWorkGraphExecution.activeWorkerRole)
            : null,
          progress:
            visibleWorkGraphExecution.totalWorkItems > 0
              ? `${visibleWorkGraphExecution.completedWorkItems}/${visibleWorkGraphExecution.totalWorkItems} work items`
              : null,
          verification:
            formatRuntimeStatusLabel(visibleWorkGraphExecution.verificationStatus) || null,
        }
      : null,
    processes,
    livePreview,
    codePreview,
  };
}
