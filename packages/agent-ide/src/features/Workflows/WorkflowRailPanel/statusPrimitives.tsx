import type { WorkflowRevisionBinding } from "../../../types/graph";
import {
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
} from "../../../runtime/harness-workflow";
import type {
  WorkflowHarnessAuthorityGateProofView,
  WorkflowHarnessWorkbenchDeepLinkTarget,
} from "./types";

export function workflowProofStringArray(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string[] = [],
): string[] {
  const value = proof?.[key];
  if (!Array.isArray(value)) return fallback;
  return value.filter((item): item is string => typeof item === "string");
}

export function workflowProofString(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string,
): string {
  const value = proof?.[key];
  return typeof value === "string" ? value : fallback;
}

export function workflowProofBoolean(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const value = proof?.[key];
  return typeof value === "boolean" ? value : fallback;
}

export function workflowHarnessAuthorityGateBlockerState(
  gate: Pick<
    WorkflowHarnessAuthorityGateProofView,
    "ready" | "attemptIds" | "receiptIds" | "replayFixtureRefs"
  >,
): string {
  if (gate.ready) return "none";
  if (gate.attemptIds.length === 0) return "missing attempt";
  if (gate.receiptIds.length === 0) return "missing receipt";
  if (gate.replayFixtureRefs.length === 0) return "missing replay fixture";
  return "needs activation review";
}

export function workflowHarnessUniqueStrings(
  values: Array<string | null | undefined>,
): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.length > 0,
      ),
    ),
  );
}

export function workflowHarnessInvariantIds(
  ...lists: Array<readonly string[] | null | undefined>
): string[] {
  return workflowHarnessUniqueStrings(
    lists.flatMap((list) => (Array.isArray(list) ? [...list] : [])),
  );
}

export function workflowHarnessHasReviewedImportActivationInvariant(
  invariantIds: readonly string[] | null | undefined,
): boolean {
  return Boolean(
    invariantIds?.includes(
      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
    ),
  );
}

export function workflowHarnessInvariantBlockers(
  ...lists: Array<readonly string[] | null | undefined>
): string[] {
  return workflowHarnessInvariantIds(...lists);
}

export function workflowHarnessPackageDeepLinkTarget(
  link: { kind?: string; ref?: string } | null | undefined,
): WorkflowHarnessWorkbenchDeepLinkTarget | null {
  if (!link?.ref) return null;
  if (link.kind === "activation") {
    return { panel: "settings", workerBindingId: link.ref };
  }
  if (link.kind === "canary_boundary" || link.kind === "rollback_drill") {
    return {
      panel: "settings",
      activationGateId: "canary",
      activationGateEvidenceRef: link.ref,
    };
  }
  if (link.kind === "rollback_restore") {
    return {
      panel: "settings",
      receiptRef: link.ref,
      activationGateId: "rollback-restore",
      activationGateReceiptRef: link.ref,
    };
  }
  if (link.kind === "worker_handoff") {
    return {
      panel: "settings",
      activationGateId: "worker-handoff",
      activationGateNodeAttemptId: link.ref,
      nodeAttemptId: link.ref,
    };
  }
  return {
    panel: "settings",
    activationGateId: "package-evidence",
    activationGateEvidenceRef: link.ref,
  };
}

export function workflowRevisionBindingDeepLinkRef(
  binding: WorkflowRevisionBinding | null | undefined,
): string | null {
  return (
    binding?.activatedRevision ??
    binding?.workflowContentHash ??
    binding?.activationId ??
    null
  );
}
