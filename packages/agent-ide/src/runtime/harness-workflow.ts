import type {
  Node,
  WorkflowEdge,
  WorkflowHarnessCanaryExecutionBoundary,
  WorkflowHarnessClusterPromotionStatus,
  WorkflowHarnessComponentAdapterResult,
  WorkflowHarnessComponentReadiness,
  WorkflowHarnessComponentKind,
  WorkflowHarnessComponentSpec,
  WorkflowHarnessDefaultRuntimeDispatchProof,
  WorkflowHarnessExecutionMode,
  WorkflowHarnessActivationAuditEvent,
  WorkflowHarnessActivationAuditEventStatus,
  WorkflowHarnessActivationAuditEventType,
  WorkflowHarnessActivationRollbackExecution,
  WorkflowHarnessActivationRollbackProof,
  WorkflowHarnessActivationIdGateClickProof,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessForkActivationRecord,
  WorkflowHarnessLiveHandoffProof,
  WorkflowHarnessMetadata,
  WorkflowHarnessNodeBinding,
  WorkflowHarnessPromotionCluster,
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessPromotionClusterReplayGateProof,
  WorkflowHarnessPromotionTransitionAttempt,
  WorkflowHarnessPromotionTransitionEligibility,
  WorkflowHarnessPromotionTransitionTarget,
  WorkflowHarnessReplayEnvelope,
  WorkflowHarnessRuntimeSelectorDecision,
  WorkflowHarnessReplayDrillDivergenceClass,
  WorkflowHarnessReplayDrillResult,
  WorkflowHarnessReplayGateResult,
  WorkflowHarnessSlotKind,
  WorkflowHarnessSlotSpec,
  WorkflowHarnessWorkerBinding,
  WorkflowRevisionBinding,
  WorkflowRevisionRestoreRequest,
  WorkflowRevisionRestoreResult,
  WorkflowNode,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
} from "../types/graph";
import { normalizeGlobalConfig, slugify } from "./workflow-defaults";

export const DEFAULT_AGENT_HARNESS_WORKFLOW_ID = "default-agent-harness";
export const DEFAULT_AGENT_HARNESS_VERSION = "2026.04.default-harness.v1";
export const DEFAULT_AGENT_HARNESS_HASH =
  "sha256:default-agent-harness-component-projection-v1";
export const DEFAULT_AGENT_HARNESS_ACTIVATION_ID =
  "activation:default-agent-harness:blessed-readonly";
export const DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET =
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
export const DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS = Object.freeze([
  "harness_activation_not_validated",
  "required_slots_unbound",
  "replay_fixtures_missing",
  "canary_not_run",
  "activation_review_incomplete",
]);
export const DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS =
  5 * 60 * 1000;

const HARNESS_INPUT_SCHEMA = {
  type: "object",
  required: ["sessionId", "turnId"],
  properties: {
    sessionId: { type: "string" },
    turnId: { type: "string" },
    input: {},
    state: { type: "object" },
    policyContext: { type: "object" },
  },
};

const HARNESS_OUTPUT_SCHEMA = {
  type: "object",
  required: ["status"],
  properties: {
    status: { type: "string" },
    value: {},
    evidence: { type: "array", items: { type: "string" } },
    receipts: { type: "array", items: { type: "string" } },
  },
};

export function workflowHarnessActivationIdGateClickProofBlockers(
  proof: WorkflowHarnessActivationIdGateClickProof | null | undefined,
  options: {
    nowMs?: number;
    maxAgeMs?: number;
  } = {},
): string[] {
  const blockers: string[] = [];
  if (!proof) return ["activation_id_gate_click_proof_missing"];
  const maxAgeMs =
    options.maxAgeMs ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS;
  if (proof.passed !== true || proof.blockers.length > 0) {
    blockers.push("activation_id_gate_click_proof_failed");
  }
  if (
    typeof options.nowMs === "number" &&
    Number.isFinite(proof.generatedAtMs) &&
    (proof.generatedAtMs > options.nowMs + 1000 ||
      options.nowMs - proof.generatedAtMs > maxAgeMs)
  ) {
    blockers.push("activation_id_gate_click_proof_stale");
  }
  const blockedDryRun = proof.blockedDryRun;
  if (blockedDryRun.clicked !== true) {
    blockers.push("activation_id_gate_dry_run_not_clicked");
  }
  if (blockedDryRun.gateId !== "activation-id") {
    blockers.push("activation_id_gate_dry_run_gate_mismatch");
  }
  if (blockedDryRun.action.kind !== "run_activation_dry_run") {
    blockers.push("activation_id_gate_dry_run_kind_mismatch");
  }
  if (blockedDryRun.action.command !== "workflow-harness-gate-action-activation-id") {
    blockers.push("activation_id_gate_dry_run_command_mismatch");
  }
  if (blockedDryRun.decision !== "blocked") {
    blockers.push("activation_id_gate_dry_run_not_blocked");
  }
  if (blockedDryRun.activationBlockerCount <= 0) {
    blockers.push("activation_id_gate_dry_run_no_blockers");
  }
  if (blockedDryRun.workflowActivationId) {
    blockers.push("activation_id_gate_dry_run_minted_activation_id");
  }
  if (blockedDryRun.workflowActivationState !== "blocked") {
    blockers.push("activation_id_gate_dry_run_activation_state_mismatch");
  }
  if (blockedDryRun.latestAuditEventType !== "dry_run_blocked") {
    blockers.push("activation_id_gate_dry_run_audit_type_mismatch");
  }

  const minted = proof.mintedActivation;
  const activationId = minted.activationId;
  if (minted.clicked !== true) blockers.push("activation_id_gate_mint_not_clicked");
  if (minted.applied !== true) blockers.push("activation_id_gate_mint_not_applied");
  if (minted.gateId !== "activation-id") {
    blockers.push("activation_id_gate_mint_gate_mismatch");
  }
  if (minted.action.kind !== "mint_activation") {
    blockers.push("activation_id_gate_mint_kind_mismatch");
  }
  if (minted.action.command !== "workflow-harness-gate-action-activation-id") {
    blockers.push("activation_id_gate_mint_command_mismatch");
  }
  if (!activationId?.startsWith("activation:")) {
    blockers.push("activation_id_gate_mint_activation_id_missing");
  }
  if (minted.workflowActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_workflow_activation_mismatch");
  }
  if (minted.workflowActivationState !== "validated") {
    blockers.push("activation_id_gate_mint_activation_state_mismatch");
  }
  if (minted.workerBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_worker_binding_mismatch");
  }
  if (minted.activationRecordWorkerBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_activation_record_binding_mismatch");
  }
  if (minted.revisionBindingActivationId !== activationId) {
    blockers.push("activation_id_gate_mint_revision_binding_mismatch");
  }
  if (minted.rollbackTarget !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
    blockers.push("activation_id_gate_mint_rollback_target_mismatch");
  }
  if (!minted.activationRecordRevisionBindingHash) {
    blockers.push("activation_id_gate_mint_revision_hash_missing");
  }
  if (!minted.rollbackRevisionBindingHash) {
    blockers.push("activation_id_gate_mint_rollback_hash_missing");
  }
  if (minted.latestAuditEventType !== "activation_minted") {
    blockers.push("activation_id_gate_mint_audit_type_mismatch");
  }
  if (minted.latestAuditStatus !== "applied") {
    blockers.push("activation_id_gate_mint_audit_status_mismatch");
  }
  if (minted.receiptRefs.length === 0) {
    blockers.push("activation_id_gate_mint_receipts_missing");
  }
  if (minted.evidenceRefs.length === 0) {
    blockers.push("activation_id_gate_mint_evidence_missing");
  }
  return uniqueStrings(blockers);
}

const HARNESS_ERROR_SCHEMA = {
  type: "object",
  required: ["code", "message", "retryable"],
  properties: {
    code: { type: "string" },
    message: { type: "string" },
    retryable: { type: "boolean" },
    evidenceRef: { type: "string" },
  },
};

export function defaultHarnessComponentVersionSet(): Record<string, string> {
  return Object.fromEntries(
    DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
      component.componentId,
      component.version,
    ]),
  );
}

export function harnessForkActivationId(workflowId: string): string {
  const normalizedWorkflowId = slugify(workflowId || "default-agent-harness-fork");
  return `activation:${normalizedWorkflowId}:validated-canary:${DEFAULT_AGENT_HARNESS_HASH.replace(
    /^sha256:/,
    "",
  ).slice(0, 12)}`;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}

function stableContentHash(value: unknown): string {
  const input = stableStringify(value);
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `stable-fnv1a32:${hash.toString(16).padStart(8, "0")}`;
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter((value): value is string => typeof value === "string" && value.length > 0),
    ),
  );
}

function receiptRefsFromEvidenceRefs(
  evidenceRefs: Array<string | null | undefined> = [],
): string[] {
  return uniqueStrings(
    evidenceRefs.filter((reference): reference is string =>
      typeof reference === "string" && reference.startsWith("workflow_restore_canary:"),
    ),
  );
}

function rollbackRestoreCanaryReceiptRefs(
  canary: WorkflowHarnessForkActivationRecord["rollbackRestoreCanary"] | null | undefined,
): string[] {
  if (!canary) return [];
  return uniqueStrings([
    canary.receiptBindingRef,
    ...receiptRefsFromEvidenceRefs(canary.evidenceRefs),
  ]);
}

function activationCandidateReceiptRefs(
  candidate: WorkflowHarnessForkActivationCandidate | null | undefined,
): string[] {
  if (!candidate) return [];
  return uniqueStrings([
    ...rollbackRestoreCanaryReceiptRefs(candidate.rollbackRestoreCanary),
    ...receiptRefsFromEvidenceRefs(candidate.evidenceRefs),
  ]);
}

function workflowRollbackReceiptRefs(
  workflow: WorkflowProject,
  latestMintEvent?: WorkflowHarnessActivationAuditEvent,
): string[] {
  return uniqueStrings([
    ...(latestMintEvent?.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(latestMintEvent?.evidenceRefs ?? []),
    ...rollbackRestoreCanaryReceiptRefs(
      workflow.metadata.harness?.activationRecord?.rollbackRestoreCanary,
    ),
    ...receiptRefsFromEvidenceRefs(
      workflow.metadata.harness?.activationRecord?.evidenceRefs ?? [],
    ),
  ]);
}

function workflowSourceProjection(workflow: WorkflowProject): unknown {
  const harness = workflow.metadata.harness;
  return {
    version: workflow.version,
    metadata: {
      id: workflow.metadata.id,
      name: workflow.metadata.name,
      slug: workflow.metadata.slug,
      workflowKind: workflow.metadata.workflowKind,
      executionMode: workflow.metadata.executionMode,
      gitLocation: workflow.metadata.gitLocation,
      branch: workflow.metadata.branch,
      readOnly: workflow.metadata.readOnly,
      harness: harness
        ? {
            schemaVersion: harness.schemaVersion,
            harnessVersion: harness.harnessVersion,
            harnessHash: harness.harnessHash,
            executionMode: harness.executionMode,
            templateName: harness.templateName,
            blessed: harness.blessed,
            forkable: harness.forkable,
            forkedFrom: harness.forkedFrom,
            packageName: harness.packageName,
            validationGates: harness.validationGates,
            aiMutationMode: harness.aiMutationMode,
            componentIds: harness.componentIds,
            slotIds: harness.slotIds,
            componentReadiness: harness.componentReadiness,
            promotionClusters: harness.promotionClusters,
          }
        : undefined,
    },
    nodes: workflow.nodes,
    edges: workflow.edges,
    global_config: workflow.global_config,
  };
}

function defaultWorkflowPath(workflow: WorkflowProject): string {
  return workflow.metadata.gitLocation || `.agents/workflows/${workflow.metadata.slug}.workflow.json`;
}

export function workflowRevisionBindingFor(
  workflow: WorkflowProject,
  options: {
    workflowPath?: string;
    repoRoot?: string;
    branch?: string;
    baseRevision?: string;
    activatedRevision?: string;
    workflowContentHash?: string;
    proposalId?: string;
    activationId?: string;
    rollbackActivationId?: string;
    rollbackRevision?: string;
    revisionSource?: WorkflowRevisionBinding["revisionSource"];
    nowMs?: number;
  } = {},
): WorkflowRevisionBinding {
  const workflowContentHash =
    options.workflowContentHash ?? stableContentHash(workflowSourceProjection(workflow));
  const revisionSource =
    options.revisionSource ??
    (options.baseRevision || options.activatedRevision ? "git" : "file_hash_only");
  return {
    schemaVersion: "workflow.revision-binding.v1",
    workflowPath: options.workflowPath ?? defaultWorkflowPath(workflow),
    repoRoot: options.repoRoot,
    branch: options.branch ?? workflow.metadata.branch ?? "main",
    baseRevision: options.baseRevision,
    activatedRevision:
      options.activatedRevision ??
      (revisionSource === "file_hash_only" ? workflowContentHash : undefined),
    workflowContentHash,
    proposalId: options.proposalId,
    activationId: options.activationId ?? workflow.metadata.harness?.activationId,
    rollbackActivationId:
      options.rollbackActivationId ?? workflow.metadata.harness?.activationRecord?.rollbackTarget,
    rollbackRevision: options.rollbackRevision,
    revisionSource,
    createdAtMs: options.nowMs ?? Date.now(),
  };
}

function workflowWithRefreshedHarnessRevisionBinding(
  workflow: WorkflowProject,
  createdAtMs: number,
): WorkflowProject {
  const harness = workflow.metadata.harness;
  if (!harness) return workflow;
  const current = harness.revisionBinding;
  const rollbackRevisionBinding = harness.activationRecord?.rollbackRevisionBinding;
  const revisionBinding = workflowRevisionBindingFor(workflow, {
    workflowPath: current?.workflowPath,
    repoRoot: current?.repoRoot,
    branch: current?.branch,
    baseRevision: current?.baseRevision,
    activatedRevision:
      current?.revisionSource === "git" ? current.activatedRevision : undefined,
    proposalId: current?.proposalId,
    activationId: current?.activationId ?? harness.activationId,
    rollbackActivationId:
      current?.rollbackActivationId ?? harness.activationRecord?.rollbackTarget,
    rollbackRevision:
      current?.rollbackRevision ??
      rollbackRevisionBinding?.activatedRevision ??
      rollbackRevisionBinding?.workflowContentHash,
    revisionSource: current?.revisionSource,
    nowMs: createdAtMs,
  });
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...harness,
        revisionBinding,
        activationRecord: harness.activationRecord
          ? {
              ...harness.activationRecord,
              revisionBinding,
            }
          : harness.activationRecord,
      },
    },
  };
}

export function makeHarnessForkActivationRecord(options: {
  workflowId: string;
  harnessWorkflowId?: string;
  activationId?: string;
  activationState: WorkflowHarnessForkActivationRecord["activationState"];
  activationBlockers?: string[];
  componentVersionSet?: Record<string, string>;
  harnessHash?: string;
  policyPosture?: WorkflowHarnessForkActivationRecord["policyPosture"];
  canaryStatus?: WorkflowHarnessForkActivationRecord["canaryStatus"];
  rollbackTarget?: string;
  rollbackAvailable?: boolean;
  liveAuthorityTransferred?: boolean;
  evidenceRefs?: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  revisionBinding?: WorkflowRevisionBinding;
  rollbackRevisionBinding?: WorkflowRevisionBinding;
  rollbackRestoreCanary?: WorkflowHarnessForkActivationRecord["rollbackRestoreCanary"];
  mintedAtMs?: number;
}): WorkflowHarnessForkActivationRecord {
  const activationId =
    options.activationId ??
    (options.activationState === "validated" || options.activationState === "active"
      ? harnessForkActivationId(options.workflowId)
      : undefined);
  return {
    schemaVersion: "workflow.harness.activation.v1",
    workflowId: options.workflowId,
    harnessWorkflowId: options.harnessWorkflowId ?? options.workflowId,
    activationId,
    harnessHash: options.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH,
    activationState: options.activationState,
    activationBlockers:
      options.activationBlockers ??
      (options.activationState === "validated" || options.activationState === "active"
        ? []
        : [...DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS]),
    componentVersionSet: options.componentVersionSet ?? defaultHarnessComponentVersionSet(),
    policyPosture:
      options.policyPosture ??
      (options.activationState === "validated" || options.activationState === "active"
        ? "canary"
        : "proposal_only"),
    canaryStatus:
      options.canaryStatus ??
      (options.activationState === "validated" || options.activationState === "active"
        ? "passed"
        : "not_run"),
    rollbackTarget: options.rollbackTarget ?? DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET,
    rollbackAvailable:
      options.rollbackAvailable ??
      (options.activationState === "validated" || options.activationState === "active"),
    liveAuthorityTransferred: options.liveAuthorityTransferred ?? false,
    evidenceRefs: options.evidenceRefs ?? [],
    workerBinding: options.workerBinding,
    revisionBinding: options.revisionBinding,
    rollbackRevisionBinding: options.rollbackRevisionBinding,
    rollbackRestoreCanary: options.rollbackRestoreCanary,
    mintedAtMs: options.mintedAtMs,
  };
}

function harnessActivationAuditEventId(
  workflowId: string,
  eventType: WorkflowHarnessActivationAuditEventType,
  createdAtMs: number,
): string {
  return `harness-activation-audit:${slugify(workflowId)}:${eventType}:${createdAtMs}`;
}

function makeWorkflowHarnessActivationAuditEvent(options: {
  workflow: WorkflowProject;
  eventType: WorkflowHarnessActivationAuditEventType;
  status: WorkflowHarnessActivationAuditEventStatus;
  candidateId?: string;
  activationId?: string;
  previousActivationId?: string;
  nextActivationId?: string;
  previousWorkerBinding?: WorkflowHarnessWorkerBinding;
  nextWorkerBinding?: WorkflowHarnessWorkerBinding;
  previousRevisionBinding?: WorkflowRevisionBinding;
  nextRevisionBinding?: WorkflowRevisionBinding;
  rollbackTarget?: string;
  rollbackExecuted?: boolean;
  blockers?: string[];
  evidenceRefs?: string[];
  receiptRefs?: string[];
  summary: string;
  createdAtMs: number;
}): WorkflowHarnessActivationAuditEvent {
  const workflowId = options.workflow.metadata.id || options.workflow.metadata.slug;
  const evidenceRefs = options.evidenceRefs ?? [];
  const receiptRefs = uniqueStrings([
    ...(options.receiptRefs ?? []),
    ...receiptRefsFromEvidenceRefs(evidenceRefs),
  ]);
  return {
    schemaVersion: "workflow.harness.activation-audit.v1",
    eventId: harnessActivationAuditEventId(workflowId, options.eventType, options.createdAtMs),
    eventType: options.eventType,
    status: options.status,
    workflowId,
    candidateId: options.candidateId,
    activationId: options.activationId,
    previousActivationId: options.previousActivationId,
    nextActivationId: options.nextActivationId,
    previousWorkerBinding: options.previousWorkerBinding,
    nextWorkerBinding: options.nextWorkerBinding,
    previousRevisionBinding: options.previousRevisionBinding,
    nextRevisionBinding: options.nextRevisionBinding,
    rollbackTarget: options.rollbackTarget,
    rollbackExecuted: options.rollbackExecuted,
    blockers: options.blockers ?? [],
    evidenceRefs,
    receiptRefs,
    summary: options.summary,
    createdAtMs: options.createdAtMs,
  };
}

function appendWorkflowHarnessActivationAudit(
  workflow: WorkflowProject,
  event: WorkflowHarnessActivationAuditEvent,
  extras: Partial<NonNullable<WorkflowProject["metadata"]["harness"]>> = {},
): WorkflowProject {
  if (!workflow.metadata.harness) return workflow;
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      dirty: true,
      harness: {
        ...workflow.metadata.harness,
        ...extras,
        activationAudit: [
          ...(workflow.metadata.harness.activationAudit ?? []),
          event,
        ],
      },
      updatedAtMs: event.createdAtMs,
    },
  };
}

export function recordWorkflowHarnessActivationDryRun(
  workflow: WorkflowProject,
  candidate: WorkflowHarnessForkActivationCandidate,
  options: { nowMs?: number } = {},
): WorkflowProject {
  if (!workflowIsHarnessFork(workflow)) return workflow;
  const createdAtMs = options.nowMs ?? Date.now();
  const receiptRefs = activationCandidateReceiptRefs(candidate);
  return appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        candidate.decision === "mintable" ? "dry_run_mintable" : "dry_run_blocked",
      status: candidate.decision === "mintable" ? "passed" : "blocked",
      candidateId: candidate.candidateId,
      activationId: candidate.activationIdPreview,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: candidate.activationIdPreview,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: candidate.workerBindingPreview,
      previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
      nextRevisionBinding: candidate.revisionBindingPreview,
      rollbackTarget: candidate.rollbackTarget,
      blockers: candidate.activationBlockers,
      evidenceRefs: candidate.evidenceRefs,
      receiptRefs,
      summary:
        candidate.decision === "mintable"
          ? `Activation dry run mintable for ${candidate.activationIdPreview}`
          : `Activation dry run blocked by ${candidate.activationBlockers.length} blockers`,
      createdAtMs,
    }),
  );
}

export function recordWorkflowHarnessRollbackTargetSelection(
  workflow: WorkflowProject,
  rollbackTarget: string,
  options: { nowMs?: number } = {},
): WorkflowProject {
  if (!workflowIsHarnessFork(workflow)) return workflow;
  const createdAtMs = options.nowMs ?? Date.now();
  return appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: "rollback_target_selected",
      status: "applied",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      previousWorkerBinding: workflow.metadata.workerHarnessBinding,
      nextWorkerBinding: workflow.metadata.workerHarnessBinding,
      previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
      nextRevisionBinding: workflow.metadata.harness?.revisionBinding,
      rollbackTarget,
      evidenceRefs: [rollbackTarget],
      summary: `Rollback target selected: ${rollbackTarget}`,
      createdAtMs,
    }),
  );
}

function rollbackWorkerBindingForTarget(
  workflow: WorkflowProject,
  rollbackTarget: string,
): WorkflowHarnessWorkerBinding {
  if (
    rollbackTarget === DEFAULT_AGENT_HARNESS_ACTIVATION_ID ||
    rollbackTarget === DEFAULT_AGENT_HARNESS_WORKFLOW_ID
  ) {
    return {
      harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      harnessHash: DEFAULT_AGENT_HARNESS_HASH,
      executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
      source: "default",
    };
  }
  if (rollbackTarget === "legacy_runtime") {
    return {
      harnessWorkflowId: "legacy_runtime",
      harnessActivationId: "legacy_runtime",
      harnessHash: "legacy_runtime",
      executionMode: "projection",
      source: "legacy",
    };
  }
  return {
    harnessWorkflowId: workflow.metadata.id || workflow.metadata.slug,
    harnessActivationId: rollbackTarget,
    harnessHash: workflow.metadata.harness?.harnessHash ?? DEFAULT_AGENT_HARNESS_HASH,
    executionMode: workflow.metadata.harness?.executionMode ?? DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
  };
}

function latestHarnessActivationMintEvent(
  workflow: WorkflowProject,
): WorkflowHarnessActivationAuditEvent | undefined {
  return [...(workflow.metadata.harness?.activationAudit ?? [])]
    .reverse()
    .find((event) => event.eventType === "activation_minted");
}

function harnessRollbackTargetFor(
  workflow: WorkflowProject,
  rollbackTarget?: string | null,
): string {
  const latestMintEvent = latestHarnessActivationMintEvent(workflow);
  return (
    rollbackTarget?.trim() ||
    workflow.metadata.harness?.activationRecord?.rollbackTarget ||
    latestMintEvent?.rollbackTarget ||
    DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET
  );
}

function harnessRollbackBindingsFor(
  workflow: WorkflowProject,
  rollbackTarget: string,
  createdAtMs: number,
): {
  latestMintEvent?: WorkflowHarnessActivationAuditEvent;
  activeWorkerBinding: WorkflowHarnessWorkerBinding;
  restoredWorkerBinding: WorkflowHarnessWorkerBinding;
  activeRevisionBinding: WorkflowRevisionBinding;
  restoredRevisionBinding: WorkflowRevisionBinding;
} {
  const latestMintEvent = latestHarnessActivationMintEvent(workflow);
  const activeWorkerBinding =
    workflow.metadata.workerHarnessBinding ?? workflowHarnessWorkerBinding(workflow);
  const restoredWorkerBinding =
    latestMintEvent?.previousWorkerBinding ??
    rollbackWorkerBindingForTarget(workflow, rollbackTarget);
  const activeRevisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    workflow.metadata.harness?.activationRecord?.revisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: workflow.metadata.harness?.activationId,
      rollbackActivationId: rollbackTarget,
      nowMs: createdAtMs,
    });
  const restoredRevisionBinding =
    latestMintEvent?.previousRevisionBinding ??
    workflow.metadata.harness?.activationRecord?.rollbackRevisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: restoredWorkerBinding.harnessActivationId,
      rollbackActivationId: workflow.metadata.harness?.activationId,
      rollbackRevision:
        activeRevisionBinding.activatedRevision ?? activeRevisionBinding.workflowContentHash,
      nowMs: createdAtMs,
    });
  return {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  };
}

function rollbackRestoreStrategyFor(
  binding: WorkflowRevisionBinding,
): WorkflowHarnessActivationRollbackExecution["restoreStrategy"] {
  if (binding.revisionSource === "git" && binding.activatedRevision) {
    return "git_show_file_restore";
  }
  if (binding.revisionSource === "file_hash_only") {
    return "file_hash_only_metadata_restore";
  }
  return "worker_binding_restore";
}

export interface WorkflowHarnessRollbackRestoreProbeRuntime {
  restoreWorkflowRevision?: (
    request: WorkflowRevisionRestoreRequest,
  ) => Promise<WorkflowRevisionRestoreResult>;
}

export async function runWorkflowHarnessRollbackRestoreCanaryProbe(options: {
  runtime: WorkflowHarnessRollbackRestoreProbeRuntime;
  workflowPath: string;
  rollbackRevisionBinding: WorkflowRevisionBinding | null | undefined;
}): Promise<{
  rollbackRestoreResult: WorkflowRevisionRestoreResult | null;
  rollbackRestoreBlockers: string[];
  restoreRequest?: WorkflowRevisionRestoreRequest;
}> {
  const { runtime, workflowPath, rollbackRevisionBinding } = options;
  if (rollbackRevisionBinding?.revisionSource !== "git") {
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: [],
    };
  }
  const restoreRequest: WorkflowRevisionRestoreRequest = {
    workflowPath,
    revisionBinding: rollbackRevisionBinding,
    expectedWorkflowContentHash: rollbackRevisionBinding.workflowContentHash,
    dryRun: true,
  };
  if (!runtime.restoreWorkflowRevision) {
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: ["rollback_restore_api_unavailable"],
      restoreRequest,
    };
  }
  try {
    return {
      rollbackRestoreResult: await runtime.restoreWorkflowRevision(restoreRequest),
      rollbackRestoreBlockers: [],
      restoreRequest,
    };
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : "Unknown rollback restore failure";
    return {
      rollbackRestoreResult: null,
      rollbackRestoreBlockers: ["rollback_restore_canary_failed", message],
      restoreRequest,
    };
  }
}

export function executeWorkflowHarnessRollbackDrill(
  workflow: WorkflowProject,
  options: {
    rollbackTarget?: string | null;
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  proof?: WorkflowHarnessActivationRollbackProof;
  blockers: string[];
  rollbackTarget?: string;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const rollbackTarget = harnessRollbackTargetFor(workflow, options.rollbackTarget);
  const blockers = [
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(workflow.metadata.harness?.activationRecord?.rollbackAvailable === false
      ? ["rollback_unavailable"]
      : []),
  ];
  const {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  } = harnessRollbackBindingsFor(workflow, rollbackTarget, createdAtMs);
  const receiptRefs = workflowRollbackReceiptRefs(workflow, latestMintEvent);
  const proof: WorkflowHarnessActivationRollbackProof = {
    schemaVersion: "workflow.harness.activation-rollback-proof.v1",
    drillId: `harness-rollback-drill:${slugify(workflow.metadata.id || workflow.metadata.slug)}:${createdAtMs}`,
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    activationId: workflow.metadata.harness?.activationId,
    rollbackTarget,
    rollbackAvailable: blockers.length === 0,
    rollbackExecuted: blockers.length === 0,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
    drillStatus: blockers.length === 0 ? "passed" : "blocked",
    policyDecision:
      blockers.length === 0
        ? "rollback_drill_restored_previous_worker_binding"
        : "rollback_drill_blocked",
    blockers,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    receiptRefs,
    createdAtMs,
  };
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        blockers.length === 0 ? "rollback_drill_passed" : "rollback_drill_blocked",
      status: blockers.length === 0 ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: restoredWorkerBinding.harnessActivationId,
      previousWorkerBinding: activeWorkerBinding,
      nextWorkerBinding: restoredWorkerBinding,
      previousRevisionBinding: activeRevisionBinding,
      nextRevisionBinding: restoredRevisionBinding,
      rollbackTarget,
      rollbackExecuted: blockers.length === 0,
      blockers,
      evidenceRefs: proof.evidenceRefs,
      receiptRefs: proof.receiptRefs,
      summary:
        blockers.length === 0
          ? `Rollback drill restored ${restoredWorkerBinding.harnessActivationId ?? restoredWorkerBinding.harnessWorkflowId}`
          : `Rollback drill blocked by ${blockers.length} blockers`,
      createdAtMs,
    }),
    { activationRollbackProof: proof },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithAudit,
    proof,
    blockers,
    rollbackTarget,
    restoredWorkerBinding,
  };
}

function activationStateForRestoredWorkerBinding(
  restoredWorkerBinding: WorkflowHarnessWorkerBinding,
): WorkflowHarnessForkActivationRecord["activationState"] {
  if (restoredWorkerBinding.source === "legacy") return "blocked";
  return restoredWorkerBinding.harnessActivationId ? "validated" : "blocked";
}

export function executeWorkflowHarnessRevisionRollback(
  workflow: WorkflowProject,
  options: {
    rollbackTarget?: string | null;
    restoredWorkflow?: WorkflowProject | null;
    restoreResult?: WorkflowRevisionRestoreResult | null;
    restoreBlockers?: string[];
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  execution?: WorkflowHarnessActivationRollbackExecution;
  blockers: string[];
  rollbackTarget?: string;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const rollbackTarget = harnessRollbackTargetFor(workflow, options.rollbackTarget);
  const {
    latestMintEvent,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding,
  } = harnessRollbackBindingsFor(workflow, rollbackTarget, createdAtMs);
  const restoredRevisionWithRollForward: WorkflowRevisionBinding = {
    ...restoredRevisionBinding,
    rollbackActivationId:
      activeWorkerBinding.harnessActivationId ??
      workflow.metadata.harness?.activationId ??
      activeWorkerBinding.harnessWorkflowId,
    rollbackRevision:
      activeRevisionBinding.activatedRevision ?? activeRevisionBinding.workflowContentHash,
    createdAtMs,
  };
  const restoredActivationState =
    activationStateForRestoredWorkerBinding(restoredWorkerBinding);
  const restoredWorkflowSource = options.restoredWorkflow ?? workflow;
  const restoreBlockers = Array.from(
    new Set([
      ...(options.restoreResult?.blockers ?? []),
      ...(options.restoreBlockers ?? []),
    ].filter(Boolean)),
  );
  const receiptRefs = uniqueStrings([
    options.restoreResult?.receiptBindingRef,
    ...workflowRollbackReceiptRefs(workflow, latestMintEvent),
    ...receiptRefsFromEvidenceRefs(options.restoreResult?.blockers ?? []),
  ]);
  const rollbackActivationRecord = makeHarnessForkActivationRecord({
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    harnessWorkflowId: restoredWorkerBinding.harnessWorkflowId,
    activationId: restoredWorkerBinding.harnessActivationId,
    activationState: restoredActivationState,
    activationBlockers:
      restoredActivationState === "validated"
        ? []
        : ["rollback_restored_non_fork_authority"],
    componentVersionSet:
      workflow.metadata.harness?.activationRecord?.componentVersionSet ??
      defaultHarnessComponentVersionSet(),
    harnessHash: restoredWorkerBinding.harnessHash,
    policyPosture:
      restoredActivationState === "validated"
        ? workflow.metadata.harness?.activationRecord?.policyPosture ?? "canary"
        : "proposal_only",
    canaryStatus:
      restoredActivationState === "validated"
        ? workflow.metadata.harness?.activationRecord?.canaryStatus ?? "passed"
        : "not_run",
    rollbackTarget:
      activeWorkerBinding.harnessActivationId ?? activeWorkerBinding.harnessWorkflowId,
    rollbackAvailable: true,
    liveAuthorityTransferred: false,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      restoredRevisionWithRollForward.workflowContentHash,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    workerBinding: restoredWorkerBinding,
    revisionBinding: restoredRevisionWithRollForward,
    rollbackRevisionBinding: activeRevisionBinding,
    mintedAtMs: createdAtMs,
  });
  const restoredWorkflowBase: WorkflowProject = {
    ...restoredWorkflowSource,
    metadata: {
      ...restoredWorkflowSource.metadata,
      dirty: true,
      harness: restoredWorkflowSource.metadata.harness
        ? {
            ...restoredWorkflowSource.metadata.harness,
            harnessWorkflowId: restoredWorkerBinding.harnessWorkflowId,
            harnessHash: restoredWorkerBinding.harnessHash,
            executionMode:
              restoredWorkerBinding.executionMode ??
              restoredWorkflowSource.metadata.harness.executionMode,
            activationId: restoredWorkerBinding.harnessActivationId,
            activationState: restoredActivationState,
            activationRecord: rollbackActivationRecord,
            activationAudit: workflow.metadata.harness?.activationAudit,
            activationRollbackProof: workflow.metadata.harness?.activationRollbackProof,
            revisionBinding: restoredRevisionWithRollForward,
          }
        : restoredWorkflowSource.metadata.harness,
      workerHarnessBinding: restoredWorkerBinding,
      updatedAtMs: createdAtMs,
    },
  };
  const actualWorkflowContentHash = stableContentHash(
    workflowSourceProjection(restoredWorkflowBase),
  );
  const expectedWorkflowContentHash =
    options.restoreResult?.expectedWorkflowContentHash ??
    restoredRevisionWithRollForward.workflowContentHash;
  const hashVerified =
    actualWorkflowContentHash === expectedWorkflowContentHash;
  const blockers = [
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(rollbackTarget ? [] : ["rollback_target_missing"]),
    ...(workflow.metadata.harness?.activationRecord?.rollbackAvailable === false
      ? ["rollback_unavailable"]
      : []),
    ...restoreBlockers,
    ...(hashVerified ? [] : ["rollback_revision_hash_mismatch"]),
  ];
  const execution: WorkflowHarnessActivationRollbackExecution = {
    schemaVersion: "workflow.harness.activation-rollback-execution.v1",
    executionId: `harness-rollback-execution:${slugify(workflow.metadata.id || workflow.metadata.slug)}:${createdAtMs}`,
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    activationId: workflow.metadata.harness?.activationId,
    rollbackTarget,
    rollbackAvailable: blockers.length === 0,
    rollbackExecuted: blockers.length === 0,
    activeWorkerBinding,
    restoredWorkerBinding,
    activeRevisionBinding,
    restoredRevisionBinding: restoredRevisionWithRollForward,
    restoreStrategy:
      options.restoreResult?.restoreStrategy ??
      rollbackRestoreStrategyFor(restoredRevisionWithRollForward),
    restoreRepoRoot:
      options.restoreResult?.repoRoot ?? restoredRevisionWithRollForward.repoRoot,
    restoreRelativeWorkflowPath: options.restoreResult?.relativeWorkflowPath,
    restoredRevision:
      options.restoreResult?.restoredRevision ??
      restoredRevisionWithRollForward.activatedRevision,
    restoredFileSha256: options.restoreResult?.fileSha256,
    restoreBlockers,
    restoreReceiptBindingRef: options.restoreResult?.receiptBindingRef,
    workflowPath:
      options.restoreResult?.workflowPath ?? restoredRevisionWithRollForward.workflowPath,
    expectedWorkflowContentHash,
    actualWorkflowContentHash,
    hashVerified,
    executionStatus: blockers.length === 0 ? "applied" : "blocked",
    policyDecision:
      blockers.length === 0
        ? "rollback_execution_restored_verified_workflow_revision"
        : "rollback_execution_blocked",
    blockers,
    evidenceRefs: [
      ...receiptRefs,
      rollbackTarget,
      restoredRevisionWithRollForward.workflowContentHash,
      ...(latestMintEvent ? [latestMintEvent.eventId] : []),
    ],
    receiptRefs,
    createdAtMs,
  };
  const workflowForAudit = blockers.length === 0 ? restoredWorkflowBase : workflow;
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflowForAudit,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: blockers.length === 0 ? "rollback_executed" : "rollback_execution_blocked",
      status: blockers.length === 0 ? "applied" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      previousActivationId: workflow.metadata.harness?.activationId,
      nextActivationId: restoredWorkerBinding.harnessActivationId,
      previousWorkerBinding: activeWorkerBinding,
      nextWorkerBinding: restoredWorkerBinding,
      previousRevisionBinding: activeRevisionBinding,
      nextRevisionBinding: restoredRevisionWithRollForward,
      rollbackTarget,
      rollbackExecuted: blockers.length === 0,
      blockers,
      evidenceRefs: execution.evidenceRefs,
      receiptRefs: execution.receiptRefs,
      summary:
        blockers.length === 0
          ? `Rollback executed: restored ${restoredRevisionWithRollForward.workflowContentHash}`
          : `Rollback execution blocked by ${blockers.length} blockers`,
      createdAtMs,
    }),
    { activationRollbackExecution: execution },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithAudit,
    execution,
    blockers,
    rollbackTarget,
    restoredWorkerBinding,
  };
}

export interface WorkflowHarnessReplayDrillInput {
  replayFixtureRef: string;
  sourceKind: string;
  sourceLabel: string;
  producerComponent: string;
  policyDecision: string;
  attemptId: string;
  receiptRef: string;
  runId: string;
  executionMode: string;
  readiness: string;
  inputHash: string;
  outputHash: string;
  deterministicEnvelope: boolean;
  capturesInput: boolean;
  capturesOutput: boolean;
  capturesPolicyDecision: boolean;
  determinism: string;
  redactionPolicy: string;
  evidenceRefs: string[];
}

function unresolvedHarnessReplayValue(value: string | null | undefined): boolean {
  if (!value) return true;
  return /pending|not resolved|not captured|unknown/i.test(value);
}

function harnessReplayDrillDivergenceClass(
  blockers: string[],
  replay: WorkflowHarnessReplayDrillInput,
): WorkflowHarnessReplayDrillDivergenceClass {
  if (blockers.includes("replay_fixture_unresolved")) return "fixture_unresolved";
  if (blockers.includes("replay_receipt_missing")) return "missing_receipt";
  if (blockers.includes("replay_policy_decision_not_captured")) {
    return "policy_divergence";
  }
  if (blockers.includes("replay_output_not_captured")) return "output_divergence";
  if (!replay.deterministicEnvelope || replay.determinism === "nondeterministic") {
    return "harmless_metadata_drift";
  }
  return "none";
}

function workflowHarnessReplayDrillResultFor(
  workflow: WorkflowProject,
  replay: WorkflowHarnessReplayDrillInput | null | undefined,
  createdAtMs: number,
): {
  drill: WorkflowHarnessReplayDrillResult;
  blockers: string[];
} {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const replayFixtureRef = replay?.replayFixtureRef?.trim() ?? "";
  const blockers = uniqueStrings([
    ...(workflow.metadata.harness ? [] : ["not_harness_workflow"]),
    ...(replay ? [] : ["replay_fixture_unresolved"]),
    ...(replayFixtureRef ? [] : ["replay_fixture_missing"]),
    ...(replay?.sourceKind === "unresolved" ? ["replay_fixture_unresolved"] : []),
    ...(unresolvedHarnessReplayValue(replay?.receiptRef)
      ? ["replay_receipt_missing"]
      : []),
    ...(replay?.capturesOutput ? [] : ["replay_output_not_captured"]),
    ...(replay?.capturesPolicyDecision
      ? []
      : ["replay_policy_decision_not_captured"]),
  ]);
  const drillId = `harness-replay-drill:${slugify(workflowId)}:${slugify(
    replayFixtureRef || "fixture",
  )}:${createdAtMs}`;
  const expectedInputHash =
    replay?.inputHash && !unresolvedHarnessReplayValue(replay.inputHash)
      ? replay.inputHash
      : stableContentHash({ replayFixtureRef, phase: "input" });
  const expectedOutputHash =
    replay?.outputHash && !unresolvedHarnessReplayValue(replay.outputHash)
      ? replay.outputHash
      : stableContentHash({ replayFixtureRef, phase: "output" });
  const actualInputHash = blockers.length === 0 ? expectedInputHash : "not_run";
  const actualOutputHash =
    blockers.length === 0
      ? expectedOutputHash
      : stableContentHash({ drillId, blockers, phase: "blocked_output" });
  const divergenceClass = replay
    ? harnessReplayDrillDivergenceClass(blockers, replay)
    : "fixture_unresolved";
  const receiptRefs = uniqueStrings([
    unresolvedHarnessReplayValue(replay?.receiptRef) ? undefined : replay?.receiptRef,
  ]);
  const evidenceRefs = uniqueStrings([
    drillId,
    replayFixtureRef,
    ...(replay?.evidenceRefs ?? []),
    ...receiptRefs,
  ]);
  return {
    blockers,
    drill: {
      schemaVersion: "workflow.harness.replay-drill-result.v1",
      drillId,
      workflowId,
      activationId: workflow.metadata.harness?.activationId,
      replayFixtureRef: replayFixtureRef || "replay fixture missing",
      sourceKind: replay?.sourceKind ?? "unresolved",
      sourceLabel: replay?.sourceLabel ?? "Unresolved harness replay fixture",
      drillStatus: blockers.length === 0 ? "passed" : "blocked",
      divergenceClass,
      componentId: replay?.producerComponent ?? "unknown",
      producerComponent: replay?.producerComponent ?? "unknown",
      attemptId: replay?.attemptId ?? "not resolved",
      receiptRef: replay?.receiptRef ?? "not resolved",
      runId: replay?.runId ?? "run pending",
      executionMode: replay?.executionMode ?? "projection",
      readiness: replay?.readiness ?? "projection_only",
      policyDecision:
        blockers.length === 0
          ? replay?.policyDecision ?? "replay_policy_not_recorded"
          : "replay_drill_blocked",
      expectedInputHash,
      actualInputHash,
      expectedOutputHash,
      actualOutputHash,
      deterministicEnvelope: replay?.deterministicEnvelope ?? false,
      capturesInput: replay?.capturesInput ?? false,
      capturesOutput: replay?.capturesOutput ?? false,
      capturesPolicyDecision: replay?.capturesPolicyDecision ?? false,
      determinism: replay?.determinism ?? "disabled",
      redactionPolicy: replay?.redactionPolicy ?? "not resolved",
      blockers,
      evidenceRefs,
      receiptRefs,
      createdAtMs,
    },
  };
}

function replayDrillBlocksPromotion(drill: WorkflowHarnessReplayDrillResult): boolean {
  return (
    drill.drillStatus !== "passed" ||
    !["none", "harmless_metadata_drift"].includes(drill.divergenceClass)
  );
}

function workflowHarnessPromotionClusterReplayGateProofFor(
  clusterId: WorkflowHarnessPromotionClusterId,
  gate: WorkflowHarnessReplayGateResult,
): WorkflowHarnessPromotionClusterReplayGateProof {
  return {
    schemaVersion: "workflow.harness.promotion-cluster-replay-gate-proof.v1",
    clusterId,
    gateId: gate.gateId,
    gateStatus: gate.gateStatus,
    activationGateImpact: gate.activationGateImpact,
    totalFixtures: gate.totalFixtures,
    passedCount: gate.passedCount,
    blockedCount: gate.blockedCount,
    failedCount: gate.failedCount,
    blockingDivergenceCount:
      gate.blockedCount + gate.failedCount + gate.blockingReplayFixtureRefs.length,
    replayFixtureRefs: gate.replayFixtureRefs,
    blockingReplayFixtureRefs: gate.blockingReplayFixtureRefs,
    receiptRefs: gate.receiptRefs,
    evidenceRefs: gate.evidenceRefs,
    blockers: gate.blockers,
    verifiedAtMs: gate.createdAtMs,
  };
}

function workflowHarnessPromotionClustersWithReplayGateProof(
  workflow: WorkflowProject,
  gate: WorkflowHarnessReplayGateResult,
): WorkflowHarnessPromotionCluster[] | undefined {
  if (gate.scopeKind !== "harness_group") return workflow.metadata.harness?.promotionClusters;
  const clusters = workflow.metadata.harness?.promotionClusters;
  if (!clusters) return clusters;
  const cluster = clusters.find((candidate) => candidate.clusterId === gate.targetId);
  if (!cluster) return clusters;
  const proof = workflowHarnessPromotionClusterReplayGateProofFor(
    cluster.clusterId,
    gate,
  );
  return clusters.map((candidate) =>
    candidate.clusterId === cluster.clusterId
      ? { ...candidate, replayGateProof: proof }
      : candidate,
  );
}

const HARNESS_READINESS_ORDER: Record<WorkflowHarnessComponentReadiness, number> = {
  projection_only: 0,
  simulated: 1,
  shadow_ready: 2,
  live_ready: 3,
};

function workflowHarnessReadinessAllows(
  actual: WorkflowHarnessComponentReadiness | undefined,
  required: WorkflowHarnessComponentReadiness,
): boolean {
  return (HARNESS_READINESS_ORDER[actual ?? "projection_only"] ?? 0) >= HARNESS_READINESS_ORDER[required];
}

function workflowHarnessClusterForId(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
): WorkflowHarnessPromotionCluster | null {
  return (
    (workflow.metadata.harness?.promotionClusters ?? []).find(
      (cluster) => String(cluster.clusterId) === String(clusterId),
    ) ?? null
  );
}

function workflowHarnessNodesForCluster(
  workflow: WorkflowProject,
  cluster: WorkflowHarnessPromotionCluster,
): Node[] {
  const componentKinds = new Set(cluster.componentKinds);
  return workflow.nodes.filter((node) => {
    const componentKind =
      node.runtimeBinding?.componentKind ?? harnessComponentForNode(node)?.kind;
    return Boolean(componentKind && componentKinds.has(componentKind));
  });
}

function workflowHarnessPromotionClusterCurrentStatus(
  workflow: WorkflowProject,
  cluster: WorkflowHarnessPromotionCluster,
): WorkflowHarnessClusterPromotionStatus {
  if (cluster.promotionStatus) return cluster.promotionStatus;
  const latestPromoted = [...(workflow.metadata.harness?.promotionTransitions ?? [])]
    .reverse()
    .find(
      (attempt) =>
        attempt.clusterId === cluster.clusterId && attempt.attemptStatus === "promoted",
    );
  return latestPromoted?.nextStatus ?? "shadow_ready";
}

function workflowHarnessPromotionClusterWithStatus(
  clusters: WorkflowHarnessPromotionCluster[] | undefined,
  clusterId: WorkflowHarnessPromotionClusterId,
  status: WorkflowHarnessClusterPromotionStatus,
): WorkflowHarnessPromotionCluster[] | undefined {
  if (!clusters) return clusters;
  return clusters.map((cluster) =>
    cluster.clusterId === clusterId ? { ...cluster, promotionStatus: status } : cluster,
  );
}

function workflowHarnessCanaryBoundaryForCluster(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId,
): WorkflowHarnessCanaryExecutionBoundary | null {
  const harness = workflow.metadata.harness;
  return (
    [
      ...(harness?.canaryExecutionBoundaries ?? []),
      ...(harness?.canaryExecutionBoundary ? [harness.canaryExecutionBoundary] : []),
    ].find((boundary) => boundary.clusterId === clusterId) ?? null
  );
}

export function workflowHarnessPromotionTransitionEligibility(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget,
  options: { nowMs?: number } = {},
): WorkflowHarnessPromotionTransitionEligibility {
  const createdAtMs = options.nowMs ?? Date.now();
  const cluster = workflowHarnessClusterForId(workflow, clusterId);
  const fallbackClusterId = (
    typeof clusterId === "string" ? clusterId : "cognition"
  ) as WorkflowHarnessPromotionClusterId;
  const currentStatus = cluster
    ? workflowHarnessPromotionClusterCurrentStatus(workflow, cluster)
    : "blocked";
  const nodes = cluster ? workflowHarnessNodesForCluster(workflow, cluster) : [];
  const requiredReadiness =
    targetExecutionMode === "live" ? "live_ready" : cluster?.minimumReadiness ?? "shadow_ready";
  const readinessReady =
    Boolean(cluster) &&
    nodes.length > 0 &&
    nodes.every((node) =>
      workflowHarnessReadinessAllows(
        node.runtimeBinding?.readiness ?? harnessComponentForNode(node)?.readiness,
        requiredReadiness,
      ),
    );
  const replayGateProof = cluster?.replayGateProof;
  const canaryBoundary = cluster
    ? workflowHarnessCanaryBoundaryForCluster(workflow, cluster.clusterId)
    : null;
  const receiptRefs = uniqueStrings([
    ...(replayGateProof?.receiptRefs ?? []),
    ...(canaryBoundary?.receiptIds ?? []),
  ]);
  const receiptReady = Boolean(cluster) && nodes.length > 0 && receiptRefs.length > 0;
  const replayGateReady =
    replayGateProof?.gateStatus === "passed" &&
    replayGateProof.activationGateImpact === "passed" &&
    replayGateProof.totalFixtures > 0 &&
    replayGateProof.blockingDivergenceCount === 0 &&
    replayGateProof.blockingReplayFixtureRefs.length === 0;
  const activationRecord = workflow.metadata.harness?.activationRecord;
  const canaryReady =
    canaryBoundary?.status === "passed" &&
    canaryBoundary.canaryEligible === true &&
    canaryBoundary.rollbackDrill.drillStatus === "passed";
  const rollbackReady =
    (canaryBoundary?.rollbackAvailable === true && Boolean(canaryBoundary.rollbackTarget)) ||
    (activationRecord?.rollbackAvailable === true && Boolean(activationRecord.rollbackTarget));
  const targetOrderReady =
    targetExecutionMode === "gated" ||
    currentStatus === "gated" ||
    currentStatus === "live";
  const blockers = uniqueStrings([
    ...(cluster ? [] : ["promotion_cluster_missing"]),
    ...(targetOrderReady ? [] : ["promotion_live_requires_gated_cluster"]),
    ...(readinessReady ? [] : [`promotion_readiness_below_${requiredReadiness}`]),
    ...(receiptReady ? [] : ["promotion_receipts_missing"]),
    ...(replayGateReady ? [] : ["promotion_replay_gate_not_passed"]),
    ...(canaryReady ? [] : ["promotion_canary_not_passed"]),
    ...(rollbackReady ? [] : ["promotion_rollback_unavailable"]),
  ]);
  return {
    schemaVersion: "workflow.harness.promotion-transition-eligibility.v1",
    clusterId: cluster?.clusterId ?? fallbackClusterId,
    targetExecutionMode,
    currentStatus,
    eligible: blockers.length === 0,
    readinessReady,
    receiptReady,
    replayGateReady,
    canaryReady,
    rollbackReady,
    componentIds: uniqueStrings(
      nodes.map((node) => node.runtimeBinding?.componentId ?? harnessComponentForNode(node)?.componentId ?? node.id),
    ),
    receiptRefs,
    replayFixtureRefs: uniqueStrings([
      ...(replayGateProof?.replayFixtureRefs ?? []),
      ...(canaryBoundary?.replayFixtureRefs ?? []),
    ]),
    canaryBoundaryId: canaryBoundary?.boundaryId,
    rollbackTarget: canaryBoundary?.rollbackTarget ?? activationRecord?.rollbackTarget,
    blockers,
    evidenceRefs: uniqueStrings([
      replayGateProof?.gateId,
      canaryBoundary?.boundaryId,
      ...(replayGateProof?.evidenceRefs ?? []),
      ...(canaryBoundary?.evidenceRefs ?? []),
    ]),
    createdAtMs,
  };
}

export function executeWorkflowHarnessPromotionTransition(
  workflow: WorkflowProject,
  clusterId: WorkflowHarnessPromotionClusterId | string,
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget,
  options: { nowMs?: number } = {},
): {
  promoted: boolean;
  workflow: WorkflowProject;
  attempt: WorkflowHarnessPromotionTransitionAttempt;
  eligibility: WorkflowHarnessPromotionTransitionEligibility;
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const eligibility = workflowHarnessPromotionTransitionEligibility(
    workflow,
    clusterId,
    targetExecutionMode,
    { nowMs: createdAtMs },
  );
  const cluster = workflowHarnessClusterForId(workflow, eligibility.clusterId);
  const previousStatus = eligibility.currentStatus;
  const nextStatus: WorkflowHarnessClusterPromotionStatus = eligibility.eligible
    ? targetExecutionMode
    : previousStatus;
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const transitionId = `harness-promotion-transition:${slugify(workflowId)}:${slugify(
    `${eligibility.clusterId}:${targetExecutionMode}`,
  )}:${createdAtMs}`;
  const attempt: WorkflowHarnessPromotionTransitionAttempt = {
    schemaVersion: "workflow.harness.promotion-transition-attempt.v1",
    transitionId,
    workflowId,
    activationId: workflow.metadata.harness?.activationId,
    clusterId: eligibility.clusterId,
    clusterLabel:
      cluster?.label ?? HARNESS_PROMOTION_CLUSTER_LABELS[eligibility.clusterId],
    targetExecutionMode,
    previousStatus,
    nextStatus,
    attemptStatus: eligibility.eligible ? "promoted" : "blocked",
    gateDecision: eligibility.eligible
      ? "allow_promotion_transition"
      : "block_promotion_transition",
    eligibility,
    blockers: eligibility.blockers,
    receiptRefs: eligibility.receiptRefs,
    replayFixtureRefs: eligibility.replayFixtureRefs,
    evidenceRefs: uniqueStrings([transitionId, ...eligibility.evidenceRefs]),
    createdAtMs,
  };
  const promotionClusters = eligibility.eligible
    ? workflowHarnessPromotionClusterWithStatus(
        workflow.metadata.harness?.promotionClusters,
        eligibility.clusterId,
        nextStatus,
      )
    : workflow.metadata.harness?.promotionClusters;
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType: eligibility.eligible
        ? "promotion_transition_promoted"
        : "promotion_transition_blocked",
      status: eligibility.eligible ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      blockers: eligibility.blockers,
      evidenceRefs: attempt.evidenceRefs,
      receiptRefs: attempt.receiptRefs,
      summary: eligibility.eligible
        ? `${attempt.clusterLabel} promoted to ${targetExecutionMode}`
        : `${attempt.clusterLabel} promotion to ${targetExecutionMode} blocked by ${eligibility.blockers.length} gates`,
      createdAtMs,
    }),
    {
      promotionClusters,
      promotionTransitions: [
        ...(workflow.metadata.harness?.promotionTransitions ?? []),
        attempt,
      ],
    },
  );
  return {
    promoted: eligibility.eligible,
    workflow: workflowWithRefreshedHarnessRevisionBinding(workflowWithAudit, createdAtMs),
    attempt,
    eligibility,
    blockers: eligibility.blockers,
  };
}

export function executeWorkflowHarnessReplayDrill(
  workflow: WorkflowProject,
  replay: WorkflowHarnessReplayDrillInput | null | undefined,
  options: { nowMs?: number } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  drill?: WorkflowHarnessReplayDrillResult;
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const { drill, blockers } = workflowHarnessReplayDrillResultFor(
    workflow,
    replay,
    createdAtMs,
  );
  return {
    executed: blockers.length === 0,
    workflow: appendWorkflowHarnessActivationAudit(
      workflow,
      makeWorkflowHarnessActivationAuditEvent({
        workflow,
        eventType:
          blockers.length === 0 ? "replay_drill_passed" : "replay_drill_blocked",
        status: blockers.length === 0 ? "passed" : "blocked",
        activationId: workflow.metadata.harness?.activationId,
        blockers,
        evidenceRefs: drill.evidenceRefs,
        receiptRefs: drill.receiptRefs,
        summary:
          blockers.length === 0
            ? `Replay drill passed: ${drill.replayFixtureRef}`
            : `Replay drill blocked by ${blockers.length} blockers`,
        createdAtMs,
      }),
      {
        replayDrills: [
          ...(workflow.metadata.harness?.replayDrills ?? []),
          drill,
        ],
      },
    ),
    drill,
    blockers,
  };
}

export function executeWorkflowHarnessReplayGate(
  workflow: WorkflowProject,
  replays: Array<WorkflowHarnessReplayDrillInput | null | undefined>,
  options: {
    scopeKind?: WorkflowHarnessReplayGateResult["scopeKind"];
    targetId?: string;
    nowMs?: number;
  } = {},
): {
  executed: boolean;
  workflow: WorkflowProject;
  gate: WorkflowHarnessReplayGateResult;
  drills: WorkflowHarnessReplayDrillResult[];
  blockers: string[];
} {
  const createdAtMs = options.nowMs ?? Date.now();
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const scopeKind = options.scopeKind ?? "workflow";
  const targetId = options.targetId ?? workflowId;
  const drills = replays.map((replay, index) =>
    workflowHarnessReplayDrillResultFor(workflow, replay, createdAtMs + index).drill,
  );
  const blockingDrills = drills.filter(replayDrillBlocksPromotion);
  const divergenceCounts = drills.reduce<Record<string, number>>((counts, drill) => {
    counts[drill.divergenceClass] = (counts[drill.divergenceClass] ?? 0) + 1;
    return counts;
  }, {});
  const blockers = uniqueStrings([
    ...(workflow.metadata.harness ? [] : ["not_harness_workflow"]),
    ...(drills.length > 0 ? [] : ["replay_gate_no_fixtures"]),
    ...blockingDrills.flatMap((drill) =>
      drill.blockers.length > 0
        ? drill.blockers
        : [`replay_divergence:${drill.divergenceClass}`],
    ),
  ]);
  const gateId = `harness-replay-gate:${slugify(workflowId)}:${slugify(
    `${scopeKind}:${targetId}`,
  )}:${createdAtMs}`;
  const gate: WorkflowHarnessReplayGateResult = {
    schemaVersion: "workflow.harness.replay-gate-result.v1",
    gateId,
    workflowId,
    activationId: workflow.metadata.harness?.activationId,
    scopeKind,
    targetId,
    gateStatus: blockers.length === 0 ? "passed" : "blocked",
    totalFixtures: drills.length,
    passedCount: drills.filter((drill) => drill.drillStatus === "passed").length,
    blockedCount: drills.filter((drill) => drill.drillStatus === "blocked").length,
    failedCount: drills.filter((drill) => drill.drillStatus === "failed").length,
    divergenceCounts,
    replayFixtureRefs: uniqueStrings(drills.map((drill) => drill.replayFixtureRef)),
    blockingReplayFixtureRefs: uniqueStrings(
      blockingDrills.map((drill) => drill.replayFixtureRef),
    ),
    drillIds: drills.map((drill) => drill.drillId),
    receiptRefs: uniqueStrings(drills.flatMap((drill) => drill.receiptRefs)),
    evidenceRefs: uniqueStrings([
      gateId,
      ...drills.flatMap((drill) => drill.evidenceRefs),
    ]),
    activationGateImpact: blockers.length === 0 ? "passed" : "blocked",
    blockers,
    createdAtMs,
  };
  const promotionClusters = workflowHarnessPromotionClustersWithReplayGateProof(
    workflow,
    gate,
  );
  const workflowWithAudit = appendWorkflowHarnessActivationAudit(
    workflow,
    makeWorkflowHarnessActivationAuditEvent({
      workflow,
      eventType:
        blockers.length === 0 ? "replay_gate_passed" : "replay_gate_blocked",
      status: blockers.length === 0 ? "passed" : "blocked",
      activationId: workflow.metadata.harness?.activationId,
      blockers,
      evidenceRefs: gate.evidenceRefs,
      receiptRefs: gate.receiptRefs,
      summary:
        blockers.length === 0
          ? `Replay gate passed: ${gate.totalFixtures} fixtures`
          : `Replay gate blocked by ${blockingDrills.length} fixtures`,
      createdAtMs,
    }),
    {
      replayDrills: [
        ...(workflow.metadata.harness?.replayDrills ?? []),
        ...drills,
      ],
      replayGates: [
        ...(workflow.metadata.harness?.replayGates ?? []),
        gate,
      ],
      promotionClusters,
    },
  );
  return {
    executed: blockers.length === 0,
    workflow: workflowWithRefreshedHarnessRevisionBinding(workflowWithAudit, createdAtMs),
    gate,
    drills,
    blockers,
  };
}

export function applyWorkflowHarnessActivationCandidate(
  workflow: WorkflowProject,
  candidate: WorkflowHarnessForkActivationCandidate | null | undefined,
  options: {
    rollbackTarget?: string | null;
    nowMs?: number;
  } = {},
): {
  applied: boolean;
  workflow: WorkflowProject;
  activationId?: string;
  blockers: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  rollbackTarget?: string;
} {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const activationId = candidate?.activationId ?? candidate?.activationIdPreview;
  const blockers = [
    ...(candidate?.activationBlockers ?? []),
    ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ...(candidate?.decision === "mintable" ? [] : ["candidate_not_mintable"]),
    ...(activationId ? [] : ["activation_id_missing"]),
  ];
  if (blockers.length > 0 || !candidate || !activationId) {
    const uniqueBlockers = Array.from(new Set(blockers));
    const receiptRefs = activationCandidateReceiptRefs(candidate);
    return {
      applied: false,
      workflow: workflowIsHarnessFork(workflow)
        ? appendWorkflowHarnessActivationAudit(
            workflow,
            makeWorkflowHarnessActivationAuditEvent({
              workflow,
              eventType: "activation_mint_blocked",
              status: "blocked",
              candidateId: candidate?.candidateId,
              activationId,
              previousActivationId: workflow.metadata.harness?.activationId,
              nextActivationId: activationId,
              previousWorkerBinding: workflow.metadata.workerHarnessBinding,
              nextWorkerBinding: candidate?.workerBindingPreview,
              previousRevisionBinding: workflow.metadata.harness?.revisionBinding,
              nextRevisionBinding: candidate?.revisionBindingPreview,
              rollbackTarget: candidate?.rollbackTarget,
              blockers: uniqueBlockers,
              evidenceRefs: candidate?.evidenceRefs ?? [],
              receiptRefs,
              summary: `Activation mint blocked by ${uniqueBlockers.length} blockers`,
              createdAtMs: options.nowMs ?? Date.now(),
            }),
          )
        : workflow,
      blockers: uniqueBlockers,
    };
  }

  const nowMs = options.nowMs ?? Date.now();
  const rollbackTarget =
    options.rollbackTarget?.trim() ||
    candidate.rollbackTarget ||
    workflow.metadata.harness?.activationRecord?.rollbackTarget ||
    DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET;
  const previousRevisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    workflow.metadata.harness?.activationRecord?.revisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: workflow.metadata.harness?.activationId,
      rollbackActivationId: rollbackTarget,
      nowMs,
    });
  const workerBinding: WorkflowHarnessWorkerBinding = {
    ...candidate.workerBindingPreview,
    harnessWorkflowId: candidate.workerBindingPreview.harnessWorkflowId || workflowId,
    harnessActivationId: activationId,
    harnessHash:
      candidate.workerBindingPreview.harnessHash ||
      candidate.harnessHash ||
      workflow.metadata.harness?.harnessHash ||
      DEFAULT_AGENT_HARNESS_HASH,
    executionMode:
      candidate.workerBindingPreview.executionMode ??
      workflow.metadata.harness?.executionMode ??
      DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
  };
  const revisionBinding: WorkflowRevisionBinding = {
    ...candidate.revisionBindingPreview,
    activationId,
    rollbackActivationId: rollbackTarget,
    rollbackRevision:
      previousRevisionBinding.activatedRevision ?? previousRevisionBinding.workflowContentHash,
    createdAtMs: nowMs,
  };
  const receiptRefs = activationCandidateReceiptRefs(candidate);
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId,
    harnessWorkflowId: workerBinding.harnessWorkflowId,
    activationId,
    activationState: "validated",
    activationBlockers: [],
    componentVersionSet: candidate.componentVersionSet,
    harnessHash: candidate.harnessHash,
    policyPosture: candidate.policyPosture,
    canaryStatus: candidate.canaryStatus,
    rollbackTarget,
    rollbackAvailable: candidate.rollbackAvailable || Boolean(rollbackTarget),
    liveAuthorityTransferred: false,
    evidenceRefs: uniqueStrings([candidate.candidateId, ...receiptRefs, ...candidate.evidenceRefs]),
    workerBinding,
    revisionBinding,
    rollbackRevisionBinding: previousRevisionBinding,
    rollbackRestoreCanary: candidate.rollbackRestoreCanary,
    mintedAtMs: nowMs,
  });
  return {
    applied: true,
    workflow: appendWorkflowHarnessActivationAudit(
      {
        ...workflow,
        metadata: {
          ...workflow.metadata,
          dirty: true,
          harness: workflow.metadata.harness
            ? {
                ...workflow.metadata.harness,
                harnessWorkflowId: workerBinding.harnessWorkflowId,
                harnessHash: workerBinding.harnessHash,
                executionMode:
                  workerBinding.executionMode ?? workflow.metadata.harness.executionMode,
                activationId,
                activationState: "validated",
                activationRecord,
                revisionBinding,
              }
            : workflow.metadata.harness,
          workerHarnessBinding: workerBinding,
          updatedAtMs: nowMs,
        },
      },
      makeWorkflowHarnessActivationAuditEvent({
        workflow,
        eventType: "activation_minted",
        status: "applied",
        candidateId: candidate.candidateId,
        activationId,
        previousActivationId: workflow.metadata.harness?.activationId,
        nextActivationId: activationId,
        previousWorkerBinding: workflow.metadata.workerHarnessBinding,
        nextWorkerBinding: workerBinding,
        previousRevisionBinding,
        nextRevisionBinding: revisionBinding,
        rollbackTarget,
        evidenceRefs: uniqueStrings([candidate.candidateId, ...receiptRefs, ...candidate.evidenceRefs]),
        receiptRefs,
        summary: `Activation minted: ${activationId}`,
        createdAtMs: nowMs,
      }),
    ),
    activationId,
    blockers: [],
    workerBinding,
    rollbackTarget,
  };
}

export function makeBlessedHarnessLiveHandoffProof(options: {
  selector?: WorkflowHarnessLiveHandoffProof["selector"];
  productionDefaultSelector?: WorkflowHarnessLiveHandoffProof["productionDefaultSelector"];
  canaryStatus?: WorkflowHarnessLiveHandoffProof["canaryStatus"];
  canaryTurnRoutedThroughWorkflow?: boolean;
  defaultAuthorityTransferred?: boolean;
  runtimeAuthority?: WorkflowHarnessLiveHandoffProof["runtimeAuthority"];
  fallbackSelector?: WorkflowHarnessLiveHandoffProof["fallbackSelector"];
  rollbackAvailable?: boolean;
  policyDecision?: string;
  defaultPromotionGateEnabled?: boolean;
  defaultPromotionGateEligible?: boolean;
  defaultPromotionGateActivationBlockers?: string[];
  defaultPromotionGatePolicyDecision?: string;
  activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
  activationIdGateProofNowMs?: number;
  activationIdGateProofMaxAgeMs?: number;
  requireActivationIdGateClickProof?: boolean;
  gatedClusterIds?: WorkflowHarnessLiveHandoffProof["gatedClusterIds"];
  executionBoundaryIds?: string[];
  executionBoundaryClusterIds?: WorkflowHarnessPromotionClusterId[];
  nodeTimelineAttemptIds?: string[];
  receiptIds?: string[];
  replayFixtureRefs?: string[];
  activationBlockers?: string[];
  evidenceRefs?: string[];
} = {}): WorkflowHarnessLiveHandoffProof {
  const selector = options.selector ?? "blessed_workflow_live_canary";
  const defaultAuthorityTransferred = options.defaultAuthorityTransferred ?? false;
  const productionDefaultSelector =
    options.productionDefaultSelector ??
    (defaultAuthorityTransferred ? "blessed_workflow_live_default" : "legacy_runtime");
  const defaultPromotionGateEnabled =
    options.defaultPromotionGateEnabled ?? defaultAuthorityTransferred;
  const defaultPromotionGateEligible =
    options.defaultPromotionGateEligible ?? defaultAuthorityTransferred;
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? defaultAuthorityTransferred)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const defaultPromotionGateActivationBlockers =
    uniqueStrings([
      ...(options.defaultPromotionGateActivationBlockers ??
        (defaultPromotionGateEligible ? [] : ["promotion_gate_disabled"])),
      ...activationIdGateProofBlockers,
    ]);
  const activationBlockers = uniqueStrings([
    ...(options.activationBlockers ?? []),
    ...activationIdGateProofBlockers,
  ]);
  const defaultPromotionGatePolicyDecision =
    options.defaultPromotionGatePolicyDecision ??
    (defaultPromotionGateEligible
      ? "promote_blessed_workflow_default_for_non_mutating_turn"
      : "retain_legacy_runtime_default");
  return {
    schemaVersion: "workflow.harness.live-handoff.v1",
    selector,
    availableSelectors: [
      "legacy_runtime",
      "blessed_workflow_gated",
      "blessed_workflow_live_canary",
      "blessed_workflow_live_default",
    ],
    productionDefaultSelector,
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    componentVersionSet: defaultHarnessComponentVersionSet(),
    canaryStatus: options.canaryStatus ?? "passed",
    canaryTurnRoutedThroughWorkflow: options.canaryTurnRoutedThroughWorkflow ?? true,
    executionBoundaryId:
      "harness-canary-boundary:default-agent-harness:verification_output",
    executionBoundaryIds:
      options.executionBoundaryIds ?? [
        "harness-canary-boundary:default-agent-harness:cognition",
        "harness-canary-boundary:default-agent-harness:routing_model",
        "harness-canary-boundary:default-agent-harness:verification_output",
        "harness-canary-boundary:default-agent-harness:authority_tooling",
      ],
    executionBoundaryClusterIds:
      options.executionBoundaryClusterIds ?? [
        "cognition",
        "routing_model",
        "verification_output",
        "authority_tooling",
      ],
    executionBoundaryStatus: "passed",
    executionBoundaryExecutor: "crate::project::execute_workflow_harness_canary_node",
    defaultAuthorityTransferred,
    runtimeAuthority:
      options.runtimeAuthority ??
      (defaultAuthorityTransferred
        ? "blessed_workflow_activation_default"
        : "blessed_workflow_activation_canary"),
    fallbackSelector: options.fallbackSelector ?? "legacy_runtime",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: options.rollbackAvailable ?? true,
    policyDecision:
      options.policyDecision ??
      (defaultAuthorityTransferred
        ? "promote_blessed_workflow_default_for_non_mutating_turn"
        : "allow_blessed_workflow_live_canary"),
    gatedClusterIds:
      options.gatedClusterIds ?? [
        "cognition",
        "routing_model",
        "verification_output",
        "authority_tooling",
      ],
    nodeTimelineAttemptIds: options.nodeTimelineAttemptIds ?? [],
    receiptIds: options.receiptIds ?? [],
    replayFixtureRefs: options.replayFixtureRefs ?? [],
    activationBlockers,
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: defaultPromotionGateEnabled,
      eligible: defaultPromotionGateEligible,
      nonMutatingOnly: true,
      selector,
      productionDefaultSelector,
      defaultAuthorityTransferred,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      activationBlockers: defaultPromotionGateActivationBlockers,
      policyDecision: defaultPromotionGatePolicyDecision,
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

export function makeHarnessRuntimeSelectorDecision(options: {
  decisionId?: string;
  requestedSelector?: WorkflowHarnessRuntimeSelectorDecision["requestedSelector"];
  selectedSelector?: WorkflowHarnessRuntimeSelectorDecision["selectedSelector"];
  productionDefaultSelector?: WorkflowHarnessRuntimeSelectorDecision["productionDefaultSelector"];
  canaryEligible?: boolean;
  canaryBlockers?: string[];
  executionMode?: WorkflowHarnessExecutionMode;
  actualRuntimeAuthority?: WorkflowHarnessRuntimeSelectorDecision["actualRuntimeAuthority"];
  policyDecision?: string;
  routeReason?: string;
  defaultPromotionGateEnabled?: boolean;
  defaultPromotionGateEligible?: boolean;
  defaultPromotionGateAuthorityTransferred?: boolean;
  defaultPromotionGateActivationBlockers?: string[];
  defaultPromotionGatePolicyDecision?: string;
  activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
  activationIdGateProofNowMs?: number;
  activationIdGateProofMaxAgeMs?: number;
  requireActivationIdGateClickProof?: boolean;
  evidenceRefs?: string[];
} = {}): WorkflowHarnessRuntimeSelectorDecision {
  const selectedSelector = options.selectedSelector ?? "blessed_workflow_live_canary";
  const workflowSelected =
    selectedSelector === "blessed_workflow_live_canary" ||
    selectedSelector === "blessed_workflow_live_default";
  const defaultSelected = selectedSelector === "blessed_workflow_live_default";
  const productionDefaultSelector =
    options.productionDefaultSelector ??
    (defaultSelected ? "blessed_workflow_live_default" : "legacy_runtime");
  const defaultPromotionGateEnabled =
    options.defaultPromotionGateEnabled ?? defaultSelected;
  const defaultPromotionGateEligible =
    options.defaultPromotionGateEligible ?? defaultSelected;
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? defaultSelected)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const defaultPromotionGateAuthorityTransferred =
    options.defaultPromotionGateAuthorityTransferred ?? defaultSelected;
  const defaultPromotionGateActivationBlockers =
    uniqueStrings([
      ...(options.defaultPromotionGateActivationBlockers ??
        (defaultPromotionGateEligible ? [] : ["promotion_gate_disabled"])),
      ...activationIdGateProofBlockers,
    ]);
  const defaultPromotionGatePolicyDecision =
    options.defaultPromotionGatePolicyDecision ??
    (defaultPromotionGateEligible
      ? "promote_blessed_workflow_default_for_non_mutating_turn"
      : "retain_legacy_runtime_default");
  return {
    schemaVersion: "workflow.harness.runtime-selector.v1",
    decisionId: options.decisionId ?? "harness-selector:default-agent-harness:canary",
    requestedSelector: options.requestedSelector ?? "auto_canary",
    selectedSelector,
    productionDefaultSelector,
    canaryEligible: options.canaryEligible ?? workflowSelected,
    canaryBlockers: options.canaryBlockers ?? [],
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: options.executionMode ?? (workflowSelected ? "live" : "gated"),
    actualRuntimeAuthority:
      options.actualRuntimeAuthority ??
      (defaultSelected
        ? "blessed_workflow_activation_default"
        : workflowSelected
          ? "blessed_workflow_activation_canary"
          : "existing_runtime_service"),
    fallbackSelector: "legacy_runtime",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    policyDecision:
      options.policyDecision ??
      (defaultSelected
        ? "promote_blessed_workflow_default_for_non_mutating_turn"
        : workflowSelected
        ? "allow_blessed_workflow_live_canary"
        : "retain_legacy_runtime_default"),
    routeReason:
      options.routeReason ??
      (defaultSelected
        ? "Blessed workflow activation is promoted to the default runtime selector for a non-mutating turn."
        : workflowSelected
        ? "Turn is non-mutating and eligible for blessed workflow canary routing."
        : "Turn remains on the legacy runtime selector."),
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: defaultPromotionGateEnabled,
      eligible: defaultPromotionGateEligible,
      nonMutatingOnly: true,
      selector: selectedSelector,
      productionDefaultSelector,
      defaultAuthorityTransferred: defaultPromotionGateAuthorityTransferred,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      activationBlockers: defaultPromotionGateActivationBlockers,
      policyDecision: defaultPromotionGatePolicyDecision,
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

const DEFAULT_COGNITION_ADAPTER_COMPONENTS: Array<{
  kind: WorkflowHarnessComponentKind;
  attemptSlug: string;
  policyDecision: string;
}> = [
  {
    kind: "planner",
    attemptSlug: "planner_envelope",
    policyDecision: "accept_workflow_planner_objective_envelope",
  },
  {
    kind: "prompt_assembler",
    attemptSlug: "prompt_assembler_envelope",
    policyDecision: "accept_workflow_prompt_assembly_hash_envelope",
  },
  {
    kind: "task_state",
    attemptSlug: "task_state_envelope",
    policyDecision: "accept_workflow_task_state_envelope",
  },
];

function makeDefaultCognitionAdapterResult(
  kind: WorkflowHarnessComponentKind,
  attemptSlug: string,
  policyDecision: string,
  attemptIndex: number,
): WorkflowHarnessComponentAdapterResult {
  const component = componentFor(kind);
  const replay = {
    ...replayEnvelopeFor(component),
    fixtureRef: `harness-default-dispatch:fixture-${attemptSlug}`,
  };
  const actionFrame = {
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    workflowVersion: DEFAULT_AGENT_HARNESS_VERSION,
    workflowHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: "live" as WorkflowHarnessExecutionMode,
    nodeId: `harness.${kind}`,
    componentId: component.componentId,
    componentVersion: component.version,
    componentKind: kind,
    readiness: component.readiness,
    kernelRef: component.kernelRef,
    slotIds: slotIdsFor(kind),
    deterministicEnvelope: replay.deterministicEnvelope,
    replay,
    eventKinds: component.emittedEvents,
    evidenceKeys: component.evidence,
  };
  const receiptId = `harness-default-dispatch:receipt-${attemptSlug}`;
  const outputHash = `sha256:${attemptSlug}`;
  return {
    schemaVersion: "workflow.harness.component-adapter-result.v1",
    invocationId: `default-dispatch:${attemptSlug}`,
    actionFrame,
    nodeAttempt: {
      attemptId: `${actionFrame.nodeId}:default-dispatch:${attemptSlug}`,
      harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      harnessHash: DEFAULT_AGENT_HARNESS_HASH,
      workflowNodeId: actionFrame.nodeId,
      componentId: actionFrame.componentId,
      componentKind: kind,
      executionMode: "live",
      readiness: component.readiness,
      attemptIndex,
      status: "live",
      inputHash: `sha256:input-${attemptSlug}`,
      outputHash,
      policyDecision,
      receiptIds: [receiptId],
      evidenceRefs: [`runtime-evidence:default`, DEFAULT_AGENT_HARNESS_ACTIVATION_ID],
      replay,
    },
    slotIds: actionFrame.slotIds,
    resultHash: outputHash,
    readiness: component.readiness,
    receiptIds: [receiptId],
    replay,
  };
}

function makeDefaultCognitionAdapterResults(): WorkflowHarnessComponentAdapterResult[] {
  return DEFAULT_COGNITION_ADAPTER_COMPONENTS.map((component, index) =>
    makeDefaultCognitionAdapterResult(
      component.kind,
      component.attemptSlug,
      component.policyDecision,
      index + 1,
    ),
  );
}

export function makeHarnessDefaultRuntimeDispatchProof(options: {
  dispatchId?: string;
  selectorDecisionId?: string;
  acceptedClusterIds?: WorkflowHarnessPromotionClusterId[];
  sourceBoundaryIds?: string[];
  dispatchNodeAttemptIds?: string[];
  outputWriterHandoffAttemptIds?: string[];
  acceptedNodeAttemptIds?: string[];
  nodeAttemptIds?: string[];
  receiptIds?: string[];
  replayFixtureRefs?: string[];
  activationBlockers?: string[];
  activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof | null;
  activationIdGateProofNowMs?: number;
  activationIdGateProofMaxAgeMs?: number;
  activationIdGateWorkerBindingActivationId?: string;
  requireActivationIdGateClickProof?: boolean;
  evidenceRefs?: string[];
} = {}): WorkflowHarnessDefaultRuntimeDispatchProof {
  const acceptedClusterIds = options.acceptedClusterIds ?? [
    "cognition",
    "routing_model",
    "verification_output",
    "authority_tooling",
  ];
  const deferredComponentKinds: WorkflowHarnessComponentKind[] = [
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];
  const authorityToolingReadOnlyComponentKinds: WorkflowHarnessComponentKind[] = [
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];
  const authorityToolingMutationDeferredComponentKinds: WorkflowHarnessComponentKind[] = [
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ];
  const proposedVisibleOutputHash = "sha256:visible-output";
  const actualVisibleOutputHash = "sha256:visible-output";
  const promptAssemblyPromptHash = "sha256:prompt-final";
  const modelExecutionBindingId =
    "model-binding:default-agent-harness:workflow-default-model-route";
  const modelExecutionPromptHash = promptAssemblyPromptHash;
  const modelExecutionOutputHash = actualVisibleOutputHash;
  const cognitionExecutionAdapterResults = makeDefaultCognitionAdapterResults();
  const cognitionExecutionActionFrameIds = cognitionExecutionAdapterResults.map(
    (result) => `${result.actionFrame.nodeId}:${result.actionFrame.componentId}`,
  );
  const cognitionExecutionLiveReadyComponentKinds = cognitionExecutionAdapterResults.map(
    (result) => result.actionFrame.componentKind,
  );
  const activationIdGateProofBlockers =
    (options.requireActivationIdGateClickProof ?? true)
      ? workflowHarnessActivationIdGateClickProofBlockers(
          options.activationIdGateClickProof,
          {
            nowMs: options.activationIdGateProofNowMs,
            maxAgeMs: options.activationIdGateProofMaxAgeMs,
          },
        )
      : [];
  const activationBlockers = uniqueStrings([
    ...(options.activationBlockers ?? []),
    ...activationIdGateProofBlockers,
  ]);
  const dispatchAccepted = activationBlockers.length === 0;
  const activationIdGateClickProofPresent = Boolean(
    options.activationIdGateClickProof,
  );
  const activationIdGateClickProofPassed =
    activationIdGateClickProofPresent &&
    activationIdGateProofBlockers.length === 0;
  const activationIdGateWorkerBindingActivationId =
    activationIdGateClickProofPassed
      ? options.activationIdGateWorkerBindingActivationId ??
        DEFAULT_AGENT_HARNESS_ACTIVATION_ID
      : "";
  const workflowTranscriptWriteCandidate = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef: "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "blessed_workflow_activation_default",
    committed: false,
    commitMode: "candidate_only",
  };
  const workflowTranscriptWriteRecord = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef: "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeIdentityHash: "sha256:workflow-visible-transcript-write",
    writeAuthority: "blessed_workflow_activation_default",
    committed: true,
    visible: true,
    visibleTranscriptCommit: true,
    commitMode: "workflow_visible_transcript_write",
  };
  const legacyTranscriptWriteRecord = {
    target: "checkpoint_transcript_messages",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: actualVisibleOutputHash,
    receiptBindingRef: "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "existing_runtime_service",
    committed: false,
    suppressedByIdempotency: true,
    commitMode: "idempotent_noop",
  };
  const stagedTranscriptWriteRecord = {
    target: "checkpoint_transcript_messages",
    stagingSurface: "checkpoint_blobs",
    checkpointName: "autopilot.workflow_output_writer_transcript_staging.v1",
    role: "agent",
    timestampMs: 1,
    orderIndex: 1,
    contentHash: proposedVisibleOutputHash,
    receiptBindingRef: "checkpoint_transcript_messages:default-agent-harness:agent:1:1",
    writeAuthority: "blessed_workflow_activation_default",
    committed: true,
    stagingCommitted: true,
    visible: false,
    visibleTranscriptCommit: false,
    commitMode: "staged_non_visible",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  };
  const stagedTranscriptWriteProof = {
    schemaVersion: "workflow.output_writer.transcript-staging-proof.v1",
    surface: "checkpoint_blobs",
    checkpointName: "autopilot.workflow_output_writer_transcript_staging.v1",
    record: stagedTranscriptWriteRecord,
    persisted: true,
    loadedBeforeRollback: true,
    visibleBeforeCount: 1,
    visibleAfterCount: 1,
    excludedFromVisibleTranscript: true,
    rollbackAction: "delete_checkpoint_blob",
    rollbackExecuted: true,
    rollbackVerified: true,
    rollbackStatus: "deleted",
  };
  const visibleTranscriptWriteProof = {
    schemaVersion: "workflow.output_writer.visible-transcript-write-proof.v1",
    mode: "workflow_visible_transcript_write",
    target: "checkpoint_transcript_messages",
    record: workflowTranscriptWriteRecord,
    persisted: true,
    committed: true,
    created: true,
    visible: true,
    visibleRowsDelta: 1,
    idempotencyGuard: "session_role_timestamp_order_content_hash_receipt_binding",
    duplicateSuppressionReady: true,
    identityCheckpointPersisted: true,
    rollbackAvailable: true,
    rollbackMode: "legacy_runtime_fallback_with_idempotent_duplicate_suppression",
  };
  const legacyTranscriptFallbackProof = {
    schemaVersion: "workflow.output_writer.legacy-transcript-fallback.v1",
    phase: "legacy_fallback_after_workflow_output",
    writeAuthority: "existing_runtime_service",
    appendedCount: 0,
    duplicateSuppressedCount: 1,
    latestAgentDuplicateSuppressed: true,
    idempotencyGuard: "role_timestamp_content_hash",
  };
  return {
    schemaVersion: "workflow.harness.default-runtime-dispatch.v1",
    dispatchId:
      options.dispatchId ?? "harness-default-dispatch:default-agent-harness:readonly",
    selectorDecisionId:
      options.selectorDecisionId ?? "harness-selector:default-agent-harness:default",
    selectedSelector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: dispatchAccepted ? "live" : "gated",
    runtimeAuthority: dispatchAccepted
      ? "blessed_workflow_activation_default"
      : "existing_runtime_service",
    dispatchScope: "read_only_cognition_routing_verification_completion_authority_tooling",
    acceptedClusterIds,
    componentKinds: acceptedClusterIds
      .flatMap((clusterId) => HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId])
      .filter((componentKind) => !deferredComponentKinds.includes(componentKind)),
    deferredComponentKinds,
    handoffValidatedComponentKinds: ["output_writer"],
    materializationCanaryComponentKinds: ["output_writer"],
    sourceBoundaryIds:
      options.sourceBoundaryIds ??
      acceptedClusterIds.map(
        (clusterId) => `harness-canary-boundary:default-agent-harness:${clusterId}`,
      ),
    dispatchNodeAttemptIds:
      options.dispatchNodeAttemptIds ?? [
        ...acceptedClusterIds.map(
          (clusterId) => `harness-default-dispatch:attempt-${clusterId}`,
        ),
        "harness-default-dispatch:attempt-planner_envelope",
        "harness-default-dispatch:attempt-prompt_assembler_envelope",
        "harness-default-dispatch:attempt-task_state_envelope",
        "harness-default-dispatch:attempt-model_router_envelope",
        "harness-default-dispatch:attempt-model_call_envelope",
        "harness-default-dispatch:attempt-model_provider_call_canary",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
        "harness-default-dispatch:attempt-read_only_source_router",
        "harness-default-dispatch:attempt-read_only_capability_sequencer",
        "harness-default-dispatch:attempt-read_only_tool_router",
        "harness-default-dispatch:attempt-read_only_no_mutation_drill",
        "harness-default-dispatch:attempt-output_writer_handoff",
        "harness-default-dispatch:attempt-output_writer_materialization_canary",
        "harness-default-dispatch:attempt-output_writer_staged_write_canary",
        "harness-default-dispatch:attempt-output_writer_visible_write_commit",
        "harness-default-dispatch:attempt-authority_tooling_policy_gate",
        "harness-default-dispatch:attempt-authority_tooling_tool_router",
        "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator",
        "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
        "harness-default-dispatch:attempt-authority_tooling_approval_gate",
        "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ],
    cognitionExecutionAttemptIds: [
      "harness-default-dispatch:attempt-planner_envelope",
      "harness-default-dispatch:attempt-prompt_assembler_envelope",
      "harness-default-dispatch:attempt-task_state_envelope",
    ],
    cognitionExecutionReceiptIds: [
      "harness-default-dispatch:receipt-planner_envelope",
      "harness-default-dispatch:receipt-prompt_assembler_envelope",
      "harness-default-dispatch:receipt-task_state_envelope",
    ],
    cognitionExecutionReplayFixtureRefs: [
      "harness-default-dispatch:fixture-planner_envelope",
      "harness-default-dispatch:fixture-prompt_assembler_envelope",
      "harness-default-dispatch:fixture-task_state_envelope",
    ],
    cognitionExecutionAdapterMode: "workflow_component_adapter_live",
    cognitionExecutionAdapterResults,
    cognitionExecutionActionFrameIds,
    cognitionExecutionLiveReadyComponentKinds,
    modelExecutionAttemptIds: [
      "harness-default-dispatch:attempt-model_router_envelope",
      "harness-default-dispatch:attempt-model_call_envelope",
      "harness-default-dispatch:attempt-model_provider_call_canary",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelExecutionReceiptIds: [
      "harness-default-dispatch:receipt-model_router_envelope",
      "harness-default-dispatch:receipt-model_call_envelope",
      "harness-default-dispatch:receipt-model_provider_call_canary",
      "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelExecutionReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_router_envelope",
      "harness-default-dispatch:fixture-model_call_envelope",
      "harness-default-dispatch:fixture-model_provider_call_canary",
      "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderCanaryAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_call_canary",
    ],
    modelProviderCanaryReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_call_canary",
    ],
    modelProviderCanaryReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_call_canary",
    ],
    modelProviderGatedVisibleOutputAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_gated_visible_output",
    ],
    modelProviderGatedVisibleOutputRollbackDrillAttemptIds: [
      "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderGatedVisibleOutputRollbackDrillReceiptIds: [
      "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
    ],
    modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs: [
      "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
    ],
    readOnlyCapabilityRoutingAttemptIds: [
      "harness-default-dispatch:attempt-read_only_source_router",
      "harness-default-dispatch:attempt-read_only_capability_sequencer",
      "harness-default-dispatch:attempt-read_only_tool_router",
      "harness-default-dispatch:attempt-read_only_no_mutation_drill",
    ],
    readOnlyCapabilityRoutingReceiptIds: [
      "harness-default-dispatch:receipt-read_only_source_router",
      "harness-default-dispatch:receipt-read_only_capability_sequencer",
      "harness-default-dispatch:receipt-read_only_tool_router",
      "harness-default-dispatch:receipt-read_only_no_mutation_drill",
    ],
    readOnlyCapabilityRoutingReplayFixtureRefs: [
      "harness-default-dispatch:fixture-read_only_source_router",
      "harness-default-dispatch:fixture-read_only_capability_sequencer",
      "harness-default-dispatch:fixture-read_only_tool_router",
      "harness-default-dispatch:fixture-read_only_no_mutation_drill",
    ],
    outputWriterHandoffAttemptIds:
      options.outputWriterHandoffAttemptIds ?? [
        "harness-default-dispatch:attempt-output_writer_handoff",
      ],
    outputWriterMaterializationCanaryAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_materialization_canary",
    ],
    outputWriterStagedWriteCanaryAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_staged_write_canary",
    ],
    outputWriterVisibleWriteAttemptIds: [
      "harness-default-dispatch:attempt-output_writer_visible_write_commit",
    ],
    authorityToolingLiveDryRunAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      "harness-default-dispatch:attempt-authority_tooling_tool_router",
      "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator",
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
    ],
    authorityToolingGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_policy_gate",
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      "harness-default-dispatch:receipt-authority_tooling_approval_gate",
    ],
    authorityToolingGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_policy_gate",
      "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
      "harness-default-dispatch:fixture-authority_tooling_approval_gate",
    ],
    authorityToolingPolicyGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_policy_gate",
    ],
    authorityToolingPolicyGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_policy_gate",
    ],
    authorityToolingPolicyGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_policy_gate",
    ],
    authorityToolingDestructiveDenialLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
    ],
    authorityToolingDestructiveDenialLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
    ],
    authorityToolingDestructiveDenialLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
    ],
    authorityToolingApprovalGateLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_approval_gate",
    ],
    authorityToolingApprovalGateLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_approval_gate",
    ],
    authorityToolingApprovalGateLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_approval_gate",
    ],
    authorityToolingReadOnlyLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
      "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
      "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingProviderCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingProviderCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingProviderCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
    ],
    authorityToolingMcpToolCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingMcpToolCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingMcpToolCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
    ],
    authorityToolingNativeToolCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
    ],
    authorityToolingConnectorCatalogLiveReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunAttemptIds: [
      "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs: [
      "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
    ],
    authorityToolingReadOnlyComponentKinds,
    authorityToolingMutationDeferredComponentKinds,
    authorityToolingDenialReceiptIds: [
      "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
    ],
    acceptedNodeAttemptIds: options.acceptedNodeAttemptIds ?? [],
    nodeAttemptIds: options.nodeAttemptIds ?? [],
    receiptIds: options.receiptIds ?? [],
    replayFixtureRefs: options.replayFixtureRefs ?? [],
    executorKind: "workflow_node_executor",
    executorRef: "crate::project::execute_workflow_harness_live_default_node",
    synchronous: true,
    drivesRuntimeDecision: dispatchAccepted,
    activationIdGateClickProofPresent,
    activationIdGateClickProofPassed,
    activationIdGateClickProofBlockers: activationIdGateProofBlockers,
    defaultDispatchActivationBlockers: activationBlockers,
    activationIdGate: {
      schemaVersion: "workflow.harness.default-runtime-dispatch.activation-id-gate.v1",
      gateId: "activation-id",
      proofPresent: activationIdGateClickProofPresent,
      proofPassed: activationIdGateClickProofPassed,
      proofBlockers: activationIdGateProofBlockers,
      workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      workerBindingActivationId: activationIdGateWorkerBindingActivationId,
      defaultDispatchActivationBlockers: activationBlockers,
    },
    cognitionExecutionMode: "workflow_synchronous_envelope",
    cognitionExecutionReady: true,
    promptAssemblyMode: "workflow_synchronous_envelope",
    promptAssemblyPromptHash,
    promptAssemblyPromptHashMatches: true,
    cognitionExecutionProof: {
      schemaVersion: "workflow.harness.cognition-execution-envelope.v1",
      mode: "workflow_synchronous_envelope",
      adapterMode: "workflow_component_adapter_live",
      adapterResultCount: cognitionExecutionAdapterResults.length,
      actionFrameIds: cognitionExecutionActionFrameIds,
      liveReadyComponentKinds: cognitionExecutionLiveReadyComponentKinds,
      promptAssemblyMode: "workflow_synchronous_envelope",
      promptHash: promptAssemblyPromptHash,
      promptHashMatches: true,
      ready: true,
      attemptIds: [
        "harness-default-dispatch:attempt-planner_envelope",
        "harness-default-dispatch:attempt-prompt_assembler_envelope",
        "harness-default-dispatch:attempt-task_state_envelope",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-planner_envelope",
        "harness-default-dispatch:receipt-prompt_assembler_envelope",
        "harness-default-dispatch:receipt-task_state_envelope",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-planner_envelope",
        "harness-default-dispatch:fixture-prompt_assembler_envelope",
        "harness-default-dispatch:fixture-task_state_envelope",
      ],
      policyDecision: "accept_workflow_prompt_assembly_hash_envelope",
    },
    modelExecutionMode: "workflow_synchronous_envelope",
    modelExecutionEnvelopeReady: true,
    modelExecutionBindingId,
    modelExecutionBindingReady: true,
    modelExecutionPromptHash,
    modelExecutionPromptHashMatches: true,
    modelExecutionOutputHash,
    modelExecutionOutputHashMatches: true,
    modelExecutionProviderInvocationMode: "workflow_provider_canary",
    modelExecutionLowLevelInvocationDeferred: false,
    modelExecutionFallbackSelector: "legacy_runtime_model_invocation",
    modelExecutionLatencyMs: 0,
    modelProviderCanaryMode: "workflow_provider_canary",
    modelProviderCanaryReady: true,
    modelProviderCanaryCandidateOutputHash: actualVisibleOutputHash,
    modelProviderCanaryLegacyOutputHash: actualVisibleOutputHash,
    modelProviderCanaryOutputHashMatches: true,
    modelProviderCanaryTranscriptMatches: true,
    modelProviderCanaryFallbackRetained: true,
    modelProviderCanaryRollbackAvailable: true,
    modelProviderGatedVisibleOutputMode: "workflow_provider_gated_visible_output",
    modelProviderGatedVisibleOutputEnabled: true,
    modelProviderGatedVisibleOutputReady: true,
    modelProviderGatedVisibleOutputSelected: true,
    modelProviderGatedVisibleOutputEligible: true,
    modelProviderGatedVisibleOutputScenario: "retained_no_tool_answer",
    modelProviderGatedVisibleOutputCohort: "retained_read_only_no_tool",
    modelProviderGatedVisibleOutputRetainedReadOnlyNoTool: true,
    modelProviderGatedVisibleOutputRequiredScenarioSet: [
      "retained_no_tool_answer",
      "retained_repo_grounded_answer",
      "retained_planning_without_mutation",
      "retained_mermaid_rendering",
      "retained_source_heavy_synthesis",
      "retained_probe_behavior",
      "retained_harness_dogfooding",
    ],
    modelProviderGatedVisibleOutputScenarioCoverageKey:
      "retained_no_tool_answer",
    modelProviderGatedVisibleOutputActivationFlag:
      "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT",
    modelProviderGatedVisibleOutputActivationId:
      DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    modelProviderGatedVisibleOutputAuthority: "workflow_model_provider_call",
    modelProviderGatedVisibleOutputRollbackTarget:
      "legacy_runtime_model_invocation",
    modelProviderGatedVisibleOutputRollbackAvailable: true,
    selectedVisibleOutputAuthority: "workflow_model_provider_call",
    selectedVisibleOutputHash: actualVisibleOutputHash,
    workflowProviderVisibleOutputHash: actualVisibleOutputHash,
    legacyVisibleOutputHash: actualVisibleOutputHash,
    legacyVisibleOutputComputed: true,
    legacyVisibleOutputHashMatchesSelected: true,
    selectedVisibleOutputAuthorityMatchesTranscript: true,
    visibleOutputDivergenceClass: null,
    modelProviderGatedVisibleOutputRollbackDrillEnabled: true,
    modelProviderGatedVisibleOutputRollbackDrillReady: true,
    modelProviderGatedVisibleOutputRollbackDrillFailureInjected: true,
    modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash:
      "sha256:provider-output-divergence",
    modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges: true,
    modelProviderGatedVisibleOutputRollbackDrillDivergenceClass:
      "provider_output_hash_divergence",
    modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority:
      "legacy_runtime_model_invocation",
    modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority:
      "legacy_runtime_model_invocation",
    modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged: true,
    modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted: true,
    modelProviderGatedVisibleOutputRollbackDrillActivationBlockers: [
      "model_provider_output_hash_divergence",
    ],
    readOnlyCapabilityRoutingMode: "workflow_read_only_capability_routing",
    readOnlyCapabilityRoutingReady: true,
    readOnlyCapabilityRoutingSelected: true,
    readOnlyCapabilityRoutingEligible: true,
    readOnlyCapabilityRoutingScenario: "retained_repo_grounded_answer",
    readOnlyCapabilityRoutingRequiredScenarioSet: [
      "retained_repo_grounded_answer",
      "retained_source_heavy_synthesis",
      "retained_probe_behavior",
    ],
    readOnlyCapabilityRoutingScenarioCoverageKey:
      "retained_repo_grounded_answer",
    readOnlyCapabilityRoutingSourceMaterialReady: true,
    readOnlyCapabilityRoutingNoMutationReady: true,
    readOnlyCapabilityRoutingWorkflowOwnedNodeKinds: [
      "memory_read",
      "capability_sequencer",
      "tool_router",
      "dry_run_simulator",
    ],
    modelProviderCanaryProof: {
      schemaVersion: "workflow.harness.model-provider-call-canary.v1",
      mode: "workflow_provider_canary",
      candidateOutputHash: actualVisibleOutputHash,
      legacyOutputHash: actualVisibleOutputHash,
      outputHashMatches: true,
      transcriptMatches: true,
      fallbackRetained: true,
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_call_canary",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_call_canary",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_call_canary",
      ],
      policyDecision: "accept_workflow_model_provider_call_canary_with_legacy_rollback",
    },
    modelProviderGatedVisibleOutputProof: {
      schemaVersion: "workflow.harness.model-provider-gated-visible-output.v1",
      mode: "workflow_provider_gated_visible_output",
      enabled: true,
      ready: true,
      selected: true,
      eligible: true,
      scope: "retained_no_tool_answer",
      cohort: "retained_read_only_no_tool",
      retainedReadOnlyNoTool: true,
      requiredScenarioSet: [
        "retained_no_tool_answer",
        "retained_repo_grounded_answer",
        "retained_planning_without_mutation",
        "retained_mermaid_rendering",
        "retained_source_heavy_synthesis",
        "retained_probe_behavior",
        "retained_harness_dogfooding",
      ],
      scenarioCoverageKey: "retained_no_tool_answer",
      activationFlag: "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT",
      activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      selectedVisibleOutputAuthority: "workflow_model_provider_call",
      selectedVisibleOutputHash: actualVisibleOutputHash,
      workflowProviderOutputHash: actualVisibleOutputHash,
      legacyVisibleOutputHash: actualVisibleOutputHash,
      legacyVisibleOutputComputed: true,
      legacyVisibleOutputHashMatchesSelected: true,
      selectedAuthorityMatchesTranscript: true,
      divergenceClass: null,
      rollbackTarget: "legacy_runtime_model_invocation",
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      ],
      policyDecision:
        "accept_workflow_provider_gated_visible_output_with_legacy_rollback",
    },
    modelProviderGatedVisibleOutputRollbackDrillProof: {
      schemaVersion:
        "workflow.harness.model-provider-gated-visible-output-rollback-drill.v1",
      drillId:
        "harness-provider-gated-visible-output-rollback-drill:default-agent-harness:turn-default",
      enabled: true,
      ready: true,
      failureInjected: true,
      workflowProviderOutputHash: actualVisibleOutputHash,
      injectedWorkflowProviderOutputHash: "sha256:provider-output-divergence",
      legacyVisibleOutputHash: actualVisibleOutputHash,
      actualVisibleOutputHash,
      outputHashDiverges: true,
      divergenceClass: "provider_output_hash_divergence",
      fallbackAuthority: "legacy_runtime_model_invocation",
      selectedAuthorityAfterRollback: "legacy_runtime_model_invocation",
      transcriptUnchanged: true,
      rollbackExecuted: true,
      rollbackTarget: "legacy_runtime_model_invocation",
      rollbackAvailable: true,
      activationBlockers: ["model_provider_output_hash_divergence"],
      attemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      policyDecision:
        "rollback_to_legacy_runtime_model_invocation_on_provider_output_hash_divergence",
    },
    readOnlyCapabilityRoutingProof: {
      schemaVersion: "workflow.harness.read-only-capability-routing.v1",
      mode: "workflow_read_only_capability_routing",
      ready: true,
      selected: true,
      eligible: true,
      scenario: "retained_repo_grounded_answer",
      requiredScenarioSet: [
        "retained_repo_grounded_answer",
        "retained_source_heavy_synthesis",
        "retained_probe_behavior",
      ],
      scenarioCoverageKey: "retained_repo_grounded_answer",
      sourceMaterialReady: true,
      workflowOwnedNodeKinds: [
        "memory_read",
        "capability_sequencer",
        "tool_router",
        "dry_run_simulator",
      ],
      toolUseMode: "read_only_or_dry_run",
      sideEffectsExecuted: false,
      mutationExecuted: false,
      noMutationReady: true,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      attemptIds: [
        "harness-default-dispatch:attempt-read_only_source_router",
        "harness-default-dispatch:attempt-read_only_capability_sequencer",
        "harness-default-dispatch:attempt-read_only_tool_router",
        "harness-default-dispatch:attempt-read_only_no_mutation_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-read_only_source_router",
        "harness-default-dispatch:receipt-read_only_capability_sequencer",
        "harness-default-dispatch:receipt-read_only_tool_router",
        "harness-default-dispatch:receipt-read_only_no_mutation_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-read_only_source_router",
        "harness-default-dispatch:fixture-read_only_capability_sequencer",
        "harness-default-dispatch:fixture-read_only_tool_router",
        "harness-default-dispatch:fixture-read_only_no_mutation_drill",
      ],
      policyDecision:
        "accept_workflow_read_only_capability_routing_without_side_effects",
    },
    modelExecutionProof: {
      schemaVersion: "workflow.harness.model-execution-envelope.v1",
      mode: "workflow_synchronous_envelope",
      bindingId: modelExecutionBindingId,
      bindingReady: true,
      promptHash: modelExecutionPromptHash,
      promptHashMatches: true,
      outputHash: modelExecutionOutputHash,
      outputHashMatches: true,
      providerInvocationMode: "workflow_provider_canary",
      lowLevelInvocationDeferred: false,
      fallbackSelector: "legacy_runtime_model_invocation",
      latencyMs: 0,
      providerCanaryReady: true,
      providerCanaryAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_call_canary",
      ],
      providerCanaryReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_call_canary",
      ],
      providerCanaryReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_call_canary",
      ],
      providerGatedVisibleOutputReady: true,
      providerGatedVisibleOutputSelected: true,
      providerGatedVisibleOutputAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
      ],
      providerGatedVisibleOutputRollbackDrillReady: true,
      providerGatedVisibleOutputRollbackDrillAttemptIds: [
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      providerGatedVisibleOutputRollbackDrillReceiptIds: [
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      providerGatedVisibleOutputRollbackDrillReplayFixtureRefs: [
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      selectedVisibleOutputAuthority: "workflow_model_provider_call",
      attemptIds: [
        "harness-default-dispatch:attempt-model_router_envelope",
        "harness-default-dispatch:attempt-model_call_envelope",
        "harness-default-dispatch:attempt-model_provider_call_canary",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output",
        "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill",
      ],
      receiptIds: [
        "harness-default-dispatch:receipt-model_router_envelope",
        "harness-default-dispatch:receipt-model_call_envelope",
        "harness-default-dispatch:receipt-model_provider_call_canary",
        "harness-default-dispatch:receipt-model_provider_gated_visible_output",
        "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill",
      ],
      replayFixtureRefs: [
        "harness-default-dispatch:fixture-model_router_envelope",
        "harness-default-dispatch:fixture-model_call_envelope",
        "harness-default-dispatch:fixture-model_provider_call_canary",
        "harness-default-dispatch:fixture-model_provider_gated_visible_output",
        "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill",
      ],
      policyDecision:
        "accept_workflow_model_provider_call_canary_with_legacy_rollback",
    },
    outputAuthority: "blessed_workflow_activation_default",
    outputWriterDeferred: false,
    outputWriterStatus: "visible_write_committed",
    outputWriterHandoffReady: true,
    outputWriterAuthorityTransferred: true,
    outputWriterMaterializationMode: "workflow_visible_transcript_write",
    outputWriterMaterializationCanaryReady: true,
    outputWriterMaterializationCommitted: true,
    outputWriterStagedWriteMode: "isolated_checkpoint_blob",
    outputWriterStagedWriteCanaryReady: true,
    outputWriterStagedWritePersisted: true,
    outputWriterStagedWriteCommitted: true,
    outputWriterStagedWriteVisible: false,
    outputWriterStagedWriteExcludedFromVisibleTranscript: true,
    outputWriterStagedWriteRollbackStatus: "deleted",
    outputWriterStagedWriteRollbackVerified: true,
    outputWriterVisibleWriteMode: "workflow_visible_transcript_write",
    outputWriterVisibleWriteReady: true,
    outputWriterVisibleWritePersisted: true,
    outputWriterVisibleWriteCommitted: true,
    outputWriterVisibleWriteVisible: true,
    outputWriterVisibleWriteIdentityCheckpointPersisted: true,
    outputWriterVisibleWriteLegacyDuplicateSuppressed: true,
    authorityToolingMode: "workflow_live_dry_run",
    authorityToolingReady: true,
    authorityToolingPolicyGateReady: true,
    authorityToolingToolRouterReady: true,
    authorityToolingDryRunSimulatorReady: true,
    authorityToolingApprovalGateReady: true,
    authorityToolingGateLiveReady: true,
    authorityToolingPolicyGateLiveReady: true,
    authorityToolingDestructiveDenialLiveReady: true,
    authorityToolingApprovalGateLiveReady: true,
    authorityToolingReadOnlyAuthorityCanaryReady: true,
    authorityToolingProviderCatalogLiveReady: true,
    authorityToolingProviderCatalogLiveComponentKind: "mcp_provider",
    authorityToolingMcpToolCatalogLiveReady: true,
    authorityToolingMcpToolCatalogLiveComponentKind: "mcp_tool_call",
    authorityToolingNativeToolCatalogLiveReady: true,
    authorityToolingNativeToolCatalogLiveComponentKind: "tool_call",
    authorityToolingConnectorCatalogLiveReady: true,
    authorityToolingConnectorCatalogLiveComponentKind: "connector_call",
    authorityToolingWalletCapabilityLiveDryRunReady: true,
    authorityToolingWalletCapabilityLiveDryRunComponentKind: "wallet_capability",
    authorityToolingReadOnlyRouteAccepted: true,
    authorityToolingDestructiveRouteDenied: true,
    authorityToolingMutatingToolCallsBlocked: true,
    authorityToolingSideEffectsExecuted: false,
    authorityToolingRollbackAvailable: true,
    authorityToolingProof: {
      schemaVersion: "workflow.harness.authority-tooling-live-dry-run.v1",
      mode: "workflow_live_dry_run",
      readOnlyRouteAccepted: true,
      destructiveRouteDenied: true,
      mutatingToolCallsBlocked: true,
      sideEffectsExecuted: false,
      policyGateReady: true,
      toolRouterReady: true,
      dryRunSimulatorReady: true,
      approvalGateReady: true,
      rollbackAvailable: true,
      gateLiveReady: true,
      gateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_policy_gate",
        "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
        "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      ],
      gateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_policy_gate",
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
        "harness-default-dispatch:receipt-authority_tooling_approval_gate",
      ],
      gateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_policy_gate",
        "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
        "harness-default-dispatch:fixture-authority_tooling_approval_gate",
      ],
      policyGateLiveReady: true,
      policyGateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_policy_gate",
      ],
      policyGateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_policy_gate",
      ],
      policyGateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_policy_gate",
      ],
      destructiveDenialLiveReady: true,
      destructiveDenialLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_destructive_denial",
      ],
      destructiveDenialLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      ],
      destructiveDenialLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_destructive_denial",
      ],
      approvalGateLiveReady: true,
      approvalGateLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_approval_gate",
      ],
      approvalGateLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_approval_gate",
      ],
      approvalGateLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_approval_gate",
      ],
      readOnlyAuthorityCanaryReady: true,
      providerCatalogLiveReady: true,
      providerCatalogLiveComponentKind: "mcp_provider",
      providerCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
      ],
      providerCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
      ],
      providerCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
      ],
      mcpToolCatalogLiveReady: true,
      mcpToolCatalogLiveComponentKind: "mcp_tool_call",
      mcpToolCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
      ],
      mcpToolCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
      ],
      mcpToolCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
      ],
      nativeToolCatalogLiveReady: true,
      nativeToolCatalogLiveComponentKind: "tool_call",
      nativeToolCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
      ],
      nativeToolCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
      ],
      nativeToolCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
      ],
      connectorCatalogLiveReady: true,
      connectorCatalogLiveComponentKind: "connector_call",
      connectorCatalogLiveAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
      ],
      connectorCatalogLiveReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
      ],
      connectorCatalogLiveReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
      ],
      walletCapabilityLiveDryRunReady: true,
      walletCapabilityLiveDryRunComponentKind: "wallet_capability",
      walletCapabilityLiveDryRunAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ],
      walletCapabilityLiveDryRunReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
      ],
      walletCapabilityLiveDryRunReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyComponentKinds: authorityToolingReadOnlyComponentKinds,
      readOnlyAttemptIds: [
        "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only",
      ],
      readOnlyReplayFixtureRefs: [
        "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only",
        "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only",
        "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only",
      ],
      denialReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      ],
      deferredMutationComponentKinds: authorityToolingMutationDeferredComponentKinds,
      mutationDeferredComponentKinds: authorityToolingMutationDeferredComponentKinds,
      policyDecision:
        "allow_read_only_route_and_deny_destructive_tooling_without_side_effect",
    },
    legacyTranscriptAuthorityRetained: false,
    legacyTranscriptFallbackAvailable: true,
    proposedVisibleOutputHash,
    actualVisibleOutputHash,
    outputHashAlgorithm: "runtime_prompt_hash:v1",
    outputHashMatches: proposedVisibleOutputHash === actualVisibleOutputHash,
    outputHashDivergence: false,
    outputHashDivergenceCount: 0,
    workflowTranscriptWriteCandidate,
    workflowTranscriptWriteRecord,
    visibleTranscriptWriteProof,
    legacyTranscriptFallbackProof,
    legacyTranscriptWriteRecord,
    stagedTranscriptWriteRecord,
    stagedTranscriptWriteProof,
    transcriptMaterializationContentHashMatches: true,
    transcriptMaterializationOrderMatches: true,
    transcriptMaterializationReceiptBindingMatches: true,
    transcriptMaterializationTargetMatches: true,
    transcriptMaterializationMatches: true,
    transcriptMaterializationDivergenceCount: 0,
    stagedTranscriptWriteContentHashMatches: true,
    stagedTranscriptWriteOrderMatches: true,
    stagedTranscriptWriteReceiptBindingMatches: true,
    stagedTranscriptWriteTargetMatches: true,
    stagedTranscriptWriteMatches: true,
    stagedTranscriptWriteDivergenceCount: 0,
    visibleTranscriptWriteContentHashMatches: true,
    visibleTranscriptWriteOrderMatches: true,
    visibleTranscriptWriteReceiptBindingMatches: true,
    visibleTranscriptWriteTargetMatches: true,
    visibleTranscriptWriteMatches: true,
    visibleTranscriptWriteDivergenceCount: 0,
    stagedTranscriptWriteComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      stagedWritePersisted: true,
      stagedWriteCommitted: true,
      stagedWriteVisible: false,
      excludedFromVisibleTranscript: true,
      rollbackStatus: "deleted",
      rollbackVerified: true,
      matches: true,
      divergenceClass: null,
    },
    transcriptMaterializationComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      candidateCommitted: false,
      legacyCommitted: false,
      legacyDuplicateSuppressed: true,
      matches: true,
      divergenceClass: null,
    },
    visibleTranscriptWriteComparison: {
      contentHashMatches: true,
      orderMatches: true,
      receiptBindingMatches: true,
      targetMatches: true,
      workflowWritePersisted: true,
      workflowWriteCommitted: true,
      workflowWriteVisible: true,
      identityCheckpointPersisted: true,
      legacyDuplicateSuppressed: true,
      matches: true,
      divergenceClass: null,
    },
    outputHashComparison: {
      proposedVisibleOutputHash,
      actualVisibleOutputHash,
      hashAlgorithm: "runtime_prompt_hash:v1",
      matches: proposedVisibleOutputHash === actualVisibleOutputHash,
      divergenceClass: null,
    },
    legacyOutputAuthorityRetained: false,
    legacyOutputFallbackAvailable: true,
    mutatingTurnsBlocked: true,
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    activationBlockers,
    policyDecision:
      dispatchAccepted
        ? "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write"
        : "retain_legacy_runtime_default",
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

export function makeHarnessCanaryExecutionBoundary(options: {
  boundaryId?: string;
  clusterId?: WorkflowHarnessPromotionClusterId;
  selectorDecisionId?: string;
  status?: WorkflowHarnessCanaryExecutionBoundary["status"];
  executionMode?: WorkflowHarnessExecutionMode;
  runtimeAuthority?: WorkflowHarnessCanaryExecutionBoundary["runtimeAuthority"];
  activationBlockers?: string[];
  rollbackDrillStatus?: WorkflowHarnessCanaryExecutionBoundary["rollbackDrill"]["drillStatus"];
} = {}): WorkflowHarnessCanaryExecutionBoundary {
  const clusterId = options.clusterId ?? "verification_output";
  const componentKinds: WorkflowHarnessCanaryExecutionBoundary["componentKinds"] =
    HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId];
  const failedNodeKind =
    clusterId === "cognition"
      ? "task_state"
      : clusterId === "routing_model"
        ? "model_router"
        : clusterId === "authority_tooling"
          ? "policy_gate"
          : "verifier";
  const passed = options.status !== "blocked" && options.status !== "rolled_back";
  return {
    schemaVersion: "workflow.harness.canary-execution-boundary.v1",
    boundaryId:
      options.boundaryId ?? `harness-canary-boundary:default-agent-harness:${clusterId}`,
    clusterId,
    clusterLabel: HARNESS_PROMOTION_CLUSTER_LABELS[clusterId],
    selectorDecisionId:
      options.selectorDecisionId ?? "harness-selector:default-agent-harness:canary",
    selectedSelector: passed ? "blessed_workflow_live_canary" : "legacy_runtime",
    productionDefaultSelector: "legacy_runtime",
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: options.executionMode ?? (passed ? "live" : "gated"),
    runtimeAuthority:
      options.runtimeAuthority ??
      (passed ? "blessed_workflow_activation_canary" : "existing_runtime_service"),
    executorKind: "workflow_node_executor",
    executorRef: "crate::project::execute_workflow_harness_canary_node",
    synchronous: true,
    enforcedBeforeVisibleOutput: true,
    canaryEligible: passed,
    status: options.status ?? "passed",
    componentKinds,
    executedComponentKinds: passed ? componentKinds : [],
    workflowNodeIds: componentKinds.map((kind) => `harness.${kind}`),
    nodeAttemptIds: componentKinds.map(
      (kind, index) => `harness-canary:default:turn-1:${kind}:attempt-${index + 1}`,
    ),
    receiptIds: componentKinds.map((kind) => `default:harness.${kind}:workflow-node-execution`),
    replayFixtureRefs: componentKinds.map((kind) => `runtime-evidence:default:canary-fixture:${kind}`),
    activationBlockers: options.activationBlockers ?? [],
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    rollbackDrill: {
      schemaVersion: "workflow.harness.canary-rollback-drill.v1",
      drillId: "harness-canary-rollback-drill:default",
      selectorDecisionId:
        options.selectorDecisionId ?? "harness-selector:default-agent-harness:canary",
      failureInjected: passed,
      failedNodeId: `harness.${failedNodeKind}.rollback_drill`,
      clusterId,
      failureClass: "deterministic_executor_failure",
      observedFailure: passed,
      rollbackExecuted: passed,
      rollbackSelector: "legacy_runtime",
      fallbackAuthority: "existing_runtime_service",
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      rollbackAvailable: true,
      drillStatus: options.rollbackDrillStatus ?? (passed ? "passed" : "not_run"),
      policyDecision: passed
        ? "rollback_to_legacy_runtime_on_workflow_executor_failure"
        : "retain_legacy_runtime_default",
      evidenceRefs: ["runtime-evidence:default"],
    },
    policyDecision: passed
      ? "allow_synchronous_workflow_node_canary_boundary"
      : "retain_legacy_runtime_default",
    evidenceRefs: [`runtime-evidence:canary-boundary:${clusterId}`],
  };
}

export function makeHarnessCanaryExecutionBoundaries(): WorkflowHarnessCanaryExecutionBoundary[] {
  return [
    makeHarnessCanaryExecutionBoundary({ clusterId: "cognition" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "routing_model" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "verification_output" }),
    makeHarnessCanaryExecutionBoundary({ clusterId: "authority_tooling" }),
  ];
}

const DEFAULT_HARNESS_EXECUTION_MODE: WorkflowHarnessExecutionMode = "projection";
const DEFAULT_HARNESS_COMPONENT_READINESS: WorkflowHarnessComponentReadiness = "projection_only";
const LIVE_READY_HARNESS_COMPONENTS = new Set<WorkflowHarnessComponentKind>([
  "planner",
  "prompt_assembler",
  "task_state",
]);
const SHADOW_READY_HARNESS_COMPONENTS = new Set<WorkflowHarnessComponentKind>([
  "uncertainty_gate",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "policy_gate",
  "approval_gate",
  "postcondition_synthesizer",
  "verifier",
  "completion_gate",
  "receipt_writer",
  "quality_ledger",
  "output_writer",
]);

const HARNESS_PROMOTION_CLUSTER_COMPONENTS: Record<
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessComponentKind[]
> = {
  cognition: [
    "planner",
    "prompt_assembler",
    "task_state",
    "uncertainty_gate",
    "budget_gate",
    "capability_sequencer",
  ],
  routing_model: ["model_router", "model_call", "tool_router"],
  verification_output: [
    "postcondition_synthesizer",
    "verifier",
    "completion_gate",
    "receipt_writer",
    "quality_ledger",
    "output_writer",
  ],
  authority_tooling: [
    "policy_gate",
    "approval_gate",
    "dry_run_simulator",
    "mcp_provider",
    "mcp_tool_call",
    "tool_call",
    "connector_call",
    "wallet_capability",
  ],
};

const HARNESS_PROMOTION_CLUSTER_LABELS: Record<WorkflowHarnessPromotionClusterId, string> = {
  cognition: "Cognition",
  routing_model: "Routing and model",
  verification_output: "Verification and output",
  authority_tooling: "Authority and tooling",
};

type ComponentSeed = {
  kind: WorkflowHarnessComponentKind;
  label: string;
  description: string;
  kernelRef: string;
  readiness?: WorkflowHarnessComponentReadiness;
  capabilityScope: string[];
  approvalMode?: WorkflowHarnessComponentSpec["approval"]["mode"];
  approvalRequired?: boolean;
  eventKinds: string[];
  evidence: string[];
  group: string;
  icon: string;
  timeoutMs?: number;
  maxAttempts?: number;
};

function componentId(kind: WorkflowHarnessComponentKind): string {
  return `ioi.agent-harness.${kind}.v1`;
}

function defaultReadinessForKind(kind: WorkflowHarnessComponentKind): WorkflowHarnessComponentReadiness {
  if (LIVE_READY_HARNESS_COMPONENTS.has(kind)) {
    return "live_ready";
  }
  return SHADOW_READY_HARNESS_COMPONENTS.has(kind)
    ? "shadow_ready"
    : DEFAULT_HARNESS_COMPONENT_READINESS;
}

function makeComponent(seed: ComponentSeed): WorkflowHarnessComponentSpec {
  const approvalRequired = seed.approvalRequired ?? false;
  return {
    componentId: componentId(seed.kind),
    version: "1.0.0",
    kind: seed.kind,
    readiness: seed.readiness ?? defaultReadinessForKind(seed.kind),
    label: seed.label,
    description: seed.description,
    kernelRef: seed.kernelRef,
    inputSchema: HARNESS_INPUT_SCHEMA,
    outputSchema: HARNESS_OUTPUT_SCHEMA,
    errorSchema: HARNESS_ERROR_SCHEMA,
    timeout: {
      timeoutMs: seed.timeoutMs ?? 30000,
      cancellation: "cooperative",
    },
    retry: {
      maxAttempts: seed.maxAttempts ?? 1,
      backoffMs: seed.maxAttempts && seed.maxAttempts > 1 ? 250 : 0,
      retryableErrors: ["timeout", "rate_limit", "transient_provider_error"],
    },
    requiredCapabilityScope: seed.capabilityScope,
    approval: {
      required: approvalRequired,
      mode: seed.approvalMode ?? (approvalRequired ? "policy_gate" : "none"),
      reason: approvalRequired
        ? "Component may cross a privileged runtime boundary."
        : "Component is governed by workflow and node policy.",
    },
    emittedEvents: seed.eventKinds,
    evidence: seed.evidence,
    ui: {
      icon: seed.icon,
      group: seed.group,
      summary: seed.description,
    },
  };
}

export const DEFAULT_AGENT_HARNESS_COMPONENTS: WorkflowHarnessComponentSpec[] = [
  makeComponent({
    kind: "planner",
    label: "Planner",
    description: "Produces the next plan step from session state, user input, and available capabilities.",
    kernelRef: "crates/services/src/agentic/runtime/service/planning/planner",
    capabilityScope: ["reasoning.read", "session.state.read"],
    eventKinds: ["PlanReceipt", "KernelEvent::PlanReceipt"],
    evidence: ["plan_id", "planner_policy_hash", "chosen_step_reason"],
    group: "Planning",
    icon: "list-checks",
  }),
  makeComponent({
    kind: "prompt_assembler",
    label: "Prompt assembler",
    description: "Builds the runtime prompt envelope from session state, policy, tools, evidence, and truncation diagnostics.",
    kernelRef: "crates/types/src/app/runtime_contracts.rs::PromptAssemblyContract",
    capabilityScope: ["prompt.assemble", "session.state.read", "evidence.read"],
    eventKinds: ["PromptAssemblyContract", "AgentRuntimeEvent"],
    evidence: ["sections", "final_prompt_hash", "conflict_resolutions", "truncation_diagnostics"],
    group: "Planning",
    icon: "panel-top",
  }),
  makeComponent({
    kind: "task_state",
    label: "Task state",
    description: "Projects the current objective, known facts, uncertainty, blockers, stale facts, and evidence references.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["session.state.read", "evidence.read"],
    eventKinds: ["AgentRuntimeEvent", "TaskStateModel"],
    evidence: ["task_state_id", "evidence_refs", "stale_fact_refs"],
    group: "Cognition",
    icon: "map",
  }),
  makeComponent({
    kind: "uncertainty_gate",
    label: "Uncertainty gate",
    description: "Chooses whether to ask, retrieve, probe, dry-run, execute, verify, escalate, or stop.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["reasoning.route", "session.state.read"],
    eventKinds: ["UncertaintyAssessment", "RuntimeStrategyDecision"],
    evidence: ["ambiguity_level", "value_of_information", "selected_action"],
    group: "Cognition",
    icon: "circle-help",
  }),
  makeComponent({
    kind: "probe_runner",
    label: "Probe runner",
    description: "Runs the cheapest bounded validation action for a stated hypothesis.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/probe.rs",
    capabilityScope: ["probe.run", "verification.read"],
    eventKinds: ["ProbeStarted", "ProbeCompleted"],
    evidence: ["hypothesis", "expected_observation", "probe_result"],
    group: "Cognition",
    icon: "radar",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "budget_gate",
    label: "Cognitive budget",
    description: "Bounds reasoning tokens, tool calls, retries, verification spend, and wall time.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["budget.evaluate", "session.state.read"],
    eventKinds: ["CognitiveBudget", "RuntimeStrategyDecision"],
    evidence: ["remaining_tokens", "remaining_tool_calls", "stop_threshold"],
    group: "Cognition",
    icon: "gauge",
  }),
  makeComponent({
    kind: "capability_sequencer",
    label: "Capability sequencer",
    description: "Separates capability discovery, selection, sequencing, and retirement decisions.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["capability.read", "tool.route"],
    eventKinds: ["CapabilitySequence", "RoutingReceipt"],
    evidence: ["discovered_capabilities", "selected_sequence", "retired_capabilities"],
    group: "Routing",
    icon: "waypoints",
  }),
  makeComponent({
    kind: "model_router",
    label: "Model router",
    description: "Selects a model binding under workflow-level model policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/model_router",
    capabilityScope: ["model.route"],
    eventKinds: ["RoutingReceipt", "KernelEvent::RoutingReceipt"],
    evidence: ["model_policy_slot", "candidate_models", "routing_reason"],
    group: "Routing",
    icon: "brain",
  }),
  makeComponent({
    kind: "model_call",
    label: "Model call",
    description: "Invokes the selected model with deterministic request and response capture.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/model_call",
    capabilityScope: ["model.invoke"],
    eventKinds: ["ModelInvocationStarted", "ModelInvocationCompleted"],
    evidence: ["request_hash", "response_hash", "model_binding"],
    group: "Execution",
    icon: "message-square",
    timeoutMs: 120000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "tool_router",
    label: "Tool router",
    description: "Chooses native, workflow, MCP, or connector tools under grant policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/action_execution.rs",
    capabilityScope: ["tool.route", "capability.read"],
    eventKinds: ["RoutingReceipt", "ActionDispatchPrepared"],
    evidence: ["tool_grant_slot", "candidate_tools", "routing_reason"],
    group: "Routing",
    icon: "route",
  }),
  makeComponent({
    kind: "tool_call",
    label: "Tool call",
    description: "Executes a native or workflow tool through the action execution envelope.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution",
    capabilityScope: ["tool.invoke"],
    approvalRequired: true,
    eventKinds: ["AgentActionResult", "WorkloadReceipt"],
    evidence: ["action_request_id", "tool_ref", "result_hash"],
    group: "Execution",
    icon: "wrench",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "dry_run_simulator",
    label: "Dry-run simulator",
    description: "Previews side effects and policy outcomes before file, shell, connector, or commerce actions execute.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["dry_run.preview", "policy.evaluate"],
    eventKinds: ["DryRunPreview", "PolicyPreview"],
    evidence: ["side_effect_preview", "policy_preview", "preview_artifact"],
    group: "Governance",
    icon: "scan-search",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "mcp_provider",
    label: "MCP provider",
    description: "Represents an MCP server as a capability provider with reviewed grants.",
    kernelRef: "crates/services/src/mcp",
    capabilityScope: ["mcp.provider.read", "mcp.catalog.read"],
    eventKinds: ["McpServerCatalogued", "CapabilityLease"],
    evidence: ["server_id", "catalog_hash", "grant_scope"],
    group: "MCP",
    icon: "server",
  }),
  makeComponent({
    kind: "mcp_tool_call",
    label: "MCP tool invocation",
    description: "Invokes an MCP tool as a componentized callable unit with receipts.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/dynamic_native_tool.rs",
    capabilityScope: ["mcp.tool.invoke"],
    approvalRequired: true,
    eventKinds: ["AgentActionResult", "ExecutionContractReceipt"],
    evidence: ["server_id", "tool_name", "argument_hash", "result_hash"],
    group: "MCP",
    icon: "plug",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "connector_call",
    label: "Connector call",
    description: "Calls a connector operation through policy and capability grants.",
    kernelRef: "crates/services/src/connectors",
    capabilityScope: ["connector.invoke"],
    approvalRequired: true,
    eventKinds: ["ConnectorInvocation", "WorkloadReceipt"],
    evidence: ["connector_id", "operation", "request_hash", "result_hash"],
    group: "Connectors",
    icon: "cable",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "policy_gate",
    label: "Policy and firewall gate",
    description: "Evaluates firewall policy, deterministic commitments, and capability leases.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
    capabilityScope: ["policy.evaluate", "capability.lease"],
    eventKinds: ["FirewallDecisionReceipt", "DeterminismCommit"],
    evidence: ["policy_hash", "decision", "lease_id", "determinism_commit"],
    group: "Governance",
    icon: "shield",
  }),
  makeComponent({
    kind: "approval_gate",
    label: "Approval gate",
    description: "Pauses privileged actions until approval semantics are satisfied.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/approval",
    capabilityScope: ["approval.request"],
    approvalRequired: true,
    approvalMode: "human_gate",
    eventKinds: ["ApprovalRequested", "ApprovalSatisfied"],
    evidence: ["approval_id", "approval_scope", "approver"],
    group: "Governance",
    icon: "badge-check",
  }),
  makeComponent({
    kind: "wallet_capability",
    label: "Wallet capability request",
    description: "Requests runtime capability scope before spend, connector write, or external effect.",
    kernelRef: "crates/services/src/capabilities/wallet",
    capabilityScope: ["wallet.request", "capability.grant"],
    approvalRequired: true,
    approvalMode: "wallet_capability",
    eventKinds: ["CapabilityLease", "WalletRequestReceipt"],
    evidence: ["capability_scope", "lease_id", "budget"],
    group: "Governance",
    icon: "wallet",
  }),
  makeComponent({
    kind: "memory_read",
    label: "Memory read",
    description: "Reads session or worker memory through scoped state access.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/memory",
    capabilityScope: ["memory.read"],
    eventKinds: ["MemoryRead"],
    evidence: ["memory_key", "state_hash"],
    group: "State",
    icon: "database",
  }),
  makeComponent({
    kind: "memory_write",
    label: "Memory write",
    description: "Writes memory through state reducers and receipt-backed updates.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/memory",
    capabilityScope: ["memory.write"],
    approvalRequired: true,
    eventKinds: ["MemoryWrite", "StateUpdate"],
    evidence: ["memory_key", "previous_hash", "next_hash"],
    group: "State",
    icon: "database",
  }),
  makeComponent({
    kind: "verifier",
    label: "Verifier",
    description: "Checks component outputs, schemas, contract receipts, and completion claims.",
    kernelRef: "crates/services/src/agentic/runtime/service/verifier",
    capabilityScope: ["verification.run"],
    eventKinds: ["ExecutionContractReceipt", "VerificationReceipt"],
    evidence: ["schema_hash", "contract_key", "verification_result"],
    group: "Verification",
    icon: "check-circle",
  }),
  makeComponent({
    kind: "semantic_impact_analyzer",
    label: "Semantic impact",
    description: "Classifies changed symbols, APIs, schemas, policies, call sites, tests, docs, and migration implications.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["impact.analyze", "evidence.read"],
    eventKinds: ["SemanticImpactAnalysis"],
    evidence: ["changed_symbols", "affected_tests", "risk_class"],
    group: "Verification",
    icon: "git-branch-plus",
  }),
  makeComponent({
    kind: "postcondition_synthesizer",
    label: "Postcondition synthesizer",
    description: "Derives success criteria, required receipts, and minimum verification evidence from the objective.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["verification.plan", "evidence.read"],
    eventKinds: ["PostconditionSynthesis"],
    evidence: ["postcondition_checks", "minimum_evidence", "unknowns"],
    group: "Verification",
    icon: "list-checks",
  }),
  makeComponent({
    kind: "drift_detector",
    label: "Drift detector",
    description: "Detects plan, file, branch, connector, requirement, policy, model, and projection drift.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["drift.detect", "session.state.read"],
    eventKinds: ["DriftSignal"],
    evidence: ["drift_flags", "drift_evidence_refs"],
    group: "Verification",
    icon: "activity",
  }),
  makeComponent({
    kind: "quality_ledger",
    label: "Quality ledger",
    description: "Records strategy, tool sequence, costs, failures, stop reason, scorecards, and promotion decisions.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["quality.write", "scorecard.read"],
    eventKinds: ["AgentQualityLedger", "BenchmarkScorecard"],
    evidence: ["quality_ledger_id", "scorecard_metrics", "stop_condition"],
    group: "Verification",
    icon: "badge-check",
  }),
  makeComponent({
    kind: "handoff_bridge",
    label: "Handoff bridge",
    description: "Preserves objective, current state, blockers, evidence refs, and receiving-agent outcome across delegation.",
    kernelRef: "crates/services/src/agentic/runtime/service/lifecycle/worker_results",
    capabilityScope: ["handoff.write", "delegation.merge"],
    eventKinds: ["HandoffQuality", "WorkerResultMerged"],
    evidence: ["objective_preserved", "blockers_included", "receiver_succeeded"],
    group: "Delegation",
    icon: "split",
  }),
  makeComponent({
    kind: "gui_harness_validator",
    label: "GUI harness validator",
    description: "Validates retained Autopilot chat queries, screenshots, transcripts, traces, receipts, source chips, scorecards, and clean chat UX.",
    kernelRef: "scripts/run-autopilot-gui-harness-validation.mjs",
    capabilityScope: ["gui.validate", "harness.validate"],
    eventKinds: ["AutopilotGuiHarnessValidation", "CleanChatUxValidation"],
    evidence: ["screenshots", "transcripts", "trace_refs", "quality_ledger"],
    group: "Validation",
    icon: "monitor-check",
    timeoutMs: 600000,
  }),
  makeComponent({
    kind: "output_writer",
    label: "Output writer",
    description: "Materializes final user-visible output under output policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/output",
    capabilityScope: ["output.write"],
    approvalRequired: true,
    eventKinds: ["OutputWritten", "AgentActionResult"],
    evidence: ["output_hash", "delivery_target", "output_policy_slot"],
    group: "Output",
    icon: "file-output",
  }),
  makeComponent({
    kind: "receipt_writer",
    label: "Receipt writer",
    description: "Emits durable receipts that link runtime events to workflow node ids.",
    kernelRef: "crates/services/src/agentic/runtime/service/receipts",
    capabilityScope: ["receipt.write"],
    eventKinds: ["ExecutionContractReceipt", "PlanReceipt", "WorkloadReceipt"],
    evidence: ["receipt_id", "node_id", "evidence_commit_hash"],
    group: "Receipts",
    icon: "receipt",
  }),
  makeComponent({
    kind: "retry_policy",
    label: "Retry policy",
    description: "Classifies retryable failures and chooses bounded retry behavior.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/processing/retry",
    capabilityScope: ["retry.evaluate"],
    eventKinds: ["RetryScheduled", "RetryExhausted"],
    evidence: ["attempt", "max_attempts", "retry_reason"],
    group: "Recovery",
    icon: "rotate-ccw",
    maxAttempts: 3,
  }),
  makeComponent({
    kind: "repair_loop",
    label: "Repair loop",
    description: "Creates bounded repair attempts after verifier or tool failures.",
    kernelRef: "crates/services/src/agentic/runtime/service/repair",
    capabilityScope: ["repair.propose"],
    eventKinds: ["RepairAttemptStarted", "RepairAttemptCompleted"],
    evidence: ["failure_ref", "repair_strategy", "bounded_targets"],
    group: "Recovery",
    icon: "git-pull-request",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "merge_judge",
    label: "Merge and judge",
    description: "Merges branch outputs and judges competing repair or tool results.",
    kernelRef: "crates/services/src/agentic/runtime/service/judge",
    capabilityScope: ["judgement.run"],
    eventKinds: ["MergeReceipt", "JudgementReceipt"],
    evidence: ["candidate_hashes", "winner_reason", "judge_policy_hash"],
    group: "Verification",
    icon: "git-compare",
  }),
  makeComponent({
    kind: "completion_gate",
    label: "Completion gate",
    description: "Determines whether the turn is complete and safe to finalize.",
    kernelRef: "crates/services/src/agentic/runtime/service/decision_loop/completion",
    capabilityScope: ["completion.evaluate"],
    eventKinds: ["CompletionGateReceipt", "PlanReceipt"],
    evidence: ["completion_contract", "pending_actions", "final_decision"],
    group: "Completion",
    icon: "flag",
  }),
];

const REQUIRED_HARNESS_SLOTS: WorkflowHarnessSlotSpec[] = [
  {
    slotId: "slot.model-policy",
    kind: "model_policy",
    label: "Model policy",
    description: "Workflow-level model selection, budget, and fallback policy.",
    required: true,
    allowedComponentKinds: ["model_router", "model_call"],
    defaultComponentId: componentId("model_router"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must bind model routing to an explicit policy slot.",
    },
  },
  {
    slotId: "slot.tool-grants",
    kind: "tool_grant_policy",
    label: "Tool grant policy",
    description: "Workflow-level grants for native, workflow, connector, and MCP tools.",
    required: true,
    allowedComponentKinds: ["tool_router", "tool_call", "mcp_provider", "mcp_tool_call", "connector_call"],
    defaultComponentId: componentId("tool_router"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must make tool grants inspectable.",
    },
  },
  {
    slotId: "slot.state-policy",
    kind: "state_policy",
    label: "State policy",
    description: "Task state, drift, memory, and projection-state access rules.",
    required: true,
    allowedComponentKinds: ["task_state", "drift_detector", "memory_read", "memory_write"],
    defaultComponentId: componentId("task_state"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must project task/world state through the shared substrate.",
    },
  },
  {
    slotId: "slot.budget-policy",
    kind: "budget_policy",
    label: "Budget policy",
    description: "Cognitive budget, escalation threshold, stop threshold, and retry bounds.",
    required: true,
    allowedComponentKinds: ["budget_gate", "model_router", "retry_policy"],
    defaultComponentId: componentId("budget_gate"),
    validation: {
      blocksActivation: true,
      reason: "Autonomous harnesses must expose their cognitive budget before activation.",
    },
  },
  {
    slotId: "slot.dry-run-policy",
    kind: "dry_run_policy",
    label: "Dry-run policy",
    description: "Preview rules for file, shell, connector, commerce, and policy side effects.",
    required: true,
    allowedComponentKinds: ["dry_run_simulator", "policy_gate", "tool_call", "connector_call"],
    defaultComponentId: componentId("dry_run_simulator"),
    validation: {
      blocksActivation: true,
      reason: "Effectful harness paths need a dry-run or preview policy.",
    },
  },
  {
    slotId: "slot.verifier",
    kind: "verifier_policy",
    label: "Verifier policy",
    description: "Schema, receipt, and completion verification policy.",
    required: true,
    allowedComponentKinds: [
      "verifier",
      "semantic_impact_analyzer",
      "postcondition_synthesizer",
      "merge_judge",
      "completion_gate",
      "gui_harness_validator",
    ],
    defaultComponentId: componentId("verifier"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses require a verifier policy slot.",
    },
  },
  {
    slotId: "slot.approval",
    kind: "approval_policy",
    label: "Approval policy",
    description: "Approval gate and wallet capability semantics for privileged work.",
    required: true,
    allowedComponentKinds: ["approval_gate", "policy_gate", "wallet_capability"],
    defaultComponentId: componentId("approval_gate"),
    validation: {
      blocksActivation: true,
      reason: "Privileged harness forks require explicit approval semantics.",
    },
  },
  {
    slotId: "slot.output-policy",
    kind: "output_policy",
    label: "Output policy",
    description: "Rules for output writing, materialization, and receipt emission.",
    required: true,
    allowedComponentKinds: ["output_writer", "receipt_writer"],
    defaultComponentId: componentId("output_writer"),
    validation: {
      blocksActivation: true,
      reason: "Outputs must be governed before a harness fork can activate.",
    },
  },
  {
    slotId: "slot.memory-policy",
    kind: "memory_policy",
    label: "Memory policy",
    description: "Memory read/write scope and reducer behavior.",
    required: true,
    allowedComponentKinds: ["memory_read", "memory_write"],
    defaultComponentId: componentId("memory_read"),
    validation: {
      blocksActivation: true,
      reason: "Memory access must declare scope before activation.",
    },
  },
  {
    slotId: "slot.quality-ledger",
    kind: "quality_ledger_policy",
    label: "Quality ledger policy",
    description: "Scorecard, ledger writeback, stop reason, and bounded self-improvement evidence.",
    required: true,
    allowedComponentKinds: ["quality_ledger", "verifier", "completion_gate"],
    defaultComponentId: componentId("quality_ledger"),
    validation: {
      blocksActivation: true,
      reason: "Harness runs must emit quality ledger evidence before activation.",
    },
  },
  {
    slotId: "slot.handoff-policy",
    kind: "handoff_policy",
    label: "Handoff policy",
    description: "Delegation handoff, worker merge, blocker preservation, and receiver outcome quality.",
    required: true,
    allowedComponentKinds: ["handoff_bridge", "merge_judge", "receipt_writer"],
    defaultComponentId: componentId("handoff_bridge"),
    validation: {
      blocksActivation: true,
      reason: "Delegation-capable harnesses must preserve handoff quality evidence.",
    },
  },
  {
    slotId: "slot.retry-repair",
    kind: "retry_repair_policy",
    label: "Retry and repair policy",
    description: "Retry bounds, repair loops, and merge/judge behavior.",
    required: true,
    allowedComponentKinds: ["retry_policy", "repair_loop", "merge_judge"],
    defaultComponentId: componentId("retry_policy"),
    validation: {
      blocksActivation: true,
      reason: "Recovery behavior must be bounded before activation.",
    },
  },
];

export const DEFAULT_AGENT_HARNESS_SLOTS = REQUIRED_HARNESS_SLOTS;

const HARNESS_FLOW: WorkflowHarnessComponentKind[] = [
  "planner",
  "prompt_assembler",
  "task_state",
  "uncertainty_gate",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "dry_run_simulator",
  "policy_gate",
  "approval_gate",
  "wallet_capability",
  "mcp_provider",
  "mcp_tool_call",
  "tool_call",
  "connector_call",
  "probe_runner",
  "memory_read",
  "memory_write",
  "semantic_impact_analyzer",
  "postcondition_synthesizer",
  "verifier",
  "drift_detector",
  "retry_policy",
  "repair_loop",
  "merge_judge",
  "quality_ledger",
  "handoff_bridge",
  "gui_harness_validator",
  "completion_gate",
  "receipt_writer",
  "output_writer",
];

const SLOT_BY_KIND: Partial<Record<WorkflowHarnessComponentKind, WorkflowHarnessSlotKind[]>> = {
  planner: ["state_policy"],
  prompt_assembler: ["state_policy"],
  task_state: ["state_policy"],
  uncertainty_gate: ["state_policy", "budget_policy"],
  probe_runner: ["verifier_policy", "budget_policy"],
  budget_gate: ["budget_policy"],
  capability_sequencer: ["tool_grant_policy"],
  model_router: ["model_policy"],
  model_call: ["model_policy"],
  tool_router: ["tool_grant_policy"],
  tool_call: ["tool_grant_policy"],
  dry_run_simulator: ["dry_run_policy"],
  mcp_provider: ["tool_grant_policy"],
  mcp_tool_call: ["tool_grant_policy"],
  connector_call: ["tool_grant_policy"],
  policy_gate: ["approval_policy"],
  approval_gate: ["approval_policy"],
  wallet_capability: ["approval_policy"],
  memory_read: ["memory_policy"],
  memory_write: ["memory_policy"],
  semantic_impact_analyzer: ["verifier_policy"],
  postcondition_synthesizer: ["verifier_policy"],
  verifier: ["verifier_policy"],
  drift_detector: ["state_policy", "verifier_policy"],
  retry_policy: ["retry_repair_policy"],
  repair_loop: ["retry_repair_policy"],
  merge_judge: ["retry_repair_policy", "verifier_policy"],
  quality_ledger: ["quality_ledger_policy"],
  handoff_bridge: ["handoff_policy"],
  gui_harness_validator: ["verifier_policy", "quality_ledger_policy"],
  output_writer: ["output_policy"],
  receipt_writer: ["output_policy"],
  completion_gate: ["verifier_policy", "quality_ledger_policy"],
};

function componentFor(kind: WorkflowHarnessComponentKind): WorkflowHarnessComponentSpec {
  const component = DEFAULT_AGENT_HARNESS_COMPONENTS.find((item) => item.kind === kind);
  if (!component) {
    throw new Error(`Missing harness component spec for ${kind}`);
  }
  return component;
}

function slotIdsFor(kind: WorkflowHarnessComponentKind): string[] {
  return (SLOT_BY_KIND[kind] ?? [])
    .map((slotKind) => REQUIRED_HARNESS_SLOTS.find((slot) => slot.kind === slotKind)?.slotId)
    .filter((slotId): slotId is string => Boolean(slotId));
}

function componentCapturesPolicyDecision(kind: WorkflowHarnessComponentKind): boolean {
  return [
    "uncertainty_gate",
    "budget_gate",
    "dry_run_simulator",
    "policy_gate",
    "approval_gate",
    "wallet_capability",
    "retry_policy",
    "completion_gate",
  ].includes(kind);
}

function componentIsNondeterministic(kind: WorkflowHarnessComponentKind): boolean {
  return [
    "model_call",
    "tool_call",
    "mcp_tool_call",
    "connector_call",
    "wallet_capability",
  ].includes(kind);
}

function replayEnvelopeFor(component: WorkflowHarnessComponentSpec): WorkflowHarnessReplayEnvelope {
  const nondeterministic = componentIsNondeterministic(component.kind);
  return {
    deterministicEnvelope: !nondeterministic,
    capturesInput: true,
    capturesOutput: true,
    capturesPolicyDecision: componentCapturesPolicyDecision(component.kind),
    determinism: nondeterministic ? "nondeterministic" : "deterministic",
    nondeterminismReason: nondeterministic
      ? "External model, tool, connector, or wallet boundary requires retained fixture evidence"
      : undefined,
    redactionPolicy: "runtime_redacted",
  };
}

function runtimeBindingFor(component: WorkflowHarnessComponentSpec): WorkflowHarnessNodeBinding {
  const replayEnvelope = replayEnvelopeFor(component);
  return {
    componentId: component.componentId,
    componentVersion: component.version,
    componentKind: component.kind,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    readiness: component.readiness,
    kernelRef: component.kernelRef,
    slotIds: slotIdsFor(component.kind),
    evidenceEventKinds: component.emittedEvents,
    receiptKinds: component.evidence,
    replayEnvelope,
    replay: {
      deterministicEnvelope: replayEnvelope.deterministicEnvelope,
      capturesInput: replayEnvelope.capturesInput,
      capturesOutput: replayEnvelope.capturesOutput,
      capturesPolicyDecision: replayEnvelope.capturesPolicyDecision,
    },
  };
}

function nodeTypeFor(kind: WorkflowHarnessComponentKind): WorkflowNode["type"] {
  switch (kind) {
    case "task_state":
      return "task_state";
    case "uncertainty_gate":
      return "uncertainty_gate";
    case "probe_runner":
      return "probe";
    case "budget_gate":
      return "budget_gate";
    case "capability_sequencer":
      return "capability_sequence";
    case "model_call":
      return "model_call";
    case "tool_call":
    case "mcp_tool_call":
      return "plugin_tool";
    case "mcp_provider":
    case "connector_call":
      return "adapter";
    case "approval_gate":
    case "wallet_capability":
      return "human_gate";
    case "memory_read":
    case "memory_write":
      return "state";
    case "dry_run_simulator":
      return "dry_run";
    case "semantic_impact_analyzer":
      return "semantic_impact";
    case "postcondition_synthesizer":
      return "postcondition_synthesis";
    case "drift_detector":
      return "drift_detector";
    case "quality_ledger":
      return "quality_ledger";
    case "handoff_bridge":
      return "handoff";
    case "gui_harness_validator":
      return "gui_harness_validation";
    case "tool_router":
    case "model_router":
    case "policy_gate":
    case "merge_judge":
    case "completion_gate":
      return "decision";
    case "retry_policy":
    case "repair_loop":
      return "loop";
    case "receipt_writer":
      return "output";
    default:
      return "function";
  }
}

function nodeLogicFor(component: WorkflowHarnessComponentSpec): Record<string, unknown> {
  const base = {
    harnessComponent: component,
    harnessSlots: slotIdsFor(component.kind),
    inputSchema: component.inputSchema,
    outputSchema: component.outputSchema,
    errorSchema: component.errorSchema,
  };
  switch (component.kind) {
    case "model_call":
      return {
        ...base,
        modelRef: "reasoning",
        prompt: "Default agent harness model invocation envelope.",
        validateStructuredOutput: true,
        outputSchema: component.outputSchema,
      };
    case "tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "native_tool",
          toolRef: "agent.runtime.native-tool.catalog.read",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["native.tool.catalog.read", "mcp.tool.catalog.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {
            mode: "native_catalog_preview",
            mutation: false,
            mcpToolCatalogRef: "input.mcpToolCatalog",
          },
        },
      };
    case "mcp_tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "mcp_tool",
          toolRef: "mcp.tool.catalog.read",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["mcp.tool.catalog.read", "mcp.provider.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {
            mode: "catalog_preview",
            mutation: false,
            providerCatalogRef: "previousAuthorityOutput.providerCatalog",
          },
        },
      };
    case "mcp_provider":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "mcp.capability-provider",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "read",
          requiresApproval: false,
          operation: "catalog",
        },
      };
    case "connector_call":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "agent.connector.catalog",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["connector.catalog.read", "mcp.tool.catalog.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          operation: "describe",
        },
      };
    case "policy_gate":
      return {
        ...base,
        authorityGateKind: "policy_gate",
        policyGateLiveExecution: true,
        routes: ["allow_read_only_route", "deny_mutation"],
        defaultRoute: "allow_read_only_route",
        readOnlyRouteAccepted: true,
        destructiveRouteDenied: true,
        mutatingToolCallsBlocked: true,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        policyDecision: "allow_read_only_route_through_workflow_authority",
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "approval_gate":
      return {
        ...base,
        authorityGateKind: "approval_gate",
        text: "Mutating tool authority remains blocked without explicit governed approval.",
        approvalMode: "legacy_runtime_required",
        requiresApproval: true,
        syntheticApprovalGranted: false,
        authorityTransferred: false,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        policyDecision: "require_legacy_approval_for_mutating_tooling",
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "wallet_capability":
      return {
        ...base,
        text: "Wallet and spending authority remain unavailable during read-only default harness dispatch.",
        approvalMode: "wallet_capability_dry_run",
        capabilityScope: ["wallet.request", "capability.grant"],
        readOnlyAuthority: true,
        requiresApproval: true,
        policyDecision: "retain_wallet_capability_without_grant",
        syntheticApprovalGranted: false,
        capabilityDryRunLiveExecution: true,
        capabilityGranted: false,
        grantMaterialized: false,
        authorityTransferred: false,
        sideEffectsExecuted: false,
        mutationExecuted: false,
        rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      };
    case "memory_read":
    case "memory_write":
      return {
        ...base,
        stateKey: component.kind,
        stateOperation: {
          key: component.kind,
          operation: component.kind === "memory_read" ? "read" : "write",
          reducer: "merge",
        },
      };
    case "retry_policy":
    case "repair_loop":
      return {
        ...base,
        loopKind: component.kind,
        maxIterations: component.retry.maxAttempts,
      };
    case "receipt_writer":
      return {
        ...base,
        format: "receipt",
        materialization: { enabled: false, assetPath: "receipts/harness/{{run.id}}.json" },
        deliveryTarget: { targetKind: "none" },
      };
    default:
      return {
        ...base,
        language: "javascript",
        code: "return { status: 'success', evidence: [], receipts: [] };",
        functionBinding: {
          language: "javascript",
          code: "return { status: 'success', evidence: [], receipts: [] };",
          outputSchema: component.outputSchema,
          sandboxPolicy: {
            timeoutMs: component.timeout.timeoutMs,
            memoryMb: 64,
            outputLimitBytes: 32768,
            permissions: [],
          },
          testInput: { sessionId: "test", turnId: "test" },
        },
      };
  }
}

function makeHarnessNode(
  kind: WorkflowHarnessComponentKind,
  index: number,
): WorkflowNode {
  const component = componentFor(kind);
  const type = nodeTypeFor(kind);
  const runtimeBinding = runtimeBindingFor(component);
  return {
    id: `harness.${kind}`,
    type,
    name: component.label,
    x: 90 + (index % 5) * 260,
    y: 110 + Math.floor(index / 5) * 190,
    metricLabel: component.ui.group,
    metricValue: component.kind,
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error", "retry"],
    runtimeBinding,
    config: {
      logic: nodeLogicFor(component),
      law: {
        requireHumanGate: component.approval.required,
        privilegedActions: component.approval.required ? component.requiredCapabilityScope : [],
        sandboxPolicy: {
          timeoutMs: component.timeout.timeoutMs,
          memoryMb: 64,
          outputLimitBytes: 65536,
          permissions: [],
        },
      },
    },
  };
}

function makeHarnessEdges(nodes: WorkflowNode[]): WorkflowEdge[] {
  return nodes.slice(0, -1).map((node, index) => ({
    id: `harness.edge.${node.id}.${nodes[index + 1].id}`,
    from: node.id,
    to: nodes[index + 1].id,
    fromPort: "output",
    toPort: "input",
    type: "data",
    connectionClass: "data",
    label: "deterministic envelope",
    data: {
      connectionClass: "data",
      receiptCorrelation: true,
    },
  }));
}

export function defaultHarnessPromotionClusters(): WorkflowHarnessPromotionCluster[] {
  return ([
    "cognition",
    "routing_model",
    "verification_output",
    "authority_tooling",
  ] as WorkflowHarnessPromotionClusterId[]).map((clusterId, index) => ({
    clusterId,
    label: HARNESS_PROMOTION_CLUSTER_LABELS[clusterId],
    activationOrder: index + 1,
    componentKinds: HARNESS_PROMOTION_CLUSTER_COMPONENTS[clusterId],
    requiredExecutionMode: "gated",
    minimumReadiness: "shadow_ready",
    promotionRule:
      "Requires zero blocking divergence, receipt coverage, replay fixture coverage, canary pass, and rollback target.",
    rollbackTarget: "shadow",
    blocksLiveActivation: true,
    promotionStatus: "shadow_ready",
    replayGateProof: {
      schemaVersion: "workflow.harness.promotion-cluster-replay-gate-proof.v1",
      clusterId,
      gateStatus: "not_run",
      activationGateImpact: "pending",
      totalFixtures: 0,
      passedCount: 0,
      blockedCount: 0,
      failedCount: 0,
      blockingDivergenceCount: 0,
      replayFixtureRefs: [],
      blockingReplayFixtureRefs: [],
      receiptRefs: [],
      evidenceRefs: [],
      blockers: ["replay_gate_not_run"],
    },
  }));
}

function harnessMetadata(options: {
  blessed: boolean;
  forkedFrom?: WorkflowHarnessMetadata["forkedFrom"];
  packageName?: string;
  activationId?: string;
  activationState: WorkflowHarnessMetadata["activationState"];
  activationRecord?: WorkflowHarnessForkActivationRecord;
  liveHandoffProof?: WorkflowHarnessLiveHandoffProof;
  runtimeSelectorDecision?: WorkflowHarnessRuntimeSelectorDecision;
  defaultRuntimeDispatchProof?: WorkflowHarnessDefaultRuntimeDispatchProof;
  canaryExecutionBoundary?: WorkflowHarnessCanaryExecutionBoundary;
  canaryExecutionBoundaries?: WorkflowHarnessCanaryExecutionBoundary[];
}): WorkflowHarnessMetadata {
  return {
    schemaVersion: "workflow.harness.v1",
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    templateName: "Default Agent Harness",
    blessed: options.blessed,
    forkable: options.blessed,
    forkedFrom: options.forkedFrom,
    packageName: options.packageName,
    activationId: options.activationId,
    activationState: options.activationState,
    activationRecord: options.activationRecord,
    liveHandoffProof: options.liveHandoffProof,
    runtimeSelectorDecision: options.runtimeSelectorDecision,
    defaultRuntimeDispatchProof: options.defaultRuntimeDispatchProof,
    canaryExecutionBoundary: options.canaryExecutionBoundary,
    canaryExecutionBoundaries: options.canaryExecutionBoundaries,
    validationGates: [
      "component_contracts_present",
      "required_slots_bound",
      "proposal_only_self_mutation",
      "receipts_mapped_to_nodes",
      "tests_and_replay_present",
      "activation_review_complete",
    ],
    aiMutationMode: "proposal_only",
    componentIds: DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => component.componentId),
    slotIds: REQUIRED_HARNESS_SLOTS.map((slot) => slot.slotId),
    componentReadiness: Object.fromEntries(
      DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
        component.componentId,
        component.readiness,
      ]),
    ),
    promotionClusters: defaultHarnessPromotionClusters(),
  };
}

export function makeDefaultAgentHarnessWorkflow(nowMs = Date.now()): WorkflowProject {
  const nodes = HARNESS_FLOW.map(makeHarnessNode);
  const workflow: WorkflowProject = {
    version: "workflow.v1",
    metadata: {
      id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      name: "Default Agent Harness",
      slug: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      workflowKind: "agent_workflow",
      executionMode: "hybrid",
      gitLocation: `.agents/workflows/${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}.workflow.json`,
      readOnly: true,
      dirty: false,
      harness: harnessMetadata({
        blessed: true,
        activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        activationState: "read_only",
      }),
      workerHarnessBinding: {
        harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
        source: "default",
      },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    nodes,
    edges: makeHarnessEdges(nodes),
    global_config: normalizeGlobalConfig({
      environmentProfile: {
        target: "local",
        credentialScope: "runtime-default",
        mockBindingPolicy: "warn",
      },
      modelBindings: {
        reasoning: { modelId: "default-agent-model-policy", required: true },
        vision: { modelId: "", required: false },
        embedding: { modelId: "", required: false },
        image: { modelId: "", required: false },
      },
      policy: {
        maxBudget: 10,
        maxSteps: 80,
        timeoutMs: 180000,
      },
      contract: {
        developerBond: 0,
        adjudicationRubric:
          "Default harness projection is inspectable and read-only; forks must pass activation gates before use.",
      },
      meta: {
        name: "Default Agent Harness",
        description:
          "Read-only projection of the blessed agent runtime harness as workflow-addressable components.",
      },
      production: {
        errorWorkflowPath: ".agents/workflows/default-agent-harness-error.workflow.json",
        evaluationSetPath: ".agents/workflows/default-agent-harness.tests.json",
        expectedTimeSavedMinutes: 0,
        mcpAccessReviewed: true,
        requireReplayFixtures: false,
      },
    }),
  };
  const revisionBinding = workflowRevisionBindingFor(workflow, {
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    activatedRevision: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    revisionSource: "file_hash_only",
    nowMs,
  });
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            revisionBinding,
          }
        : workflow.metadata.harness,
    },
  };
}

export function defaultAgentHarnessTests(
  workflow: WorkflowProject = makeDefaultAgentHarnessWorkflow(0),
): WorkflowTestCase[] {
  const componentNodeIds = workflow.nodes.map((node) => node.id);
  return [
    {
      id: "test-default-harness-components-present",
      name: "Default harness components are projected",
      targetNodeIds: componentNodeIds.slice(0, 8),
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-governance-present",
      name: "Default harness governance components are projected",
      targetNodeIds: ["harness.policy_gate", "harness.approval_gate", "harness.receipt_writer"],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-recovery-present",
      name: "Default harness retry and repair components are projected",
      targetNodeIds: ["harness.retry_policy", "harness.repair_loop", "harness.merge_judge"],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
  ];
}

export function forkDefaultAgentHarnessWorkflow(
  name = "Default Agent Harness Fork",
  nowMs = Date.now(),
): {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
} {
  const base = makeDefaultAgentHarnessWorkflow(nowMs);
  const slug = slugify(name);
  const activationGateProposalId = `proposal-${slug}-activation-gates`;
  const forkWorkerHarnessBinding: WorkflowHarnessWorkerBinding = {
    harnessWorkflowId: slug,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    source: "fork",
  };
  const blockedActivationRecord = makeHarnessForkActivationRecord({
    workflowId: slug,
    harnessWorkflowId: slug,
    activationState: "blocked",
    evidenceRefs: [activationGateProposalId],
    workerBinding: forkWorkerHarnessBinding,
    mintedAtMs: nowMs,
  });
  const workflow: WorkflowProject = {
    ...base,
    metadata: {
      ...base.metadata,
      id: slug,
      name,
      slug,
      gitLocation: `.agents/workflows/${slug}.workflow.json`,
      readOnly: false,
      dirty: true,
      harness: harnessMetadata({
        blessed: false,
        forkedFrom: {
          harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
          harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
          harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        },
        packageName: slug,
        activationState: "blocked",
        activationRecord: blockedActivationRecord,
      }),
      workerHarnessBinding: forkWorkerHarnessBinding,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    global_config: normalizeGlobalConfig({
      ...base.global_config,
      environmentProfile: {
        target: "sandbox",
        credentialScope: "harness-fork",
        mockBindingPolicy: "block",
      },
      meta: {
        name,
        description:
          "Editable fork of the Default Agent Harness. Activation remains blocked until validation gates pass.",
      },
      production: {
        ...(base.global_config.production ?? {}),
        mcpAccessReviewed: false,
        requireReplayFixtures: true,
      },
    }),
  };
  const revisionBinding = workflowRevisionBindingFor(workflow, {
    proposalId: activationGateProposalId,
    rollbackActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackRevision: base.metadata.harness?.revisionBinding?.activatedRevision,
    nowMs,
  });
  const workflowWithRevisionBinding: WorkflowProject = {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            revisionBinding,
            activationRecord: workflow.metadata.harness.activationRecord
              ? {
                  ...workflow.metadata.harness.activationRecord,
                  revisionBinding,
                  rollbackRevisionBinding: base.metadata.harness?.revisionBinding,
                }
              : workflow.metadata.harness.activationRecord,
          }
        : workflow.metadata.harness,
    },
  };
  return {
    workflow: workflowWithRevisionBinding,
    tests: defaultAgentHarnessTests(workflowWithRevisionBinding),
    proposals: [
      {
        id: activationGateProposalId,
        title: "Review harness fork activation gates",
        summary:
          "Forked harness packages stay inactive until component slots, MCP access, replay evidence, and proposal-only mutation gates are validated.",
        status: "open",
        createdAtMs: nowMs,
        boundedTargets: [
          "workflow-metadata",
          "workflow-config",
          "harness.slot.model-policy",
          "harness.slot.tool-grants",
          "harness.slot.approval",
          "harness.slot.output-policy",
        ],
        configDiff: {
          changedGlobalKeys: ["environmentProfile", "production"],
          changedMetadataKeys: ["harness", "workerHarnessBinding"],
        },
        sidecarDiff: {
          testsChanged: true,
          fixturesChanged: true,
          bindingsChanged: true,
          proposalsChanged: true,
          changedRoles: ["tests", "fixtures", "bindings", "activation"],
        },
      },
    ],
  };
}

export function workflowIsHarness(workflow: WorkflowProject): boolean {
  return Boolean(workflow.metadata.harness);
}

export function workflowIsBlessedHarness(workflow: WorkflowProject): boolean {
  return workflow.metadata.harness?.blessed === true;
}

export function workflowIsHarnessFork(workflow: WorkflowProject): boolean {
  return workflowIsHarness(workflow) && workflow.metadata.harness?.blessed !== true;
}

export function harnessComponentForNode(node: Node): WorkflowHarnessComponentSpec | null {
  const logic = node.config?.logic ?? {};
  const value = (logic as Record<string, unknown>).harnessComponent;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const component = value as WorkflowHarnessComponentSpec;
  if (!component.componentId || !component.kind) return null;
  return component;
}

export function harnessSlotsForWorkflow(workflow: WorkflowProject): WorkflowHarnessSlotSpec[] {
  if (!workflowIsHarness(workflow)) return [];
  return REQUIRED_HARNESS_SLOTS;
}

export function workflowHarnessWorkerBinding(
  workflow: WorkflowProject,
): WorkflowHarnessWorkerBinding {
  if (workflow.metadata.workerHarnessBinding) return workflow.metadata.workerHarnessBinding;
  const harness = workflow.metadata.harness;
  if (harness) {
    return {
      harnessWorkflowId: workflow.metadata.id,
      harnessActivationId: harness.activationId,
      harnessHash: harness.harnessHash,
      executionMode: harness.executionMode,
      source: harness.blessed ? "default" : "fork",
    };
  }
  return {
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: DEFAULT_HARNESS_EXECUTION_MODE,
    source: "legacy",
  };
}

export function harnessNodeEvidenceSummary(node: Node): Array<{ label: string; value: string }> {
  const component = harnessComponentForNode(node);
  if (!component) return [];
  return [
    { label: "Component", value: component.componentId },
    { label: "Version", value: component.version },
    { label: "Readiness", value: component.readiness },
    { label: "Kernel", value: component.kernelRef },
    { label: "Capability", value: component.requiredCapabilityScope.join(", ") || "none" },
    { label: "Approval", value: component.approval.required ? component.approval.mode : "none" },
    { label: "Events", value: component.emittedEvents.join(", ") },
    { label: "Evidence", value: component.evidence.join(", ") },
  ];
}
