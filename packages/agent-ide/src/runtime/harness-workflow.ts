import type {
  Node,
  WorkflowEdge,
  WorkflowHarnessCanaryExecutionBoundary,
  WorkflowHarnessComponentReadiness,
  WorkflowHarnessComponentKind,
  WorkflowHarnessComponentSpec,
  WorkflowHarnessDefaultRuntimeDispatchProof,
  WorkflowHarnessExecutionMode,
  WorkflowHarnessForkActivationRecord,
  WorkflowHarnessLiveHandoffProof,
  WorkflowHarnessMetadata,
  WorkflowHarnessNodeBinding,
  WorkflowHarnessPromotionCluster,
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessReplayEnvelope,
  WorkflowHarnessRuntimeSelectorDecision,
  WorkflowHarnessSlotKind,
  WorkflowHarnessSlotSpec,
  WorkflowHarnessWorkerBinding,
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

export function makeHarnessForkActivationRecord(options: {
  workflowId: string;
  harnessWorkflowId?: string;
  activationId?: string;
  activationState: WorkflowHarnessForkActivationRecord["activationState"];
  activationBlockers?: string[];
  canaryStatus?: WorkflowHarnessForkActivationRecord["canaryStatus"];
  rollbackTarget?: string;
  rollbackAvailable?: boolean;
  liveAuthorityTransferred?: boolean;
  evidenceRefs?: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
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
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    activationState: options.activationState,
    activationBlockers:
      options.activationBlockers ??
      (options.activationState === "validated" || options.activationState === "active"
        ? []
        : [...DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS]),
    componentVersionSet: defaultHarnessComponentVersionSet(),
    policyPosture:
      options.activationState === "validated" || options.activationState === "active"
        ? "canary"
        : "proposal_only",
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
    mintedAtMs: options.mintedAtMs,
  };
}

export function makeBlessedHarnessLiveHandoffProof(options: {
  selector?: WorkflowHarnessLiveHandoffProof["selector"];
  canaryStatus?: WorkflowHarnessLiveHandoffProof["canaryStatus"];
  canaryTurnRoutedThroughWorkflow?: boolean;
  defaultAuthorityTransferred?: boolean;
  runtimeAuthority?: WorkflowHarnessLiveHandoffProof["runtimeAuthority"];
  fallbackSelector?: WorkflowHarnessLiveHandoffProof["fallbackSelector"];
  rollbackAvailable?: boolean;
  policyDecision?: string;
  gatedClusterIds?: WorkflowHarnessLiveHandoffProof["gatedClusterIds"];
  executionBoundaryIds?: string[];
  executionBoundaryClusterIds?: WorkflowHarnessPromotionClusterId[];
  nodeTimelineAttemptIds?: string[];
  receiptIds?: string[];
  replayFixtureRefs?: string[];
  activationBlockers?: string[];
  evidenceRefs?: string[];
} = {}): WorkflowHarnessLiveHandoffProof {
  return {
    schemaVersion: "workflow.harness.live-handoff.v1",
    selector: options.selector ?? "blessed_workflow_live_canary",
    availableSelectors: [
      "legacy_runtime",
      "blessed_workflow_gated",
      "blessed_workflow_live_canary",
      "blessed_workflow_live_default",
    ],
    productionDefaultSelector: "legacy_runtime",
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
    defaultAuthorityTransferred: options.defaultAuthorityTransferred ?? false,
    runtimeAuthority: options.runtimeAuthority ?? "blessed_workflow_activation_canary",
    fallbackSelector: options.fallbackSelector ?? "legacy_runtime",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: options.rollbackAvailable ?? true,
    policyDecision: options.policyDecision ?? "allow_blessed_workflow_live_canary",
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
    activationBlockers: options.activationBlockers ?? [],
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: false,
      eligible: false,
      nonMutatingOnly: true,
      selector: options.selector ?? "blessed_workflow_live_canary",
      productionDefaultSelector: "legacy_runtime",
      defaultAuthorityTransferred: options.defaultAuthorityTransferred ?? false,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      activationBlockers: ["promotion_gate_disabled"],
      policyDecision: "retain_legacy_runtime_default",
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
}

export function makeHarnessRuntimeSelectorDecision(options: {
  decisionId?: string;
  selectedSelector?: WorkflowHarnessRuntimeSelectorDecision["selectedSelector"];
  canaryEligible?: boolean;
  canaryBlockers?: string[];
  executionMode?: WorkflowHarnessExecutionMode;
  actualRuntimeAuthority?: WorkflowHarnessRuntimeSelectorDecision["actualRuntimeAuthority"];
  policyDecision?: string;
  routeReason?: string;
  evidenceRefs?: string[];
} = {}): WorkflowHarnessRuntimeSelectorDecision {
  const selectedSelector = options.selectedSelector ?? "blessed_workflow_live_canary";
  const canarySelected = selectedSelector === "blessed_workflow_live_canary";
  return {
    schemaVersion: "workflow.harness.runtime-selector.v1",
    decisionId: options.decisionId ?? "harness-selector:default-agent-harness:canary",
    requestedSelector: "auto_canary",
    selectedSelector,
    productionDefaultSelector: "legacy_runtime",
    canaryEligible: options.canaryEligible ?? canarySelected,
    canaryBlockers: options.canaryBlockers ?? [],
    workflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    executionMode: options.executionMode ?? (canarySelected ? "live" : "gated"),
    actualRuntimeAuthority:
      options.actualRuntimeAuthority ??
      (canarySelected ? "blessed_workflow_activation_canary" : "existing_runtime_service"),
    fallbackSelector: "legacy_runtime",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    policyDecision:
      options.policyDecision ??
      (canarySelected
        ? "allow_blessed_workflow_live_canary"
        : "retain_legacy_runtime_default"),
    routeReason:
      options.routeReason ??
      (canarySelected
        ? "Turn is non-mutating and eligible for blessed workflow canary routing."
        : "Turn remains on the legacy runtime selector."),
    defaultPromotionGate: {
      configKey: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION",
      enabled: false,
      eligible: false,
      nonMutatingOnly: true,
      selector: selectedSelector,
      productionDefaultSelector: "legacy_runtime",
      defaultAuthorityTransferred: false,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      activationBlockers: ["promotion_gate_disabled"],
      policyDecision: "retain_legacy_runtime_default",
    },
    evidenceRefs: options.evidenceRefs ?? [],
  };
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
  const proposedVisibleOutputHash = "sha256:visible-output";
  const actualVisibleOutputHash = "sha256:visible-output";
  const promptAssemblyPromptHash = "sha256:prompt-final";
  const modelExecutionBindingId =
    "model-binding:default-agent-harness:workflow-default-model-route";
  const modelExecutionPromptHash = promptAssemblyPromptHash;
  const modelExecutionOutputHash = actualVisibleOutputHash;
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
    executionMode: "live",
    runtimeAuthority: "blessed_workflow_activation_default",
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
    ],
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
    drivesRuntimeDecision: true,
    cognitionExecutionMode: "workflow_synchronous_envelope",
    cognitionExecutionReady: true,
    promptAssemblyMode: "workflow_synchronous_envelope",
    promptAssemblyPromptHash,
    promptAssemblyPromptHashMatches: true,
    cognitionExecutionProof: {
      schemaVersion: "workflow.harness.cognition-execution-envelope.v1",
      mode: "workflow_synchronous_envelope",
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
      denialReceiptIds: [
        "harness-default-dispatch:receipt-authority_tooling_destructive_denial",
      ],
      deferredMutationComponentKinds: deferredComponentKinds,
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
    activationBlockers: options.activationBlockers ?? [],
    policyDecision:
      "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write",
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
const SHADOW_READY_HARNESS_COMPONENTS = new Set<WorkflowHarnessComponentKind>([
  "planner",
  "prompt_assembler",
  "task_state",
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
          toolRef: "agent.runtime.tool.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      };
    case "mcp_tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "mcp_tool",
          toolRef: "mcp.tool.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
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
        },
      };
    case "connector_call":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "agent.connector.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
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
  return {
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
  return {
    workflow,
    tests: defaultAgentHarnessTests(workflow),
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
