import type {
  Node,
  NodeLogic,
  WorkflowConnectionClass,
  WorkflowHarnessActivationCandidateGateResult,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessMetadata,
  WorkflowHarnessPromotionCluster,
  WorkflowHarnessRollbackRestoreCanary,
  WorkflowNodeFixture,
  WorkflowProject,
  WorkflowProposal,
  WorkflowModelBinding,
  WorkflowRevisionBinding,
  WorkflowRevisionRestoreResult,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import {
  actionKindForWorkflowNodeType,
  validateActionEdge,
  validateWorkflowConnection,
} from "./runtime-projection-adapter";
import {
  harnessComponentForNode,
  harnessForkActivationId,
  harnessSlotsForWorkflow,
  workflowRevisionBindingFor,
  workflowHarnessForkMutationCanaryReady,
  workflowHarnessForkMutationCanaryRefs,
  workflowHarnessWorkerBinding,
  workflowIsBlessedHarness,
  workflowIsHarness,
  workflowIsHarnessFork,
} from "./harness-workflow";
import {
  workflowExpressionReferences,
  workflowFieldMappingEntries,
  workflowNodeDeclaredOutputSchema,
  workflowSchemaHasFieldPath,
  workflowSchemaIsObjectLike,
} from "./workflow-schema";
import {
  workflowSchedulerLaneReadiness,
  workflowSchedulerLaneReadinessIssues,
} from "./workflow-scheduler-lane-readiness";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import { normalizeWorkflowModelBinding } from "./workflow-model-capability-binding";
import { workflowWorkspaceTrustGateIssues } from "./workflow-workspace-trust-gate";

export function defaultTestsForWorkflow(workflow: WorkflowProject): WorkflowTestCase[] {
  if (workflow.nodes.length === 0) return [];
  return [
    {
      id: `test-${workflow.metadata.slug}-nodes`,
      name: "Core nodes exist",
      targetNodeIds: workflow.nodes.slice(0, Math.min(workflow.nodes.length, 4)).map((nodeItem) => nodeItem.id),
      assertion: { kind: "node_exists" },
      status: "idle",
    },
  ];
}

function liveBindingContractMetadataIssues(
  nodeId: string,
  bindingKind: "connector" | "tool",
  binding: {
    mockBinding?: boolean;
    credentialReady?: boolean;
    credentialReadiness?: { status?: string } | Record<string, unknown>;
    rateLimitProfile?: Record<string, unknown>;
    idempotencyBehavior?: Record<string, unknown>;
    receiptBehavior?: Record<string, unknown>;
    workflowAvailability?: { available?: boolean } | Record<string, unknown>;
    agentAvailability?: { available?: boolean } | Record<string, unknown>;
    sideEffectClass?: string;
  } | null | undefined,
): WorkflowValidationIssue[] {
  if (!binding || binding.mockBinding !== false) return [];
  const issues: WorkflowValidationIssue[] = [];
  const sideEffectClass = String(binding.sideEffectClass ?? "none");
  const effectful = !["none", "read"].includes(sideEffectClass);
  const credentialStatus = String(
    (binding.credentialReadiness as { status?: unknown } | undefined)?.status ?? "",
  ).trim();
  if (!credentialStatus && typeof binding.credentialReady !== "boolean") {
    issues.push({
      nodeId,
      code: "missing_credential_readiness_contract",
      message: `Live ${bindingKind} bindings need credentialReadiness status metadata or a compatibility credentialReady projection.`,
    });
  }
  if (!effectful) return issues;
  if (!String(binding.rateLimitProfile?.policy ?? "").trim()) {
    issues.push({
      nodeId,
      code: "missing_rate_limit_profile",
      message: `Live ${bindingKind} bindings need rateLimitProfile.policy before execution.`,
    });
  }
  const receiptRequired = Boolean(binding.receiptBehavior?.receiptRequired);
  const receiptTypes = Array.isArray(binding.receiptBehavior?.requiredReceiptTypes)
    ? binding.receiptBehavior.requiredReceiptTypes.length
    : 0;
  if (!receiptRequired || receiptTypes === 0) {
    issues.push({
      nodeId,
      code: "missing_receipt_behavior",
      message: `Live ${bindingKind} bindings need receiptBehavior with required receipt types before execution.`,
    });
  }
  if (effectful) {
    const idempotencyRequired = Boolean(binding.idempotencyBehavior?.required);
    const idempotencyStrategy = String(binding.idempotencyBehavior?.strategy ?? "").trim();
    if (!idempotencyRequired || !idempotencyStrategy) {
      issues.push({
        nodeId,
        code: "missing_idempotency_behavior",
        message: `Effectful live ${bindingKind} bindings need idempotencyBehavior.required and strategy metadata.`,
      });
    }
  }
  if (binding.workflowAvailability?.available !== true) {
    issues.push({
      nodeId,
      code: "missing_workflow_availability",
      message: `Live ${bindingKind} bindings need workflowAvailability.available=true before activation.`,
    });
  }
  if (binding.agentAvailability?.available !== true) {
    issues.push({
      nodeId,
      code: "missing_agent_availability",
      message: `Live ${bindingKind} bindings need agentAvailability.available=true before execution.`,
    });
  }
  return issues;
}

function liveModelBindingContractMetadataIssues(
  nodeId: string,
  binding: {
    mockBinding?: boolean;
    credentialReady?: boolean;
    credentialReadiness?: { status?: string } | Record<string, unknown>;
    receiptBehavior?: Record<string, unknown>;
    workflowAvailability?: { available?: boolean } | Record<string, unknown>;
    agentAvailability?: { available?: boolean } | Record<string, unknown>;
    privacyTier?: string;
    providerPriority?: string[];
    fallbackPolicy?: Record<string, unknown>;
    costEstimateVisibility?: Record<string, unknown>;
    modelCapabilityRef?: string;
    routeId?: string;
    authorityScopes?: string[];
    authorityScopeRequirements?: string[];
    grantReadiness?: { status?: string } | Record<string, unknown>;
    policyPosture?: Record<string, unknown>;
  } | null | undefined,
): WorkflowValidationIssue[] {
  if (!binding || binding.mockBinding !== false) return [];
  const normalized = normalizeWorkflowModelBinding(binding as Partial<WorkflowModelBinding>, {});
  const issues: WorkflowValidationIssue[] = [];
  const credentialStatus = String(
    (normalized.credentialReadiness as { status?: unknown } | undefined)?.status ?? "",
  ).trim();
  if (credentialStatus !== "ready" && normalized.credentialReady !== true) {
    issues.push({
      nodeId,
      code: "missing_model_credential_readiness_contract",
      message: "Live model bindings need ready credentialReadiness or capability readiness metadata before execution.",
    });
  }
  if (!String(normalized.modelCapabilityRef ?? "").trim()) {
    issues.push({
      nodeId,
      code: "missing_model_capability_ref",
      message: "Live model bindings need a modelCapabilityRef from /api/v1/model-capabilities or authority projection.",
    });
  }
  if (!String(normalized.routeId ?? "").trim()) {
    issues.push({
      nodeId,
      code: "missing_model_route_id",
      message: "Live model bindings need a canonical routeId for deterministic model routing.",
    });
  }
  const receiptRequired = Boolean(normalized.receiptBehavior?.receiptRequired);
  const receiptTypes = Array.isArray(normalized.receiptBehavior?.requiredReceiptTypes)
    ? normalized.receiptBehavior.requiredReceiptTypes.length
    : 0;
  if (!receiptRequired || receiptTypes === 0) {
    issues.push({
      nodeId,
      code: "missing_model_receipt_behavior",
      message: "Live model bindings need receiptBehavior with model route and invocation receipt types.",
    });
  }
  if (normalized.workflowAvailability?.available !== true) {
    issues.push({
      nodeId,
      code: "missing_model_workflow_availability",
      message: "Live model bindings need workflowAvailability.available=true before activation.",
    });
  }
  if (normalized.agentAvailability?.available !== true) {
    issues.push({
      nodeId,
      code: "missing_model_agent_availability",
      message: "Live model bindings need agentAvailability.available=true before execution.",
    });
  }
  if (!String(normalized.privacyTier ?? "").trim()) {
    issues.push({
      nodeId,
      code: "missing_model_privacy_tier",
      message: "Live model bindings need privacyTier metadata for routing policy.",
    });
  }
  if (!Array.isArray(normalized.providerPriority) || normalized.providerPriority.length === 0) {
    issues.push({
      nodeId,
      code: "missing_model_provider_priority",
      message: "Live model bindings need providerPriority metadata for deterministic routing.",
    });
  }
  if (!normalized.fallbackPolicy || Object.keys(normalized.fallbackPolicy).length === 0) {
    issues.push({
      nodeId,
      code: "missing_model_fallback_policy",
      message: "Live model bindings need fallbackPolicy metadata for deterministic failover.",
    });
  }
  if (!normalized.costEstimateVisibility || Object.keys(normalized.costEstimateVisibility).length === 0) {
    issues.push({
      nodeId,
      code: "missing_model_cost_estimate_visibility",
      message: "Live model bindings need costEstimateVisibility metadata before execution.",
    });
  }
  const authorityScopes = Array.isArray(normalized.authorityScopes) && normalized.authorityScopes.length > 0
    ? normalized.authorityScopes
    : normalized.authorityScopeRequirements;
  if (!Array.isArray(authorityScopes) || authorityScopes.length === 0) {
    issues.push({
      nodeId,
      code: "missing_model_authority_scope_requirements",
      message: "Live model bindings need authorityScopes or authorityScopeRequirements metadata.",
    });
  }
  const grantStatus = String(
    (normalized.grantReadiness as { status?: unknown } | undefined)?.status ?? "",
  ).trim();
  if (grantStatus !== "ready") {
    issues.push({
      nodeId,
      code: "missing_model_grant_readiness",
      message: "Live model bindings need ready grantReadiness from wallet authority before execution.",
    });
  }
  const policyStatus = String(
    (normalized.policyPosture as { status?: unknown } | undefined)?.status ?? "",
  ).trim();
  if (!["allowed", "approved", "ready"].includes(policyStatus)) {
    issues.push({
      nodeId,
      code: "missing_model_policy_posture",
      message: "Live model bindings need an allowed policyPosture before execution.",
    });
  }
  return issues;
}

function workflowHarnessPromotionClusterReplayGateBlocksActivation(
  cluster: WorkflowHarnessPromotionCluster,
): boolean {
  if (!cluster.blocksLiveActivation) return false;
  const proof = cluster.replayGateProof;
  if (!proof) return true;
  return (
    proof.gateStatus !== "passed" ||
    proof.activationGateImpact !== "passed" ||
    proof.totalFixtures <= 0 ||
    proof.blockingDivergenceCount > 0 ||
    proof.blockingReplayFixtureRefs.length > 0
  );
}

function workflowHarnessPromotionClusterReplayGateBlockers(
  harness: Pick<WorkflowHarnessMetadata, "promotionClusters"> | null | undefined,
): WorkflowHarnessPromotionCluster[] {
  return (harness?.promotionClusters ?? []).filter(
    workflowHarnessPromotionClusterReplayGateBlocksActivation,
  );
}

type WorkflowHarnessPackageEvidenceReview = {
  ready: boolean;
  required: boolean;
  value: string;
  blockers: string[];
  evidenceRefs: string[];
};

function workflowUniqueStrings(refs: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      refs.filter((ref): ref is string => typeof ref === "string" && ref.length > 0),
    ),
  );
}

function workflowHarnessPackageEvidenceReview(
  workflow: WorkflowProject,
): WorkflowHarnessPackageEvidenceReview {
  const harness = workflow.metadata.harness;
  const activationRecord = harness?.activationRecord;
  const manifest = harness?.packageManifest ?? activationRecord?.packageManifest;
  const required =
    harness?.activationState === "validated" ||
    Boolean(harness?.activationId) ||
    activationRecord?.activationState === "validated" ||
    Boolean(activationRecord?.activationId);
  if (!manifest) {
    return {
      ready: !required,
      required,
      value: required ? "missing" : "not required",
      blockers: required ? ["package_manifest_missing"] : [],
      evidenceRefs: [],
    };
  }
  const manifestIsValidated =
    required ||
    manifest.activationState === "validated" ||
    Boolean(manifest.activationId);
  const receiptRefs = Array.isArray(manifest.receiptRefs) ? manifest.receiptRefs : [];
  const evidenceRefs = Array.isArray(manifest.evidenceRefs) ? manifest.evidenceRefs : [];
  const replayFixtureRefs = Array.isArray(manifest.replayFixtureRefs)
    ? manifest.replayFixtureRefs
    : [];
  const deepLinks = Array.isArray(manifest.deepLinks) ? manifest.deepLinks : [];
  const workerHandoffNodeAttemptIds = Array.isArray(
    manifest.workerHandoffNodeAttemptIds,
  )
    ? manifest.workerHandoffNodeAttemptIds
    : [];
  const workerHandoffReceiptIds = Array.isArray(manifest.workerHandoffReceiptIds)
    ? manifest.workerHandoffReceiptIds
    : [];
  const forkMutationCanary =
    manifest.forkMutationCanary ??
    activationRecord?.forkMutationCanary ??
    harness?.forkMutationCanary ??
    null;
  const forkMutationCanaryReceiptRefs = Array.isArray(
    manifest.forkMutationCanaryReceiptRefs,
  )
    ? manifest.forkMutationCanaryReceiptRefs
    : (forkMutationCanary?.receiptRefs ?? []);
  const forkMutationCanaryReplayFixtureRefs = Array.isArray(
    manifest.forkMutationCanaryReplayFixtureRefs,
  )
    ? manifest.forkMutationCanaryReplayFixtureRefs
    : (forkMutationCanary?.replayFixtureRefs ?? []);
  const forkMutationCanaryNodeAttemptIds = Array.isArray(
    manifest.forkMutationCanaryNodeAttemptIds,
  )
    ? manifest.forkMutationCanaryNodeAttemptIds
    : (forkMutationCanary?.nodeAttemptIds ?? []);
  const rollbackRestoreReceiptRefs = Array.isArray(
    manifest.rollbackRestoreReceiptRefs,
  )
    ? manifest.rollbackRestoreReceiptRefs
    : [];
  const blockers = manifestIsValidated
    ? [
        ...(manifest.schemaVersion ===
        "workflow.harness.package-evidence-manifest.v1"
          ? []
          : ["package_manifest_schema_mismatch"]),
        ...(receiptRefs.length > 0
          ? []
          : ["package_manifest_receipts_missing"]),
        ...(replayFixtureRefs.length > 0
          ? []
          : ["package_manifest_replay_fixtures_missing"]),
        ...(deepLinks.length > 0
          ? []
          : ["package_manifest_deep_links_missing"]),
        ...(workflowHarnessForkMutationCanaryReady(forkMutationCanary)
          ? []
          : ["package_manifest_fork_mutation_canary_missing"]),
        ...(forkMutationCanaryReceiptRefs.length > 0
          ? []
          : ["package_manifest_fork_mutation_canary_receipts_missing"]),
        ...(forkMutationCanaryReplayFixtureRefs.length > 0
          ? []
          : ["package_manifest_fork_mutation_canary_replay_missing"]),
        ...(forkMutationCanaryNodeAttemptIds.length > 0
          ? []
          : ["package_manifest_fork_mutation_canary_attempts_missing"]),
        ...(workerHandoffNodeAttemptIds.length > 0
          ? []
          : ["package_manifest_worker_handoff_attempts_missing"]),
        ...(workerHandoffReceiptIds.length > 0
          ? []
          : ["package_manifest_worker_handoff_receipts_missing"]),
        ...(rollbackRestoreReceiptRefs.length > 0
          ? []
          : ["package_manifest_rollback_restore_receipts_missing"]),
      ]
    : [];
  return {
    ready: blockers.length === 0,
    required: manifestIsValidated,
    value:
      blockers.length === 0
        ? manifestIsValidated
          ? "verified"
          : "recorded"
        : `${blockers.length} blockers`,
    blockers,
    evidenceRefs: workflowUniqueStrings([
      manifest.activationId,
      manifest.workflowContentHash,
      manifest.rollbackTarget,
      ...evidenceRefs,
      ...receiptRefs,
      ...replayFixtureRefs,
      ...workflowHarnessForkMutationCanaryRefs(forkMutationCanary),
      ...forkMutationCanaryReceiptRefs,
      ...forkMutationCanaryReplayFixtureRefs,
      ...forkMutationCanaryNodeAttemptIds,
      ...rollbackRestoreReceiptRefs,
      ...workerHandoffNodeAttemptIds,
      ...workerHandoffReceiptIds,
      ...deepLinks.map((link) => link?.ref),
    ]),
  };
}

const WORKFLOW_REPAIR_BY_CODE: Record<
  string,
  Partial<
    Pick<
      WorkflowValidationIssue,
      | "configSection"
      | "fieldPath"
      | "repairActionId"
      | "repairLabel"
      | "suggestedCreatorId"
    >
  >
> = {
  invalid_expression_connection: {
    configSection: "mapping",
    repairActionId: "open-field-mapping",
    repairLabel: "Review field mapping",
  },
  invalid_field_mapping_source: {
    configSection: "mapping",
    repairActionId: "open-field-mapping",
    repairLabel: "Choose upstream field",
  },
  invalid_workflow_tool_attempts: {
    configSection: "bindings",
    fieldPath: "toolBinding.workflowTool.retry.maxAttempts",
    repairActionId: "open-tool-binding",
    repairLabel: "Fix retry limit",
  },
  invalid_workflow_tool_timeout: {
    configSection: "bindings",
    fieldPath: "toolBinding.workflowTool.timeoutMs",
    repairActionId: "open-tool-binding",
    repairLabel: "Fix timeout",
  },
  live_connector_write_unavailable: {
    configSection: "bindings",
    repairActionId: "open-connector-binding",
    repairLabel: "Bind connector",
  },
  live_tool_side_effect_unavailable: {
    configSection: "bindings",
    repairActionId: "open-tool-binding",
    repairLabel: "Bind tool",
  },
  mcp_access_not_reviewed: {
    configSection: "policy",
    fieldPath: "production.mcpAccessReviewed",
    repairActionId: "open-policy",
    repairLabel: "Review MCP access",
  },
  missing_ai_evaluation_coverage: {
    configSection: "tests",
    repairActionId: "create-eval-test",
    repairLabel: "Add evaluation coverage",
    suggestedCreatorId: "test_assertion.eval",
  },
  missing_connector_binding: {
    configSection: "bindings",
    fieldPath: "connectorBinding.connectorRef",
    repairActionId: "open-connector-binding",
    repairLabel: "Choose connector",
  },
  missing_runtime_coding_tool_budget_recovery_approval_binding: {
    configSection: "mapping",
    fieldPath: "runtimeCodingToolBudgetRecoveryApprovalIdField",
    repairActionId: "bind-coding-tool-budget-recovery-evidence",
    repairLabel: "Bind recovery input",
  },
  missing_runtime_coding_tool_budget_recovery_policy_binding: {
    configSection: "mapping",
    fieldPath: "runtimeCodingToolBudgetRecoveryPolicyInputField",
    repairActionId: "bind-coding-tool-budget-recovery-evidence",
    repairLabel: "Bind recovery input",
  },
  missing_runtime_coding_tool_budget_recovery_run_binding: {
    configSection: "mapping",
    fieldPath: "runtimeCodingToolBudgetRecoveryRunIdField",
    repairActionId: "bind-coding-tool-budget-recovery-evidence",
    repairLabel: "Bind recovery input",
  },
  missing_runtime_coding_tool_budget_recovery_target_binding: {
    configSection: "mapping",
    fieldPath: "runtimeCodingToolBudgetRecoveryTargetNodeIdsField",
    repairActionId: "bind-coding-tool-budget-recovery-evidence",
    repairLabel: "Bind recovery input",
  },
  missing_runtime_coding_tool_budget_recovery_thread_binding: {
    configSection: "mapping",
    fieldPath: "runtimeCodingToolBudgetRecoveryThreadIdField",
    repairActionId: "bind-coding-tool-budget-recovery-evidence",
    repairLabel: "Bind recovery input",
  },
  missing_runtime_telemetry_source_budget_usage_binding: {
    configSection: "mapping",
    repairActionId: "bind-runtime-telemetry-source",
    repairLabel: "Bind telemetry source",
  },
  missing_runtime_telemetry_source_context_budget_binding: {
    configSection: "mapping",
    repairActionId: "bind-runtime-telemetry-source",
    repairLabel: "Bind telemetry source",
  },
  missing_runtime_telemetry_source_thread_binding: {
    configSection: "mapping",
    repairActionId: "bind-runtime-telemetry-source",
    repairLabel: "Bind telemetry source",
  },
  missing_runtime_telemetry_source_usage_binding: {
    configSection: "mapping",
    repairActionId: "bind-runtime-telemetry-source",
    repairLabel: "Bind telemetry source",
  },
  missing_edge_endpoint: {
    configSection: "connections",
    repairActionId: "repair-connection",
    repairLabel: "Repair connection",
  },
  missing_error_handling_path: {
    configSection: "connections",
    repairActionId: "add-error-path",
    repairLabel: "Add error path",
    suggestedCreatorId: "flow.error_path",
  },
  missing_event_trigger: {
    configSection: "settings",
    repairActionId: "add-event-trigger",
    repairLabel: "Add event trigger",
    suggestedCreatorId: "trigger.event",
  },
  missing_expression_node: {
    configSection: "mapping",
    repairActionId: "open-field-mapping",
    repairLabel: "Repair expression",
  },
  missing_expression_port: {
    configSection: "mapping",
    repairActionId: "open-field-mapping",
    repairLabel: "Repair expression port",
  },
  missing_field_mapping_path: {
    configSection: "mapping",
    repairActionId: "open-field-mapping",
    repairLabel: "Choose valid field",
  },
  missing_function_binding: {
    configSection: "bindings",
    fieldPath: "functionBinding.code",
    repairActionId: "open-function-editor",
    repairLabel: "Configure function",
    suggestedCreatorId: "function.javascript",
  },
  missing_live_connector_credential: {
    configSection: "bindings",
    repairActionId: "open-connector-binding",
    repairLabel: "Add connector credentials",
  },
  missing_live_model_credential: {
    configSection: "bindings",
    repairActionId: "open-model-binding",
    repairLabel: "Add model credentials",
  },
  missing_live_tool_credential: {
    configSection: "bindings",
    repairActionId: "open-tool-binding",
    repairLabel: "Add tool credentials",
  },
  missing_model_binding: {
    configSection: "bindings",
    fieldPath: "modelRef",
    repairActionId: "open-model-binding",
    repairLabel: "Choose model",
    suggestedCreatorId: "model_call.model",
  },
  missing_model_binding_result_schema: {
    configSection: "schema",
    fieldPath: "modelBinding.resultSchema",
    repairActionId: "open-schema",
    repairLabel: "Define model result schema",
  },
  missing_model_memory_attachment: {
    configSection: "connections",
    repairActionId: "add-memory",
    repairLabel: "Attach memory",
    suggestedCreatorId: "state.memory",
  },
  missing_model_output_schema: {
    configSection: "schema",
    fieldPath: "outputSchema",
    repairActionId: "open-schema",
    repairLabel: "Define model output schema",
  },
  missing_model_parser_attachment: {
    configSection: "connections",
    repairActionId: "add-parser",
    repairLabel: "Attach parser",
    suggestedCreatorId: "model_call.parser",
  },
  missing_model_tool_attachment: {
    configSection: "connections",
    repairActionId: "add-tool",
    repairLabel: "Attach tool",
    suggestedCreatorId: "plugin_tool.mcp",
  },
  missing_output_node: {
    configSection: "outputs",
    repairActionId: "add-output",
    repairLabel: "Add output",
    suggestedCreatorId: "output.inline",
  },
  missing_output_schema: {
    configSection: "schema",
    fieldPath: "outputSchema",
    repairActionId: "open-schema",
    repairLabel: "Define output schema",
  },
  missing_parser_binding: {
    configSection: "bindings",
    repairActionId: "open-parser-binding",
    repairLabel: "Choose parser",
  },
  missing_parser_result_schema: {
    configSection: "schema",
    fieldPath: "parserBinding.resultSchema",
    repairActionId: "open-schema",
    repairLabel: "Define parser schema",
  },
  missing_proposal_bounds: {
    configSection: "advanced",
    fieldPath: "proposalAction.boundedTargets",
    repairActionId: "open-proposal-bounds",
    repairLabel: "Set proposal bounds",
    suggestedCreatorId: "proposal.bounded_config",
  },
  missing_replay_fixture: {
    configSection: "fixtures",
    repairActionId: "capture-fixture",
    repairLabel: "Capture fixture",
  },
  missing_scheduled_trigger: {
    configSection: "settings",
    repairActionId: "add-scheduled-trigger",
    repairLabel: "Add schedule",
    suggestedCreatorId: "trigger.scheduled",
  },
  missing_start_node: {
    configSection: "settings",
    repairActionId: "add-start",
    repairLabel: "Add start primitive",
    suggestedCreatorId: "trigger.manual",
  },
  missing_state_key: {
    configSection: "settings",
    fieldPath: "stateOperation.key",
    repairActionId: "open-state-settings",
    repairLabel: "Set state key",
  },
  missing_subgraph_ref: {
    configSection: "bindings",
    fieldPath: "subgraphRef.workflowPath",
    repairActionId: "open-subgraph-binding",
    repairLabel: "Choose subworkflow",
  },
  missing_test_target: {
    configSection: "tests",
    repairActionId: "open-test-editor",
    repairLabel: "Repair test target",
  },
  missing_tool_binding: {
    configSection: "bindings",
    fieldPath: "toolBinding.toolRef",
    repairActionId: "open-tool-binding",
    repairLabel: "Choose tool",
    suggestedCreatorId: "plugin_tool.mcp",
  },
  missing_trigger_event_source: {
    configSection: "settings",
    fieldPath: "eventSource",
    repairActionId: "open-trigger-settings",
    repairLabel: "Set event source",
  },
  missing_trigger_schedule: {
    configSection: "settings",
    fieldPath: "schedule",
    repairActionId: "open-trigger-settings",
    repairLabel: "Set schedule",
  },
  missing_unit_tests: {
    configSection: "tests",
    repairActionId: "create-test",
    repairLabel: "Add unit test",
    suggestedCreatorId: "test_assertion",
  },
  missing_workflow_tool_argument_schema: {
    configSection: "schema",
    fieldPath: "toolBinding.workflowTool.argumentSchema",
    repairActionId: "open-tool-schema",
    repairLabel: "Define tool arguments",
  },
  missing_workflow_tool_ref: {
    configSection: "bindings",
    fieldPath: "toolBinding.workflowTool.workflowPath",
    repairActionId: "open-workflow-tool-binding",
    repairLabel: "Choose workflow tool",
    suggestedCreatorId: "plugin_tool.workflow",
  },
  missing_workflow_tool_result_schema: {
    configSection: "schema",
    fieldPath: "toolBinding.workflowTool.resultSchema",
    repairActionId: "open-tool-schema",
    repairLabel: "Define tool result",
  },
  mock_binding_active: {
    configSection: "bindings",
    repairActionId: "open-binding-mode",
    repairLabel: "Review binding mode",
  },
  harness_activation_not_validated: {
    configSection: "advanced",
    repairActionId: "open-harness-readiness",
    repairLabel: "Validate harness activation",
  },
  harness_component_contract_missing: {
    configSection: "advanced",
    repairActionId: "open-harness-component",
    repairLabel: "Review component contract",
  },
  harness_fork_lineage_missing: {
    configSection: "advanced",
    repairActionId: "open-harness-lineage",
    repairLabel: "Review harness lineage",
  },
  harness_read_only_template: {
    configSection: "advanced",
    repairActionId: "fork-harness",
    repairLabel: "Fork harness",
  },
  harness_required_slot_unbound: {
    configSection: "advanced",
    repairActionId: "open-harness-slots",
    repairLabel: "Bind harness slot",
  },
  harness_promotion_cluster_replay_gate_not_passed: {
    configSection: "advanced",
    repairActionId: "open-harness-replay-gate",
    repairLabel: "Run cluster replay gate",
  },
  harness_package_manifest_incomplete: {
    configSection: "advanced",
    repairActionId: "open-harness-package-evidence",
    repairLabel: "Review package evidence",
  },
  harness_self_mutation_not_proposal_only: {
    configSection: "policy",
    repairActionId: "open-policy",
    repairLabel: "Require proposal-only edits",
  },
  harness_worker_binding_missing: {
    configSection: "advanced",
    repairActionId: "open-harness-worker-binding",
    repairLabel: "Bind worker identity",
  },
  scheduler_lane_capability_missing: {
    configSection: "advanced",
    repairActionId: "open-harness-readiness",
    repairLabel: "Review scheduler lanes",
  },
  open_proposal: {
    configSection: "advanced",
    repairActionId: "open-proposals",
    repairLabel: "Resolve proposal",
  },
  operational_value_not_estimated: {
    configSection: "advanced",
    fieldPath: "production.expectedTimeSavedMinutes",
    repairActionId: "open-value-settings",
    repairLabel: "Estimate value",
  },
  output_policy_required: {
    configSection: "policy",
    repairActionId: "open-output-policy",
    repairLabel: "Configure output policy",
  },
  policy_required: {
    configSection: "policy",
    repairActionId: "open-policy",
    repairLabel: "Add approval gate",
    suggestedCreatorId: "human_gate",
  },
  proposal_approval_required: {
    configSection: "policy",
    repairActionId: "open-policy",
    repairLabel: "Require proposal approval",
  },
  unbound_model_ref: {
    configSection: "bindings",
    fieldPath: "modelRef",
    repairActionId: "open-model-binding",
    repairLabel: "Choose model",
  },
  unconnected_expression_ref: {
    configSection: "connections",
    repairActionId: "connect-expression-source",
    repairLabel: "Connect upstream source",
  },
  unsafe_function_permission: {
    configSection: "policy",
    fieldPath: "functionBinding.sandboxPolicy.permissions",
    repairActionId: "open-function-policy",
    repairLabel: "Review sandbox permissions",
  },
  unsupported_function_dependency: {
    configSection: "bindings",
    fieldPath: "functionRef.dependencyManifest",
    repairActionId: "open-function-dependencies",
    repairLabel: "Review dependencies",
  },
  unsupported_function_runtime: {
    configSection: "bindings",
    fieldPath: "functionBinding.language",
    repairActionId: "open-function-editor",
    repairLabel: "Choose supported runtime",
  },
  unsupported_live_trigger: {
    configSection: "settings",
    fieldPath: "runtimeReady",
    repairActionId: "open-trigger-settings",
    repairLabel: "Configure trigger runtime",
  },
  unsupported_node_kind: {
    configSection: "settings",
    repairActionId: "replace-node",
    repairLabel: "Replace unsupported node",
  },
};

function withWorkflowIssueRepairMetadata(
  issue: WorkflowValidationIssue,
): WorkflowValidationIssue {
  const repair = WORKFLOW_REPAIR_BY_CODE[issue.code];
  return repair ? { ...repair, ...issue } : issue;
}

function withWorkflowIssueListRepairMetadata(
  issues: WorkflowValidationIssue[] | undefined,
): WorkflowValidationIssue[] {
  return (issues ?? []).map(withWorkflowIssueRepairMetadata);
}

export function validateWorkflowExpressionReferences(
  workflow: WorkflowProject,
  node: Node,
): WorkflowValidationIssue[] {
  const issues: WorkflowValidationIssue[] = [];
  const nodeById = new Map(workflow.nodes.map((item) => [item.id, item]));
  const logic = node.config?.logic ?? {};
  const mappedValues = {
    inputMapping: logic.inputMapping,
    fieldMappings: logic.fieldMappings,
    subgraphInputMapping: logic.subgraphRef?.inputMapping,
    prompt: logic.prompt,
    testInput: logic.testInput,
    functionTestInput: logic.functionBinding?.testInput,
    toolArguments: logic.toolBinding?.arguments,
  };
  const references = workflowExpressionReferences(mappedValues);
  references.forEach((reference) => {
    const sourceNode = nodeById.get(reference.nodeId);
    if (!sourceNode) {
      issues.push({
        nodeId: node.id,
        code: "missing_expression_node",
        message: `Expression ${reference.expression} references a missing source node.`,
      });
      return;
    }
    const sourcePort = sourceNode.ports?.find((port) => port.direction === "output" && port.id === reference.portId);
    if (!sourcePort) {
      issues.push({
        nodeId: node.id,
        code: "missing_expression_port",
        message: `Expression ${reference.expression} references a missing output port.`,
      });
      return;
    }
    const incomingEdge = workflow.edges.find(
      (edge) =>
        edge.from === sourceNode.id &&
        edge.to === node.id &&
        (edge.fromPort || "output") === sourcePort.id,
    );
    if (!incomingEdge) {
      issues.push({
        nodeId: node.id,
        code: "unconnected_expression_ref",
        message: `Expression ${reference.expression} needs a matching incoming edge from '${sourceNode.name}'.`,
      });
      return;
    }
    const targetPort = node.ports?.find((port) => port.direction === "input" && port.id === incomingEdge.toPort);
    const classIssue = validateWorkflowConnection(
      actionKindForWorkflowNodeType(sourceNode.type),
      actionKindForWorkflowNodeType(node.type),
      sourcePort,
      targetPort ?? null,
    );
    if (classIssue) {
      issues.push({
        nodeId: node.id,
        code: "invalid_expression_connection",
        message: `${reference.expression} cannot use the connected ports: ${classIssue.message}`,
      });
    }
  });
  workflowFieldMappingEntries(logic.fieldMappings).forEach((mapping) => {
    const [reference] = workflowExpressionReferences(mapping.source);
    if (!reference) {
      issues.push({
        nodeId: node.id,
        code: "invalid_field_mapping_source",
        message: `Field mapping '${mapping.key}' needs a node output source expression.`,
      });
      return;
    }
    const sourceNode = nodeById.get(reference.nodeId);
    if (!sourceNode) return;
    const sourcePort = sourceNode.ports?.find((port) => port.direction === "output" && port.id === reference.portId);
    if (!sourcePort) return;
    const sourceSchema = workflowNodeDeclaredOutputSchema(sourceNode);
    if (!workflowSchemaHasFieldPath(sourceSchema, mapping.path)) {
      issues.push({
        nodeId: node.id,
        code: "missing_field_mapping_path",
        message: `Field mapping '${mapping.key}' references '${mapping.path}', which is not in '${sourceNode.name}' output schema.`,
      });
    }
  });
  return issues;
}

function workflowHasErrorOrRetryPath(workflow: WorkflowProject): boolean {
  const production = workflow.global_config.production ?? {};
  return Boolean(production.errorWorkflowPath?.trim()) ||
    workflow.edges.some((edge) => {
      const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
      return edgeClass === "error" || edgeClass === "retry" || edge.fromPort === "error" || edge.fromPort === "retry";
    });
}

function workflowNodeNeedsOperationalErrorPath(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  if (node.type === "adapter") {
    const sideEffectClass = logic.connectorBinding?.sideEffectClass ?? "none";
    return !["none", "read"].includes(sideEffectClass);
  }
  if (node.type === "plugin_tool") {
    const sideEffectClass = logic.toolBinding?.sideEffectClass ?? "none";
    return !["none", "read"].includes(sideEffectClass);
  }
  if (node.type === "output") {
    const materializesAsset = logic.materialization?.enabled === true;
    const targetKind = logic.deliveryTarget?.targetKind ?? "none";
    return materializesAsset || ["local_file", "repo_patch", "connector_write", "deploy"].includes(targetKind);
  }
  return false;
}

function workflowNodeIsMcpTool(node: Node): boolean {
  return node.type === "plugin_tool" && node.config?.logic?.toolBinding?.bindingKind === "mcp_tool";
}

function workflowNodeIsHookPolicy(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  return (
    node.type === "hook_policy" ||
    node.runtimeBinding?.componentKind === "hook_policy" ||
    logic.nodeTypeLabel === "HookPolicyNode" ||
    logic.hookDryRunOnly === true ||
    logic.requireHookDryRunPlan === true
  );
}

function workflowObjectRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function workflowValueAtPath(value: unknown, path: string): unknown {
  const parts = path.split(".").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0) return value;
  let current: unknown = value;
  for (const part of parts) {
    const record = workflowObjectRecord(current);
    if (!record || !(part in record)) return undefined;
    current = record[part];
  }
  return current;
}

function workflowStringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function workflowNumberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function workflowBooleanValue(value: unknown): boolean {
  return value === true;
}

function workflowHookDryRunPlanForNode(node: Node): Record<string, unknown> | null {
  const logic = node.config?.logic ?? {};
  const activationGate = workflowObjectRecord(logic.activationGate);
  const planField =
    workflowStringValue(logic.hookDryRunPlanField) ??
    workflowStringValue(activationGate?.hookDryRunPlanField) ??
    "hookDryRunPlan";
  return (
    workflowObjectRecord(workflowValueAtPath(logic, planField)) ??
    workflowObjectRecord(logic.hookDryRunPlan)
  );
}

function workflowHookPolicyStatusForNode(
  node: Node,
  plan: Record<string, unknown>,
): string | null {
  const logic = node.config?.logic ?? {};
  const activationGate = workflowObjectRecord(logic.activationGate);
  const statusField =
    workflowStringValue(logic.hookPolicyDecisionField) ??
    workflowStringValue(activationGate?.hookPolicyDecisionField) ??
    "hookDryRunPlan.policyDecision.status";
  return (
    workflowStringValue(workflowValueAtPath(logic, statusField)) ??
    workflowStringValue(workflowValueAtPath(plan, "policyDecision.status"))
  );
}

function workflowHookDryRunBlockedCount(plan: Record<string, unknown>): number {
  const explicitCount = workflowNumberValue(plan.blockedCount);
  if (explicitCount !== null) return explicitCount;
  const decisions = Array.isArray(plan.decisions) ? plan.decisions : [];
  return decisions.filter((decision) => {
    const record = workflowObjectRecord(decision);
    return record?.decision === "blocked";
  }).length;
}

function workflowHookCommandExecutionEnabled(
  node: Node,
  plan: Record<string, unknown> | null,
): boolean {
  const logic = node.config?.logic ?? {};
  const policyDecision = workflowObjectRecord(plan?.policyDecision);
  return (
    workflowBooleanValue(logic.hookExecutionEnabled) ||
    workflowBooleanValue(logic.hookCommandExecutionEnabled) ||
    workflowBooleanValue(plan?.hookExecutionEnabled) ||
    workflowBooleanValue(plan?.commandExecutionEnabled) ||
    workflowBooleanValue(policyDecision?.hookExecutionEnabled) ||
    workflowBooleanValue(policyDecision?.commandExecutionEnabled)
  );
}

function workflowHookPolicyRoutesConfigured(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  const routes = Array.isArray(logic.routes) ? logic.routes.map(String) : [];
  const passedRoute = workflowStringValue(logic.hookPolicyPassedRoute);
  const blockedRoute = workflowStringValue(logic.hookPolicyBlockedRoute);
  return Boolean(
    passedRoute &&
      blockedRoute &&
      routes.includes(passedRoute) &&
      routes.includes(blockedRoute),
  );
}

type RuntimeCodingToolBudgetRecoveryBindingRequirement = {
  code: string;
  label: string;
  fixedKey: string;
  fieldKey: string;
  defaultField: string;
  aliases: string[];
  fieldPath: string;
  fixed: (value: unknown) => boolean;
};

const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDINGS: RuntimeCodingToolBudgetRecoveryBindingRequirement[] = [
  {
    code: "missing_runtime_coding_tool_budget_recovery_run_binding",
    label: "run id",
    fixedKey: "runtimeCodingToolBudgetRecoveryRunId",
    fieldKey: "runtimeCodingToolBudgetRecoveryRunIdField",
    defaultField: "runId",
    aliases: ["runId", "run_id"],
    fieldPath: "runtimeCodingToolBudgetRecoveryRunIdField",
    fixed: workflowStringIsPresent,
  },
  {
    code: "missing_runtime_coding_tool_budget_recovery_thread_binding",
    label: "thread id",
    fixedKey: "runtimeCodingToolBudgetRecoveryThreadId",
    fieldKey: "runtimeCodingToolBudgetRecoveryThreadIdField",
    defaultField: "threadId",
    aliases: ["threadId", "thread_id"],
    fieldPath: "runtimeCodingToolBudgetRecoveryThreadIdField",
    fixed: workflowStringIsPresent,
  },
  {
    code: "missing_runtime_coding_tool_budget_recovery_approval_binding",
    label: "approval id",
    fixedKey: "runtimeCodingToolBudgetRecoveryApprovalId",
    fieldKey: "runtimeCodingToolBudgetRecoveryApprovalIdField",
    defaultField: "approvalId",
    aliases: ["approvalId", "approval_id"],
    fieldPath: "runtimeCodingToolBudgetRecoveryApprovalIdField",
    fixed: workflowStringIsPresent,
  },
  {
    code: "missing_runtime_coding_tool_budget_recovery_target_binding",
    label: "target node ids",
    fixedKey: "runtimeCodingToolBudgetRecoveryTargetNodeIds",
    fieldKey: "runtimeCodingToolBudgetRecoveryTargetNodeIdsField",
    defaultField: "targetNodeIds",
    aliases: ["targetNodeIds", "target_node_ids"],
    fieldPath: "runtimeCodingToolBudgetRecoveryTargetNodeIdsField",
    fixed: workflowStringListIsPresent,
  },
  {
    code: "missing_runtime_coding_tool_budget_recovery_policy_binding",
    label: "recovery policy",
    fixedKey: "runtimeCodingToolBudgetRecoveryPolicy",
    fieldKey: "runtimeCodingToolBudgetRecoveryPolicyInputField",
    defaultField: "recoveryPolicy",
    aliases: ["recoveryPolicy", "recovery_policy"],
    fieldPath: "runtimeCodingToolBudgetRecoveryPolicyInputField",
    fixed: workflowRecoveryPolicyIsFixed,
  },
];

function workflowStringIsPresent(value: unknown): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function workflowStringListIsPresent(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => workflowStringIsPresent(item));
  }
  return workflowStringIsPresent(value);
}

function workflowRecoveryPolicyIsFixed(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (workflowStringListIsPresent(record.targetNodeIds)) return true;
  if (workflowStringListIsPresent(record.sourceNodeIds)) return true;
  const source = workflowStringValue(record.source);
  return Boolean(source && source !== "react_flow_template");
}

function workflowMappedInputFieldIsPresent(
  logicValue: unknown,
  aliases: string[],
): boolean {
  const logic =
    logicValue && typeof logicValue === "object" && !Array.isArray(logicValue)
      ? (logicValue as Record<string, unknown>)
      : {};
  const inputMapping =
    logic.inputMapping &&
    typeof logic.inputMapping === "object" &&
    !Array.isArray(logic.inputMapping)
      ? (logic.inputMapping as Record<string, unknown>)
      : {};
  const inputMapped = aliases.some((alias) =>
    workflowStringIsPresent(inputMapping[alias]),
  );
  if (inputMapped) return true;
  return workflowFieldMappingEntries(logic.fieldMappings).some(
    (mapping) => aliases.includes(mapping.key),
  );
}

function workflowRuntimeCodingToolBudgetRecoveryBindingIssues(
  node: Node,
): WorkflowValidationIssue[] {
  if (node.type !== "runtime_coding_tool_budget_recovery") return [];
  const logic = node.config?.logic ?? {};
  return RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDINGS.flatMap((requirement) => {
    const fixedValue = (logic as Record<string, unknown>)[requirement.fixedKey];
    if (requirement.fixed(fixedValue)) return [];
    const configuredField =
      workflowStringValue((logic as Record<string, unknown>)[requirement.fieldKey]) ??
      requirement.defaultField;
    const aliases = Array.from(
      new Set([configuredField, requirement.defaultField, ...requirement.aliases]),
    );
    if (workflowMappedInputFieldIsPresent(logic, aliases)) return [];
    return [
      {
        nodeId: node.id,
        code: requirement.code,
        message:
          `Runtime coding-tool budget recovery template node '${node.name}' needs a ` +
          `${requirement.label} input mapping or fixed value before execution.`,
        configSection: "mapping",
        fieldPath: requirement.fieldPath,
        repairActionId: "bind-coding-tool-budget-recovery-evidence",
        repairLabel: "Bind recovery input",
      },
    ];
  });
}

function workflowRuntimeTelemetrySourceBindingIssues(
  node: Node,
): WorkflowValidationIssue[] {
  const logic = node.config?.logic ?? {};
  if (node.type === "runtime_usage_meter") {
    const scope = workflowStringValue(logic.runtimeUsageMeterScope) ?? "thread";
    if (scope === "workflow") return [];
    return workflowTelemetrySourceFixedOrMapped(
      logic,
      scope === "run" ? logic.runtimeUsageMeterRunId : logic.runtimeUsageMeterThreadId,
      scope === "run"
        ? logic.runtimeUsageMeterRunIdField ?? "runId"
        : logic.runtimeUsageMeterThreadIdField ?? "threadId",
      scope === "run" ? ["runId", "run_id"] : ["threadId", "thread_id"],
    )
      ? []
      : [
          workflowTelemetrySourceBindingIssue(
            node,
            "missing_runtime_telemetry_source_thread_binding",
            scope === "run" ? "runtimeUsageMeterRunIdField" : "runtimeUsageMeterThreadIdField",
            "Runtime usage meter nodes need selected telemetry evidence for their run/thread input before activation.",
          ),
        ];
  }
  if (node.type === "runtime_context_budget") {
    const scope = workflowStringValue(logic.runtimeContextBudgetScope) ?? "thread";
    const issues: WorkflowValidationIssue[] = [];
    if (
      scope !== "workflow" &&
      !workflowTelemetrySourceFixedOrMapped(
        logic,
        scope === "run"
          ? logic.runtimeContextBudgetRunId
          : logic.runtimeContextBudgetThreadId,
        scope === "run"
          ? logic.runtimeContextBudgetRunIdField ?? "runId"
          : logic.runtimeContextBudgetThreadIdField ?? "threadId",
        scope === "run" ? ["runId", "run_id"] : ["threadId", "thread_id"],
      )
    ) {
      issues.push(
        workflowTelemetrySourceBindingIssue(
          node,
          "missing_runtime_telemetry_source_thread_binding",
          scope === "run"
            ? "runtimeContextBudgetRunIdField"
            : "runtimeContextBudgetThreadIdField",
          "Runtime context budget nodes need selected telemetry evidence for their run/thread input before activation.",
        ),
      );
    }
    if (
      !workflowTelemetrySourceFixedOrMapped(
        logic,
        logic.runtimeContextBudget ?? logic.runtimeTelemetrySummary,
        logic.runtimeContextBudgetUsageField ?? "runtimeUsageMeter",
        ["runtimeUsageMeter", "runtimeTelemetrySummary", "usageTelemetry", "usage_telemetry"],
      )
    ) {
      issues.push(
        workflowTelemetrySourceBindingIssue(
          node,
          "missing_runtime_telemetry_source_usage_binding",
          "runtimeContextBudgetUsageField",
          "Runtime context budget nodes need selected usage/context telemetry evidence before activation.",
        ),
      );
    }
    return issues;
  }
  if (node.type === "runtime_compaction_policy") {
    const issues: WorkflowValidationIssue[] = [];
    if (
      !workflowTelemetrySourceFixedOrMapped(
        logic,
        logic.runtimeCompactionPolicyThreadId,
        logic.runtimeCompactionPolicyThreadIdField ?? "threadId",
        ["threadId", "thread_id"],
      )
    ) {
      issues.push(
        workflowTelemetrySourceBindingIssue(
          node,
          "missing_runtime_telemetry_source_thread_binding",
          "runtimeCompactionPolicyThreadIdField",
          "Runtime compaction policy nodes need selected telemetry evidence for their thread input before activation.",
        ),
      );
    }
    if (
      !workflowTelemetrySourceFixedOrMapped(
        logic,
        logic.runtimeCompactionPolicyContextBudget ??
          logic.runtimeTelemetrySummary,
        logic.runtimeCompactionPolicyContextBudgetField ?? "runtimeContextBudget",
        ["runtimeContextBudget", "runtimeTelemetrySummary", "contextBudget", "context_budget"],
      )
    ) {
      issues.push(
        workflowTelemetrySourceBindingIssue(
          node,
          "missing_runtime_telemetry_source_context_budget_binding",
          "runtimeCompactionPolicyContextBudgetField",
          "Runtime compaction policy nodes need selected context-budget telemetry evidence before activation.",
        ),
      );
    }
    return issues;
  }
  if (node.type === "plugin_tool" && workflowNodeUsesCodingToolBudgetGate(node)) {
    const budgetUsageField =
      workflowStringValue(logic.toolBinding?.toolPack?.budgetUsageField) ??
      "runtimeTelemetrySummary";
    const hasBudgetUsage =
      workflowRuntimeTelemetryValueIsPresent(logic.runtimeTelemetrySummary) ||
      workflowRuntimeTelemetryValueIsPresent(
        logic.toolBinding?.toolPack?.budgetUsageTelemetry,
      ) ||
      workflowRuntimeTelemetryValueIsPresent(
        workflowValueAtPath(logic.testInput, budgetUsageField),
      ) ||
      workflowMappedInputFieldIsPresent(logic, [
        budgetUsageField,
        "runtimeTelemetrySummary",
        "budgetUsageTelemetry",
      ]);
    return hasBudgetUsage
      ? []
      : [
          workflowTelemetrySourceBindingIssue(
            node,
            "missing_runtime_telemetry_source_budget_usage_binding",
            "toolBinding.toolPack.budgetUsageField",
            "Coding-tool budget gates in warn/block mode need selected telemetry evidence before activation.",
          ),
        ];
  }
  return [];
}

function workflowTelemetrySourceFixedOrMapped(
  logic: NodeLogic,
  fixedValue: unknown,
  configuredField: string,
  aliases: string[],
): boolean {
  if (workflowRuntimeTelemetryValueIsPresent(fixedValue)) return true;
  return workflowMappedInputFieldIsPresent(logic, [
    configuredField,
    ...aliases,
  ]);
}

function workflowTelemetrySourceBindingIssue(
  node: Node,
  code: string,
  fieldPath: string,
  message: string,
): WorkflowValidationIssue {
  return {
    nodeId: node.id,
    code,
    message,
    configSection: "mapping",
    fieldPath,
    repairActionId: "bind-runtime-telemetry-source",
    repairLabel: "Bind telemetry source",
  };
}

function workflowNodeUsesCodingToolBudgetGate(node: Node): boolean {
  const binding = node.config?.logic?.toolBinding;
  const toolPack = binding?.toolPack;
  const mode = workflowStringValue(toolPack?.budgetMode) ?? "simulate";
  return (
    (binding?.bindingKind === "coding_tool_pack" || toolPack?.pack === "coding") &&
    (mode === "warn" || mode === "block")
  );
}

function workflowRuntimeTelemetryValueIsPresent(value: unknown): boolean {
  if (workflowStringIsPresent(value)) return true;
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object");
}

function workflowCriticalAiNodeIds(workflow: WorkflowProject): string[] {
  return workflow.nodes
    .filter((node) => node.type === "model_call")
    .map((node) => node.id);
}

export function validateWorkflowProject(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
): WorkflowValidationResult {
  const nodeIds = new Set(workflow.nodes.map((nodeItem) => nodeItem.id));
  const nodeTypesById = new Map(workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem.type]));
  const errors: WorkflowValidationResult["errors"] = [];
  const warnings: WorkflowValidationResult["warnings"] = [];
  const missingConfig: WorkflowValidationResult["missingConfig"] = [];
  const connectorBindingIssues: WorkflowValidationResult["connectorBindingIssues"] = [];
  const executionReadinessIssues: WorkflowValidationResult["executionReadinessIssues"] = [];
  const verificationIssues: WorkflowValidationResult["verificationIssues"] = [];
  const schedulerLaneReadiness = workflowSchedulerLaneReadiness();
  const unsupportedRuntimeNodes: string[] = [];
  const policyRequiredNodes: string[] = [];
  const coverageByNodeId: Record<string, string[]> = {};
  const hasIncomingHumanGate = (nodeId: string) =>
    workflow.edges.some((edge) => {
      if (edge.to !== nodeId) return false;
      return nodeTypesById.get(edge.from) === "human_gate";
    });

  if (workflowIsHarness(workflow)) {
    const harness = workflow.metadata.harness;
    if (harness?.aiMutationMode !== "proposal_only") {
      executionReadinessIssues.push({
        code: "harness_self_mutation_not_proposal_only",
        message: "Harness workflow edits authored by AI must remain proposal-only.",
      });
    }
    if (!workflow.metadata.workerHarnessBinding) {
      missingConfig.push({
        code: "harness_worker_binding_missing",
        message: "Harness workflows need worker harness identity fields before workers can bind to them.",
      });
    }
    workflow.nodes.forEach((nodeItem) => {
      const component = harnessComponentForNode(nodeItem);
      if (!component || !nodeItem.runtimeBinding) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "harness_component_contract_missing",
          message: `Harness node '${nodeItem.name}' needs a durable component contract and runtime binding.`,
        });
        return;
      }
      if (
        nodeItem.runtimeBinding.componentId !== component.componentId ||
        nodeItem.runtimeBinding.componentVersion !== component.version ||
        nodeItem.runtimeBinding.componentKind !== component.kind
      ) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "harness_component_contract_missing",
          message: `Harness node '${nodeItem.name}' runtime binding must match its component contract.`,
        });
      }
      if (!component.inputSchema || !component.outputSchema || !component.errorSchema) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "harness_component_contract_missing",
          message: `Harness component '${component.componentId}' needs input, output, and error schemas.`,
        });
      }
    });
  }
  executionReadinessIssues.push(
    ...workflowSchedulerLaneReadinessIssues(schedulerLaneReadiness),
  );

  tests.forEach((test) => {
    test.targetNodeIds.forEach((nodeId) => {
      coverageByNodeId[nodeId] = [...(coverageByNodeId[nodeId] ?? []), test.id];
      if (!nodeIds.has(nodeId)) {
        errors.push({
          nodeId,
          code: "missing_test_target",
          message: `Test '${test.name}' targets a missing node.`,
        });
      }
    });
  });

  workflow.edges.forEach((edge) => {
    const sourceType = nodeTypesById.get(edge.from);
    const targetType = nodeTypesById.get(edge.to);
    if (!sourceType || !targetType) {
      errors.push({
        code: "missing_edge_endpoint",
        message: `Edge '${edge.id}' references a missing node.`,
      });
      return;
    }
    const sourceNode = workflow.nodes.find((item) => item.id === edge.from);
    const targetNode = workflow.nodes.find((item) => item.id === edge.to);
    const sourcePort = sourceNode?.ports?.find(
      (port) => port.direction === "output" && port.id === (edge.fromPort || "output"),
    );
    const targetPort = targetNode?.ports?.find(
      (port) => port.direction === "input" && port.id === (edge.toPort || "input"),
    );
    const edgeIssue = validateActionEdge(
      edge.from,
      actionKindForWorkflowNodeType(sourceType),
      edge.to,
      actionKindForWorkflowNodeType(targetType),
      sourcePort ?? null,
      targetPort ?? null,
    );
    if (edgeIssue) {
      errors.push({
        nodeId: edgeIssue.actionId,
        code: edgeIssue.code,
        message: edgeIssue.message,
      });
    }
  });

  workflow.nodes.forEach((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    const law = nodeItem.config?.law ?? {};
    executionReadinessIssues.push(...validateWorkflowExpressionReferences(workflow, nodeItem));
    if (nodeItem.type === "model_call") {
      const hasIncomingConnectionClass = (connectionClass: WorkflowConnectionClass) =>
        workflow.edges.some((edge) => {
          if (edge.to !== nodeItem.id) return false;
          const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
          return edgeClass === connectionClass || edge.toPort === connectionClass;
        });
      if (!logic.modelRef && !hasIncomingConnectionClass("model")) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_model_binding",
          message: "Model nodes need an inline model ref or attached Model Binding before runtime execution.",
        });
      }
      const modelRef = String(logic.modelRef ?? logic.modelBinding?.modelRef ?? "").trim();
      const modelBinding = logic.modelBinding ?? (modelRef ? workflow.global_config.modelBindings?.[modelRef] : undefined);
      executionReadinessIssues.push(...liveModelBindingContractMetadataIssues(nodeItem.id, modelBinding));
      const toolUseMode = logic.modelBinding?.toolUseMode ?? logic.toolUseMode ?? "none";
      if ((toolUseMode === "explicit" || toolUseMode === "auto") && !hasIncomingConnectionClass("tool")) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "missing_model_tool_attachment",
          message: "Model tool-use mode needs an attached tool port before runtime execution.",
        });
      }
      if (logic.parserRef && !hasIncomingConnectionClass("parser")) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "missing_model_parser_attachment",
          message: "Model parser references need an attached parser port.",
        });
      }
      if (logic.memoryKey && !hasIncomingConnectionClass("memory")) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "missing_model_memory_attachment",
          message: "Model memory keys need an attached memory port.",
        });
      }
      if (
        (logic.validateStructuredOutput || logic.jsonMode) &&
        !logic.outputSchema &&
        !logic.modelBinding?.resultSchema
      ) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_model_output_schema",
          message: "Structured model output validation needs a result schema.",
        });
      }
    }
    if (nodeItem.type === "model_binding") {
      const modelBinding = logic.modelBinding;
      if (!logic.modelRef && !modelBinding?.modelRef) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_model_binding",
          message: "Model Binding nodes need a model ref before they can attach to model calls.",
        });
      }
      if (!workflowSchemaIsObjectLike(modelBinding?.resultSchema ?? logic.outputSchema)) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_model_binding_result_schema",
          message: "Model Binding nodes need a result schema so downstream model outputs can be verified.",
        });
      }
      executionReadinessIssues.push(...liveModelBindingContractMetadataIssues(nodeItem.id, modelBinding));
    }
    if (nodeItem.type === "parser") {
      const parserBinding = logic.parserBinding;
      if (!logic.parserRef && !parserBinding?.parserRef) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_parser_binding",
          message: "Output Parser nodes need a parser binding before model attachment.",
        });
      }
      if (!workflowSchemaIsObjectLike(parserBinding?.resultSchema ?? logic.outputSchema)) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_parser_result_schema",
          message: "Output Parser nodes need a result schema for typed model output validation.",
        });
      }
    }
    if (nodeItem.type === "function") {
      const functionBinding = logic.functionBinding;
      const code = functionBinding?.code ?? logic.code;
      const language = String(
        functionBinding?.language ?? logic.language ?? "javascript",
      ).toLowerCase();
      if (!code) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_function_binding",
          message: "Function nodes need sandboxed code before runtime execution.",
        });
      }
      if (!functionBinding?.outputSchema && !logic.outputSchema) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_output_schema",
          message: "Function nodes need an output schema for typed verification.",
        });
      }
      if (!["javascript", "typescript"].includes(language)) {
        unsupportedRuntimeNodes.push(nodeItem.id);
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "unsupported_function_runtime",
          message: `Function runtime '${language}' is not supported in the local sandbox.`,
        });
      }
      const permissions = functionBinding?.sandboxPolicy?.permissions ?? law.sandboxPolicy?.permissions ?? [];
      if (!permissions.includes("filesystem") && /\b(require\(|import |fs\.|node:fs)\b/.test(String(code ?? ""))) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "unsafe_function_permission",
          message: "Function uses filesystem/module access without sandbox permission.",
        });
      }
    }
    if (nodeItem.type === "adapter" && !logic.connectorBinding?.connectorRef) {
      connectorBindingIssues.push({
        nodeId: nodeItem.id,
        code: "missing_connector_binding",
        message: "Adapter nodes need a typed connector binding.",
      });
    }
    if (
      nodeItem.type === "adapter" &&
      logic.connectorBinding?.mockBinding === false &&
      logic.connectorBinding?.credentialReady !== true
    ) {
      connectorBindingIssues.push({
        nodeId: nodeItem.id,
        code: "missing_live_connector_credential",
        message: "Live connector bindings need credentials marked ready before execution.",
      });
    }
    if (nodeItem.type === "adapter") {
      executionReadinessIssues.push(
        ...liveBindingContractMetadataIssues(
          nodeItem.id,
          "connector",
          logic.connectorBinding,
        ),
      );
    }
    if (nodeItem.type === "plugin_tool" && !logic.toolBinding?.toolRef) {
      connectorBindingIssues.push({
        nodeId: nodeItem.id,
        code: "missing_tool_binding",
        message: "Plugin tool nodes need a typed tool binding.",
      });
    }
    if (
      nodeItem.type === "plugin_tool" &&
      logic.toolBinding?.bindingKind !== "workflow_tool" &&
      logic.toolBinding?.mockBinding === false &&
      logic.toolBinding?.credentialReady !== true
    ) {
      connectorBindingIssues.push({
        nodeId: nodeItem.id,
        code: "missing_live_tool_credential",
        message: "Live plugin or MCP tool bindings need credentials marked ready before execution.",
      });
    }
    if (
      nodeItem.type === "plugin_tool" &&
      logic.toolBinding?.bindingKind !== "workflow_tool"
    ) {
      executionReadinessIssues.push(
        ...liveBindingContractMetadataIssues(
          nodeItem.id,
          "tool",
          logic.toolBinding,
        ),
      );
    }
    if (
      nodeItem.type === "plugin_tool" &&
      logic.toolBinding?.bindingKind === "workflow_tool"
    ) {
      const workflowTool = logic.toolBinding.workflowTool;
      if (!workflowTool?.workflowPath) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_workflow_tool_ref",
          message: "Workflow tool bindings need a child workflow path.",
        });
      }
      if (!workflowSchemaIsObjectLike(workflowTool?.argumentSchema)) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_workflow_tool_argument_schema",
          message: "Workflow tool bindings need an argument schema before agent/tool execution.",
        });
      }
      if (!workflowSchemaIsObjectLike(workflowTool?.resultSchema)) {
        verificationIssues.push({
          nodeId: nodeItem.id,
          code: "missing_workflow_tool_result_schema",
          message: "Workflow tool bindings need a result schema before agent/tool execution.",
        });
      }
      const timeoutMs = Number(workflowTool?.timeoutMs ?? 0);
      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "invalid_workflow_tool_timeout",
          message: "Workflow tool timeout must be greater than zero milliseconds.",
        });
      }
      const maxAttempts = Number(workflowTool?.maxAttempts ?? 0);
      if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 5) {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "invalid_workflow_tool_attempts",
          message: "Workflow tool retry attempts must be between 1 and 5.",
        });
      }
    }
    if (nodeItem.type === "trigger") {
      const triggerKind = logic.triggerKind ?? "manual";
      if (triggerKind === "scheduled" && !logic.cronSchedule) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_trigger_schedule",
          message: "Scheduled triggers need a schedule before runtime execution.",
        });
      }
      if (triggerKind === "event" && !logic.eventSourceRef) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_trigger_event_source",
          message: "Event triggers need an event source binding before runtime execution.",
        });
      }
    }
    if (nodeItem.type === "state" && !logic.stateKey) {
      missingConfig.push({
        nodeId: nodeItem.id,
        code: "missing_state_key",
        message: "State nodes need a state key.",
      });
    }
    if (nodeItem.type === "subgraph" && !logic.subgraphRef?.workflowPath) {
      executionReadinessIssues.push({
        nodeId: nodeItem.id,
        code: "missing_subgraph_ref",
        message: "Subgraph nodes need a workflow reference before runtime execution.",
      });
    }
    if (nodeItem.type === "proposal") {
      const boundedTargets = logic.proposalAction?.boundedTargets ?? [];
      if (workflowIsHarness(workflow) && logic.proposalAction?.actionKind === "apply") {
        executionReadinessIssues.push({
          nodeId: nodeItem.id,
          code: "harness_self_mutation_not_proposal_only",
          message: "Harness self-mutation nodes may preview or create proposals but cannot directly apply them.",
        });
      }
      if (boundedTargets.length === 0) {
        missingConfig.push({
          nodeId: nodeItem.id,
          code: "missing_proposal_bounds",
          message: "Proposal nodes need bounded targets before they can create changes.",
        });
      }
      if (!law.requireHumanGate && !hasIncomingHumanGate(nodeItem.id)) {
        policyRequiredNodes.push(nodeItem.id);
        warnings.push({
          nodeId: nodeItem.id,
          code: "proposal_approval_required",
          message: "Proposal mutations require explicit approval before apply.",
        });
      }
    }
    if (nodeItem.type === "output") {
      const materialization = logic.materialization;
      const deliveryTarget = logic.deliveryTarget;
      const writesAsset = Boolean(materialization?.enabled);
      const privilegedTarget = ["local_file", "repo_patch", "connector_write", "deploy"].includes(
        String(deliveryTarget?.targetKind ?? "none"),
      );
      if ((writesAsset || privilegedTarget) && !law.requireHumanGate && !hasIncomingHumanGate(nodeItem.id)) {
        policyRequiredNodes.push(nodeItem.id);
        warnings.push({
          nodeId: nodeItem.id,
          code: "output_policy_required",
          message: "Materialized or externally delivered outputs need an approval boundary.",
        });
      }
    }
    const typedBinding = logic.connectorBinding ?? logic.toolBinding;
    if (typedBinding?.requiresApproval && !law.requireHumanGate && !hasIncomingHumanGate(nodeItem.id)) {
      policyRequiredNodes.push(nodeItem.id);
    }
    const logicPrivilegedActions = (logic as { privilegedActions?: unknown }).privilegedActions;
    const privilegedActions = Array.isArray(law.privilegedActions)
      ? law.privilegedActions
      : Array.isArray(logicPrivilegedActions)
        ? logicPrivilegedActions
        : [];
    if (privilegedActions.length > 0 && !law.requireHumanGate && !hasIncomingHumanGate(nodeItem.id)) {
      policyRequiredNodes.push(nodeItem.id);
      warnings.push({
        nodeId: nodeItem.id,
        code: "policy_required",
        message: "Privileged actions need an approval or policy gate.",
      });
    }
  });

  const blockedNodes = Array.from(new Set([
    ...unsupportedRuntimeNodes,
    ...policyRequiredNodes,
    ...missingConfig.map((issue) => issue.nodeId).filter(Boolean) as string[],
    ...connectorBindingIssues.map((issue) => issue.nodeId).filter(Boolean) as string[],
    ...(executionReadinessIssues ?? []).map((issue) => issue.nodeId).filter(Boolean) as string[],
    ...(verificationIssues ?? []).map((issue) => issue.nodeId).filter(Boolean) as string[],
  ]));
  const allWarnings = [
    ...warnings,
    ...missingConfig,
    ...connectorBindingIssues,
    ...(executionReadinessIssues ?? []),
    ...(verificationIssues ?? []),
  ];
  const status = errors.length > 0 ? "failed" : blockedNodes.length > 0 ? "blocked" : "passed";
  return {
    status,
    errors: withWorkflowIssueListRepairMetadata(errors),
    warnings: withWorkflowIssueListRepairMetadata(allWarnings),
    blockedNodes,
    missingConfig: withWorkflowIssueListRepairMetadata(missingConfig),
    unsupportedRuntimeNodes,
    policyRequiredNodes,
    coverageByNodeId,
    connectorBindingIssues: withWorkflowIssueListRepairMetadata(connectorBindingIssues),
    executionReadinessIssues: withWorkflowIssueListRepairMetadata(executionReadinessIssues),
    verificationIssues: withWorkflowIssueListRepairMetadata(verificationIssues),
    schedulerLaneReadiness,
  };
}

export function evaluateWorkflowActivationReadiness(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  baseResult: WorkflowValidationResult = validateWorkflowProject(workflow, tests),
  proposals: WorkflowProposal[] = [],
  fixtures: WorkflowNodeFixture[] | null = [],
  runtimeThreadEvents: readonly WorkflowRuntimeThreadEventLike[] | null = null,
): WorkflowValidationResult {
  const next: WorkflowValidationResult = {
    ...baseResult,
    errors: [...baseResult.errors],
    warnings: [...baseResult.warnings],
    blockedNodes: [...baseResult.blockedNodes],
    missingConfig: [...baseResult.missingConfig],
    unsupportedRuntimeNodes: [...baseResult.unsupportedRuntimeNodes],
    policyRequiredNodes: [...baseResult.policyRequiredNodes],
    coverageByNodeId: { ...baseResult.coverageByNodeId },
    connectorBindingIssues: [...baseResult.connectorBindingIssues],
    executionReadinessIssues: [...(baseResult.executionReadinessIssues ?? [])],
    verificationIssues: [...(baseResult.verificationIssues ?? [])],
    schedulerLaneReadiness:
      baseResult.schedulerLaneReadiness ?? workflowSchedulerLaneReadiness(),
  };
  const addReadinessIssue = (issue: WorkflowValidationIssue) => {
    const exists = next.executionReadinessIssues?.some(
      (current) =>
        current.code === issue.code &&
        current.nodeId === issue.nodeId &&
        current.message === issue.message,
    );
    if (exists) return;
    next.executionReadinessIssues = [...(next.executionReadinessIssues ?? []), issue];
    next.warnings.push(issue);
    if (issue.nodeId) next.blockedNodes.push(issue.nodeId);
  };
  const addAdvisoryWarning = (issue: WorkflowValidationIssue) => {
    const exists = next.warnings.some(
      (current) =>
        current.code === issue.code &&
        current.nodeId === issue.nodeId &&
        current.message === issue.message,
    );
    if (!exists) next.warnings.push(issue);
  };
  const hasIncomingConnectionClass = (nodeId: string, connectionClass: WorkflowConnectionClass) =>
    workflow.edges.some((edge) => {
      if (edge.to !== nodeId) return false;
      const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
      return edgeClass === connectionClass || edge.toPort === connectionClass;
    });
  const hasStart = workflow.nodes.some((node) => node.type === "trigger" || node.type === "source");
  const hasOutput = workflow.nodes.some((node) => node.type === "output");
  if (!hasStart) {
    addReadinessIssue({
      code: "missing_start_node",
      message: "Activation needs a trigger or source/input node.",
    });
  }
  if (!hasOutput) {
    addReadinessIssue({
      code: "missing_output_node",
      message: "Activation needs at least one output node.",
    });
  }
  if (tests.length === 0) {
    addReadinessIssue({
      code: "missing_unit_tests",
      message: "Activation needs at least one workflow unit test.",
    });
  }
  const production = workflow.global_config.production ?? {};
  const environmentProfile = workflow.global_config.environmentProfile ?? {
    target: "local",
    mockBindingPolicy: "block",
  };
  const liveReadinessRequired =
    environmentProfile.target === "staging" || environmentProfile.target === "production";
  const mockBindingsBlockActivation =
    environmentProfile.target === "production" || environmentProfile.mockBindingPolicy === "block";
  const operationalSideEffectNodes = workflow.nodes.filter(workflowNodeNeedsOperationalErrorPath);
  if (operationalSideEffectNodes.length > 0 && !workflowHasErrorOrRetryPath(workflow)) {
    addReadinessIssue({
      nodeId: operationalSideEffectNodes[0].id,
      code: "missing_error_handling_path",
      message: "Operational side effects need an error or retry path before activation.",
    });
  }
  const coveredNodeIds = new Set(tests.flatMap((test) => test.targetNodeIds));
  const uncoveredAiNodeIds = workflowCriticalAiNodeIds(workflow).filter((nodeId) => !coveredNodeIds.has(nodeId));
  if (uncoveredAiNodeIds.length > 0 && !production.evaluationSetPath?.trim()) {
    addReadinessIssue({
      nodeId: uncoveredAiNodeIds[0],
      code: "missing_ai_evaluation_coverage",
      message: "Model-driven workflow nodes need unit-test coverage or an evaluation set before activation.",
    });
  }
  const mcpNode = workflow.nodes.find(workflowNodeIsMcpTool);
  if (mcpNode && production.mcpAccessReviewed !== true) {
    addReadinessIssue({
      nodeId: mcpNode.id,
      code: "mcp_access_not_reviewed",
      message: "MCP tool workflows need access review before activation.",
    });
  }
  if (liveReadinessRequired) {
    workflow.nodes
      .filter((node) => {
        const triggerKind = String(node.config?.logic?.triggerKind ?? "manual");
        return node.type === "trigger" && (triggerKind === "scheduled" || triggerKind === "event");
      })
      .filter((node) => node.config?.logic?.runtimeReady !== true)
      .forEach((node) => {
        addReadinessIssue({
          nodeId: node.id,
          code: "unsupported_live_trigger",
          message:
            "Scheduled and event triggers need a configured live trigger runtime before staging or production activation.",
        });
      });
  }
  if (!Number.isFinite(production.expectedTimeSavedMinutes) || Number(production.expectedTimeSavedMinutes ?? 0) <= 0) {
    addAdvisoryWarning({
      code: "operational_value_not_estimated",
      message: "Add an expected time-saved estimate so the workflow has an operator-facing value baseline.",
    });
  }
  if (workflowIsBlessedHarness(workflow)) {
    addAdvisoryWarning({
      code: "harness_read_only_template",
      message: "The Default Agent Harness is a read-only blessed template. Fork it before attempting activation changes.",
    });
  }
  if (workflowIsHarnessFork(workflow)) {
    const harness = workflow.metadata.harness;
    if (!harness?.forkedFrom) {
      addReadinessIssue({
        code: "harness_fork_lineage_missing",
        message: "Harness forks need lineage metadata before they can be packaged or activated.",
      });
    }
    if (!workflow.metadata.workerHarnessBinding?.harnessWorkflowId) {
      addReadinessIssue({
        code: "harness_worker_binding_missing",
        message: "Harness forks need worker binding fields for harness workflow id, activation id, and hash.",
      });
    }
    const boundSlotIds = new Set(
      workflow.nodes.flatMap((node) => node.runtimeBinding?.slotIds ?? []),
    );
    harnessSlotsForWorkflow(workflow)
      .filter((slot) => slot.required && !boundSlotIds.has(slot.slotId))
      .forEach((slot) => {
        addReadinessIssue({
          code: "harness_required_slot_unbound",
          message: `${slot.label} must be bound before this harness fork can activate. ${slot.validation.reason}`,
        });
      });
    workflowHarnessPromotionClusterReplayGateBlockers(harness).forEach((cluster) => {
      const proof = cluster.replayGateProof;
      addReadinessIssue({
        code: "harness_promotion_cluster_replay_gate_not_passed",
        message:
          proof?.gateStatus === "blocked" || proof?.gateStatus === "failed"
            ? `${cluster.label} replay gate is ${proof.gateStatus}; resolve blocking divergence before gated or live promotion.`
            : `${cluster.label} needs a passing replay gate before gated or live promotion.`,
      });
    });
    const packageEvidenceReview = workflowHarnessPackageEvidenceReview(workflow);
    if (!packageEvidenceReview.ready) {
      addReadinessIssue({
        code: "harness_package_manifest_incomplete",
        message: `Imported or validated harness forks need a portable package evidence manifest with receipts, replay fixtures, rollback restore refs, worker handoff refs, and deep links. Missing: ${packageEvidenceReview.blockers.join(", ")}.`,
      });
    }
    if (harness?.aiMutationMode !== "proposal_only") {
      addReadinessIssue({
        code: "harness_self_mutation_not_proposal_only",
        message: "Harness forks can only accept AI-authored edits as proposals until a user applies them.",
      });
    }
    const activationRecord = harness?.activationRecord;
    const forkMutationCanary =
      activationRecord?.forkMutationCanary ??
      harness?.forkMutationCanary ??
      harness?.packageManifest?.forkMutationCanary ??
      null;
    if (!workflowHarnessForkMutationCanaryReady(forkMutationCanary)) {
      addReadinessIssue({
        code: "harness_fork_mutation_canary_not_passed",
        message:
          "Harness forks need a passing proposal-bound mutation canary with receipt, replay, node-attempt, and rollback refs before activation can mint.",
      });
    }
    const activationRecordValidated =
      activationRecord?.activationState === "validated" &&
      activationRecord.activationId === harness?.activationId &&
      activationRecord.canaryStatus === "passed" &&
      workflowHarnessForkMutationCanaryReady(
        activationRecord.forkMutationCanary,
      ) &&
      activationRecord.rollbackAvailable === true &&
      activationRecord.liveAuthorityTransferred === false &&
      activationRecord.workerBinding?.harnessActivationId === harness?.activationId;
    if (!harness?.activationId || harness.activationState !== "validated" || !activationRecordValidated) {
      addReadinessIssue({
        code: "harness_activation_not_validated",
        message:
          "Harness forks remain inactive until validation creates a reviewed activation id, passing canary, rollback target, and matching worker binding.",
      });
    }
  }
  if (fixtures !== null) {
    const replayFixturesBlockActivation =
      liveReadinessRequired || production.requireReplayFixtures === true;
    workflow.nodes
      .filter(workflowNodeNeedsReplayFixture)
      .filter((node) => !workflowHasUsableReplayFixture(node.id, fixtures))
      .forEach((node) => {
        const issue = {
          nodeId: node.id,
          code: "missing_replay_fixture",
          message: `Capture a sample for '${node.name}' so tests and downstream nodes can replay it without re-running external or expensive work.`,
        };
        if (replayFixturesBlockActivation) addReadinessIssue(issue);
        else addAdvisoryWarning(issue);
      });
  }
  const workspaceTrustGateIssues =
    runtimeThreadEvents === null
      ? workflowWorkspaceTrustGateIssues(workflow, []).filter(
          (issue) => issue.code === "missing_workspace_trust_gate",
        )
      : workflowWorkspaceTrustGateIssues(workflow, runtimeThreadEvents);
  workspaceTrustGateIssues.forEach(addReadinessIssue);
  if (
    workflow.metadata.workflowKind === "scheduled_workflow" &&
    !workflow.nodes.some((node) => node.type === "trigger" && node.config?.logic?.triggerKind === "scheduled")
  ) {
    addReadinessIssue({
      code: "missing_scheduled_trigger",
      message: "Scheduled workflows need a scheduled trigger before activation.",
    });
  }
  if (
    workflow.metadata.workflowKind === "event_workflow" &&
    !workflow.nodes.some((node) => node.type === "trigger" && node.config?.logic?.triggerKind === "event")
  ) {
    addReadinessIssue({
      code: "missing_event_trigger",
      message: "Event workflows need an event trigger before activation.",
    });
  }
  workflow.nodes.forEach((node) => {
    const logic = node.config?.logic ?? {};
    if (node.type === "model_call") {
      const modelRef = String(logic.modelRef ?? "");
      const binding = modelRef ? workflow.global_config.modelBindings?.[modelRef] : null;
      if (!binding?.modelId && !hasIncomingConnectionClass(node.id, "model")) {
        const issue = {
          nodeId: node.id,
          code: "unbound_model_ref",
          message: `Model node '${node.name}' needs a concrete model binding before activation.`,
        };
        const hasMissing = next.missingConfig.some(
          (current) => current.code === issue.code && current.nodeId === issue.nodeId,
        );
        if (!hasMissing) next.missingConfig.push(issue);
        addReadinessIssue(issue);
      }
    }
    const binding = logic.toolBinding ?? logic.connectorBinding ?? logic.modelBinding ?? logic.parserBinding;
    if (binding?.mockBinding === true) {
      const issue = {
        nodeId: node.id,
        code: "mock_binding_active",
        message: mockBindingsBlockActivation
          ? `'${node.name}' is using an explicit mock binding. Switch to live credentials before activation.`
          : `'${node.name}' is using an explicit mock binding in ${environmentProfile.target ?? "local"} mode.`,
      };
      if (mockBindingsBlockActivation) {
        addReadinessIssue(issue);
      } else {
        addAdvisoryWarning(issue);
      }
    }
    workflowRuntimeCodingToolBudgetRecoveryBindingIssues(node).forEach(
      addReadinessIssue,
    );
    workflowRuntimeTelemetrySourceBindingIssues(node).forEach(addReadinessIssue);
    if (workflowNodeIsHookPolicy(node)) {
      const plan = workflowHookDryRunPlanForNode(node);
      if (logic.hookDryRunOnly !== true) {
        addReadinessIssue({
          nodeId: node.id,
          code: "hook_policy_not_preview_only",
          message:
            "Hook Policy nodes must remain preview-only until governed hook execution is implemented.",
        });
      }
      if (workflowHookCommandExecutionEnabled(node, plan)) {
        addReadinessIssue({
          nodeId: node.id,
          code: "hook_policy_execution_enabled",
          message:
            "Hook Policy nodes cannot enable hook or command execution during activation.",
        });
      }
      if (!workflowHookPolicyRoutesConfigured(node)) {
        addReadinessIssue({
          nodeId: node.id,
          code: "hook_policy_routes_missing",
          message:
            "Hook Policy nodes need explicit passed-preview and blocked routes before activation.",
        });
      }
      if (!plan) {
        addReadinessIssue({
          nodeId: node.id,
          code: "hook_policy_dry_run_plan_missing",
          message:
            "Hook Policy nodes must consume a hook dry-run plan before activation can continue.",
        });
      } else {
        const policyStatus = workflowHookPolicyStatusForNode(node, plan);
        const blockedCount = workflowHookDryRunBlockedCount(plan);
        if (!policyStatus) {
          addReadinessIssue({
            nodeId: node.id,
            code: "hook_policy_decision_missing",
            message:
              "Hook Policy nodes need a hook dry-run policy decision status before activation.",
          });
        }
        if (policyStatus === "blocked" || blockedCount > 0) {
          addReadinessIssue({
            nodeId: node.id,
            code: "hook_policy_dry_run_blocked",
            message:
              blockedCount > 0
                ? `Hook dry-run policy blocks activation for ${blockedCount} hook(s).`
                : "Hook dry-run policy blocks activation.",
          });
        }
      }
    }
  });
  proposals
    .filter((proposal) => proposal.status === "open")
    .forEach((proposal) => {
      addReadinessIssue({
        code: "open_proposal",
        message: `Open proposal '${proposal.title}' must be applied or closed before activation.`,
      });
    });
  next.blockedNodes = Array.from(new Set(next.blockedNodes)).sort();
  next.status =
    next.errors.length > 0
      ? "failed"
      : next.blockedNodes.length > 0 || (next.executionReadinessIssues?.length ?? 0) > 0
        ? "blocked"
        : "passed";
  return {
    ...next,
    errors: withWorkflowIssueListRepairMetadata(next.errors),
    warnings: withWorkflowIssueListRepairMetadata(next.warnings),
    missingConfig: withWorkflowIssueListRepairMetadata(next.missingConfig),
    connectorBindingIssues: withWorkflowIssueListRepairMetadata(next.connectorBindingIssues),
    executionReadinessIssues: withWorkflowIssueListRepairMetadata(next.executionReadinessIssues),
    verificationIssues: withWorkflowIssueListRepairMetadata(next.verificationIssues),
  };
}

function workflowValidationIssueKey(issue: WorkflowValidationIssue): string {
  return `${issue.code}:${issue.nodeId ?? ""}:${issue.message}`;
}

function workflowHarnessRollbackRestoreCanaryFor(
  workflow: WorkflowProject,
  rollbackRevisionBinding: WorkflowRevisionBinding | null | undefined,
  restoreResult: WorkflowRevisionRestoreResult | null | undefined,
  restoreBlockers: string[],
  createdAtMs: number,
): WorkflowHarnessRollbackRestoreCanary {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const fallbackBinding =
    rollbackRevisionBinding ??
    workflowRevisionBindingFor(workflow, {
      activationId: workflow.metadata.harness?.activationId,
      nowMs: createdAtMs,
    });
  const expectedWorkflowContentHash =
    restoreResult?.expectedWorkflowContentHash ?? fallbackBinding.workflowContentHash;
  const actualWorkflowContentHash =
    restoreResult?.actualWorkflowContentHash ??
    (restoreResult?.bundle?.workflow
      ? workflowRevisionBindingFor(restoreResult.bundle.workflow, {
          nowMs: createdAtMs,
        }).workflowContentHash
      : undefined);
  const hashVerified =
    typeof restoreResult?.hashVerified === "boolean"
      ? restoreResult.hashVerified
      : actualWorkflowContentHash
        ? actualWorkflowContentHash === expectedWorkflowContentHash
        : fallbackBinding.revisionSource !== "git";
  if (fallbackBinding.revisionSource !== "git") {
    return {
      schemaVersion: "workflow.harness.rollback-restore-canary.v1",
      canaryId: `harness-rollback-restore-canary:${workflowId}:${createdAtMs}`,
      status: "not_required",
      revisionSource: fallbackBinding.revisionSource,
      restoreStrategy: "file_hash_only_metadata_restore",
      workflowPath: fallbackBinding.workflowPath,
      repoRoot: fallbackBinding.repoRoot,
      relativeWorkflowPath: fallbackBinding.workflowPath,
      restoredRevision:
        fallbackBinding.activatedRevision ?? fallbackBinding.workflowContentHash,
      expectedWorkflowContentHash,
      actualWorkflowContentHash: fallbackBinding.workflowContentHash,
      hashVerified: true,
      receiptBindingRef: `workflow_restore_canary:${fallbackBinding.workflowContentHash}`,
      blockers: [],
      evidenceRefs: [
        `workflow_restore_canary:${fallbackBinding.workflowContentHash}`,
        fallbackBinding.workflowContentHash,
      ],
      createdAtMs,
    };
  }
  const blockers = Array.from(
    new Set([
      ...restoreBlockers,
      ...(restoreResult?.blockers ?? []),
      ...(restoreResult ? [] : ["rollback_restore_canary_not_run"]),
      ...(restoreResult?.restored === true ? [] : ["rollback_restore_canary_not_restored"]),
      ...(restoreResult?.bundle?.workflow ? [] : ["rollback_restore_canary_bundle_missing"]),
      ...(hashVerified ? [] : ["rollback_restore_canary_hash_mismatch"]),
    ].filter(Boolean)),
  );
  const status = blockers.length === 0 ? "passed" : "blocked";
  return {
    schemaVersion: "workflow.harness.rollback-restore-canary.v1",
    canaryId: `harness-rollback-restore-canary:${workflowId}:${createdAtMs}`,
    status,
    revisionSource: "git",
    restoreStrategy: restoreResult?.restoreStrategy ?? "git_show_file_restore",
    workflowPath: restoreResult?.workflowPath ?? fallbackBinding.workflowPath,
    repoRoot: restoreResult?.repoRoot ?? fallbackBinding.repoRoot,
    relativeWorkflowPath:
      restoreResult?.relativeWorkflowPath ?? fallbackBinding.workflowPath,
    restoredRevision:
      restoreResult?.restoredRevision ?? fallbackBinding.activatedRevision,
    restoredFileSha256: restoreResult?.fileSha256,
    expectedWorkflowContentHash,
    actualWorkflowContentHash,
    hashVerified,
    receiptBindingRef: restoreResult?.receiptBindingRef,
    blockers,
    evidenceRefs: [
      ...(restoreResult?.receiptBindingRef ? [restoreResult.receiptBindingRef] : []),
      ...(restoreResult?.restoredRevision ? [restoreResult.restoredRevision] : []),
      ...(restoreResult?.relativeWorkflowPath ? [restoreResult.relativeWorkflowPath] : []),
      ...(restoreResult?.fileSha256 ? [restoreResult.fileSha256] : []),
      expectedWorkflowContentHash,
    ],
    createdAtMs,
  };
}

export function createWorkflowHarnessActivationCandidate(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  readinessResult: WorkflowValidationResult = evaluateWorkflowActivationReadiness(
    workflow,
    tests,
  ),
  proposals: WorkflowProposal[] = [],
  createdAtMs = Date.now(),
  options: {
    rollbackRestoreResult?: WorkflowRevisionRestoreResult | null;
    rollbackRestoreBlockers?: string[];
  } = {},
): WorkflowHarnessForkActivationCandidate {
  const harness = workflow.metadata.harness;
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const activationIdPreview = harnessForkActivationId(workflowId);
  const workerBinding = workflowHarnessWorkerBinding(workflow);
  const workerBindingPreview = {
    ...workerBinding,
    harnessWorkflowId: workerBinding.harnessWorkflowId || workflowId,
    harnessActivationId: activationIdPreview,
    harnessHash: harness?.harnessHash ?? workerBinding.harnessHash,
    executionMode: harness?.executionMode ?? workerBinding.executionMode,
    source: "fork" as const,
  };
  const activationGateProposal = proposals.find(
    (proposal) =>
      proposal.id.includes("activation") ||
      proposal.sidecarDiff?.changedRoles?.includes("activation"),
  );
  const revisionBindingPreview = workflowRevisionBindingFor(workflow, {
    proposalId: activationGateProposal?.id,
    activationId: activationIdPreview,
    rollbackActivationId: harness?.activationRecord?.rollbackTarget,
    rollbackRevision:
      harness?.activationRecord?.rollbackRevisionBinding?.activatedRevision ??
      harness?.activationRecord?.rollbackRevisionBinding?.workflowContentHash ??
      harness?.revisionBinding?.rollbackRevision,
    nowMs: createdAtMs,
  });
  const activationIssues = [
    ...readinessResult.errors,
    ...readinessResult.warnings,
    ...(readinessResult.executionReadinessIssues ?? []),
  ];
  const uniqueIssues = Array.from(
    new Map(activationIssues.map((issue) => [workflowValidationIssueKey(issue), issue])).values(),
  );
  const blockingIssues = uniqueIssues.filter(
    (issue) => issue.code !== "harness_activation_not_validated",
  );
  const issueCodes = new Set(uniqueIssues.map((issue) => issue.code));
  const requiredSlots = harnessSlotsForWorkflow(workflow).filter((slot) => slot.required);
  const boundSlotIds = new Set(workflow.nodes.flatMap((node) => node.runtimeBinding?.slotIds ?? []));
  const boundRequiredSlots = requiredSlots.filter((slot) => boundSlotIds.has(slot.slotId));
  const receiptReadyComponentCount = workflow.nodes.filter(
    (node) => (node.runtimeBinding?.receiptKinds ?? []).length > 0,
  ).length;
  const packageEvidenceReview = workflowHarnessPackageEvidenceReview(workflow);
  const activationRecord = harness?.activationRecord;
  const canaryBoundaries =
    harness?.canaryExecutionBoundaries ??
    (harness?.canaryExecutionBoundary ? [harness.canaryExecutionBoundary] : []);
  const canaryReady =
    activationRecord?.canaryStatus === "passed" ||
    (canaryBoundaries.length > 0 &&
      canaryBoundaries.every(
        (boundary) =>
          boundary.status === "passed" &&
          boundary.canaryEligible === true &&
          boundary.rollbackDrill.drillStatus === "passed",
      ));
  const rollbackReady =
    activationRecord?.rollbackAvailable === true &&
    Boolean(activationRecord.rollbackTarget);
  const rollbackRevisionBinding =
    activationRecord?.rollbackRevisionBinding ??
    harness?.activationRollbackProof?.restoredRevisionBinding ??
    harness?.revisionBinding;
  const rollbackRestoreCanary = workflowHarnessRollbackRestoreCanaryFor(
    workflow,
    rollbackRevisionBinding,
    options.rollbackRestoreResult,
    options.rollbackRestoreBlockers ?? [],
    createdAtMs,
  );
  const rollbackRestoreReady =
    rollbackRestoreCanary.status === "passed" ||
    rollbackRestoreCanary.status === "not_required";
  const forkMutationCanary =
    activationRecord?.forkMutationCanary ??
    harness?.forkMutationCanary ??
    harness?.packageManifest?.forkMutationCanary ??
    null;
  const forkMutationCanaryReady =
    workflowHarnessForkMutationCanaryReady(forkMutationCanary);
  const forkMutationCanaryRefs =
    workflowHarnessForkMutationCanaryRefs(forkMutationCanary);
  const policyPostureReady =
    harness?.aiMutationMode === "proposal_only" &&
    (workflow.global_config.environmentProfile?.mockBindingPolicy ?? "block") === "block" &&
    !issueCodes.has("harness_self_mutation_not_proposal_only") &&
    !issueCodes.has("mcp_access_not_reviewed") &&
    !issueCodes.has("mock_binding_active");
  const replayDrillBlockers = (harness?.replayDrills ?? []).filter(
    (drill) =>
      drill.drillStatus !== "passed" ||
      !["none", "harmless_metadata_drift"].includes(drill.divergenceClass),
  );
  const replayGateBlockers = (harness?.replayGates ?? []).filter(
    (gate) => gate.activationGateImpact !== "passed" || gate.gateStatus !== "passed",
  );
  const promotionClusterReplayGateBlockers =
    workflowHarnessPromotionClusterReplayGateBlockers(harness);
  const replayReady =
    !issueCodes.has("missing_replay_fixture") &&
    replayDrillBlockers.length === 0 &&
    replayGateBlockers.length === 0 &&
    promotionClusterReplayGateBlockers.length === 0;
  const workerBindingReady =
    Boolean(workerBindingPreview.harnessWorkflowId) &&
    workerBindingPreview.harnessActivationId === activationIdPreview &&
    Boolean(workerBindingPreview.harnessHash);
  const schedulerLaneReadiness =
    readinessResult.schedulerLaneReadiness ?? workflowSchedulerLaneReadiness();
  const schedulerLaneReadyCount = schedulerLaneReadiness.filter(
    (lane) => lane.status === "ready",
  ).length;
  const gateResults: WorkflowHarnessActivationCandidateGateResult[] = [
    {
      gateId: "slots",
      label: "Slots",
      status: boundRequiredSlots.length === requiredSlots.length ? "passed" : "blocked",
      value: `${boundRequiredSlots.length}/${requiredSlots.length}`,
      detail: "Required component slots must be bound.",
      evidenceRefs: requiredSlots.map((slot) => slot.slotId),
    },
    {
      gateId: "tests",
      label: "Tests",
      status: tests.length > 0 ? "passed" : "blocked",
      value: `${tests.length}`,
      detail: "Activation requires test coverage.",
      evidenceRefs: tests.map((test) => test.id),
    },
    {
      gateId: "replay-fixtures",
      label: "Replay fixtures",
      status: replayReady ? "passed" : "blocked",
      value: replayReady
        ? "ready"
        : replayDrillBlockers.length > 0
          ? `${replayDrillBlockers.length} drill blockers`
          : replayGateBlockers.length > 0
            ? `${replayGateBlockers.length} gate blockers`
            : promotionClusterReplayGateBlockers.length > 0
              ? `${promotionClusterReplayGateBlockers.length} cluster gate blockers`
          : "missing",
      detail:
        "Required replay fixtures, replay drills, and promotion cluster replay gates must pass without blocking divergence.",
      evidenceRefs: [
        ...uniqueIssues
          .filter((issue) => issue.code === "missing_replay_fixture")
          .map((issue) => issue.nodeId ?? issue.code),
        ...replayDrillBlockers.map((drill) => drill.drillId),
        ...replayGateBlockers.map((gate) => gate.gateId),
        ...promotionClusterReplayGateBlockers.map(
          (cluster) => cluster.replayGateProof?.gateId ?? `cluster:${cluster.clusterId}:replay-gate`,
        ),
      ],
    },
    {
      gateId: "policy-posture",
      label: "Policy posture",
      status: policyPostureReady ? "passed" : "blocked",
      value: activationRecord?.policyPosture ?? "proposal_only",
      detail: "Policy must keep self-mutation proposal-only and block unreviewed live access.",
      evidenceRefs: activationGateProposal ? [activationGateProposal.id] : [],
    },
    {
      gateId: "mutation-canary",
      label: "Mutation canary",
      status: forkMutationCanaryReady ? "passed" : "blocked",
      value: forkMutationCanary
        ? `${forkMutationCanary.mutationKind}:${forkMutationCanary.status}`
        : "missing",
      detail:
        "A real fork workflow diff must be proposal-bound, replayed, receipted, node-attempted, and rollback-safe.",
      evidenceRefs: forkMutationCanaryRefs,
    },
    {
      gateId: "receipt-coverage",
      label: "Receipt coverage",
      status: receiptReadyComponentCount === workflow.nodes.length ? "passed" : "blocked",
      value: `${receiptReadyComponentCount}/${workflow.nodes.length}`,
      detail: "Every harness component must expose mapped receipt refs.",
      evidenceRefs: workflow.nodes.flatMap((node) => node.runtimeBinding?.receiptKinds ?? []),
    },
    {
      gateId: "scheduler-lanes",
      label: "Scheduler lanes",
      status:
        schedulerLaneReadyCount === schedulerLaneReadiness.length
          ? "passed"
          : "blocked",
      value: `${schedulerLaneReadyCount}/${schedulerLaneReadiness.length}`,
      detail:
        "React Flow activation readiness must expose the runtime scheduler lane decomposition with matching source-contract proof keys.",
      evidenceRefs: schedulerLaneReadiness.flatMap((lane) => [
        lane.proofCheckKey,
        ...lane.evidenceRefs,
      ]),
    },
    {
      gateId: "package-evidence",
      label: "Package evidence",
      status: packageEvidenceReview.ready ? "passed" : "blocked",
      value: packageEvidenceReview.value,
      detail: packageEvidenceReview.required
        ? "Portable package evidence must preserve receipts, replay fixtures, rollback restore refs, worker handoff refs, and deep links."
        : "Package evidence is recorded for export/import review once activation evidence exists.",
      evidenceRefs: packageEvidenceReview.evidenceRefs,
    },
    {
      gateId: "canary",
      label: "Canary",
      status: canaryReady ? "passed" : "blocked",
      value: activationRecord?.canaryStatus ?? "not_run",
      detail: "Canary proof must pass with rollback drill coverage.",
      evidenceRefs: canaryBoundaries.map((boundary) => boundary.boundaryId),
    },
    {
      gateId: "rollback-restore",
      label: "Rollback restore",
      status: rollbackRestoreReady ? "passed" : "blocked",
      value: rollbackRestoreCanary.status,
      detail:
        rollbackRestoreCanary.status === "passed"
          ? "Rollback revision restore canary verified git content and hash."
          : rollbackRestoreCanary.status === "not_required"
            ? "Rollback revision uses metadata-only restore."
            : "Git-backed rollback revision must be restorable before activation.",
      evidenceRefs: rollbackRestoreCanary.evidenceRefs,
    },
    {
      gateId: "rollback",
      label: "Rollback",
      status: rollbackReady ? "passed" : "blocked",
      value: activationRecord?.rollbackTarget ?? "not set",
      detail: "A rollback target and rollback availability must be recorded.",
      evidenceRefs: activationRecord?.rollbackTarget ? [activationRecord.rollbackTarget] : [],
    },
    {
      gateId: "worker-binding",
      label: "Worker binding",
      status: workerBindingReady ? "passed" : "blocked",
      value: workerBindingPreview.harnessActivationId ?? "blocked",
      detail: "Worker binding preview must point at the candidate activation id.",
      evidenceRefs: [workerBindingPreview.harnessWorkflowId, workerBindingPreview.harnessHash],
    },
  ];
  const failedGateIds = gateResults
    .filter((gate) => gate.status !== "passed")
    .map((gate) => gate.gateId);
  const decision =
    workflowIsHarnessFork(workflow) &&
    blockingIssues.length === 0 &&
    failedGateIds.length === 0
      ? "mintable"
      : "blocked";
  const activationGate: WorkflowHarnessActivationCandidateGateResult = {
    gateId: "activation-id",
    label: "Activation id",
    status: decision === "mintable" ? "passed" : "blocked",
    value: decision === "mintable" ? activationIdPreview : "not minted",
    detail:
      decision === "mintable"
        ? "Dry run is mintable; applying activation would use this id."
        : "Activation id stays unminted while blocking gates remain.",
    evidenceRefs: decision === "mintable" ? [activationIdPreview] : [],
  };
  const activationBlockers = Array.from(
    new Set([
      ...blockingIssues.map((issue) => `${issue.code}: ${issue.message}`),
      ...failedGateIds.map((gateId) => `gate_blocked:${gateId}`),
      ...(workflowIsHarnessFork(workflow) ? [] : ["not_harness_fork"]),
    ]),
  );
  return {
    schemaVersion: "workflow.harness.activation-candidate.v1",
    candidateId: `candidate:${workflowId}:activation-dry-run:${createdAtMs}`,
    workflowId,
    harnessWorkflowId: harness?.harnessWorkflowId ?? workflowId,
    harnessHash: harness?.harnessHash ?? workerBindingPreview.harnessHash,
    decision,
    activationId: decision === "mintable" ? activationIdPreview : undefined,
    activationIdPreview: decision === "mintable" ? activationIdPreview : undefined,
    dryRunOnly: true,
    activationBlockers,
    blockerCodes: Array.from(
      new Set([...blockingIssues.map((issue) => issue.code), ...failedGateIds]),
    ),
    gateResults: [...gateResults, activationGate],
    componentVersionSet:
      activationRecord?.componentVersionSet ??
      Object.fromEntries(
        workflow.nodes
          .filter((node) => node.runtimeBinding)
          .map((node) => [
            node.runtimeBinding?.componentId ?? node.id,
            node.runtimeBinding?.componentVersion ?? "unknown",
          ]),
      ),
    policyPosture: activationRecord?.policyPosture ?? "proposal_only",
    canaryStatus: canaryReady ? "passed" : (activationRecord?.canaryStatus ?? "not_run"),
    rollbackTarget: activationRecord?.rollbackTarget ?? "",
    rollbackAvailable: rollbackReady,
    rollbackRestoreCanary,
    forkMutationCanary:
      forkMutationCanary ??
      ({
        schemaVersion: "workflow.harness.fork-mutation-canary.v1",
        canaryId: "missing",
        mutationId: "missing",
        mutationKind: "budget_gate_limit",
        mutationScope: "workflow_policy",
        workflowId,
        harnessWorkflowId: harness?.harnessWorkflowId ?? workflowId,
        componentId: "ioi.agent-harness.budget_gate.v1",
        workflowNodeId: "harness.budget_gate",
        targetPath: "global_config.policy.maxSteps",
        beforeValue: "",
        afterValue: "",
        diffHash: "",
        proposalId: activationGateProposal?.id ?? "",
        status: "blocked",
        canaryStatus: "not_run",
        replayFixtureRefs: [],
        receiptRefs: [],
        nodeAttemptIds: [],
        evidenceRefs: [],
        policyDecision: "block_missing_fork_mutation_canary",
        rollbackTarget: activationRecord?.rollbackTarget ?? "",
        rollbackAvailable: false,
        blockers: ["harness_fork_mutation_canary_not_passed"],
        createdAtMs,
      }),
    workerBindingPreview,
    revisionBindingPreview,
    evidenceRefs: [
      ...gateResults.flatMap((gate) => gate.evidenceRefs),
      ...rollbackRestoreCanary.evidenceRefs,
      ...(activationGateProposal ? [activationGateProposal.id] : []),
    ],
    createdAtMs,
  };
}

function workflowNodeNeedsReplayFixture(node: Node): boolean {
  return ["model_call", "adapter", "plugin_tool", "function"].includes(node.type);
}

function workflowHasUsableReplayFixture(nodeId: string, fixtures: WorkflowNodeFixture[]): boolean {
  return fixtures.some((fixture) => {
    if (fixture.nodeId !== nodeId) return false;
    if (fixture.stale === true) return false;
    if (fixture.validationStatus === "failed" || fixture.validationStatus === "stale") return false;
    return fixture.input !== undefined && fixture.output !== undefined;
  });
}
