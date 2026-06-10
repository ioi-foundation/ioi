import { spawnSync } from "node:child_process";

export const CONTEXT_POLICY_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const CONTEXT_POLICY_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.context-budget-policy-request.v1";
export const CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-budget-policy-request.v1";
export const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-budget-recovery-state-update-request.v1";
export const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.diagnostics-operator-override-state-update-request.v1";
export const OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.operator-interrupt-state-update-request.v1";
export const OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.operator-steer-state-update-request.v1";
export const RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.run-cancel-state-update-request.v1";
export const THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-control-agent-state-update-request.v1";
export const MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-control-agent-state-update-request.v1";
export const MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-server-validation-request.v1";
export const MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-server-validation-input-request.v1";
export const MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-validation-projection-request.v1";
export const MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-status-projection-request.v1";
export const MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-catalog-projection-request.v1";
export const MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-catalog-summary-projection-request.v1";
export const MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-validation-projection-request.v1";
export const MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-status-projection-request.v1";
export const THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.thread-memory-agent-state-update-request.v1";
export const RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.runtime-bridge-thread-start-agent-state-update-request.v1";
export const RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.runtime-bridge-turn-run-state-update-request.v1";
export const SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.subagent-record-state-update-request.v1";
export const AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.agent-create-state-update-request.v1";
export const RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.run-create-state-update-request.v1";
export const AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.agent-status-state-update-request.v1";
export const COMPACTION_POLICY_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.compaction-policy-request.v1";
export const CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.context-compaction-plan-request.v1";
export const CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.context-compaction-state-update-request.v1";
export const RUST_CONTEXT_POLICY_BACKEND = "rust_policy";

export function createContextPolicyRunnerFromEnv(env = process.env, options = {}) {
  assertNoContextPolicyCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustContextPolicyRunner({
    command: options.command ?? env[CONTEXT_POLICY_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoContextPolicyCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new ContextPolicyRunnerError(
    "Context policy command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "context_policy_command_args_retired",
    { retired_args: value },
  );
}

export class RustContextPolicyRunner {
  constructor(options = {}) {
    assertNoContextPolicyCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  evaluateContextBudgetPolicy(request = {}) {
    return this.evaluatePolicy({
      operation: "evaluate_context_budget_policy",
      schemaVersion: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
      request,
    });
  }

  evaluateCodingToolBudgetPolicy(request = {}) {
    return this.evaluatePolicy({
      operation: "evaluate_coding_tool_budget_policy",
      schemaVersion: CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
      request,
    });
  }

  evaluateCompactionPolicy(request = {}) {
    return normalizeCompactionPolicyBridgeResult(this.evaluateRawPolicy({
      operation: "evaluate_compaction_policy",
      schemaVersion: COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planContextCompaction(request = {}) {
    return normalizeContextCompactionPlanBridgeResult(this.evaluateRawPolicy({
      operation: "plan_context_compaction",
      schemaVersion: CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planContextCompactionStateUpdate(request = {}) {
    return normalizeContextCompactionStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_context_compaction_state_update",
      schemaVersion: CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planCodingToolBudgetRecoveryStateUpdate(request = {}) {
    return normalizeCodingToolBudgetRecoveryStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_coding_tool_budget_recovery_state_update",
      schemaVersion: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planDiagnosticsOperatorOverrideStateUpdate(request = {}) {
    return normalizeDiagnosticsOperatorOverrideStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_diagnostics_operator_override_state_update",
      schemaVersion: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planOperatorInterruptStateUpdate(request = {}) {
    return normalizeOperatorInterruptStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_operator_interrupt_state_update",
      schemaVersion: OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planOperatorSteerStateUpdate(request = {}) {
    return normalizeOperatorSteerStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_operator_steer_state_update",
      schemaVersion: OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planRunCancelStateUpdate(request = {}) {
    return normalizeRunCancelStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_run_cancel_state_update",
      schemaVersion: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planThreadControlAgentStateUpdate(request = {}) {
    return normalizeThreadControlAgentStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_thread_control_agent_state_update",
      schemaVersion: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMcpControlAgentStateUpdate(request = {}) {
    return normalizeMcpControlAgentStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_mcp_control_agent_state_update",
      schemaVersion: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  validateMcpServers(request = {}) {
    return normalizeMcpServerValidationBridgeResult(this.evaluateRawPolicy({
      operation: "validate_mcp_servers",
      schemaVersion: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  projectMcpServerValidationInput(request = {}) {
    return normalizeMcpServerValidationInputBridgeResult(this.evaluateRawPolicy({
      operation: "project_mcp_server_validation_input",
      schemaVersion: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMcpManagerValidationProjection(request = {}) {
    return normalizeMcpManagerValidationProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_mcp_manager_validation_projection",
      schemaVersion: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMcpManagerStatusProjection(request = {}) {
    return normalizeMcpManagerStatusProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_mcp_manager_status_projection",
      schemaVersion: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMcpManagerCatalogProjection(request = {}) {
    return normalizeMcpManagerCatalogProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_mcp_manager_catalog_projection",
      schemaVersion: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMcpManagerCatalogSummaryProjection(request = {}) {
    return normalizeMcpManagerCatalogSummaryProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_mcp_manager_catalog_summary_projection",
      schemaVersion: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMemoryManagerValidationProjection(request = {}) {
    return normalizeMemoryManagerValidationProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_memory_manager_validation_projection",
      schemaVersion: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planMemoryManagerStatusProjection(request = {}) {
    return normalizeMemoryManagerStatusProjectionBridgeResult(this.evaluateRawPolicy({
      operation: "plan_memory_manager_status_projection",
      schemaVersion: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planThreadMemoryAgentStateUpdate(request = {}) {
    return normalizeThreadMemoryAgentStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_thread_memory_agent_state_update",
      schemaVersion: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planRuntimeBridgeThreadStartAgentStateUpdate(request = {}) {
    return normalizeRuntimeBridgeThreadStartAgentStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_runtime_bridge_thread_start_agent_state_update",
      schemaVersion: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planRuntimeBridgeTurnRunStateUpdate(request = {}) {
    return normalizeRuntimeBridgeTurnRunStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_runtime_bridge_turn_run_state_update",
      schemaVersion: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planSubagentRecordStateUpdate(request = {}) {
    return normalizeSubagentRecordStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_subagent_record_state_update",
      schemaVersion: SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planAgentCreateStateUpdate(request = {}) {
    return normalizeAgentCreateStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_agent_create_state_update",
      schemaVersion: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planRunCreateStateUpdate(request = {}) {
    return normalizeRunCreateStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_run_create_state_update",
      schemaVersion: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  planAgentStatusStateUpdate(request = {}) {
    return normalizeAgentStatusStateUpdateBridgeResult(this.evaluateRawPolicy({
      operation: "plan_agent_status_state_update",
      schemaVersion: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
      request,
    }));
  }

  evaluatePolicy({ operation, schemaVersion, request }) {
    return normalizeContextBudgetPolicyBridgeResult(this.evaluateRawPolicy({
      operation,
      schemaVersion,
      request,
    }));
  }

  evaluateRawPolicy({ operation, schemaVersion, request }) {
    const bridgeRequest = {
      schema_version: CONTEXT_POLICY_COMMAND_SCHEMA_VERSION,
      operation,
      backend: RUST_CONTEXT_POLICY_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: schemaVersion,
      },
    };
    return this.invokeBridge(bridgeRequest);
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_context_budget_policy_mock",
        backend: request.backend ?? RUST_CONTEXT_POLICY_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ContextPolicyRunnerError(
        "Context policy requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core policy evaluation.",
        "context_policy_bridge_unconfigured",
        {
          env: CONTEXT_POLICY_COMMAND_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ContextPolicyRunnerError(
        "Failed to spawn Rust context policy bridge command.",
        "context_policy_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ContextPolicyRunnerError(
        "Rust context policy bridge command failed.",
        "context_policy_bridge_failed",
        {
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new ContextPolicyRunnerError(
        "Rust context policy bridge command returned invalid JSON.",
        "context_policy_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ContextPolicyRunnerError(
        parsed.error?.message ?? "Rust context policy rejected the request.",
        parsed.error?.code ?? "context_policy_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class ContextPolicyRunnerError extends Error {
  constructor(message, code = "context_policy_runner_error", details = {}) {
    super(message);
    this.name = "ContextPolicyRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function requiredContextPolicyBridgeOperationKind(result, record, options = {}) {
  const {
    codePrefix,
    expectedOperationKind = null,
    expectedOperationKinds = expectedOperationKind ? [expectedOperationKind] : [],
    expectedPrefix = null,
  } = options;
  const operationKind = optionalString(result.operation_kind ?? record.operation_kind);
  if (!operationKind) {
    throw new ContextPolicyRunnerError(
      "Rust context policy bridge result did not include an operation kind.",
      `${codePrefix}_operation_kind_missing`,
      {
        operation_kind: expectedOperationKinds[0] ?? expectedPrefix ?? null,
        expected_operation_kinds: expectedOperationKinds,
        expected_prefix: expectedPrefix,
      },
    );
  }
  if (expectedOperationKinds.length > 0 && !expectedOperationKinds.includes(operationKind)) {
    throw new ContextPolicyRunnerError(
      "Rust context policy bridge result included an unexpected operation kind.",
      `${codePrefix}_operation_kind_mismatch`,
      {
        expected_operation_kind: expectedOperationKinds[0],
        expected_operation_kinds: expectedOperationKinds,
        operation_kind: operationKind,
      },
    );
  }
  if (expectedPrefix && !operationKind.startsWith(expectedPrefix)) {
    throw new ContextPolicyRunnerError(
      "Rust context policy bridge result included an unexpected operation kind.",
      `${codePrefix}_operation_kind_mismatch`,
      { expected_prefix: expectedPrefix, operation_kind: operationKind },
    );
  }
  return operationKind;
}

export function normalizeContextBudgetPolicyBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const enabledToolCount = numberValue(result.enabled_tool_count ?? record.enabled_tool_count);
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_context_budget_policy_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "ok",
    mode: optionalString(result.mode ?? record.mode) ?? "simulate",
    usage_telemetry: objectRecord(result.usage_telemetry) ?? objectRecord(record.usage_telemetry) ?? {},
    usage_summary: objectRecord(result.usage_summary) ?? objectRecord(record.usage_summary) ?? {},
    policy_decision_id: optionalString(result.policy_decision_id ?? record.policy_decision_id),
    policy_decision: objectRecord(result.policy_decision) ?? objectRecord(record.policy_decision) ?? null,
    receipt_refs: stringArray(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: stringArray(result.policy_decision_refs ?? record.policy_decision_refs),
    warnings: arrayValue(result.warnings ?? record.warnings),
    violations: arrayValue(result.violations ?? record.violations),
    would_block: Boolean(result.would_block ?? record.would_block),
    runtime_event_kind:
      optionalString(result.runtime_event_kind ?? record.runtime_event_kind) ??
      "context_budget.evaluated",
    runtime_event_status:
      optionalString(result.runtime_event_status ?? record.runtime_event_status) ?? "completed",
    runtime_event_item_id: optionalString(
      result.runtime_event_item_id ?? record.runtime_event_item_id,
    ),
    runtime_event_idempotency_key: optionalString(
      result.runtime_event_idempotency_key ?? record.runtime_event_idempotency_key,
    ),
    summary: optionalString(result.summary ?? record.summary) ?? null,
  };
}

export function normalizeCompactionPolicyBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_compaction_policy_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "ok",
    action: optionalString(result.action ?? record.action) ?? "noop",
    selected_action: optionalString(result.selected_action ?? record.selected_action) ?? "noop",
    budget_status: optionalString(result.budget_status ?? record.budget_status) ?? "ok",
    policy_decision_id: optionalString(result.policy_decision_id ?? record.policy_decision_id),
    receipt_refs: stringArray(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: stringArray(result.policy_decision_refs ?? record.policy_decision_refs),
    approval_id: optionalString(result.approval_id ?? record.approval_id),
    approval_required: Boolean(result.approval_required ?? record.approval_required),
    approval_granted: Boolean(result.approval_granted ?? record.approval_granted),
    approval_satisfied: Boolean(result.approval_satisfied ?? record.approval_satisfied),
    execute_compaction: Boolean(result.execute_compaction ?? record.execute_compaction),
    compaction_requested: Boolean(result.compaction_requested ?? record.compaction_requested),
    compaction_executed: Boolean(result.compaction_executed ?? record.compaction_executed),
    compaction_event_id: optionalString(result.compaction_event_id ?? record.compaction_event_id),
    compaction_seq: numberValue(result.compaction_seq ?? record.compaction_seq),
    compact_reason: optionalString(result.compact_reason ?? record.compact_reason) ?? null,
    compact_scope: optionalString(result.compact_scope ?? record.compact_scope) ?? "thread",
    runtime_event_kind:
      optionalString(result.runtime_event_kind ?? record.runtime_event_kind) ??
      "compaction_policy.evaluated",
    runtime_event_status:
      optionalString(result.runtime_event_status ?? record.runtime_event_status) ?? "completed",
    runtime_event_item_id: optionalString(
      result.runtime_event_item_id ?? record.runtime_event_item_id,
    ),
    runtime_event_idempotency_key: optionalString(
      result.runtime_event_idempotency_key ?? record.runtime_event_idempotency_key,
    ),
    compact_idempotency_key: optionalString(
      result.compact_idempotency_key ?? record.compact_idempotency_key,
    ),
    compact_workflow_node_id:
      optionalString(result.compact_workflow_node_id ?? record.compact_workflow_node_id) ??
      "runtime.context-compact",
    continuation_allowed: Boolean(result.continuation_allowed ?? record.continuation_allowed),
    summary: optionalString(result.summary ?? record.summary) ?? null,
  };
}

export function normalizeContextCompactionPlanBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_context_compaction_plan_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    event_source: optionalString(result.event_source ?? record.event_source ?? record.source) ?? "sdk_client",
    actor: optionalString(result.actor ?? record.actor) ?? "user",
    item_id: optionalString(result.item_id ?? record.item_id),
    idempotency_key: optionalString(result.idempotency_key ?? record.idempotency_key),
    compact_hash: optionalString(result.compact_hash ?? record.compact_hash),
    source_event_kind:
      optionalString(result.source_event_kind ?? record.source_event_kind) ??
      "OperatorControl.Compact",
    event_kind: optionalString(result.event_kind ?? record.event_kind) ?? "context.compacted",
    component_kind:
      optionalString(result.component_kind ?? record.component_kind) ?? "context_compaction",
    payload_schema_version:
      optionalString(result.payload_schema_version ?? record.payload_schema_version) ??
      "ioi.runtime.context-compaction.v1",
    payload: objectRecord(result.payload) ?? objectRecord(record.payload) ?? {},
    receipt_refs: stringArray(result.receipt_refs ?? record.receipt_refs),
    policy_decision_refs: stringArray(result.policy_decision_refs ?? record.policy_decision_refs),
    artifact_refs: stringArray(result.artifact_refs ?? record.artifact_refs),
    rollback_refs: stringArray(result.rollback_refs ?? record.rollback_refs),
    redaction_profile: optionalString(result.redaction_profile ?? record.redaction_profile) ?? "internal",
    reason: optionalString(result.reason ?? record.reason) ?? null,
    scope: optionalString(result.scope ?? record.scope) ?? "thread",
    requested_by: optionalString(result.requested_by ?? record.requested_by) ?? "operator",
    previous_latest_seq: numberValue(result.previous_latest_seq ?? record.previous_latest_seq) ?? 0,
  };
}

export function normalizeContextCompactionStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_context_compaction_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    target_kind: optionalString(result.target_kind ?? record.target_kind) ?? "agent",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "context_compaction_state_update",
      expectedOperationKind: "thread.compact",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    context_compaction:
      objectRecord(result.context_compaction) ?? objectRecord(record.context_compaction) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeCodingToolBudgetRecoveryStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_coding_tool_budget_recovery_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "coding_tool_budget_recovery_state_update",
      expectedOperationKind: "workflow.run.retry_completed",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeDiagnosticsOperatorOverrideStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_diagnostics_operator_override_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "diagnostics_operator_override_state_update",
      expectedOperationKind: "diagnostics.operator_override.event",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeOperatorInterruptStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_operator_interrupt_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "operator_interrupt_state_update",
      expectedOperationKind: "turn.interrupt",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    stop_condition:
      objectRecord(result.stop_condition) ?? objectRecord(record.stop_condition) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeOperatorSteerStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_operator_steer_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "operator_steer_state_update",
      expectedOperationKind: "turn.steer",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    operator_control:
      objectRecord(result.operator_control) ?? objectRecord(record.operator_control) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeRunCancelStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_run_cancel_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "run_cancel_state_update",
      expectedOperationKind: "run.cancel",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    stop_condition:
      objectRecord(result.stop_condition) ?? objectRecord(record.stop_condition) ?? null,
    runtime_task:
      objectRecord(result.runtime_task) ?? objectRecord(record.runtime_task) ?? null,
    runtime_job:
      objectRecord(result.runtime_job) ?? objectRecord(record.runtime_job) ?? null,
    runtime_checklist:
      objectRecord(result.runtime_checklist) ?? objectRecord(record.runtime_checklist) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeThreadControlAgentStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_thread_control_agent_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "thread_control_agent_state_update",
      expectedPrefix: "thread.",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    control:
      objectRecord(result.control) ?? objectRecord(record.control) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeMcpControlAgentStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_mcp_control_agent_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "mcp_control_agent_state_update",
      expectedPrefix: "thread.",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    control:
      objectRecord(result.control) ?? objectRecord(record.control) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeMcpServerValidationBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const issues = arrayValue(result.issues ?? record.issues);
  const warnings = arrayValue(result.warnings ?? record.warnings);
  const ok = Boolean(result.ok ?? record.ok);
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_mcp_server_validation_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status:
      optionalString(result.status ?? record.status) ??
      (ok ? "pass" : "blocked"),
    ok,
    issue_count: numberValue(result.issue_count ?? record.issue_count) ?? issues.length,
    warning_count:
      numberValue(result.warning_count ?? record.warning_count) ?? warnings.length,
    issues,
    warnings,
  };
}

export function normalizeMcpServerValidationInputBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const servers = arrayValue(result.servers ?? record.servers);
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_mcp_server_validation_input_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "projected",
    workspace_root: optionalString(result.workspace_root ?? record.workspace_root) ?? null,
    server_count: numberValue(result.server_count ?? record.server_count) ?? servers.length,
    servers,
  };
}

export function normalizeMcpManagerStatusProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const enabledToolCount = numberValue(result.enabled_tool_count ?? record.enabled_tool_count);
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_mcp_manager_status_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object: optionalString(result.object ?? record.object) ?? "ioi.runtime_mcp_manager_status",
    status: optionalString(result.status ?? record.status) ?? "needs_review",
    server_count: numberValue(result.server_count ?? record.server_count) ?? 0,
    tool_count: numberValue(result.tool_count ?? record.tool_count) ?? 0,
    resource_count: numberValue(result.resource_count ?? record.resource_count) ?? 0,
    prompt_count: numberValue(result.prompt_count ?? record.prompt_count) ?? 0,
    enabled_server_count:
      numberValue(result.enabled_server_count ?? record.enabled_server_count) ?? 0,
    ...(enabledToolCount === null ? {} : { enabled_tool_count: enabledToolCount }),
    servers: arrayValue(result.servers ?? record.servers),
    tools: arrayValue(result.tools ?? record.tools),
    resources: arrayValue(result.resources ?? record.resources),
    prompts: arrayValue(result.prompts ?? record.prompts),
    validation: objectRecord(result.validation ?? record.validation) ?? {},
    routes: objectRecord(result.routes ?? record.routes) ?? {},
  };
}

export function normalizeMcpManagerValidationProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const issues = arrayValue(result.issues ?? record.issues);
  const warnings = arrayValue(result.warnings ?? record.warnings);
  const ok = Boolean(result.ok ?? record.ok);
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_mcp_manager_validation_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object:
      optionalString(result.object ?? record.object) ??
      "ioi.runtime_mcp_manager_validation",
    ok,
    status:
      optionalString(result.status ?? record.status) ??
      (ok ? "pass" : "blocked"),
    server_count: numberValue(result.server_count ?? record.server_count) ?? 0,
    tool_count: numberValue(result.tool_count ?? record.tool_count) ?? 0,
    resource_count: numberValue(result.resource_count ?? record.resource_count) ?? 0,
    prompt_count: numberValue(result.prompt_count ?? record.prompt_count) ?? 0,
    issue_count: numberValue(result.issue_count ?? record.issue_count) ?? issues.length,
    warning_count:
      numberValue(result.warning_count ?? record.warning_count) ?? warnings.length,
    issues,
    warnings,
    servers: arrayValue(result.servers ?? record.servers),
    tools: arrayValue(result.tools ?? record.tools),
    resources: arrayValue(result.resources ?? record.resources),
    prompts: arrayValue(result.prompts ?? record.prompts),
  };
}

export function normalizeMemoryManagerStatusProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const evidenceRefs = stringArray(result.evidence_refs ?? record.evidence_refs);
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_memory_manager_status_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object:
      optionalString(result.object ?? record.object) ??
      "ioi.runtime_memory_manager_status",
    status: optionalString(result.status ?? record.status) ?? "needs_review",
    disabled: Boolean(result.disabled ?? record.disabled),
    injection_enabled: Boolean(result.injection_enabled ?? record.injection_enabled ?? true),
    read_only: Boolean(result.read_only ?? record.read_only),
    write_requires_approval: Boolean(
      result.write_requires_approval ?? record.write_requires_approval,
    ),
    write_blocked_reason:
      optionalString(result.write_blocked_reason ?? record.write_blocked_reason) ?? null,
    record_count: numberValue(result.record_count ?? record.record_count) ?? 0,
    scope_count: numberValue(result.scope_count ?? record.scope_count) ?? 0,
    memory_key_count: numberValue(result.memory_key_count ?? record.memory_key_count) ?? 0,
    scopes: stringArray(result.scopes ?? record.scopes),
    memory_keys: stringArray(result.memory_keys ?? record.memory_keys),
    policy: objectRecord(result.policy ?? record.policy) ?? {},
    paths: objectRecord(result.paths ?? record.paths) ?? {},
    filters: objectRecord(result.filters ?? record.filters) ?? {},
    records: arrayValue(result.records ?? record.records),
    validation: objectRecord(result.validation ?? record.validation) ?? {},
    routes: objectRecord(result.routes ?? record.routes) ?? {},
    evidence_refs: evidenceRefs,
  };
}

export function normalizeMemoryManagerValidationProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const issues = arrayValue(result.issues ?? record.issues);
  const warnings = arrayValue(result.warnings ?? record.warnings);
  const ok = Boolean(result.ok ?? record.ok);
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_memory_manager_validation_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object:
      optionalString(result.object ?? record.object) ??
      "ioi.runtime_memory_manager_validation",
    ok,
    status:
      optionalString(result.status ?? record.status) ??
      (ok ? "pass" : "blocked"),
    issue_count: numberValue(result.issue_count ?? record.issue_count) ?? issues.length,
    warning_count:
      numberValue(result.warning_count ?? record.warning_count) ?? warnings.length,
    record_count: numberValue(result.record_count ?? record.record_count) ?? 0,
    issues,
    warnings,
    policy: objectRecord(result.policy ?? record.policy) ?? {},
    paths: objectRecord(result.paths ?? record.paths) ?? {},
    filters: objectRecord(result.filters ?? record.filters) ?? {},
    records: arrayValue(result.records ?? record.records),
  };
}

export function normalizeMcpManagerCatalogProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const tools = arrayValue(result.tools ?? record.tools);
  const resources = arrayValue(result.resources ?? record.resources);
  const prompts = arrayValue(result.prompts ?? record.prompts);
  const enabledTools = arrayValue(result.enabled_tools ?? record.enabled_tools);
  return {
    ...record,
    source: result.source ?? record.source ?? "rust_mcp_manager_catalog_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object:
      optionalString(result.object ?? record.object) ??
      "ioi.runtime_mcp_manager_catalog_projection",
    status: optionalString(result.status ?? record.status) ?? "projected",
    server_count: numberValue(result.server_count ?? record.server_count) ?? 0,
    tool_count: numberValue(result.tool_count ?? record.tool_count) ?? tools.length,
    resource_count:
      numberValue(result.resource_count ?? record.resource_count) ?? resources.length,
    prompt_count: numberValue(result.prompt_count ?? record.prompt_count) ?? prompts.length,
    enabled_tool_count:
      numberValue(result.enabled_tool_count ?? record.enabled_tool_count) ?? enabledTools.length,
    servers: arrayValue(result.servers ?? record.servers),
    tools,
    resources,
    prompts,
    enabled_tools: enabledTools,
  };
}

export function normalizeMcpManagerCatalogSummaryProjectionBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  const namespaces = arrayValue(result.namespaces ?? record.namespaces);
  const previewToolNames = arrayValue(result.preview_tool_names ?? record.preview_tool_names);
  const deferred = Boolean(result.deferred ?? record.deferred);
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_mcp_manager_catalog_summary_projection_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    schema_version: optionalString(result.schema_version ?? record.schema_version) ?? null,
    object:
      optionalString(result.object ?? record.object) ??
      "ioi.runtime_mcp_catalog_summary",
    status: optionalString(result.status ?? record.status) ?? "completed",
    server_id: optionalString(result.server_id ?? record.server_id) ?? null,
    server_label: optionalString(result.server_label ?? record.server_label) ?? null,
    transport: optionalString(result.transport ?? record.transport) ?? null,
    execution_mode: optionalString(result.execution_mode ?? record.execution_mode) ?? null,
    catalog_hash: optionalString(result.catalog_hash ?? record.catalog_hash) ?? null,
    tool_count: numberValue(result.tool_count ?? record.tool_count) ?? 0,
    resource_count: numberValue(result.resource_count ?? record.resource_count) ?? 0,
    prompt_count: numberValue(result.prompt_count ?? record.prompt_count) ?? 0,
    namespace_count:
      numberValue(result.namespace_count ?? record.namespace_count) ?? namespaces.length,
    namespaces,
    preview_limit: numberValue(result.preview_limit ?? record.preview_limit) ?? 25,
    preview_tool_names: previewToolNames,
    deferred,
    full_catalog_included: Boolean(result.full_catalog_included ?? record.full_catalog_included ?? !deferred),
    error_code: optionalString(result.error_code ?? record.error_code) ?? null,
    search_route:
      optionalString(result.search_route ?? record.search_route) ??
      "/v1/mcp/tools/search",
    fetch_route:
      optionalString(result.fetch_route ?? record.fetch_route) ??
      "/v1/mcp/tools/{tool_id}",
  };
}

export function normalizeThreadMemoryAgentStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_thread_memory_agent_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "thread_memory_agent_state_update",
      expectedPrefix: "thread.",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    control:
      objectRecord(result.control) ?? objectRecord(record.control) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeRuntimeBridgeThreadStartAgentStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_runtime_bridge_thread_start_agent_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "runtime_bridge_thread_start_agent_state_update",
      expectedOperationKind: "thread.runtime_bridge.start",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    bridge_start:
      objectRecord(result.bridge_start) ?? objectRecord(record.bridge_start) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeRuntimeBridgeTurnRunStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_runtime_bridge_turn_run_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "runtime_bridge_turn_run_state_update",
      expectedOperationKind: "turn.runtime_bridge.submit",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeSubagentRecordStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_subagent_record_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "subagent_record_state_update",
      expectedPrefix: "subagent.",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    subagent: objectRecord(result.subagent) ?? objectRecord(record.subagent) ?? null,
  };
}

export function normalizeAgentCreateStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_agent_create_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "agent_create_state_update",
      expectedOperationKind: "agent.create",
    }),
    created_at: optionalString(result.created_at ?? record.created_at) ?? null,
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

export function normalizeRunCreateStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_run_create_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "run_create_state_update",
      expectedOperationKind: "run.create",
    }),
    created_at: optionalString(result.created_at ?? record.created_at) ?? null,
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    run: objectRecord(result.run) ?? objectRecord(record.run) ?? null,
  };
}

export function normalizeAgentStatusStateUpdateBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? result;
  return {
    ...record,
    source:
      result.source ??
      record.source ??
      "rust_agent_status_state_update_command",
    backend: result.backend ?? record.backend ?? RUST_CONTEXT_POLICY_BACKEND,
    status: optionalString(result.status ?? record.status) ?? "planned",
    operation_kind: requiredContextPolicyBridgeOperationKind(result, record, {
      codePrefix: "agent_status_state_update",
      expectedPrefix: "agent.",
    }),
    updated_at: optionalString(result.updated_at ?? record.updated_at) ?? null,
    agent: objectRecord(result.agent) ?? objectRecord(record.agent) ?? null,
  };
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function stringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => optionalString(entry)).filter(Boolean);
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function numberValue(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}
