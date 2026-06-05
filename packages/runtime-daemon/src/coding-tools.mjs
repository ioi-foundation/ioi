import { createCodingToolStepModuleProjection } from "./step-module-abi.mjs";

export const CODING_TOOL_PACK_SCHEMA_VERSION = "ioi.runtime.coding-tool-pack.v1";
export const CODING_TOOL_RESULT_SCHEMA_VERSION = "ioi.runtime.coding-tool-result.v1";
export const CODING_TOOL_PACK_ID = "coding";
export const CODING_TOOL_IDS = new Set([
  "workspace.status",
  "git.diff",
  "file.inspect",
  "file.apply_patch",
  "test.run",
  "lsp.diagnostics",
  "artifact.read",
  "tool.retrieve_result",
  "computer_use.request_lease",
]);

const CODING_TOOL_MAX_PREVIEW_BYTES = 64 * 1024;
const CODING_TOOL_DIFF_MAX_BYTES = 64 * 1024;
const CODING_TOOL_APPLY_PATCH_MAX_EDITS = 20;
const CODING_TOOL_TEST_MAX_OUTPUT_BYTES = 64 * 1024;
const CODING_TOOL_TEST_MAX_TIMEOUT_MS = 5 * 60 * 1000;
const CODING_TOOL_TEST_COMMAND_IDS = ["node.test", "npm.test", "cargo.test", "cargo.check"];
const CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES = 64 * 1024;
const CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS = 2 * 60 * 1000;
const CODING_TOOL_DIAGNOSTIC_COMMAND_IDS = ["auto", "node.check", "typescript.check"];
const CODING_TOOL_ARTIFACT_MAX_READ_BYTES = 256 * 1024;
const CODING_TOOL_ARTIFACT_DEFAULT_READ_BYTES = 64 * 1024;
const CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS = [
  "toolPack.coding.budgetMode",
  "toolPack.coding.budgetUsageField",
  "toolPack.coding.maxTotalTokens",
  "toolPack.coding.maxCostUsd",
  "toolPack.coding.maxContextPressure",
  "toolPack.coding.warnAtRatio",
];

export function codingToolContracts() {
  return [
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "workspace.status",
      displayName: "Workspace status",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:workspace.status", "prim:git.status"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "workspace",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          includeIgnored: { type: "boolean" },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "git", "changedFiles", "shellFallbackUsed"],
      },
      evidenceRequirements: ["workspace_status_receipt", "coding_tool_receipt"],
      workflowNodeType: "CodingToolNode",
      workflowConfigFields: [
        "toolPack.coding.workspaceStatus",
        "toolPack.coding.gitEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "git.diff",
      displayName: "Git diff",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:git.diff"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "git",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIFF_MAX_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "paths", "diff", "diffHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["git_diff_receipt", "coding_tool_receipt"],
      workflowNodeType: "GitToolNode",
      workflowConfigFields: [
        "toolPack.coding.gitEnabled",
        "toolPack.coding.allowedPaths",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "file.inspect",
      displayName: "Inspect file",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:fs.inspect"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "filesystem",
      inputSchema: {
        type: "object",
        required: ["path"],
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_MAX_PREVIEW_BYTES },
          previewLines: { type: "integer", minimum: 1, maximum: 500 },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "path", "kind", "exists", "shellFallbackUsed"],
      },
      evidenceRequirements: ["file_inspect_receipt", "coding_tool_receipt"],
      workflowNodeType: "FilesystemToolNode",
      workflowConfigFields: [
        "toolPack.coding.filesystemEnabled",
        "toolPack.coding.allowedPaths",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "file.apply_patch",
      displayName: "Apply file patch",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:fs.apply_patch", "prim:fs.write"],
      authorityScopeRequirements: ["scope:workspace.write"],
      effectClass: "local_write",
      riskDomain: "filesystem",
      inputSchema: {
        type: "object",
        required: ["path"],
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          dryRun: { type: "boolean" },
          create: { type: "boolean" },
          oldText: { type: "string" },
          newText: { type: "string" },
          appendText: { type: "string" },
          prependText: { type: "string" },
          occurrence: { type: "string", enum: ["only", "first", "all"] },
          diagnosticsMode: { type: "string", enum: ["advisory", "blocking", "skip"] },
          diagnosticCommandId: { type: "string", enum: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS },
          diagnosticTimeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS },
          diagnosticMaxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES },
          edits: {
            type: "array",
            maxItems: CODING_TOOL_APPLY_PATCH_MAX_EDITS,
            items: {
              type: "object",
              required: ["type"],
              additionalProperties: false,
              properties: {
                type: { type: "string", enum: ["replace", "append", "prepend"] },
                oldText: { type: "string" },
                newText: { type: "string" },
                text: { type: "string" },
                occurrence: { type: "string", enum: ["only", "first", "all"] },
              },
            },
          },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "path",
          "dryRun",
          "applied",
          "changed",
          "beforeHash",
          "afterHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: [
        "file_apply_patch_receipt",
        "workspace_mutation_receipt",
        "workspace_snapshot_receipt",
        "coding_tool_receipt",
      ],
      workflowNodeType: "FilesystemPatchNode",
      workflowConfigFields: [
        "toolPack.coding.filesystemEnabled",
        "toolPack.coding.writeEnabled",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.dryRun",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.restorePolicy",
        "toolPack.coding.restoreConflictPolicy",
        "toolPack.coding.diagnosticsRepairDefault",
        "toolPack.coding.operatorOverrideRequiresApproval",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "test.run",
      displayName: "Run tests",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:test.run", "prim:process.exec_file"],
      authorityScopeRequirements: ["scope:workspace.test"],
      effectClass: "local_command",
      riskDomain: "test",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          commandId: { type: "string", enum: CODING_TOOL_TEST_COMMAND_IDS },
          cwd: { type: "string" },
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          args: { type: "array", items: { type: "string" } },
          timeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_TEST_MAX_TIMEOUT_MS },
          maxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_TEST_MAX_OUTPUT_BYTES },
          env: { type: "object", additionalProperties: { type: "string" } },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "commandId",
          "cwd",
          "exitCode",
          "testStatus",
          "stdout",
          "stderr",
          "outputHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: ["test_run_receipt", "coding_tool_receipt"],
      workflowNodeType: "TestRunNode",
      workflowConfigFields: [
        "toolPack.coding.testEnabled",
        "toolPack.coding.allowedTestCommandIds",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "lsp.diagnostics",
      displayName: "LSP diagnostics",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:lsp.diagnostics", "prim:process.exec_file"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "diagnostics",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          commandId: { type: "string", enum: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS },
          cwd: { type: "string" },
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          args: { type: "array", items: { type: "string" } },
          timeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS },
          maxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "commandId",
          "resolvedCommandId",
          "backend",
          "diagnosticStatus",
          "diagnostics",
          "diagnosticCount",
          "outputHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: ["lsp_diagnostics_receipt", "coding_tool_receipt"],
      workflowNodeType: "LspDiagnosticsNode",
      workflowConfigFields: [
        "toolPack.coding.diagnosticsEnabled",
        "toolPack.coding.allowedDiagnosticCommandIds",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.restorePolicy",
        "toolPack.coding.restoreConflictPolicy",
        "toolPack.coding.diagnosticsRepairDefault",
        "toolPack.coding.operatorOverrideRequiresApproval",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "artifact.read",
      displayName: "Read artifact",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: {
        type: "object",
        required: ["artifactId"],
        additionalProperties: false,
        properties: {
          artifactId: { type: "string" },
          artifactRef: { type: "string" },
          offsetBytes: { type: "integer", minimum: 0 },
          lengthBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["artifactId", "offsetBytes", "lengthBytes", "content", "contentHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ArtifactReadNode",
      workflowConfigFields: [
        "toolPack.coding.artifactEnabled",
        "toolPack.coding.resultRetrievalEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "tool.retrieve_result",
      displayName: "Retrieve tool result",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:tool.retrieve_result", "prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          toolCallId: { type: "string" },
          artifactId: { type: "string" },
          artifactRef: { type: "string" },
          channel: { type: "string" },
          offsetBytes: { type: "integer", minimum: 0 },
          lengthBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["toolCallId", "artifactId", "content", "contentHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["tool_result_retrieval_receipt", "artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ToolResultRetrievalNode",
      workflowConfigFields: [
        "toolPack.coding.resultRetrievalEnabled",
        "toolPack.coding.artifactEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "computer_use.request_lease",
      displayName: "Request computer-use lease",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:computer_use.lease.request", "prim:computer_use.manifest"],
      authorityScopeRequirements: ["computer_use.lease.request"],
      effectClass: "local_read",
      riskDomain: "computer_use",
      inputSchema: {
        type: "object",
        required: ["prompt"],
        additionalProperties: false,
        properties: {
          prompt: { type: "string" },
          lane: { type: "string", enum: ["native_browser", "visual_gui", "sandboxed_hosted"] },
          sessionMode: { type: "string" },
          session_mode: { type: "string" },
          actionKind: { type: "string" },
          action_kind: { type: "string" },
          url: { type: "string" },
          targetRef: { type: "string" },
          target_ref: { type: "string" },
          selector: { type: "string" },
          approvalRef: { type: "string" },
          approval_ref: { type: "string" },
          observationRetentionMode: { type: "string" },
          observation_retention_mode: { type: "string" },
        },
      },
      outputSchema: {
        type: "object",
        required: ["requestRef", "leaseRequest", "threadTool"],
      },
      evidenceRequirements: ["computer_use_lease_request_receipt", "coding_tool_receipt"],
      workflowNodeType: "ComputerUseLeaseRequestNode",
      workflowConfigFields: [
        "toolPack.coding.computerUseLeaseRequest",
        "computerUse.lane",
        "computerUse.sessionMode",
        "computerUse.actionKind",
        "computerUse.approvalPolicy",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
  ].map((tool) => codingToolRegistryGovernanceMetadata(tool));
}

function codingToolRegistryGovernanceMetadata(tool = {}) {
  const stableToolId = optionalString(tool.stableToolId ?? tool.stable_tool_id) ?? "runtime.tool";
  const effectClass = optionalString(tool.effectClass ?? tool.effect_class) ?? "local_read";
  const riskDomain = optionalString(tool.riskDomain ?? tool.risk_domain) ?? "workspace";
  const authorityScopeRequirements = normalizeStringArray(
    tool.authorityScopeRequirements ?? tool.authority_scope_requirements,
  );
  const evidenceRequirements = normalizeStringArray(tool.evidenceRequirements ?? tool.evidence_requirements);
  const workflowNodeType = optionalString(tool.workflowNodeType ?? tool.workflow_node_type) ?? null;
  const workflowConfigFields = normalizeStringArray(tool.workflowConfigFields ?? tool.workflow_config_fields);
  const approvalRequired =
    typeof tool.approvalRequired === "boolean"
      ? tool.approvalRequired
      : typeof tool.approval_required === "boolean"
        ? tool.approval_required
        : authorityScopeRequirements.length > 0 || !codingToolEffectIsReadOnly(effectClass);
  const credentialReadiness =
    tool.credentialReadiness && typeof tool.credentialReadiness === "object"
      ? tool.credentialReadiness
      : {
          status: codingToolLikelyRequiresCredential(stableToolId, riskDomain, effectClass) ? "unknown" : "not_required",
          checkedAt: null,
          evidenceRefs: [],
          reason: null,
        };
  const credentialReady = credentialReadiness.status === "ready" || credentialReadiness.status === "not_required";
  const receiptBehavior = {
    emitsReceipt: true,
    receiptRequired: evidenceRequirements.length > 0,
    requiredReceiptTypes: evidenceRequirements,
    evidenceRequirements,
    ...(tool.receiptBehavior && typeof tool.receiptBehavior === "object" ? tool.receiptBehavior : {}),
  };
  return {
    ...tool,
    stableToolId,
    displayName: tool.displayName ?? tool.display_name ?? stableToolId,
    primitiveCapabilities: normalizeStringArray(tool.primitiveCapabilities ?? tool.primitive_capabilities),
    authorityScopeRequirements,
    effectClass,
    riskDomain,
    evidenceRequirements,
    credentialReady,
    credentialReadiness,
    approvalRequired,
    approval_required: approvalRequired,
    rateLimitProfile:
      tool.rateLimitProfile ??
      tool.rate_limit_profile ?? {
        policy: codingToolEffectIsReadOnly(effectClass) ? "unlimited_local_read" : "runtime_governed",
        scope: stableToolId,
        maxCalls: null,
        windowMs: null,
        burst: null,
        evidenceRefs: [],
      },
    idempotencyBehavior:
      tool.idempotencyBehavior ??
      tool.idempotency_behavior ?? {
        required: !codingToolEffectIsReadOnly(effectClass),
        strategy: codingToolEffectIsReadOnly(effectClass)
          ? "read_only"
          : codingToolEffectIsExternal(effectClass)
            ? "caller_or_runtime_key"
            : "runtime_key",
        keyScope: codingToolEffectIsReadOnly(effectClass) ? null : stableToolId,
        evidenceRefs: [],
      },
    receiptBehavior,
    workflowAvailability:
      tool.workflowAvailability ??
      tool.workflow_availability ?? {
        available: Boolean(workflowNodeType),
        reason: workflowNodeType ? null : "No workflow node projection registered.",
        nodeType: workflowNodeType,
        configFields: workflowConfigFields,
        evidenceRefs: [],
      },
    agentAvailability:
      tool.agentAvailability ??
      tool.agent_availability ?? {
        available: true,
        reason: null,
        nodeType: null,
        configFields: [],
        evidenceRefs: [],
      },
    marketplaceExposure:
      tool.marketplaceExposure ??
      tool.marketplace_exposure ?? {
        eligible: !approvalRequired && credentialReady && codingToolEffectIsReadOnly(effectClass),
        reason:
          !approvalRequired && credentialReady && codingToolEffectIsReadOnly(effectClass)
            ? "Read-only coding tool is eligible for governed exposure."
            : "Requires authority review before exposure.",
        trustRequired: approvalRequired,
        versionPinned: true,
        evidenceRefs: [],
      },
    workflowNodeType,
    workflowConfigFields,
  };
}

function codingToolEffectIsReadOnly(effectClass) {
  const normalized = String(effectClass ?? "").trim().toLowerCase();
  return normalized === "read" || normalized === "local_read" || normalized.endsWith("_read");
}

function codingToolEffectIsExternal(effectClass) {
  const normalized = String(effectClass ?? "").trim().toLowerCase();
  return (
    normalized.includes("external") ||
    normalized.includes("connector") ||
    normalized.includes("destructive") ||
    normalized.includes("commerce")
  );
}

function codingToolLikelyRequiresCredential(stableToolId, riskDomain, effectClass) {
  const haystack = `${stableToolId} ${riskDomain} ${effectClass}`.toLowerCase();
  return haystack.includes("connector") || haystack.includes("mcp") || haystack.includes("model") || haystack.includes("oauth");
}

export function codingToolInputForRequest(request = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return {};
  const input = Object.hasOwn(request, "input") ? request.input : request;
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  return input;
}

export function codingToolStepModuleProjection(toolId, input = {}, result = {}, context = {}) {
  const contract = codingToolContracts().find((candidate) => candidate.stableToolId === toolId);
  if (!contract) {
    throw codingToolError(404, "not_found", `Coding tool not found: ${toolId}`, {
      toolId,
      pack: CODING_TOOL_PACK_ID,
    });
  }
  return createCodingToolStepModuleProjection({
    contract,
    toolId,
    input,
    result,
    runId: context.runId ?? context.run_id,
    taskId: context.taskId ?? context.task_id,
    threadId: context.threadId ?? context.thread_id ?? null,
    workflowGraphId: context.workflowGraphId ?? context.workflow_graph_id,
    workflowNodeId: context.workflowNodeId ?? context.workflow_node_id,
    contextChamberRef: context.contextChamberRef ?? context.context_chamber_ref ?? null,
    actionProposalRef: context.actionProposalRef ?? context.action_proposal_ref,
    gateResultRef: context.gateResultRef ?? context.gate_result_ref,
    actorId: context.actorId ?? context.actor_id,
    runtimeNodeRef: context.runtimeNodeRef ?? context.runtime_node_ref,
    policyHash: context.policyHash ?? context.policy_hash,
    authorityGrantRefs: context.authorityGrantRefs ?? context.authority_grant_refs ?? [],
    approvalRef: context.approvalRef ?? context.approval_ref ?? null,
    stateRootBefore: context.stateRootBefore ?? context.state_root_before ?? null,
    projectionWatermark: context.projectionWatermark ?? context.projection_watermark ?? null,
    idempotencyKey: context.idempotencyKey ?? context.idempotency_key,
    deadlineMs: context.deadlineMs ?? context.deadline_ms,
    status: context.status ?? "success",
    workflowProjectionStatus: context.workflowProjectionStatus ?? context.workflow_projection_status ?? "projected",
    executionResultRef: context.executionResultRef ?? context.execution_result_ref ?? null,
    normalizedObservationRef: context.normalizedObservationRef ?? context.normalized_observation_ref ?? null,
    receiptRefs: context.receiptRefs ?? context.receipt_refs ?? null,
    artifactRefs: context.artifactRefs ?? context.artifact_refs ?? [],
    payloadRefs: context.payloadRefs ?? context.payload_refs ?? [],
    agentgresOperationRefs: context.agentgresOperationRefs ?? context.agentgres_operation_refs ?? [],
    stateRootAfter: context.stateRootAfter ?? context.state_root_after ?? null,
    resultingHead: context.resultingHead ?? context.resulting_head ?? null,
    evidenceRefs: context.evidenceRefs ?? context.evidence_refs ?? [],
    modelReentryRequired: context.modelReentryRequired ?? context.model_reentry_required ?? false,
    verifierRequired: context.verifierRequired ?? context.verifier_required ?? false,
  });
}

export function codingToolInputSummary(toolId, input = {}) {
  if (toolId === "file.inspect") return { path: optionalString(input.path) ?? null };
  if (toolId === "file.apply_patch") {
    return {
      path: optionalString(input.path) ?? null,
      dryRun: Boolean(input.dryRun ?? input.dry_run),
      editCount: normalizePatchEdits(input).length,
    };
  }
  if (toolId === "test.run") {
    return {
      commandId: optionalString(input.commandId ?? input.command_id) ?? "node.test",
      paths: codingToolRawPathSummary(input),
      cwd: optionalString(input.cwd) ?? ".",
      timeoutMs: input.timeoutMs ?? input.timeout_ms ?? null,
    };
  }
  if (toolId === "lsp.diagnostics") {
    return {
      commandId: optionalString(input.commandId ?? input.command_id) ?? "auto",
      paths: codingToolRawPathSummary(input),
      cwd: optionalString(input.cwd) ?? ".",
      timeoutMs: input.timeoutMs ?? input.timeout_ms ?? null,
    };
  }
  if (toolId === "artifact.read") {
    return {
      artifactId: optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref) ?? null,
      offsetBytes: Number(input.offsetBytes ?? input.offset_bytes ?? 0),
      lengthBytes: input.lengthBytes ?? input.length_bytes ?? input.maxBytes ?? input.max_bytes ?? null,
    };
  }
  if (toolId === "tool.retrieve_result") {
    return {
      toolCallId: optionalString(input.toolCallId ?? input.tool_call_id) ?? null,
      artifactId: optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref) ?? null,
      channel: optionalString(input.channel) ?? null,
    };
  }
  if (toolId === "computer_use.request_lease") {
    return {
      lane: computerUseLaneForInput(input),
      sessionMode: computerUseSessionModeForInput(input),
      actionKind: computerUseActionKindForInput(input),
      url: optionalString(input.url) ?? null,
    };
  }
  if (toolId === "git.diff") return { paths: codingToolRawPathSummary(input) };
  if (toolId === "workspace.status") {
    return { includeIgnored: Boolean(input.includeIgnored ?? input.include_ignored) };
  }
  return {};
}

export function codingToolResultSummary(toolId, result = {}) {
  if (toolId === "workspace.status") {
    return {
      changed: Number(result?.counts?.changed ?? 0),
      branch: result?.git?.branch ?? null,
      gitAvailable: Boolean(result?.git?.available),
    };
  }
  if (toolId === "git.diff") {
    return {
      paths: normalizeArray(result?.paths),
      diffBytes: Number(result?.diffBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "file.inspect") {
    return {
      path: result?.path ?? null,
      kind: result?.kind ?? null,
      sizeBytes: Number(result?.sizeBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "file.apply_patch") {
    return {
      path: result?.path ?? null,
      dryRun: Boolean(result?.dryRun),
      applied: Boolean(result?.applied),
      changed: Boolean(result?.changed),
      editCount: Number(result?.editCount ?? 0),
      changedFileCount: normalizeArray(result?.changedFiles).length,
      workspaceSnapshotId: result?.workspaceSnapshotId ?? result?.workspace_snapshot_id ?? null,
    };
  }
  if (toolId === "test.run") {
    return {
      commandId: result?.commandId ?? null,
      testStatus: result?.testStatus ?? null,
      exitCode: Number(result?.exitCode ?? 0),
      durationMs: Number(result?.durationMs ?? 0),
      truncated: Boolean(result?.truncated),
      spilloverRecommended: Boolean(result?.spilloverRecommended),
    };
  }
  if (toolId === "lsp.diagnostics") {
    return {
      commandId: result?.commandId ?? null,
      resolvedCommandId: result?.resolvedCommandId ?? null,
      backend: result?.backend ?? null,
      diagnosticStatus: result?.diagnosticStatus ?? null,
      diagnosticCount: Number(result?.diagnosticCount ?? 0),
      backendStatus: result?.backendStatus ?? null,
      fallbackUsed: Boolean(result?.fallbackUsed),
      truncated: Boolean(result?.truncated),
      spilloverRecommended: Boolean(result?.spilloverRecommended),
    };
  }
  if (toolId === "artifact.read") {
    return {
      artifactId: result?.artifactId ?? null,
      offsetBytes: Number(result?.offsetBytes ?? 0),
      lengthBytes: Number(result?.lengthBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "tool.retrieve_result") {
    return {
      toolCallId: result?.toolCallId ?? null,
      artifactId: result?.artifactId ?? null,
      offsetBytes: Number(result?.offsetBytes ?? 0),
      lengthBytes: Number(result?.lengthBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "computer_use.request_lease") {
    return {
      requestRef: result?.requestRef ?? null,
      lane: result?.leaseRequest?.lane ?? null,
      sessionMode: result?.leaseRequest?.sessionMode ?? null,
      actionKind: result?.leaseRequest?.actionKind ?? null,
      approvalRequiredBeforeExecution: Boolean(result?.approvalRequiredBeforeExecution),
    };
  }
  return {};
}

export function codingToolSummary(toolId, result = {}, status = "completed") {
  if (status === "failed") return `${toolId} failed.`;
  if (toolId === "workspace.status") {
    return `Workspace status inspected ${Number(result?.counts?.changed ?? 0)} changed file(s).`;
  }
  if (toolId === "git.diff") {
    return `Git diff inspected ${Number(result?.diffBytes ?? 0)} byte(s).`;
  }
  if (toolId === "file.inspect") {
    return `Inspected ${result?.kind ?? "path"} ${result?.path ?? ""}`.trim();
  }
  if (toolId === "file.apply_patch") {
    if (result?.dryRun) return `Patch previewed ${result?.path ?? "file"}.`;
    return result?.changed
      ? `Patch applied to ${result?.path ?? "file"}.`
      : `Patch checked ${result?.path ?? "file"} with no content change.`;
  }
  if (toolId === "test.run") {
    return `Test run ${result?.testStatus ?? "completed"} with exit code ${Number(result?.exitCode ?? 0)}.`;
  }
  if (toolId === "lsp.diagnostics") {
    return `Diagnostics ${result?.diagnosticStatus ?? "completed"} with ${Number(result?.diagnosticCount ?? 0)} finding(s).`;
  }
  if (toolId === "artifact.read") {
    return `Read artifact ${result?.artifactId ?? "artifact"}.`;
  }
  if (toolId === "tool.retrieve_result") {
    return `Retrieved tool result ${result?.toolCallId ?? result?.artifactId ?? "artifact"}.`;
  }
  if (toolId === "computer_use.request_lease") {
    return `Recorded computer-use lease request ${result?.requestRef ?? ""}`.trim();
  }
  return `${toolId} completed.`;
}

export function codingToolSourceEventKind(toolId) {
  return `CodingTool.${toolId
    .split(/[._-]/)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join("")}`;
}

function computerUseLaneForInput(input = {}) {
  const value = optionalString(input.lane ?? input.computerUseLane ?? input.computer_use_lane);
  if (value === "visual_gui" || value === "sandboxed_hosted") return value;
  return "native_browser";
}

function computerUseSessionModeForInput(input = {}) {
  const value = optionalString(input.sessionMode ?? input.session_mode);
  if (value) return value;
  const lane = computerUseLaneForInput(input);
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "local_sandbox";
  return "owned_hermetic_browser";
}

function computerUseActionKindForInput(input = {}) {
  const value = optionalString(input.actionKind ?? input.action_kind)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!value) return "inspect";
  if (value === "type" || value === "input_text") return "type_text";
  if (value === "keypress") return "key_press";
  if ([
    "click",
    "type_text",
    "key_press",
    "scroll",
    "drag",
    "hover",
    "select",
    "upload",
    "clipboard",
    "wait",
    "shell",
    "mobile_gesture",
    "navigate",
    "inspect",
  ].includes(value)) return value;
  return "inspect";
}

export function artifactReadRange(input = {}) {
  return {
    offsetBytes: boundedInteger(input.offsetBytes ?? input.offset_bytes, 0, 0, Number.MAX_SAFE_INTEGER),
    lengthBytes: boundedInteger(
      input.lengthBytes ?? input.length_bytes ?? input.maxBytes ?? input.max_bytes,
      CODING_TOOL_ARTIFACT_DEFAULT_READ_BYTES,
      1,
      CODING_TOOL_ARTIFACT_MAX_READ_BYTES,
    ),
  };
}

function codingToolPathList(value) {
  if (Array.isArray(value)) return value;
  const text = optionalString(value);
  return text ? [text] : [];
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function codingToolRawPathSummary(input = {}) {
  return [
    ...codingToolPathList(input.paths),
    ...codingToolPathList(input.path),
  ].map((value) => optionalString(value)).filter(Boolean);
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function normalizePatchEdits(input = {}) {
  const edits = Array.isArray(input.edits) ? input.edits.slice(0, CODING_TOOL_APPLY_PATCH_MAX_EDITS) : [];
  if (Object.hasOwn(input, "oldText") || Object.hasOwn(input, "old_text")) {
    edits.push({
      type: "replace",
      oldText: input.oldText ?? input.old_text,
      newText: input.newText ?? input.new_text ?? "",
      occurrence: input.occurrence,
    });
  }
  if (Object.hasOwn(input, "appendText") || Object.hasOwn(input, "append_text")) {
    edits.push({ type: "append", text: input.appendText ?? input.append_text ?? "" });
  }
  if (Object.hasOwn(input, "prependText") || Object.hasOwn(input, "prepend_text")) {
    edits.push({ type: "prepend", text: input.prependText ?? input.prepend_text ?? "" });
  }
  return edits
    .map((edit) => (edit && typeof edit === "object" && !Array.isArray(edit) ? edit : null))
    .filter(Boolean)
    .slice(0, CODING_TOOL_APPLY_PATCH_MAX_EDITS);
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => optionalString(item)).filter(Boolean);
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function codingToolError(status, code, message, details) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}
