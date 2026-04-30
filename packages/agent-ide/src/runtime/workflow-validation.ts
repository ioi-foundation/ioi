import type {
  Node,
  WorkflowConnectionClass,
  WorkflowNodeFixture,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import {
  actionKindForWorkflowNodeType,
  validateActionEdge,
  validateWorkflowConnection,
} from "./agent-execution-substrate";
import {
  workflowExpressionReferences,
  workflowFieldMappingEntries,
  workflowNodeDeclaredOutputSchema,
  workflowSchemaHasFieldPath,
  workflowSchemaIsObjectLike,
} from "./workflow-schema";

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
  const unsupportedRuntimeNodes: string[] = [];
  const policyRequiredNodes: string[] = [];
  const coverageByNodeId: Record<string, string[]> = {};
  const hasIncomingHumanGate = (nodeId: string) =>
    workflow.edges.some((edge) => {
      if (edge.to !== nodeId) return false;
      return nodeTypesById.get(edge.from) === "human_gate";
    });

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
  };
}

export function evaluateWorkflowActivationReadiness(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  baseResult: WorkflowValidationResult = validateWorkflowProject(workflow, tests),
  proposals: WorkflowProposal[] = [],
  fixtures: WorkflowNodeFixture[] | null = [],
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
