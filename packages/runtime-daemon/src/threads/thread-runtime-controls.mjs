import {
  RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
} from "../runtime-contract-constants.mjs";
import {
  isRuntimeServiceProfile,
} from "../runtime-api-bridge.mjs";
import {
  runtimeError,
} from "../runtime-http-utils.mjs";
import * as routeDecision from "../model-mounting/route-decision.mjs";

export function initialThreadRuntimeControls(options = {}, modelRoute = {}, now = new Date().toISOString()) {
  const mode = normalizeThreadInteractionMode(
    options.interaction_mode ?? "agent",
  );
  const approvalMode = normalizeThreadApprovalMode(
    options.approval_mode,
    approvalModeForThreadMode(mode),
  );
  return {
    schemaVersion: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
    schema_version: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
    mode,
    approvalMode,
    approval_mode: approvalMode,
    model: {
      id: modelRoute.requestedModelId ?? options.model?.id ?? options.model?.model ?? "auto",
      routeId: modelRoute.routeId ?? options.model?.route_id ?? options.route_id ?? "route.local-first",
      selectedModel: modelRoute.selectedModel ?? null,
      endpointId: modelRoute.endpointId ?? null,
      providerId: modelRoute.providerId ?? null,
      receiptId: modelRoute.receiptId ?? null,
      reasoningEffort: modelRoute.decision?.reasoning_effort ?? options.model?.reasoning_effort ?? options.model?.thinking ?? null,
      privacy: options.model?.privacy ?? null,
      maxCostUsd: options.model?.max_cost_usd ?? null,
      allow_hosted_fallback: options.model?.allow_hosted_fallback ?? null,
      workflowGraphId: modelRoute.decision?.workflow_graph_id ?? options.model?.workflow_graph_id ?? null,
      workflowNodeId: modelRoute.decision?.workflow_node_id ?? options.model?.workflow_node_id ?? "runtime.model-router",
      updatedAt: now,
    },
    updatedAt: now,
  };
}

export function normalizedAgentRuntimeControls(agent = {}) {
  const source = agent.runtimeControls ?? {};
  const mode = normalizeThreadInteractionMode(source.mode ?? agent.mode ?? "agent");
  const approvalMode = normalizeThreadApprovalMode(
    source.approvalMode ?? source.approval_mode ?? agent.approvalMode ?? agent.approval_mode,
    approvalModeForThreadMode(mode),
  );
  const model = source.model ?? {};
  return {
    schemaVersion: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
    schema_version: RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION,
    mode,
    approvalMode,
    approval_mode: approvalMode,
    model: {
      id: model.id ?? agent.requestedModelId ?? agent.modelId ?? "auto",
      routeId: model.routeId ?? model.route_id ?? agent.modelRouteId ?? "route.local-first",
      selectedModel: model.selectedModel ?? model.selected_model ?? agent.modelId ?? null,
      endpointId: model.endpointId ?? model.endpoint_id ?? agent.modelRouteEndpointId ?? null,
      providerId: model.providerId ?? model.provider_id ?? agent.modelRouteProviderId ?? null,
      receiptId: model.receiptId ?? model.receipt_id ?? agent.modelRouteReceiptId ?? null,
      reasoningEffort: model.reasoningEffort ?? model.reasoning_effort ?? agent.modelRouteDecision?.reasoning_effort ?? null,
      privacy: model.privacy ?? null,
      maxCostUsd: model.maxCostUsd ?? model.max_cost_usd ?? null,
      allow_hosted_fallback: model.allow_hosted_fallback ?? null,
      workflowGraphId: model.workflowGraphId ?? model.workflow_graph_id ?? agent.modelRouteDecision?.workflow_graph_id ?? null,
      workflowNodeId: model.workflowNodeId ?? model.workflow_node_id ?? agent.modelRouteDecision?.workflow_node_id ?? "runtime.model-router",
      updatedAt: model.updatedAt ?? model.updated_at ?? source.updatedAt ?? source.updated_at ?? agent.updatedAt ?? null,
    },
    updatedAt: source.updatedAt ?? source.updated_at ?? agent.updatedAt ?? null,
  };
}

export function requestWithThreadRuntimeControls(agent, request = {}) {
  const controls = normalizedAgentRuntimeControls(agent);
  const explicitOptions = request.options ?? {};
  const controlledOptions = {
    ...explicitOptions,
  };
  if (isRuntimeBackedAgent(agent) && !explicitOptions.model && controls.model) {
    controlledOptions.model = threadRuntimeControlModelForOptions(controls.model);
  }
  const mode = request.mode ?? runModeForThreadMode(controls.mode);
  return {
    ...request,
    mode,
    threadMode: request.thread_mode ?? controls.mode,
    approvalMode:
      request.approval_mode ??
      controls.approvalMode ??
      approvalModeForThreadMode(controls.mode),
    options: controlledOptions,
  };
}

export function threadRuntimeControlModelForOptions(model = {}) {
  return {
    id: model.id ?? "auto",
    routeId: model.routeId ?? model.route_id ?? "route.local-first",
    reasoningEffort: model.reasoningEffort ?? model.reasoning_effort ?? undefined,
    privacy: model.privacy ?? undefined,
    maxCostUsd: model.maxCostUsd ?? model.max_cost_usd ?? undefined,
    allow_hosted_fallback: model.allow_hosted_fallback ?? undefined,
    workflowGraphId: model.workflowGraphId ?? model.workflow_graph_id ?? undefined,
    workflowNodeId: model.workflowNodeId ?? model.workflow_node_id ?? "runtime.model-router",
    workflowNodeType: "Model Router",
  };
}

export function threadRuntimeControlKind(request = {}) {
  const value = optionalString(request.control ?? request.control_kind ?? request.kind ?? request.command)?.toLowerCase();
  if (value === "mode" || value === "model" || value === "thinking") return value;
  if (
    request.reasoning_effort !== undefined ||
    request.thinking !== undefined ||
    request.effort !== undefined
  ) {
    return "thinking";
  }
  if (request.model !== undefined || request.model_id !== undefined || request.route_id !== undefined) {
    return "model";
  }
  if (request.mode !== undefined || request.interaction_mode !== undefined) {
    return "mode";
  }
  throw runtimeError({
    status: 400,
    code: "thread_control_kind_required",
    message: "Thread runtime controls require mode, model, or thinking.",
    details: { requestKeys: Object.keys(request ?? {}) },
  });
}

export function threadRuntimeControlModelInput(request = {}, controls = {}, agent = {}) {
  const bodyModel =
    request.model && typeof request.model === "object" && !Array.isArray(request.model)
      ? request.model
      : {};
  const existingModel = controls.model ?? {};
  const modelId =
    optionalString(bodyModel.id ?? bodyModel.modelId ?? bodyModel.model_id) ??
    (typeof request.model === "string" ? optionalString(request.model) : undefined) ??
    optionalString(request.model_id ?? request.id) ??
    existingModel.id ??
    agent.requestedModelId ??
    agent.modelId ??
    "auto";
  const routeId =
    optionalString(bodyModel.routeId ?? bodyModel.route_id ?? bodyModel.route) ??
    optionalString(request.route_id ?? request.route) ??
    existingModel.routeId ??
    existingModel.route_id ??
    agent.modelRouteId ??
    "route.local-first";
  const reasoningEffort = normalizeReasoningEffort(
    bodyModel.reasoningEffort ??
      bodyModel.reasoning_effort ??
      bodyModel.thinking ??
      request.reasoning_effort ??
      request.thinking ??
      request.effort ??
      existingModel.reasoningEffort ??
      existingModel.reasoning_effort ??
      agent.modelRouteDecision?.reasoning_effort ??
      null,
    true,
  );
  const workflowNodeId =
    optionalString(
      bodyModel.workflowNodeId ??
        bodyModel.workflow_node_id ??
        request.workflow_node_id,
    ) ??
    existingModel.workflowNodeId ??
    existingModel.workflow_node_id ??
    "runtime.model-router";
  const model = {
    id: modelId,
    routeId,
    workflowNodeId,
    workflowNodeType: "Model Router",
  };
  if (reasoningEffort) model.reasoningEffort = reasoningEffort;
  for (const [key, snakeKey, outputKey] of [
    ["privacy", "privacy", "privacy"],
    ["maxCostUsd", "max_cost_usd", "maxCostUsd"],
    ["allow_hosted_fallback", "allow_hosted_fallback", "allow_hosted_fallback"],
    ["workflowGraphId", "workflow_graph_id", "workflowGraphId"],
  ]) {
    const value = bodyModel[key] ?? bodyModel[snakeKey] ?? request[key] ?? request[snakeKey] ?? existingModel[key] ?? existingModel[snakeKey];
    if (value !== undefined && value !== null) model[outputKey] = value;
  }
  return { model, workflowNodeId };
}

export function modelPolicyForOptions(options = {}) {
  const model = options.model ?? {};
  const policy = {
    ...(options.model_policy ?? options.modelPolicy ?? {}),
    ...(model.policy ?? model.model_policy ?? model.modelPolicy ?? {}),
  };
  if (model.provider && policy.provider === undefined) policy.provider = model.provider;
  if (model.reasoningEffort && policy.reasoning_effort === undefined) {
    policy.reasoning_effort = model.reasoningEffort;
  }
  if (model.thinking && policy.reasoning_effort === undefined) {
    policy.reasoning_effort = model.thinking;
  }
  if (model.privacy && policy.privacy === undefined) policy.privacy = model.privacy;
  if (model.maxCostUsd !== undefined && policy.max_cost_usd === undefined) {
    policy.max_cost_usd = model.maxCostUsd;
  }
  if (model.max_cost_usd !== undefined && policy.max_cost_usd === undefined) {
    policy.max_cost_usd = model.max_cost_usd;
  }
  if (model.allow_hosted_fallback !== undefined && policy.allow_hosted_fallback === undefined) {
    policy.allow_hosted_fallback = model.allow_hosted_fallback;
  }
  return policy;
}

export function modelWorkflowContext({ model = {}, options = {}, context = {} } = {}) {
  const workflow = options.workflow ?? model.workflow ?? {};
  return {
    workflow_graph_id:
      model.workflowGraphId ??
      model.workflow_graph_id ??
      options.workflowGraphId ??
      options.workflow_graph_id ??
      workflow.graphId ??
      workflow.graph_id ??
      context.workflowGraphId ??
      null,
    workflow_node_id:
      model.workflowNodeId ??
      model.workflow_node_id ??
      options.workflowNodeId ??
      options.workflow_node_id ??
      workflow.nodeId ??
      workflow.node_id ??
      context.workflowNodeId ??
      "runtime.model-router",
    workflow_node_type:
      model.workflowNodeType ??
      model.workflow_node_type ??
      options.workflowNodeType ??
      options.workflow_node_type ??
      workflow.nodeType ??
      workflow.node_type ??
      context.workflowNodeType ??
      "Model Router",
  };
}

export function modelRouteBindingFromReceipt(receipt, requestedModelId) {
  const decision = routeDecision.routeDecisionProjectionFromReceipt(receipt);
  return {
    requestedModelId: decision?.requested_model ?? requestedModelId ?? "auto",
    selectedModel: decision?.selected_model ?? requestedModelId ?? null,
    routeId: decision?.route_id ?? null,
    endpointId: decision?.endpoint_id ?? null,
    providerId: decision?.provider_id ?? null,
    receiptId: receipt.id,
    decision,
  };
}

export function normalizeThreadInteractionMode(value) {
  const mode = optionalString(value)?.toLowerCase().replace(/-/g, "_") ?? "agent";
  if (["agent", "send", "chat", "run", "tui"].includes(mode)) return "agent";
  if (["plan", "planning", "read_only", "readonly"].includes(mode)) return "plan";
  if (["review", "review_mode", "human_review", "approval_review"].includes(mode)) return "review";
  if (["yolo", "auto", "auto_local", "never_prompt"].includes(mode)) return "yolo";
  if (["custom", "dry_run", "handoff", "learn"].includes(mode)) return "custom";
  throw runtimeError({
    status: 400,
    code: "thread_mode_invalid",
    message: "Thread mode must be plan, review, agent, yolo, or custom.",
    details: { mode: value ?? null },
  });
}

export function normalizeThreadApprovalMode(value, fallback = "suggest") {
  const mode = optionalString(value)?.toLowerCase().replace(/-/g, "_");
  if (!mode) return fallback;
  if (["suggest", "auto_local", "never_prompt", "human_required", "policy_required"].includes(mode)) {
    return mode;
  }
  throw runtimeError({
    status: 400,
    code: "approval_mode_invalid",
    message: "Approval mode must be suggest, auto_local, never_prompt, human_required, or policy_required.",
    details: { approvalMode: value ?? null },
  });
}

export function approvalModeForThreadMode(mode) {
  switch (normalizeThreadInteractionMode(mode)) {
    case "plan":
    case "review":
      return "human_required";
    case "yolo":
      return "never_prompt";
    case "agent":
    case "custom":
    default:
      return "suggest";
  }
}

export function runModeForThreadMode(mode) {
  switch (normalizeThreadInteractionMode(mode)) {
    case "plan":
    case "review":
      return "plan";
    case "agent":
    case "yolo":
    case "custom":
    default:
      return "send";
  }
}

export function threadModeForRunMode(runMode, fallback = "agent") {
  const mode = optionalString(runMode)?.toLowerCase().replace(/-/g, "_");
  if (mode === "plan") return "plan";
  if (mode === "send" || mode === "agent" || mode === "tui") return normalizeThreadInteractionMode(fallback);
  return normalizeThreadInteractionMode(fallback);
}

export function normalizeReasoningEffort(value, allowNull = false) {
  const effort = optionalString(value)?.toLowerCase();
  if (!effort) return allowNull ? null : "medium";
  if (["provider_default", "default", "auto"].includes(effort)) {
    return allowNull ? null : "medium";
  }
  if (["off", "disabled"].includes(effort)) return "none";
  if (["none", "low", "medium", "high", "xhigh"].includes(effort)) return effort;
  throw runtimeError({
    status: 400,
    code: "reasoning_effort_invalid",
    message: "Thinking controls accept none, low, medium, high, or xhigh.",
    details: { reasoningEffort: value ?? null },
  });
}

function isRuntimeBackedAgent(agent = {}) {
  return isRuntimeServiceProfile(agent.runtimeProfile);
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
