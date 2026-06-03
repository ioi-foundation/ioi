import assert from "node:assert/strict";
import test from "node:test";

import {
  approvalModeForThreadMode,
  initialThreadRuntimeControls,
  modelPolicyForOptions,
  modelRouteBindingFromReceipt,
  modelWorkflowContext,
  normalizeReasoningEffort,
  normalizeThreadApprovalMode,
  normalizeThreadInteractionMode,
  normalizedAgentRuntimeControls,
  requestWithThreadRuntimeControls,
  runModeForThreadMode,
  threadModeForRunMode,
  threadRuntimeControlKind,
  threadRuntimeControlModelInput,
} from "./thread-runtime-controls.mjs";

test("thread mode and approval aliases normalize to daemon control values", () => {
  assert.equal(normalizeThreadInteractionMode("read-only"), "plan");
  assert.equal(normalizeThreadInteractionMode("human_review"), "review");
  assert.equal(normalizeThreadInteractionMode("never-prompt"), "yolo");
  assert.equal(normalizeThreadApprovalMode("policy-required"), "policy_required");
  assert.equal(approvalModeForThreadMode("review"), "human_required");
  assert.equal(approvalModeForThreadMode("yolo"), "never_prompt");
  assert.equal(runModeForThreadMode("plan"), "plan");
  assert.equal(runModeForThreadMode("agent"), "send");
  assert.equal(threadModeForRunMode("send", "review"), "review");
});

test("initial and normalized runtime controls preserve schema and model route fields", () => {
  const controls = initialThreadRuntimeControls(
    {
      mode: "plan",
      model: { id: "auto", routeId: "route.local-first", privacy: "local_private" },
    },
    {
      requestedModelId: "auto",
      selectedModel: "local-model",
      routeId: "route.local-first",
      endpointId: "endpoint-1",
      providerId: "provider-1",
      receiptId: "receipt-1",
      decision: { reasoningEffort: "low", workflowGraphId: "graph-1", workflowNodeId: "node-1" },
    },
    "2026-06-03T00:00:00.000Z",
  );

  assert.equal(controls.schema_version, "ioi.runtime.thread-controls.v1");
  assert.equal(controls.mode, "plan");
  assert.equal(controls.approvalMode, "human_required");
  assert.equal(controls.model.selectedModel, "local-model");
  assert.equal(controls.model.reasoningEffort, "low");

  assert.deepEqual(normalizedAgentRuntimeControls({
    mode: "chat",
    requestedModelId: "requested-model",
    modelRouteId: "route.test",
    modelRouteEndpointId: "endpoint-test",
  }).model, {
    id: "requested-model",
    routeId: "route.test",
    selectedModel: null,
    endpointId: "endpoint-test",
    providerId: null,
    receiptId: null,
    reasoningEffort: null,
    privacy: null,
    maxCostUsd: null,
    allowHostedFallback: null,
    workflowGraphId: null,
    workflowNodeId: "runtime.model-router",
    updatedAt: null,
  });
});

test("runtime-backed requests inherit model controls without overriding explicit options", () => {
  const agent = {
    runtimeProfile: "runtime_service",
    runtimeControls: {
      mode: "review",
      approvalMode: "human_required",
      model: {
        id: "auto",
        routeId: "route.local-first",
        reasoningEffort: "high",
        workflowNodeId: "node-1",
      },
    },
  };

  const controlled = requestWithThreadRuntimeControls(agent, { prompt: "ship it", options: {} });
  assert.equal(controlled.mode, "plan");
  assert.equal(controlled.threadMode, "review");
  assert.equal(controlled.approvalMode, "human_required");
  assert.deepEqual(controlled.options.model, {
    id: "auto",
    routeId: "route.local-first",
    reasoningEffort: "high",
    privacy: undefined,
    maxCostUsd: undefined,
    allowHostedFallback: undefined,
    workflowGraphId: undefined,
    workflowNodeId: "node-1",
    workflowNodeType: "Model Router",
  });

  const explicit = requestWithThreadRuntimeControls(agent, {
    options: { model: { id: "explicit" } },
  });
  assert.deepEqual(explicit.options.model, { id: "explicit" });
});

test("thread control request kind and model input infer compact operator updates", () => {
  assert.equal(threadRuntimeControlKind({ thinking: "off" }), "thinking");
  assert.equal(threadRuntimeControlKind({ modelId: "auto" }), "model");
  assert.equal(threadRuntimeControlKind({ interactionMode: "plan" }), "mode");

  const input = threadRuntimeControlModelInput(
    {
      model: {
        model_id: "model-1",
        route: "route-1",
        thinking: "off",
        max_cost_usd: 0.05,
      },
    },
    { model: { workflowNodeId: "existing-node" } },
    {},
  );
  assert.deepEqual(input, {
    model: {
      id: "model-1",
      routeId: "route-1",
      workflowNodeId: "existing-node",
      workflowNodeType: "Model Router",
      reasoningEffort: "none",
      maxCostUsd: 0.05,
    },
    workflowNodeId: "existing-node",
  });
});

test("model policy, workflow context, reasoning effort, and route receipt binding stay stable", () => {
  assert.deepEqual(modelPolicyForOptions({
    model: {
      provider: "local",
      reasoningEffort: "medium",
      allowHostedFallback: false,
    },
  }), {
    provider: "local",
    reasoning_effort: "medium",
    allow_hosted_fallback: false,
  });

  assert.deepEqual(modelWorkflowContext({
    options: { workflow: { graph_id: "graph-1", node_id: "node-1", node_type: "Model Router" } },
  }), {
    workflow_graph_id: "graph-1",
    workflow_node_id: "node-1",
    workflow_node_type: "Model Router",
  });

  assert.equal(normalizeReasoningEffort("default", true), null);
  assert.equal(normalizeReasoningEffort("disabled"), "none");
  assert.throws(() => normalizeReasoningEffort("maximum"), /Thinking controls accept/);

  const binding = modelRouteBindingFromReceipt({
    id: "receipt-1",
    details: {
      modelRouteDecision: {
        requestedModel: "auto",
        selectedModel: "local-model",
        routeId: "route.local-first",
        endpointId: "endpoint-1",
        providerId: "provider-1",
      },
    },
  }, "fallback-model");
  assert.equal(binding.requestedModelId, "auto");
  assert.equal(binding.selectedModel, "local-model");
  assert.equal(binding.receiptId, "receipt-1");
});
