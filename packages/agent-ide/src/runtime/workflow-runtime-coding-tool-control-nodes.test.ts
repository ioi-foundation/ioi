import assert from "node:assert/strict";
import test from "node:test";

import {
  createRuntimeCodingToolControlRequest,
  createRuntimeCodingToolControlRequestFromWorkflowNode,
} from "./workflow-runtime-coding-tool-control-nodes";

test("React Flow coding-tool nodes compile approval policy into daemon requests", () => {
  const request = createRuntimeCodingToolControlRequest({
    threadId: "thread-coding-approval",
    toolId: "file.apply_patch",
    workflowGraphId: "workflow.coding-approval",
    workflowNodeId: "workflow.coding.file.apply_patch",
    requiresApproval: true,
    approvalMode: "human_required",
    trustProfile: "review_required",
    nodeApprovalOverride: "require_approval",
    toolInput: {
      path: "README.md",
      oldText: "before",
      newText: "after",
    },
    toolPack: {
      pack: "coding",
      writeEnabled: true,
      dryRun: false,
    },
  });

  assert.equal(
    request.endpoint,
    "/v1/threads/thread-coding-approval/tools/file.apply_patch/invoke",
  );
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.workflowGraphId, "workflow.coding-approval");
  assert.equal(request.body.workflowNodeId, "workflow.coding.file.apply_patch");
  assert.equal(request.body.toolId, "file.apply_patch");
  assert.equal(request.body.requiresApproval, true);
  assert.equal(request.body.approvalMode, "human_required");
  assert.equal(request.body.trustProfile, "review_required");
  assert.equal(request.body.nodeApprovalOverride, "require_approval");
  assert.equal(request.body.toolPack.coding.requiresApproval, true);
  assert.equal(request.body.toolPack.coding.approvalMode, "human_required");
  assert.equal(request.body.toolPack.coding.trustProfile, "review_required");
  assert.equal(request.body.toolPack.coding.nodeApprovalOverride, "require_approval");
});

test("workflow coding-tool pack binding compiles policy provenance", () => {
  const request = createRuntimeCodingToolControlRequestFromWorkflowNode(
    {
      id: "node-file-patch",
      type: "plugin_tool",
      config: {
        logic: {
          toolBinding: {
            toolRef: "file.apply_patch",
            bindingKind: "coding_tool_pack",
            mockBinding: false,
            credentialReady: true,
            capabilityScope: ["file.apply_patch"],
            sideEffectClass: "write",
            requiresApproval: true,
            arguments: {
              path: "README.md",
              oldText: "before",
              newText: "after",
            },
            toolPack: {
              pack: "coding",
              writeEnabled: true,
              approvalMode: "policy_required",
              trustProfile: "restricted",
              nodeApprovalOverride: "require_approval",
              requiresApproval: true,
            },
          },
        },
      },
    } as any,
    { threadId: "thread-from-node" },
    { workflowGraphId: "workflow.from-node" },
  );

  assert.equal(request.threadId, "thread-from-node");
  assert.equal(request.toolId, "file.apply_patch");
  assert.equal(request.body.approvalMode, "policy_required");
  assert.equal(request.body.trustProfile, "restricted");
  assert.equal(request.body.nodeApprovalOverride, "require_approval");
  assert.deepEqual(request.body.input, {
    path: "README.md",
    oldText: "before",
    newText: "after",
  });
});

test("workflow coding-tool pack binding compiles runtime telemetry summary budget gates", () => {
  const request = createRuntimeCodingToolControlRequestFromWorkflowNode(
    {
      id: "node-budgeted-file-patch",
      type: "plugin_tool",
      config: {
        logic: {
          toolBinding: {
            toolRef: "file.apply_patch",
            bindingKind: "coding_tool_pack",
            arguments: {
              path: "README.md",
              oldText: "before",
              newText: "after",
            },
            toolPack: {
              pack: "coding",
              writeEnabled: true,
              budgetMode: "block",
              budgetUsageField: "runtimeTelemetrySummary",
              maxTotalTokens: 100,
              maxCostUsd: 0.01,
              maxContextPressure: 0.5,
            },
          },
        },
      },
    } as any,
    {
      threadId: "thread-budgeted-coding-tool",
      runtimeTelemetrySummary: {
        schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
        status: "elevated",
        sourceKinds: ["runtime_usage_events"],
        threadIds: ["thread-budgeted-coding-tool"],
        turnIds: ["turn-budgeted-coding-tool"],
        workflowGraphIds: ["workflow.budgeted-coding-tool"],
        eventIds: ["evt_usage_budgeted_coding_tool"],
        inputTokens: 420,
        outputTokens: 300,
        totalTokens: 720,
        costEstimateUsd: 0.0042,
        contextPressure: 0.72,
        contextPressureStatus: "elevated",
        runCount: 1,
        subagentCount: 0,
        receiptRefs: ["receipt_usage_budgeted_coding_tool"],
        policyDecisionRefs: ["policy_context_budget_budgeted_coding_tool"],
      },
    },
    { workflowGraphId: "workflow.budgeted-coding-tool" },
  );

  assert.equal(request.body.budgetMode, "block");
  assert.equal(request.body.budget_mode, "block");
  assert.equal(request.body.thresholds.maxTotalTokens, 100);
  assert.equal(request.body.thresholds.max_cost_usd, 0.01);
  assert.equal(request.body.thresholds.maxContextPressure, 0.5);
  assert.equal(request.body.toolPack.coding.budgetUsageField, "runtimeTelemetrySummary");
  assert.equal(request.body.toolPack.coding.budget_mode, "block");

  const budgetUsageTelemetry = request.body.budgetUsageTelemetry as Record<
    string,
    unknown
  >;
  assert.equal(budgetUsageTelemetry.total_tokens, 720);
  assert.equal(budgetUsageTelemetry.estimated_cost_usd, 0.0042);
  assert.equal(budgetUsageTelemetry.context_pressure, 0.72);
  assert.equal(budgetUsageTelemetry.runtimeTelemetrySummarySchemaVersion, "ioi.workflow.runtime-telemetry-summary.v1");
  assert.deepEqual(request.body.budget_usage_telemetry, request.body.budgetUsageTelemetry);
});
