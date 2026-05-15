import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { makeWorkflowNode } from "./workflow-node-registry";
import { validateWorkflowProject } from "./workflow-validation";

function liveToolWorkflow(toolBinding: Record<string, unknown>): WorkflowProject {
  const workflow = makeDefaultWorkflow();
  return {
    ...workflow,
    nodes: [
      ...workflow.nodes,
      makeWorkflowNode("live-tool", "plugin_tool", "Live tool", 320, 160, {
        toolBinding: {
          toolRef: "filesystem.write",
          bindingKind: "plugin_tool",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: ["scope:filesystem:write"],
          sideEffectClass: "write",
          requiresApproval: true,
          ...toolBinding,
        },
      }),
    ],
  };
}

test("React Flow validation blocks live tool bindings missing authority metadata", () => {
  const validation = validateWorkflowProject(liveToolWorkflow({}), []);
  const codes = (validation.executionReadinessIssues ?? []).map(
    (issue) => issue.code,
  );

  assert.equal(validation.status, "blocked");
  assert.equal(codes.includes("missing_rate_limit_profile"), true);
  assert.equal(codes.includes("missing_receipt_behavior"), true);
  assert.equal(codes.includes("missing_idempotency_behavior"), true);
  assert.equal(codes.includes("missing_workflow_availability"), true);
  assert.equal(codes.includes("missing_agent_availability"), true);
});

test("React Flow validation accepts complete live tool authority metadata", () => {
  const validation = validateWorkflowProject(
    liveToolWorkflow({
      credentialReadiness: {
        status: "ready",
        checkedAt: "2026-05-15T00:00:00Z",
        evidenceRefs: ["credential:filesystem"],
      },
      rateLimitProfile: {
        policy: "workspace_local",
        maxCalls: 30,
        windowMs: 60000,
      },
      idempotencyBehavior: {
        required: true,
        strategy: "operation_hash",
      },
      receiptBehavior: {
        receiptRequired: true,
        requiredReceiptTypes: ["action", "verification"],
      },
      workflowAvailability: {
        available: true,
        reason: "Workflow manifest declares filesystem write capability.",
      },
      agentAvailability: {
        available: true,
        reason: "Agent runtime can request the tool capability.",
      },
      marketplaceExposure: {
        eligible: false,
        reason: "Local filesystem write capability is workspace-scoped.",
      },
    }),
    [],
  );
  const codes = (validation.executionReadinessIssues ?? []).map(
    (issue) => issue.code,
  );

  assert.equal(codes.includes("missing_rate_limit_profile"), false);
  assert.equal(codes.includes("missing_receipt_behavior"), false);
  assert.equal(codes.includes("missing_idempotency_behavior"), false);
  assert.equal(codes.includes("missing_workflow_availability"), false);
  assert.equal(codes.includes("missing_agent_availability"), false);
});

console.log("workflow-capability-contract-metadata.test.ts: ok");
