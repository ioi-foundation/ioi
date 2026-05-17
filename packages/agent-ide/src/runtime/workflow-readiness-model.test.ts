import assert from "node:assert/strict";
import test from "node:test";
import type {
  Node,
  WorkflowProject,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import {
  workflowCodingToolBudgetPreflight,
  workflowCodingToolBudgetRunLaunchAnnotation,
  workflowReadinessModel,
} from "./workflow-readiness-model";
import { workflowSchedulerLaneReadiness } from "./workflow-scheduler-lane-readiness";
import { createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow } from "./workflow-runtime-coding-tool-budget-recovery-subflow";
import { evaluateWorkflowActivationReadiness } from "./workflow-validation";

const issue = (code: string, message = code): WorkflowValidationIssue => ({
  code,
  message,
});

const validationResult = (
  overrides: Partial<WorkflowValidationResult> = {},
): WorkflowValidationResult => ({
  status: "passed",
  errors: [],
  warnings: [],
  blockedNodes: [],
  missingConfig: [],
  unsupportedRuntimeNodes: [],
  policyRequiredNodes: [],
  coverageByNodeId: {},
  connectorBindingIssues: [],
  executionReadinessIssues: [],
  verificationIssues: [],
  schedulerLaneReadiness: workflowSchedulerLaneReadiness(),
  ...overrides,
});

const workflow = (overrides: Partial<WorkflowProject> = {}): WorkflowProject =>
  ({
    version: "1",
    nodes: [
      {
        id: "trigger",
        type: "trigger",
        name: "Trigger",
        x: 0,
        y: 0,
        config: { logic: {} },
      },
      {
        id: "model",
        type: "model_call",
        name: "Model",
        x: 0,
        y: 0,
        config: { logic: { modelRef: "primary" } },
      },
      {
        id: "output",
        type: "output",
        name: "Output",
        x: 0,
        y: 0,
        config: { logic: {} },
      },
    ],
    edges: [],
    global_config: {
      env: "test",
      modelBindings: { primary: { modelId: "gpt-test" } },
      requiredCapabilities: {},
      policy: {
        maxBudget: 1,
        maxSteps: 4,
        timeoutMs: 1_000,
      },
      contract: {
        developerBond: 1,
        adjudicationRubric: "test",
      },
      meta: {
        name: "Test workflow",
        description: "Test workflow",
      },
    },
    metadata: {
      id: "workflow",
      name: "Workflow",
      slug: "workflow",
      workflowKind: "agent_workflow",
      executionMode: "mock",
    },
    ...overrides,
  }) as unknown as WorkflowProject;

const testCase = {
  id: "test",
  name: "Test",
  targetNodeIds: ["output"],
  assertion: { kind: "node_exists", expected: "output" },
} as WorkflowTestCase;

const model = (
  overrides: Partial<Parameters<typeof workflowReadinessModel>[0]> = {},
) =>
  workflowReadinessModel({
    validationResult: validationResult(),
    readinessResult: validationResult(),
    workflow: workflow(),
    tests: [testCase],
    operationalSideEffectNodes: [],
    hasErrorOrRetryPath: false,
    criticalAiNodeIds: [],
    productionProfile: {
      expectedTimeSavedMinutes: 5,
      mcpAccessReviewed: true,
    },
    coveredNodeIds: new Set(),
    mcpToolNodes: [],
    harnessWorkflow: false,
    harnessSlots: [],
    boundHarnessSlotIds: new Set(),
    harnessActivationReady: true,
    harnessDefaultRuntimeDispatchProof: null,
    harnessAuthorityGateLiveReady: true,
    ...overrides,
  });

const checklistReady = (
  readinessItems: ReturnType<typeof model>["readinessItems"],
  label: string,
) => readinessItems.find((item) => item.label === label)?.ready;

test("workflow readiness model reports all scheduler lanes ready from the manifest", () => {
  const readiness = model();

  assert.equal(readiness.schedulerLaneReadiness.length, 10);
  assert.equal(readiness.schedulerLaneReadyCount, 10);
  assert.equal(checklistReady(readiness.readinessItems, "Scheduler lanes"), true);
  assert.equal(checklistReady(readiness.readinessItems, "No blockers"), true);
  assert.equal(readiness.attentionIssues.length, 0);
});

test("workflow readiness model blocks the scheduler checklist when manifest lanes are missing", () => {
  const readiness = model({
    readinessResult: validationResult({
      schedulerLaneReadiness: workflowSchedulerLaneReadiness([]),
    }),
  });

  assert.equal(readiness.schedulerLaneReadiness.length, 10);
  assert.equal(readiness.schedulerLaneReadyCount, 0);
  assert.equal(checklistReady(readiness.readinessItems, "Scheduler lanes"), false);
});

test("workflow readiness model aggregates blockers before warnings", () => {
  const readiness = model({
    readinessResult: validationResult({
      status: "blocked",
      errors: [issue("error")],
      executionReadinessIssues: [issue("execution")],
      missingConfig: [issue("missing_config")],
      connectorBindingIssues: [issue("connector_binding")],
      verificationIssues: [issue("verification")],
      warnings: [issue("missing_replay_fixture")],
    }),
  });

  assert.equal(readiness.blockers.length, 5);
  assert.equal(readiness.readinessWarnings.length, 1);
  assert.deepEqual(
    readiness.attentionIssues.map((attention) => attention.status),
    ["blocked", "blocked", "blocked", "blocked", "blocked", "warning"],
  );
  assert.equal(checklistReady(readiness.readinessItems, "Replay samples"), false);
  assert.equal(checklistReady(readiness.readinessItems, "No blockers"), false);
});

test("workflow readiness model treats an incoming model-class edge as a model binding", () => {
  const provider = {
    id: "provider",
    type: "model_binding",
    name: "Provider",
    x: 0,
    y: 0,
    config: { logic: {} },
  } as Node;
  const readiness = model({
    workflow: workflow({
      nodes: [
        provider,
        {
          id: "model",
          type: "model_call",
          name: "Model",
          x: 0,
          y: 0,
          config: { logic: { modelRef: "missing" } },
        } as Node,
        {
          id: "trigger",
          type: "trigger",
          name: "Trigger",
          x: 0,
          y: 0,
        } as Node,
        {
          id: "output",
          type: "output",
          name: "Output",
          x: 0,
          y: 0,
        } as Node,
      ],
      edges: [
        {
          id: "edge-model",
          from: "provider",
          to: "model",
          fromPort: "model",
          toPort: "model",
          type: "data",
          connectionClass: "model",
        },
      ],
      global_config: {
        ...workflow().global_config,
        modelBindings: {},
      },
    }),
  });

  assert.equal(checklistReady(readiness.readinessItems, "Model binding"), true);
});

test("workflow readiness model blocks mutating coding tools on prior TUI budget evidence", () => {
  const codingToolNode = {
    id: "workflow.coding.file.apply_patch.followup",
    type: "plugin_tool",
    name: "Apply patch",
    x: 0,
    y: 0,
    config: {
      logic: {
        toolBinding: {
          bindingKind: "coding_tool_pack",
          toolRef: "file.apply_patch",
          sideEffectClass: "write",
        },
      },
    },
  } as Node;
  const readiness = model({
    workflow: workflow({
      nodes: [...workflow().nodes, codingToolNode],
    }),
    runtimeCodingToolBudgetEvidence: {
      sourceKind: "tui_coding_tool_rows",
      label: "TUI coding budget evidence",
      status: "blocked",
      rowCount: 1,
      eventIds: ["event-budget"],
      workflowNodeIds: ["workflow.coding.file.apply_patch.prior"],
      toolNames: ["file.apply_patch"],
      toolCallIds: ["tool-call-budget"],
      budgetStatuses: ["exceeded"],
      contextBudgetStatuses: ["blocked"],
      totalTokens: 720,
      costEstimateUsd: 0.0042,
      contextPressure: 0.72,
      contextPressureStatus: "blocked",
      mutationBlocked: true,
      receiptRefs: ["receipt-budget"],
      policyDecisionRefs: ["policy-budget"],
    },
  });

  assert.equal(
    checklistReady(readiness.readinessItems, "Coding budget preflight"),
    false,
  );
  assert.equal(checklistReady(readiness.readinessItems, "No blockers"), false);
  assert.equal(readiness.codingToolBudgetPreflight?.status, "blocked");
  assert.equal(
    readiness.codingToolBudgetPreflight?.issue.nodeId,
    "workflow.coding.file.apply_patch.followup",
  );
  assert.equal(
    readiness.codingToolBudgetPreflight?.issue.code,
    "prior_coding_tool_budget_evidence",
  );
  assert.match(
    readiness.codingToolBudgetPreflight?.issue.message ?? "",
    /event-budget/,
  );
  assert.match(
    readiness.codingToolBudgetPreflight?.issue.message ?? "",
    /tool-call-budget/,
  );
  assert.match(
    readiness.codingToolBudgetPreflight?.issue.message ?? "",
    /policy-budget/,
  );
  assert.deepEqual(readiness.codingToolBudgetPreflight?.targetNodeIds, [
    "workflow.coding.file.apply_patch.followup",
  ]);
  assert.deepEqual(readiness.codingToolBudgetPreflight?.policyDecisionRefs, [
    "policy-budget",
  ]);
  assert.equal(
    readiness.blockers[readiness.blockers.length - 1]?.code,
    "prior_coding_tool_budget_evidence",
  );
  assert.equal(
    readiness.attentionIssues[readiness.attentionIssues.length - 1]?.status,
    "blocked",
  );
});

test("workflow readiness model exposes capability preflight repair actions", () => {
  const liveToolNode = {
    id: "tool",
    type: "plugin_tool",
    name: "External writer",
    x: 0,
    y: 0,
    config: {
      kind: "plugin_tool",
      logic: {
        toolBinding: {
          toolRef: "external.crm.write",
          toolCapabilityRef: "tool-capability:external.crm.write",
          bindingKind: "plugin_tool",
          mockBinding: false,
          credentialReady: false,
          credentialReadiness: { status: "unknown" },
          grantReadiness: { status: "unknown" },
          policyPosture: { status: "unknown" },
          workflowAvailability: { available: false },
          agentAvailability: { available: false },
          receiptBehavior: {
            receiptRequired: false,
            requiredReceiptTypes: [],
          },
          authorityScopes: [],
          authorityScopeRequirements: [],
          capabilityScope: ["write"],
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      },
      law: {},
    },
  } as Node;
  const readiness = model({
    workflow: workflow({
      nodes: [...workflow().nodes, liveToolNode],
    }),
  });

  assert.equal(
    checklistReady(readiness.readinessItems, "Capability preflight"),
    false,
  );
  assert.equal(checklistReady(readiness.readinessItems, "No blockers"), false);
  assert.equal(readiness.capabilityPreflight?.status, "blocked");
  assert.deepEqual(readiness.capabilityPreflight?.targetNodeIds, ["tool"]);
  assert.equal(
    readiness.capabilityPreflight?.rows[0]?.capabilityRef,
    "tool-capability:external.crm.write",
  );
  assert.deepEqual(
    readiness.capabilityPreflight?.rows[0]?.repairActions.map(
      (action) => action.kind,
    ),
    [
      "open_capability_binding",
      "request_authority_grant",
      "apply_approved_grant",
      "attach_ready_capability",
      "review_receipt_policy",
    ],
  );
  assert.equal(
    readiness.blockers.some(
      (blocker) => blocker.code === "workflow_capability_preflight_blocked",
    ),
    true,
  );
});

test("workflow coding budget preflight creates run launch annotations", () => {
  const preflight = workflowCodingToolBudgetPreflight({
    workflow: workflow({
      nodes: [
        ...workflow().nodes,
        {
          id: "workflow.coding.file.apply_patch.followup",
          type: "plugin_tool",
          name: "Apply patch",
          x: 0,
          y: 0,
          config: {
            logic: {
              toolBinding: {
                bindingKind: "coding_tool_pack",
                toolRef: "file.apply_patch",
                sideEffectClass: "write",
                toolPack: {
                  pack: "coding",
                  budgetRecoveryApprovalScope: "target_nodes",
                  budgetRecoveryTargetNodeIds: [
                    "workflow.coding.file.apply_patch.followup",
                  ],
                  budgetRecoveryRetryLimit: 2,
                  budgetRecoveryTtlMs: 300000,
                  budgetRecoveryOperatorRole: "budget_operator",
                  budgetRecoveryAllowOverride: true,
                  budgetRecoveryRequiresApproval: true,
                },
              },
            },
          },
        } as Node,
      ],
    }),
    evidence: {
      sourceKind: "tui_coding_tool_rows",
      label: "TUI coding budget evidence",
      status: "elevated",
      rowCount: 2,
      eventIds: ["event-budget"],
      workflowNodeIds: ["workflow.coding.file.apply_patch.prior"],
      toolNames: ["file.apply_patch"],
      toolCallIds: ["tool-call-budget"],
      budgetStatuses: ["warn"],
      contextBudgetStatuses: ["warn"],
      totalTokens: 420,
      costEstimateUsd: 0.0024,
      contextPressure: 0.62,
      contextPressureStatus: "elevated",
      mutationBlocked: false,
      receiptRefs: ["receipt-budget"],
      policyDecisionRefs: ["policy-budget"],
    },
  });

  const annotation = workflowCodingToolBudgetRunLaunchAnnotation(preflight);

  assert.equal(
    annotation?.schemaVersion,
    "ioi.workflow.coding-tool-budget-preflight.v1",
  );
  assert.equal(annotation?.status, "warning");
  assert.deepEqual(annotation?.targetNodeIds, [
    "workflow.coding.file.apply_patch.followup",
  ]);
  assert.equal(
    annotation?.recoveryPolicy.schemaVersion,
    "ioi.workflow.coding-tool-budget-recovery-policy.v1",
  );
  assert.equal(annotation?.recoveryPolicy.operatorRole, "budget_operator");
  assert.equal(annotation?.recoveryPolicy.retryLimit, 2);
  assert.equal(annotation?.recoveryPolicy.ttlMs, 300000);
  assert.deepEqual(annotation?.recoveryPolicy.targetNodeIds, [
    "workflow.coding.file.apply_patch.followup",
  ]);
  assert.deepEqual(annotation?.toolCallIds, ["tool-call-budget"]);
  assert.deepEqual(annotation?.policyDecisionRefs, ["policy-budget"]);
  assert.equal(annotation?.issueCode, "prior_coding_tool_budget_evidence");
  assert.match(annotation?.issueMessage ?? "", /reported tool-call-budget/);
});

test("workflow activation readiness blocks unbound coding-tool budget recovery templates", () => {
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow({
    idPrefix: "budget-recovery-template",
    workflowGraphId: "workflow",
  });
  const baseWorkflow = workflow();
  const templateWorkflow = workflow({
    nodes: [
      baseWorkflow.nodes.find((node) => node.id === "trigger")!,
      baseWorkflow.nodes.find((node) => node.id === "output")!,
      ...subflow.nodes,
    ],
  });
  const readiness = evaluateWorkflowActivationReadiness(
    templateWorkflow,
    [testCase],
    validationResult(),
  );
  const bindingIssues = (readiness.executionReadinessIssues ?? []).filter((issue) =>
    issue.code.startsWith(
      "missing_runtime_coding_tool_budget_recovery_",
    ),
  );

  assert.equal(readiness.status, "blocked");
  assert.equal(bindingIssues.length, subflow.nodes.length * 5);
  assert.deepEqual(
    new Set(bindingIssues.map((issue) => issue.code)),
    new Set([
      "missing_runtime_coding_tool_budget_recovery_run_binding",
      "missing_runtime_coding_tool_budget_recovery_thread_binding",
      "missing_runtime_coding_tool_budget_recovery_approval_binding",
      "missing_runtime_coding_tool_budget_recovery_target_binding",
      "missing_runtime_coding_tool_budget_recovery_policy_binding",
    ]),
  );
  assert(
    bindingIssues.every((issue) => issue.nodeId?.startsWith("budget-recovery-template-")),
  );
  assert(
    bindingIssues.some(
      (issue) =>
        issue.nodeId === subflow.requestNodeId &&
        issue.code === "missing_runtime_coding_tool_budget_recovery_run_binding" &&
        issue.fieldPath === "runtimeCodingToolBudgetRecoveryRunIdField" &&
        issue.repairLabel === "Bind recovery input",
    ),
  );
});

test("workflow activation readiness accepts mapped coding-tool budget recovery template inputs", () => {
  const subflow = createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow({
    idPrefix: "budget-recovery-template-bound",
    workflowGraphId: "workflow",
  });
  const bindRecoveryInputs = (node: Node): Node => ({
    ...node,
    config: {
      ...(node.config as NonNullable<Node["config"]>),
      logic: {
        ...node.config?.logic,
        fieldMappings: {
          runId: {
            source: "{{nodes.recovery-runtime-input.output}}",
            path: "runId",
            type: "string",
          },
          threadId: {
            source: "{{nodes.recovery-runtime-input.output}}",
            path: "threadId",
            type: "string",
          },
          approvalId: {
            source: "{{nodes.recovery-runtime-input.output}}",
            path: "approvalId",
            type: "string",
          },
          targetNodeIds: {
            source: "{{nodes.recovery-runtime-input.output}}",
            path: "targetNodeIds",
            type: "array",
          },
          recoveryPolicy: {
            source: "{{nodes.recovery-runtime-input.output}}",
            path: "recoveryPolicy",
            type: "object",
          },
        },
      },
    } as NonNullable<Node["config"]>,
  });
  const baseWorkflow = workflow();
  const templateWorkflow = workflow({
    nodes: [
      baseWorkflow.nodes.find((node) => node.id === "trigger")!,
      baseWorkflow.nodes.find((node) => node.id === "output")!,
      ...subflow.nodes.map(bindRecoveryInputs),
    ],
  });
  const readiness = evaluateWorkflowActivationReadiness(
    templateWorkflow,
    [testCase],
    validationResult(),
  );

  assert.equal(
    (readiness.executionReadinessIssues ?? []).some((issue) =>
      issue.code.startsWith(
        "missing_runtime_coding_tool_budget_recovery_",
      ),
    ),
    false,
  );
});
