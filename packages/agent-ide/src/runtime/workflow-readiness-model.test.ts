import assert from "node:assert/strict";
import test from "node:test";
import type {
  Node,
  WorkflowProject,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import { workflowReadinessModel } from "./workflow-readiness-model";
import { workflowSchedulerLaneReadiness } from "./workflow-scheduler-lane-readiness";

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
