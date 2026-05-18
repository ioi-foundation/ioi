import assert from "node:assert/strict";
import test from "node:test";

import type { Node, WorkflowProject, WorkflowValidationResult } from "../types/graph";
import {
  workflowCompatibleSearchRecovery,
  workflowNodeCreatorDefaultAddMode,
  workflowModelBindingKeyForNode,
  workflowSelectedNodeLifecycleSummary,
  workflowSelectedNodeRepairActions,
} from "./workflow-composer-model";
import type { WorkflowNodeDefinition } from "./workflow-node-registry";

const emptyValidation: WorkflowValidationResult = {
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
};

function workflow(nodes: Node[], edges: WorkflowProject["edges"] = []): WorkflowProject {
  return {
    version: "1",
    nodes,
    edges,
    global_config: {
      env: "test",
      modelBindings: {},
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
      executionMode: "local",
    },
  } as WorkflowProject;
}

test("agent step repair actions prioritize model binding and output", () => {
  const agent: Node = {
    id: "agent",
    type: "model_call",
    name: "Agent Step",
    x: 0,
    y: 0,
    config: {
      kind: "model_call",
      logic: { modelRef: "reasoning" },
      law: {},
    },
  };

  const actions = workflowSelectedNodeRepairActions({
    workflow: workflow([agent]),
    selectedNode: agent,
    validationResult: emptyValidation,
    tests: [],
  });

  assert.deepEqual(
    actions.map((action) => action.kind),
    [
      "bind_model_capability",
      "add_output",
      "add_evaluation",
      "check_readiness",
    ],
  );
  assert.equal(actions[0]?.priority, "primary");
  assert.equal(actions[0]?.bindingFocusKey, "reasoning");
});

test("tool node repair actions focus connector binding before topology helpers", () => {
  const tool: Node = {
    id: "browser",
    type: "plugin_tool",
    name: "Browser tool",
    x: 0,
    y: 0,
  };

  const actions = workflowSelectedNodeRepairActions({
    workflow: workflow([tool]),
    selectedNode: tool,
    validationResult: emptyValidation,
    tests: [],
  });

  assert.deepEqual(
    actions.map((action) => action.kind),
    [
      "bind_tool_capability",
      "connect_to_agent",
      "add_verifier",
      "check_readiness",
    ],
  );
  assert.equal(actions[0]?.priority, "primary");
});

test("repository context repair actions teach connection to an agent", () => {
  const repo: Node = {
    id: "repo",
    type: "repository_context",
    name: "Repository Context",
    x: 0,
    y: 0,
  };

  const actions = workflowSelectedNodeRepairActions({
    workflow: workflow([repo]),
    selectedNode: repo,
    validationResult: emptyValidation,
    tests: [],
  });

  assert.equal(actions[0]?.kind, "connect_to_agent");
  assert.equal(actions[0]?.label, "Connect to agent");
  assert.equal(actions[actions.length - 1]?.kind, "check_readiness");
});

test("model binding focus maps model node capability to global binding role", () => {
  assert.equal(
    workflowModelBindingKeyForNode({
      id: "vision-agent",
      type: "model_call",
      name: "Vision Agent",
      x: 0,
      y: 0,
      config: { kind: "model_call", logic: { modelRef: "vision" }, law: {} },
    }),
    "vision",
  );
  assert.equal(
    workflowModelBindingKeyForNode({
      id: "default-agent",
      type: "model_call",
      name: "Agent",
      x: 0,
      y: 0,
    }),
    "reasoning",
  );
});

test("compatible search recovery explains global matches hidden by compatibility", () => {
  const manualInput: Node = {
    id: "input",
    type: "source",
    name: "Manual input",
    x: 0,
    y: 0,
  };

  const recovery = workflowCompatibleSearchRecovery({
    query: "repo",
    nodeGroupFilter: "Compatible",
    selectedNode: manualInput,
    globalMatchCount: 4,
    compatibleMatchCount: 0,
  });

  assert.equal(
    recovery?.title,
    "No repo primitives connect directly from Manual input.",
  );
  assert.match(recovery?.message ?? "", /bridge step/);
  assert.equal(recovery?.recommendedBridgeLabel, "Add Agent Step");
});

test("compatible search recovery stays hidden when compatible matches exist", () => {
  const selectedNode: Node = {
    id: "agent",
    type: "model_call",
    name: "Agent Step",
    x: 0,
    y: 0,
  };

  assert.equal(
    workflowCompatibleSearchRecovery({
      query: "output",
      nodeGroupFilter: "Compatible",
      selectedNode,
      globalMatchCount: 3,
      compatibleMatchCount: 1,
    }),
    null,
  );
});

test("topology-first add mode covers context, tool, and output primitives", () => {
  const base = {
    label: "Test",
    family: "state",
    token: "T",
    familyLabel: "Test",
    metricLabel: "Test",
    metricValue: "test",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: [],
    portDefinitions: [],
    ports: [],
    configSchema: { type: "object" },
    policyProfile: {},
    evidenceProfile: {},
    executor: {
      nodeType: "test",
      executorId: "test",
      sandboxed: false,
    },
    defaultLogic: {},
    defaultLaw: {},
    paletteVisibility: "default",
    displayLabel: "Test",
    advancedLabel: "Test",
    runtimeContract: {
      nodeKind: "test",
      actionKind: "test",
      componentKind: "test",
      manifestKind: "test",
    },
    primitive: {
      primitiveId: "test",
      label: "Test",
      category: "context",
      summary: "Test",
      configGroups: [],
      defaultPorts: [],
    },
  } as unknown as WorkflowNodeDefinition;

  assert.equal(
    workflowNodeCreatorDefaultAddMode({
      ...base,
      type: "repository_context",
      group: "State",
    }),
    "topology_first",
  );
  assert.equal(
    workflowNodeCreatorDefaultAddMode({
      ...base,
      type: "plugin_tool",
      group: "Tools",
    }),
    "topology_first",
  );
  assert.equal(
    workflowNodeCreatorDefaultAddMode({
      ...base,
      type: "model_call",
      group: "AI",
    }),
    "configure",
  );
});

test("selected node lifecycle summary replaces raw config with readiness checks", () => {
  const input: Node = {
    id: "input",
    type: "source",
    name: "Manual input",
    x: 0,
    y: 0,
  };
  const agent: Node = {
    id: "agent",
    type: "model_call",
    name: "Agent Step",
    x: 120,
    y: 0,
    config: {
      kind: "model_call",
      logic: {
        modelCapabilityRef: "model-capability:route.local-first",
        routeId: "route.local-first",
        receiptRequired: true,
      },
      law: {},
    },
  };
  const output: Node = {
    id: "output",
    type: "output",
    name: "Inline output",
    x: 240,
    y: 0,
  };

  const summary = workflowSelectedNodeLifecycleSummary({
    workflow: workflow(
      [input, agent, output],
      [
        {
          id: "edge-input-agent",
          from: "input",
          to: "agent",
          fromPort: "output",
          toPort: "input",
          type: "data",
        },
        {
          id: "edge-agent-output",
          from: "agent",
          to: "output",
          fromPort: "output",
          toPort: "input",
          type: "data",
        },
      ],
    ),
    selectedNode: agent,
    validationResult: emptyValidation,
    tests: [
      {
        id: "agent-test",
        name: "Agent exists",
        targetNodeIds: ["agent"],
        assertion: { kind: "node_exists" },
      },
    ],
  });

  assert.deepEqual(
    summary?.items.map((item) => [item.label, item.value, item.status]),
    [
      ["Input", "connected", "ready"],
      ["Model capability", "declared route", "ready"],
      ["Tools", "none", "idle"],
      ["Output", "connected", "ready"],
      ["Receipts", "required", "ready"],
      ["Tests", "1 linked", "ready"],
      ["Ready", "no node blockers", "ready"],
    ],
  );
});
