const now = () => Date.now();

function node(seed: any) {
  return {
    ...seed,
    config: seed.config ?? { logic: {}, law: {} },
  };
}

function edge(
  id: string,
  from: string,
  to: string,
  fromPort = "output",
  toPort = "input",
) {
  return {
    id,
    from,
    to,
    fromPort,
    toPort,
    type: "data",
    connectionClass: "data",
    data: { connectionClass: "data" },
  };
}

function source(id: string, name: string, x: number, y: number, payload: any) {
  return node({
    id,
    type: "source",
    name,
    x,
    y,
    metricLabel: "Input",
    metricValue: "manual",
    ioTypes: { in: "none", out: "payload" },
    outputs: ["output"],
    config: {
      logic: {
        sourceKind: "manual",
        payload,
        variables: { input: `{{${id}}}` },
      },
      law: {},
    },
  });
}

function model(id: string, name: string, x: number, y: number, prompt: string) {
  return node({
    id,
    type: "model_call",
    name,
    x,
    y,
    metricLabel: "Model",
    metricValue: "reasoning",
    ioTypes: { in: "prompt", out: "message" },
    inputs: ["input", "context"],
    outputs: ["output", "error", "retry"],
    config: {
      logic: {
        modelRef: "reasoning",
        prompt,
      },
      law: {},
    },
  });
}

function fn(id: string, name: string, x: number, y: number, code: string) {
  const outputSchema = { type: "object" };
  return node({
    id,
    type: "function",
    name,
    x,
    y,
    metricLabel: "Runtime",
    metricValue: "fixture",
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error"],
    config: {
      logic: {
        language: "javascript",
        code,
        outputSchema,
        functionBinding: {
          language: "javascript",
          code,
          outputSchema,
          sandboxPolicy: {
            timeoutMs: 1000,
            memoryMb: 64,
            outputLimitBytes: 32768,
            permissions: [],
          },
          testInput: { payload: "fixture" },
        },
      },
      law: {
        sandboxPolicy: {
          timeoutMs: 1000,
          memoryMb: 64,
          outputLimitBytes: 32768,
          permissions: [],
        },
      },
    },
  });
}

function decision(id: string, name: string, x: number, y: number, routes: string[]) {
  return node({
    id,
    type: "decision",
    name,
    x,
    y,
    metricLabel: "Paths",
    metricValue: String(routes.length),
    ioTypes: { in: "payload", out: "branch" },
    inputs: ["input", "context"],
    outputs: ["left", "right", "error"],
    config: {
      logic: {
        routes,
        routerInstruction: `Route to ${routes.join(" or ")}.`,
      },
      law: {},
    },
  });
}

function gate(id: string, name: string, x: number, y: number) {
  return node({
    id,
    type: "human_gate",
    name,
    x,
    y,
    metricLabel: "Gate",
    metricValue: "approval",
    ioTypes: { in: "request", out: "decision" },
    inputs: ["approval"],
    outputs: ["output", "error"],
    config: {
      logic: { text: "Approval required before privileged action." },
      law: { requireHumanGate: true },
    },
  });
}

function connector(
  id: string,
  name: string,
  x: number,
  y: number,
  operation: string,
  privileged = false,
) {
  const sideEffectClass = privileged ? "external_write" : "read";
  return node({
    id,
    type: "adapter",
    name,
    x,
    y,
    metricLabel: "Connector",
    metricValue: "mock-capability",
    ioTypes: { in: "request", out: "response" },
    inputs: ["input", "context"],
    outputs: ["output", "error", "retry"],
    config: {
      logic: {
        connectorBinding: {
          connectorRef: "mock.connector.fixture",
          connectorCapabilityRef: "connector-capability:mock.fixture",
          mockBinding: true,
          capabilityScope: privileged ? ["read", "write"] : ["read"],
          sideEffectClass,
          requiresApproval: privileged,
          operation,
          externalAction: false,
        },
      },
      law: privileged
        ? { requireHumanGate: true, privilegedActions: [sideEffectClass] }
        : {},
    },
  });
}

function output(id: string, name: string, x: number, y: number, metricValue = "artifact") {
  return node({
    id,
    type: "output",
    name,
    x,
    y,
    metricLabel: "Output",
    metricValue,
    ioTypes: { in: "payload", out: "output_bundle" },
    inputs: ["input"],
    outputs: [],
    config: {
      logic: {
        format: "markdown",
        rendererRef: { rendererId: "markdown", displayMode: "inline" },
        materialization: { enabled: false },
        deliveryTarget: { targetKind: "none" },
        retentionPolicy: { retentionKind: "run_scoped" },
        versioning: { enabled: true },
      },
      law: {},
    },
  });
}

function globalConfig(name: string, description: string) {
  return {
    env: "{}",
    workflowChromeLocale: "en-US",
    environmentProfile: {
      target: "local",
      credentialScope: "local",
      mockBindingPolicy: "allow",
    },
    modelBindings: {
      reasoning: {
        bindingKey: "reasoning",
        modelId: "fixture.reasoning.model",
        modelCapabilityRef: "model-capability:fixture.reasoning",
        routeId: "daemon.fixture.route",
        required: false,
        authorityScopes: ["model.invoke.fixture"],
        credentialReadiness: { status: "ready" },
        receiptBehavior: { receiptRequired: true },
        policyPosture: { status: "ready" },
      },
    },
    requiredCapabilities: {
      reasoning: { required: false, bindingKey: "reasoning" },
    },
    policy: { maxBudget: 5, maxSteps: 50, timeoutMs: 30000 },
    contract: { developerBond: 0, adjudicationRubric: "" },
    meta: { name, description },
    production: {
      errorWorkflowPath: "",
      evaluationSetPath: "",
      expectedTimeSavedMinutes: 0,
      mcpAccessReviewed: false,
      requireReplayFixtures: true,
    },
  };
}

function project(id: string, name: string, description: string, nodes: any[], edges: any[]) {
  const createdAtMs = now();
  return {
    version: "workflow.v1",
    metadata: {
      id,
      name,
      slug: id,
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: `.agents/workflows/${id}.workflow.json`,
      branch: "main",
      readOnly: false,
      dirty: false,
      createdAtMs,
      updatedAtMs: createdAtMs,
      harness: {
        executionMode: "projection",
        authorityBoundary: "daemon-owned",
        defaultRuntimeDispatchProof: null,
      },
    },
    nodes,
    edges,
    global_config: globalConfig(name, description),
    tests: [
      {
        id: `${id}-node-presence`,
        name: "Node presence",
        targetNodeIds: nodes.map((item) => item.id),
        assertion: { kind: "node_exists" },
        status: "idle",
      },
    ],
    proposals: [],
    runs: [],
  };
}

function withDaemonModelBinding(workflow: any) {
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...workflow.metadata.harness,
        executionMode: "daemon_model_dry_run",
        defaultRuntimeDispatchProof: null,
      },
    },
    global_config: {
      ...workflow.global_config,
      environmentProfile: {
        ...workflow.global_config.environmentProfile,
        mockBindingPolicy: "deny",
        credentialScope: "daemon",
      },
      modelBindings: {
        reasoning: {
          bindingKey: "reasoning",
          modelId: "native:electron-gui-model",
          modelCapabilityRef: "model-capability:daemon.native-local",
          routeId: "route.native-local",
          endpointId: "endpoint.electron.model-gui",
          required: true,
          authorityScopes: ["model.chat:*", "route.use:*"],
          credentialReadiness: { status: "ready" },
          receiptBehavior: { receiptRequired: true },
          policyPosture: { status: "ready", privacy: "local_only" },
        },
      },
      requiredCapabilities: {
        reasoning: { required: true, bindingKey: "reasoning" },
      },
    },
  };
}

export const workflowScenarios = [
  {
    id: "sequential",
    label: "Sequential",
    screenshotName: "workflow-from-scratch-sequential.png",
    description: "A source, agent step, verifier, and evidence output chain.",
    project: project(
      "electron-parity-sequential",
      "Electron parity sequential workflow",
      "Source to reasoning step to verifier to output, created through the Electron composer.",
      [
        source("source-goal", "Operator goal", 40, 160, {
          request: "Summarize UX readiness blockers.",
        }),
        model("agent-step", "Reasoning step", 320, 150, "Summarize the readiness signal and next action."),
        fn("verify", "Verify receipts", 620, 150, "return { status: 'passed', receipts: input?.receipts ?? [] };"),
        output("evidence-output", "Evidence output", 900, 160, "receipt"),
      ],
      [
        edge("edge-source-agent", "source-goal", "agent-step"),
        edge("edge-agent-verify", "agent-step", "verify"),
        edge("edge-verify-output", "verify", "evidence-output"),
      ],
    ),
  },
  {
    id: "model-backed-dry-run",
    label: "Daemon Model",
    screenshotName: "workflow-from-scratch-model-backed-dry-run.png",
    description: "A live daemon-backed model dry-run with route binding and receipts.",
    project: withDaemonModelBinding(
      project(
        "electron-model-backed-dry-run",
        "Electron model-backed daemon dry-run",
        "Workflow Composer binds a model node to route.native-local and invokes the IOI daemon.",
        [
          source("source-model-task", "Operator prompt", 40, 160, {
            request: "Use the mounted local model route to summarize readiness.",
          }),
          model(
            "daemon-model-call",
            "Mounted model call",
            340,
            150,
            "Summarize the model mounting readiness signal using the daemon route.",
          ),
          output("model-receipt-output", "Model receipts", 660, 160, "daemon"),
        ],
        [
          edge("edge-model-source", "source-model-task", "daemon-model-call"),
          edge("edge-model-output", "daemon-model-call", "model-receipt-output"),
        ],
      ),
    ),
  },
  {
    id: "branching-approval",
    label: "Approval Gate",
    screenshotName: "workflow-from-scratch-branching-approval.png",
    description: "A branch that pauses at a human approval gate before privileged work.",
    project: project(
      "electron-parity-branching-approval",
      "Electron parity approval-gated workflow",
      "Branching workflow with explicit policy and approval projection.",
      [
        source("source-request", "Operator request", 40, 160, { request: "Draft and gate a privileged change." }),
        decision("risk-router", "Risk router", 310, 150, ["low_risk", "requires_approval"]),
        gate("approval-gate", "Approval gate", 600, 70),
        fn("approved-action", "Approved dry-run action", 840, 80, "return { approved: true, externalAction: false };"),
        output("approval-output", "Approval receipt", 1110, 150, "policy"),
      ],
      [
        edge("edge-source-router", "source-request", "risk-router"),
        edge("edge-router-gate", "risk-router", "approval-gate", "right", "approval"),
        edge("edge-gate-action", "approval-gate", "approved-action"),
        edge("edge-action-output", "approved-action", "approval-output"),
      ],
    ),
  },
  {
    id: "connector-fixture",
    label: "Connector Fixture",
    screenshotName: "workflow-from-scratch-connector-fixture.png",
    description: "A connector-neutral dry-run with mock capability binding and no external action.",
    project: project(
      "electron-parity-connector-fixture",
      "Electron parity connector fixture workflow",
      "Mock connector capability binding and receipt projection without live connector action.",
      [
        source("source-intent", "Connector intent", 40, 160, { request: "Run connector-neutral dry-run only." }),
        connector("mock-read", "Mock capability read", 330, 150, "read_fixture", false),
        gate("mock-approval", "Mock approval", 620, 150),
        connector("mock-write-preview", "Mock write preview", 880, 150, "preview_write", true),
        output("connector-evidence", "Connector evidence", 1160, 160, "fixture"),
      ],
      [
        edge("edge-intent-read", "source-intent", "mock-read"),
        edge("edge-read-approval", "mock-read", "mock-approval"),
        edge("edge-approval-preview", "mock-approval", "mock-write-preview"),
        edge("edge-preview-evidence", "mock-write-preview", "connector-evidence"),
      ],
    ),
  },
  {
    id: "code-proposal",
    label: "Code Proposal",
    screenshotName: "workflow-from-scratch-code-proposal.png",
    description: "A workflow-to-code proposal path that remains proposal-only.",
    project: project(
      "electron-parity-code-proposal",
      "Electron parity workflow-to-code proposal",
      "Plan a code change, verify it, and emit proposal evidence without direct mutation.",
      [
        source("source-code-goal", "Code goal", 40, 160, { request: "Create a proposal-only code change." }),
        model("proposal-planner", "Proposal planner", 320, 150, "Create a bounded diff proposal, no apply."),
        node({
          id: "proposal-node",
          type: "proposal",
          name: "Proposal artifact",
          x: 620,
          y: 150,
          metricLabel: "Mutation",
          metricValue: "proposal-only",
          ioTypes: { in: "plan", out: "proposal" },
          inputs: ["input"],
          outputs: ["output", "error"],
          config: {
            logic: {
              proposalOnly: true,
              boundedTargets: ["workbench-adapters/ioi-workbench"],
            },
            law: { requireReceipt: true, directMutation: false },
          },
        }),
        output("proposal-output", "Proposal evidence", 900, 160, "diff"),
      ],
      [
        edge("edge-code-planner", "source-code-goal", "proposal-planner"),
        edge("edge-planner-proposal", "proposal-planner", "proposal-node"),
        edge("edge-proposal-output", "proposal-node", "proposal-output"),
      ],
    ),
  },
  {
    id: "replay-evidence",
    label: "Replay Evidence",
    screenshotName: "workflow-from-scratch-replay-evidence.png",
    description: "A replay-focused chain with fixtures, checkpoints, receipts, and evidence.",
    project: project(
      "electron-parity-replay-evidence",
      "Electron parity replay and evidence workflow",
      "Captures fixture-backed replay evidence and run receipts.",
      [
        source("source-replay", "Replay input", 40, 160, { request: "Retain replay evidence." }),
        fn("fixture-capture", "Capture fixture", 320, 150, "return { fixture: true, inputHash: 'fixture-input-hash' };"),
        fn("receipt-map", "Map receipts", 610, 150, "return { receipts: ['receipt:composer-fixture'], replay: true };"),
        output("replay-output", "Replay bundle", 900, 160, "replay"),
      ],
      [
        edge("edge-replay-capture", "source-replay", "fixture-capture"),
        edge("edge-capture-receipt", "fixture-capture", "receipt-map"),
        edge("edge-receipt-output", "receipt-map", "replay-output"),
      ],
    ),
  },
];

export function scenarioById(id: string) {
  return workflowScenarios.find((scenario) => scenario.id === id) ?? workflowScenarios[0];
}
