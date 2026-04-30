import type {
  WorkflowEdge,
  WorkflowNode,
  WorkflowProject,
  WorkflowTestCase,
} from "../types/graph";
import {
  DEFAULT_SANDBOX,
  makeWorkflowEdge,
  makeWorkflowNode,
} from "./workflow-node-registry";

export function buildRepoTestEngineerScratchWorkflow(seed: WorkflowProject): {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
} {
  const scanSchema = {
    type: "object",
    required: ["summary", "count", "passed", "files"],
    properties: {
      summary: { type: "string" },
      count: { type: "integer" },
      passed: { type: "boolean" },
      files: { type: "array" },
    },
  };
  const scanCode = [
    "const payload = input.payload || input;",
    "const files = ['apps/autopilot/src-tauri/src/project.rs', 'packages/agent-ide/src/WorkflowComposer.tsx', 'apps/autopilot/scripts/desktop_workflow_scratch_probe.py'];",
    "console.log(`scanned ${files.length} workflow runtime files`);",
    "return { summary: `repo scan ready for ${payload.task || 'test engineering'}`, count: files.length, passed: true, files };",
  ].join("\n");
  const workflow: WorkflowProject = {
    ...seed,
    metadata: {
      ...seed.metadata,
      name: "Scratch GUI Node Composition",
      slug: "scratch-gui-node-composition",
      workflowKind: "agent_workflow",
      executionMode: "local",
      dirty: true,
      updatedAtMs: Date.now(),
    },
    global_config: {
      ...seed.global_config,
      meta: {
        ...(seed.global_config?.meta ?? {}),
        name: "Scratch GUI Node Composition",
        description: "Scratch-authored node composition workflow.",
      },
    },
    nodes: [
      makeWorkflowNode(
        "scratch-source",
        "source",
        "Workspace source",
        120,
        180,
        {
          payload: {
            task: "Inspect workflow runtime and propose bounded tests for gaps.",
            scope: "workspace",
          },
        },
        undefined,
        { metricValue: "repo" },
      ),
      makeWorkflowNode(
        "scratch-function",
        "function",
        "Scan workspace files",
        380,
        180,
        {
          language: "javascript",
          code: scanCode,
          inputSchema: { type: "object" },
          outputSchema: scanSchema,
          functionBinding: {
            language: "javascript",
            code: scanCode,
            inputSchema: { type: "object" },
            outputSchema: scanSchema,
            sandboxPolicy: DEFAULT_SANDBOX,
            testInput: { payload: { task: "scan workflow runtime" } },
          },
        },
        { sandboxPolicy: DEFAULT_SANDBOX },
        { metricValue: "sandbox" },
      ),
      makeWorkflowNode(
        "scratch-model-binding",
        "model_binding",
        "Model binding",
        640,
        20,
        {
          modelRef: "reasoning",
          modelBinding: {
            modelRef: "reasoning",
            mockBinding: true,
            capabilityScope: ["reasoning"],
            argumentSchema: { type: "object" },
            resultSchema: {
              type: "object",
              properties: { message: { type: "string" } },
            },
            sideEffectClass: "none",
            requiresApproval: false,
            credentialReady: false,
            toolUseMode: "none",
          },
        },
        undefined,
        { metricValue: "reasoning" },
      ),
      makeWorkflowNode(
        "scratch-model",
        "model_call",
        "Diagnose test gaps",
        640,
        180,
        {
          modelRef: "reasoning",
          parserRef: "json_schema",
          outputSchema: {
            type: "object",
            properties: { message: { type: "string" } },
          },
          validateStructuredOutput: true,
          prompt:
            "Diagnose repository workflow-runtime test gaps from the scan result and produce a bounded recommendation. Include the word completed when the recommendation is ready.",
        },
        undefined,
        { metricValue: "reasoning" },
      ),
      makeWorkflowNode(
        "scratch-parser",
        "parser",
        "Structured response parser",
        640,
        360,
        {
          parserRef: "json_schema",
          parserBinding: {
            parserRef: "json_schema",
            parserKind: "json_schema",
            resultSchema: {
              type: "object",
              properties: { message: { type: "string" } },
            },
            mockBinding: true,
          },
          outputSchema: {
            type: "object",
            properties: { message: { type: "string" } },
          },
        },
        undefined,
        { metricValue: "schema" },
      ),
      makeWorkflowNode(
        "scratch-assertion",
        "test_assertion",
        "Diagnosis completed",
        900,
        180,
        {
          assertionKind: "output_contains",
          expected: "completed",
        },
        undefined,
        { metricValue: "contains" },
      ),
      makeWorkflowNode(
        "scratch-gate",
        "human_gate",
        "Approve bounded change",
        1160,
        180,
        {
          text: "Approve before staging a bounded repo test proposal.",
        },
        {
          requireHumanGate: true,
          privilegedActions: ["bounded_self_mutation"],
        },
        { metricValue: "approval" },
      ),
      makeWorkflowNode(
        "scratch-output",
        "output",
        "Repo test report",
        1420,
        180,
        {
          format: "markdown",
          rendererRef: { rendererId: "markdown", displayMode: "inline" },
          materialization: {
            enabled: true,
            assetPath: "reports/repo-test-engineer.md",
            assetKind: "report",
          },
          deliveryTarget: { targetKind: "local_file" },
        },
        undefined,
        { metricValue: "report" },
      ),
    ],
    edges: [
      makeWorkflowEdge(
        "edge-source-function",
        "scratch-source",
        "scratch-function",
      ),
      makeWorkflowEdge(
        "edge-function-model",
        "scratch-function",
        "scratch-model",
      ),
      makeWorkflowEdge(
        "edge-model-binding-model",
        "scratch-model-binding",
        "scratch-model",
        "model",
        "model",
        "model",
      ),
      makeWorkflowEdge(
        "edge-parser-model",
        "scratch-parser",
        "scratch-model",
        "parser",
        "parser",
        "parser",
      ),
      makeWorkflowEdge(
        "edge-model-assertion",
        "scratch-model",
        "scratch-assertion",
      ),
      makeWorkflowEdge(
        "edge-assertion-gate",
        "scratch-assertion",
        "scratch-gate",
      ),
      makeWorkflowEdge("edge-gate-output", "scratch-gate", "scratch-output"),
    ],
  };

  return {
    workflow,
    tests: [
      {
        id: "test-scratch-function-schema",
        name: "Scanner output schema",
        targetNodeIds: ["scratch-function"],
        assertion: {
          kind: "schema_matches",
          expected: scanSchema,
        },
        status: "idle",
      },
      {
        id: "test-scratch-model-completion",
        name: "Model diagnosis completed",
        targetNodeIds: ["scratch-model"],
        assertion: {
          kind: "output_contains",
          expected: "completed",
        },
        status: "idle",
      },
    ],
  };
}

export const SCRATCH_WORKFLOW_BLUEPRINTS = [
  "repo-test-engineer",
  "mcp-research-operator",
  "connector-triage-agent",
  "financial-close-assistant",
  "media-transform-agent",
  "scheduled-reporter",
  "self-improving-proposal",
  "stateful-memory-workflow",
  "subgraph-orchestration-workflow",
  "trigger-driven-workflow",
  "failed-function-resume",
] as const;

export type ScratchWorkflowBlueprintId =
  (typeof SCRATCH_WORKFLOW_BLUEPRINTS)[number];

function finishScratchWorkflow(
  seed: WorkflowProject,
  slug: string,
  name: string,
  description: string,
  nodes: WorkflowNode[],
  edges: WorkflowEdge[],
  tests: WorkflowTestCase[] = [],
): { workflow: WorkflowProject; tests: WorkflowTestCase[] } {
  const now = Date.now();
  return {
    workflow: {
      ...seed,
      metadata: {
        ...seed.metadata,
        name,
        slug,
        workflowKind: "agent_workflow",
        executionMode: "local",
        dirty: true,
        updatedAtMs: now,
      },
      global_config: {
        ...seed.global_config,
        meta: {
          ...(seed.global_config?.meta ?? {}),
          name,
          description,
        },
      },
      nodes,
      edges,
    },
    tests:
      tests.length > 0
        ? tests
        : [
            {
              id: `test-${slug}-nodes`,
              name: "Core nodes exist",
              targetNodeIds: nodes
                .slice(0, Math.min(nodes.length, 4))
                .map((node) => node.id),
              assertion: { kind: "node_exists" },
              status: "idle",
            },
          ],
  };
}

function scratchOutput(
  id: string,
  name: string,
  x: number,
  y: number,
  format = "markdown",
  materialize = false,
): WorkflowNode {
  return makeWorkflowNode(
    id,
    "output",
    name,
    x,
    y,
    {
      format,
      rendererRef: {
        rendererId: format === "svg" ? "svg" : "markdown",
        displayMode: format === "svg" ? "media" : "inline",
      },
      materialization: materialize
        ? {
            enabled: true,
            assetPath: `outputs/${id}.${format === "svg" ? "svg" : "md"}`,
            assetKind: format === "svg" ? "svg" : "report",
          }
        : { enabled: false },
      deliveryTarget: materialize
        ? { targetKind: "local_file" }
        : { targetKind: "none" },
      retentionPolicy: { retentionKind: "run_scoped" },
      versioning: { enabled: true },
    },
    undefined,
    { metricValue: format },
  );
}

function scratchFunction(
  id: string,
  name: string,
  x: number,
  y: number,
  code: string,
): WorkflowNode {
  return makeWorkflowNode(
    id,
    "function",
    name,
    x,
    y,
    {
      language: "javascript",
      code,
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "javascript",
        code,
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    { sandboxPolicy: DEFAULT_SANDBOX },
    { metricValue: "sandbox" },
  );
}

function scratchModelBinding(
  id: string,
  name: string,
  x: number,
  y: number,
  modelRef = "reasoning",
): WorkflowNode {
  return makeWorkflowNode(
    id,
    "model_binding",
    name,
    x,
    y,
    {
      modelRef,
      modelBinding: {
        modelRef,
        mockBinding: true,
        capabilityScope: [modelRef],
        argumentSchema: { type: "object" },
        resultSchema: {
          type: "object",
          properties: { message: { type: "string" } },
        },
        sideEffectClass: "none",
        requiresApproval: false,
        credentialReady: false,
        toolUseMode: "none",
      },
    },
    undefined,
    { metricValue: modelRef },
  );
}

export function buildScratchWorkflow(
  seed: WorkflowProject,
  blueprintId: ScratchWorkflowBlueprintId,
): { workflow: WorkflowProject; tests: WorkflowTestCase[] } {
  if (blueprintId === "repo-test-engineer") {
    return buildRepoTestEngineerScratchWorkflow(seed);
  }

  const passThroughCode =
    "return { result: input, passed: true, completed: true };";
  switch (blueprintId) {
    case "mcp-research-operator": {
      const nodes = [
        makeWorkflowNode(
          "research-source",
          "source",
          "Research prompt",
          120,
          180,
          { payload: { topic: "workflow runtime gaps" } },
          undefined,
          { metricValue: "prompt" },
        ),
        makeWorkflowNode(
          "research-tool",
          "plugin_tool",
          "Search via MCP tool",
          380,
          180,
          {
            toolBinding: {
              toolRef: "mock.web.search",
              mockBinding: true,
              capabilityScope: ["read"],
              sideEffectClass: "read",
              requiresApproval: false,
              arguments: { query: "{{input.topic}}" },
            },
          },
          undefined,
          { metricValue: "mock" },
        ),
        scratchFunction(
          "research-validate",
          "Validate citations",
          640,
          180,
          passThroughCode,
        ),
        scratchModelBinding("research-model-binding", "Model binding", 900, 20),
        makeWorkflowNode(
          "research-model",
          "model_call",
          "Synthesize cited answer",
          900,
          180,
          {
            toolUseMode: "explicit",
            prompt: "Summarize validated research with cited source notes.",
          },
        ),
        scratchOutput("research-output", "Cited summary", 1160, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-mcp-research-operator",
        "Scratch MCP research operator",
        "Scratch-built research workflow with explicit MCP/tool validation.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-tool",
            "research-source",
            "research-tool",
          ),
          makeWorkflowEdge(
            "edge-tool-validate",
            "research-tool",
            "research-validate",
          ),
          makeWorkflowEdge(
            "edge-validate-model",
            "research-validate",
            "research-model",
          ),
          makeWorkflowEdge(
            "edge-research-model-binding",
            "research-model-binding",
            "research-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge(
            "edge-research-tool-attachment",
            "research-tool",
            "research-model",
            "tool",
            "tool",
            "tool",
          ),
          makeWorkflowEdge(
            "edge-model-output",
            "research-model",
            "research-output",
          ),
        ],
      );
    }
    case "connector-triage-agent": {
      const nodes = [
        makeWorkflowNode(
          "triage-source",
          "source",
          "Support intake",
          120,
          180,
          {
            payload: { channel: "support", message: "Request needs triage" },
          },
          undefined,
          { metricValue: "inbox" },
        ),
        makeWorkflowNode(
          "triage-read",
          "adapter",
          "Read connector payload",
          380,
          180,
          {
            connectorBinding: {
              connectorRef: "mock.support.read",
              mockBinding: true,
              capabilityScope: ["read"],
              sideEffectClass: "read",
              requiresApproval: false,
              operation: "read",
            },
          },
          undefined,
          { metricValue: "mock" },
        ),
        makeWorkflowNode(
          "triage-decision",
          "decision",
          "Classify ticket path",
          640,
          180,
          { routes: ["left", "right"], defaultRoute: "left" },
        ),
        makeWorkflowNode(
          "triage-gate",
          "human_gate",
          "Approve ticket draft",
          900,
          180,
          { text: "Approve before creating or updating an external ticket." },
          { requireHumanGate: true },
        ),
        makeWorkflowNode(
          "triage-write",
          "adapter",
          "Draft ticket",
          1160,
          180,
          {
            connectorBinding: {
              connectorRef: "mock.ticket.write",
              mockBinding: true,
              capabilityScope: ["write"],
              sideEffectClass: "external_write",
              requiresApproval: true,
              operation: "draft",
            },
          },
          undefined,
          { metricValue: "draft" },
        ),
        scratchOutput("triage-output", "Triage summary", 1420, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-connector-triage-agent",
        "Scratch connector triage agent",
        "Scratch-built connector read/write workflow with contextual approval.",
        nodes,
        [
          makeWorkflowEdge("edge-source-read", "triage-source", "triage-read"),
          makeWorkflowEdge(
            "edge-read-decision",
            "triage-read",
            "triage-decision",
          ),
          makeWorkflowEdge(
            "edge-decision-gate",
            "triage-decision",
            "triage-gate",
            "left",
          ),
          makeWorkflowEdge("edge-gate-write", "triage-gate", "triage-write"),
          makeWorkflowEdge(
            "edge-write-output",
            "triage-write",
            "triage-output",
          ),
        ],
      );
    }
    case "financial-close-assistant": {
      const nodes = [
        makeWorkflowNode(
          "close-source",
          "source",
          "Close source pack",
          120,
          180,
          { payload: { period: "month-end" } },
          undefined,
          { metricValue: "period" },
        ),
        scratchFunction(
          "close-reconcile",
          "Reconcile sources",
          380,
          180,
          passThroughCode,
        ),
        scratchModelBinding("close-model-binding", "Model binding", 640, 20),
        makeWorkflowNode(
          "close-model",
          "model_call",
          "Variance analysis",
          640,
          180,
          { prompt: "Draft variance analysis and workpaper notes." },
        ),
        makeWorkflowNode(
          "close-gate",
          "human_gate",
          "Approve financial output",
          900,
          180,
          { text: "Strong approval required before financial export." },
          { requireHumanGate: true, privilegedActions: ["financial_write"] },
        ),
        scratchOutput(
          "close-output",
          "Workpaper bundle",
          1160,
          180,
          "report",
          true,
        ),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-financial-close-assistant",
        "Scratch financial close assistant",
        "Scratch-built financial workflow with strong approval before materialization.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-reconcile",
            "close-source",
            "close-reconcile",
          ),
          makeWorkflowEdge(
            "edge-reconcile-model",
            "close-reconcile",
            "close-model",
          ),
          makeWorkflowEdge(
            "edge-close-model-binding",
            "close-model-binding",
            "close-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge("edge-model-gate", "close-model", "close-gate"),
          makeWorkflowEdge("edge-gate-output", "close-gate", "close-output"),
        ],
      );
    }
    case "media-transform-agent": {
      const nodes = [
        makeWorkflowNode(
          "media-source",
          "source",
          "Media input",
          120,
          180,
          {
            sourceKind: "media",
            sourcePath: "input.jpg",
            fileExtension: "jpg",
            mediaKind: "image",
            mimeType: "image/jpeg",
            sanitizeInput: true,
            validateMime: true,
            stripMetadata: true,
            payload: { file: "input.jpg", mediaKind: "image", extension: "jpg" },
          },
          undefined,
          { metricLabel: "Media", metricValue: "image" },
        ),
        scratchModelBinding(
          "media-vision-binding",
          "Vision model binding",
          380,
          20,
          "vision",
        ),
        makeWorkflowNode(
          "media-vision",
          "model_call",
          "Vision trace prompt",
          380,
          180,
          { prompt: "Describe edges suitable for SVG tracing." },
          undefined,
          { metricValue: "vision" },
        ),
        scratchFunction(
          "media-svg",
          "Trace SVG function",
          640,
          180,
          'return { svg: \'<svg viewBox="0 0 10 10"><path d="M1 1L9 9"/></svg>\', completed: true };',
        ),
        scratchOutput("media-output", "SVG output", 900, 180, "svg", false),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-media-transform-agent",
        "Scratch media transform agent",
        "Scratch-built media-to-SVG transform with no materialization gate by default.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-vision",
            "media-source",
            "media-vision",
          ),
          makeWorkflowEdge(
            "edge-media-vision-binding",
            "media-vision-binding",
            "media-vision",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge("edge-vision-svg", "media-vision", "media-svg"),
          makeWorkflowEdge("edge-svg-output", "media-svg", "media-output"),
        ],
      );
    }
    case "scheduled-reporter": {
      const nodes = [
        makeWorkflowNode(
          "report-trigger",
          "trigger",
          "Weekly schedule",
          120,
          180,
          {
            triggerKind: "scheduled",
            cronSchedule: "0 9 * * MON",
            dedupeKey: "weekly-report",
          },
          undefined,
          { metricValue: "weekly" },
        ),
        makeWorkflowNode(
          "report-data",
          "adapter",
          "Pull metrics",
          380,
          180,
          {
            connectorBinding: {
              connectorRef: "mock.metrics.read",
              mockBinding: true,
              capabilityScope: ["read"],
              sideEffectClass: "read",
              requiresApproval: false,
              operation: "read",
            },
          },
          undefined,
          { metricValue: "mock" },
        ),
        scratchFunction(
          "report-chart",
          "Generate chart data",
          640,
          180,
          passThroughCode,
        ),
        scratchModelBinding("report-model-binding", "Model binding", 900, 20),
        makeWorkflowNode(
          "report-model",
          "model_call",
          "Narrative draft",
          900,
          180,
          { prompt: "Draft weekly metrics narrative." },
        ),
        scratchOutput("report-output", "Scheduled report", 1160, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-scheduled-reporter",
        "Scratch scheduled reporter",
        "Scratch-built scheduled reporting workflow with checkpoint-friendly steps.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-trigger-data",
            "report-trigger",
            "report-data",
          ),
          makeWorkflowEdge("edge-data-chart", "report-data", "report-chart"),
          makeWorkflowEdge("edge-chart-model", "report-chart", "report-model"),
          makeWorkflowEdge(
            "edge-report-model-binding",
            "report-model-binding",
            "report-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge(
            "edge-model-output",
            "report-model",
            "report-output",
          ),
        ],
      );
    }
    case "self-improving-proposal": {
      const nodes = [
        makeWorkflowNode(
          "improve-source",
          "source",
          "Existing workflow",
          120,
          180,
          { payload: { target: "current workflow" } },
        ),
        scratchModelBinding("improve-model-binding", "Model binding", 380, 20),
        makeWorkflowNode(
          "improve-model",
          "model_call",
          "Analyze improvement",
          380,
          180,
          { prompt: "Find bounded improvements only." },
        ),
        makeWorkflowNode(
          "improve-gate",
          "human_gate",
          "Approve proposal creation",
          640,
          180,
          { text: "Approve before staging bounded self-mutation." },
          {
            requireHumanGate: true,
            privilegedActions: ["bounded_self_mutation"],
          },
        ),
        makeWorkflowNode(
          "improve-proposal",
          "proposal",
          "Bounded proposal",
          900,
          180,
          {
            proposalAction: {
              actionKind: "create",
              boundedTargets: ["improve-model"],
              requiresApproval: true,
            },
          },
          {
            requireHumanGate: true,
            privilegedActions: ["bounded_self_mutation"],
          },
          { metricValue: "bounded" },
        ),
        scratchOutput("improve-output", "Proposal output", 1160, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-self-improving-proposal",
        "Scratch self-improving proposal",
        "Scratch-built proposal-only self-improvement workflow.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-model",
            "improve-source",
            "improve-model",
          ),
          makeWorkflowEdge(
            "edge-improve-model-binding",
            "improve-model-binding",
            "improve-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge("edge-model-gate", "improve-model", "improve-gate"),
          makeWorkflowEdge(
            "edge-gate-proposal",
            "improve-gate",
            "improve-proposal",
          ),
          makeWorkflowEdge(
            "edge-proposal-output",
            "improve-proposal",
            "improve-output",
          ),
        ],
      );
    }
    case "stateful-memory-workflow": {
      const nodes = [
        makeWorkflowNode(
          "memory-source",
          "source",
          "Conversation input",
          120,
          180,
          { payload: { message: "Remember this preference." } },
        ),
        makeWorkflowNode("memory-state", "state", "Merge memory", 380, 180, {
          stateKey: "user_memory",
          stateOperation: "merge",
          reducer: "merge",
          initialValue: {},
        }),
        scratchModelBinding("memory-model-binding", "Model binding", 640, 20),
        makeWorkflowNode(
          "memory-model",
          "model_call",
          "Answer with memory",
          640,
          180,
          {
            memoryKey: "user_memory",
            prompt: "Use workflow state to answer.",
          },
        ),
        scratchOutput("memory-output", "Memory answer", 900, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-stateful-memory-workflow",
        "Scratch stateful memory workflow",
        "Scratch-built workflow with explicit state reducer.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-state",
            "memory-source",
            "memory-state",
          ),
          makeWorkflowEdge("edge-state-model", "memory-state", "memory-model"),
          makeWorkflowEdge(
            "edge-memory-model-binding",
            "memory-model-binding",
            "memory-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge(
            "edge-state-memory-model",
            "memory-state",
            "memory-model",
            "memory",
            "memory",
            "memory",
          ),
          makeWorkflowEdge(
            "edge-model-output",
            "memory-model",
            "memory-output",
          ),
        ],
      );
    }
    case "subgraph-orchestration-workflow": {
      const nodes = [
        makeWorkflowNode(
          "subgraph-source",
          "source",
          "Parent input",
          120,
          180,
          { payload: { task: "invoke child workflow" } },
        ),
        makeWorkflowNode(
          "subgraph-tool",
          "plugin_tool",
          "Workflow tool",
          380,
          300,
          {
            toolBinding: {
              toolRef: "scratch-media-transform-agent",
              bindingKind: "workflow_tool",
              mockBinding: false,
              capabilityScope: ["workflow.invoke"],
              sideEffectClass: "none",
              requiresApproval: false,
              arguments: { input: "{{nodes.subgraph-source.output}}" },
              workflowTool: {
                workflowPath:
                  ".agents/workflows/scratch-media-transform-agent.workflow.json",
                argumentSchema: { type: "object" },
                resultSchema: { type: "object" },
                timeoutMs: 30000,
                maxAttempts: 1,
              },
            },
          },
          undefined,
          { metricValue: "workflow" },
        ),
        scratchModelBinding("subgraph-model-binding", "Model binding", 640, 20),
        makeWorkflowNode(
          "subgraph-model",
          "model_call",
          "Synthesize child run",
          640,
          180,
          {
            toolUseMode: "explicit",
            prompt: "Use the workflow tool result to summarize the child run.",
          },
        ),
        scratchOutput("subgraph-output", "Child run summary", 900, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-subgraph-orchestration-workflow",
        "Scratch subgraph orchestration workflow",
        "Scratch-built parent workflow with explicit child workflow binding.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-tool",
            "subgraph-source",
            "subgraph-tool",
          ),
          makeWorkflowEdge(
            "edge-source-model",
            "subgraph-source",
            "subgraph-model",
          ),
          makeWorkflowEdge(
            "edge-subgraph-model-binding",
            "subgraph-model-binding",
            "subgraph-model",
            "model",
            "model",
            "model",
          ),
          makeWorkflowEdge(
            "edge-workflow-tool-attachment",
            "subgraph-tool",
            "subgraph-model",
            "tool",
            "tool",
            "tool",
          ),
          makeWorkflowEdge(
            "edge-model-output",
            "subgraph-model",
            "subgraph-output",
          ),
        ],
      );
    }
    case "trigger-driven-workflow": {
      const nodes = [
        makeWorkflowNode(
          "event-trigger",
          "trigger",
          "Event trigger",
          120,
          180,
          {
            triggerKind: "event",
            eventSourceRef: "mock.slack.message",
            dedupeKey: "message-id",
          },
          undefined,
          { metricValue: "event" },
        ),
        scratchFunction(
          "event-normalize",
          "Normalize event",
          380,
          180,
          passThroughCode,
        ),
        scratchOutput("event-output", "Event result", 640, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-trigger-driven-workflow",
        "Scratch trigger-driven workflow",
        "Scratch-built event workflow with explicit dedupe metadata.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-trigger-normalize",
            "event-trigger",
            "event-normalize",
          ),
          makeWorkflowEdge(
            "edge-normalize-output",
            "event-normalize",
            "event-output",
          ),
        ],
      );
    }
    case "failed-function-resume": {
      const nodes = [
        makeWorkflowNode(
          "resume-source",
          "source",
          "Manual input",
          120,
          180,
          { payload: { message: "resume after function repair" } },
          undefined,
          { metricValue: "manual" },
        ),
        makeWorkflowNode(
          "resume-function",
          "function",
          "Repairable transform",
          380,
          180,
          {
            language: "javascript",
            code: "throw new Error('intentional checkpoint repair target');",
            inputSchema: { type: "object" },
            outputSchema: {
              type: "object",
              required: ["repaired"],
              properties: { repaired: { type: "boolean" } },
            },
            functionBinding: {
              language: "javascript",
              code: "throw new Error('intentional checkpoint repair target');",
              inputSchema: { type: "object" },
              outputSchema: {
                type: "object",
                required: ["repaired"],
                properties: { repaired: { type: "boolean" } },
              },
              sandboxPolicy: DEFAULT_SANDBOX,
              testInput: { payload: "resume" },
            },
          },
          { sandboxPolicy: DEFAULT_SANDBOX },
          { metricValue: "repair" },
        ),
        scratchOutput("resume-output", "Resumed output", 640, 180),
      ];
      return finishScratchWorkflow(
        seed,
        "scratch-failed-function-resume",
        "Scratch failed function resume",
        "Scratch-built failed function workflow repaired and resumed from checkpoint.",
        nodes,
        [
          makeWorkflowEdge(
            "edge-source-function",
            "resume-source",
            "resume-function",
          ),
          makeWorkflowEdge(
            "edge-function-output",
            "resume-function",
            "resume-output",
          ),
        ],
      );
    }
    default:
      return buildRepoTestEngineerScratchWorkflow(seed);
  }
}
