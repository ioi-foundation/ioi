import type {
  FirewallPolicy,
  Node,
  NodeLogic,
  WorkflowEdge,
  WorkflowEvidenceProfile,
  WorkflowConnectionClass,
  WorkflowNode,
  WorkflowNodeActionDefinition,
  WorkflowNodeDefinitionContract,
  WorkflowNodeFamily,
  WorkflowNodeKind,
  WorkflowPolicyProfile,
  WorkflowPortDataType,
  WorkflowPortDefinition,
  WorkflowScaffoldDefinition,
} from "../types/graph";

export type WorkflowNodeGroup =
  | "Start"
  | "Sources"
  | "Transform"
  | "AI"
  | "Tools"
  | "Connectors"
  | "Flow"
  | "State"
  | "Human"
  | "Outputs"
  | "Tests"
  | "Proposals";

export interface WorkflowNodeDefinition extends WorkflowNodeDefinitionContract {
  type: WorkflowNodeKind;
  label: string;
  group: WorkflowNodeGroup;
  family: WorkflowNodeFamily;
  token: string;
  familyLabel: string;
  metricLabel: string;
  metricValue: string;
  ioTypes: { in: string; out: string };
  inputs: string[];
  outputs: string[];
  portDefinitions: WorkflowPortDefinition[];
  defaultLogic: NodeLogic;
  defaultLaw: FirewallPolicy;
}

export interface WorkflowNodeCreatorDefinition
  extends Omit<WorkflowNodeDefinition, "type"> {
  type: WorkflowNodeKind;
  creatorId: string;
  baseType: WorkflowNodeKind;
  creatorDescription: string;
}

export const DEFAULT_SANDBOX = {
  timeoutMs: 1000,
  memoryMb: 64,
  outputLimitBytes: 32768,
  permissions: [],
} satisfies NonNullable<FirewallPolicy["sandboxPolicy"]>;

function port(
  id: string,
  label: string,
  direction: WorkflowPortDefinition["direction"],
  dataType: WorkflowPortDataType,
  semanticRole: WorkflowPortDefinition["semanticRole"] = direction === "input"
    ? "input"
    : "output",
  required = direction === "input",
  connectionClass?: WorkflowConnectionClass,
): WorkflowPortDefinition {
  return {
    id,
    label,
    direction,
    dataType,
    connectionClass:
      connectionClass ?? connectionClassForPort(dataType, semanticRole),
    cardinality: "one",
    required,
    semanticRole,
  };
}

function connectionClassForPort(
  dataType: WorkflowPortDataType,
  semanticRole: WorkflowPortDefinition["semanticRole"],
): WorkflowConnectionClass {
  if (semanticRole === "error") return "error";
  if (semanticRole === "retry") return "retry";
  if (semanticRole === "approval" || dataType === "approval") return "approval";
  if (semanticRole === "state") return "state";
  if (semanticRole === "memory") return "memory";
  if (semanticRole === "model") return "model";
  if (semanticRole === "tool") return "tool";
  if (semanticRole === "parser") return "parser";
  if (semanticRole === "delivery") return "delivery";
  if (semanticRole === "subgraph" || dataType === "run") return "subgraph";
  if (semanticRole === "trigger") return "control";
  return "data";
}

function policyProfile(
  sideEffectClass = "none",
  requiresApproval = false,
  sandboxed = false,
): WorkflowPolicyProfile {
  return {
    sideEffectClass:
      sideEffectClass as WorkflowPolicyProfile["sideEffectClass"],
    requiresApproval,
    sandboxed,
    privilegedBoundary: requiresApproval,
  };
}

function evidenceProfile(
  completionRequirements: WorkflowEvidenceProfile["completionRequirements"],
  requiredEvidence: WorkflowEvidenceProfile["requiredEvidence"] = ["execution"],
): WorkflowEvidenceProfile {
  return {
    requiredEvidence,
    completionRequirements,
  };
}

export const WORKFLOW_NODE_DEFINITIONS: WorkflowNodeDefinition[] = [
  {
    type: "source",
    label: "Source/Input",
    group: "Sources",
    family: "sources",
    token: "IN",
    familyLabel: "Source",
    metricLabel: "Input",
    metricValue: "ready",
    ioTypes: { in: "none", out: "payload" },
    inputs: [],
    outputs: ["output"],
    portDefinitions: [
      port("output", "Output", "output", "payload", "output", false),
    ],
    ports: [port("output", "Output", "output", "payload", "output", false)],
    configSchema: { type: "object" },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile([]),
    executor: {
      nodeType: "source",
      executorId: "workflow.source",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      payload: { request: "Describe the input for this workflow." },
    },
    defaultLaw: {},
  },
  {
    type: "trigger",
    label: "Trigger",
    group: "Start",
    family: "triggers",
    token: "TR",
    familyLabel: "Trigger",
    metricLabel: "Trigger",
    metricValue: "manual",
    ioTypes: { in: "none", out: "payload" },
    inputs: [],
    outputs: ["output"],
    portDefinitions: [
      port("output", "Output", "output", "payload", "trigger", false, "data"),
    ],
    ports: [
      port("output", "Output", "output", "payload", "trigger", false, "data"),
    ],
    configSchema: { type: "object", required: ["triggerKind"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile([]),
    executor: {
      nodeType: "trigger",
      executorId: "workflow.trigger",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      triggerKind: "manual",
      cronSchedule: "",
      dedupeKey: "",
    },
    defaultLaw: {},
  },
  {
    type: "function",
    label: "Function",
    group: "Transform",
    family: "functions",
    token: "FN",
    familyLabel: "Function",
    metricLabel: "Runtime",
    metricValue: "local",
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("output", "Output", "output", "payload", "output", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("output", "Output", "output", "payload", "output", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    configSchema: { type: "object", required: ["functionBinding"] },
    policyProfile: policyProfile("none", false, true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "function",
      executorId: "workflow.function",
      sandboxed: true,
      supportsDryRun: true,
    },
    defaultLogic: {
      language: "javascript",
      code: "return { result: input };",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "javascript",
        code: "return { result: input };",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    defaultLaw: { sandboxPolicy: DEFAULT_SANDBOX },
  },
  {
    type: "model_binding",
    label: "Model Binding",
    group: "AI",
    family: "models",
    token: "MB",
    familyLabel: "Model",
    metricLabel: "Binding",
    metricValue: "reasoning",
    ioTypes: { in: "none", out: "model" },
    inputs: [],
    outputs: ["model"],
    portDefinitions: [
      port("model", "Chat model", "output", "payload", "model", false, "model"),
    ],
    ports: [
      port("model", "Chat model", "output", "payload", "model", false, "model"),
    ],
    configSchema: { type: "object", required: ["modelBinding"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "model_binding",
      executorId: "workflow.model_binding",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      modelRef: "reasoning",
      modelBinding: {
        modelRef: "reasoning",
        mockBinding: true,
        capabilityScope: ["reasoning"],
        argumentSchema: { type: "object" },
        resultSchema: { type: "object" },
        sideEffectClass: "none",
        requiresApproval: false,
        credentialReady: false,
        toolUseMode: "none",
      },
    },
    defaultLaw: {},
  },
  {
    type: "model_call",
    label: "Model",
    group: "AI",
    family: "models",
    token: "AI",
    familyLabel: "Model",
    metricLabel: "Model",
    metricValue: "reasoning",
    ioTypes: { in: "prompt", out: "message" },
    inputs: ["input", "context", "model", "memory", "tool", "parser"],
    outputs: ["output", "error", "retry"],
    portDefinitions: [
      port("input", "Input", "input", "prompt"),
      port("context", "Context", "input", "payload", "context", false),
      port("model", "Chat model", "input", "payload", "model", false, "model"),
      port("memory", "Memory", "input", "state", "memory", false, "memory"),
      port("tool", "Tool", "input", "args", "tool", false, "tool"),
      port("parser", "Parser", "input", "payload", "parser", false, "parser"),
      port("output", "Output", "output", "message", "output", false),
      port("error", "Error", "output", "message", "error", false),
      port("retry", "Retry", "output", "message", "retry", false),
    ],
    ports: [
      port("input", "Input", "input", "prompt"),
      port("context", "Context", "input", "payload", "context", false),
      port("model", "Chat model", "input", "payload", "model", false, "model"),
      port("memory", "Memory", "input", "state", "memory", false, "memory"),
      port("tool", "Tool", "input", "args", "tool", false, "tool"),
      port("parser", "Parser", "input", "payload", "parser", false, "parser"),
      port("output", "Output", "output", "message", "output", false),
      port("error", "Error", "output", "message", "error", false),
      port("retry", "Retry", "output", "message", "retry", false),
    ],
    configSchema: { type: "object", required: ["modelRef"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "model_call",
      executorId: "workflow.model",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      modelRef: "reasoning",
      prompt: "Use the input and context to produce the next workflow result.",
    },
    defaultLaw: {},
  },
  {
    type: "parser",
    label: "Output Parser",
    group: "AI",
    family: "models",
    token: "PR",
    familyLabel: "Parser",
    metricLabel: "Parser",
    metricValue: "schema",
    ioTypes: { in: "none", out: "parser" },
    inputs: [],
    outputs: ["parser"],
    portDefinitions: [
      port("parser", "Parser", "output", "payload", "parser", false, "parser"),
    ],
    ports: [
      port("parser", "Parser", "output", "payload", "parser", false, "parser"),
    ],
    configSchema: { type: "object", required: ["parserBinding"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "parser",
      executorId: "workflow.parser",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      parserRef: "json_schema",
      parserBinding: {
        parserRef: "json_schema",
        parserKind: "json_schema",
        resultSchema: { type: "object" },
        mockBinding: true,
      },
      outputSchema: { type: "object" },
    },
    defaultLaw: {},
  },
  {
    type: "adapter",
    label: "Adapter",
    group: "Connectors",
    family: "connectors",
    token: "AD",
    familyLabel: "Adapter",
    metricLabel: "Connector",
    metricValue: "mock",
    ioTypes: { in: "request", out: "response" },
    inputs: ["input", "context"],
    outputs: ["output", "error", "retry"],
    portDefinitions: [
      port("input", "Input", "input", "request"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Output", "output", "response", "output", false),
      port("error", "Error", "output", "response", "error", false),
      port("retry", "Retry", "output", "response", "retry", false),
    ],
    ports: [
      port("input", "Input", "input", "request"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Output", "output", "response", "output", false),
      port("error", "Error", "output", "response", "error", false),
      port("retry", "Retry", "output", "response", "retry", false),
    ],
    configSchema: { type: "object", required: ["connectorBinding"] },
    policyProfile: policyProfile("read"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution"],
    ),
    executor: {
      nodeType: "adapter",
      executorId: "workflow.adapter",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      connectorBinding: {
        connectorRef: "",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["read"],
        sideEffectClass: "read",
        requiresApproval: false,
        operation: "read",
      },
    },
    defaultLaw: {},
  },
  {
    type: "plugin_tool",
    label: "Plugin Tool",
    group: "Tools",
    family: "tools",
    token: "PL",
    familyLabel: "Plugin",
    metricLabel: "Plugin",
    metricValue: "mock",
    ioTypes: { in: "args", out: "result" },
    inputs: ["input"],
    outputs: ["output", "tool", "error"],
    portDefinitions: [
      port("input", "Input", "input", "args"),
      port("output", "Output", "output", "result", "output", false),
      port("tool", "Tool attachment", "output", "args", "tool", false, "tool"),
      port("error", "Error", "output", "result", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "args"),
      port("output", "Output", "output", "result", "output", false),
      port("tool", "Tool attachment", "output", "args", "tool", false, "tool"),
      port("error", "Error", "output", "result", "error", false),
    ],
    configSchema: { type: "object", required: ["toolBinding"] },
    policyProfile: policyProfile("read"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution"],
    ),
    executor: {
      nodeType: "plugin_tool",
      executorId: "workflow.plugin_tool",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      toolBinding: {
        toolRef: "",
        bindingKind: "plugin_tool",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["read"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
      },
    },
    defaultLaw: {},
  },
  {
    type: "state",
    label: "State",
    group: "State",
    family: "state",
    token: "ST",
    familyLabel: "State",
    metricLabel: "Reducer",
    metricValue: "merge",
    ioTypes: { in: "payload", out: "state" },
    inputs: ["input", "context"],
    outputs: ["output", "memory", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "state", "context", false),
      port("output", "State", "output", "state", "output", false, "data"),
      port(
        "memory",
        "Memory attachment",
        "output",
        "state",
        "memory",
        false,
        "memory",
      ),
      port("error", "Error", "output", "payload", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "state", "context", false),
      port("output", "State", "output", "state", "output", false, "data"),
      port(
        "memory",
        "Memory attachment",
        "output",
        "state",
        "memory",
        false,
        "memory",
      ),
      port("error", "Error", "output", "payload", "error", false),
    ],
    configSchema: { type: "object", required: ["stateKey", "stateOperation"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(["execution"]),
    executor: {
      nodeType: "state",
      executorId: "workflow.state",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "merge",
      reducer: "merge",
      initialValue: {},
    },
    defaultLaw: {},
  },
  {
    type: "decision",
    label: "Decision",
    group: "Flow",
    family: "flow_control",
    token: "IF",
    familyLabel: "Decision",
    metricLabel: "Paths",
    metricValue: "2",
    ioTypes: { in: "payload", out: "branch" },
    inputs: ["input", "context"],
    outputs: ["left", "right", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("left", "Left", "output", "branch", "branch", false),
      port("right", "Right", "output", "branch", "branch", false),
      port("error", "Error", "output", "branch", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("left", "Left", "output", "branch", "branch", false),
      port("right", "Right", "output", "branch", "branch", false),
      port("error", "Error", "output", "branch", "error", false),
    ],
    configSchema: { type: "object", required: ["routes"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(["execution"]),
    executor: {
      nodeType: "decision",
      executorId: "workflow.decision",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      routes: ["left", "right"],
      defaultRoute: "left",
    },
    defaultLaw: {},
  },
  {
    type: "loop",
    label: "Loop",
    group: "Flow",
    family: "flow_control",
    token: "LO",
    familyLabel: "Loop",
    metricLabel: "Limit",
    metricValue: "3",
    ioTypes: { in: "payload", out: "branch" },
    inputs: ["input", "context"],
    outputs: ["output", "retry", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Done", "output", "branch", "branch", false),
      port("retry", "Repeat", "output", "branch", "retry", false),
      port("error", "Error", "output", "branch", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Done", "output", "branch", "branch", false),
      port("retry", "Repeat", "output", "branch", "retry", false),
      port("error", "Error", "output", "branch", "error", false),
    ],
    configSchema: { type: "object" },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(["execution"]),
    executor: {
      nodeType: "loop",
      executorId: "workflow.loop",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      loopCondition: "return input.iteration < 3;",
      maxIterations: 3,
    },
    defaultLaw: {},
  },
  {
    type: "barrier",
    label: "Barrier",
    group: "Flow",
    family: "flow_control",
    token: "BA",
    familyLabel: "Barrier",
    metricLabel: "Join",
    metricValue: "all",
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["left", "right"],
    outputs: ["output", "tool", "error"],
    portDefinitions: [
      port("left", "Left", "input", "payload"),
      port("right", "Right", "input", "payload"),
      port("output", "Output", "output", "payload", "output", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    ports: [
      port("left", "Left", "input", "payload"),
      port("right", "Right", "input", "payload"),
      port("output", "Output", "output", "payload", "output", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    configSchema: { type: "object" },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(["execution"]),
    executor: {
      nodeType: "barrier",
      executorId: "workflow.barrier",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      barrierStrategy: "all",
    },
    defaultLaw: {},
  },
  {
    type: "subgraph",
    label: "Subgraph",
    group: "Flow",
    family: "subgraphs",
    token: "SG",
    familyLabel: "Subgraph",
    metricLabel: "Child run",
    metricValue: "bound",
    ioTypes: { in: "payload", out: "run" },
    inputs: ["input", "context"],
    outputs: ["output", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Child run", "output", "run", "output", false, "data"),
      port("tool", "Workflow tool", "output", "args", "tool", false, "tool"),
      port("error", "Error", "output", "run", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("context", "Context", "input", "payload", "context", false),
      port("output", "Child run", "output", "run", "output", false, "data"),
      port("tool", "Workflow tool", "output", "args", "tool", false, "tool"),
      port("error", "Error", "output", "run", "error", false),
    ],
    configSchema: { type: "object", required: ["subgraphRef"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution"],
    ),
    executor: {
      nodeType: "subgraph",
      executorId: "workflow.subgraph",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      subgraphRef: { workflowPath: "" },
    },
    defaultLaw: {},
  },
  {
    type: "human_gate",
    label: "Human Gate",
    group: "Human",
    family: "gates",
    token: "OK",
    familyLabel: "Gate",
    metricLabel: "Gate",
    metricValue: "approval",
    ioTypes: { in: "request", out: "decision" },
    inputs: ["approval"],
    outputs: ["output", "error"],
    portDefinitions: [
      port("approval", "Approval", "input", "approval", "approval"),
      port("output", "Approved", "output", "decision", "output", false),
      port("error", "Rejected", "output", "decision", "error", false),
    ],
    ports: [
      port("approval", "Approval", "input", "approval", "approval"),
      port("output", "Approved", "output", "decision", "output", false),
      port("error", "Rejected", "output", "decision", "error", false),
    ],
    configSchema: { type: "object" },
    policyProfile: policyProfile("none", true),
    evidenceProfile: evidenceProfile(
      ["execution", "approval"],
      ["execution", "approval"],
    ),
    executor: {
      nodeType: "human_gate",
      executorId: "workflow.human_gate",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      text: "Approval required before privileged action.",
    },
    defaultLaw: { requireHumanGate: true },
  },
  {
    type: "output",
    label: "Output",
    group: "Outputs",
    family: "outputs",
    token: "OUT",
    familyLabel: "Output",
    metricLabel: "Output",
    metricValue: "draft",
    ioTypes: { in: "payload", out: "output_bundle" },
    inputs: ["input"],
    outputs: [],
    portDefinitions: [port("input", "Input", "input", "payload")],
    ports: [port("input", "Input", "input", "payload")],
    configSchema: { type: "object", required: ["format"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "output_created"],
      ["execution", "output"],
    ),
    executor: {
      nodeType: "output",
      executorId: "workflow.output",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      format: "markdown",
      rendererRef: { rendererId: "markdown", displayMode: "inline" },
      materialization: { enabled: false },
      deliveryTarget: { targetKind: "none" },
      retentionPolicy: { retentionKind: "run_scoped" },
      versioning: { enabled: true },
    },
    defaultLaw: {},
  },
  {
    type: "test_assertion",
    label: "Test Assertion",
    group: "Tests",
    family: "tests",
    token: "TS",
    familyLabel: "Test",
    metricLabel: "Tests",
    metricValue: "idle",
    ioTypes: { in: "actual", out: "result" },
    inputs: ["input"],
    outputs: ["output", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("output", "Result", "output", "test_result", "output", false),
      port("error", "Error", "output", "test_result", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("output", "Result", "output", "test_result", "output", false),
      port("error", "Error", "output", "test_result", "error", false),
    ],
    configSchema: { type: "object", required: ["assertionKind"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "test"],
      ["execution", "test"],
    ),
    executor: {
      nodeType: "test_assertion",
      executorId: "workflow.test_assertion",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      assertionKind: "node_exists",
    },
    defaultLaw: {},
  },
  {
    type: "proposal",
    label: "Proposal",
    group: "Proposals",
    family: "proposals",
    token: "PR",
    familyLabel: "Proposal",
    metricLabel: "Bounds",
    metricValue: "draft",
    ioTypes: { in: "payload", out: "proposal" },
    inputs: ["input"],
    outputs: ["output", "approval", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("output", "Proposal", "output", "proposal", "proposal", false),
      port("approval", "Approval", "output", "approval", "approval", false),
      port("error", "Error", "output", "proposal", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("output", "Proposal", "output", "proposal", "proposal", false),
      port("approval", "Approval", "output", "approval", "approval", false),
      port("error", "Error", "output", "proposal", "error", false),
    ],
    configSchema: { type: "object", required: ["proposalAction"] },
    policyProfile: policyProfile("write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution"],
    ),
    executor: {
      nodeType: "proposal",
      executorId: "workflow.proposal",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: {
      proposalAction: {
        actionKind: "create",
        boundedTargets: [],
        requiresApproval: true,
      },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["bounded_self_mutation"],
    },
  },
];

const DEFINITION_BY_TYPE = new Map(
  WORKFLOW_NODE_DEFINITIONS.map((item) => [item.type, item]),
);

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function creatorDefinition(
  baseType: WorkflowNodeKind,
  overrides: {
    creatorId: string;
    label: string;
    description: string;
    metricLabel?: string;
    metricValue?: string;
    defaultLogic?: NodeLogic;
    defaultLaw?: FirewallPolicy;
    keywords?: string[];
  },
): WorkflowNodeCreatorDefinition {
  const definition = workflowNodeDefinition(baseType);
  return {
    ...definition,
    label: overrides.label,
    creatorId: overrides.creatorId,
    baseType,
    creatorDescription: overrides.description,
    metricLabel: overrides.metricLabel ?? definition.metricLabel,
    metricValue: overrides.metricValue ?? definition.metricValue,
    defaultLogic: overrides.defaultLogic
      ? clone(overrides.defaultLogic)
      : clone(definition.defaultLogic),
    defaultLaw: overrides.defaultLaw
      ? clone(overrides.defaultLaw)
      : clone(definition.defaultLaw),
  };
}

export function workflowNodeDefinition(type: string): WorkflowNodeDefinition {
  return (
    DEFINITION_BY_TYPE.get(type as WorkflowNodeKind) ??
    WORKFLOW_NODE_DEFINITIONS[0]
  );
}

export function workflowNodeDefaults(
  type: string,
): Pick<
  Node,
  "metricLabel" | "metricValue" | "ioTypes" | "inputs" | "outputs" | "ports"
> {
  const definition = workflowNodeDefinition(type);
  return {
    metricLabel: definition.metricLabel,
    metricValue: definition.metricValue,
    ioTypes: clone(definition.ioTypes),
    inputs: [...definition.inputs],
    outputs: [...definition.outputs],
    ports: clone(definition.portDefinitions),
  };
}

export function workflowNodeDefaultLogic(type: string): NodeLogic {
  return clone(workflowNodeDefinition(type).defaultLogic);
}

export function workflowNodeDefaultLaw(type: string): FirewallPolicy {
  return clone(workflowNodeDefinition(type).defaultLaw);
}

export function workflowNodeCreatorDefinitions(): WorkflowNodeCreatorDefinition[] {
  const sourceManual = creatorDefinition("source", {
    creatorId: "source.manual",
    label: "Manual input",
    description: "Typed user or prompt payload entered directly into the workflow.",
    metricLabel: "Input",
    metricValue: "manual",
    defaultLogic: {
      sourceKind: "manual",
      payload: { request: "Describe the input for this workflow." },
      schema: { type: "object" },
    },
  });
  const sourceFile = creatorDefinition("source", {
    creatorId: "source.file",
    label: "File input",
    description: "A local file source with extension and MIME validation.",
    metricLabel: "File",
    metricValue: "selected",
    defaultLogic: {
      sourceKind: "file",
      sourcePath: "",
      fileExtension: "",
      mimeType: "application/octet-stream",
      sanitizeInput: true,
      validateMime: true,
      payload: { file: "" },
      schema: { type: "object" },
    },
  });
  const sourceMedia = creatorDefinition("source", {
    creatorId: "source.media",
    label: "Media input",
    description:
      "Image, audio, video, or document input with extension, MIME, and sanitization controls.",
    metricLabel: "Media",
    metricValue: "image",
    defaultLogic: {
      sourceKind: "media",
      sourcePath: "input.jpg",
      fileExtension: "jpg",
      mediaKind: "image",
      mimeType: "image/jpeg",
      sanitizeInput: true,
      validateMime: true,
      stripMetadata: true,
      payload: { file: "input.jpg", mediaKind: "image", extension: "jpg" },
      schema: { type: "object" },
    },
  });
  const sourceDataset = creatorDefinition("source", {
    creatorId: "source.dataset",
    label: "Dataset input",
    description: "Tabular or JSON collection input with declared schema.",
    metricLabel: "Rows",
    metricValue: "sample",
    defaultLogic: {
      sourceKind: "dataset",
      mimeType: "application/json",
      payload: { rows: [], schema: {} },
      schema: { type: "object" },
    },
  });
  const sourceApiPayload = creatorDefinition("source", {
    creatorId: "source.api_payload",
    label: "Webhook/API payload",
    description: "Structured request body, webhook payload, or API sample.",
    metricLabel: "Payload",
    metricValue: "json",
    defaultLogic: {
      sourceKind: "api_payload",
      mimeType: "application/json",
      payload: { body: {} },
      schema: { type: "object" },
    },
  });
  const triggerChat = creatorDefinition("trigger", {
    creatorId: "trigger.chat",
    label: "Chat trigger",
    description: "Start from an inbound chat message payload.",
    metricValue: "chat",
    defaultLogic: {
      triggerKind: "event",
      eventSourceRef: "chat.message",
      runtimeReady: false,
      dedupeKey: "{{message.id}}",
      payload: { message: "" },
    },
  });
  const triggerManual = creatorDefinition("trigger", {
    creatorId: "trigger.manual",
    label: "Manual trigger",
    description: "Run on demand from the workbench.",
    metricValue: "manual",
    defaultLogic: {
      triggerKind: "manual",
      runtimeReady: true,
      dedupeKey: "",
    },
  });
  const triggerScheduled = creatorDefinition("trigger", {
    creatorId: "trigger.scheduled",
    label: "Scheduled trigger",
    description: "Start a workflow on a cron-style schedule.",
    metricValue: "cron",
    defaultLogic: {
      triggerKind: "scheduled",
      cronSchedule: "0 9 * * 1",
      runtimeReady: false,
      dedupeKey: "{{scheduled_at}}",
    },
  });
  const triggerEvent = creatorDefinition("trigger", {
    creatorId: "trigger.event",
    label: "Event trigger",
    description: "Start from a connector or app event payload.",
    metricValue: "event",
    defaultLogic: {
      triggerKind: "event",
      eventSourceRef: "",
      runtimeReady: false,
      dedupeKey: "{{event.id}}",
    },
  });
  const functionJavascript = creatorDefinition("function", {
    creatorId: "function.javascript",
    label: "JavaScript function",
    description: "Run sandboxed JavaScript with typed input and output schemas.",
    metricValue: "javascript",
    defaultLogic: {
      language: "javascript",
      code: "return { result: input };",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "javascript",
        code: "return { result: input };",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    defaultLaw: { sandboxPolicy: DEFAULT_SANDBOX },
  });
  const functionTypescript = creatorDefinition("function", {
    creatorId: "function.typescript",
    label: "TypeScript function",
    description: "Author a sandboxed TypeScript function with schemas.",
    metricValue: "typescript",
    defaultLogic: {
      language: "typescript",
      code: "return { result: input };",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "typescript",
        code: "return { result: input };",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    defaultLaw: { sandboxPolicy: DEFAULT_SANDBOX },
  });
  const functionPython = creatorDefinition("function", {
    creatorId: "function.python",
    label: "Python function",
    description:
      "Prepare a Python function; validation blocks execution until Python sandbox support is enabled.",
    metricValue: "python",
    defaultLogic: {
      language: "python",
      code: "def run(input):\n    return {\"result\": input}",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "python",
        code: "def run(input):\n    return {\"result\": input}",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    defaultLaw: { sandboxPolicy: DEFAULT_SANDBOX },
  });
  const functionFileBacked = creatorDefinition("function", {
    creatorId: "function.file_backed",
    label: "File-backed function",
    description: "Materialize function code beside the workflow bundle.",
    metricValue: "file",
    defaultLogic: {
      language: "javascript",
      code: "return { result: input };",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      functionBinding: {
        language: "javascript",
        code: "return { result: input };",
        functionRef: {
          runtime: "javascript",
          entrypoint: "run",
          sourcePath: "",
          codeHash: "",
        },
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        sandboxPolicy: DEFAULT_SANDBOX,
        testInput: { payload: "sample" },
      },
    },
    defaultLaw: { sandboxPolicy: DEFAULT_SANDBOX },
  });
  const modelVision = creatorDefinition("model_call", {
    creatorId: "model_call.vision",
    label: "Vision model",
    description: "Call a model with image/media context and structured output.",
    metricValue: "vision",
    defaultLogic: {
      modelRef: "vision",
      prompt: "Inspect the media input and return structured observations.",
      modelBinding: {
        modelRef: "vision",
        mockBinding: true,
        capabilityScope: ["vision"],
        argumentSchema: { type: "object" },
        resultSchema: { type: "object" },
        sideEffectClass: "none",
        requiresApproval: false,
        credentialReady: false,
        toolUseMode: "none",
      },
      validateStructuredOutput: true,
      jsonMode: true,
    },
  });
  const modelEmbedding = creatorDefinition("model_call", {
    creatorId: "model_call.embedding",
    label: "Embedding model",
    description: "Create an embedding or semantic vector from input text.",
    metricValue: "embedding",
    defaultLogic: {
      modelRef: "embedding",
      prompt: "Embed the input for semantic comparison.",
      modelBinding: {
        modelRef: "embedding",
        mockBinding: true,
        capabilityScope: ["embedding"],
        argumentSchema: { type: "object" },
        resultSchema: { type: "object" },
        sideEffectClass: "none",
        requiresApproval: false,
        credentialReady: false,
        toolUseMode: "none",
      },
    },
  });
  const modelEvaluator = creatorDefinition("model_call", {
    creatorId: "model_call.evaluator",
    label: "Evaluator",
    description: "Score or review a previous result with structured criteria.",
    metricValue: "eval",
    defaultLogic: {
      modelRef: "reasoning",
      prompt: "Evaluate the input against the declared criteria.",
      outputSchema: { type: "object" },
      validateStructuredOutput: true,
      jsonMode: true,
    },
  });
  const connectorRead = creatorDefinition("adapter", {
    creatorId: "adapter.read",
    label: "Connector read",
    description: "Read from an external connector with explicit mock/live binding.",
    metricValue: "read",
    defaultLogic: {
      connectorBinding: {
        connectorRef: "",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["read"],
        sideEffectClass: "read",
        requiresApproval: false,
        operation: "read",
      },
    },
  });
  const connectorWrite = creatorDefinition("adapter", {
    creatorId: "adapter.write",
    label: "Connector write",
    description: "Prepare an external write that requires contextual approval.",
    metricValue: "write",
    defaultLogic: {
      connectorBinding: {
        connectorRef: "",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["write"],
        sideEffectClass: "external_write",
        requiresApproval: true,
        operation: "write",
      },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["external_write"],
    },
  });
  const pluginTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.plugin",
    label: "Plugin/MCP tool",
    description: "Call a plugin or MCP tool through an explicit binding.",
    metricValue: "tool",
    defaultLogic: workflowNodeDefaultLogic("plugin_tool"),
  });
  const mcpTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.mcp",
    label: "MCP tool",
    description: "Call an MCP tool through an explicit mock or live binding.",
    metricValue: "mcp",
    defaultLogic: {
      toolBinding: {
        toolRef: "",
        bindingKind: "mcp_tool",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["read"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
      },
    },
  });
  const browserTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.browser",
    label: "Browser/computer tool",
    description: "Prepare a privileged browser or computer-use tool call.",
    metricValue: "privileged",
    defaultLogic: {
      toolBinding: {
        toolRef: "",
        bindingKind: "plugin_tool",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["browser", "computer"],
        sideEffectClass: "external_write",
        requiresApproval: true,
        arguments: {},
      },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["computer_use", "browser_action"],
    },
  });
  const workflowTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.workflow_tool",
    label: "Workflow tool",
    description: "Call another workflow as a schema-bound tool.",
    metricValue: "subflow",
    defaultLogic: {
      toolBinding: {
        toolRef: "",
        bindingKind: "workflow_tool",
        mockBinding: true,
        credentialReady: true,
        capabilityScope: ["workflow_tool"],
        sideEffectClass: "none",
        requiresApproval: false,
        workflowTool: {
          workflowPath: "",
          argumentSchema: { type: "object" },
          resultSchema: { type: "object" },
          timeoutMs: 30000,
          maxAttempts: 1,
        },
      },
    },
  });
  const outputInline = creatorDefinition("output", {
    creatorId: "output.inline",
    label: "Inline output",
    description: "Create a workflow output rendered inline or on the canvas.",
    metricValue: "inline",
    defaultLogic: {
      format: "markdown",
      rendererRef: { rendererId: "markdown", displayMode: "inline" },
      materialization: { enabled: false },
      retentionPolicy: { retentionKind: "run_scoped", ttlMs: 2592000000 },
    },
  });
  const outputFile = creatorDefinition("output", {
    creatorId: "output.file",
    label: "File output",
    description: "Materialize a durable local file with output evidence.",
    metricValue: "file",
    defaultLogic: {
      format: "json",
      path: "outputs/result.json",
      rendererRef: { rendererId: "json", displayMode: "json" },
      materialization: {
        enabled: true,
        assetPath: "outputs/result.json",
        assetKind: "file",
      },
      deliveryTarget: { targetKind: "local_file", requiresApproval: false },
      retentionPolicy: { retentionKind: "versioned" },
    },
  });
  const outputMedia = creatorDefinition("output", {
    creatorId: "output.media",
    label: "Media output",
    description: "Render or materialize image, SVG, audio, or video output.",
    metricValue: "media",
    defaultLogic: {
      format: "svg",
      path: "outputs/result.svg",
      fileExtension: "svg",
      mimeType: "image/svg+xml",
      rendererRef: { rendererId: "media", displayMode: "media" },
      materialization: {
        enabled: false,
        assetPath: "outputs/result.svg",
        assetKind: "svg",
      },
      retentionPolicy: { retentionKind: "versioned" },
    },
  });
  const outputDelivery = creatorDefinition("output", {
    creatorId: "output.delivery_draft",
    label: "Delivery draft",
    description: "Prepare a message, ticket, or connector delivery draft.",
    metricValue: "draft",
    defaultLogic: {
      format: "message",
      rendererRef: { rendererId: "report", displayMode: "report" },
      materialization: { enabled: false },
      deliveryTarget: {
        targetKind: "message_draft",
        targetRef: "",
        requiresApproval: true,
      },
      retentionPolicy: { retentionKind: "run_scoped", ttlMs: 2592000000 },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["message_sending"],
    },
  });
  const outputTable = creatorDefinition("output", {
    creatorId: "output.table",
    label: "Table output",
    description: "Render structured rows as a table output bundle.",
    metricValue: "table",
    defaultLogic: {
      format: "dataset",
      rendererRef: { rendererId: "table", displayMode: "table" },
      materialization: { enabled: false },
      deliveryTarget: { targetKind: "none" },
      retentionPolicy: { retentionKind: "run_scoped", ttlMs: 2592000000 },
    },
  });
  const outputPatch = creatorDefinition("output", {
    creatorId: "output.patch",
    label: "Patch/proposal output",
    description: "Produce a patch or proposal output without applying changes.",
    metricValue: "patch",
    defaultLogic: {
      format: "patch",
      rendererRef: { rendererId: "patch", displayMode: "diff" },
      materialization: { enabled: false },
      deliveryTarget: { targetKind: "repo_patch", requiresApproval: true },
      retentionPolicy: { retentionKind: "versioned" },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["bounded_self_mutation"],
    },
  });
  const outputDeploy = creatorDefinition("output", {
    creatorId: "output.deploy",
    label: "Deploy target",
    description: "Prepare deployment output that blocks on readiness and approval.",
    metricValue: "deploy",
    defaultLogic: {
      format: "report",
      rendererRef: { rendererId: "report", displayMode: "report" },
      materialization: { enabled: false },
      deliveryTarget: { targetKind: "deploy", requiresApproval: true },
      retentionPolicy: { retentionKind: "versioned" },
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["deploy"],
    },
  });
  const stateRead = creatorDefinition("state", {
    creatorId: "state.read",
    label: "State read",
    description: "Read workflow state or memory by key.",
    metricValue: "read",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "read",
      reducer: "replace",
    },
  });
  const stateWrite = creatorDefinition("state", {
    creatorId: "state.write",
    label: "State write",
    description: "Replace workflow state at a declared key.",
    metricValue: "write",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "write",
      reducer: "replace",
      initialValue: {},
    },
  });
  const stateAppend = creatorDefinition("state", {
    creatorId: "state.append",
    label: "State append",
    description: "Append input into retained workflow state.",
    metricValue: "append",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "append",
      reducer: "append",
      initialValue: [],
    },
  });
  const stateReducer = creatorDefinition("state", {
    creatorId: "state.reducer",
    label: "State reducer",
    description: "Merge input into workflow state with deterministic reducer rules.",
    metricValue: "merge",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "merge",
      reducer: "merge",
      initialValue: {},
    },
  });
  const stateCheckpoint = creatorDefinition("state", {
    creatorId: "state.checkpoint",
    label: "Checkpoint read/fork",
    description: "Reference checkpoint state for replay or forked execution.",
    metricValue: "checkpoint",
    defaultLogic: {
      stateKey: "checkpoint",
      stateOperation: "read",
      reducer: "replace",
    },
  });

  return [
    triggerManual,
    triggerScheduled,
    triggerEvent,
    triggerChat,
    sourceManual,
    sourceFile,
    sourceMedia,
    sourceDataset,
    sourceApiPayload,
    functionJavascript,
    functionTypescript,
    functionPython,
    functionFileBacked,
    modelVision,
    modelEmbedding,
    modelEvaluator,
    stateRead,
    stateWrite,
    stateAppend,
    stateReducer,
    stateCheckpoint,
    ...WORKFLOW_NODE_DEFINITIONS.filter(
      (definition) =>
        !["source", "trigger", "adapter", "plugin_tool", "output"].includes(
          definition.type,
        ),
    ).map((definition) =>
      creatorDefinition(definition.type, {
        creatorId: definition.type,
        label: definition.label,
        description: `${definition.familyLabel} primitive backed by ${definition.executor.executorId}.`,
      }),
    ),
    connectorRead,
    connectorWrite,
    pluginTool,
    mcpTool,
    browserTool,
    workflowTool,
    outputInline,
    outputFile,
    outputMedia,
    outputTable,
    outputPatch,
    outputDelivery,
    outputDeploy,
  ];
}

export function workflowScaffoldDefinitions(): WorkflowScaffoldDefinition[] {
  return WORKFLOW_NODE_DEFINITIONS.map((definition) => ({
    scaffoldId: `workflow.${definition.type}`,
    nodeType: definition.type,
    family: definition.family,
    label: definition.label,
    description: `${definition.familyLabel} node with typed ports and ${definition.executor.executorId} execution.`,
    defaultName: definition.label,
    connectionClasses: Array.from(
      new Set(
        definition.portDefinitions.map(
          (portDefinition) => portDefinition.connectionClass,
        ),
      ),
    ),
    relatedNodeTypes: relatedNodeTypesFor(definition.type),
    keywords: [
      definition.label,
      definition.familyLabel,
      definition.group,
      definition.executor.executorId,
      ...definition.portDefinitions.map(
        (portDefinition) => portDefinition.connectionClass,
      ),
    ].map((item) => item.toLowerCase()),
  }));
}

export function workflowNodeActionDefinitions(): WorkflowNodeActionDefinition[] {
  return WORKFLOW_NODE_DEFINITIONS.map((definition) => {
    const connectionClasses = Array.from(
      new Set(
        definition.portDefinitions.map(
          (portDefinition) => portDefinition.connectionClass,
        ),
      ),
    );
    const requiredBinding = requiredBindingFor(definition.type);
    const compatibleNodeTypes = relatedNodeTypesFor(definition.type);
    return {
      actionId: `workflow.action.${definition.type}`,
      nodeType: definition.type,
      family: definition.family,
      label: definition.label,
      description: `${definition.familyLabel} action backed by ${definition.executor.executorId}.`,
      category: definition.group,
      requiredBinding,
      bindingMode: requiredBinding ? "required" : "none",
      supportsMockBinding: supportsMockBinding(definition.type),
      sideEffectClass: definition.policyProfile.sideEffectClass,
      requiresApproval: definition.policyProfile.requiresApproval,
      sandboxed: definition.executor.sandboxed,
      supportsDryRun: definition.executor.supportsDryRun,
      schemaRequired: schemaRequiredFor(definition.type),
      connectionClasses,
      compatibleNodeTypes,
      keywords: [
        definition.label,
        definition.familyLabel,
        definition.group,
        definition.executor.executorId,
        definition.policyProfile.sideEffectClass,
        requiredBinding ?? "",
        ...connectionClasses,
      ]
        .filter(Boolean)
        .map((item) => item.toLowerCase()),
    };
  });
}

function relatedNodeTypesFor(type: WorkflowNodeKind): WorkflowNodeKind[] {
  switch (type) {
    case "trigger":
    case "source":
      return ["function", "model_call", "adapter", "plugin_tool", "output"];
    case "model_call":
      return [
        "model_binding",
        "parser",
        "state",
        "plugin_tool",
        "decision",
        "human_gate",
        "output",
      ];
    case "model_binding":
      return ["model_call"];
    case "parser":
      return ["model_call"];
    case "plugin_tool":
      return ["model_call", "decision", "output"];
    case "adapter":
      return ["decision", "function", "human_gate", "output"];
    case "function":
      return ["test_assertion", "model_call", "output"];
    case "decision":
      return ["function", "human_gate", "output"];
    case "state":
      return ["model_call", "decision", "output"];
    case "subgraph":
      return ["model_call", "output"];
    case "proposal":
      return ["human_gate", "test_assertion", "output"];
    default:
      return ["output"];
  }
}

function requiredBindingFor(
  type: WorkflowNodeKind,
): WorkflowNodeActionDefinition["requiredBinding"] {
  switch (type) {
    case "function":
      return "function";
    case "model_binding":
    case "model_call":
      return "model";
    case "parser":
      return "parser";
    case "adapter":
      return "connector";
    case "plugin_tool":
      return "tool";
    case "subgraph":
      return "subgraph";
    case "proposal":
      return "proposal";
    default:
      return undefined;
  }
}

function supportsMockBinding(type: WorkflowNodeKind): boolean {
  return (
    type === "model_binding" ||
    type === "parser" ||
    type === "adapter" ||
    type === "plugin_tool" ||
    type === "subgraph"
  );
}

function schemaRequiredFor(type: WorkflowNodeKind): boolean {
  return (
    type === "function" ||
    type === "model_call" ||
    type === "parser" ||
    type === "plugin_tool" ||
    type === "adapter" ||
    type === "subgraph" ||
    type === "output" ||
    type === "test_assertion"
  );
}

export function makeWorkflowNode(
  id: string,
  type: WorkflowNodeKind,
  name: string,
  x: number,
  y: number,
  logic?: NodeLogic,
  law?: FirewallPolicy,
  metric?: Partial<Pick<Node, "metricLabel" | "metricValue">>,
): WorkflowNode {
  const defaults = workflowNodeDefaults(type);
  return {
    id,
    type,
    name,
    x,
    y,
    ...defaults,
    ...metric,
    config: {
      kind: type,
      logic: logic ? clone(logic) : workflowNodeDefaultLogic(type),
      law: law ? clone(law) : workflowNodeDefaultLaw(type),
    },
  };
}

export function makeWorkflowEdge(
  id: string,
  from: string,
  to: string,
  fromPort = "output",
  toPort = "input",
  connectionClass: WorkflowConnectionClass = "data",
): WorkflowEdge {
  return {
    id,
    from,
    to,
    fromPort,
    toPort,
    type: connectionClass === "control" ? "control" : "data",
    connectionClass,
    data: { connectionClass },
  };
}
