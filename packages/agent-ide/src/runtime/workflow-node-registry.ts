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
import {
  runtimeNodeAccessibility,
  runtimeNodeChromeLogic,
  runtimeNodeLocalization,
} from "./workflow-runtime-ui-strings";

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

const RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES = {
  runtimeUiStringCatalogRef: { type: "string" },
  workflowChromeLocale: { type: "string" },
  localeKey: { type: "string" },
  ariaLabelKey: { type: "string" },
  statusAnnouncementKey: { type: "string" },
  accessibleStatusField: { type: "string" },
  colorIndependentStatus: { type: "boolean" },
} as const;

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

export const WORKFLOW_SKILL_CONTEXT_OUTPUT_SCHEMA = {
  type: "object",
  required: [
    "schemaVersion",
    "status",
    "mode",
    "selectedSkills",
    "promptContext",
    "evidenceRefs",
  ],
  properties: {
    schemaVersion: { type: "string" },
    status: { type: "string" },
    mode: { type: "string" },
    goal: { type: "string" },
    selectedSkills: {
      type: "array",
      items: {
        type: "object",
        required: [
          "skillHash",
          "name",
          "description",
          "lifecycleState",
          "sourceType",
          "stale",
          "score",
          "guidanceHash",
        ],
        properties: {
          skillHash: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          lifecycleState: { type: "string" },
          sourceType: { type: "string" },
          stale: { type: "boolean" },
          relativePath: { type: "string" },
          score: { type: "number" },
          guidanceHash: { type: "string" },
          guidanceMarkdown: { type: "string" },
        },
      },
    },
    promptContext: { type: "string" },
    evidenceRefs: { type: "array", items: { type: "string" } },
  },
};

export const DEFAULT_WORKFLOW_SKILL_CONTEXT_LOGIC: NodeLogic = {
  skillContext: {
    mode: "discover",
    goalSource: "node_input",
    goal: "",
    minScoreBps: 6500,
    maxSkills: 3,
    onNoMatch: "warn",
    pinnedSkills: [],
    onMissingPinned: "block",
    includeMarkdown: true,
    guidanceMaxChars: 1800,
  },
  outputSchema: WORKFLOW_SKILL_CONTEXT_OUTPUT_SCHEMA,
};

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
    type: "runtime_doctor",
    label: "Runtime Doctor",
    group: "Tests",
    family: "tests",
    token: "RX",
    familyLabel: "Doctor",
    metricLabel: "Readiness",
    metricValue: "preflight",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["report", "blockers"],
    portDefinitions: [
      port("report", "Doctor report", "output", "state", "output", false, "state"),
      port("blockers", "Blockers", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("report", "Doctor report", "output", "state", "output", false, "state"),
      port("blockers", "Blockers", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["doctorEndpoint", "blockOnRequiredFailures"],
      properties: {
        doctorEndpoint: { type: "string" },
        blockOnRequiredFailures: { type: "boolean" },
        allowOptionalDegraded: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_doctor"),
    accessibility: runtimeNodeAccessibility("runtime_doctor", "status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_doctor",
      executorId: "workflow.runtime_doctor",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("runtime_doctor", "status"),
      doctorEndpoint: "/v1/doctor",
      blockOnRequiredFailures: true,
      allowOptionalDegraded: true,
      redactionProfile: "doctor_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "checks", "blockers", "redaction"],
      },
      activationGate: {
        consumesDoctorReport: true,
        blockerField: "blockers",
        optionalWarningsField: "optionalWarnings",
      },
      nodeTypeLabel: "RuntimeDoctorNode",
    },
    defaultLaw: {},
  },
  {
    type: "runtime_task",
    label: "Runtime Task",
    group: "State",
    family: "state",
    token: "RT",
    familyLabel: "Runtime",
    metricLabel: "Task",
    metricValue: "durable",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["task", "status"],
    portDefinitions: [
      port("task", "Runtime task", "output", "state", "output", false, "state"),
      port("status", "Task status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("task", "Runtime task", "output", "state", "output", false, "state"),
      port("status", "Task status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["runtimeTaskEndpoint", "runtimeTaskField"],
      properties: {
        runtimeTaskEndpoint: { type: "string" },
        runtimeTaskField: { type: "string" },
        runtimeTaskStatusField: { type: "string" },
        runtimeTaskReceiptField: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_task"),
    accessibility: runtimeNodeAccessibility("runtime_task", "runtimeTask.status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_task",
      executorId: "workflow.runtime_task",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("runtime_task", "runtimeTask.status"),
      runtimeTaskEndpoint: "/v1/jobs",
      runtimeTaskField: "runtimeTask",
      runtimeTaskStatusField: "runtimeTask.status",
      runtimeTaskReceiptField: "runtimeTask.receiptId",
      readOnly: true,
      redactionProfile: "runtime_task_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "taskId", "runId", "status", "durable", "replayable", "redaction"],
        properties: {
          runtimeTask: { type: "object" },
          status: { type: "string" },
          taskFamily: { type: "string" },
        },
      },
      activationGate: {
        consumesRuntimeTask: true,
        runtimeTaskField: "runtimeTask",
        runtimeTaskStatusField: "runtimeTask.status",
      },
      nodeTypeLabel: "RuntimeTaskNode",
    },
    defaultLaw: {},
  },
  {
    type: "runtime_job",
    label: "Runtime Job",
    group: "State",
    family: "state",
    token: "RJ",
    familyLabel: "Runtime",
    metricLabel: "Job",
    metricValue: "queued",
    ioTypes: { in: "state", out: "state" },
    inputs: ["task"],
    outputs: ["job", "status", "events"],
    portDefinitions: [
      port("task", "Runtime task", "input", "state", "state", false, "state"),
      port("job", "Runtime job", "output", "state", "output", false, "state"),
      port("status", "Job status", "output", "state", "output", false, "state"),
      port("events", "Lifecycle events", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("task", "Runtime task", "input", "state", "state", false, "state"),
      port("job", "Runtime job", "output", "state", "output", false, "state"),
      port("status", "Job status", "output", "state", "output", false, "state"),
      port("events", "Lifecycle events", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["runtimeJobEndpoint", "runtimeJobField"],
      properties: {
        runtimeJobEndpoint: { type: "string" },
        runtimeJobField: { type: "string" },
        runtimeJobStatusField: { type: "string" },
        runtimeJobLifecycleField: { type: "string" },
        runtimeJobQueueField: { type: "string" },
        runtimeJobCancelEndpoint: { type: "string" },
        runtimeJobCancelable: { type: "boolean" },
        runtimeJobCancelRoute: { type: "string" },
        runtimeJobReceiptField: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_job"),
    accessibility: runtimeNodeAccessibility("runtime_job", "runtimeJob.status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_job",
      executorId: "workflow.runtime_job",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("runtime_job", "runtimeJob.status"),
      runtimeJobEndpoint: "/v1/jobs",
      runtimeJobField: "runtimeJob",
      runtimeJobStatusField: "runtimeJob.status",
      runtimeJobLifecycleField: "runtimeJob.lifecycle",
      runtimeJobQueueField: "runtimeJob.queueName",
      runtimeJobCancelEndpoint: "/v1/jobs/{jobId}/cancel",
      runtimeJobCancelable: true,
      runtimeJobCancelRoute: "job_cancel_route",
      runtimeJobReceiptField: "runtimeJob.receiptId",
      runtimeTaskField: "runtimeTask",
      readOnly: true,
      redactionProfile: "runtime_job_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "jobId", "taskId", "runId", "status", "durable", "replayable", "endpoints", "redaction"],
        properties: {
          runtimeJob: { type: "object" },
          status: { type: "string" },
          lifecycle: { type: "array" },
          queueName: { type: "string" },
        },
      },
      activationGate: {
        consumesRuntimeTask: true,
        consumesRuntimeJob: true,
        runtimeTaskField: "runtimeTask",
        runtimeJobField: "runtimeJob",
        runtimeJobStatusField: "runtimeJob.status",
      },
      nodeTypeLabel: "RuntimeJobNode",
    },
    defaultLaw: {},
  },
  {
    type: "runtime_checklist",
    label: "Runtime Checklist",
    group: "State",
    family: "state",
    token: "CL",
    familyLabel: "Runtime",
    metricLabel: "Checklist",
    metricValue: "ready",
    ioTypes: { in: "state", out: "state" },
    inputs: ["task", "job"],
    outputs: ["checklist", "items", "status"],
    portDefinitions: [
      port("task", "Runtime task", "input", "state", "state", false, "state"),
      port("job", "Runtime job", "input", "state", "state", false, "state"),
      port("checklist", "Runtime checklist", "output", "state", "output", false, "state"),
      port("items", "Checklist items", "output", "state", "output", false, "state"),
      port("status", "Checklist status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("task", "Runtime task", "input", "state", "state", false, "state"),
      port("job", "Runtime job", "input", "state", "state", false, "state"),
      port("checklist", "Runtime checklist", "output", "state", "output", false, "state"),
      port("items", "Checklist items", "output", "state", "output", false, "state"),
      port("status", "Checklist status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["runtimeChecklistEndpoint", "runtimeChecklistField"],
      properties: {
        runtimeChecklistEndpoint: { type: "string" },
        runtimeChecklistField: { type: "string" },
        runtimeChecklistStatusField: { type: "string" },
        runtimeChecklistItemsField: { type: "string" },
        runtimeChecklistReceiptField: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_checklist"),
    accessibility: runtimeNodeAccessibility("runtime_checklist", "runtimeChecklist.status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_checklist",
      executorId: "workflow.runtime_checklist",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("runtime_checklist", "runtimeChecklist.status"),
      runtimeChecklistEndpoint: "/v1/runs/{runId}/trace",
      runtimeChecklistField: "runtimeChecklist",
      runtimeChecklistStatusField: "runtimeChecklist.status",
      runtimeChecklistItemsField: "runtimeChecklist.items",
      runtimeChecklistReceiptField: "runtimeChecklist.receiptId",
      runtimeTaskField: "runtimeTask",
      runtimeJobField: "runtimeJob",
      readOnly: true,
      redactionProfile: "runtime_checklist_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "checklistId", "taskId", "jobId", "runId", "status", "itemCount", "durable", "replayable", "redaction"],
        properties: {
          runtimeChecklist: { type: "object" },
          status: { type: "string" },
          items: { type: "array" },
          itemCount: { type: "number" },
        },
      },
      activationGate: {
        consumesRuntimeTask: true,
        consumesRuntimeJob: true,
        consumesRuntimeChecklist: true,
        runtimeTaskField: "runtimeTask",
        runtimeJobField: "runtimeJob",
        runtimeChecklistField: "runtimeChecklist",
        runtimeChecklistStatusField: "runtimeChecklist.status",
      },
      nodeTypeLabel: "RuntimeChecklistNode",
    },
    defaultLaw: {},
  },
  {
    type: "runtime_thread_fork",
    label: "Runtime Thread Fork",
    group: "Flow",
    family: "flow_control",
    token: "TF",
    familyLabel: "Runtime",
    metricLabel: "Fork",
    metricValue: "control",
    ioTypes: { in: "state", out: "state" },
    inputs: ["thread"],
    outputs: ["fork", "event", "status"],
    portDefinitions: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("fork", "Fork request", "output", "state", "output", false, "state"),
      port("event", "Fork event", "output", "state", "output", false, "state"),
      port("status", "Fork status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("fork", "Fork request", "output", "state", "output", false, "state"),
      port("event", "Fork event", "output", "state", "output", false, "state"),
      port("status", "Fork status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeThreadForkEndpoint",
        "runtimeThreadForkThreadIdField",
        "runtimeThreadForkWorkflowNodeId",
      ],
      properties: {
        runtimeThreadForkEndpoint: { type: "string" },
        runtimeThreadForkField: { type: "string" },
        runtimeThreadForkEventField: { type: "string" },
        runtimeThreadForkStatusField: { type: "string" },
        runtimeThreadForkReceiptField: { type: "string" },
        runtimeThreadForkPolicyField: { type: "string" },
        runtimeThreadForkThreadId: { type: "string" },
        runtimeThreadForkThreadIdField: { type: "string" },
        runtimeThreadForkReason: { type: "string" },
        runtimeThreadForkReasonField: { type: "string" },
        runtimeThreadForkWorkflowNodeId: { type: "string" },
        runtimeThreadForkSource: { type: "string" },
        runtimeThreadForkActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_thread_fork"),
    accessibility: runtimeNodeAccessibility("runtime_thread_fork", "runtimeThreadFork.status"),
    policyProfile: policyProfile("write"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_thread_fork",
      executorId: "workflow.runtime_thread_fork",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("runtime_thread_fork", "runtimeThreadFork.status"),
      runtimeThreadForkEndpoint: "/v1/threads/{threadId}/fork",
      runtimeThreadForkField: "runtimeThreadFork",
      runtimeThreadForkEventField: "runtimeThreadFork.event",
      runtimeThreadForkStatusField: "runtimeThreadFork.status",
      runtimeThreadForkReceiptField: "runtimeThreadFork.receiptRefs",
      runtimeThreadForkPolicyField: "runtimeThreadFork.policyDecisionRefs",
      runtimeThreadForkThreadIdField: "threadId",
      runtimeThreadForkReasonField: "reason",
      runtimeThreadForkReason: "Fork thread from React Flow workflow control.",
      runtimeThreadForkWorkflowNodeId: "runtime.thread-fork",
      runtimeThreadForkSource: "react_flow",
      runtimeThreadForkActor: "operator",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_thread_fork_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "request"],
        properties: {
          runtimeThreadFork: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeThreadFork: true,
        runtimeThreadForkField: "runtimeThreadFork",
        runtimeThreadForkStatusField: "runtimeThreadFork.status",
      },
      nodeTypeLabel: "RuntimeThreadForkNode",
    },
    defaultLaw: { privilegedActions: ["runtime.thread.fork"] },
  },
  {
    type: "runtime_operator_interrupt",
    label: "Runtime Operator Interrupt",
    group: "Flow",
    family: "flow_control",
    token: "INT",
    familyLabel: "Runtime",
    metricLabel: "Interrupt",
    metricValue: "control",
    ioTypes: { in: "state", out: "state" },
    inputs: ["turn"],
    outputs: ["interrupt", "event", "status"],
    portDefinitions: [
      port("turn", "Turn state", "input", "state", "state", false, "state"),
      port("interrupt", "Interrupt request", "output", "state", "output", false, "state"),
      port("event", "Interrupt event", "output", "state", "output", false, "state"),
      port("status", "Interrupt status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("turn", "Turn state", "input", "state", "state", false, "state"),
      port("interrupt", "Interrupt request", "output", "state", "output", false, "state"),
      port("event", "Interrupt event", "output", "state", "output", false, "state"),
      port("status", "Interrupt status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeOperatorInterruptEndpoint",
        "runtimeOperatorInterruptThreadIdField",
        "runtimeOperatorInterruptTurnIdField",
        "runtimeOperatorInterruptWorkflowNodeId",
      ],
      properties: {
        runtimeOperatorInterruptEndpoint: { type: "string" },
        runtimeOperatorInterruptField: { type: "string" },
        runtimeOperatorInterruptEventField: { type: "string" },
        runtimeOperatorInterruptStatusField: { type: "string" },
        runtimeOperatorInterruptReceiptField: { type: "string" },
        runtimeOperatorInterruptPolicyField: { type: "string" },
        runtimeOperatorInterruptThreadId: { type: "string" },
        runtimeOperatorInterruptThreadIdField: { type: "string" },
        runtimeOperatorInterruptTurnId: { type: "string" },
        runtimeOperatorInterruptTurnIdField: { type: "string" },
        runtimeOperatorInterruptReason: { type: "string" },
        runtimeOperatorInterruptReasonField: { type: "string" },
        runtimeOperatorInterruptWorkflowNodeId: { type: "string" },
        runtimeOperatorInterruptSource: { type: "string" },
        runtimeOperatorInterruptActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_operator_interrupt"),
    accessibility: runtimeNodeAccessibility(
      "runtime_operator_interrupt",
      "runtimeOperatorInterrupt.status",
    ),
    policyProfile: policyProfile("write"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_operator_interrupt",
      executorId: "workflow.runtime_operator_interrupt",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_operator_interrupt",
        "runtimeOperatorInterrupt.status",
      ),
      runtimeOperatorInterruptEndpoint:
        "/v1/threads/{threadId}/turns/{turnId}/interrupt",
      runtimeOperatorInterruptField: "runtimeOperatorInterrupt",
      runtimeOperatorInterruptEventField: "runtimeOperatorInterrupt.event",
      runtimeOperatorInterruptStatusField: "runtimeOperatorInterrupt.status",
      runtimeOperatorInterruptReceiptField: "runtimeOperatorInterrupt.receiptRefs",
      runtimeOperatorInterruptPolicyField:
        "runtimeOperatorInterrupt.policyDecisionRefs",
      runtimeOperatorInterruptThreadIdField: "threadId",
      runtimeOperatorInterruptTurnIdField: "turnId",
      runtimeOperatorInterruptReasonField: "reason",
      runtimeOperatorInterruptReason:
        "Interrupt turn from React Flow workflow control.",
      runtimeOperatorInterruptWorkflowNodeId: "runtime.operator-interrupt",
      runtimeOperatorInterruptSource: "react_flow",
      runtimeOperatorInterruptActor: "operator",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_operator_interrupt_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "request"],
        properties: {
          runtimeOperatorInterrupt: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeOperatorInterrupt: true,
        runtimeOperatorInterruptField: "runtimeOperatorInterrupt",
        runtimeOperatorInterruptStatusField: "runtimeOperatorInterrupt.status",
      },
      nodeTypeLabel: "RuntimeOperatorInterruptNode",
    },
    defaultLaw: { privilegedActions: ["runtime.turn.interrupt"] },
  },
  {
    type: "runtime_operator_steer",
    label: "Runtime Operator Steer",
    group: "Flow",
    family: "flow_control",
    token: "ST",
    familyLabel: "Runtime",
    metricLabel: "Steer",
    metricValue: "control",
    ioTypes: { in: "state", out: "state" },
    inputs: ["turn"],
    outputs: ["steer", "event", "status"],
    portDefinitions: [
      port("turn", "Turn state", "input", "state", "state", false, "state"),
      port("steer", "Steer request", "output", "state", "output", false, "state"),
      port("event", "Steer event", "output", "state", "output", false, "state"),
      port("status", "Steer status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("turn", "Turn state", "input", "state", "state", false, "state"),
      port("steer", "Steer request", "output", "state", "output", false, "state"),
      port("event", "Steer event", "output", "state", "output", false, "state"),
      port("status", "Steer status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeOperatorSteerEndpoint",
        "runtimeOperatorSteerThreadIdField",
        "runtimeOperatorSteerTurnIdField",
        "runtimeOperatorSteerWorkflowNodeId",
      ],
      properties: {
        runtimeOperatorSteerEndpoint: { type: "string" },
        runtimeOperatorSteerField: { type: "string" },
        runtimeOperatorSteerEventField: { type: "string" },
        runtimeOperatorSteerStatusField: { type: "string" },
        runtimeOperatorSteerReceiptField: { type: "string" },
        runtimeOperatorSteerPolicyField: { type: "string" },
        runtimeOperatorSteerThreadId: { type: "string" },
        runtimeOperatorSteerThreadIdField: { type: "string" },
        runtimeOperatorSteerTurnId: { type: "string" },
        runtimeOperatorSteerTurnIdField: { type: "string" },
        runtimeOperatorSteerGuidance: { type: "string" },
        runtimeOperatorSteerGuidanceField: { type: "string" },
        runtimeOperatorSteerWorkflowNodeId: { type: "string" },
        runtimeOperatorSteerSource: { type: "string" },
        runtimeOperatorSteerActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_operator_steer"),
    accessibility: runtimeNodeAccessibility(
      "runtime_operator_steer",
      "runtimeOperatorSteer.status",
    ),
    policyProfile: policyProfile("write"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_operator_steer",
      executorId: "workflow.runtime_operator_steer",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_operator_steer",
        "runtimeOperatorSteer.status",
      ),
      runtimeOperatorSteerEndpoint:
        "/v1/threads/{threadId}/turns/{turnId}/steer",
      runtimeOperatorSteerField: "runtimeOperatorSteer",
      runtimeOperatorSteerEventField: "runtimeOperatorSteer.event",
      runtimeOperatorSteerStatusField: "runtimeOperatorSteer.status",
      runtimeOperatorSteerReceiptField: "runtimeOperatorSteer.receiptRefs",
      runtimeOperatorSteerPolicyField: "runtimeOperatorSteer.policyDecisionRefs",
      runtimeOperatorSteerThreadIdField: "threadId",
      runtimeOperatorSteerTurnIdField: "turnId",
      runtimeOperatorSteerGuidanceField: "guidance",
      runtimeOperatorSteerGuidance: "Steer turn from React Flow workflow control.",
      runtimeOperatorSteerWorkflowNodeId: "runtime.operator-steer",
      runtimeOperatorSteerSource: "react_flow",
      runtimeOperatorSteerActor: "operator",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_operator_steer_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "request"],
        properties: {
          runtimeOperatorSteer: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeOperatorSteer: true,
        runtimeOperatorSteerField: "runtimeOperatorSteer",
        runtimeOperatorSteerStatusField: "runtimeOperatorSteer.status",
      },
      nodeTypeLabel: "RuntimeOperatorSteerNode",
    },
    defaultLaw: { privilegedActions: ["runtime.turn.steer"] },
  },
  {
    type: "runtime_context_compact",
    label: "Runtime Context Compact",
    group: "Flow",
    family: "flow_control",
    token: "CC",
    familyLabel: "Runtime",
    metricLabel: "Compact",
    metricValue: "control",
    ioTypes: { in: "state", out: "state" },
    inputs: ["thread"],
    outputs: ["compact", "event", "status"],
    portDefinitions: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("compact", "Compact request", "output", "state", "output", false, "state"),
      port("event", "Compaction event", "output", "state", "output", false, "state"),
      port("status", "Compaction status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("compact", "Compact request", "output", "state", "output", false, "state"),
      port("event", "Compaction event", "output", "state", "output", false, "state"),
      port("status", "Compaction status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeContextCompactEndpoint",
        "runtimeContextCompactThreadIdField",
        "runtimeContextCompactWorkflowNodeId",
      ],
      properties: {
        runtimeContextCompactEndpoint: { type: "string" },
        runtimeContextCompactField: { type: "string" },
        runtimeContextCompactEventField: { type: "string" },
        runtimeContextCompactStatusField: { type: "string" },
        runtimeContextCompactReceiptField: { type: "string" },
        runtimeContextCompactPolicyField: { type: "string" },
        runtimeContextCompactThreadId: { type: "string" },
        runtimeContextCompactThreadIdField: { type: "string" },
        runtimeContextCompactTurnId: { type: "string" },
        runtimeContextCompactTurnIdField: { type: "string" },
        runtimeContextCompactReason: { type: "string" },
        runtimeContextCompactReasonField: { type: "string" },
        runtimeContextCompactScope: { type: "string" },
        runtimeContextCompactScopeField: { type: "string" },
        runtimeContextCompactWorkflowNodeId: { type: "string" },
        runtimeContextCompactSource: { type: "string" },
        runtimeContextCompactActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_context_compact"),
    accessibility: runtimeNodeAccessibility(
      "runtime_context_compact",
      "runtimeContextCompact.status",
    ),
    policyProfile: policyProfile("write"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_context_compact",
      executorId: "workflow.runtime_context_compact",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_context_compact",
        "runtimeContextCompact.status",
      ),
      runtimeContextCompactEndpoint: "/v1/threads/{threadId}/compact",
      runtimeContextCompactField: "runtimeContextCompact",
      runtimeContextCompactEventField: "runtimeContextCompact.event",
      runtimeContextCompactStatusField: "runtimeContextCompact.status",
      runtimeContextCompactReceiptField: "runtimeContextCompact.receiptRefs",
      runtimeContextCompactPolicyField:
        "runtimeContextCompact.policyDecisionRefs",
      runtimeContextCompactThreadIdField: "threadId",
      runtimeContextCompactTurnIdField: "turnId",
      runtimeContextCompactReasonField: "reason",
      runtimeContextCompactReason:
        "Compact thread context from React Flow workflow control.",
      runtimeContextCompactScopeField: "scope",
      runtimeContextCompactScope: "thread",
      runtimeContextCompactWorkflowNodeId: "runtime.context-compact",
      runtimeContextCompactSource: "react_flow",
      runtimeContextCompactActor: "operator",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_context_compact_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "request"],
        properties: {
          runtimeContextCompact: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeContextCompact: true,
        runtimeContextCompactField: "runtimeContextCompact",
        runtimeContextCompactStatusField: "runtimeContextCompact.status",
      },
      nodeTypeLabel: "RuntimeContextCompactNode",
    },
    defaultLaw: { privilegedActions: ["runtime.context.compact"] },
  },
  {
    type: "runtime_rollback_snapshot",
    label: "Runtime Rollback Snapshot",
    group: "Flow",
    family: "flow_control",
    token: "RS",
    familyLabel: "Runtime",
    metricLabel: "Snapshot",
    metricValue: "list",
    ioTypes: { in: "state", out: "state" },
    inputs: ["thread"],
    outputs: ["snapshots", "event", "status"],
    portDefinitions: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("snapshots", "Snapshot list request", "output", "state", "output", false, "state"),
      port("event", "Snapshot event", "output", "state", "output", false, "state"),
      port("status", "Snapshot status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("thread", "Thread state", "input", "state", "state", false, "state"),
      port("snapshots", "Snapshot list request", "output", "state", "output", false, "state"),
      port("event", "Snapshot event", "output", "state", "output", false, "state"),
      port("status", "Snapshot status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeRollbackSnapshotEndpoint",
        "runtimeRollbackSnapshotThreadIdField",
        "runtimeRollbackSnapshotWorkflowNodeId",
      ],
      properties: {
        runtimeRollbackSnapshotEndpoint: { type: "string" },
        runtimeRollbackSnapshotField: { type: "string" },
        runtimeRollbackSnapshotEventField: { type: "string" },
        runtimeRollbackSnapshotStatusField: { type: "string" },
        runtimeRollbackSnapshotReceiptField: { type: "string" },
        runtimeRollbackSnapshotPolicyField: { type: "string" },
        runtimeRollbackSnapshotThreadId: { type: "string" },
        runtimeRollbackSnapshotThreadIdField: { type: "string" },
        runtimeRollbackSnapshotWorkflowNodeId: { type: "string" },
        runtimeRollbackSnapshotSource: { type: "string" },
        runtimeRollbackSnapshotActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_rollback_snapshot"),
    accessibility: runtimeNodeAccessibility(
      "runtime_rollback_snapshot",
      "runtimeRollbackSnapshot.status",
    ),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_rollback_snapshot",
      executorId: "workflow.runtime_rollback_snapshot",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_rollback_snapshot",
        "runtimeRollbackSnapshot.status",
      ),
      runtimeRollbackSnapshotEndpoint: "/v1/threads/{threadId}/snapshots",
      runtimeRollbackSnapshotField: "runtimeRollbackSnapshot",
      runtimeRollbackSnapshotEventField: "runtimeRollbackSnapshot.event",
      runtimeRollbackSnapshotStatusField: "runtimeRollbackSnapshot.status",
      runtimeRollbackSnapshotReceiptField:
        "runtimeRollbackSnapshot.receiptRefs",
      runtimeRollbackSnapshotPolicyField:
        "runtimeRollbackSnapshot.policyDecisionRefs",
      runtimeRollbackSnapshotThreadIdField: "threadId",
      runtimeRollbackSnapshotWorkflowNodeId: "runtime.rollback-snapshot",
      runtimeRollbackSnapshotSource: "react_flow",
      runtimeRollbackSnapshotActor: "operator",
      readOnly: true,
      dryRun: false,
      mutationExecuted: false,
      redactionProfile: "runtime_rollback_snapshot_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "request"],
        properties: {
          runtimeRollbackSnapshot: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          threadId: { type: "string" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeRollbackSnapshot: true,
        runtimeRollbackSnapshotField: "runtimeRollbackSnapshot",
        runtimeRollbackSnapshotStatusField: "runtimeRollbackSnapshot.status",
      },
      nodeTypeLabel: "RuntimeRollbackSnapshotNode",
    },
    defaultLaw: {},
  },
  {
    type: "runtime_restore_gate",
    label: "Runtime Restore Gate",
    group: "Flow",
    family: "flow_control",
    token: "RG",
    familyLabel: "Runtime",
    metricLabel: "Restore",
    metricValue: "gated",
    ioTypes: { in: "state", out: "state" },
    inputs: ["snapshot"],
    outputs: ["restore", "event", "status"],
    portDefinitions: [
      port("snapshot", "Snapshot selection", "input", "state", "state", false, "state"),
      port("restore", "Restore request", "output", "state", "output", false, "state"),
      port("event", "Restore event", "output", "state", "output", false, "state"),
      port("status", "Restore status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("snapshot", "Snapshot selection", "input", "state", "state", false, "state"),
      port("restore", "Restore request", "output", "state", "output", false, "state"),
      port("event", "Restore event", "output", "state", "output", false, "state"),
      port("status", "Restore status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeRestoreGateEndpoint",
        "runtimeRestoreGateThreadIdField",
        "runtimeRestoreGateSnapshotIdField",
        "runtimeRestoreGateWorkflowNodeId",
      ],
      properties: {
        runtimeRestoreGateEndpoint: { type: "string" },
        runtimeRestoreGateField: { type: "string" },
        runtimeRestoreGateEventField: { type: "string" },
        runtimeRestoreGateStatusField: { type: "string" },
        runtimeRestoreGateReceiptField: { type: "string" },
        runtimeRestoreGatePolicyField: { type: "string" },
        runtimeRestoreGateThreadId: { type: "string" },
        runtimeRestoreGateThreadIdField: { type: "string" },
        runtimeRestoreGateSnapshotId: { type: "string" },
        runtimeRestoreGateSnapshotIdField: { type: "string" },
        runtimeRestoreGateMode: {
          type: "string",
          enum: ["preview", "apply"],
        },
        runtimeRestoreGateModeField: { type: "string" },
        runtimeRestoreGateConflictPolicy: {
          type: "string",
          enum: ["block", "allow_override"],
        },
        runtimeRestoreGateConflictPolicyField: { type: "string" },
        runtimeRestoreGateApprovalGranted: { type: "boolean" },
        runtimeRestoreGateApprovalGrantedField: { type: "string" },
        runtimeRestoreGateWorkflowNodeId: { type: "string" },
        runtimeRestoreGateSource: { type: "string" },
        runtimeRestoreGateActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_restore_gate"),
    accessibility: runtimeNodeAccessibility(
      "runtime_restore_gate",
      "runtimeRestoreGate.status",
    ),
    policyProfile: policyProfile("write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "approval", "verification"],
      ["execution", "approval", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_restore_gate",
      executorId: "workflow.runtime_restore_gate",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_restore_gate",
        "runtimeRestoreGate.status",
      ),
      runtimeRestoreGateEndpoint:
        "/v1/threads/{threadId}/snapshots/{snapshotId}/restore-{mode}",
      runtimeRestoreGateField: "runtimeRestoreGate",
      runtimeRestoreGateEventField: "runtimeRestoreGate.event",
      runtimeRestoreGateStatusField: "runtimeRestoreGate.status",
      runtimeRestoreGateReceiptField: "runtimeRestoreGate.receiptRefs",
      runtimeRestoreGatePolicyField: "runtimeRestoreGate.policyDecisionRefs",
      runtimeRestoreGateThreadIdField: "threadId",
      runtimeRestoreGateSnapshotIdField: "snapshotId",
      runtimeRestoreGateMode: "preview",
      runtimeRestoreGateModeField: "mode",
      runtimeRestoreGateConflictPolicy: "block",
      runtimeRestoreGateConflictPolicyField: "conflictPolicy",
      runtimeRestoreGateApprovalGranted: false,
      runtimeRestoreGateApprovalGrantedField: "approvalGranted",
      runtimeRestoreGateWorkflowNodeId: "runtime.restore-gate",
      runtimeRestoreGateSource: "react_flow",
      runtimeRestoreGateActor: "operator",
      readOnly: false,
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_restore_gate_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "snapshotId", "mode", "request"],
        properties: {
          runtimeRestoreGate: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          threadId: { type: "string" },
          snapshotId: { type: "string" },
          mode: { type: "string" },
          conflictPolicy: { type: "string" },
          approvalGranted: { type: "boolean" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeRestoreGate: true,
        runtimeRestoreGateField: "runtimeRestoreGate",
        runtimeRestoreGateStatusField: "runtimeRestoreGate.status",
      },
      nodeTypeLabel: "RuntimeRestoreGateNode",
    },
    defaultLaw: { privilegedActions: ["runtime.workspace.restore"] },
  },
  {
    type: "runtime_diagnostics_repair",
    label: "Runtime Diagnostics Repair",
    group: "Flow",
    family: "flow_control",
    token: "DR",
    familyLabel: "Runtime",
    metricLabel: "Repair",
    metricValue: "decision",
    ioTypes: { in: "state", out: "state" },
    inputs: ["decision"],
    outputs: ["repair", "event", "status"],
    portDefinitions: [
      port("decision", "Repair decision", "input", "state", "state", false, "state"),
      port("repair", "Repair request", "output", "state", "output", false, "state"),
      port("event", "Repair event", "output", "state", "output", false, "state"),
      port("status", "Repair status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("decision", "Repair decision", "input", "state", "state", false, "state"),
      port("repair", "Repair request", "output", "state", "output", false, "state"),
      port("event", "Repair event", "output", "state", "output", false, "state"),
      port("status", "Repair status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: [
        "runtimeDiagnosticsRepairEndpoint",
        "runtimeDiagnosticsRepairThreadIdField",
        "runtimeDiagnosticsRepairDecisionIdField",
        "runtimeDiagnosticsRepairWorkflowNodeId",
      ],
      properties: {
        runtimeDiagnosticsRepairEndpoint: { type: "string" },
        runtimeDiagnosticsRepairField: { type: "string" },
        runtimeDiagnosticsRepairEventField: { type: "string" },
        runtimeDiagnosticsRepairStatusField: { type: "string" },
        runtimeDiagnosticsRepairReceiptField: { type: "string" },
        runtimeDiagnosticsRepairPolicyField: { type: "string" },
        runtimeDiagnosticsRepairThreadId: { type: "string" },
        runtimeDiagnosticsRepairThreadIdField: { type: "string" },
        runtimeDiagnosticsRepairDecisionId: { type: "string" },
        runtimeDiagnosticsRepairDecisionIdField: { type: "string" },
        runtimeDiagnosticsRepairAction: {
          type: "string",
          enum: [
            "repair_retry",
            "restore_preview",
            "restore_apply",
            "operator_override",
          ],
        },
        runtimeDiagnosticsRepairActionField: { type: "string" },
        runtimeDiagnosticsRepairMessage: { type: "string" },
        runtimeDiagnosticsRepairMessageField: { type: "string" },
        runtimeDiagnosticsRepairApprovalGranted: { type: "boolean" },
        runtimeDiagnosticsRepairApprovalGrantedField: { type: "string" },
        runtimeDiagnosticsRepairAllowConflicts: { type: "boolean" },
        runtimeDiagnosticsRepairAllowConflictsField: { type: "string" },
        runtimeDiagnosticsRepairWorkflowNodeId: { type: "string" },
        runtimeDiagnosticsRepairSource: { type: "string" },
        runtimeDiagnosticsRepairActor: { type: "string" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("runtime_diagnostics_repair"),
    accessibility: runtimeNodeAccessibility(
      "runtime_diagnostics_repair",
      "runtimeDiagnosticsRepair.status",
    ),
    policyProfile: policyProfile("write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "approval", "verification"],
      ["execution", "approval", "schema_validation"],
    ),
    executor: {
      nodeType: "runtime_diagnostics_repair",
      executorId: "workflow.runtime_diagnostics_repair",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "runtime_diagnostics_repair",
        "runtimeDiagnosticsRepair.status",
      ),
      runtimeDiagnosticsRepairEndpoint:
        "/v1/threads/{threadId}/diagnostics/repair-decisions/{decisionId}/execute",
      runtimeDiagnosticsRepairField: "runtimeDiagnosticsRepair",
      runtimeDiagnosticsRepairEventField: "runtimeDiagnosticsRepair.event",
      runtimeDiagnosticsRepairStatusField: "runtimeDiagnosticsRepair.status",
      runtimeDiagnosticsRepairReceiptField:
        "runtimeDiagnosticsRepair.receiptRefs",
      runtimeDiagnosticsRepairPolicyField:
        "runtimeDiagnosticsRepair.policyDecisionRefs",
      runtimeDiagnosticsRepairThreadIdField: "threadId",
      runtimeDiagnosticsRepairDecisionIdField: "decisionId",
      runtimeDiagnosticsRepairAction: "repair_retry",
      runtimeDiagnosticsRepairActionField: "action",
      runtimeDiagnosticsRepairMessageField: "message",
      runtimeDiagnosticsRepairApprovalGranted: false,
      runtimeDiagnosticsRepairApprovalGrantedField: "approvalGranted",
      runtimeDiagnosticsRepairAllowConflicts: false,
      runtimeDiagnosticsRepairAllowConflictsField: "allowConflicts",
      runtimeDiagnosticsRepairWorkflowNodeId: "runtime.diagnostics-repair",
      runtimeDiagnosticsRepairSource: "react_flow",
      runtimeDiagnosticsRepairActor: "operator",
      readOnly: false,
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "runtime_diagnostics_repair_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "source", "componentKind", "workflowNodeId", "decisionId", "action", "request"],
        properties: {
          runtimeDiagnosticsRepair: { type: "object" },
          status: { type: "string" },
          source: { type: "string" },
          componentKind: { type: "string" },
          workflowGraphId: { type: ["string", "null"] },
          workflowNodeId: { type: "string" },
          threadId: { type: "string" },
          decisionId: { type: "string" },
          action: { type: "string" },
          approvalGranted: { type: "boolean" },
          allowConflicts: { type: "boolean" },
          request: { type: "object" },
        },
      },
      activationGate: {
        consumesRuntimeDiagnosticsRepair: true,
        runtimeDiagnosticsRepairField: "runtimeDiagnosticsRepair",
        runtimeDiagnosticsRepairStatusField: "runtimeDiagnosticsRepair.status",
      },
      nodeTypeLabel: "RuntimeDiagnosticsRepairNode",
    },
    defaultLaw: { privilegedActions: ["runtime.diagnostics.repair"] },
  },
  {
    type: "workflow_package_export",
    label: "Workflow Package Export",
    group: "Tools",
    family: "tools",
    token: "PKG",
    familyLabel: "Package",
    metricLabel: "Export",
    metricValue: "portable",
    ioTypes: { in: "state", out: "output_bundle" },
    inputs: ["workflow"],
    outputs: ["package", "manifest", "readiness", "locale"],
    portDefinitions: [
      port("workflow", "Workflow state", "input", "state", "state", false, "state"),
      port("package", "Portable package", "output", "output_bundle", "output", false),
      port("manifest", "Package manifest", "output", "state", "output", false, "state"),
      port("readiness", "Readiness", "output", "state", "output", false, "state"),
      port("locale", "Chrome locale", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("workflow", "Workflow state", "input", "state", "state", false, "state"),
      port("package", "Portable package", "output", "output_bundle", "output", false),
      port("manifest", "Package manifest", "output", "state", "output", false, "state"),
      port("readiness", "Readiness", "output", "state", "output", false, "state"),
      port("locale", "Chrome locale", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["workflowPackageExportEndpoint", "workflowPackageExportField"],
      properties: {
        workflowPackageExportEndpoint: { type: "string" },
        workflowPackageExportField: { type: "string" },
        workflowPackagePath: { type: "string" },
        workflowPackageOutputDir: { type: "string" },
        workflowPackageManifestField: { type: "string" },
        workflowPackageReadinessStatusField: { type: "string" },
        workflowPackagePortableField: { type: "string" },
        workflowPackageLocaleField: { type: "string" },
        workflowPackageEvidenceReadyField: { type: "string" },
        dryRun: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("workflow_package_export"),
    accessibility: runtimeNodeAccessibility(
      "workflow_package_export",
      "workflowPackageExport.status",
    ),
    policyProfile: policyProfile("write"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "workflow_package_export",
      executorId: "workflow.package.export",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("workflow_package_export", "workflowPackageExport.status"),
      workflowPackageExportEndpoint: "runtime.exportWorkflowPackage",
      workflowPackageExportField: "workflowPackageExport",
      workflowPackagePath: "{{workflow.path}}",
      workflowPackageOutputDir: "",
      workflowPackageManifestField: "workflowPackageExport.manifest",
      workflowPackageReadinessStatusField:
        "workflowPackageExport.manifest.readinessStatus",
      workflowPackagePortableField: "workflowPackageExport.manifest.portable",
      workflowPackageLocaleField:
        "workflowPackageExport.manifest.workflowChromeLocale",
      workflowPackageEvidenceReadyField:
        "workflowPackageExport.manifest.harnessPackageManifest",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "workflow_package_manifest_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "status",
          "toolName",
          "packagePath",
          "manifest",
          "portable",
          "readinessStatus",
          "workflowChromeLocale",
        ],
        properties: {
          workflowPackageExport: { type: "object" },
          manifest: { type: "object" },
          packagePath: { type: "string" },
          portable: { type: "boolean" },
          readinessStatus: { type: "string" },
          workflowChromeLocale: { type: ["string", "null"] },
          packageEvidenceReady: { type: "boolean" },
        },
      },
      activationGate: {
        consumesWorkflowPackageExport: true,
        workflowPackageExportField: "workflowPackageExport",
        workflowPackageReadinessStatusField:
          "workflowPackageExport.manifest.readinessStatus",
        workflowPackagePortableField: "workflowPackageExport.manifest.portable",
      },
      nodeTypeLabel: "WorkflowPackageExportNode",
    },
    defaultLaw: {
      privilegedActions: ["workflow.package.export"],
    },
  },
  {
    type: "workflow_package_import",
    label: "Workflow Package Import",
    group: "Tools",
    family: "tools",
    token: "IMP",
    familyLabel: "Package",
    metricLabel: "Import",
    metricValue: "review",
    ioTypes: { in: "output_bundle", out: "state" },
    inputs: ["package"],
    outputs: ["review", "imported_workflow", "evidence", "locale"],
    portDefinitions: [
      port("package", "Portable package", "input", "output_bundle"),
      port("review", "Import review", "output", "state", "output", false, "state"),
      port("imported_workflow", "Imported workflow", "output", "state", "output", false, "state"),
      port("evidence", "Package evidence", "output", "state", "output", false, "state"),
      port("locale", "Chrome locale", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("package", "Portable package", "input", "output_bundle"),
      port("review", "Import review", "output", "state", "output", false, "state"),
      port("imported_workflow", "Imported workflow", "output", "state", "output", false, "state"),
      port("evidence", "Package evidence", "output", "state", "output", false, "state"),
      port("locale", "Chrome locale", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["workflowPackageImportEndpoint", "workflowPackageImportReviewField"],
      properties: {
        workflowPackageImportEndpoint: { type: "string" },
        workflowPackagePath: { type: "string" },
        workflowPackageProjectRoot: { type: "string" },
        workflowPackageImportName: { type: "string" },
        workflowPackageImportField: { type: "string" },
        workflowPackageImportReviewField: { type: "string" },
        workflowPackageImportEvidenceReadyField: { type: "string" },
        workflowPackageImportLocalePreservedField: { type: "string" },
        workflowPackageImportedWorkflowPathField: { type: "string" },
        dryRun: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("workflow_package_import"),
    accessibility: runtimeNodeAccessibility(
      "workflow_package_import",
      "workflowPackageImportReview.evidence.packageEvidenceReady",
    ),
    policyProfile: policyProfile("write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification", "approval"],
      ["execution", "schema_validation", "approval"],
    ),
    executor: {
      nodeType: "workflow_package_import",
      executorId: "workflow.package.import",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic(
        "workflow_package_import",
        "workflowPackageImportReview.evidence.packageEvidenceReady",
      ),
      workflowPackageImportEndpoint: "runtime.importWorkflowPackage",
      workflowPackagePath: "{{workflowPackageExport.packagePath}}",
      workflowPackageProjectRoot: "{{project.root}}",
      workflowPackageImportName: "",
      workflowPackageImportField: "workflowPackageImport",
      workflowPackageImportReviewField: "workflowPackageImportReview",
      workflowPackageImportEvidenceReadyField:
        "workflowPackageImportReview.evidence.packageEvidenceReady",
      workflowPackageImportLocalePreservedField:
        "workflowPackageImportReview.evidence.workflowChromeLocalePreserved",
      workflowPackageImportedWorkflowPathField:
        "workflowPackageImport.imported.workflowPath",
      dryRun: false,
      mutationExecuted: true,
      redactionProfile: "workflow_package_import_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "status",
          "toolName",
          "packagePath",
          "importedWorkflowPath",
          "review",
          "packageEvidenceReady",
          "workflowChromeLocalePreserved",
        ],
        properties: {
          workflowPackageImport: { type: "object" },
          workflowPackageImportReview: { type: "object" },
          review: { type: "object" },
          packagePath: { type: "string" },
          importedWorkflowPath: { type: "string" },
          packageEvidenceReady: { type: "boolean" },
          workflowChromeLocalePreserved: { type: "boolean" },
          sourceWorkflowChromeLocale: { type: ["string", "null"] },
          importedWorkflowChromeLocale: { type: ["string", "null"] },
        },
      },
      activationGate: {
        consumesWorkflowPackageImportReview: true,
        workflowPackageImportReviewField: "workflowPackageImportReview",
        workflowPackageImportEvidenceReadyField:
          "workflowPackageImportReview.evidence.packageEvidenceReady",
        workflowPackageImportLocalePreservedField:
          "workflowPackageImportReview.evidence.workflowChromeLocalePreserved",
      },
      nodeTypeLabel: "WorkflowPackageImportNode",
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["workflow.package.import"],
    },
  },
  {
    type: "repository_context",
    label: "Repository Context",
    group: "State",
    family: "state",
    token: "RC",
    familyLabel: "Repository",
    metricLabel: "Git",
    metricValue: "snapshot",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["context", "status"],
    portDefinitions: [
      port("context", "Repository context", "output", "state", "output", false, "state"),
      port("status", "Worktree status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("context", "Repository context", "output", "state", "output", false, "state"),
      port("status", "Worktree status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["repositoryEndpoint", "readOnly"],
      properties: {
        repositoryEndpoint: { type: "string" },
        readOnly: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("repository_context"),
    accessibility: runtimeNodeAccessibility("repository_context", "repositoryContext.status.availability"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "repository_context",
      executorId: "workflow.repository_context",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("repository_context", "repositoryContext.status.availability"),
      repositoryEndpoint: "/v1/repository-context",
      repositoryContextField: "repositoryContext",
      repositoryBranchField: "repositoryContext.branch",
      repositoryHeadField: "repositoryContext.headSha",
      repositoryDirtyField: "repositoryContext.status.isDirty",
      readOnly: true,
      mutationExecuted: false,
      redactionProfile: "repository_context_safe",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "contextId", "readOnly", "status", "redaction"],
        properties: {
          repositoryContext: { type: "object" },
          branch: { type: ["string", "null"] },
          headSha: { type: ["string", "null"] },
          isDirty: { type: "boolean" },
          remotes: { type: "array" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
      },
      nodeTypeLabel: "RepositoryContextNode",
    },
    defaultLaw: {},
  },
  {
    type: "branch_policy",
    label: "Branch Policy",
    group: "State",
    family: "gates",
    token: "BP",
    familyLabel: "Branch",
    metricLabel: "Policy",
    metricValue: "gate",
    ioTypes: { in: "state", out: "state" },
    inputs: ["repository"],
    outputs: ["policy", "blockers", "warnings"],
    portDefinitions: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("policy", "Branch policy", "output", "state", "state", false, "state"),
      port("blockers", "Blockers", "output", "state", "output", false, "state"),
      port("warnings", "Warnings", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("policy", "Branch policy", "output", "state", "state", false, "state"),
      port("blockers", "Blockers", "output", "state", "output", false, "state"),
      port("warnings", "Warnings", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["blockProtectedBranches", "allowDirtyWorktree", "requireUpstream"],
      properties: {
        protectedBranchNames: { type: "array" },
        blockProtectedBranches: { type: "boolean" },
        allowDirtyWorktree: { type: "boolean" },
        requireUpstream: { type: "boolean" },
        requireReviewForWarnings: { type: "boolean" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("branch_policy"),
    accessibility: runtimeNodeAccessibility("branch_policy", "branchPolicy.status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "branch_policy",
      executorId: "workflow.branch_policy",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("branch_policy", "branchPolicy.status"),
      branchPolicyField: "branchPolicy",
      branchPolicyStatusField: "branchPolicy.status",
      branchPolicyBlockersField: "branchPolicy.blockers",
      branchPolicyWarningsField: "branchPolicy.warnings",
      branchPolicyReceiptField: "branchPolicy.receiptId",
      repositoryContextField: "repositoryContext",
      protectedBranchNames: ["main", "master", "trunk", "production", "release", "stable"],
      blockProtectedBranches: true,
      allowDirtyWorktree: false,
      requireUpstream: true,
      requireReviewForWarnings: true,
      readOnly: true,
      mutationExecuted: false,
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "policyId", "status", "readOnly", "mutationAllowed"],
        properties: {
          branchPolicy: { type: "object" },
          status: { type: "string" },
          blockers: { type: "array" },
          warnings: { type: "array" },
          mutationAllowed: { type: "boolean" },
          prCreationAllowed: { type: "boolean" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
        consumesBranchPolicy: true,
        branchPolicyField: "branchPolicy",
        branchPolicyStatusField: "branchPolicy.status",
        branchPolicyBlockersField: "branchPolicy.blockers",
        branchPolicyWarningsField: "branchPolicy.warnings",
      },
      nodeTypeLabel: "BranchPolicyNode",
    },
    defaultLaw: {},
  },
  {
    type: "github_context",
    label: "GitHub Context",
    group: "Connectors",
    family: "state",
    token: "GH",
    familyLabel: "GitHub",
    metricLabel: "Repo",
    metricValue: "read-only",
    ioTypes: { in: "state", out: "state" },
    inputs: ["repository", "branch_policy"],
    outputs: ["context", "preconditions", "remote"],
    portDefinitions: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("context", "GitHub context", "output", "state", "state", false, "state"),
      port("preconditions", "PR preconditions", "output", "state", "output", false, "state"),
      port("remote", "GitHub remote", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("context", "GitHub context", "output", "state", "state", false, "state"),
      port("preconditions", "PR preconditions", "output", "state", "output", false, "state"),
      port("remote", "GitHub remote", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["githubContextEndpoint", "readOnly"],
      properties: {
        githubContextEndpoint: { type: "string" },
        githubContextField: { type: "string" },
        githubPrPreconditionsField: { type: "string" },
        readOnly: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("github_context"),
    accessibility: runtimeNodeAccessibility("github_context", "githubContext.status"),
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "github_context",
      executorId: "workflow.github_context",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("github_context", "githubContext.status"),
      githubContextEndpoint: "/v1/github-context",
      githubContextField: "githubContext",
      githubRemoteField: "githubContext.defaultRemoteName",
      githubOwnerField: "githubContext.owner",
      githubRepoField: "githubContext.repo",
      githubDefaultBranchField: "githubContext.defaultBranch",
      githubPrPreconditionsField: "githubContext.prCreationPreconditions",
      githubContextReceiptField: "githubContext.receiptId",
      repositoryContextField: "repositoryContext",
      branchPolicyField: "branchPolicy",
      readOnly: true,
      mutationExecuted: false,
      redactionProfile: "github_context_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "contextId",
          "status",
          "githubRemotePresent",
          "readOnly",
          "mutationExecuted",
          "redaction",
        ],
        properties: {
          githubContext: { type: "object" },
          status: { type: "string" },
          repoFullName: { type: ["string", "null"] },
          prCreationEligible: { type: "boolean" },
          prCreationPreconditions: { type: "object" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
        consumesBranchPolicy: true,
        consumesGithubContext: true,
        githubContextField: "githubContext",
        githubPrPreconditionsField: "githubContext.prCreationPreconditions",
      },
      nodeTypeLabel: "GitHubContextNode",
    },
    defaultLaw: {},
  },
  {
    type: "issue_context",
    label: "Issue Context",
    group: "Connectors",
    family: "connectors",
    token: "IC",
    familyLabel: "GitHub",
    metricLabel: "Issue",
    metricValue: "optional",
    ioTypes: { in: "state", out: "state" },
    inputs: ["github_context"],
    outputs: ["context", "issue", "status"],
    portDefinitions: [
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("context", "Issue context", "output", "state", "state", false, "state"),
      port("issue", "Issue binding", "output", "state", "output", false, "state"),
      port("status", "Issue status", "output", "state", "output", false, "state"),
    ],
    ports: [
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("context", "Issue context", "output", "state", "state", false, "state"),
      port("issue", "Issue binding", "output", "state", "output", false, "state"),
      port("status", "Issue status", "output", "state", "output", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["issueContextEndpoint", "readOnly"],
      properties: {
        issueContextEndpoint: { type: "string" },
        issueContextField: { type: "string" },
        issueContextStatusField: { type: "string" },
        issueContextBoundField: { type: "string" },
        readOnly: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("issue_context"),
    accessibility: runtimeNodeAccessibility("issue_context", "issueContext.status"),
    policyProfile: policyProfile("read", false),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "issue_context",
      executorId: "workflow.issue_context",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("issue_context", "issueContext.status"),
      issueContextEndpoint: "/v1/issue-context",
      issueContextField: "issueContext",
      issueContextStatusField: "issueContext.status",
      issueContextBoundField: "issueContext.bound",
      issueContextIssueNumberField: "issueContext.issueNumber",
      issueContextSourceUrlField: "issueContext.sourceUrl",
      issueContextReceiptField: "issueContext.receiptId",
      githubContextField: "githubContext",
      readOnly: true,
      mutationExecuted: false,
      redactionProfile: "issue_context_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "contextId",
          "status",
          "bound",
          "readOnly",
          "mutationExecuted",
          "redaction",
        ],
        properties: {
          issueContext: { type: "object" },
          status: { type: "string" },
          bound: { type: "boolean" },
          issueNumber: { type: ["number", "null"] },
          sourceUrl: { type: ["string", "null"] },
        },
      },
      activationGate: {
        consumesGithubContext: true,
        consumesIssueContext: true,
        issueContextField: "issueContext",
        issueContextStatusField: "issueContext.status",
        issueContextBoundField: "issueContext.bound",
      },
      nodeTypeLabel: "IssueContextNode",
    },
    defaultLaw: {},
  },
  {
    type: "pr_attempt",
    label: "PR Attempt",
    group: "Connectors",
    family: "connectors",
    token: "PR",
    familyLabel: "GitHub",
    metricLabel: "Attempt",
    metricValue: "preview",
    ioTypes: { in: "state", out: "state" },
    inputs: ["repository", "branch_policy", "github_context", "issue_context"],
    outputs: ["attempt", "blockers", "artifacts"],
    portDefinitions: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("attempt", "PR attempt", "output", "state", "state", false, "state"),
      port("blockers", "PR blockers", "output", "state", "output", false, "state"),
      port("artifacts", "PR artifacts", "output", "payload", "output", false, "delivery"),
    ],
    ports: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("attempt", "PR attempt", "output", "state", "state", false, "state"),
      port("blockers", "PR blockers", "output", "state", "output", false, "state"),
      port("artifacts", "PR artifacts", "output", "payload", "output", false, "delivery"),
    ],
    configSchema: {
      type: "object",
      required: ["prAttemptEndpoint", "readOnly"],
      properties: {
        prAttemptEndpoint: { type: "string" },
        prAttemptField: { type: "string" },
        prAttemptStatusField: { type: "string" },
        prAttemptAuthorityField: { type: "string" },
        readOnly: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("pr_attempt"),
    accessibility: runtimeNodeAccessibility("pr_attempt", "prAttempt.status"),
    policyProfile: policyProfile("external_write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification", "approval", "asset_materialized"],
      ["execution", "schema_validation", "approval"],
    ),
    executor: {
      nodeType: "pr_attempt",
      executorId: "workflow.pr_attempt",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("pr_attempt", "prAttempt.status"),
      prAttemptEndpoint: "/v1/pr-attempts",
      prAttemptField: "prAttempt",
      prAttemptStatusField: "prAttempt.status",
      prAttemptBlockersField: "prAttempt.blockers",
      prAttemptAuthorityField: "prAttempt.authority",
      prAttemptBranchArtifactField: "prAttempt.branchArtifact",
      prAttemptDiffArtifactField: "prAttempt.diffArtifact",
      prAttemptReceiptField: "prAttempt.receiptId",
      repositoryContextField: "repositoryContext",
      branchPolicyField: "branchPolicy",
      githubContextField: "githubContext",
      issueContextField: "issueContext",
      readOnly: true,
      mutationExecuted: false,
      redactionProfile: "pr_attempt_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "attemptId",
          "status",
          "outcome",
          "previewOnly",
          "mutationExecuted",
          "authority",
          "branchArtifact",
          "diffArtifact",
          "redaction",
        ],
        properties: {
          prAttempt: { type: "object" },
          status: { type: "string" },
          outcome: { type: "string" },
          blockers: { type: "array" },
          authority: { type: "object" },
          artifacts: { type: "array" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
        consumesBranchPolicy: true,
        consumesGithubContext: true,
        consumesPrAttempt: true,
        prAttemptField: "prAttempt",
        prAttemptStatusField: "prAttempt.status",
        prAttemptBlockersField: "prAttempt.blockers",
        prAttemptAuthorityField: "prAttempt.authority",
      },
      nodeTypeLabel: "PrAttemptNode",
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["github.pr.create"],
    },
  },
  {
    type: "review_gate",
    label: "Review Gate",
    group: "Human",
    family: "gates",
    token: "RG",
    familyLabel: "Review",
    metricLabel: "Gate",
    metricValue: "blocked",
    ioTypes: { in: "state", out: "decision" },
    inputs: ["repository", "branch_policy", "github_context", "issue_context", "pr_attempt"],
    outputs: ["decision", "blockers", "review"],
    portDefinitions: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("pr_attempt", "PR attempt", "input", "state", "state", true, "state"),
      port("decision", "Review decision", "output", "decision", "output", false, "approval"),
      port("blockers", "Review blockers", "output", "state", "output", false, "state"),
      port("review", "Review requirements", "output", "state", "output", false, "approval"),
    ],
    ports: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("pr_attempt", "PR attempt", "input", "state", "state", true, "state"),
      port("decision", "Review decision", "output", "decision", "output", false, "approval"),
      port("blockers", "Review blockers", "output", "state", "output", false, "state"),
      port("review", "Review requirements", "output", "state", "output", false, "approval"),
    ],
    configSchema: {
      type: "object",
      required: ["reviewGateEndpoint", "readOnly"],
      properties: {
        reviewGateEndpoint: { type: "string" },
        reviewGateField: { type: "string" },
        reviewGateStatusField: { type: "string" },
        reviewGateReviewersField: { type: "string" },
        readOnly: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("review_gate"),
    accessibility: runtimeNodeAccessibility("review_gate", "reviewGate.status"),
    policyProfile: policyProfile("external_write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification", "approval"],
      ["execution", "schema_validation", "approval"],
    ),
    executor: {
      nodeType: "review_gate",
      executorId: "workflow.review_gate",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("review_gate", "reviewGate.status"),
      reviewGateEndpoint: "/v1/review-gate",
      reviewGateField: "reviewGate",
      reviewGateStatusField: "reviewGate.status",
      reviewGateBlockersField: "reviewGate.blockers",
      reviewGateReviewersField: "reviewGate.requiredReviewers",
      reviewGateChecksField: "reviewGate.requiredChecks",
      reviewGateReceiptField: "reviewGate.receiptId",
      repositoryContextField: "repositoryContext",
      branchPolicyField: "branchPolicy",
      githubContextField: "githubContext",
      issueContextField: "issueContext",
      prAttemptField: "prAttempt",
      readOnly: true,
      mutationExecuted: false,
      redactionProfile: "review_gate_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "gateId",
          "status",
          "decision",
          "reviewRequired",
          "reviewSatisfied",
          "mutationExecuted",
          "redaction",
        ],
        properties: {
          reviewGate: { type: "object" },
          status: { type: "string" },
          decision: { type: "string" },
          blockers: { type: "array" },
          requiredReviewers: { type: "array" },
          requiredChecks: { type: "array" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
        consumesBranchPolicy: true,
        consumesGithubContext: true,
        consumesPrAttempt: true,
        consumesReviewGate: true,
        reviewGateField: "reviewGate",
        reviewGateStatusField: "reviewGate.status",
        reviewGateBlockersField: "reviewGate.blockers",
      },
      nodeTypeLabel: "ReviewGateNode",
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["github.pr.create"],
    },
  },
  {
    type: "github_pr_create",
    label: "GitHub PR Create",
    group: "Connectors",
    family: "connectors",
    token: "PR+",
    familyLabel: "GitHub",
    metricLabel: "Dry Run",
    metricValue: "blocked",
    ioTypes: { in: "state", out: "decision" },
    inputs: ["repository", "branch_policy", "github_context", "issue_context", "pr_attempt", "review_gate"],
    outputs: ["plan", "blockers", "request"],
    portDefinitions: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("pr_attempt", "PR attempt", "input", "state", "state", true, "state"),
      port("review_gate", "Review gate", "input", "decision", "state", true, "approval"),
      port("plan", "PR create plan", "output", "decision", "output", false, "approval"),
      port("blockers", "Plan blockers", "output", "state", "output", false, "state"),
      port("request", "Request hash", "output", "payload", "output", false, "data"),
    ],
    ports: [
      port("repository", "Repository context", "input", "state", "state", true, "state"),
      port("branch_policy", "Branch policy", "input", "state", "state", true, "state"),
      port("github_context", "GitHub context", "input", "state", "state", true, "state"),
      port("issue_context", "Issue context", "input", "state", "state", false, "state"),
      port("pr_attempt", "PR attempt", "input", "state", "state", true, "state"),
      port("review_gate", "Review gate", "input", "decision", "state", true, "approval"),
      port("plan", "PR create plan", "output", "decision", "output", false, "approval"),
      port("blockers", "Plan blockers", "output", "state", "output", false, "state"),
      port("request", "Request hash", "output", "payload", "output", false, "data"),
    ],
    configSchema: {
      type: "object",
      required: ["githubPrCreatePlanEndpoint", "dryRun", "mutationExecuted"],
      properties: {
        githubPrCreatePlanEndpoint: { type: "string" },
        githubPrCreatePlanField: { type: "string" },
        githubPrCreatePlanStatusField: { type: "string" },
        githubPrCreatePlanRequestHashField: { type: "string" },
        dryRun: { type: "boolean" },
        mutationExecuted: { type: "boolean" },
        redactionProfile: { type: "string" },
        ...RUNTIME_CHROME_CONFIG_SCHEMA_PROPERTIES,
      },
    },
    localization: runtimeNodeLocalization("github_pr_create"),
    accessibility: runtimeNodeAccessibility("github_pr_create", "githubPrCreatePlan.status"),
    policyProfile: policyProfile("external_write", true),
    evidenceProfile: evidenceProfile(
      ["execution", "verification", "approval"],
      ["execution", "schema_validation", "approval"],
    ),
    executor: {
      nodeType: "github_pr_create",
      executorId: "workflow.github_pr_create",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      ...runtimeNodeChromeLogic("github_pr_create", "githubPrCreatePlan.status"),
      githubPrCreatePlanEndpoint: "/v1/github/pr-create-plan",
      githubPrCreatePlanField: "githubPrCreatePlan",
      githubPrCreatePlanStatusField: "githubPrCreatePlan.status",
      githubPrCreatePlanBlockersField: "githubPrCreatePlan.blockers",
      githubPrCreatePlanRequestHashField: "githubPrCreatePlan.request.payloadHash",
      githubPrCreatePlanAuthorityField: "githubPrCreatePlan.authority",
      githubPrCreatePlanReceiptField: "githubPrCreatePlan.receiptId",
      repositoryContextField: "repositoryContext",
      branchPolicyField: "branchPolicy",
      githubContextField: "githubContext",
      issueContextField: "issueContext",
      prAttemptField: "prAttempt",
      reviewGateField: "reviewGate",
      dryRun: true,
      mutationExecuted: false,
      redactionProfile: "github_pr_create_plan_safe",
      outputSchema: {
        type: "object",
        required: [
          "schemaVersion",
          "planId",
          "status",
          "decision",
          "dryRun",
          "toolName",
          "request",
          "authority",
          "mutationExecuted",
          "redaction",
        ],
        properties: {
          githubPrCreatePlan: { type: "object" },
          status: { type: "string" },
          decision: { type: "string" },
          blockers: { type: "array" },
          request: { type: "object" },
          authority: { type: "object" },
        },
      },
      activationGate: {
        consumesRepositoryContext: true,
        consumesBranchPolicy: true,
        consumesGithubContext: true,
        consumesIssueContext: true,
        consumesPrAttempt: true,
        consumesReviewGate: true,
        consumesGithubPrCreatePlan: true,
        githubPrCreatePlanField: "githubPrCreatePlan",
        githubPrCreatePlanStatusField: "githubPrCreatePlan.status",
        githubPrCreatePlanBlockersField: "githubPrCreatePlan.blockers",
      },
      nodeTypeLabel: "GitHubPrCreateNode",
    },
    defaultLaw: {
      requireHumanGate: true,
      privilegedActions: ["github.pr.create"],
    },
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
      modelId: null,
      routeId: "route.local-first",
      reasoningEffort: "medium",
      modelBinding: {
        modelRef: "reasoning",
        modelId: null,
        routeId: "route.local-first",
        reasoningEffort: "medium",
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
    configSchema: {
      type: "object",
      required: ["modelRef"],
      properties: {
        memoryKey: { type: "string" },
        memoryScope: {
          type: "string",
          enum: ["global", "workspace", "thread", "workflow", "subagent"],
        },
        memoryInjectionEnabled: { type: "boolean" },
        memoryReadOnly: { type: "boolean" },
        memoryWriteRequiresApproval: { type: "boolean" },
        memorySubagentInheritance: {
          type: "string",
          enum: ["none", "explicit", "read_only", "full"],
        },
      },
    },
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
      modelId: null,
      routeId: "route.local-first",
      reasoningEffort: "medium",
      modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
      capability: "chat",
      receiptRequired: true,
      memoryScope: "thread",
      memoryInjectionEnabled: true,
      memoryReadOnly: false,
      memoryWriteRequiresApproval: false,
      memorySubagentInheritance: "explicit",
      prompt: "Use the input and context to produce the next workflow result.",
      modelBinding: {
        modelRef: "reasoning",
        modelId: null,
        routeId: "route.local-first",
        reasoningEffort: "medium",
        modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
        capability: "chat",
        receiptRequired: true,
        daemonApi: "/api/v1/workflows/nodes/execute",
        mockBinding: true,
        capabilityScope: ["chat"],
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
    type: "skill_context",
    label: "Skill Context",
    group: "AI",
    family: "context",
    token: "SK",
    familyLabel: "Context",
    metricLabel: "Skills",
    metricValue: "discover",
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error"],
    portDefinitions: [
      port("input", "Input", "input", "payload"),
      port("output", "Context", "output", "payload", "context", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    ports: [
      port("input", "Input", "input", "payload"),
      port("output", "Context", "output", "payload", "context", false),
      port("error", "Error", "output", "payload", "error", false),
    ],
    configSchema: { type: "object", required: ["skillContext"] },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "skill_context",
      executorId: "workflow.skill_context",
      sandboxed: false,
      supportsDryRun: false,
    },
    defaultLogic: DEFAULT_WORKFLOW_SKILL_CONTEXT_LOGIC,
    defaultLaw: {},
  },
  {
    type: "skill",
    label: "Skill",
    group: "AI",
    family: "context",
    token: "SK",
    familyLabel: "Skill",
    metricLabel: "Discovery",
    metricValue: "registry",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["skills"],
    portDefinitions: [
      port("skills", "Skills", "output", "state", "state", false, "state"),
    ],
    ports: [port("skills", "Skills", "output", "state", "state", false, "state")],
    configSchema: {
      type: "object",
      required: ["skillEndpoint", "requireSkillMd"],
      properties: {
        skillEndpoint: { type: "string" },
        skillSource: { type: "string" },
        includeCursorImports: { type: "boolean" },
        requireSkillMd: { type: "boolean" },
      },
    },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "skill",
      executorId: "workflow.skill_registry",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      skillEndpoint: "/v1/skills",
      skillSource: "workspace_and_global",
      includeCursorImports: true,
      requireSkillMd: true,
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "skillCount", "skills", "redaction"],
      },
      activationGate: {
        consumesSkillHookManifest: true,
        skillSetHashField: "activeSkillSetHash",
        manifestValidationField: "validation.status",
        requireValidationPass: true,
      },
      nodeTypeLabel: "SkillNode",
    },
    defaultLaw: {},
  },
  {
    type: "skill_pack",
    label: "Skill Pack",
    group: "AI",
    family: "context",
    token: "SP",
    familyLabel: "Skill Pack",
    metricLabel: "Pack",
    metricValue: "governed",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["skillPack"],
    portDefinitions: [
      port("skillPack", "Skill pack", "output", "state", "state", false, "state"),
    ],
    ports: [port("skillPack", "Skill pack", "output", "state", "state", false, "state")],
    configSchema: {
      type: "object",
      required: ["skillEndpoint", "packSources", "activationMode"],
      properties: {
        skillEndpoint: { type: "string" },
        packSources: { type: "array" },
        activationMode: { type: "string" },
      },
    },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "skill_pack",
      executorId: "workflow.skill_pack",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      skillEndpoint: "/v1/skills",
      packSources: [".agents/skills", ".cursor/skills", ".claude/skills"],
      activationMode: "manual_or_discoverable",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "skillCount", "activeSkillSetHash", "skills"],
      },
      activationGate: {
        consumesSkillHookManifest: true,
        skillSetHashField: "activeSkillSetHash",
        manifestValidationField: "validation.status",
        requireValidationPass: true,
      },
      nodeTypeLabel: "SkillPackNode",
    },
    defaultLaw: {},
  },
  {
    type: "hook",
    label: "Hook",
    group: "State",
    family: "state",
    token: "HK",
    familyLabel: "Hook",
    metricLabel: "Events",
    metricValue: "subscribe",
    ioTypes: { in: "none", out: "state" },
    inputs: [],
    outputs: ["hooks"],
    portDefinitions: [
      port("hooks", "Hooks", "output", "state", "state", false, "state"),
    ],
    ports: [port("hooks", "Hooks", "output", "state", "state", false, "state")],
    configSchema: {
      type: "object",
      required: ["hookEndpoint", "eventKinds", "failurePolicy"],
      properties: {
        hookEndpoint: { type: "string" },
        eventKinds: { type: "array" },
        failurePolicy: { type: "string" },
        authorityScopes: { type: "array" },
        toolContracts: { type: "array" },
      },
    },
    policyProfile: policyProfile("read"),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "hook",
      executorId: "workflow.hook_registry",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      hookEndpoint: "/v1/hooks",
      eventKinds: ["pre_model", "post_model", "pre_tool", "post_tool", "approval", "workflow_activation"],
      failurePolicy: "warn",
      authorityScopes: [],
      toolContracts: [],
      hookInvocationLedgerField: "hookInvocationLedger",
      hookInvocationStateField: "hookInvocationLedger.records",
      outputSchema: {
        type: "object",
        required: ["schemaVersion", "status", "hookCount", "hooks", "redaction"],
        properties: {
          hookInvocationLedger: { type: "object" },
          invocationRecords: { type: "array" },
        },
      },
      activationGate: {
        consumesSkillHookManifest: true,
        hookSetHashField: "activeHookSetHash",
        hookInvocationLedgerField: "hookInvocationLedger",
        hookInvocationStateField: "hookInvocationLedger.records",
        manifestValidationField: "validation.status",
        requireValidationPass: true,
      },
      nodeTypeLabel: "HookNode",
    },
    defaultLaw: {},
  },
  {
    type: "hook_policy",
    label: "Hook Policy",
    group: "State",
    family: "gates",
    token: "HP",
    familyLabel: "Hook Policy",
    metricLabel: "Failure",
    metricValue: "warn",
    ioTypes: { in: "state", out: "state" },
    inputs: ["hooks"],
    outputs: ["policy"],
    portDefinitions: [
      port("hooks", "Hooks", "input", "state", "state", true, "state"),
      port("policy", "Policy", "output", "state", "state", false, "state"),
    ],
    ports: [
      port("hooks", "Hooks", "input", "state", "state", true, "state"),
      port("policy", "Policy", "output", "state", "state", false, "state"),
    ],
    configSchema: {
      type: "object",
      required: ["failurePolicy", "allowMutationWithoutContract", "requireAuthorityScopes"],
      properties: {
        failurePolicy: { type: "string" },
        allowMutationWithoutContract: { type: "boolean" },
        requireAuthorityScopes: { type: "boolean" },
      },
    },
    policyProfile: policyProfile(),
    evidenceProfile: evidenceProfile(
      ["execution", "verification"],
      ["execution", "schema_validation"],
    ),
    executor: {
      nodeType: "hook_policy",
      executorId: "workflow.hook_policy",
      sandboxed: false,
      supportsDryRun: true,
    },
    defaultLogic: {
      failurePolicy: "warn",
      allowMutationWithoutContract: false,
      requireAuthorityScopes: true,
      hookDryRunOnly: true,
      requireHookDryRunPlan: true,
      hookExecutionEnabled: false,
      hookCommandExecutionEnabled: false,
      hookDryRunPlanField: "hookDryRunPlan",
      hookDryRunDecisionField: "hookDryRunPlan.decisions",
      hookPolicyDecisionField: "hookDryRunPlan.policyDecision.status",
      hookInvocationLedgerField: "hookInvocationLedger",
      hookEscalationCountField: "hookInvocationLedger.escalationCount",
      hookEscalationDetailsField: "hookInvocationLedger.escalations",
      hookEscalationReceiptField: "hookInvocationLedger.escalations.receiptId",
      routes: ["hook_policy_passed_preview", "hook_policy_blocked"],
      defaultRoute: "hook_policy_blocked",
      hookPolicyPassedRoute: "hook_policy_passed_preview",
      hookPolicyBlockedRoute: "hook_policy_blocked",
      outputSchema: {
        type: "object",
        required: [
          "failurePolicy",
          "allowMutationWithoutContract",
          "requireAuthorityScopes",
          "hookDryRunPlan",
        ],
        properties: {
          hookDryRunPlan: { type: "object" },
          policyDecision: { type: "object" },
          hookInvocationLedger: { type: "object" },
          hookEscalations: { type: "array" },
          hookEscalationCount: { type: "number" },
        },
      },
      activationGate: {
        consumesSkillHookManifest: true,
        hookSetHashField: "activeHookSetHash",
        hookDryRunPlanField: "hookDryRunPlan",
        hookDryRunDecisionField: "hookDryRunPlan.decisions",
        hookPolicyDecisionField: "hookDryRunPlan.policyDecision.status",
        hookInvocationLedgerField: "hookInvocationLedger",
        hookEscalationCountField: "hookInvocationLedger.escalationCount",
        hookEscalationDetailsField: "hookInvocationLedger.escalations",
        hookEscalationReceiptField: "hookInvocationLedger.escalations.receiptId",
        manifestValidationField: "hookExecution.mutationBlockedHookIds",
        requireValidationPass: true,
      },
      nodeTypeLabel: "HookPolicyNode",
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
    configSchema: {
      type: "object",
      required: ["stateKey", "stateOperation"],
      properties: {
        stateKey: { type: "string" },
        stateOperation: {
          type: "string",
          enum: [
            "read",
            "write",
            "append",
            "merge",
            "mcp_status",
            "mcp_tool_search",
            "mcp_tool_fetch",
            "mcp_tool_invoke",
            "mcp_import",
            "mcp_add",
            "mcp_serve",
            "mcp_remove",
            "mcp_enable",
            "mcp_disable",
            "memory_status",
            "memory_policy",
            "memory_search",
            "memory_list",
            "memory_remember",
            "memory_edit",
            "memory_delete",
            "subagent_list",
            "subagent_spawn",
            "subagent_wait",
            "subagent_result",
            "subagent_send_input",
            "subagent_cancel",
            "subagent_resume",
            "subagent_assign",
          ],
        },
        mcpServerId: { type: "string" },
        mcpServerLabel: { type: "string" },
        mcpTransport: { type: "string", enum: ["stdio", "http", "sse"] },
        mcpServerUrl: { type: "string" },
        mcpServerHeadersJson: { type: "string" },
        mcpServerConfigJson: { type: "string" },
        mcpImportJson: { type: "string" },
        mcpConfigSourceMode: {
          type: "string",
          enum: ["workspace_and_global", "workspace", "global"],
        },
        mcpCatalogMode: { type: "string", enum: ["summary", "full"] },
        mcpToolSearchQuery: { type: "string" },
        mcpToolCatalogPreviewLimit: { type: "number" },
        mcpServeEndpoint: { type: "string" },
        mcpServeAllowedToolsJson: { type: "string" },
        mcpToolName: { type: "string" },
        mcpToolInputJson: { type: "string" },
        mcpVaultHeaderRefsJson: { type: "string" },
        mcpContainmentMode: {
          type: "string",
          enum: ["read_only", "sandboxed", "review_required"],
        },
        mcpAllowNetworkEgress: { type: "boolean" },
        subagentId: { type: "string" },
        subagentRole: { type: "string" },
        subagentPrompt: { type: "string" },
        subagentInput: { type: "string" },
        subagentParentTurnId: { type: "string" },
        subagentModelRoute: { type: "string" },
        subagentToolPack: { type: "string" },
        subagentForkContext: { type: "boolean" },
        subagentMaxConcurrency: { type: "number" },
        subagentWaitTimeoutMs: { type: "number" },
        subagentBudgetJson: { type: "string" },
        subagentOutputContractJson: { type: "string" },
        subagentMergePolicy: {
          type: "string",
          enum: ["manual", "append", "replace", "merge", "evidence_only"],
        },
        subagentCancellationInheritance: {
          type: "string",
          enum: ["propagate", "detach", "manual"],
        },
        memoryRecordId: { type: "string" },
        memoryText: { type: "string" },
        memoryKey: { type: "string" },
        memoryScope: {
          type: "string",
          enum: ["global", "workspace", "thread", "workflow", "subagent"],
        },
        query: { type: "string" },
        limit: { type: "number" },
        memoryRedaction: { type: "string", enum: ["none", "redacted"] },
      },
    },
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
      routeId: "route.local-first",
      modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
      capability: "vision",
      receiptRequired: true,
      prompt: "Inspect the media input and return structured observations.",
      modelBinding: {
        modelRef: "vision",
        modelId: null,
        routeId: "route.local-first",
        modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
        capability: "vision",
        receiptRequired: true,
        daemonApi: "/api/v1/workflows/nodes/execute",
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
      routeId: "route.local-first",
      modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
      capability: "embeddings",
      receiptRequired: true,
      prompt: "Embed the input for semantic comparison.",
      modelBinding: {
        modelRef: "embedding",
        modelId: null,
        routeId: "route.local-first",
        modelPolicy: { privacy: "local_or_enterprise", quality: "adaptive" },
        capability: "embeddings",
        receiptRequired: true,
        daemonApi: "/api/v1/workflows/nodes/execute",
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
  const skillContextDiscover = creatorDefinition("skill_context", {
    creatorId: "skill_context.discover",
    label: "Discover skills",
    description:
      "Resolve runtime skills deterministically from workflow or node input goal text.",
    metricValue: "discover",
    defaultLogic: DEFAULT_WORKFLOW_SKILL_CONTEXT_LOGIC,
    keywords: ["skill", "context", "discover", "registry"],
  });
  const skillContextPinned = creatorDefinition("skill_context", {
    creatorId: "skill_context.pinned",
    label: "Pinned skill",
    description:
      "Attach one or more pinned runtime skills by skill hash or deterministic name lookup.",
    metricValue: "pinned",
    defaultLogic: {
      ...DEFAULT_WORKFLOW_SKILL_CONTEXT_LOGIC,
      skillContext: {
        ...DEFAULT_WORKFLOW_SKILL_CONTEXT_LOGIC.skillContext,
        mode: "pinned",
        pinnedSkills: [{ skillHash: "", name: "", required: true }],
      },
    },
    keywords: ["skill", "context", "pinned", "registry"],
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
        toolRef: "mcp.tool.catalog.read",
        bindingKind: "mcp_tool",
        mockBinding: true,
        credentialReady: false,
        capabilityScope: ["mcp.provider.read", "mcp.tool.catalog.read"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
        mcp: {
          serverId: "",
          toolName: "",
          catalogRef: "mcp.tool.catalog.read",
          catalogMode: "deferred",
          catalogSearchQuery: "",
          configSourceMode: "workspace_and_global",
          validateBeforeInvoke: true,
          containmentMode: "read_only",
        },
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
  const codingToolPack = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.coding_pack",
    label: "Coding tool pack",
    description: "Invoke daemon-owned workspace status, git diff, file inspection, governed patch, test, diagnostics, and artifact retrieval tools.",
    metricValue: "coding",
    defaultLogic: {
      toolBinding: {
        toolRef: "workspace.status",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: [
          "workspace.status",
          "git.diff",
          "file.inspect",
          "file.apply_patch",
          "test.run",
          "lsp.diagnostics",
          "artifact.read",
          "tool.retrieve_result",
        ],
        sideEffectClass: "write",
        requiresApproval: true,
        arguments: {},
        toolPack: {
          pack: "coding",
          workspaceStatusEnabled: true,
          gitEnabled: true,
          filesystemEnabled: true,
          writeEnabled: true,
          testEnabled: true,
          diagnosticsEnabled: true,
          artifactEnabled: true,
          resultRetrievalEnabled: true,
          allowedTestCommandIds: ["node.test", "npm.test", "cargo.test", "cargo.check"],
          allowedDiagnosticCommandIds: ["auto", "node.check", "typescript.check"],
          diagnosticsMode: "advisory",
          defaultDiagnosticCommandId: "auto",
          restorePolicy: "apply_with_approval",
          restoreConflictPolicy: "block",
          diagnosticsRepairDefault: "repair_retry",
          operatorOverrideRequiresApproval: true,
          timeoutMs: 60000,
          dryRun: false,
          allowedPaths: [],
        },
      },
    },
  });
  const gitDiffTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.git_diff",
    label: "Git diff",
    description: "Inspect a daemon-backed git diff without shell-only fallback.",
    metricValue: "git",
    defaultLogic: {
      toolBinding: {
        toolRef: "git.diff",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["git.diff"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
        toolPack: {
          pack: "coding",
          gitEnabled: true,
          allowedPaths: [],
        },
      },
    },
  });
  const fileInspectTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.file_inspect",
    label: "File inspect",
    description: "Inspect a workspace file through the daemon coding tool contract.",
    metricValue: "file",
    defaultLogic: {
      toolBinding: {
        toolRef: "file.inspect",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["file.inspect"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
        toolPack: {
          pack: "coding",
          filesystemEnabled: true,
          allowedPaths: [],
        },
      },
    },
  });
  const fileApplyPatchTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.file_apply_patch",
    label: "File apply patch",
    description: "Apply an exact workspace file edit through the daemon coding tool contract.",
    metricValue: "patch",
    defaultLogic: {
      toolBinding: {
        toolRef: "file.apply_patch",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["file.apply_patch"],
        sideEffectClass: "write",
        requiresApproval: true,
        arguments: {},
        toolPack: {
          pack: "coding",
          filesystemEnabled: true,
          writeEnabled: true,
          dryRun: true,
          restorePolicy: "apply_with_approval",
          restoreConflictPolicy: "block",
          diagnosticsRepairDefault: "repair_retry",
          operatorOverrideRequiresApproval: true,
          allowedPaths: [],
        },
      },
    },
  });
  const testRunTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.test_run",
    label: "Test run",
    description: "Run a structured workspace test command through the daemon coding tool contract.",
    metricValue: "test",
    defaultLogic: {
      toolBinding: {
        toolRef: "test.run",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["test.run"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: { commandId: "node.test" },
        toolPack: {
          pack: "coding",
          testEnabled: true,
          allowedTestCommandIds: ["node.test", "npm.test", "cargo.test", "cargo.check"],
          timeoutMs: 60000,
          allowedPaths: [],
        },
      },
    },
  });
  const lspDiagnosticsTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.lsp_diagnostics",
    label: "LSP diagnostics",
    description: "Run daemon-owned post-edit diagnostics over workspace files.",
    metricValue: "diagnostics",
    defaultLogic: {
      toolBinding: {
        toolRef: "lsp.diagnostics",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["lsp.diagnostics"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: { commandId: "auto" },
        toolPack: {
          pack: "coding",
          diagnosticsEnabled: true,
          allowedDiagnosticCommandIds: ["auto", "node.check", "typescript.check"],
          diagnosticsMode: "advisory",
          defaultDiagnosticCommandId: "auto",
          restorePolicy: "apply_with_approval",
          restoreConflictPolicy: "block",
          diagnosticsRepairDefault: "repair_retry",
          operatorOverrideRequiresApproval: true,
          timeoutMs: 30000,
          allowedPaths: [],
        },
      },
    },
  });
  const artifactReadTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.artifact_read",
    label: "Artifact read",
    description: "Read a bounded byte range from a daemon coding-tool artifact.",
    metricValue: "artifact",
    defaultLogic: {
      toolBinding: {
        toolRef: "artifact.read",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["artifact.read"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
        toolPack: {
          pack: "coding",
          artifactEnabled: true,
          resultRetrievalEnabled: true,
        },
      },
    },
  });
  const toolRetrieveResultTool = creatorDefinition("plugin_tool", {
    creatorId: "plugin_tool.tool_retrieve_result",
    label: "Retrieve tool result",
    description: "Retrieve full or ranged output for a prior daemon coding-tool call.",
    metricValue: "retrieve",
    defaultLogic: {
      toolBinding: {
        toolRef: "tool.retrieve_result",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope: ["tool.retrieve_result", "artifact.read"],
        sideEffectClass: "read",
        requiresApproval: false,
        arguments: {},
        toolPack: {
          pack: "coding",
          artifactEnabled: true,
          resultRetrievalEnabled: true,
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
  const mcpStatus = creatorDefinition("state", {
    creatorId: "mcp.status",
    label: "MCP status",
    description: "Inspect daemon-owned MCP server and tool status.",
    metricValue: "mcp",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_status",
      reducer: "replace",
      mcpConfigSourceMode: "workspace_and_global",
    },
  });
  const mcpToolSearch = creatorDefinition("state", {
    creatorId: "mcp.tool.search",
    label: "Search MCP tools",
    description: "Search large MCP catalogs without embedding every tool schema in workflow state.",
    metricValue: "search",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_tool_search",
      reducer: "replace",
      mcpServerId: "",
      mcpToolSearchQuery: "",
      mcpConfigSourceMode: "workspace_and_global",
      mcpCatalogMode: "summary",
      mcpToolCatalogPreviewLimit: 50,
    },
  });
  const mcpToolFetch = creatorDefinition("state", {
    creatorId: "mcp.tool.fetch",
    label: "Fetch MCP tool",
    description: "Fetch one MCP tool schema by stable server/tool reference.",
    metricValue: "fetch",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_tool_fetch",
      reducer: "replace",
      mcpServerId: "",
      mcpToolName: "",
      mcpConfigSourceMode: "workspace_and_global",
      mcpCatalogMode: "summary",
      mcpToolCatalogPreviewLimit: 50,
    },
  });
  const mcpToolInvoke = creatorDefinition("state", {
    creatorId: "mcp.tool.invoke",
    label: "Invoke MCP tool",
    description: "Invoke one daemon-governed MCP tool with explicit containment and request input.",
    metricValue: "invoke",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_tool_invoke",
      reducer: "replace",
      mcpServerId: "",
      mcpToolName: "",
      mcpToolInputJson: "{}",
      mcpConfigSourceMode: "workspace_and_global",
      mcpCatalogMode: "summary",
      mcpToolCatalogPreviewLimit: 50,
      mcpContainmentMode: "sandboxed",
      mcpAllowNetworkEgress: false,
      mcpVaultHeaderRefsJson: "{}",
    },
  });
  const mcpImport = creatorDefinition("state", {
    creatorId: "mcp.import",
    label: "Import MCP config",
    description: "Import MCP server definitions into the active runtime registry.",
    metricValue: "import",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_import",
      reducer: "replace",
      mcpImportJson: "{\"mcpServers\":{}}",
    },
  });
  const mcpServerAdd = creatorDefinition("state", {
    creatorId: "mcp.server.add",
    label: "Add MCP server",
    description: "Add an MCP server to the active runtime registry.",
    metricValue: "add",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_add",
      reducer: "replace",
      mcpServerId: "",
      mcpServerLabel: "",
      mcpTransport: "stdio",
      mcpServerUrl: "",
      mcpServerHeadersJson: "{}",
      mcpServerConfigJson: "{\"transport\":\"stdio\"}",
    },
  });
  const mcpHttpServerAdd = creatorDefinition("state", {
    creatorId: "mcp.server.add.http",
    label: "Add HTTP MCP server",
    description: "Add a streamable HTTP MCP server to the active runtime registry.",
    metricValue: "http",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_add",
      reducer: "replace",
      mcpServerId: "",
      mcpServerLabel: "",
      mcpTransport: "http",
      mcpServerUrl: "",
      mcpServerHeadersJson: "{}",
      mcpServerConfigJson:
        "{\"transport\":\"http\",\"url\":\"\",\"allowedTools\":[]}",
    },
  });
  const mcpSseServerAdd = creatorDefinition("state", {
    creatorId: "mcp.server.add.sse",
    label: "Add SSE MCP server",
    description: "Add a server-sent-events MCP server to the active runtime registry.",
    metricValue: "sse",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_add",
      reducer: "replace",
      mcpServerId: "",
      mcpServerLabel: "",
      mcpTransport: "sse",
      mcpServerUrl: "",
      mcpServerHeadersJson: "{}",
      mcpServerConfigJson:
        "{\"transport\":\"sse\",\"url\":\"\",\"allowedTools\":[]}",
    },
  });
  const mcpServe = creatorDefinition("state", {
    creatorId: "mcp.serve",
    label: "Serve MCP tools",
    description: "Expose selected governed IOI runtime tools through a thread-scoped MCP endpoint.",
    metricValue: "serve",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_serve",
      reducer: "replace",
      mcpServeEndpoint: "/v1/threads/{thread_id}/mcp/serve",
      mcpServeAllowedToolsJson:
        "[\"workspace.status\",\"git.diff\",\"file.inspect\"]",
    },
  });
  const mcpServerRemove = creatorDefinition("state", {
    creatorId: "mcp.server.remove",
    label: "Remove MCP server",
    description: "Remove an MCP server from the active runtime registry.",
    metricValue: "remove",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_remove",
      reducer: "replace",
      mcpServerId: "",
    },
  });
  const mcpServerEnable = creatorDefinition("state", {
    creatorId: "mcp.server.enable",
    label: "Enable MCP server",
    description: "Enable an MCP server in the active runtime registry.",
    metricValue: "enable",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_enable",
      reducer: "replace",
      mcpServerId: "",
    },
  });
  const mcpServerDisable = creatorDefinition("state", {
    creatorId: "mcp.server.disable",
    label: "Disable MCP server",
    description: "Disable an MCP server in the active runtime registry.",
    metricValue: "disable",
    defaultLogic: {
      stateKey: "mcp",
      stateOperation: "mcp_disable",
      reducer: "replace",
      mcpServerId: "",
    },
  });
  const subagentPool = creatorDefinition("state", {
    creatorId: "subagent.pool",
    label: "Subagent pool",
    description: "List thread subagents and configure role-aware pool constraints.",
    metricValue: "pool",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_list",
      reducer: "replace",
      subagentRole: "general",
      subagentMaxConcurrency: 2,
      subagentOutputContractJson:
        "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentRole = creatorDefinition("state", {
    creatorId: "subagent.role",
    label: "Subagent role",
    description: "Assign or update a subagent role using the daemon lifecycle contract.",
    metricValue: "role",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_assign",
      reducer: "replace",
      subagentId: "",
      subagentRole: "general",
      subagentOutputContractJson:
        "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentSpawn = creatorDefinition("state", {
    creatorId: "subagent.spawn",
    label: "Spawn subagent",
    description: "Spawn a role-aware child agent with explicit context, budget, and output contract.",
    metricValue: "spawn",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_spawn",
      reducer: "append",
      subagentRole: "explore",
      subagentPrompt: "Inspect the assigned area and return SUMMARY, EVIDENCE, RISKS, and BLOCKERS.",
      subagentToolPack: "coding",
      subagentForkContext: false,
      subagentMaxConcurrency: 2,
      subagentBudgetJson: "{}",
      subagentOutputContractJson:
        "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentJoin = creatorDefinition("state", {
    creatorId: "subagent.join",
    label: "Join subagent",
    description: "Wait for a child agent and gate merge on its output contract.",
    metricValue: "join",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_wait",
      reducer: "merge",
      subagentId: "",
      subagentWaitTimeoutMs: 300000,
      subagentOutputContractJson:
        "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentResult = creatorDefinition("state", {
    creatorId: "subagent.result",
    label: "Subagent result",
    description: "Fetch a child agent result and output contract status.",
    metricValue: "result",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_result",
      reducer: "replace",
      subagentId: "",
      subagentOutputContractJson:
        "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentSendInput = creatorDefinition("state", {
    creatorId: "subagent.send_input",
    label: "Send subagent input",
    description: "Send follow-up input to a running child agent.",
    metricValue: "input",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_send_input",
      reducer: "append",
      subagentId: "",
      subagentInput: "",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentCancel = creatorDefinition("state", {
    creatorId: "subagent.cancel",
    label: "Cancel subagent",
    description: "Cancel a running child agent with explicit cancellation inheritance.",
    metricValue: "cancel",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_cancel",
      reducer: "replace",
      subagentId: "",
      subagentCancellationInheritance: "propagate",
    },
  });
  const subagentResume = creatorDefinition("state", {
    creatorId: "subagent.resume",
    label: "Resume subagent",
    description: "Resume a paused or restarted child agent and keep restart status visible.",
    metricValue: "resume",
    defaultLogic: {
      stateKey: "subagents",
      stateOperation: "subagent_resume",
      reducer: "replace",
      subagentId: "",
      subagentMergePolicy: "manual",
      subagentCancellationInheritance: "propagate",
    },
  });
  const memoryStatus = creatorDefinition("state", {
    creatorId: "memory.status",
    label: "Memory status",
    description: "Inspect governed memory status and validation receipts.",
    metricValue: "status",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_status",
      reducer: "replace",
      memoryScope: "thread",
      memoryRedaction: "none",
    },
  });
  const memoryPolicy = creatorDefinition("state", {
    creatorId: "memory.policy",
    label: "Memory policy",
    description: "Inspect effective memory policy for a thread or workflow.",
    metricValue: "policy",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_policy",
      reducer: "replace",
      memoryScope: "thread",
      memorySubagentInheritance: "explicit",
      memoryInjectionEnabled: true,
      memoryReadOnly: false,
      memoryWriteRequiresApproval: false,
    },
  });
  const memorySearch = creatorDefinition("state", {
    creatorId: "memory.search",
    label: "Memory search",
    description: "Filter governed memory by scope, key, and query.",
    metricValue: "search",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_search",
      reducer: "replace",
      memoryScope: "thread",
      memoryKey: "conversation",
      query: "",
      limit: 10,
      memoryRedaction: "none",
    },
  });
  const memoryList = creatorDefinition("state", {
    creatorId: "memory.list",
    label: "Memory list",
    description: "List governed memory by scope and key.",
    metricValue: "list",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_list",
      reducer: "replace",
      memoryScope: "thread",
      memoryKey: "conversation",
      limit: 20,
      memoryRedaction: "none",
    },
  });
  const memoryRemember = creatorDefinition("state", {
    creatorId: "memory.remember",
    label: "Memory remember",
    description: "Write a governed memory record with receipt-backed policy.",
    metricValue: "remember",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_remember",
      reducer: "append",
      memoryScope: "thread",
      memoryKey: "conversation",
      memoryText: "",
      memoryWriteRequiresApproval: true,
      memoryRedaction: "none",
    },
  });
  const memoryEdit = creatorDefinition("state", {
    creatorId: "memory.edit",
    label: "Memory edit",
    description: "Edit a governed memory record by id.",
    metricValue: "edit",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_edit",
      reducer: "replace",
      memoryRecordId: "",
      memoryText: "",
      memoryWriteRequiresApproval: true,
    },
  });
  const memoryDelete = creatorDefinition("state", {
    creatorId: "memory.delete",
    label: "Memory delete",
    description: "Delete a governed memory record by id.",
    metricValue: "delete",
    defaultLogic: {
      stateKey: "memory",
      stateOperation: "memory_delete",
      reducer: "replace",
      memoryRecordId: "",
      memoryWriteRequiresApproval: true,
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
    mcpStatus,
    mcpToolSearch,
    mcpToolFetch,
    mcpToolInvoke,
    mcpImport,
    mcpServerAdd,
    mcpHttpServerAdd,
    mcpSseServerAdd,
    mcpServe,
    mcpServerRemove,
    mcpServerEnable,
    mcpServerDisable,
    subagentPool,
    subagentRole,
    subagentSpawn,
    subagentJoin,
    subagentResult,
    subagentSendInput,
    subagentCancel,
    subagentResume,
    memoryStatus,
    memoryPolicy,
    memorySearch,
    memoryList,
    memoryRemember,
    memoryEdit,
    memoryDelete,
    stateWrite,
    stateAppend,
    stateReducer,
    stateCheckpoint,
    skillContextDiscover,
    skillContextPinned,
    ...WORKFLOW_NODE_DEFINITIONS.filter(
      (definition) =>
        ![
          "source",
          "trigger",
          "adapter",
          "plugin_tool",
          "output",
          "skill_context",
        ].includes(definition.type),
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
    codingToolPack,
    gitDiffTool,
    fileInspectTool,
    fileApplyPatchTool,
    testRunTool,
    lspDiagnosticsTool,
    artifactReadTool,
    toolRetrieveResultTool,
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
    case "runtime_doctor":
      return ["decision", "verifier", "output"];
    case "runtime_thread_fork":
      return ["runtime_checklist", "decision", "verifier", "output"];
    case "runtime_operator_interrupt":
      return ["runtime_thread_fork", "human_gate", "decision", "output"];
    case "runtime_operator_steer":
      return ["runtime_operator_interrupt", "decision", "verifier", "output"];
    case "runtime_context_compact":
      return ["runtime_operator_steer", "decision", "verifier", "output"];
    case "runtime_rollback_snapshot":
      return ["runtime_context_compact", "decision", "verifier", "output"];
    case "runtime_restore_gate":
      return ["runtime_rollback_snapshot", "human_gate", "decision", "output"];
    case "runtime_diagnostics_repair":
      return ["runtime_restore_gate", "human_gate", "decision", "output"];
    case "workflow_package_export":
      return ["workflow_package_import", "verifier", "output"];
    case "workflow_package_import":
      return ["human_gate", "decision", "verifier", "output"];
    case "trigger":
    case "source":
      return [
        "function",
        "skill_context",
        "model_call",
        "adapter",
        "plugin_tool",
        "output",
      ];
    case "skill_context":
    case "skill":
    case "skill_pack":
      return ["model_call", "hook", "output"];
    case "hook":
      return ["hook_policy", "decision", "output"];
    case "hook_policy":
      return ["decision", "verifier", "output"];
    case "model_call":
      return [
        "model_binding",
        "skill_context",
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
    type === "skill_context" ||
    type === "skill" ||
    type === "skill_pack" ||
    type === "hook" ||
    type === "hook_policy" ||
    type === "workflow_package_export" ||
    type === "workflow_package_import" ||
    type === "runtime_thread_fork" ||
    type === "runtime_operator_interrupt" ||
    type === "runtime_operator_steer" ||
    type === "runtime_context_compact" ||
    type === "runtime_rollback_snapshot" ||
    type === "runtime_restore_gate" ||
    type === "runtime_diagnostics_repair" ||
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
    } as WorkflowNode["config"],
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
