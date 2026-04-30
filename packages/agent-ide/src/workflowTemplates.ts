import type {
  WorkflowEdge,
  WorkflowExecutionMode,
  WorkflowKind,
  WorkflowNode,
  WorkflowTemplateMetadata,
  WorkflowTestCase,
} from "./types/graph";

type NodeSeed = Pick<
  WorkflowNode,
  | "id"
  | "type"
  | "name"
  | "x"
  | "y"
  | "metricLabel"
  | "metricValue"
  | "ioTypes"
  | "inputs"
  | "outputs"
  | "config"
>;

function node(seed: NodeSeed): WorkflowNode {
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
): WorkflowEdge {
  return { id, from, to, fromPort, toPort, type: "data", connectionClass: "data", data: { connectionClass: "data" } };
}

function test(id: string, name: string, targetNodeIds: string[]): WorkflowTestCase {
  return {
    id,
    name,
    targetNodeIds,
    assertion: { kind: "node_exists" },
    status: "idle",
  };
}

function source(id: string, name: string, x: number, y: number, metricValue: string): WorkflowNode {
  const sourceLogic =
    metricValue === "image"
      ? {
          sourceKind: "media" as const,
          sourcePath: "input.jpg",
          fileExtension: "jpg",
          mediaKind: "image" as const,
          mimeType: "image/jpeg",
          sanitizeInput: true,
          validateMime: true,
          stripMetadata: true,
          payload: { file: "input.jpg", mediaKind: "image", extension: "jpg" },
          variables: { input: `{{${id}}}` },
        }
      : {
          sourceKind: "manual" as const,
          variables: { input: `{{${id}}}` },
        };
  return node({
    id,
    type: "source",
    name,
    x,
    y,
    metricLabel: "Input",
    metricValue,
    ioTypes: { in: "none", out: "payload" },
    outputs: ["output"],
    config: { logic: sourceLogic, law: {} },
  });
}

function model(id: string, name: string, x: number, y: number, prompt: string, binding = "reasoning"): WorkflowNode {
  return node({
    id,
    type: "model_call",
    name,
    x,
    y,
    metricLabel: "Model",
    metricValue: binding,
    ioTypes: { in: "prompt", out: "message" },
    inputs: ["input", "context"],
    outputs: ["output", "error", "retry"],
    config: { logic: { modelRef: binding, prompt }, law: {} },
  });
}

function fn(id: string, name: string, x: number, y: number, code: string): WorkflowNode {
  const outputSchema = { type: "object" };
  return node({
    id,
    type: "function",
    name,
    x,
    y,
    metricLabel: "Runtime",
    metricValue: "local",
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
          sandboxPolicy: { timeoutMs: 1000, memoryMb: 64, outputLimitBytes: 32768, permissions: [] },
          testInput: { payload: "sample" },
        },
      },
      law: { sandboxPolicy: { timeoutMs: 1000, memoryMb: 64, outputLimitBytes: 32768, permissions: [] } },
    },
  });
}

function adapter(id: string, name: string, x: number, y: number, connector: string, privileged = false): WorkflowNode {
  const sideEffectClass = privileged ? "external_write" : "read";
  return node({
    id,
    type: "adapter",
    name,
    x,
    y,
    metricLabel: "Connector",
    metricValue: connector,
    ioTypes: { in: "request", out: "response" },
    inputs: ["input", "context"],
    outputs: ["output", "error", "retry"],
    config: {
      logic: {
        connectorBinding: {
          connectorRef: connector,
          mockBinding: true,
          capabilityScope: privileged ? ["read", "write"] : ["read"],
          sideEffectClass,
          requiresApproval: privileged,
          operation: privileged ? "draft_or_create" : "read",
        },
      },
      law: privileged ? { requireHumanGate: true, privilegedActions: [sideEffectClass] } : {},
    },
  });
}

function plugin(id: string, name: string, x: number, y: number, toolName: string): WorkflowNode {
  return node({
    id,
    type: "plugin_tool",
    name,
    x,
    y,
    metricLabel: "Plugin",
    metricValue: toolName,
    ioTypes: { in: "args", out: "result" },
    inputs: ["input"],
    outputs: ["output", "error"],
    config: {
      logic: {
        toolBinding: {
          toolRef: toolName,
          mockBinding: true,
          capabilityScope: ["read"],
          sideEffectClass: "read",
          requiresApproval: false,
          arguments: {},
        },
      },
      law: {},
    },
  });
}

function decision(id: string, name: string, x: number, y: number, routes: string[]): WorkflowNode {
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
    config: { logic: { routes, routerInstruction: `Route to ${routes.join(" or ")}.` }, law: {} },
  });
}

function gate(id: string, name: string, x: number, y: number): WorkflowNode {
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
    config: { logic: { text: "Approval required before privileged action." }, law: { requireHumanGate: true } },
  });
}

function output(id: string, name: string, x: number, y: number, metricValue = "draft"): WorkflowNode {
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

function assertion(id: string, name: string, x: number, y: number): WorkflowNode {
  return node({
    id,
    type: "test_assertion",
    name,
    x,
    y,
    metricLabel: "Tests",
    metricValue: "mapped",
    ioTypes: { in: "actual", out: "result" },
    inputs: ["input"],
    outputs: ["output", "error"],
    config: { logic: { conditionScript: "return Boolean(input);" }, law: {} },
  });
}

function template(
  templateId: string,
  name: string,
  description: string,
  workflowKind: WorkflowKind,
  executionMode: WorkflowExecutionMode,
  guardrailProfile: string,
  requiredConnectors: string[],
  optionalConnectors: string[],
  seedNodes: WorkflowNode[],
  seedEdges: WorkflowEdge[],
  seedTests: WorkflowTestCase[],
): WorkflowTemplateMetadata {
  return {
    templateId,
    name,
    description,
    workflowKind,
    executionMode,
    requiredConnectors,
    optionalConnectors,
    guardrailProfile,
    seedNodes,
    seedEdges,
    seedTests,
  };
}

export const WORKFLOW_TEMPLATES: WorkflowTemplateMetadata[] = [
  template(
    "basic-agent-answer",
    "Basic agent answer",
    "Manual input, model response, and answer output.",
    "agent_workflow",
    "local",
    "read_transform",
    [],
    [],
    [
      source("source-user-input", "User input", 120, 180, "manual"),
      model("model-answer", "Draft answer", 390, 170, "Answer the user request using available context."),
      output("output-answer", "Answer bundle", 690, 180),
    ],
    [edge("edge-source-model", "source-user-input", "model-answer"), edge("edge-model-output", "model-answer", "output-answer")],
    [test("test-basic-path", "Input and answer path exists", ["source-user-input", "model-answer", "output-answer"])],
  ),
  template(
    "repo-function-test",
    "Repo function test",
    "Source data transformed by a local function with a mapped test assertion.",
    "evaluation_workflow",
    "local",
    "read_transform",
    [],
    [],
    [
      source("source-repo-context", "Repo context", 90, 180, "workspace"),
      fn("function-summarize", "Summarize files", 340, 170, "return { summary: input?.summary || 'ready' };"),
      assertion("test-shape", "Output has summary", 590, 180),
      output("output-test-report", "Test report", 840, 180, "report"),
    ],
    [
      edge("edge-source-function", "source-repo-context", "function-summarize"),
      edge("edge-function-test", "function-summarize", "test-shape"),
      edge("edge-test-output", "test-shape", "output-test-report"),
    ],
    [test("test-function-path", "Function and test path exists", ["source-repo-context", "function-summarize", "test-shape"])],
  ),
  template(
    "adapter-connector-check",
    "Adapter connector check",
    "Connector read, decision branch, and output bundle.",
    "agent_workflow",
    "hybrid",
    "connector_read",
    ["generic_connector"],
    [],
    [
      source("source-request", "Request", 90, 190, "manual"),
      adapter("adapter-read", "Read connector", 330, 180, "generic_connector"),
      decision("decision-health", "Check response", 570, 175, ["usable", "needs_attention"]),
      output("output-connector", "Connector report", 820, 185, "status"),
    ],
    [
      edge("edge-request-adapter", "source-request", "adapter-read"),
      edge("edge-adapter-decision", "adapter-read", "decision-health"),
      edge("edge-decision-output", "decision-health", "output-connector", "left"),
    ],
    [test("test-adapter-path", "Connector path exists", ["source-request", "adapter-read", "decision-health"])],
  ),
  template(
    "plugin-tool-action",
    "Plugin tool action",
    "Plugin tool invocation followed by model interpretation.",
    "agent_workflow",
    "hybrid",
    "tool_read",
    [],
    ["codex_plugin"],
    [
      source("source-task", "Task input", 90, 180, "manual"),
      plugin("plugin-codex", "Invoke plugin", 330, 170, "codex_plugin"),
      model("model-interpret", "Interpret result", 590, 170, "Summarize the plugin result and propose next action."),
      output("output-plugin", "Plugin result", 860, 180, "summary"),
    ],
    [
      edge("edge-task-plugin", "source-task", "plugin-codex"),
      edge("edge-plugin-model", "plugin-codex", "model-interpret"),
      edge("edge-model-output", "model-interpret", "output-plugin"),
    ],
    [test("test-plugin-path", "Plugin path exists", ["source-task", "plugin-codex", "model-interpret"])],
  ),
  template(
    "human-gated-change",
    "Human gated change",
    "Model proposal gated by human approval before output.",
    "agent_workflow",
    "local",
    "approval_required",
    [],
    [],
    [
      source("source-change-request", "Change request", 90, 180, "manual"),
      model("model-proposal", "Draft change", 330, 170, "Draft a bounded change proposal."),
      gate("gate-approval", "Approval gate", 590, 175),
      output("output-approved-change", "Approved bundle", 840, 185, "pending"),
    ],
    [
      edge("edge-request-model", "source-change-request", "model-proposal"),
      edge("edge-model-gate", "model-proposal", "gate-approval"),
      edge("edge-gate-output", "gate-approval", "output-approved-change"),
    ],
    [test("test-gated-path", "Gated path exists", ["source-change-request", "model-proposal", "gate-approval"])],
  ),
  template(
    "jpg-to-svg-tracing",
    "JPG to SVG tracing",
    "Image input converted into an SVG output without privileged policy unless exported.",
    "agent_workflow",
    "local",
    "media_transform",
    [],
    [],
    [
      source("source-jpg", "Media input", 80, 180, "image"),
      model("model-vision-trace", "Trace image", 330, 170, "Extract clean vector paths from the input image.", "vision"),
      fn("function-svg", "Build SVG", 590, 170, "return { svg: '<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>' };"),
      output("output-svg", "SVG output", 850, 180, "svg"),
    ],
    [
      edge("edge-jpg-vision", "source-jpg", "model-vision-trace"),
      edge("edge-vision-function", "model-vision-trace", "function-svg"),
      edge("edge-function-svg", "function-svg", "output-svg"),
    ],
    [test("test-svg-path", "SVG transform path exists", ["source-jpg", "model-vision-trace", "function-svg", "output-svg"])],
  ),
  template(
    "proposal-mutation",
    "Proposal mutation",
    "A bounded proposal preview before explicit graph mutation.",
    "agent_workflow",
    "local",
    "proposal_required",
    [],
    [],
    [
      source("source-existing-flow", "Existing workflow", 80, 180, "graph"),
      model("model-mutation", "Suggest mutation", 330, 170, "Suggest a bounded improvement to this workflow."),
      gate("gate-apply", "Apply approval", 590, 175),
      output("output-proposal", "Proposal preview", 850, 180, "diff"),
    ],
    [
      edge("edge-flow-model", "source-existing-flow", "model-mutation"),
      edge("edge-model-gate", "model-mutation", "gate-apply"),
      edge("edge-gate-proposal", "gate-apply", "output-proposal"),
    ],
    [test("test-proposal-path", "Proposal path exists", ["source-existing-flow", "model-mutation", "gate-apply"])],
  ),
  template(
    "software-request-triage-agent",
    "Software request triage agent",
    "Intake, policy check, ticket draft or creation, and approval for privileged actions.",
    "event_workflow",
    "hybrid",
    "approval_required",
    ["it_ticketing"],
    ["slack"],
    [
      source("source-request-intake", "Request intake", 70, 185, "queue"),
      decision("decision-policy", "Policy check", 300, 170, ["allowed", "needs_approval"]),
      adapter("adapter-ticket", "IT ticket draft", 540, 170, "it_ticketing", true),
      gate("gate-ticket-create", "Create approval", 780, 175),
      output("output-triage", "Triage record", 1030, 185, "ticket"),
    ],
    [
      edge("edge-intake-policy", "source-request-intake", "decision-policy"),
      edge("edge-policy-ticket", "decision-policy", "adapter-ticket", "left"),
      edge("edge-ticket-gate", "adapter-ticket", "gate-ticket-create"),
      edge("edge-gate-record", "gate-ticket-create", "output-triage"),
    ],
    [test("test-triage-path", "Triage path exists", ["source-request-intake", "decision-policy", "adapter-ticket", "gate-ticket-create"])],
  ),
  template(
    "product-feedback-router-agent",
    "Product feedback router",
    "Feedback intake from multiple sources, dedupe, classify, prioritize, and weekly output.",
    "scheduled_workflow",
    "hybrid",
    "connector_read",
    ["slack"],
    ["support", "public_channels"],
    [
      source("source-feedback", "Feedback sources", 70, 180, "multi"),
      fn("function-dedupe", "Dedupe feedback", 310, 170, "return { items: input?.items || [] };"),
      model("model-classify", "Classify themes", 550, 170, "Cluster feedback into product themes and urgency."),
      output("output-priority", "Weekly signal", 820, 180, "weekly"),
    ],
    [
      edge("edge-feedback-dedupe", "source-feedback", "function-dedupe"),
      edge("edge-dedupe-model", "function-dedupe", "model-classify"),
      edge("edge-model-signal", "model-classify", "output-priority"),
    ],
    [test("test-feedback-path", "Feedback router path exists", ["source-feedback", "function-dedupe", "model-classify"])],
  ),
  template(
    "weekly-metrics-reporting-agent",
    "Weekly metrics reporting agent",
    "Data pull, chart generation, narrative draft, and scheduled delivery.",
    "scheduled_workflow",
    "hybrid",
    "connector_read",
    ["analytics"],
    ["slack", "email"],
    [
      adapter("adapter-metrics", "Pull metrics", 80, 180, "analytics"),
      fn("function-chart", "Generate charts", 320, 170, "return { charts: [] };"),
      model("model-narrative", "Draft narrative", 560, 170, "Write a concise metrics narrative with notable changes."),
      output("output-report", "Weekly report", 830, 180, "scheduled"),
    ],
    [
      edge("edge-metrics-chart", "adapter-metrics", "function-chart"),
      edge("edge-chart-narrative", "function-chart", "model-narrative"),
      edge("edge-narrative-report", "model-narrative", "output-report"),
    ],
    [test("test-metrics-path", "Metrics report path exists", ["adapter-metrics", "function-chart", "model-narrative"])],
  ),
  template(
    "month-end-accounting-close-agent",
    "Month-end accounting close agent",
    "Collection, reconciliation, variance analysis, and workpaper bundle with strong approvals.",
    "scheduled_workflow",
    "hybrid",
    "financial_approval_required",
    ["accounting_system"],
    ["drive"],
    [
      adapter("adapter-close-source", "Collect close data", 70, 185, "accounting_system"),
      fn("function-reconcile", "Reconcile entries", 310, 170, "return { reconciled: true };"),
      model("model-variance", "Variance analysis", 550, 170, "Explain material variances and unresolved items."),
      gate("gate-financial-write", "Financial approval", 800, 175),
      output("output-workpapers", "Workpaper bundle", 1050, 185, "close"),
    ],
    [
      edge("edge-source-reconcile", "adapter-close-source", "function-reconcile"),
      edge("edge-reconcile-variance", "function-reconcile", "model-variance"),
      edge("edge-variance-gate", "model-variance", "gate-financial-write"),
      edge("edge-gate-workpapers", "gate-financial-write", "output-workpapers"),
    ],
    [test("test-close-path", "Close path exists", ["adapter-close-source", "function-reconcile", "model-variance", "gate-financial-write"])],
  ),
  template(
    "slack-qa-agent",
    "Slack Q&A agent",
    "Question intake, source lookup, answer, and ticket proposal for novel issues.",
    "event_workflow",
    "hybrid",
    "connector_read_write_with_approval",
    ["slack", "docs"],
    ["it_ticketing"],
    [
      adapter("adapter-slack-question", "Slack question", 70, 180, "slack"),
      adapter("adapter-docs", "Docs lookup", 310, 170, "docs"),
      model("model-answer", "Answer question", 550, 170, "Answer using source links; identify if a new ticket is needed."),
      decision("decision-novel", "Novel issue?", 800, 175, ["answer", "ticket"]),
      output("output-qa", "Answer or ticket proposal", 1050, 185, "response"),
    ],
    [
      edge("edge-slack-docs", "adapter-slack-question", "adapter-docs"),
      edge("edge-docs-answer", "adapter-docs", "model-answer"),
      edge("edge-answer-decision", "model-answer", "decision-novel"),
      edge("edge-decision-output", "decision-novel", "output-qa", "left"),
    ],
    [test("test-qa-path", "Q&A path exists", ["adapter-slack-question", "adapter-docs", "model-answer", "decision-novel"])],
  ),
  template(
    "heavy-repo-test-engineer",
    "Repo test engineer",
    "Scan workspace context, diagnose failing tests, and stage a bounded repair proposal.",
    "evaluation_workflow",
    "local",
    "proposal_required",
    [],
    [],
    [
      source("source-workspace", "Workspace source", 70, 180, "repo"),
      fn("function-file-scan", "File scanner", 300, 170, "return { result: { files: ['package.json'], findings: [] } };"),
      model("model-test-diagnosis", "Test diagnosis", 540, 170, "Diagnose failing tests from the file scan and propose focused verification."),
      assertion("test-diagnosis", "Diagnosis exists", 790, 180),
      output("output-repair-report", "Repair report", 1040, 185, "proposal"),
    ],
    [
      edge("edge-workspace-scan", "source-workspace", "function-file-scan"),
      edge("edge-scan-diagnosis", "function-file-scan", "model-test-diagnosis"),
      edge("edge-diagnosis-test", "model-test-diagnosis", "test-diagnosis"),
      edge("edge-test-report", "test-diagnosis", "output-repair-report"),
    ],
    [test("test-heavy-repo-path", "Repo test workflow path exists", ["source-workspace", "function-file-scan", "model-test-diagnosis"])],
  ),
  template(
    "heavy-mcp-research-operator",
    "MCP research operator",
    "Use a sandboxed MCP-style search tool, validate the payload, and synthesize a cited output.",
    "agent_workflow",
    "hybrid",
    "tool_read",
    [],
    ["web_search_mcp"],
    [
      source("source-research-prompt", "Research prompt", 70, 180, "prompt"),
      plugin("plugin-search", "Search tool", 310, 170, "web_search_mcp"),
      fn("function-validate-sources", "Validate sources", 550, 170, "return { result: { sourceCount: 1, valid: true } };"),
      model("model-research-synthesis", "Synthesize answer", 790, 170, "Synthesize a concise answer from validated sources."),
      output("output-research", "Research brief", 1060, 185, "cited"),
    ],
    [
      edge("edge-prompt-search", "source-research-prompt", "plugin-search"),
      edge("edge-search-validate", "plugin-search", "function-validate-sources"),
      edge("edge-validate-synthesis", "function-validate-sources", "model-research-synthesis"),
      edge("edge-synthesis-brief", "model-research-synthesis", "output-research"),
    ],
    [test("test-heavy-research-path", "Research operator path exists", ["source-research-prompt", "plugin-search", "function-validate-sources"])],
  ),
  template(
    "heavy-connector-triage",
    "Connector triage agent",
    "Read from a support connector, branch on urgency, draft a ticket, and pause before writes.",
    "event_workflow",
    "hybrid",
    "connector_read_write_with_approval",
    ["support", "it_ticketing"],
    ["slack"],
    [
      source("source-support-event", "Support event", 70, 185, "event"),
      adapter("adapter-support-read", "Support read", 300, 175, "support"),
      decision("decision-urgency", "Urgency branch", 540, 170, ["draft", "ignore"]),
      adapter("adapter-ticket-draft", "Ticket draft", 790, 170, "it_ticketing", true),
      gate("gate-ticket-write", "Write approval", 1030, 175),
      output("output-ticket-plan", "Ticket plan", 1280, 185, "ticket"),
    ],
    [
      edge("edge-event-support", "source-support-event", "adapter-support-read"),
      edge("edge-support-urgency", "adapter-support-read", "decision-urgency"),
      edge("edge-urgency-ticket", "decision-urgency", "adapter-ticket-draft", "left"),
      edge("edge-ticket-gate-heavy", "adapter-ticket-draft", "gate-ticket-write"),
      edge("edge-gate-ticket-plan", "gate-ticket-write", "output-ticket-plan"),
    ],
    [test("test-heavy-triage-path", "Connector triage path exists", ["adapter-support-read", "decision-urgency", "adapter-ticket-draft"])],
  ),
  template(
    "heavy-financial-close",
    "Financial close assistant",
    "Reconcile close data, explain variances, and require strong approval before financial writes.",
    "scheduled_workflow",
    "hybrid",
    "financial_approval_required",
    ["accounting_system"],
    ["drive"],
    [
      adapter("adapter-close-collect", "Close data", 70, 185, "accounting_system"),
      fn("function-reconcile-heavy", "Reconciliation", 310, 170, "return { result: { balanced: true, exceptions: [] } };"),
      fn("function-variance-heavy", "Variance calc", 550, 170, "return { result: { materialVariances: [] } };"),
      model("model-close-analysis", "Close analysis", 790, 170, "Draft variance analysis and workpaper notes."),
      gate("gate-close-write", "Financial write approval", 1030, 175),
      output("output-close-workpapers", "Workpapers", 1280, 185, "bundle"),
    ],
    [
      edge("edge-close-collect-reconcile", "adapter-close-collect", "function-reconcile-heavy"),
      edge("edge-reconcile-variance-heavy", "function-reconcile-heavy", "function-variance-heavy"),
      edge("edge-variance-analysis-heavy", "function-variance-heavy", "model-close-analysis"),
      edge("edge-analysis-gate-heavy", "model-close-analysis", "gate-close-write"),
      edge("edge-gate-workpapers-heavy", "gate-close-write", "output-close-workpapers"),
    ],
    [test("test-heavy-close-path", "Financial close path exists", ["adapter-close-collect", "function-reconcile-heavy", "gate-close-write"])],
  ),
  template(
    "heavy-media-transform",
    "Media transform agent",
    "Trace a JPG into SVG with local validation and no approval unless export permissions are added.",
    "agent_workflow",
    "local",
    "media_transform",
    [],
    [],
    [
      source("source-media-jpg", "Media source", 70, 180, "image"),
      model("model-media-vision", "Vision trace", 310, 170, "Find vector-friendly contours in the image.", "vision"),
      fn("function-svg-trace", "SVG tracing", 550, 170, "return { result: { svg: '<svg xmlns=\"http://www.w3.org/2000/svg\" />' } };"),
      output("output-media-svg", "SVG output", 820, 185, "svg"),
    ],
    [
      edge("edge-media-vision", "source-media-jpg", "model-media-vision"),
      edge("edge-vision-svg-trace", "model-media-vision", "function-svg-trace"),
      edge("edge-svg-output", "function-svg-trace", "output-media-svg"),
    ],
    [test("test-heavy-media-path", "Media transform path exists", ["source-media-jpg", "model-media-vision", "function-svg-trace"])],
  ),
  template(
    "heavy-scheduled-reporter",
    "Long-running scheduled reporter",
    "Pull metrics, generate chart payloads, draft narrative, and keep checkpointed run history.",
    "scheduled_workflow",
    "hybrid",
    "connector_read",
    ["analytics"],
    ["email"],
    [
      source("source-schedule", "Weekly trigger", 70, 185, "schedule"),
      adapter("adapter-report-data", "Data pull", 300, 175, "analytics"),
      fn("function-chart-payload", "Chart payload", 540, 170, "return { result: { series: [], chartType: 'line' } };"),
      model("model-report-narrative", "Narrative", 790, 170, "Draft the weekly report narrative from chart payloads."),
      output("output-scheduled-report", "Scheduled report", 1060, 185, "report"),
    ],
    [
      edge("edge-schedule-data", "source-schedule", "adapter-report-data"),
      edge("edge-data-chart", "adapter-report-data", "function-chart-payload"),
      edge("edge-chart-narrative-heavy", "function-chart-payload", "model-report-narrative"),
      edge("edge-narrative-report-heavy", "model-report-narrative", "output-scheduled-report"),
    ],
    [test("test-heavy-reporter-path", "Scheduled reporter path exists", ["source-schedule", "adapter-report-data", "function-chart-payload"])],
  ),
  template(
    "heavy-self-improving-proposal",
    "Self-improving workflow proposal",
    "Analyze an existing workflow and stage bounded improvements for explicit user review.",
    "agent_workflow",
    "local",
    "proposal_required",
    [],
    [],
    [
      source("source-workflow-under-review", "Workflow under review", 70, 185, "graph"),
      fn("function-gap-scan", "Gap scanner", 310, 170, "return { result: { boundedTargets: ['model-review'], issues: [] } };"),
      model("model-review", "Improvement proposal", 550, 170, "Create a bounded proposal that improves workflow behavior."),
      gate("gate-apply-proposal", "Apply approval", 800, 175),
      output("output-improvement-proposal", "Proposal diff", 1050, 185, "diff"),
    ],
    [
      edge("edge-review-gap-scan", "source-workflow-under-review", "function-gap-scan"),
      edge("edge-gap-proposal", "function-gap-scan", "model-review"),
      edge("edge-proposal-gate-heavy", "model-review", "gate-apply-proposal"),
      edge("edge-gate-diff-heavy", "gate-apply-proposal", "output-improvement-proposal"),
    ],
    [test("test-heavy-self-improving-path", "Self-improving proposal path exists", ["source-workflow-under-review", "function-gap-scan", "gate-apply-proposal"])],
  ),
];

export function getWorkflowTemplate(templateId: string): WorkflowTemplateMetadata | undefined {
  return WORKFLOW_TEMPLATES.find((templateItem) => templateItem.templateId === templateId);
}
