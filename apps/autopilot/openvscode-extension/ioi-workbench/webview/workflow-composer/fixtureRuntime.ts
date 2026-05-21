import { scenarioById, workflowScenarios } from "./fixtureWorkflows";

type BridgePost = (requestType: string, payload?: Record<string, unknown>) => void;

const now = () => Date.now();

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function runtimeThreadEvent(
  event: any,
  index: number,
  threadId: string,
  workflowId: string,
) {
  const id = event.id ?? `event:${threadId}:${index + 1}`;
  const createdAtMs = event.createdAtMs ?? now();
  const status = String(event.status ?? "completed");
  const eventKind = String(event.kind ?? event.eventKind ?? "fixture_projection");
  return {
    schemaVersion: "ioi.runtime.thread-event.v1",
    id,
    eventId: id,
    cursor: String(index + 1),
    seq: index + 1,
    threadId,
    turnId: `turn:${workflowId}:fixture`,
    type: eventKind,
    eventKind,
    sourceEventKind: `Fixture.${eventKind}`,
    status,
    createdAt: new Date(createdAtMs).toISOString(),
    createdAtMs,
    componentKind: event.nodeId ? "workflow_node" : "workflow_runtime",
    workflowNodeId: event.nodeId ?? null,
    workflowGraphId: workflowId,
    payloadSchemaVersion: "ioi.workflow-compositor.fixture-event.v1",
    receiptRefs: [`receipt:${id}`],
    artifactRefs: [],
    policyDecisionRefs:
      eventKind === "approval_required"
        ? [`policy:${workflowId}:approval-fixture`]
        : [],
    rollbackRefs: [],
    replayFixtureRefs: [`replay:${id}`],
    externalAction: false,
    payload: {
      message: event.message,
      nodeId: event.nodeId ?? null,
      source: "electron-workflow-compositor-fixture",
      externalAction: false,
    },
  };
}

function harnessComponentKind(node: any) {
  if (node.type === "model") return "model_call";
  if (node.type === "connector") return "connector_call";
  if (node.type === "approval") return "approval_gate";
  if (node.type === "output") return "workflow_package_export";
  if (node.type === "source") return "repository_context";
  return "runtime_task";
}

function passedValidation(workflow: any) {
  const coverageByNodeId = Object.fromEntries(
    (workflow.nodes ?? []).map((node: any) => [
      node.id,
      ["node_configured", "fixture_runtime_projection"],
    ]),
  );
  return {
    status: "passed",
    errors: [],
    warnings: [
      {
        code: "daemon_workflow_composer_api_fixture",
        message:
          "Daemon workflow-composer APIs are not wired yet; this adapter projects fixture results and emits bridge requests.",
      },
    ],
    blockedNodes: [],
    missingConfig: [],
    unsupportedRuntimeNodes: [],
    policyRequiredNodes: (workflow.nodes ?? [])
      .filter((node: any) => node.config?.law?.requireHumanGate)
      .map((node: any) => node.id),
    coverageByNodeId,
    connectorBindingIssues: [],
    executionReadinessIssues: [],
    verificationIssues: [],
    schedulerLaneReadiness: [
      {
        id: "scheduler",
        label: "Daemon scheduler lane",
        capabilityScope: "workflow.run.fixture",
        proofCheckKey: "fixture-scheduler-lane",
        status: "warning",
        detail:
          "Fixture lane is ready for UI parity; live daemon scheduler API remains a blocker before connector sprint execution.",
        evidenceRefs: ["receipt:workflow-compositor-fixture"],
      },
      {
        id: "validation",
        label: "Readiness validation",
        capabilityScope: "workflow.validate.fixture",
        proofCheckKey: "fixture-validation-lane",
        status: "ready",
        detail: "Readiness can be projected and inspected from the Electron composer.",
        evidenceRefs: ["readiness:workflow-compositor-fixture"],
      },
    ],
  };
}

function daemonInitialState() {
  const state = (window as any).__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__ ?? {};
  return {
    endpoint:
      typeof state.daemonEndpoint === "string" && state.daemonEndpoint.trim()
        ? state.daemonEndpoint.replace(/\/+$/, "")
        : "",
    token: typeof state.daemonToken === "string" ? state.daemonToken : "",
    modelId:
      typeof state.daemonModelId === "string" && state.daemonModelId.trim()
        ? state.daemonModelId.trim()
        : "native:electron-gui-model",
  };
}

function hasDaemonRuntime() {
  const config = daemonInitialState();
  return Boolean(config.endpoint && config.token);
}

async function daemonRequest(routePath: string, options: { method?: string; body?: any } = {}) {
  const config = daemonInitialState();
  if (!config.endpoint) {
    throw new Error("IOI daemon endpoint is not configured for WorkflowComposer.");
  }
  const response = await fetch(`${config.endpoint}${routePath}`, {
    method: options.method ?? "GET",
    headers: {
      accept: "application/json",
      ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      ...(config.token ? { authorization: `Bearer ${config.token}` } : {}),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(value?.error?.message || value?.message || `${routePath} failed with ${response.status}`);
  }
  return value;
}

function daemonModelCatalogFromProjection(projection: any) {
  const routes = Array.isArray(projection?.routes) ? projection.routes : [];
  const endpoints = Array.isArray(projection?.endpoints) ? projection.endpoints : [];
  const instances = Array.isArray(projection?.instances) ? projection.instances : [];
  const artifacts = Array.isArray(projection?.artifacts) ? projection.artifacts : [];
  const models = routes.flatMap((route: any) => {
    const routeEndpoints = endpoints.filter((endpoint: any) =>
      (route.fallback ?? []).includes(endpoint.id) ||
      route.lastSelectedModel === endpoint.modelId ||
      route.id === "route.native-local",
    );
    const resolvedEndpoints = routeEndpoints.length > 0 ? routeEndpoints : endpoints.slice(0, 1);
    return resolvedEndpoints.map((endpoint: any) => {
      const instance = instances.find(
        (item: any) => item.endpointId === endpoint.id && item.status === "loaded",
      );
      const artifact = artifacts.find(
        (item: any) => item.id === endpoint.artifactId || item.modelId === endpoint.modelId,
      );
      return {
        modelId: endpoint.modelId ?? artifact?.modelId ?? route.id,
        status: instance ? "ready" : endpoint.status === "mounted" ? "mounted" : "available",
        residency: instance ? "loaded" : "daemon-mounted",
        backendId: instance?.backendId ?? endpoint.backendId ?? null,
        routeId: route.id,
      };
    });
  });
  return {
    refreshedAtMs: Date.now(),
    models: models.length
      ? models
      : artifacts.map((artifact: any) => ({
          modelId: artifact.modelId,
          status: "available",
          residency: "artifact",
          backendId: null,
        })),
  };
}

function workflowNodeKind(node: any) {
  if (node.type === "model_call" || node.type === "model") return "Model Call";
  if (node.type === "decision") return "Model Router";
  return String(node.name ?? node.type ?? "Workflow Node");
}

function daemonThreadEvent(event: any, index: number, threadId: string, workflowId: string) {
  return {
    schemaVersion: "ioi.runtime.thread-event.v1",
    id: event.id,
    eventId: event.id,
    cursor: String(index + 1),
    seq: index + 1,
    threadId,
    turnId: `turn:${workflowId}:daemon-model`,
    type: event.kind,
    eventKind: event.kind,
    sourceEventKind: `DaemonModelRuntime.${event.kind}`,
    status: event.status,
    createdAt: new Date(event.createdAtMs).toISOString(),
    createdAtMs: event.createdAtMs,
    componentKind: event.nodeId ? "workflow_node" : "workflow_runtime",
    workflowNodeId: event.nodeId ?? null,
    workflowGraphId: workflowId,
    payloadSchemaVersion: "ioi.workflow-compositor.daemon-model-event.v1",
    receiptRefs: event.receiptRefs ?? [],
    artifactRefs: [],
    policyDecisionRefs: event.policyDecisionRefs ?? [],
    rollbackRefs: [],
    replayFixtureRefs: [],
    externalAction: false,
    payload: {
      message: event.message,
      nodeId: event.nodeId ?? null,
      routeId: event.routeId ?? null,
      modelId: event.modelId ?? null,
      source: "ioi-daemon-model-runtime",
      externalAction: false,
    },
  };
}

async function daemonRunResult(workflow: any, path: string, options: Record<string, unknown> = {}) {
  const startedAtMs = now();
  const runId = `run:${workflow.metadata?.id ?? "workflow"}:${startedAtMs}`;
  const threadId = `thread:${workflow.metadata?.id ?? "workflow"}:daemon-model`;
  const nodes = workflow.nodes ?? [];
  const modelNodes = nodes.filter((node: any) => node.type === "model_call" || node.type === "model" || node.type === "decision");
  const events: any[] = [
    {
      id: `${runId}:started`,
      runId,
      threadId,
      sequence: 1,
      kind: "run_started",
      createdAtMs: startedAtMs,
      status: "running",
      message: "Daemon-backed model dry-run started through Electron WorkflowComposer.",
      receiptRefs: [],
    },
  ];
  const nodeResults: any[] = [];
  for (const [index, node] of modelNodes.entries()) {
    events.push({
      id: `${runId}:${node.id}:started`,
      runId,
      threadId,
      sequence: events.length + 1,
      kind: "node_started",
      createdAtMs: startedAtMs + index * 80 + 20,
      nodeId: node.id,
      status: "running",
      message: `${node.name ?? node.id} sent to daemon model runtime`,
    });
    const daemonState = daemonInitialState();
    const result = await daemonRequest("/api/v1/workflows/nodes/execute", {
      method: "POST",
      body: {
        node: workflowNodeKind(node),
        route_id: node.type === "decision" ? "route.native-local" : "route.native-local",
        model: daemonState.modelId,
        input: node.config?.logic?.prompt ?? `Dry-run ${node.name ?? node.id}`,
        max_tokens: 1,
        temperature: 0,
        workflow_graph_id: workflow.metadata?.id ?? "workflow",
        workflow_node_id: node.id,
        workflow_node_type: workflowNodeKind(node),
        model_policy: { privacy: "local_only", reasoning_effort: "low" },
      },
    });
    const receiptId = result.receipt?.id ?? result.invocation?.receipt_id ?? result.receipt_id ?? null;
    const routeReceiptId = result.routeReceipt?.id ?? result.invocation?.route_receipt_id ?? null;
    nodeResults.push({ node, result, receiptId, routeReceiptId });
    events.push({
      id: `${runId}:${node.id}:daemon-model`,
      runId,
      threadId,
      sequence: events.length + 1,
      kind: result.node === "Model Router" ? "model_route_selected" : "model_invocation",
      createdAtMs: startedAtMs + index * 80 + 55,
      nodeId: node.id,
      status: "success",
      message: `${node.name ?? node.id} completed through daemon route ${result.invocation?.route_id ?? result.selection?.route?.id ?? "route.native-local"}`,
      receiptRefs: [receiptId, routeReceiptId].filter(Boolean),
      routeId: result.invocation?.route_id ?? result.selection?.route?.id ?? "route.native-local",
      modelId: result.invocation?.model ?? result.selection?.endpoint?.modelId ?? "native:electron-gui-model",
    });
  }
  events.push({
    id: `${runId}:completed`,
    runId,
    threadId,
    sequence: events.length + 1,
    kind: "run_completed",
    createdAtMs: startedAtMs + Math.max(1, modelNodes.length) * 100,
    status: "passed",
    message: "Daemon-backed model dry-run completed with receipts and replay metadata.",
    receiptRefs: nodeResults.flatMap((item) => [item.receiptId, item.routeReceiptId]).filter(Boolean),
  });
  const finalReceiptRefs = nodeResults.flatMap((item) => [item.receiptId, item.routeReceiptId]).filter(Boolean);
  return {
    summary: {
      id: runId,
      threadId,
      status: "passed",
      startedAtMs,
      finishedAtMs: startedAtMs + Math.max(1, modelNodes.length) * 100,
      nodeCount: nodes.length,
      testCount: workflow.tests?.length ?? 1,
      checkpointCount: Math.max(1, modelNodes.length),
      summary:
        "Electron WorkflowComposer dry-run invoked mounted local models through the IOI daemon.",
      evidencePath: "docs/evidence/autopilot-electron-model-mounting-daemon-runtime-adapter",
    },
    thread: {
      id: threadId,
      workflowPath: path,
      status: "passed",
      createdAtMs: startedAtMs,
      latestCheckpointId: `${runId}:checkpoint:final`,
      input: { source: options.source ?? "daemon-model-dry-run" },
    },
    finalState: {
      threadId,
      checkpointId: `${runId}:checkpoint:final`,
      runId,
      stepIndex: nodes.length,
      values: {
        externalAction: false,
        runtimeAuthority: "ioi-daemon",
        source: "daemon-model-dry-run",
      },
      nodeOutputs: Object.fromEntries(
        nodeResults.map(({ node, receiptId, routeReceiptId }) => [
          node.id,
          {
            status: "passed",
            receiptId,
            routeReceiptId,
          },
        ]),
      ),
      completedNodeIds: modelNodes.map((node: any) => node.id),
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: nodeResults.map(({ node, receiptId, routeReceiptId }, index) => ({
      nodeId: node.id,
      nodeType: node.type,
      status: "success",
      startedAtMs: startedAtMs + index * 80 + 20,
      finishedAtMs: startedAtMs + index * 80 + 55,
      attempt: 1,
      input: { source: "daemon-model-dry-run" },
      output: {
        status: "passed",
        externalAction: false,
        receiptId,
        routeReceiptId,
      },
      checkpointId: `${runId}:checkpoint:${node.id}`,
      lifecycle: ["queued", "running", "success"],
    })),
    checkpoints: nodeResults.map(({ node }, index) => ({
      id: `${runId}:checkpoint:${node.id}`,
      threadId,
      runId,
      createdAtMs: startedAtMs + index * 80 + 60,
      stepIndex: index + 1,
      nodeId: node.id,
      status: "passed",
      summary: `Daemon checkpoint for ${node.name ?? node.id}`,
    })),
    events,
    runtimeThreadEvents: events.map((event: any, index: number) =>
      daemonThreadEvent(event, index, threadId, workflow.metadata?.id ?? "workflow"),
    ),
    harnessAttempts: nodeResults.map(({ node, receiptId, routeReceiptId }, index) => ({
      attemptId: `attempt:${runId}:${node.id}`,
      harnessWorkflowId: workflow.metadata?.id ?? "workflow",
      harnessActivationId: "electron-workflow-composer-daemon-model",
      harnessHash: `daemon-model:${workflow.metadata?.id ?? "workflow"}`,
      workflowNodeId: node.id,
      componentId: node.config?.logic?.modelRef ?? "route.native-local",
      componentKind: "model_call",
      executionMode: "daemon_dry_run",
      readiness: "validated",
      attemptIndex: index + 1,
      status: "succeeded",
      inputHash: `input:${node.id}`,
      outputHash: `output:${node.id}`,
      policyDecision: "daemon_policy_allowed",
      startedAtMs: startedAtMs + index * 80 + 20,
      durationMs: 35,
      receiptIds: [receiptId, routeReceiptId].filter(Boolean),
      evidenceRefs: [receiptId, routeReceiptId].filter(Boolean),
      replay: {
        deterministicEnvelope: true,
        capturesInput: true,
        capturesOutput: true,
        capturesPolicyDecision: true,
        fixtureRef: null,
        determinism: "daemon_receipted",
        redactionPolicy: "daemon-redacted",
      },
    })),
    verificationEvidence: [
      {
        id: `evidence:${runId}`,
        kind: "run",
        createdAtMs: startedAtMs,
        status: "passed",
        summary: "Daemon model run produced receipts without external connector action.",
        evidenceRefs: finalReceiptRefs,
      },
    ],
    completionRequirements: [
      {
        id: "daemon-model-route",
        label: "Workflow model route invoked through daemon",
        status: finalReceiptRefs.length > 0 ? "passed" : "blocked",
        evidenceRefs: finalReceiptRefs,
      },
      {
        id: "no-external-action",
        label: "No external connector action",
        status: "passed",
        evidenceRefs: finalReceiptRefs,
      },
    ],
  };
}

function runResult(workflow: any, path: string, source = "fixture-dry-run") {
  const startedAtMs = now();
  const runId = `run:${workflow.metadata?.id ?? "workflow"}:${startedAtMs}`;
  const threadId = `thread:${workflow.metadata?.id ?? "workflow"}`;
  const nodes = workflow.nodes ?? [];
  const events = [
    {
      id: `${runId}:started`,
      runId,
      threadId,
      sequence: 1,
      kind: "run_started",
      createdAtMs: startedAtMs,
      status: "running",
      message: "Fixture dry-run started through Electron WorkflowComposer.",
    },
    ...nodes.flatMap((node: any, index: number) => [
      {
        id: `${runId}:${node.id}:started`,
        runId,
        threadId,
        sequence: index * 2 + 2,
        kind: "node_started",
        createdAtMs: startedAtMs + index * 50,
        nodeId: node.id,
        status: "running",
        message: `${node.name ?? node.id} started`,
      },
      {
        id: `${runId}:${node.id}:succeeded`,
        runId,
        threadId,
        sequence: index * 2 + 3,
        kind: node.config?.law?.requireHumanGate
          ? "approval_required"
          : "node_succeeded",
        createdAtMs: startedAtMs + index * 50 + 25,
        nodeId: node.id,
        status: node.config?.law?.requireHumanGate ? "blocked" : "success",
        message: node.config?.law?.requireHumanGate
          ? "Mock approval projected; no external action performed."
          : `${node.name ?? node.id} completed with fixture output`,
      },
    ]),
    {
      id: `${runId}:completed`,
      runId,
      threadId,
      sequence: nodes.length * 2 + 4,
      kind: "run_completed",
      createdAtMs: startedAtMs + nodes.length * 60,
      status: "passed",
      message: "Fixture dry-run completed with replayable receipts.",
    },
  ];
  return {
    summary: {
      id: runId,
      threadId,
      status: "passed",
      startedAtMs,
      finishedAtMs: startedAtMs + nodes.length * 60,
      nodeCount: nodes.length,
      testCount: workflow.tests?.length ?? 1,
      checkpointCount: Math.max(1, nodes.length),
      summary:
        "Electron WorkflowComposer fixture dry-run emitted timeline, receipts, replay evidence, and no external connector action.",
      evidencePath: "docs/evidence/autopilot-workbench-workflow-compositor-parity",
    },
    thread: {
      id: threadId,
      workflowPath: path,
      status: "passed",
      createdAtMs: startedAtMs,
      latestCheckpointId: `${runId}:checkpoint:final`,
      input: { source },
    },
    finalState: {
      threadId,
      checkpointId: `${runId}:checkpoint:final`,
      runId,
      stepIndex: nodes.length,
      values: {
        externalAction: false,
        runtimeAuthority: "daemon-fixture-adapter",
        source,
      },
      nodeOutputs: Object.fromEntries(
        nodes.map((node: any) => [
          node.id,
          {
            status: "passed",
            receiptId: `receipt:${runId}:${node.id}`,
            replayFixtureRef: `replay:${runId}:${node.id}`,
          },
        ]),
      ),
      completedNodeIds: nodes.map((node: any) => node.id),
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: nodes.map((node: any, index: number) => ({
      nodeId: node.id,
      nodeType: node.type,
      status: "success",
      startedAtMs: startedAtMs + index * 50,
      finishedAtMs: startedAtMs + index * 50 + 25,
      attempt: 1,
      input: { source },
      output: {
        status: "passed",
        externalAction: false,
        receiptId: `receipt:${runId}:${node.id}`,
      },
      checkpointId: `${runId}:checkpoint:${node.id}`,
      lifecycle: ["queued", "running", "success"],
    })),
    checkpoints: nodes.map((node: any, index: number) => ({
      id: `${runId}:checkpoint:${node.id}`,
      threadId,
      runId,
      createdAtMs: startedAtMs + index * 50 + 30,
      stepIndex: index + 1,
      nodeId: node.id,
      status: "passed",
      summary: `Checkpoint for ${node.name ?? node.id}`,
    })),
    events,
    runtimeThreadEvents: events.map((event: any, index: number) =>
      runtimeThreadEvent(event, index, threadId, workflow.metadata?.id ?? "workflow"),
    ),
    harnessAttempts: nodes.map((node: any, index: number) => {
      const receiptId = `receipt:${runId}:${node.id}`;
      const replayFixtureRef = `replay:${runId}:${node.id}`;
      return {
        attemptId: `attempt:${runId}:${node.id}`,
        harnessWorkflowId: workflow.metadata?.id ?? "workflow",
        harnessActivationId: "electron-workflow-composer-fixture",
        harnessHash: `fixture:${workflow.metadata?.id ?? "workflow"}`,
        workflowNodeId: node.id,
        componentId: node.config?.capabilityBinding?.capabilityRef ?? node.id,
        componentKind: harnessComponentKind(node),
        executionMode: "projection",
        readiness: node.config?.law?.requireHumanGate ? "validated" : "shadow_ready",
        attemptIndex: index + 1,
        status: node.config?.law?.requireHumanGate ? "blocked" : "succeeded",
        inputHash: `input:${node.id}`,
        outputHash: `output:${node.id}`,
        policyDecision: node.config?.law?.requireHumanGate
          ? "approval_required_fixture"
          : "fixture_allowed",
        startedAtMs: startedAtMs + index * 50,
        durationMs: 25,
        receiptIds: [receiptId],
        evidenceRefs: [receiptId, replayFixtureRef],
        replay: {
          deterministicEnvelope: true,
          capturesInput: true,
          capturesOutput: true,
          capturesPolicyDecision: true,
          fixtureRef: replayFixtureRef,
          determinism: "deterministic",
          redactionPolicy: "fixture-redacted",
        },
      };
    }),
    verificationEvidence: [
      {
        id: `evidence:${runId}`,
        kind: "run",
        createdAtMs: startedAtMs,
        status: "passed",
        summary: "Fixture run produced replayable evidence without external action.",
        evidenceRefs: [`receipt:${runId}`, `replay:${runId}`],
      },
    ],
    completionRequirements: [
      {
        id: "no-external-action",
        label: "No external connector action",
        status: "passed",
        evidenceRefs: [`receipt:${runId}`],
      },
      {
        id: "receipts-replay-visible",
        label: "Receipts and replay visible",
        status: "passed",
        evidenceRefs: [`replay:${runId}`],
      },
    ],
  };
}

export function createFixtureRuntime(getScenarioId: () => string, postBridge: BridgePost) {
  const projects = new Map(
    workflowScenarios.map((scenario) => [
      scenario.project.metadata.gitLocation,
      clone(scenario.project),
    ]),
  );
  const runs = new Map<string, any[]>();

  function activeScenario() {
    return scenarioById(getScenarioId());
  }

  function workflowForPath(path?: string) {
    if (path && projects.has(path)) return projects.get(path);
    const scenario = activeScenario();
    return projects.get(scenario.project.metadata.gitLocation) ?? scenario.project;
  }

  function rememberRun(path: string, result: any) {
    const current = runs.get(path) ?? [];
    runs.set(path, [result, ...current]);
    return result;
  }

  return {
    async runGraph(payload: any) {
      postBridge("workflowCompositor.fixtureRunGraph", {
        nodeCount: payload?.nodes?.length ?? 0,
        edgeCount: payload?.edges?.length ?? 0,
        externalAction: false,
      });
    },
    async stopExecution() {
      postBridge("workflowCompositor.fixtureStop", { externalAction: false });
    },
    async getAvailableTools() {
      return [
        { id: "fixture.read", name: "Fixture read", desc: "Read-only fixture tool", icon: "plug" },
        { id: "fixture.receipts", name: "Receipt projector", desc: "Fixture receipt projection", icon: "file" },
      ];
    },
    async checkNodeCache() {
      return null;
    },
    async getGraphModelBindingCatalog() {
      if (hasDaemonRuntime()) {
        const projection = await daemonRequest("/api/v1/projections/model-mounting");
        const catalog = daemonModelCatalogFromProjection(projection);
        postBridge("workflowCompositor.daemonModelCatalog", {
          modelCount: catalog.models.length,
          daemonBacked: true,
          externalAction: false,
        });
        return catalog;
      }
      return {
        refreshedAtMs: now(),
        models: [
          {
            modelId: "fixture.reasoning.model",
            status: "projection",
            residency: "fixture",
            backendId: "daemon.fixture.adapter",
          },
        ],
      };
    },
    async runNode(nodeType: string, config: any, input: string) {
      postBridge("workflowCompositor.fixtureRunNode", {
        nodeType,
        configHash: String(JSON.stringify(config ?? {})).length,
        externalAction: false,
      });
      return { output: input, status: "passed", externalAction: false };
    },
    onEvent(callback: (event: unknown) => void) {
      const event = {
        node_id: "fixture-runtime",
        status: "ready",
        result: {
          output: "Electron WorkflowComposer fixture runtime is attached.",
        },
      };
      window.setTimeout(() => callback(event), 0);
      return () => undefined;
    },
    async loadProject(path?: string) {
      return clone(workflowForPath(path));
    },
    async saveProject(path: string, projectFile: any) {
      projects.set(path, clone(projectFile));
      postBridge("workflowCompositor.fixtureSaveProject", {
        path,
        nodeCount: projectFile?.nodes?.length ?? 0,
        edgeCount: projectFile?.edges?.length ?? 0,
        directFileMutation: false,
      });
    },
    async saveWorkflowProject(path: string, workflow: any) {
      projects.set(path, clone(workflow));
      postBridge("workflowCompositor.fixtureSaveWorkflowProject", {
        path,
        nodeCount: workflow?.nodes?.length ?? 0,
        edgeCount: workflow?.edges?.length ?? 0,
        directFileMutation: false,
      });
    },
    async saveWorkflowTests(path: string, tests: any[]) {
      const workflow = workflowForPath(path);
      workflow.tests = clone(tests);
      projects.set(path, workflow);
    },
    async listWorkflowProjects() {
      return workflowScenarios.map((scenario) => ({
        workflowId: scenario.project.metadata.id,
        name: scenario.project.metadata.name,
        description: scenario.description,
        path: scenario.project.metadata.gitLocation,
        nodeCount: scenario.project.nodes.length,
        updatedAtMs: scenario.project.metadata.updatedAtMs,
      }));
    },
    async listWorkflowRuns(path: string) {
      return (runs.get(path) ?? []).map((result) => result.summary);
    },
    async loadWorkflowRun(path: string, runId: string) {
      const result = (runs.get(path) ?? []).find((item) => item.summary.id === runId);
      if (result) return clone(result);
      return runResult(workflowForPath(path), path, "fixture-load-run");
    },
    async listWorkflowNodeFixtures(path: string) {
      const workflow = workflowForPath(path);
      return (workflow.nodes ?? []).map((node: any) => ({
        id: `fixture:${workflow.metadata.id}:${node.id}`,
        nodeId: node.id,
        name: `${node.name ?? node.id} fixture`,
        input: { source: "electron-composer-fixture" },
        output: { status: "passed", receiptId: `receipt:fixture:${node.id}` },
        schemaHash: "fixture-schema-hash",
        nodeConfigHash: "fixture-node-config-hash",
        pinned: true,
        stale: false,
        validationStatus: "passed",
        validationMessage: "Fixture retained for replay.",
        createdAtMs: now(),
      }));
    },
    async saveWorkflowNodeFixture(path: string, nodeId: string, fixture: any) {
      postBridge("workflowCompositor.fixtureCapture", {
        path,
        nodeId,
        fixtureId: fixture?.id ?? `fixture:${nodeId}:${now()}`,
      });
      return this.listWorkflowNodeFixtures(path);
    },
    async dryRunWorkflowFunction(path: string, nodeId: string, input?: unknown) {
      return runResult(workflowForPath(path), path, `function:${nodeId}:${JSON.stringify(input ?? {})}`);
    },
    async dryRunWorkflowNode(path: string, nodeId: string, input?: unknown) {
      return runResult(workflowForPath(path), path, `node:${nodeId}:${JSON.stringify(input ?? {})}`);
    },
    async runWorkflowNode(path: string, nodeId: string, input?: unknown) {
      const result = runResult(workflowForPath(path), path, `node-run:${nodeId}:${JSON.stringify(input ?? {})}`);
      return rememberRun(path, result);
    },
    async validateWorkflowNodeConfig(path: string) {
      return passedValidation(workflowForPath(path));
    },
    async validateWorkflowBundle(path: string) {
      return passedValidation(workflowForPath(path));
    },
    async validateWorkflowExecutionReadiness(path: string) {
      if (hasDaemonRuntime()) {
        const workflow = workflowForPath(path);
        const catalog = await this.getGraphModelBindingCatalog();
        const result = passedValidation(workflow);
        return {
          ...result,
          warnings: [],
          schedulerLaneReadiness: [
            {
              id: "daemon-model-runtime",
              label: "Daemon model runtime",
              capabilityScope: "model.chat:*",
              proofCheckKey: "daemon-model-route",
              status: catalog.models.some((model: any) => model.status === "ready" || model.residency === "loaded")
                ? "ready"
                : "warning",
              detail:
                "Workflow model bindings are projected from the daemon model route catalog.",
              evidenceRefs: catalog.models.map((model: any) => model.routeId).filter(Boolean),
            },
          ],
        };
      }
      return passedValidation(workflowForPath(path));
    },
    async runWorkflowTests(path: string) {
      const workflow = workflowForPath(path);
      return {
        runId: `test-run:${workflow.metadata.id}:${now()}`,
        status: "passed",
        startedAtMs: now(),
        finishedAtMs: now() + 50,
        passed: workflow.tests?.length ?? 1,
        failed: 0,
        blocked: 0,
        skipped: 0,
        results: (workflow.tests ?? []).map((test: any) => ({
          testId: test.id,
          status: "passed",
          message: "Fixture test passed.",
          coveredNodeIds: test.targetNodeIds ?? [],
        })),
      };
    },
    async createWorkflowThread(path: string, input?: Record<string, unknown>) {
      return {
        id: `thread:${workflowForPath(path).metadata.id}:${now()}`,
        workflowPath: path,
        status: "queued",
        createdAtMs: now(),
        input,
      };
    },
    async loadWorkflowRuntimeThreadEvents(threadId: string) {
      if (hasDaemonRuntime()) {
        const projection = await daemonRequest("/api/v1/projections/model-mounting");
        const receipts = Array.isArray(projection?.receipts) ? projection.receipts.slice(-10) : [];
        return receipts.map((receipt: any, index: number) =>
          daemonThreadEvent(
            {
              id: `event:${threadId}:${receipt.id ?? index}`,
              kind: receipt.kind ?? "model_receipt",
              status: "completed",
              message: receipt.summary ?? receipt.kind ?? "Daemon model receipt",
              createdAtMs: Date.parse(receipt.createdAt ?? receipt.created_at ?? new Date().toISOString()) || now(),
              receiptRefs: [receipt.id].filter(Boolean),
              routeId: receipt.details?.routeId ?? null,
              modelId: receipt.details?.selectedModel ?? receipt.details?.modelId ?? null,
            },
            index,
            threadId,
            workflowScenarios[0].project.metadata?.id ?? "workflow",
          ),
        );
      }
      const workflow = workflowScenarios[0].project;
      return [
        runtimeThreadEvent(
          {
            id: `event:${threadId}:fixture`,
            kind: "fixture_projection",
            status: "completed",
            message:
              "Fixture runtime event projected by ioi-workbench; daemon stream API remains a blocker.",
          },
          0,
          threadId,
          workflow.metadata?.id ?? "workflow",
        ),
      ];
    },
    onWorkflowRuntimeThreadEvent() {
      return () => undefined;
    },
    async runWorkflowProject(path: string, options?: Record<string, unknown>) {
      if (hasDaemonRuntime()) {
        const result = await daemonRunResult(workflowForPath(path), path, options ?? {});
        postBridge("workflowCompositor.daemonRunProject", {
          path,
          runId: result.summary.id,
          receiptRefs: result.completionRequirements.flatMap((requirement: any) => requirement.evidenceRefs ?? []),
          replayRefs: result.runtimeThreadEvents.map((event: any) => event.id),
          daemonBacked: true,
          externalAction: false,
          options: options ?? null,
        });
        return rememberRun(path, result);
      }
      const result = runResult(workflowForPath(path), path, String(options?.source ?? "fixture-run"));
      postBridge("workflowCompositor.fixtureRunProject", {
        path,
        runId: result.summary.id,
        receiptRefs: [`receipt:${result.summary.id}`],
        replayRefs: [`replay:${result.summary.id}`],
        externalAction: false,
        options: options ?? null,
      });
      return rememberRun(path, result);
    },
    async listWorkflowCheckpoints(path: string, threadId: string) {
      return runResult(workflowForPath(path), path, `checkpoints:${threadId}`).checkpoints;
    },
    async loadWorkflowBindingManifest(path: string) {
      const workflow = workflowForPath(path);
      return {
        schemaVersion: "workflow.binding-manifest.v1",
        workflowId: workflow.metadata.id,
        generatedAtMs: now(),
        summary: {
          total: workflow.nodes.length,
          ready: workflow.nodes.length,
          blocked: 0,
          warning: 1,
        },
        bindings: workflow.nodes.map((node: any) => ({
          nodeId: node.id,
          status: "ready",
          receiptBehavior: "required",
          externalAction: false,
        })),
      };
    },
    async generateWorkflowBindingManifest(path: string) {
      return this.loadWorkflowBindingManifest(path);
    },
    async checkWorkflowBinding(path: string, nodeId: string) {
      return {
        nodeId,
        status: "ready",
        message: "Fixture binding is ready; no live external connector action.",
        issues: [],
        evidenceRefs: [`binding:${path}:${nodeId}`],
      };
    },
    async listWorkflowToolCatalog() {
      return [
        {
          toolRef: "fixture.receipt.projector",
          toolCapabilityRef: "tool-capability:fixture.receipt.projector",
          bindingKind: "workflow_tool",
          sideEffectClass: "read",
          mockBinding: true,
          requiresApproval: false,
          capabilityScope: ["workflow.receipts.fixture"],
        },
      ];
    },
    async listWorkflowConnectorCatalog() {
      return [
        {
          connectorRef: "mock.connector.fixture",
          connectorCapabilityRef: "connector-capability:mock.fixture",
          operation: "dry_run_only",
          sideEffectClass: "read",
          mockBinding: true,
          requiresApproval: false,
          credentialReadiness: { status: "ready" },
          receiptBehavior: { receiptRequired: true },
          policyPosture: { status: "ready" },
          capabilityScope: ["connector.fixture.read"],
        },
      ];
    },
    async executeWorkflowRuntimeControlRequest(request: any) {
      postBridge("workflowCompositor.fixtureRuntimeControlRequest", {
        request,
        externalAction: false,
      });
      return {
        status: "accepted",
        receiptId: `receipt:runtime-control:${now()}`,
        externalAction: false,
      };
    },
    async exportWorkflowPackage(path: string) {
      const workflow = workflowForPath(path);
      return {
        packageId: `package:${workflow.metadata.id}`,
        exportedAtMs: now(),
        workflow,
        tests: workflow.tests ?? [],
        fixtures: await this.listWorkflowNodeFixtures(path),
        evidenceRefs: [`package:${workflow.metadata.id}:evidence`],
      };
    },
    async importWorkflowPackage(request: any) {
      const scenario = activeScenario();
      const path = request?.targetPath ?? scenario.project.metadata.gitLocation;
      const workflow = clone(scenario.project);
      projects.set(path, workflow);
      return {
        workflowPath: path,
        testsPath: `${path}.tests.json`,
        proposalsDir: ".agents/proposals",
        workflow,
        tests: workflow.tests ?? [],
        proposals: [],
        runs: [],
      };
    },
    async createWorkflowProposal(request: any) {
      const scenario = activeScenario();
      return {
        workflowPath: scenario.project.metadata.gitLocation,
        testsPath: `${scenario.project.metadata.gitLocation}.tests.json`,
        proposalsDir: ".agents/proposals",
        workflow: clone(scenario.project),
        tests: scenario.project.tests ?? [],
        proposals: [
          {
            id: `proposal:${now()}`,
            title: request?.title ?? "Fixture proposal",
            summary: request?.summary ?? "Proposal-only fixture; no file mutation.",
            status: "open",
            createdAtMs: now(),
            boundedTargets: request?.boundedTargets ?? ["ioi-workbench"],
            codeDiff: request?.codeDiff ?? "diff --git a/fixture b/fixture\n+fixture proposal only\n",
          },
        ],
        runs: [],
      };
    },
    async applyWorkflowProposal() {
      postBridge("workflowCompositor.fixtureProposalApplyBlocked", {
        reason: "Proposal apply must go through daemon receipts; blocked in fixture adapter.",
        externalAction: false,
      });
      throw new Error("Proposal apply is blocked in the Electron parity fixture.");
    },
    async resumeWorkflowRun(path: string) {
      const result = runResult(workflowForPath(path), path, "fixture-resume");
      return rememberRun(path, result);
    },
    async getAgents() {
      return [
        {
          id: "agent:fixture",
          name: "Fixture Worker",
          description: "Projection-only worker used for Electron composer parity.",
          model: "fixture.reasoning.model",
        },
      ];
    },
    async getFleetState() {
      return {
        zones: [
          {
            id: "zone:local-fixture",
            name: "Local fixture",
            type: "local",
            capacity: { used: 1, total: 1, unit: "worker" },
            costPerHour: 0,
          },
        ],
        containers: [
          {
            id: "container:fixture-worker",
            name: "Fixture worker",
            image: "ioi/fixture-worker:none",
            zoneId: "zone:local-fixture",
            status: "running",
            metrics: { cpu: 0, ram: 32 },
            uptime: "fixture",
          },
        ],
      };
    },
    async getRuntimeCatalogEntries() {
      return [
        {
          id: "runtime:daemon-fixture-adapter",
          name: "Daemon fixture adapter",
          description: "Typed requests and fixture projections until daemon composer APIs land.",
          ownerLabel: "IOI daemon",
          entryKind: "fixture_runtime",
          runtimeNotes: "No external connector action. No durable extension-host runtime.",
          statusLabel: "projection",
        },
      ];
    },
    async stageRuntimeCatalogEntry(entryId: string, notes?: string) {
      postBridge("workflowCompositor.fixtureStageRuntimeCatalogEntry", {
        entryId,
        notes,
      });
    },
  };
}
