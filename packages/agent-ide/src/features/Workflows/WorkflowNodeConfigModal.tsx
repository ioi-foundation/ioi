import { useEffect, useRef, useState } from "react";
import type {
  Node,
  WorkflowFieldMapping,
  WorkflowNodeFixture,
  WorkflowNodeKind,
  WorkflowNodeRun,
  WorkflowProject,
  WorkflowRunResult,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowValidationResult,
} from "../../types/graph";
import { actionKindForWorkflowNodeType } from "../../runtime/runtime-projection-adapter";
import { slugify } from "../../runtime/workflow-defaults";
import {
  workflowFunctionDryRunView,
} from "../../runtime/workflow-composer-model";
import { WorkflowNodeBindingEditor } from "./WorkflowNodeBindingEditor";
import { WorkflowNodeDetailGrid } from "./WorkflowNodeDetailGrid";
import type {
  WorkflowCompatibleNodeHint,
  WorkflowNodeConfigSectionId,
  WorkflowNodeConnectionReference,
  WorkflowUpstreamReference,
} from "./WorkflowNodeConfigTypes";
import { WORKFLOW_NODE_DETAIL_SECTIONS } from "./WorkflowNodeConfigTypes";
import {
  workflowNodeDeclaredInputSchema,
  workflowNodeDeclaredOutputSchema,
  workflowSchemaFieldReferences,
  type WorkflowSchemaFieldReference,
} from "../../runtime/workflow-schema";
import {
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeRunChildLineage,
  workflowSelectedNodeBindingSummary,
} from "../../runtime/workflow-rail-model";

export type {
  WorkflowCompatibleNodeHint,
  WorkflowUpstreamReference,
} from "./WorkflowNodeConfigTypes";

type WorkflowNodeConfigSectionStatus = "ready" | "attention" | "empty";

interface WorkflowNodeConfigSectionSummary {
  status: WorkflowNodeConfigSectionStatus;
  detail: string;
}

const CONFIG_SECTION_IDS = new Set(
  WORKFLOW_NODE_DETAIL_SECTIONS.map((section) => section.id),
);

function workflowConfigSectionForNodeIssue(
  issue: { configSection?: string; code: string },
): WorkflowNodeConfigSectionId {
  if (
    issue.configSection &&
    CONFIG_SECTION_IDS.has(issue.configSection as WorkflowNodeConfigSectionId)
  ) {
    return issue.configSection as WorkflowNodeConfigSectionId;
  }
  if (issue.code.includes("schema")) return "schema";
  if (issue.code.includes("fixture")) return "fixtures";
  if (issue.code.includes("mapping") || issue.code.includes("expression"))
    return "mapping";
  if (issue.code.includes("connection") || issue.code.includes("edge"))
    return "connections";
  if (issue.code.includes("policy") || issue.code.includes("approval"))
    return "policy";
  if (
    issue.code.includes("binding") ||
    issue.code.includes("credential") ||
    issue.code.includes("subgraph") ||
    issue.code.includes("tool")
  ) {
    return "bindings";
  }
  if (issue.code.includes("test") || issue.code.includes("evaluation"))
    return "tests";
  if (issue.code.includes("output")) return "outputs";
  return "settings";
}

export function WorkflowNodeConfigModal({
  node,
  workflow,
  dryRunResult,
  fixtures,
  selectedNodeRun,
  upstreamReferences,
  compatibleNodeHints,
  tests,
  testResult,
  validationResult,
  readinessResult,
  initialSection = "settings",
  onClose,
  onUpdate,
  onDryRun,
  onInspectNode,
  onCaptureFixture,
  onImportFixture,
  onPinFixture,
  onDryRunFixture,
}: {
  node: Node;
  workflow: WorkflowProject;
  dryRunResult: WorkflowRunResult | null;
  fixtures: WorkflowNodeFixture[];
  selectedNodeRun: WorkflowNodeRun | null;
  upstreamReferences: WorkflowUpstreamReference[];
  compatibleNodeHints: WorkflowCompatibleNodeHint[];
  tests: WorkflowTestCase[];
  testResult: WorkflowTestRunResult | null;
  validationResult: WorkflowValidationResult | null;
  readinessResult: WorkflowValidationResult | null;
  initialSection?: WorkflowNodeConfigSectionId;
  onClose: () => void;
  onUpdate: (updates: Partial<Node>) => void;
  onDryRun: () => void;
  onInspectNode: (nodeId: string) => void;
  onCaptureFixture: () => void;
  onImportFixture: (rawText: string) => void;
  onPinFixture: (fixture: WorkflowNodeFixture) => void;
  onDryRunFixture: (fixture?: WorkflowNodeFixture) => void;
}) {
  const logic = node.config?.logic ?? {};
  const law = node.config?.law ?? {};
  const viewMacro = logic.viewMacro;
  const ports = node.ports ?? [];
  const [activeSection, setActiveSection] =
    useState<WorkflowNodeConfigSectionId>(initialSection);
  const configDialogRef = useRef<HTMLFormElement | null>(null);
  const staleFixtureCount = fixtures.filter((fixture) => fixture.stale).length;
  const inputPorts = ports.filter((port) => port.direction === "input");
  const outputPorts = ports.filter((port) => port.direction === "output");
  const nodeById = new Map(
    workflow.nodes.map((workflowNode) => [workflowNode.id, workflowNode]),
  );
  const macroRoleRank = (role: string) => {
    const roleOrder = ["input", "model", "memory", "tool", "parser", "decision", "gate", "output"];
    const index = roleOrder.indexOf(role);
    return index === -1 ? roleOrder.length : index;
  };
  const macroPeerNodes = viewMacro?.macroId
    ? workflow.nodes
        .filter((workflowNode) => workflowNode.config?.logic.viewMacro?.macroId === viewMacro.macroId)
        .sort((left, right) => {
          const leftRole = left.config?.logic.viewMacro?.role ?? "";
          const rightRole = right.config?.logic.viewMacro?.role ?? "";
          return macroRoleRank(leftRole) - macroRoleRank(rightRole);
        })
    : [];
  const incomingConnections: WorkflowNodeConnectionReference[] = workflow.edges
    .filter((edge) => edge.to === node.id)
    .map((edge) => {
      const peerNode = nodeById.get(edge.from);
      const localPort = inputPorts.find((port) => port.id === edge.toPort);
      const peerPort = peerNode?.ports?.find(
        (port) => port.id === edge.fromPort,
      );
      return {
        edgeId: edge.id,
        peerNodeId: edge.from,
        peerNodeName: peerNode?.name ?? edge.from,
        peerNodeType: peerNode?.type ?? "unknown",
        localPortId: edge.toPort,
        peerPortId: edge.fromPort,
        connectionClass:
          edge.connectionClass ??
          localPort?.connectionClass ??
          peerPort?.connectionClass ??
          "data",
        label: edge.label,
      };
    });
  const outgoingConnections: WorkflowNodeConnectionReference[] = workflow.edges
    .filter((edge) => edge.from === node.id)
    .map((edge) => {
      const peerNode = nodeById.get(edge.to);
      const localPort = outputPorts.find((port) => port.id === edge.fromPort);
      const peerPort = peerNode?.ports?.find((port) => port.id === edge.toPort);
      return {
        edgeId: edge.id,
        peerNodeId: edge.to,
        peerNodeName: peerNode?.name ?? edge.to,
        peerNodeType: peerNode?.type ?? "unknown",
        localPortId: edge.fromPort,
        peerPortId: edge.toPort,
        connectionClass:
          edge.connectionClass ??
          localPort?.connectionClass ??
          peerPort?.connectionClass ??
          "data",
        label: edge.label,
      };
    });
  const testResultById = new Map(
    (testResult?.results ?? []).map((result) => [result.testId, result]),
  );
  const relatedTests = tests.filter((test) =>
    test.targetNodeIds.includes(node.id),
  );
  const relatedTestStatusCounts = relatedTests.reduce<Record<string, number>>(
    (counts, test) => {
      const status =
        testResultById.get(test.id)?.status ?? test.status ?? "idle";
      counts[status] = (counts[status] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const nodeIssues = [
    ...(validationResult?.errors ?? []),
    ...(validationResult?.warnings ?? []),
    ...(validationResult?.missingConfig ?? []),
    ...(validationResult?.connectorBindingIssues ?? []),
    ...(validationResult?.executionReadinessIssues ?? []),
    ...(validationResult?.verificationIssues ?? []),
    ...(readinessResult?.errors ?? []),
    ...(readinessResult?.warnings ?? []),
    ...(readinessResult?.missingConfig ?? []),
    ...(readinessResult?.connectorBindingIssues ?? []),
    ...(readinessResult?.executionReadinessIssues ?? []),
    ...(readinessResult?.verificationIssues ?? []),
  ].filter((issue) => issue.nodeId === node.id);
  const asRecord = (value: unknown): Record<string, unknown> =>
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const asStringRecord = (value: unknown): Record<string, string> => {
    const record = asRecord(value);
    return Object.fromEntries(
      Object.entries(record).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    );
  };
  const asFieldMappingRecord = (
    value: unknown,
  ): Record<string, WorkflowFieldMapping> => {
    const record = asRecord(value);
    return Object.fromEntries(
      Object.entries(record).filter(
        (entry): entry is [string, WorkflowFieldMapping] => {
          const item = entry[1];
          return Boolean(
            item &&
            typeof item === "object" &&
            !Array.isArray(item) &&
            typeof (item as WorkflowFieldMapping).source === "string" &&
            typeof (item as WorkflowFieldMapping).path === "string",
          );
        },
      ),
    );
  };
  const dryRunView = workflowFunctionDryRunView(dryRunResult);
  const declaredInputSchema = workflowNodeDeclaredInputSchema(node);
  const declaredOutputSchema = workflowNodeDeclaredOutputSchema(
    node,
    selectedNodeRun?.output,
  );
  const inputSchemaFields = workflowSchemaFieldReferences(declaredInputSchema);
  const outputSchemaFields = workflowSchemaFieldReferences(
    declaredOutputSchema,
    selectedNodeRun?.output,
  );
  const modelAttachmentCounts = {
    model: incomingConnections.filter(
      (connection) => connection.connectionClass === "model",
    ).length,
    memory: incomingConnections.filter(
      (connection) => connection.connectionClass === "memory",
    ).length,
    tool: incomingConnections.filter(
      (connection) => connection.connectionClass === "tool",
    ).length,
    parser: incomingConnections.filter(
      (connection) => connection.connectionClass === "parser",
    ).length,
  };
  const workflowToolLineage = workflowNodeRunChildLineage(selectedNodeRun);
  const updateLogic = (nextLogic: typeof logic) =>
    onUpdate({ config: { kind: node.type as any, logic: nextLogic, law } });
  const applyUpstreamReference = (reference: WorkflowUpstreamReference) => {
    if (node.type === "model_call") {
      updateLogic({
        ...logic,
        prompt:
          `${String(logic.prompt ?? "").trim()}\n${reference.expression}`.trim(),
      });
      return;
    }
    if (node.type === "function") {
      updateLogic({
        ...logic,
        testInput: { upstream: reference.expression },
        inputMapping: {
          ...asRecord(logic.inputMapping),
          input: reference.expression,
        },
        functionBinding: {
          ...asRecord(logic.functionBinding),
          language:
            logic.functionBinding?.language === "typescript" ||
            logic.language === "typescript"
              ? "typescript"
              : "javascript",
          code: String(
            logic.functionBinding?.code ??
              logic.code ??
              "return { result: input };",
          ),
          inputSchema: logic.functionBinding?.inputSchema ??
            logic.inputSchema ?? { type: "object" },
          outputSchema: logic.functionBinding?.outputSchema ??
            logic.outputSchema ?? { type: "object" },
          sandboxPolicy: logic.functionBinding?.sandboxPolicy ??
            law.sandboxPolicy ?? {
              timeoutMs: 1000,
              memoryMb: 64,
              outputLimitBytes: 32768,
              permissions: [],
            },
          testInput: { upstream: reference.expression },
        },
      });
      return;
    }
    updateLogic({
      ...logic,
      inputMapping: {
        ...asRecord(logic.inputMapping),
        input: reference.expression,
      },
    });
  };
  const applyUpstreamFieldReference = (
    reference: WorkflowUpstreamReference,
    field: WorkflowSchemaFieldReference,
  ) => {
    const fieldKey = slugify(field.path).replace(/-/g, "_");
    const fieldMapping = {
      source: reference.expression,
      path: field.path,
      type: field.type,
    };
    if (node.type === "model_call") {
      updateLogic({
        ...logic,
        prompt:
          `${String(logic.prompt ?? "").trim()}\n${reference.expression} field ${field.path}`.trim(),
      });
      return;
    }
    if (node.type === "function") {
      updateLogic({
        ...logic,
        testInput: {
          ...asRecord(logic.testInput),
          [fieldKey]: fieldMapping,
        },
        inputMapping: {
          ...asStringRecord(logic.inputMapping),
          [fieldKey]: reference.expression,
        },
        fieldMappings: {
          ...asFieldMappingRecord(logic.fieldMappings),
          [fieldKey]: fieldMapping,
        },
        functionBinding: {
          ...asRecord(logic.functionBinding),
          language:
            logic.functionBinding?.language === "typescript" ||
            logic.language === "typescript"
              ? "typescript"
              : "javascript",
          code: String(
            logic.functionBinding?.code ??
              logic.code ??
              "return { result: input };",
          ),
          inputSchema: logic.functionBinding?.inputSchema ??
            logic.inputSchema ?? { type: "object" },
          outputSchema: logic.functionBinding?.outputSchema ??
            logic.outputSchema ?? { type: "object" },
          sandboxPolicy: logic.functionBinding?.sandboxPolicy ??
            law.sandboxPolicy ?? {
              timeoutMs: 1000,
              memoryMb: 64,
              outputLimitBytes: 32768,
              permissions: [],
            },
          testInput: {
            ...asRecord(logic.functionBinding?.testInput ?? logic.testInput),
            [fieldKey]: fieldMapping,
          },
        },
      });
      return;
    }
    updateLogic({
      ...logic,
      inputMapping: {
        ...asStringRecord(logic.inputMapping),
        [fieldKey]: reference.expression,
      },
      fieldMappings: {
        ...asFieldMappingRecord(logic.fieldMappings),
        [fieldKey]: fieldMapping,
      },
    });
  };
  const bindingSummary = workflowSelectedNodeBindingSummary(node, logic);
  const bindingReady = (() => {
    if (node.type === "model_call") {
      return (
        String(logic.modelRef ?? "").trim().length > 0 ||
        modelAttachmentCounts.model > 0
      );
    }
    if (node.type === "model_binding") {
      return (
        String(logic.modelBinding?.modelRef ?? logic.modelRef ?? "").trim()
          .length > 0
      );
    }
    if (node.type === "adapter") {
      return (
        String(logic.connectorBinding?.connectorRef ?? "").trim().length > 0
      );
    }
    if (node.type === "plugin_tool") {
      return logic.toolBinding?.bindingKind === "workflow_tool"
        ? String(logic.toolBinding?.workflowTool?.workflowPath ?? "").trim()
            .length > 0
        : String(logic.toolBinding?.toolRef ?? "").trim().length > 0;
    }
    if (node.type === "subgraph") {
      return String(logic.subgraphRef?.workflowPath ?? "").trim().length > 0;
    }
    if (node.type === "function") {
      return (
        String(logic.functionBinding?.code ?? logic.code ?? "").trim().length >
        0
      );
    }
    if (node.type === "proposal") {
      return (logic.proposalAction?.boundedTargets ?? []).length > 0;
    }
    return true;
  })();
  const contextualPolicyActive = Boolean(
    law.requireHumanGate ||
    law.sandboxPolicy ||
    logic.modelBinding?.requiresApproval ||
    logic.functionBinding?.sandboxPolicy ||
    logic.connectorBinding?.requiresApproval ||
    logic.toolBinding?.requiresApproval ||
    logic.deliveryTarget?.targetKind === "connector_write" ||
    logic.deliveryTarget?.targetKind === "deploy",
  );
  const sectionSummaries: Record<
    WorkflowNodeConfigSectionId,
    WorkflowNodeConfigSectionSummary
  > = {
    settings: {
      status: node.name.trim().length > 0 ? "ready" : "attention",
      detail: node.name.trim().length > 0 ? node.type : "Name required",
    },
    inputs: {
      status:
        inputPorts.length > 0 || upstreamReferences.length > 0
          ? "ready"
          : "empty",
      detail: `${inputPorts.length} port${inputPorts.length === 1 ? "" : "s"}`,
    },
    mapping: {
      status:
        Object.keys(asStringRecord(logic.inputMapping)).length > 0 ||
        Object.keys(asFieldMappingRecord(logic.fieldMappings)).length > 0
          ? "ready"
          : upstreamReferences.length > 0
            ? "attention"
            : "empty",
      detail:
        Object.keys(asFieldMappingRecord(logic.fieldMappings)).length > 0
          ? `${Object.keys(asFieldMappingRecord(logic.fieldMappings)).length} fields`
          : upstreamReferences.length > 0
            ? "Available"
            : "None",
    },
    connections: {
      status:
        incomingConnections.length > 0 || outgoingConnections.length > 0
          ? "ready"
          : "empty",
      detail: `${incomingConnections.length} in / ${outgoingConnections.length} out`,
    },
    outputs: {
      status: outputPorts.length > 0 ? "ready" : "empty",
      detail: `${outputPorts.length} port${outputPorts.length === 1 ? "" : "s"}`,
    },
    schema: {
      status:
        upstreamReferences.length > 0 ||
        node.type === "function" ||
        node.type === "output"
          ? "ready"
          : "empty",
      detail:
        upstreamReferences.length > 0
          ? `${upstreamReferences.length} upstream`
          : "Local",
    },
    bindings: {
      status: bindingReady ? "ready" : "attention",
      detail:
        bindingSummary.length > 0 ? bindingSummary[0].value : "Needs setup",
    },
    policy: {
      status: contextualPolicyActive ? "attention" : "empty",
      detail: contextualPolicyActive ? "Contextual" : "None",
    },
    fixtures: {
      status:
        staleFixtureCount > 0
          ? "attention"
          : fixtures.length > 0
            ? "ready"
            : "empty",
      detail:
        staleFixtureCount > 0
          ? `${staleFixtureCount} stale`
          : `${fixtures.length} saved`,
    },
    "run-data": {
      status: selectedNodeRun ? "ready" : "empty",
      detail: selectedNodeRun?.status ?? "No run",
    },
    tests: {
      status:
        node.type === "test_assertion" || relatedTests.length > 0
          ? "ready"
          : "empty",
      detail:
        node.type === "test_assertion"
          ? "Runtime assertion"
          : `${relatedTests.length} sidecar`,
    },
    advanced: {
      status: "ready",
      detail: actionKindForWorkflowNodeType(node.type as WorkflowNodeKind),
    },
  };
  const scrollToConfigSection = (sectionId: WorkflowNodeConfigSectionId) => {
    setActiveSection(sectionId);
    const target = configDialogRef.current?.querySelector<HTMLElement>(
      `[data-config-section="${sectionId}"]`,
    );
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
    target?.focus({ preventScroll: true });
  };
  useEffect(() => {
    setActiveSection(initialSection);
    requestAnimationFrame(() => {
      const target = configDialogRef.current?.querySelector<HTMLElement>(
        `[data-config-section="${initialSection}"]`,
      );
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [initialSection, node.id]);
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);
  const selectedFixture = fixtures.find((fixture) => fixture.pinned) ?? fixtures[0];
  const previewText = (value: unknown) => {
    if (value === undefined) return "Not captured";
    const text =
      typeof value === "string" ? value : JSON.stringify(value ?? null, null, 2);
    return text.length > 420 ? `${text.slice(0, 420)}...` : text;
  };
  const latestInput = selectedNodeRun?.input ?? selectedFixture?.input;
  const latestOutput = selectedNodeRun?.output ?? selectedFixture?.output;
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-node-config-modal"
    >
      <form
        ref={configDialogRef}
        className="workflow-create-dialog workflow-config-dialog"
        onSubmit={(event) => {
          event.preventDefault();
          onClose();
        }}
      >
        <header>
          <h3>Node configuration</h3>
          <button type="button" onClick={onClose}>
            Close
          </button>
        </header>
        {nodeIssues.length > 0 ? (
          <section
            className="workflow-config-repair-strip"
            data-testid="workflow-node-repair-strip"
            aria-label="Node issues to resolve"
          >
            <header>
              <strong>Needs attention</strong>
              <span>
                {nodeIssues.length} issue{nodeIssues.length === 1 ? "" : "s"} on
                this node
              </span>
            </header>
            <div>
              {nodeIssues.slice(0, 4).map((issue, index) => {
                const sectionId = workflowConfigSectionForNodeIssue(issue);
                return (
                  <button
                    key={`${issue.code}-${issue.nodeId ?? "node"}-${index}`}
                    type="button"
                    data-testid={`workflow-node-repair-action-${index}`}
                    onClick={() => scrollToConfigSection(sectionId)}
                  >
                    <strong>{workflowIssueTitle(issue)}</strong>
                    <span>{workflowIssueActionLabel(issue)}</span>
                    <small>{sectionId}</small>
                  </button>
                );
              })}
            </div>
          </section>
        ) : null}
        <section
          className="workflow-node-detail-workbench"
          data-testid="workflow-node-detail-workbench"
        >
          <article data-testid="workflow-node-detail-input-zone">
            <header>
              <strong>Input</strong>
              <span>
                {selectedNodeRun ? "latest run" : selectedFixture ? "fixture" : "empty"}
              </span>
            </header>
            <pre>{previewText(latestInput)}</pre>
            <footer>
              <button type="button" onClick={() => scrollToConfigSection("inputs")}>
                Inspect input
              </button>
              <button type="button" onClick={onCaptureFixture}>
                Capture fixture
              </button>
            </footer>
          </article>
          <article data-testid="workflow-node-detail-config-zone">
            <header>
              <strong>Config</strong>
              <span data-section-status={sectionSummaries.bindings.status}>
                {sectionSummaries.bindings.detail}
              </span>
            </header>
            <dl>
              <div>
                <dt>Kind</dt>
                <dd>{node.type}</dd>
              </div>
              <div>
                <dt>Policy</dt>
                <dd>{sectionSummaries.policy.detail}</dd>
              </div>
              <div>
                <dt>Fixtures</dt>
                <dd>{sectionSummaries.fixtures.detail}</dd>
              </div>
            </dl>
            <footer>
              <button type="button" onClick={() => scrollToConfigSection("bindings")}>
                Configure
              </button>
              <button type="button" onClick={() => scrollToConfigSection("schema")}>
                Schema
              </button>
              {nodeIssues.length > 0 ? (
                <button
                  type="button"
                  onClick={() =>
                    scrollToConfigSection(
                      workflowConfigSectionForNodeIssue(nodeIssues[0]!),
                    )
                  }
                >
                  Resolve blockers
                </button>
              ) : null}
            </footer>
          </article>
          <article data-testid="workflow-node-detail-output-zone">
            <header>
              <strong>Output</strong>
              <span>{dryRunView?.status ?? selectedNodeRun?.status ?? "not run"}</span>
            </header>
            <pre>{previewText(dryRunView?.resultPayload ?? latestOutput)}</pre>
            <footer>
              <button type="button" onClick={onDryRun}>
                Dry run
              </button>
              <button type="button" onClick={() => scrollToConfigSection("outputs")}>
                Inspect output
              </button>
              <button type="button" onClick={() => scrollToConfigSection("tests")}>
                Add test
              </button>
            </footer>
          </article>
        </section>
        <nav
          className="workflow-config-sections"
          aria-label="Node detail sections"
        >
          {WORKFLOW_NODE_DETAIL_SECTIONS.map((section) => (
            <button
              key={section.id}
              type="button"
              title={`${section.label} section`}
              className={activeSection === section.id ? "is-active" : ""}
              data-testid={`workflow-config-nav-${section.id}`}
              data-section-status={sectionSummaries[section.id].status}
              onClick={() => scrollToConfigSection(section.id)}
            >
              <span>{section.label}</span>
              <small>{sectionSummaries[section.id].detail}</small>
            </button>
          ))}
        </nav>
        <section
          className="workflow-config-section-block"
          data-config-section="settings"
          data-testid="workflow-config-section-settings"
          tabIndex={-1}
        >
          <header>
            <div>
              <h4>Settings</h4>
              <p>Node identity, metric, and typed port posture.</p>
            </div>
            <span data-section-status={sectionSummaries.settings.status}>
              {sectionSummaries.settings.detail}
            </span>
          </header>
          <section
            className="workflow-config-port-summary"
            data-testid="workflow-node-port-summary"
          >
            <strong>Typed ports</strong>
            <div>
              {ports.length > 0 ? (
                ports.map((port) => (
                  <span
                    key={`${port.direction}-${port.id}`}
                    data-connection-class={port.connectionClass}
                  >
                    {port.direction === "input" ? "In" : "Out"} · {port.label} ·{" "}
                    {port.connectionClass}
                  </span>
                ))
              ) : (
                <span>No typed ports configured.</span>
              )}
            </div>
          </section>
          <label>
            Name
            <input
              data-testid="workflow-node-name"
              value={node.name}
              onChange={(event) => onUpdate({ name: event.target.value })}
            />
          </label>
          <label>
            Metric
            <input
              data-testid="workflow-node-metric"
              value={String(node.metricValue ?? "")}
              onChange={(event) =>
                onUpdate({ metricValue: event.target.value })
              }
            />
          </label>
        </section>
        <section
          className="workflow-config-section-block"
          data-config-section="connections"
          data-testid="workflow-node-config-connections"
          tabIndex={-1}
        >
          <header>
            <div>
              <h4>Connections</h4>
              <p>
                Typed paths into and out of this node, plus safe next steps from
                its output ports.
              </p>
            </div>
            <span data-section-status={sectionSummaries.connections.status}>
              {sectionSummaries.connections.detail}
            </span>
          </header>
          <div className="workflow-node-config-connection-grid">
            <div data-testid="workflow-node-config-incoming-edges">
              <strong>Incoming</strong>
              {incomingConnections.length > 0 ? (
                incomingConnections.map((connection) => (
                  <div
                    key={connection.edgeId}
                    className="workflow-node-config-connection-row"
                  >
                    <div>
                      <span data-connection-class={connection.connectionClass}>
                        {connection.connectionClass}
                      </span>
                      <strong>{connection.peerNodeName}</strong>
                      <small>{connection.peerNodeType}</small>
                    </div>
                    <code>
                      {connection.peerPortId} {"->"} {connection.localPortId}
                    </code>
                  </div>
                ))
              ) : (
                <p>No incoming connections.</p>
              )}
            </div>
            <div data-testid="workflow-node-config-outgoing-edges">
              <strong>Outgoing</strong>
              {outgoingConnections.length > 0 ? (
                outgoingConnections.map((connection) => (
                  <div
                    key={connection.edgeId}
                    className="workflow-node-config-connection-row"
                  >
                    <div>
                      <span data-connection-class={connection.connectionClass}>
                        {connection.connectionClass}
                      </span>
                      <strong>{connection.peerNodeName}</strong>
                      <small>{connection.peerNodeType}</small>
                    </div>
                    <code>
                      {connection.localPortId} {"->"} {connection.peerPortId}
                    </code>
                  </div>
                ))
              ) : (
                <p>No outgoing connections.</p>
              )}
            </div>
          </div>
          <div
            className="workflow-node-config-compatible-next"
            data-testid="workflow-node-config-compatible-next"
          >
            <strong>Compatible primitives</strong>
            {compatibleNodeHints.length > 0 ? (
              compatibleNodeHints.slice(0, 6).map((hint) => (
                <span
                  key={`${hint.direction}-${hint.definition.type}-${hint.sourcePort.id}-${hint.targetPort.id}`}
                  data-connection-class={hint.connectionClass}
                  data-connection-direction={hint.direction}
                  data-recommended={hint.recommended ? "true" : "false"}
                >
                  {hint.definition.label} ·{" "}
                  {hint.direction === "attachment" ? "attach" : "after"} ·{" "}
                  {hint.sourcePort.label} {"->"} {hint.targetPort.label}
                </span>
              ))
            ) : (
              <p>
                No compatible attached or downstream primitives from this node's
                current ports.
              </p>
            )}
          </div>
        </section>
        <WorkflowNodeDetailGrid
          node={node}
          inputPorts={inputPorts}
          outputPorts={outputPorts}
          inputSchemaFields={inputSchemaFields}
          outputSchemaFields={outputSchemaFields}
          upstreamReferences={upstreamReferences}
          selectedNodeRun={selectedNodeRun}
          workflowToolLineage={workflowToolLineage}
          macroPeerNodes={macroPeerNodes}
          nodeIssues={nodeIssues}
          staleFixtureCount={staleFixtureCount}
          fixtures={fixtures}
          onApplyUpstreamReference={applyUpstreamReference}
          onApplyUpstreamFieldReference={applyUpstreamFieldReference}
          onInspectNode={onInspectNode}
          onCaptureFixture={onCaptureFixture}
          onImportFixture={onImportFixture}
          onPinFixture={onPinFixture}
          onDryRunFixture={onDryRunFixture}
        />
        <section
          className="workflow-config-section-block"
          data-config-section="policy"
          data-testid="workflow-config-section-policy"
          tabIndex={-1}
        >
          <header>
            <div>
              <h4>Policy</h4>
              <p>
                Only privileged or sandboxed behavior needs explicit controls.
              </p>
            </div>
            <span data-section-status={sectionSummaries.policy.status}>
              {sectionSummaries.policy.detail}
            </span>
          </header>
          <dl className="workflow-config-summary-list">
            <div>
              <dt>Human approval</dt>
              <dd>
                {law.requireHumanGate ||
                logic.connectorBinding?.requiresApproval ||
                logic.toolBinding?.requiresApproval
                  ? "Required"
                  : "Not required"}
              </dd>
            </div>
            <div>
              <dt>Sandbox</dt>
              <dd>
                {logic.functionBinding?.sandboxPolicy || law.sandboxPolicy
                  ? "Configured"
                  : "Not used"}
              </dd>
            </div>
            <div>
              <dt>Side effect</dt>
              <dd>
                {String(
                  logic.connectorBinding?.sideEffectClass ??
                    logic.toolBinding?.sideEffectClass ??
                    asRecord(logic).sideEffectClass ??
                    "none",
                )}
              </dd>
            </div>
          </dl>
        </section>
        <WorkflowNodeBindingEditor
          node={node}
          logic={logic}
          law={law}
          sectionStatus={sectionSummaries.bindings.status}
          sectionDetail={sectionSummaries.bindings.detail}
          modelAttachmentCounts={modelAttachmentCounts}
          dryRunView={dryRunView}
          onUpdate={onUpdate}
          updateLogic={updateLogic}
          onDryRun={onDryRun}
        />
        <section
          className="workflow-config-section-block"
          data-config-section="tests"
          data-testid="workflow-config-section-tests"
          tabIndex={-1}
        >
          <header>
            <div>
              <h4>Tests</h4>
              <p>
                Runtime assertions live on the canvas; broader coverage lives in
                workflow test sidecars.
              </p>
            </div>
            <span data-section-status={sectionSummaries.tests.status}>
              {sectionSummaries.tests.detail}
            </span>
          </header>
          {node.type === "test_assertion" ? (
            <p>This assertion executes as part of the workflow run.</p>
          ) : (
            <p>
              Use the Unit Tests rail or Add test action to attach sidecar tests
              to this node or subgraph.
            </p>
          )}
          <dl
            className="workflow-node-test-summary"
            data-testid="workflow-node-test-summary"
          >
            <div>
              <dt>Covered tests</dt>
              <dd>{relatedTests.length}</dd>
            </div>
            <div>
              <dt>Passed</dt>
              <dd>{relatedTestStatusCounts.passed ?? 0}</dd>
            </div>
            <div>
              <dt>Failed</dt>
              <dd>{relatedTestStatusCounts.failed ?? 0}</dd>
            </div>
            <div>
              <dt>Blocked</dt>
              <dd>{relatedTestStatusCounts.blocked ?? 0}</dd>
            </div>
          </dl>
          <div
            className="workflow-node-config-tests"
            data-testid="workflow-node-config-related-tests"
          >
            {relatedTests.length > 0 ? (
              relatedTests.map((test) => {
                const latestResult = testResultById.get(test.id);
                const status = latestResult?.status ?? test.status ?? "idle";
                return (
                  <article
                    key={test.id}
                    className={`workflow-test-row workflow-node-test-card is-${status}`}
                    data-testid="workflow-node-related-test-row"
                  >
                    <div>
                      <strong>{test.name}</strong>
                      <span>
                        {latestResult?.message ||
                          test.lastMessage ||
                          `${test.assertion.kind} assertion`}
                      </span>
                    </div>
                    <small data-testid="workflow-node-related-test-status">
                      {status}
                    </small>
                    <code>
                      {test.assertion.kind} · {test.targetNodeIds.length} target
                      {test.targetNodeIds.length === 1 ? "" : "s"}
                    </code>
                  </article>
                );
              })
            ) : (
              <article className="workflow-output-row">
                <strong>No sidecar tests</strong>
                <span>
                  This node is not currently covered by a workflow unit test.
                </span>
              </article>
            )}
          </div>
        </section>
        <section
          className="workflow-config-section-block"
          data-config-section="advanced"
          data-testid="workflow-config-section-advanced"
          tabIndex={-1}
        >
          <header>
            <div>
              <h4>Advanced</h4>
              <p>Stable runtime identity and executor mapping.</p>
            </div>
            <span data-section-status={sectionSummaries.advanced.status}>
              {sectionSummaries.advanced.detail}
            </span>
          </header>
          <pre data-testid="workflow-node-advanced-summary">
            {JSON.stringify(
              {
                nodeId: node.id,
                nodeKind: node.type,
                actionKind: actionKindForWorkflowNodeType(
                  node.type as WorkflowNodeKind,
                ),
                bindingSummary,
              },
              null,
              2,
            )}
          </pre>
        </section>
        <footer>
          <button type="submit" data-testid="workflow-node-config-done">
            Done
          </button>
        </footer>
      </form>
    </div>
  );
}
