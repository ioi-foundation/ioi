import { memo, type KeyboardEvent } from "react";
import { Handle, Position, NodeProps } from "@xyflow/react";
import {
  Node,
  FirewallPolicy,
  WorkflowHarnessGroupView,
  WorkflowPortDefinition,
} from "../../../../types/graph";
import { workflowRuntimeNodeChrome } from "../../../../runtime/workflow-runtime-ui-strings";
import "./CanvasNode.css";

type CanvasNodeData = Node & Record<string, unknown>;
type CompatiblePortRequest = {
  nodeId: string;
  portId: string;
  direction: "downstream" | "attachment";
};
type CanvasIssueSummary = {
  blockerCount: number;
  warningCount: number;
  issueCount: number;
  title: string;
  message: string;
  actionLabel: string;
  primaryIssue: unknown;
};

const familyLabels: Record<string, string> = {
  source: "Source",
  trigger: "Trigger",
  task_state: "State",
  uncertainty_gate: "Judgment",
  probe: "Probe",
  budget_gate: "Budget",
  capability_sequence: "Route",
  runtime_doctor: "Doctor",
  runtime_thread_fork: "Fork",
  runtime_operator_interrupt: "Interrupt",
  function: "Function",
  model_binding: "Model",
  model_call: "Model",
  skill_context: "Context",
  skill: "Skill",
  skill_pack: "Skill Pack",
  hook: "Hook",
  hook_policy: "Hook Policy",
  parser: "Parser",
  adapter: "Adapter",
  plugin_tool: "Plugin",
  dry_run: "Preview",
  state: "State",
  decision: "Decision",
  loop: "Loop",
  barrier: "Barrier",
  subgraph: "Subgraph",
  human_gate: "Gate",
  semantic_impact: "Impact",
  postcondition_synthesis: "Checks",
  verifier: "Verify",
  drift_detector: "Drift",
  quality_ledger: "Quality",
  handoff: "Handoff",
  gui_harness_validation: "GUI",
  output: "Output",
  test_assertion: "Test",
  proposal: "Proposal",
  responses: "Model",
  code: "Function",
  tool: "Tool",
  router: "Decision",
  gate: "Gate",
  context: "Context",
};

const familyTokens: Record<string, string> = {
  source: "IN",
  trigger: "TR",
  task_state: "TS",
  uncertainty_gate: "?",
  probe: "PB",
  budget_gate: "$",
  capability_sequence: "SEQ",
  runtime_doctor: "DR",
  runtime_thread_fork: "TF",
  runtime_operator_interrupt: "INT",
  function: "FN",
  model_binding: "MB",
  model_call: "AI",
  skill_context: "SK",
  skill: "SK",
  skill_pack: "SP",
  hook: "HK",
  hook_policy: "HP",
  parser: "PR",
  adapter: "AD",
  plugin_tool: "PL",
  dry_run: "DR",
  state: "ST",
  decision: "IF",
  loop: "LO",
  barrier: "BA",
  subgraph: "SG",
  human_gate: "OK",
  semantic_impact: "IM",
  postcondition_synthesis: "PC",
  verifier: "VF",
  drift_detector: "DF",
  quality_ledger: "QL",
  handoff: "HO",
  gui_harness_validation: "GUI",
  output: "OUT",
  test_assertion: "TS",
  proposal: "PR",
  responses: "AI",
  code: "FN",
  tool: "TL",
  router: "IF",
  gate: "OK",
  context: "CTX",
};

function familyForType(type: string): string {
  if (type === "responses") return "model_call";
  if (type === "code" || type === "action") return "function";
  if (type === "tool") return "plugin_tool";
  if (type === "router") return "decision";
  if (type === "gate") return "human_gate";
  if (type === "context") return "source";
  return type;
}

function defaultInputHandles(type: string): string[] {
  switch (type) {
    case "source":
    case "trigger":
    case "model_binding":
    case "parser":
      return [];
    case "model_call":
    case "adapter":
    case "decision":
    case "loop":
    case "subgraph":
      return ["input", "context"];
    case "barrier":
      return ["left", "right"];
    case "human_gate":
      return ["approval"];
    default:
      return ["input"];
  }
}

function defaultOutputHandles(type: string, routes?: unknown): string[] {
  if (type === "decision" || type === "loop" || type === "router") {
    const routeList = Array.isArray(routes)
      ? routes.filter((route): route is string => typeof route === "string" && route.trim().length > 0)
      : [];
    return routeList.length > 0 ? routeList : ["left", "right", "error"];
  }
  switch (type) {
    case "output":
      return [];
    case "source":
    case "trigger":
      return ["output"];
    case "model_binding":
      return ["model"];
    case "model_call":
    case "adapter":
      return ["output", "error", "retry"];
    case "parser":
      return ["parser"];
    case "barrier":
    case "subgraph":
    case "state":
    case "proposal":
      return ["output", "error"];
    default:
      return ["output", "error"];
  }
}

function handleTop(index: number, total: number): string {
  if (total <= 1) return "50%";
  return `${24 + index * (52 / Math.max(total - 1, 1))}%`;
}

function fallbackPort(id: string, direction: WorkflowPortDefinition["direction"]): WorkflowPortDefinition {
  return {
    id,
    label: id,
    direction,
    dataType: id === "approval" ? "approval" : id === "retry" || id === "error" ? "response" : "payload",
    connectionClass: id === "approval" ? "approval" : id === "retry" ? "retry" : id === "error" ? "error" : "data",
    cardinality: "one",
    required: direction === "input",
    semanticRole: (id === "approval" || id === "retry" || id === "error" ? id : direction === "input" ? "input" : "output") as WorkflowPortDefinition["semanticRole"],
  };
}

function issueSummaryFromData(value: unknown): CanvasIssueSummary | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Partial<CanvasIssueSummary>;
  const issueCount = Number(record.issueCount ?? 0);
  if (!Number.isFinite(issueCount) || issueCount <= 0) return null;
  return {
    blockerCount: Number(record.blockerCount ?? 0),
    warningCount: Number(record.warningCount ?? 0),
    issueCount,
    title: String(record.title ?? "Needs attention"),
    message: String(record.message ?? "Review this node."),
    actionLabel: String(record.actionLabel ?? "Open configuration"),
    primaryIssue: record.primaryIssue,
  };
}

export const CanvasNode = memo(({ data, selected }: NodeProps) => {
  const nodeData = data as CanvasNodeData;
  const { type, name, status, ioTypes, metrics, isGhost, config } = nodeData;
  const nodeType = String(type || "function");
  const family = familyForType(nodeType);
  const statusClass = status || "idle";
  const ghostClass = isGhost ? "ghost" : "";
  const activeClass = status === "running" ? "active" : "";
  const routes = config?.logic?.routes;
  const inputIds = Array.isArray(nodeData.inputs)
    ? nodeData.inputs.map(String)
    : defaultInputHandles(nodeType);
  const outputIds = Array.isArray(nodeData.outputs)
    ? nodeData.outputs.map(String)
    : defaultOutputHandles(nodeType, routes);
  const portDefinitions = Array.isArray(nodeData.ports) ? nodeData.ports : [];
  const inputPorts = inputIds.map((handleId) =>
    portDefinitions.find((port) => port.id === handleId && port.direction === "input") ?? fallbackPort(handleId, "input"),
  );
  const outputPorts = outputIds.map((handleId) =>
    portDefinitions.find((port) => port.id === handleId && port.direction === "output") ?? fallbackPort(handleId, "output"),
  );

  const law = config?.law as FirewallPolicy | undefined;
  const logic = config?.logic ?? {};
  const viewMacro = logic.viewMacro && typeof logic.viewMacro === "object"
    ? logic.viewMacro
    : null;
  const harnessGroup = logic.harnessGroup && typeof logic.harnessGroup === "object"
    ? (logic.harnessGroup as WorkflowHarnessGroupView)
    : null;
  const binding = logic.connectorBinding ?? logic.toolBinding;
  const issueSummary = issueSummaryFromData(nodeData.validationIssueSummary);
  const onRequestCompatibleNodes =
    typeof nodeData.onRequestCompatibleNodes === "function"
      ? (nodeData.onRequestCompatibleNodes as (
          request: CompatiblePortRequest,
        ) => void)
      : null;
  const onResolveCanvasIssue =
    typeof nodeData.onResolveCanvasIssue === "function"
      ? (nodeData.onResolveCanvasIssue as (issue: unknown) => void)
      : null;
  const onToggleHarnessGroup =
    typeof nodeData.onToggleHarnessGroup === "function"
      ? (nodeData.onToggleHarnessGroup as () => void)
      : null;
  const onKeyboardSelect =
    typeof nodeData.onKeyboardSelect === "function"
      ? (nodeData.onKeyboardSelect as (nodeId: string) => void)
      : null;
  const hasGovernance = law && (
    (law.budgetCap !== undefined && law.budgetCap > 0) ||
    (law.networkAllowlist !== undefined && law.networkAllowlist.length > 0) ||
    (law.requireHumanGate === true)
  );
  const finalOutputs = hasGovernance && !outputPorts.some((port) => port.id === "blocked")
    ? [...outputPorts, fallbackPort("blocked", "output")]
    : outputPorts;
  const metricLabel = String(nodeData.metricLabel || "Status");
  const metricValue =
    nodeData.metricValue ??
    metrics?.records ??
    metrics?.time ??
    statusClass;
  const workflowChromeLocale =
    typeof nodeData.workflowChromeLocale === "string"
      ? nodeData.workflowChromeLocale
      : null;
  const chrome = workflowRuntimeNodeChrome(nodeData, {
    fallbackLabel: isGhost ? "Proposed step" : String(name ?? nodeType),
    locale: workflowChromeLocale,
  });
  const nodeTitle = isGhost ? "Proposed step" : chrome.label;
  const nodeFamilyLabel = familyLabels[nodeType] || familyLabels[family] || "Step";
  const footerStatus = chrome.colorIndependentStatus ? chrome.statusText : statusClass;
  const nodeId = String(nodeData.id ?? "");
  const selectNodeFromKeyboard = () => {
    if (nodeId) onKeyboardSelect?.(nodeId);
  };
  const handleNodeKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.target !== event.currentTarget) return;
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    selectNodeFromKeyboard();
  };

  return (
    <div
      className={`canvas-node canvas-node--${family} ${viewMacro ? "canvas-node--macro-member" : ""} ${harnessGroup ? "canvas-node--harness-group" : ""} ${selected ? "selected" : ""} ${ghostClass} ${activeClass} ${issueSummary ? "has-issues" : ""} ${(issueSummary?.blockerCount ?? 0) > 0 ? "has-blockers" : ""}`}
      role="group"
      tabIndex={0}
      aria-label={chrome.ariaLabel}
      aria-keyshortcuts="Enter Space"
      data-node-family={family}
      data-keyboard-selectable="true"
      data-runtime-ui-catalog={chrome.isRuntimeChrome ? logic.runtimeUiStringCatalogRef : undefined}
      data-workflow-chrome-locale={workflowChromeLocale ?? undefined}
      data-runtime-ui-locale={chrome.isRuntimeChrome ? chrome.locale : undefined}
      data-accessible-status={chrome.accessibleStatusValue}
      data-accessible-status-text={chrome.statusText}
      data-macro-id={viewMacro?.macroId}
      data-macro-role={viewMacro?.role}
      data-harness-group-id={harnessGroup?.groupId}
      data-harness-group-collapsed={harnessGroup?.collapsed}
      data-issue-count={issueSummary?.issueCount ?? 0}
      data-testid={`workflow-canvas-node-${nodeData.id}`}
      onFocus={(event) => {
        if (event.target === event.currentTarget) selectNodeFromKeyboard();
      }}
      onKeyDown={handleNodeKeyDown}
    >
      {inputPorts.map((port, index) => (
        <div
          key={`input-${port.id}`}
          className={`node-port-row node-port-row--input node-port-row--${port.connectionClass}`}
          style={{ top: handleTop(index, inputPorts.length) }}
          title={`${port.label} input (${port.connectionClass})`}
          data-connection-class={port.connectionClass}
        >
          <span className="port-label port-label--input">{port.label}</span>
          {onRequestCompatibleNodes ? (
            <button
              type="button"
              className="port-compatible-button port-compatible-button--input"
              data-testid={`workflow-port-add-compatible-${nodeData.id}-${port.id}`}
              title={`Add compatible attachment for ${port.label}`}
              aria-label={`Add compatible attachment for ${port.label}`}
              onClick={(event) => {
                event.stopPropagation();
                onRequestCompatibleNodes({
                  nodeId: String(nodeData.id),
                  portId: port.id,
                  direction: "attachment",
                });
              }}
            >
              +
            </button>
          ) : null}
          {/* @ts-ignore */}
          <Handle
            type="target"
            position={Position.Left}
            className={`node-port port-in port-${port.connectionClass}`}
            id={port.id}
          />
        </div>
      ))}

      {!isGhost ? (
        <div
          className={`status-dot status-${statusClass}`}
          aria-hidden="true"
          title={chrome.statusText}
        />
      ) : null}
      {issueSummary ? (
        <button
          type="button"
          className="node-issue-badge"
          data-testid={`workflow-canvas-node-issue-${nodeData.id}`}
          data-issue-status={issueSummary.blockerCount > 0 ? "blocked" : "warning"}
          title={`${issueSummary.title}: ${issueSummary.message}`}
          aria-label={`${issueSummary.title}: ${issueSummary.actionLabel}`}
          onClick={(event) => {
            event.stopPropagation();
            onResolveCanvasIssue?.(issueSummary.primaryIssue);
          }}
        >
          <span>{issueSummary.blockerCount > 0 ? "!" : "?"}</span>
          <em>{issueSummary.issueCount}</em>
        </button>
      ) : null}

      <div className="node-header">
        <span className="node-token">{familyTokens[nodeType] || familyTokens[family] || "WF"}</span>
        <span className="node-title">{nodeTitle}</span>
        <span className="node-family-label">{nodeFamilyLabel}</span>
      </div>

      <div className="node-io">
        <span className="io-pill">{ioTypes?.in || "payload"}</span>
        <span className="io-separator">/</span>
        <span className="io-pill">{ioTypes?.out || "result"}</span>
      </div>

      <div className="node-body">
        {status === "running" ? <div className="activity-bar" /> : null}
        <div className="node-stat">
          <span>{metricLabel}</span>
          <span className="node-stat-val">{String(metricValue)}</span>
        </div>
        {binding?.mockBinding ? <span className="node-badge node-badge--mock">Mock</span> : null}
        {binding?.requiresApproval || law?.requireHumanGate ? <span className="node-badge node-badge--gate">Approval</span> : null}
        {viewMacro ? (
          <span className="node-badge node-badge--macro" data-testid="workflow-canvas-node-macro-badge">
            {viewMacro.macroLabel} · {viewMacro.role}
          </span>
        ) : null}
        {harnessGroup ? (
          <div
            className="node-harness-group-rollup"
            data-testid={`workflow-harness-group-node-${harnessGroup.groupId}`}
            data-harness-group-id={harnessGroup.groupId}
            data-harness-group-collapsed={harnessGroup.collapsed}
          >
            <div
              className="node-harness-group-stats"
              data-testid="workflow-harness-group-rollup"
            >
              <span>{harnessGroup.statusRollup.executionMode}</span>
              <span>{harnessGroup.statusRollup.readiness}</span>
              <span>{harnessGroup.statusRollup.receiptKindCount} receipts</span>
              <span>{harnessGroup.statusRollup.replayFixtureCount} replay</span>
            </div>
            <div className="node-harness-group-meta">
              <span data-testid="workflow-harness-group-boundary-ports">
                {harnessGroup.boundaryPorts.map((port) => port.id).join(" / ")}
              </span>
              <span data-testid="workflow-harness-group-deep-link">
                {harnessGroup.deepLinks.groupId}
              </span>
            </div>
            <button
              type="button"
              className="node-harness-group-toggle"
              data-testid="workflow-harness-group-toggle"
              onClick={(event) => {
                event.stopPropagation();
                onToggleHarnessGroup?.();
              }}
            >
              {harnessGroup.collapsed ? "Expand" : "Collapse"}
            </button>
          </div>
        ) : null}
      </div>

      {finalOutputs.map((port, index) => (
        <div
          key={`output-${port.id}`}
          className={`node-port-row node-port-row--output node-port-row--${port.id} node-port-row--${port.connectionClass}`}
          style={{ top: handleTop(index, finalOutputs.length) }}
          title={`${port.label} output (${port.connectionClass})`}
          data-connection-class={port.connectionClass}
        >
          <span className="port-label port-label--output">{port.label}</span>
          {onRequestCompatibleNodes ? (
            <button
              type="button"
              className="port-compatible-button port-compatible-button--output"
              data-testid={`workflow-port-add-compatible-${nodeData.id}-${port.id}`}
              title={`Add compatible node after ${port.label}`}
              aria-label={`Add compatible node after ${port.label}`}
              onClick={(event) => {
                event.stopPropagation();
                onRequestCompatibleNodes({
                  nodeId: String(nodeData.id),
                  portId: port.id,
                  direction: "downstream",
                });
              }}
            >
              +
            </button>
          ) : null}
          {/* @ts-ignore */}
          <Handle
            type="source"
            position={Position.Right}
            id={port.id}
            className={`node-port port-out port-out--${port.id} port-${port.connectionClass}`}
          />
        </div>
      ))}

      <div className="node-footer">
        <span aria-live="polite" data-testid={`workflow-canvas-node-accessible-status-${nodeData.id}`}>
          {isGhost ? "proposal" : footerStatus}
        </span>
        <span>{nodeData.id?.slice(0, 8)}</span>
      </div>
    </div>
  );
});
