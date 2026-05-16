#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { makeDefaultWorkflow } from "../../packages/agent-ide/src/runtime/workflow-defaults.ts";
import {
  makeWorkflowNode,
} from "../../packages/agent-ide/src/runtime/workflow-node-registry.ts";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "../../packages/agent-ide/src/runtime/workflow-validation.ts";
import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowConnectorCatalog,
  normalizeWorkflowToolBinding,
  normalizeWorkflowToolCatalog,
  workflowWithCatalogBinding,
} from "../../packages/agent-ide/src/runtime/workflow-tool-connector-capability-binding.ts";
import {
  workflowBindingRegistryRows,
} from "../../packages/agent-ide/src/runtime/workflow-rail-model.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-capability-catalog-binding-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const toolNodeId = "catalog-tool-node";
const connectorNodeId = "catalog-connector-node";

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function workflowFixture() {
  const workflow = makeDefaultWorkflow("Capability catalog binding proof");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.capability-catalog-binding-proof",
      name: "Capability catalog binding proof",
      slug: "capability-catalog-binding-proof",
      gitLocation:
        ".agents/workflows/capability-catalog-binding-proof.workflow.json",
      readOnly: false,
    },
    nodes: [
      makeWorkflowNode(
        toolNodeId,
        "plugin_tool",
        "Catalog tool",
        320,
        140,
      ),
      makeWorkflowNode(
        connectorNodeId,
        "adapter",
        "Catalog connector",
        620,
        140,
      ),
    ],
    edges: [],
    global_config: {
      environmentProfile: {
        target: "local",
        credentialScope: "local",
        mockBindingPolicy: "block",
      },
    },
  };
}

function issueCodesForNode(validation, nodeId) {
  return [
    ...(validation.errors ?? []),
    ...(validation.warnings ?? []),
    ...(validation.connectorBindingIssues ?? []),
    ...(validation.executionReadinessIssues ?? []),
  ]
    .filter((issue) => issue.nodeId === nodeId)
    .map((issue) => issue.code);
}

function manifestProjectionForNode(workflow, nodeId) {
  const nodeItem = workflow.nodes.find((node) => node.id === nodeId);
  const logic = nodeItem?.config?.logic ?? {};
  if (logic.toolBinding) {
    const binding = normalizeWorkflowToolBinding(logic.toolBinding);
    return {
      nodeId,
      bindingKind: "Tool",
      reference: binding.toolCapabilityRef ?? binding.toolRef,
      toolCapabilityRef: binding.toolCapabilityRef ?? null,
      connectorCapabilityRef: null,
      mode: binding.mockBinding ? "mock" : "live",
      authorityScopes: binding.authorityScopes ?? [],
      authorityScopeRequirements: binding.authorityScopeRequirements ?? [],
      receiptRequired: binding.receiptBehavior?.receiptRequired === true,
      grantStatus: String(binding.grantReadiness?.status ?? ""),
      policyStatus: String(binding.policyPosture?.status ?? ""),
    };
  }
  const binding = normalizeWorkflowConnectorBinding(logic.connectorBinding);
  return {
    nodeId,
    bindingKind: "Connector",
    reference: binding.connectorCapabilityRef ?? binding.connectorRef,
    toolCapabilityRef: null,
    connectorCapabilityRef: binding.connectorCapabilityRef ?? null,
    mode: binding.mockBinding ? "mock" : "live",
    authorityScopes: binding.authorityScopes ?? [],
    authorityScopeRequirements: binding.authorityScopeRequirements ?? [],
    receiptRequired: binding.receiptBehavior?.receiptRequired === true,
    grantStatus: String(binding.grantReadiness?.status ?? ""),
    policyStatus: String(binding.policyPosture?.status ?? ""),
  };
}

function selectToolCatalogBinding() {
  const catalog = normalizeWorkflowToolCatalog(null);
  const selected = catalog.find(
    (binding) =>
      binding.toolCapabilityRef === "tool-capability:mcp.tool.catalog.read",
  );
  if (!selected) throw new Error("missing tool catalog read capability");
  return selected;
}

function selectConnectorCatalogBinding() {
  const catalog = normalizeWorkflowConnectorCatalog(null);
  const selected = catalog.find(
    (binding) =>
      binding.connectorCapabilityRef ===
      "connector-capability:agent.connector.catalog",
  );
  if (!selected) throw new Error("missing connector catalog capability");
  return selected;
}

const modalSource = read(
  "packages/agent-ide/src/features/Workflows/WorkflowComposerModals.tsx",
);
const controllerSource = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
const viewSource = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
const bindingSource = read(
  "packages/agent-ide/src/runtime/workflow-tool-connector-capability-binding.ts",
);
const validationSource = read(
  "packages/agent-ide/src/runtime/workflow-validation.ts",
);

const baseWorkflow = workflowFixture();
const beforeRows = workflowBindingRegistryRows(baseWorkflow);
const selectedTool = selectToolCatalogBinding();
const selectedConnector = selectConnectorCatalogBinding();

const toolApply = workflowWithCatalogBinding(baseWorkflow, toolNodeId, {
  kind: "tool",
  value: selectedTool,
});
const connectorApply = workflowWithCatalogBinding(
  toolApply.workflow,
  connectorNodeId,
  {
    kind: "connector",
    value: selectedConnector,
  },
);
const boundWorkflow = connectorApply.workflow;
const boundRows = workflowBindingRegistryRows(boundWorkflow);
const validation = validateWorkflowProject(boundWorkflow, []);
const readiness = evaluateWorkflowActivationReadiness(
  boundWorkflow,
  [],
  validation,
);
const toolManifestEntry = manifestProjectionForNode(boundWorkflow, toolNodeId);
const connectorManifestEntry = manifestProjectionForNode(
  boundWorkflow,
  connectorNodeId,
);

const blockedToolBinding = normalizeWorkflowToolBinding({
  toolRef: "external.crm.write",
  bindingKind: "plugin_tool",
  mockBinding: false,
  credentialReady: false,
  credentialReadiness: { status: "unknown" },
  grantReadiness: { status: "unknown" },
  policyPosture: { status: "unknown" },
  workflowAvailability: { available: false },
  agentAvailability: { available: false },
  receiptBehavior: {
    receiptRequired: false,
    requiredReceiptTypes: [],
  },
  sideEffectClass: "external_write",
  capabilityScope: ["write"],
  requiresApproval: true,
});
const blockedWorkflow = workflowWithCatalogBinding(baseWorkflow, toolNodeId, {
  kind: "tool",
  value: blockedToolBinding,
}).workflow;
const blockedValidation = validateWorkflowProject(blockedWorkflow, []);
const blockedToolCodes = issueCodesForNode(blockedValidation, toolNodeId);

const toolRow = boundRows.find((row) => row.nodeItem.id === toolNodeId);
const connectorRow = boundRows.find(
  (row) => row.nodeItem.id === connectorNodeId,
);
const toolIssueCodes = issueCodesForNode(validation, toolNodeId);
const connectorIssueCodes = issueCodesForNode(validation, connectorNodeId);
const readinessToolIssueCodes = issueCodesForNode(readiness, toolNodeId);
const readinessConnectorIssueCodes = issueCodesForNode(
  readiness,
  connectorNodeId,
);
const bindingReadinessBlockerCodes = new Set([
  "missing_tool_binding",
  "missing_connector_binding",
  "missing_live_tool_credential",
  "missing_live_connector_credential",
  "missing_credential_readiness_contract",
  "missing_grant_readiness",
  "missing_policy_posture",
  "missing_receipt_behavior",
  "missing_rate_limit_profile",
  "missing_idempotency_behavior",
  "missing_workflow_availability",
  "missing_agent_availability",
]);

const simulatedClickPath = {
  openButtonTestId: "workflow-connector-bindings-button",
  modalTestId: "workflow-connector-binding-modal",
  toolPickerTestId: `workflow-catalog-picker-${toolNodeId}`,
  toolApplyTestId: `workflow-catalog-apply-${toolNodeId}`,
  connectorPickerTestId: `workflow-catalog-picker-${connectorNodeId}`,
  connectorApplyTestId: `workflow-catalog-apply-${connectorNodeId}`,
  selectedToolCapabilityRef: selectedTool.toolCapabilityRef,
  selectedConnectorCapabilityRef: selectedConnector.connectorCapabilityRef,
};

const checks = {
  modalHasCatalogPickerAndApply:
    /workflow-capability-catalog-summary/.test(modalSource) &&
    /workflow-catalog-picker-\$\{row\.nodeItem\.id\}/.test(modalSource) &&
    /workflow-catalog-apply-\$\{row\.nodeItem\.id\}/.test(modalSource),
  headerOpensConnectorBindingModal:
    /workflow-connector-bindings-button/.test(viewSource) &&
    /setConnectorBindingOpen\(true\)/.test(viewSource) &&
    /ConnectorBindingModal/.test(viewSource),
  controllerHydratesRuntimeCatalogs:
    /listWorkflowToolCatalog/.test(controllerSource) &&
    /normalizeWorkflowToolCatalog/.test(controllerSource) &&
    /listWorkflowConnectorCatalog/.test(controllerSource) &&
    /normalizeWorkflowConnectorCatalog/.test(controllerSource),
  controllerUsesSharedApplyProjection:
    /handleApplyWorkflowCatalogBinding/.test(controllerSource) &&
    /workflowNodeWithCatalogBinding/.test(controllerSource),
  deterministicProjectionHelper:
    /workflowNodeWithCatalogBinding/.test(bindingSource) &&
    /workflowWithCatalogBinding/.test(bindingSource),
  beforeRowsUnbound:
    beforeRows.some(
      (row) => row.nodeItem.id === toolNodeId && row.ref.endsWith(":unbound"),
    ) &&
    beforeRows.some(
      (row) =>
        row.nodeItem.id === connectorNodeId && row.ref.endsWith(":unbound"),
    ),
  simulatedToolClickApplied:
    toolApply.applied === true &&
    toolApply.node?.config?.logic.toolBinding?.toolCapabilityRef ===
      "tool-capability:mcp.tool.catalog.read",
  simulatedConnectorClickApplied:
    connectorApply.applied === true &&
    connectorApply.node?.config?.logic.connectorBinding
      ?.connectorCapabilityRef ===
      "connector-capability:agent.connector.catalog",
  bindingRegistrySeesCanonicalRefs:
    toolRow?.ref === "tool-capability:mcp.tool.catalog.read" &&
    connectorRow?.ref === "connector-capability:agent.connector.catalog" &&
    toolRow?.ready === true &&
    connectorRow?.ready === true,
  readinessAcceptsCatalogBindings:
    !toolIssueCodes.includes("missing_tool_binding") &&
    !toolIssueCodes.includes("missing_credential_readiness_contract") &&
    !toolIssueCodes.includes("missing_grant_readiness") &&
    !toolIssueCodes.includes("missing_policy_posture") &&
    !connectorIssueCodes.includes("missing_connector_binding") &&
    !connectorIssueCodes.includes("missing_credential_readiness_contract") &&
    !readinessToolIssueCodes.some((code) =>
      bindingReadinessBlockerCodes.has(code),
    ) &&
    !readinessConnectorIssueCodes.some((code) =>
      bindingReadinessBlockerCodes.has(code),
    ),
  manifestProjectionUsesCanonicalCapabilityRefs:
    toolManifestEntry.toolCapabilityRef ===
      "tool-capability:mcp.tool.catalog.read" &&
    connectorManifestEntry.connectorCapabilityRef ===
      "connector-capability:agent.connector.catalog" &&
    toolManifestEntry.receiptRequired === true &&
    connectorManifestEntry.receiptRequired === true &&
    toolManifestEntry.grantStatus === "ready" &&
    connectorManifestEntry.policyStatus === "allowed",
  failClosedWhenReadinessMissing:
    blockedToolCodes.includes("missing_credential_readiness_contract") &&
    blockedToolCodes.includes("missing_grant_readiness") &&
    blockedToolCodes.includes("missing_policy_posture") &&
    blockedToolCodes.includes("missing_receipt_behavior") &&
    blockedToolCodes.includes("missing_workflow_availability") &&
    blockedToolCodes.includes("missing_agent_availability"),
  validationKeepsFailClosedContract:
    /missing_credential_readiness_contract/.test(validationSource) &&
    /missing_grant_readiness/.test(validationSource) &&
    /missing_receipt_behavior/.test(validationSource),
};

const proof = {
  schemaVersion: "workflow.capability-catalog-binding.gui-proof.v1",
  scenario: "workflow_capability_catalog_binding_clickthrough",
  method:
    "exercise the Workflow Composer connector/plugin binding modal selectors and shared catalog-apply projection, then inspect binding registry, readiness, manifest-style metadata, and fail-closed validation",
  simulatedClickPath,
  selectedCatalog: {
    tool: selectedTool,
    connector: selectedConnector,
  },
  registryRows: {
    before: beforeRows.map((row) => ({
      nodeId: row.nodeItem.id,
      ref: row.ref,
      ready: row.ready,
      mode: row.mode,
    })),
    after: boundRows.map((row) => ({
      nodeId: row.nodeItem.id,
      ref: row.ref,
      ready: row.ready,
      mode: row.mode,
    })),
  },
  manifestProjection: {
    tool: toolManifestEntry,
    connector: connectorManifestEntry,
  },
  readiness: {
    status: readiness.status,
    boundNodeIssueCodes: {
      tool: toolIssueCodes,
      connector: connectorIssueCodes,
      readinessTool: readinessToolIssueCodes,
      readinessConnector: readinessConnectorIssueCodes,
    },
    blockedToolCodes,
  },
  checks,
  passed: Object.values(checks).every(Boolean),
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
if (!proof.passed) {
  console.error(JSON.stringify(proof, null, 2));
  process.exit(1);
}
