import type { WorkflowProject, WorkflowRunResult } from "../types/graph";
import {
  normalizeGraphModelBinding,
  normalizeWorkflowModelBinding,
  workflowModelBindingIsReady,
} from "./workflow-model-capability-binding";
import type { WorkflowRuntimeEventProjection } from "./workflow-runtime-event-projection";
import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingIsReady,
  workflowToolBindingIsReady,
} from "./workflow-tool-connector-capability-binding";

export type WorkflowRunCapabilityReceiptRowStatus =
  | "ready"
  | "mock"
  | "warning"
  | "blocked";

export type WorkflowRunCapabilityReceiptRow = {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeType: string;
  bindingKind: "Model" | "Tool" | "Connector" | "Workflow tool";
  capabilityRef: string;
  routeId: string | null;
  mode: "mock" | "live" | "local";
  status: WorkflowRunCapabilityReceiptRowStatus;
  ready: boolean;
  failClosed: boolean;
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  receiptRequired: boolean;
  receiptTypes: string[];
  authorityScopes: string[];
  authorityScopeRequirements: string[];
  riskClass: string | null;
  sideEffectClass: string;
  requiresApproval: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  runtimeEventIds: string[];
  blockerReasons: string[];
  repairActions: WorkflowCapabilityRepairAction[];
};

export type WorkflowCapabilityRepairActionKind =
  | "open_capability_binding"
  | "request_authority_grant"
  | "apply_approved_grant"
  | "attach_ready_capability"
  | "review_receipt_policy";

export type WorkflowCapabilityRepairAction = {
  id: string;
  kind: WorkflowCapabilityRepairActionKind;
  label: string;
  detail: string;
  nodeId: string;
  nodeName: string;
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"];
  capabilityRef: string;
  routeId: string | null;
  targetSurface: "node_binding_editor" | "authority_center";
  configSection: "bindings";
  authorityEndpoint: "/api/v1/authority" | null;
  catalogEndpoint: "/v1/model-capabilities" | "/api/v1/tools" | null;
  missingFields: string[];
  authorityScopes: string[];
  blockerReasons: string[];
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  riskClass: string | null;
  sideEffectClass: string;
  requiresApproval: boolean;
  receiptRequired: boolean;
  receiptTypes: string[];
};

export type WorkflowRunCapabilityReceiptProjection = {
  schemaVersion: "workflow.run-capability-receipts.v1";
  status: "ready" | "warning" | "blocked" | "not_required";
  rows: WorkflowRunCapabilityReceiptRow[];
  capabilityRefs: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  readyCount: number;
  blockedCount: number;
  receiptRequiredCount: number;
  failClosedCount: number;
};

export function workflowRunCapabilityReceiptProjection(
  workflow: WorkflowProject,
  run: WorkflowRunResult | null,
  runtimeEventProjection: WorkflowRuntimeEventProjection,
): WorkflowRunCapabilityReceiptProjection {
  const rows = workflow.nodes.flatMap((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    const base = {
      nodeId: nodeItem.id,
      nodeName: nodeItem.name,
      nodeType: nodeItem.type,
    };
    if (nodeItem.type === "model_call") {
      const modelRef = String(logic.modelRef ?? "reasoning");
      const normalized = logic.modelBinding
        ? normalizeWorkflowModelBinding(logic.modelBinding, logic)
        : normalizeGraphModelBinding(
            modelRef,
            workflow.global_config.modelBindings?.[modelRef],
          );
      const mode = normalized.mockBinding
        ? "mock"
        : normalized.modelId
          ? "live"
          : "local";
      return [
        capabilityReceiptRow({
          ...base,
          id: `${nodeItem.id}-model-capability`,
          bindingKind: "Model",
          capabilityRef:
            normalized.modelCapabilityRef ?? normalized.modelRef ?? modelRef,
          routeId: normalized.routeId ?? null,
          mode,
          ready: workflowModelBindingIsReady(normalized),
          readinessStatus: readinessStatusOf(normalized.credentialReadiness),
          grantStatus: readinessStatusOf(normalized.grantReadiness),
          policyStatus: statusOf(normalized.policyPosture),
          receiptBehavior: normalized.receiptBehavior,
          authorityScopes: normalized.authorityScopes ?? [],
          authorityScopeRequirements:
            normalized.authorityScopeRequirements ??
            normalized.authorityScopes ??
            [],
          riskClass: null,
          sideEffectClass:
            "sideEffectClass" in normalized
              ? (normalized.sideEffectClass ?? "none")
              : "none",
          requiresApproval:
            "requiresApproval" in normalized &&
            normalized.requiresApproval === true,
          runtimeEvidence: runtimeEvidenceForCapabilityNode(
            run,
            runtimeEventProjection,
            nodeItem.id,
          ),
        }),
      ];
    }
    if (nodeItem.type === "model_binding" && logic.modelBinding) {
      const normalized = normalizeWorkflowModelBinding(logic.modelBinding, logic);
      return [
        capabilityReceiptRow({
          ...base,
          id: `${nodeItem.id}-model-binding-capability`,
          bindingKind: "Model",
          capabilityRef: normalized.modelCapabilityRef ?? normalized.modelRef,
          routeId: normalized.routeId ?? null,
          mode: normalized.mockBinding ? "mock" : "live",
          ready: workflowModelBindingIsReady(normalized),
          readinessStatus: readinessStatusOf(normalized.credentialReadiness),
          grantStatus: readinessStatusOf(normalized.grantReadiness),
          policyStatus: statusOf(normalized.policyPosture),
          receiptBehavior: normalized.receiptBehavior,
          authorityScopes: normalized.authorityScopes ?? [],
          authorityScopeRequirements:
            normalized.authorityScopeRequirements ??
            normalized.authorityScopes ??
            [],
          riskClass: null,
          sideEffectClass: normalized.sideEffectClass ?? "none",
          requiresApproval: normalized.requiresApproval === true,
          runtimeEvidence: runtimeEvidenceForCapabilityNode(
            run,
            runtimeEventProjection,
            nodeItem.id,
          ),
        }),
      ];
    }
    if (nodeItem.type === "adapter" && logic.connectorBinding) {
      const normalized = normalizeWorkflowConnectorBinding(logic.connectorBinding);
      return [
        capabilityReceiptRow({
          ...base,
          id: `${nodeItem.id}-connector-capability`,
          bindingKind: "Connector",
          capabilityRef:
            normalized.connectorCapabilityRef ?? normalized.connectorRef,
          routeId: null,
          mode: normalized.mockBinding ? "mock" : "live",
          ready: workflowConnectorBindingIsReady(normalized),
          readinessStatus: readinessStatusOf(normalized.credentialReadiness),
          grantStatus: readinessStatusOf(normalized.grantReadiness),
          policyStatus: statusOf(normalized.policyPosture),
          receiptBehavior: normalized.receiptBehavior,
          authorityScopes: normalized.authorityScopes ?? [],
          authorityScopeRequirements:
            normalized.authorityScopeRequirements ??
            normalized.authorityScopes ??
            [],
          riskClass: normalized.riskClass ?? null,
          sideEffectClass: normalized.sideEffectClass ?? "read",
          requiresApproval: normalized.requiresApproval === true,
          runtimeEvidence: runtimeEvidenceForCapabilityNode(
            run,
            runtimeEventProjection,
            nodeItem.id,
          ),
        }),
      ];
    }
    if (nodeItem.type === "plugin_tool" && logic.toolBinding) {
      const normalized = normalizeWorkflowToolBinding(logic.toolBinding);
      const isWorkflowTool = normalized.bindingKind === "workflow_tool";
      return [
        capabilityReceiptRow({
          ...base,
          id: `${nodeItem.id}-tool-capability`,
          bindingKind: isWorkflowTool ? "Workflow tool" : "Tool",
          capabilityRef: isWorkflowTool
            ? normalized.workflowTool?.workflowPath ??
              normalized.toolCapabilityRef ??
              normalized.toolRef
            : normalized.toolCapabilityRef ?? normalized.toolRef,
          routeId: null,
          mode: isWorkflowTool
            ? "local"
            : normalized.mockBinding
              ? "mock"
              : "live",
          ready: workflowToolBindingIsReady(normalized),
          readinessStatus: readinessStatusOf(normalized.credentialReadiness),
          grantStatus: readinessStatusOf(normalized.grantReadiness),
          policyStatus: statusOf(normalized.policyPosture),
          receiptBehavior: normalized.receiptBehavior,
          authorityScopes: normalized.authorityScopes ?? [],
          authorityScopeRequirements:
            normalized.authorityScopeRequirements ??
            normalized.authorityScopes ??
            [],
          riskClass: normalized.riskClass ?? null,
          sideEffectClass: normalized.sideEffectClass ?? "none",
          requiresApproval: normalized.requiresApproval === true,
          runtimeEvidence: runtimeEvidenceForCapabilityNode(
            run,
            runtimeEventProjection,
            nodeItem.id,
          ),
        }),
      ];
    }
    return [];
  });
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const failClosedCount = rows.filter((row) => row.failClosed).length;
  const status =
    rows.length === 0
      ? "not_required"
      : blockedCount > 0
        ? "blocked"
        : rows.some((row) => row.status === "warning")
          ? "warning"
          : "ready";
  return {
    schemaVersion: "workflow.run-capability-receipts.v1",
    status,
    rows,
    capabilityRefs: uniqueStrings(rows.map((row) => row.capabilityRef)),
    receiptRefs: uniqueStrings(rows.flatMap((row) => row.receiptRefs)),
    policyDecisionRefs: uniqueStrings(
      rows.flatMap((row) => row.policyDecisionRefs),
    ),
    readyCount: rows.filter((row) => row.ready).length,
    blockedCount,
    receiptRequiredCount: rows.filter((row) => row.receiptRequired).length,
    failClosedCount,
  };
}

function capabilityReceiptRow(input: {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeType: string;
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"];
  capabilityRef: string;
  routeId: string | null;
  mode: WorkflowRunCapabilityReceiptRow["mode"];
  ready: boolean;
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  receiptBehavior: Record<string, unknown> | undefined;
  authorityScopes: string[];
  authorityScopeRequirements: string[];
  riskClass: string | null;
  sideEffectClass: string;
  requiresApproval: boolean;
  runtimeEvidence: {
    receiptRefs: string[];
    policyDecisionRefs: string[];
    runtimeEventIds: string[];
  };
}): WorkflowRunCapabilityReceiptRow {
  const receiptRequired =
    asRecord(input.receiptBehavior)?.receiptRequired === true;
  const receiptTypes = uniqueStrings(
    [asRecord(input.receiptBehavior)?.requiredReceiptTypes],
  );
  const blockerReasons = capabilityReceiptBlockerReasons({
    capabilityRef: input.capabilityRef,
    ready: input.ready,
    mode: input.mode,
    readinessStatus: input.readinessStatus,
    grantStatus: input.grantStatus,
    policyStatus: input.policyStatus,
    receiptRequired,
    receiptTypes,
    authorityScopes: input.authorityScopes,
    authorityScopeRequirements: input.authorityScopeRequirements,
  });
  const failClosed = input.mode === "live" && blockerReasons.length > 0;
  const status: WorkflowRunCapabilityReceiptRowStatus = failClosed
    ? "blocked"
    : input.ready
      ? "ready"
      : input.mode === "mock"
        ? "mock"
        : "warning";
  return {
    id: input.id,
    nodeId: input.nodeId,
    nodeName: input.nodeName,
    nodeType: input.nodeType,
    bindingKind: input.bindingKind,
    capabilityRef: input.capabilityRef,
    routeId: input.routeId,
    mode: input.mode,
    status,
    ready: input.ready,
    failClosed,
    readinessStatus: input.readinessStatus,
    grantStatus: input.grantStatus,
    policyStatus: input.policyStatus,
    receiptRequired,
    receiptTypes,
    authorityScopes: uniqueStrings(input.authorityScopes),
    authorityScopeRequirements: uniqueStrings(input.authorityScopeRequirements),
    riskClass: input.riskClass,
    sideEffectClass: input.sideEffectClass,
    requiresApproval: input.requiresApproval,
    receiptRefs: input.runtimeEvidence.receiptRefs,
    policyDecisionRefs: input.runtimeEvidence.policyDecisionRefs,
    runtimeEventIds: input.runtimeEvidence.runtimeEventIds,
    blockerReasons,
    repairActions: workflowCapabilityRepairActions({
      ...input,
      blockerReasons,
      failClosed,
      receiptRequired,
      receiptTypes,
    }),
  };
}

function workflowCapabilityRepairActions(input: {
  nodeId: string;
  nodeName: string;
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"];
  capabilityRef: string;
  routeId: string | null;
  blockerReasons: string[];
  authorityScopes: string[];
  authorityScopeRequirements: string[];
  failClosed: boolean;
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  riskClass: string | null;
  sideEffectClass: string;
  requiresApproval: boolean;
  receiptRequired: boolean;
  receiptTypes: string[];
}): WorkflowCapabilityRepairAction[] {
  if (!input.failClosed) return [];
  const authorityScopes = uniqueStrings([
    ...input.authorityScopes,
    ...input.authorityScopeRequirements,
  ]);
  const missingFields = workflowCapabilityRepairMissingFields(
    input.bindingKind,
    input.blockerReasons,
  );
  const base = {
    nodeId: input.nodeId,
    nodeName: input.nodeName,
    bindingKind: input.bindingKind,
    capabilityRef: input.capabilityRef,
    routeId: input.routeId,
    configSection: "bindings" as const,
    authorityScopes,
    blockerReasons: input.blockerReasons,
    readinessStatus: input.readinessStatus,
    grantStatus: input.grantStatus,
    policyStatus: input.policyStatus,
    riskClass: input.riskClass,
    sideEffectClass: input.sideEffectClass,
    requiresApproval: input.requiresApproval,
    receiptRequired: input.receiptRequired,
    receiptTypes: input.receiptTypes,
  };
  const actions: WorkflowCapabilityRepairAction[] = [
    {
      ...base,
      id: `${input.nodeId}:open_capability_binding`,
      kind: "open_capability_binding",
      label: "Open capability binding",
      detail:
        "Open the node binding editor with canonical capability, authority, and receipt fields focused.",
      targetSurface: "node_binding_editor",
      authorityEndpoint: null,
      catalogEndpoint: workflowCapabilityCatalogEndpoint(input.bindingKind),
      missingFields,
    },
  ];
  if (
    input.blockerReasons.some((reason) =>
      [
        "missing_grant_readiness",
        "missing_policy_posture",
        "missing_authority_scope",
      ].includes(reason),
    )
  ) {
    actions.push({
      ...base,
      id: `${input.nodeId}:request_authority_grant`,
      kind: "request_authority_grant",
      label: "Request grant",
      detail:
        "Review this binding against /api/v1/authority and request the scoped runtime grant before execution.",
      targetSurface: "authority_center",
      authorityEndpoint: "/api/v1/authority",
      catalogEndpoint: null,
      missingFields: missingFields.filter((field) =>
        [
          "grantReadiness",
          "policyPosture",
          "authorityScopes",
          "authorityScopeRequirements",
        ].includes(field),
      ),
    });
    actions.push({
      ...base,
      id: `${input.nodeId}:apply_approved_grant`,
      kind: "apply_approved_grant",
      label: "Apply approved grant",
      detail:
        "Apply an approved authority grant to this node binding so the workflow can clear capability preflight.",
      targetSurface: "authority_center",
      authorityEndpoint: "/api/v1/authority",
      catalogEndpoint: null,
      missingFields: missingFields.filter((field) =>
        [
          "grantReadiness",
          "policyPosture",
          "authorityScopes",
          "authorityScopeRequirements",
        ].includes(field),
      ),
    });
  }
  if (
    input.blockerReasons.some((reason) =>
      ["missing_capability_ref", "missing_credential_readiness"].includes(
        reason,
      ),
    )
  ) {
    actions.push({
      ...base,
      id: `${input.nodeId}:attach_ready_capability`,
      kind: "attach_ready_capability",
      label: "Attach ready capability",
      detail:
        "Bind this node to a ready capability from the canonical catalog projection.",
      targetSurface: "node_binding_editor",
      authorityEndpoint: null,
      catalogEndpoint: workflowCapabilityCatalogEndpoint(input.bindingKind),
      missingFields: missingFields.filter((field) =>
        [
          workflowCapabilityRefField(input.bindingKind),
          "credentialReadiness",
          "credentialReady",
        ].includes(field),
      ),
    });
  }
  if (input.blockerReasons.includes("missing_receipt_behavior")) {
    actions.push({
      ...base,
      id: `${input.nodeId}:review_receipt_policy`,
      kind: "review_receipt_policy",
      label: "Review receipt policy",
      detail:
        "Declare required receipt types so live execution leaves replayable evidence.",
      targetSurface: "node_binding_editor",
      authorityEndpoint: null,
      catalogEndpoint: null,
      missingFields: ["receiptBehavior"],
    });
  }
  return actions;
}

function workflowCapabilityRepairMissingFields(
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"],
  blockerReasons: readonly string[],
): string[] {
  const fields = blockerReasons.flatMap((reason) => {
    if (reason === "missing_capability_ref") {
      return [workflowCapabilityRefField(bindingKind)];
    }
    if (reason === "missing_credential_readiness") {
      return ["credentialReadiness", "credentialReady"];
    }
    if (reason === "missing_grant_readiness") return ["grantReadiness"];
    if (reason === "missing_policy_posture") return ["policyPosture"];
    if (reason === "missing_receipt_behavior") return ["receiptBehavior"];
    if (reason === "missing_authority_scope") {
      return ["authorityScopes", "authorityScopeRequirements"];
    }
    if (reason === "binding_not_ready") return ["readiness"];
    return [reason];
  });
  return uniqueStrings(fields);
}

function workflowCapabilityRefField(
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"],
): string {
  if (bindingKind === "Model") return "modelCapabilityRef";
  if (bindingKind === "Connector") return "connectorCapabilityRef";
  return "toolCapabilityRef";
}

function workflowCapabilityCatalogEndpoint(
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"],
): WorkflowCapabilityRepairAction["catalogEndpoint"] {
  return bindingKind === "Model"
    ? "/v1/model-capabilities"
    : "/api/v1/tools";
}

function capabilityReceiptBlockerReasons(input: {
  capabilityRef: string;
  ready: boolean;
  mode: WorkflowRunCapabilityReceiptRow["mode"];
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  receiptRequired: boolean;
  receiptTypes: string[];
  authorityScopes: string[];
  authorityScopeRequirements: string[];
}): string[] {
  if (input.mode !== "live") return [];
  const blockers: string[] = [];
  if (!input.capabilityRef || input.capabilityRef.endsWith(":unbound")) {
    blockers.push("missing_capability_ref");
  }
  if (!["ready", "not_required"].includes(input.readinessStatus)) {
    blockers.push("missing_credential_readiness");
  }
  if (!["ready", "not_required"].includes(input.grantStatus)) {
    blockers.push("missing_grant_readiness");
  }
  if (!["allowed", "ready", "approved"].includes(input.policyStatus)) {
    blockers.push("missing_policy_posture");
  }
  if (!input.receiptRequired || input.receiptTypes.length === 0) {
    blockers.push("missing_receipt_behavior");
  }
  if (
    input.authorityScopes.length === 0 &&
    input.authorityScopeRequirements.length === 0
  ) {
    blockers.push("missing_authority_scope");
  }
  if (!input.ready && blockers.length === 0) {
    blockers.push("binding_not_ready");
  }
  return blockers;
}

function runtimeEvidenceForCapabilityNode(
  run: WorkflowRunResult | null,
  projection: WorkflowRuntimeEventProjection,
  nodeId: string,
): {
  receiptRefs: string[];
  policyDecisionRefs: string[];
  runtimeEventIds: string[];
} {
  const runtimeNodes = projection.reactFlowNodes.filter(
    (node) => node.data.workflowNodeId === nodeId || node.id === nodeId,
  );
  const nodeRuns = (run?.nodeRuns ?? []).filter(
    (nodeRun) => nodeRun.nodeId === nodeId,
  );
  const outputRecords = nodeRuns
    .map((nodeRun) => asRecord(nodeRun.output))
    .filter((record): record is Record<string, unknown> => Boolean(record));
  return {
    receiptRefs: uniqueStrings([
      ...runtimeNodes.flatMap((node) => node.data.receiptRefs),
      ...outputRecords.flatMap((record) =>
        recordStringValues(record, [
          "receiptRefs",
          "receipt_refs",
          "receiptRef",
          "receipt_ref",
          "lastReceiptId",
          "last_receipt_id",
        ]),
      ),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...runtimeNodes.flatMap((node) => node.data.policyDecisionRefs),
      ...outputRecords.flatMap((record) =>
        recordStringValues(record, [
          "policyDecisionRefs",
          "policy_decision_refs",
          "policyDecisionRef",
          "policy_decision_ref",
        ]),
      ),
    ]),
    runtimeEventIds: uniqueStrings(
      runtimeNodes.flatMap((node) => node.data.eventIds),
    ),
  };
}

function readinessStatusOf(value: unknown): string {
  return statusOf(value) || "unknown";
}

function statusOf(value: unknown): string {
  const record = asRecord(value);
  return readString(record?.status)?.toLowerCase() ?? "";
}

function recordStringValues(
  record: Record<string, unknown>,
  keys: readonly string[],
): string[] {
  return uniqueStrings(keys.flatMap((key) => record[key]));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function readString(value: unknown): string | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  return null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  const result: string[] = [];
  const visit = (value: unknown) => {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed && !result.includes(trimmed)) result.push(trimmed);
      return;
    }
    if (Array.isArray(value)) value.forEach(visit);
  };
  values.forEach(visit);
  return result;
}
