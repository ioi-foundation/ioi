import type {
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import {
  workflowRunCapabilityReceiptProjection,
  type WorkflowRunCapabilityReceiptRow,
} from "./workflow-run-capability-receipts";
import { projectRuntimeThreadEventsToWorkflowProjection } from "./workflow-runtime-event-projection";

export const WORKFLOW_CAPABILITY_PREFLIGHT_SCHEMA_VERSION =
  "ioi.workflow.capability-preflight.v1";

export type WorkflowCapabilityPreflight = {
  schemaVersion: typeof WORKFLOW_CAPABILITY_PREFLIGHT_SCHEMA_VERSION;
  sourceKind: "workflow_capability_bindings";
  status: "blocked";
  issue: WorkflowValidationIssue;
  rowCount: number;
  targetNodeIds: string[];
  capabilityRefs: string[];
  bindingKinds: string[];
  blockerReasons: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rows: WorkflowCapabilityPreflightRow[];
};

export type WorkflowCapabilityPreflightRow = {
  nodeId: string;
  nodeName: string;
  nodeType: string;
  bindingKind: WorkflowRunCapabilityReceiptRow["bindingKind"];
  capabilityRef: string;
  routeId: string | null;
  mode: WorkflowRunCapabilityReceiptRow["mode"];
  ready: boolean;
  failClosed: boolean;
  readinessStatus: string;
  grantStatus: string;
  policyStatus: string;
  receiptRequired: boolean;
  receiptTypes: string[];
  authorityScopes: string[];
  authorityScopeRequirements: string[];
  blockerReasons: string[];
};

export type WorkflowCapabilityRunLaunchAnnotation = {
  schemaVersion: typeof WORKFLOW_CAPABILITY_PREFLIGHT_SCHEMA_VERSION;
  sourceKind: "workflow_capability_bindings";
  status: "blocked";
  rowCount: number;
  targetNodeIds: string[];
  capabilityRefs: string[];
  bindingKinds: string[];
  blockerReasons: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  rows: WorkflowCapabilityPreflightRow[];
  issueCode: string;
  issueMessage: string;
};

export function workflowCapabilityPreflight(
  workflow: WorkflowProject,
): WorkflowCapabilityPreflight | null {
  const projection = workflowRunCapabilityReceiptProjection(
    workflow,
    null,
    projectRuntimeThreadEventsToWorkflowProjection([]),
  );
  const rows = projection.rows.filter((row) => row.failClosed);
  if (rows.length === 0) return null;
  const targetNodeIds = uniqueStrings(rows.map((row) => row.nodeId));
  const capabilityRefs = uniqueStrings(rows.map((row) => row.capabilityRef));
  const bindingKinds = uniqueStrings(rows.map((row) => row.bindingKind));
  const blockerReasons = uniqueStrings(
    rows.flatMap((row) => row.blockerReasons),
  );
  const issue: WorkflowValidationIssue = {
    nodeId: targetNodeIds[0],
    code: "workflow_capability_preflight_blocked",
    message:
      rows.length === 1
        ? `${rows[0]?.nodeName ?? "Workflow node"} is missing capability readiness before live execution.`
        : `${rows.length} workflow capability bindings are missing readiness before live execution.`,
    configSection: "bindings",
    repairActionId: "open-capability-binding",
    repairLabel: "Review capability binding",
  };
  return {
    schemaVersion: WORKFLOW_CAPABILITY_PREFLIGHT_SCHEMA_VERSION,
    sourceKind: "workflow_capability_bindings",
    status: "blocked",
    issue,
    rowCount: rows.length,
    targetNodeIds,
    capabilityRefs,
    bindingKinds,
    blockerReasons,
    receiptRefs: [],
    policyDecisionRefs: [],
    rows: rows.map(workflowCapabilityPreflightRow),
  };
}

export function workflowCapabilityRunLaunchAnnotation(
  preflight: WorkflowCapabilityPreflight | null,
): WorkflowCapabilityRunLaunchAnnotation | null {
  if (!preflight) return null;
  return {
    schemaVersion: preflight.schemaVersion,
    sourceKind: preflight.sourceKind,
    status: preflight.status,
    rowCount: preflight.rowCount,
    targetNodeIds: preflight.targetNodeIds,
    capabilityRefs: preflight.capabilityRefs,
    bindingKinds: preflight.bindingKinds,
    blockerReasons: preflight.blockerReasons,
    receiptRefs: preflight.receiptRefs,
    policyDecisionRefs: preflight.policyDecisionRefs,
    rows: preflight.rows,
    issueCode: preflight.issue.code,
    issueMessage: preflight.issue.message,
  };
}

export function workflowCapabilityPreflightValidationResult(
  preflight: WorkflowCapabilityPreflight,
  base?: WorkflowValidationResult | null,
): WorkflowValidationResult {
  const issues = [
    preflight.issue,
    ...preflight.rows.map(
      (row): WorkflowValidationIssue => ({
        nodeId: row.nodeId,
        code: "workflow_capability_binding_not_ready",
        message: `${row.nodeName} ${row.bindingKind.toLowerCase()} capability ${row.capabilityRef} is blocked: ${row.blockerReasons.join(", ")}.`,
        configSection: "bindings",
        repairActionId: "open-capability-binding",
        repairLabel: "Review capability binding",
      }),
    ),
  ];
  return {
    ...(base ?? emptyValidationResult()),
    status: "blocked",
    errors: [...issues, ...(base?.errors ?? [])],
    blockedNodes: uniqueStrings([
      ...(base?.blockedNodes ?? []),
      ...preflight.targetNodeIds,
    ]),
    executionReadinessIssues: [
      ...(base?.executionReadinessIssues ?? []),
      ...issues,
    ],
  };
}

function workflowCapabilityPreflightRow(
  row: WorkflowRunCapabilityReceiptRow,
): WorkflowCapabilityPreflightRow {
  return {
    nodeId: row.nodeId,
    nodeName: row.nodeName,
    nodeType: row.nodeType,
    bindingKind: row.bindingKind,
    capabilityRef: row.capabilityRef,
    routeId: row.routeId,
    mode: row.mode,
    ready: row.ready,
    failClosed: row.failClosed,
    readinessStatus: row.readinessStatus,
    grantStatus: row.grantStatus,
    policyStatus: row.policyStatus,
    receiptRequired: row.receiptRequired,
    receiptTypes: row.receiptTypes,
    authorityScopes: row.authorityScopes,
    authorityScopeRequirements: row.authorityScopeRequirements,
    blockerReasons: row.blockerReasons,
  };
}

function emptyValidationResult(): WorkflowValidationResult {
  return {
    status: "blocked",
    errors: [],
    warnings: [],
    blockedNodes: [],
    missingConfig: [],
    unsupportedRuntimeNodes: [],
    policyRequiredNodes: [],
    coverageByNodeId: {},
    connectorBindingIssues: [],
    executionReadinessIssues: [],
    verificationIssues: [],
  };
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}
